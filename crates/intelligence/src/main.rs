//! Intelligence service binary (§8) — Sprint 7 t1–t4: data stores, seeding,
//! clustering, and the `IncidentCreated` attribution consumer. The default run
//! mode (`attribute`, also bare) is the long-running consumer; every other
//! subcommand is an *operational* entry point, the same split as
//! `simulation-projection`:
//!
//!   - `migrate up|down|info` — drive the ClickHouse adjacency migrations
//!     (Postgres migrations are applied out-of-band by sqlx-cli via
//!     `just migrate-*`, the workspace-wide convention).
//!   - `ping` — connect and probe all three stores (Postgres schema, Redis,
//!     ClickHouse), so a misconfigured deployment fails fast and visibly.
//!   - `seed <feed> <file> [source-detail]` — import a downloaded §8.1 public
//!     feed (t2). Downloading stays out-of-band (see the justfile), so the
//!     import is a reproducible file, not a moving URL.
//!   - `cluster <chain-id> <address>` — run one clustering pass (t3).
//!   - `attribute` (default; also the no-arg run) — drive the t4 attribution
//!     consumer: `PreliminaryAlertCreated` + `IncidentCreated` in, entities/
//!     labels/attribution/sanctions events out, until a shutdown signal.
//!   - `risk <address>` — compute and print one address's risk score (§8.3,
//!     Sprint 8 t1): read-only, no event published (that lands with the t2
//!     cache/invalidation consumer this pure kernel plugs into).
//!   - `score` — drive the t2 risk-score cache-invalidation consumer (§8.3):
//!     `LabelAdded`/`LabelUpdated`/`LabelRevoked`/`SanctionHit`/
//!     `EntityCreated`/`EntityMerged`/`EntitySplit`/`AttributionUpdated` in
//!     (its own Kafka consumer group, independent of `attribute`'s), the
//!     `(address, model_version)` cache invalidated + recomputed and
//!     `RiskScoreUpdated` out, until a shutdown signal.
//!   - `label-update <chain-id> <label-id> <new-value>` — operator correction
//!     of a label's display value in place; emits `LabelUpdated`.
//!   - `label-revoke <chain-id> <label-id> <reason...>` — soft-revoke a label;
//!     emits `LabelRevoked`.
//!   - `entity-split <chain-id> <entity-id> <reason> <group> <group> [...]` —
//!     reverse an incorrect merge, `group` a comma-separated address list;
//!     emits `EntitySplit`.
//!   - `reorg` — drive the t3 reorg-rollback consumer (§15): `IncidentRetracted`
//!     in (its own Kafka consumer group), attribution withdrawn and eligible
//!     merges reversed, `AttributionRetracted`/`EntitySplit` out, until a
//!     shutdown signal — see [`intelligence::reorg`].
//!   - `block-production` — drive the §10 block-production consumer (Sprint 11
//!     t1): `BlockCanonicalized`/`BlockReverted`/`DetectorTriggered`/
//!     `IncidentCreated`/`IncidentRetracted` in (its own Kafka consumer
//!     group), builder/relay-attributed `BlockProductionRecord` snapshots into
//!     ClickHouse (apply the `block_production` table first via `migrate up`)
//!     and heuristic `BuilderAddress` `LabelAdded`s out, until a shutdown
//!     signal — see [`intelligence::production_consumer`].
//!   - `embed <address>` — compute and print one address's §20.3 behavior
//!     vector (Sprint 19 t1): read-only inspection, no store write and no
//!     event published.
//!   - `embedding` — drive the §20.3 behavior-embedding job: the scheduled
//!     sweep ([`intelligence::embedding_sweep`]) and the invalidation consumer
//!     ([`intelligence::embedding_consumer`]) over one shared compute core
//!     ([`intelligence::embedding_job`]), appending vectors to the
//!     `address_embeddings` ClickHouse table and publishing
//!     `AddressEmbeddingUpdated`, until a shutdown signal.
//!   - `embedding-baseline` — recompute the §20.3 population baseline (the
//!     per-feature median/MAD a similarity search standardizes against) from
//!     a bounded sample of stored vectors. A periodic operator/cron action,
//!     not part of the long-running job: the baseline moves on a much slower
//!     clock than the vectors do.
//!   - `cross-chain-attribute` — drive the Sprint 17 t4 cross-chain
//!     attribution consumer (§8, §24): `BridgeMevDetected`/
//!     `CrossChainMevDetected` in (its own Kafka consumer group), each
//!     finding's `entity_hint` clustered across its legs' chains into one
//!     entity plus the association flywheel, `EntityCreated`/`EntityMerged`/
//!     `LabelAdded`/`SanctionHit` out, until a shutdown signal — see
//!     [`intelligence::cross_chain_attribution`].
//!
//! The label/entity-split trio above are one-shot operator actions with no Kafka consumer of
//! their own (nothing else in this service calls `revoke_label`/
//! `update_label_value`/`split`), so the CLI itself is the event producer —
//! see [`publish_once`] for why that's a single best-effort publish rather
//! than the consumer's indefinite `publish_resilient` retry.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clickhouse::Client;
use event_bus::{EventSink, KafkaEventSink, PUBLISH_BACKOFF};
use events::intelligence::{EntitySplit, LabelRevoked, LabelUpdated};
use events::primitives::{Chain, EntityId, LabelId};
use events::{DomainEvent, EventEnvelope};
use intelligence::adjacency::{build_clickhouse_client, ClickhouseAdjacency};
use intelligence::attribution::{build_consumer, Attributor};
use intelligence::cache::{HotCache, RedisHotCache};
use intelligence::ch_migrate;
use intelligence::cluster::{cluster_address, ClusterLimits, ClusterSeams};
use intelligence::config::Config;
use intelligence::cross_chain_attribution::{self, CrossChainAttributor};
use intelligence::embedding::{self, baseline, BehaviorEmbedder};
use intelligence::embedding_consumer::{self, EmbeddingConsumer};
use intelligence::embedding_job::{self, Embedder, EmbedderSeams};
use intelligence::embedding_store::{ClickhouseEmbeddingStore, EmbeddingStore};
use intelligence::embedding_sweep::EmbeddingSweep;
use intelligence::grpc::IntelligenceReadService;
use intelligence::leaderboard::ClickhouseLeaderboard;
use intelligence::merge_actor::MergeActor;
use intelligence::pb::intelligence_read_server::IntelligenceReadServer;
use intelligence::production::BookCapacity;
use intelligence::production_consumer::{self, ProductionConsumer};
use intelligence::production_source::{HttpRelaySource, RpcBlockFacts};
use intelligence::production_store::ClickhouseProductionStore;
use intelligence::reorg::{self, ReorgConsumer};
use intelligence::risk;
use intelligence::risk_scorer::{self, RiskScorer};
use intelligence::seed::{Feed, Seeder};
use intelligence::store::{EntityStore, LabelStore, PgIntelligenceStore, SplitOutcome, StoreSeams};
use secrecy::ExposeSecret;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

const USAGE: &str = "expected `migrate up|down|info`, `ping`, \
                     `seed <etherscan-tags|ofac-sdn|mev-list|protocol-registry> <file> [source-detail]`, \
                     `cluster <chain-id> <address>`, `attribute` (also the no-arg default), \
                     `risk <address>`, `score`, `reorg`, `grpc`, `block-production`, \
                     `cross-chain-attribute`, `embed <address>`, `embedding`, \
                     `embedding-baseline`, \
                     `label-update <chain-id> <label-id> <new-value>`, \
                     `label-revoke <chain-id> <label-id> <reason...>`, or \
                     `entity-split <chain-id> <entity-id> <reason> <group> <group> [...]` \
                     (group = comma-separated addresses)";

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("intelligence"))?;
    let cfg = Config::from_env()?;
    let client = build_clickhouse_client(&cfg.clickhouse);

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("migrate") => {
            ch_migrate::MIGRATOR
                .cli(&client, args.next().as_deref())
                .await
        }
        Some("ping") => ping(&cfg, client).await,
        Some("seed") => seed(&cfg, args).await,
        Some("cluster") => cluster(&cfg, client, args).await,
        Some("attribute") | None => attribute(&cfg, client).await,
        Some("risk") => address_risk(&cfg, args).await,
        Some("score") => score(&cfg).await,
        Some("reorg") => reorg_cmd(&cfg).await,
        Some("grpc") => grpc_serve(&cfg, client).await,
        Some("block-production") => block_production(&cfg, client).await,
        Some("cross-chain-attribute") => cross_chain_attribute(&cfg, client).await,
        Some("embed") => address_embedding(&cfg, client, args).await,
        Some("embedding") => embedding(&cfg, client).await,
        Some("embedding-baseline") => embedding_baseline(&cfg, client).await,
        Some("label-update") => label_update(&cfg, args).await,
        Some("label-revoke") => label_revoke(&cfg, args).await,
        Some("entity-split") => entity_split(&cfg, args).await,
        Some(other) => bail!("unknown argument {other:?}; {USAGE}"),
    }
}

/// Parse the leading `<chain-id>` positional argument every CLI subcommand
/// that publishes an event needs — solely to stamp the `Chain` an
/// [`EventEnvelope`] requires; none of the label/entity facts these commands
/// touch are themselves chain-scoped in storage.
fn parse_chain_arg(args: &mut impl Iterator<Item = String>) -> Result<Chain> {
    let Some(raw) = args.next() else {
        bail!("missing chain id; {USAGE}");
    };
    Ok(Chain(raw.parse().map_err(|_| {
        anyhow::anyhow!("chain id {raw:?} is not a u64; {USAGE}")
    })?))
}

/// Publish one event and move on — the CLI's one-shot analogue of
/// [`event_bus::publish_resilient`]. That function is right for a long-running
/// consumer, which owns a Kafka offset it can simply leave uncommitted and
/// retry forever; a one-shot admin command has no such offset and no operator
/// standing by to wait out an indefinite retry loop against a down broker. The
/// store write already happened and is the durable fact (§8's system of
/// record); a failed publish here is logged loudly so the operator knows the
/// audit event may need a manual replay, but the process still exits.
async fn publish_once(sink: &dyn EventSink, chain: Chain, payload: DomainEvent) {
    let event_type = payload.event_type();
    if let Err(err) = sink.publish(EventEnvelope::new(chain, payload)).await {
        tracing::error!(
            error = %err,
            event_type,
            "publishing the audit event failed; the store write already succeeded — \
             the event may need a manual replay"
        );
        eprintln!("⚠️  store updated, but publishing {event_type} failed: {err}");
    }
}

/// Import one downloaded §8.1 feed file: parse (pure, hard error with a
/// location on any malformed row), then apply through the Postgres store and
/// evict touched addresses from the hot cache. Re-running the same file is an
/// idempotent no-op (deterministic seeded label ids + keyed sanctions upsert).
async fn seed(cfg: &Config, mut args: impl Iterator<Item = String>) -> Result<()> {
    let feed: Feed = match args.next() {
        Some(raw) => raw
            .parse()
            .map_err(|_| anyhow::anyhow!("unknown feed {raw:?}; {USAGE}"))?,
        None => bail!("missing feed; {USAGE}"),
    };
    let Some(path) = args.next() else {
        bail!("missing feed file path; {USAGE}");
    };
    // Optional provenance override naming the specific list/registry; an empty
    // arg (justfile default) means "use the feed's canonical name".
    let detail = args
        .next()
        .filter(|raw| !raw.is_empty())
        .unwrap_or_else(|| feed.canonical_detail().to_owned());

    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading feed file {path:?}"))?;
    let batch = feed.parse(&raw, &detail, chrono::Utc::now())?;
    println!(
        "parsed {path}: {} labels, {} sanctions rows (source_detail {detail:?})",
        batch.labels.len(),
        batch.sanctions.len()
    );

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let store = Arc::new(PgIntelligenceStore::new(pool));
    let cache = RedisHotCache::connect(cfg.redis.url.expose_secret(), cfg.redis.cache_ttl)
        .await
        .context("connecting to Redis")?;

    // The span names *which* feed/file this import is; `Seeder::apply`'s own
    // instrumentation nests the batch sizes and outcome under it.
    let report = Seeder::new(store.clone(), store, Arc::new(cache))
        .apply(&batch)
        .instrument(tracing::info_span!("seed_import", %feed, %detail, path = %path))
        .await
        .context("applying the parsed feed (safe to re-run: writes are keyed)")?;
    println!("✅ {report}");
    Ok(())
}

/// Run one basic-entity-clustering pass (§8.2, Sprint 7 t3) from a seed
/// address: walk the adjacency graph over the funder/deployer/
/// profit-receiver/code-hash signal only, degree-capped and hop-bounded, then
/// apply the resulting component to the Postgres entity store. Safe to re-run
/// (idempotent) and safe to seed on an unknown or infrastructure address (the
/// latter simply reports no cluster).
async fn cluster(
    cfg: &Config,
    client: Client,
    mut args: impl Iterator<Item = String>,
) -> Result<()> {
    let chain = parse_chain_arg(&mut args)?;
    let Some(raw_address) = args.next() else {
        bail!("missing address; {USAGE}");
    };
    let address = raw_address
        .parse()
        .map_err(|_| anyhow::anyhow!("address {raw_address:?} is not 0x-hex; {USAGE}"))?;

    let graph = ClickhouseAdjacency::new(client);
    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let store = PgIntelligenceStore::new(pool);
    // A one-shot process gets its own actor — nothing else shares this
    // invocation's mailbox, so there's no contention to serialize against
    // (see `merge_actor`'s module docs on the cross-process limit this
    // implies if this CLI ever races the `attribute` consumer).
    let merge_actor = MergeActor::spawn();

    let outcome = cluster_address(
        ClusterSeams {
            graph: &graph,
            entities: &store,
            merge_actor: &merge_actor,
        },
        chain,
        &address,
        "cli:cluster",
        None,
        chrono::Utc::now(),
        ClusterLimits::default(),
    )
    .instrument(tracing::info_span!("cluster_address", %chain, %raw_address))
    .await
    .context("clustering the seed address")?;

    match outcome {
        Some(outcome) => println!(
            "✅ entity {}: {} newly linked, {} entities absorbed, {} hubs excluded ({:?})",
            outcome.entity_id,
            outcome.linked.len(),
            outcome.absorbed.len(),
            outcome.hubs.len(),
            outcome.hubs,
        ),
        None => println!(
            "no cluster formed: {raw_address} is itself an infrastructure endpoint \
             (degree over the cap at hop 0)"
        ),
    }
    Ok(())
}

/// Compute and print one address's risk score (§8.3, Sprint 8 t1): read the
/// four store seams directly, hand the fetched rows to the pure
/// [`risk::score`] kernel, and print the same explainable breakdown the
/// architecture doc's worked example shows. Read-only — no `RiskScoreUpdated`
/// is published here; that lands with the t2 cache/invalidation consumer this
/// kernel plugs into.
async fn address_risk(cfg: &Config, mut args: impl Iterator<Item = String>) -> Result<()> {
    let Some(raw_address) = args.next() else {
        bail!("missing address; {USAGE}");
    };
    let address = raw_address
        .parse()
        .map_err(|_| anyhow::anyhow!("address {raw_address:?} is not 0x-hex; {USAGE}"))?;

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let store = Arc::new(PgIntelligenceStore::new(pool));
    let stores = StoreSeams::single(store);

    let as_of = chrono::Utc::now();
    let (entity_id, inputs) = risk_scorer::load_risk_inputs(&stores, &address, as_of)
        .await
        .context("loading risk inputs")?;
    let result = risk::score(address, entity_id, &inputs, as_of);

    println!(
        "Score: {} / 100   Confidence: {:.2}   (model {})",
        result.score,
        result.confidence.get(),
        result.model_version
    );
    if result.factors.is_empty() {
        println!("(no risk signal on record for this address)");
    }
    for factor in &result.factors {
        println!(
            "{:+.0}  {}  [{}]",
            factor.delta, factor.name, factor.evidence_ref
        );
    }
    Ok(())
}

/// Compute and print one address's behavior vector (§20.3, Sprint 19 t1):
/// read the adjacency history and the store seams, hand them to each enabled
/// version's pure kernel, and print the vectors with the factors that dominate
/// them. Read-only — nothing is appended and no
/// `AddressEmbeddingUpdated` is published; that is the `embedding` run mode's
/// job. The one-shot analogue of `risk <address>`, and the operator's way to
/// ask "what does the system think this address *behaves* like" before
/// trusting a similarity result built on it.
async fn address_embedding(
    cfg: &Config,
    client: Client,
    mut args: impl Iterator<Item = String>,
) -> Result<()> {
    let Some(raw_address) = args.next() else {
        bail!("missing address; {USAGE}");
    };
    let address = raw_address
        .parse()
        .map_err(|_| anyhow::anyhow!("address {raw_address:?} is not 0x-hex; {USAGE}"))?;

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let stores = StoreSeams::single(Arc::new(PgIntelligenceStore::new(pool)));
    let graph = ClickhouseAdjacency::new(client);

    let as_of = chrono::Utc::now();
    let (entity_id, inputs) = embedding_job::load_behavior_inputs(
        &stores,
        &graph,
        cfg.embedding.chain,
        &address,
        as_of,
        cfg.embedding.limits.history_cap,
    )
    .await
    .context("loading behavior inputs")?;

    println!(
        "chain {}   observations {}{}",
        cfg.embedding.chain,
        inputs.history.edges.len(),
        if inputs.history.truncated {
            " (TRUNCATED — this is a hub; the vector describes its recent window)"
        } else {
            ""
        }
    );
    if inputs.history.edges.is_empty() {
        println!("(no observations on record for this address on this chain)");
    }

    // Every enabled version, so an operator mid-rollout can see what each one
    // makes of the same address rather than only the default.
    for embedder in resolve_versions(&cfg.embedding.versions)? {
        let vector = embedder.embed(address, entity_id, &inputs, as_of);
        println!(
            "\n{} dims (model {}, schema {})",
            vector.values.len(),
            vector.embedding_version(),
            &vector.schema_hash()[..12],
        );
        for factor in vector.top_factors(embedding::MAX_VISIBLE_FACTORS) {
            println!(
                "{:>10.4}  {:5.1}%  {}",
                factor.value,
                factor.share * 100.0,
                factor.feature
            );
        }
    }
    Ok(())
}

/// Resolve the schema versions this deployment computes, failing at boot on an
/// unknown one.
///
/// An empty config means "the newest registered version". A named version that
/// this build does not ship is a *refused boot*, never a silent fallback to the
/// default: embedding under a different version than the operator asked for is
/// exactly the drift the version stamp exists to prevent, and it would only
/// surface much later as two incomparable vectors that look comparable.
fn resolve_versions(names: &[String]) -> Result<Vec<&'static dyn BehaviorEmbedder>> {
    if names.is_empty() {
        return Ok(vec![embedding::default_embedder()]);
    }
    names
        .iter()
        .map(|name| {
            embedding::embedder_for(name).with_context(|| {
                let known: Vec<&str> = embedding::embedders()
                    .iter()
                    .map(|embedder| embedder.version())
                    .collect();
                format!(
                    "INTEL_EMBEDDING_VERSIONS names {name:?}, which this build does not ship \
                     (known versions: {})",
                    known.join(", ")
                )
            })
        })
        .collect()
}

/// Build the shared §20.3 compute core the sweep, the consumer and the
/// one-shot commands all run through — so no entry point can read a different
/// set of seams than the long-running job does.
async fn build_embedder(
    cfg: &Config,
    client: Client,
    shutdown: CancellationToken,
) -> Result<Embedder> {
    let embed_cfg = &cfg.embedding;
    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let stores = StoreSeams::single(Arc::new(PgIntelligenceStore::new(pool)));

    let graph = Arc::new(ClickhouseAdjacency::new(client.clone()));
    graph
        .ping()
        .await
        .context("probing ClickHouse (the adjacency graph the embedding reads)")?;
    let embeddings = Arc::new(ClickhouseEmbeddingStore::new(client));

    let sink =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka event sink")?);

    Ok(Embedder::new(
        embed_cfg.chain,
        EmbedderSeams {
            stores,
            graph,
            embeddings,
            sink,
        },
        shutdown,
        embed_cfg.limits,
        resolve_versions(&embed_cfg.versions)?,
    ))
}

/// Run the §20.3 behavior-embedding job (Sprint 19 t1): the scheduled sweep and
/// the invalidation consumer, supervised together over one shared compute core.
///
/// Neither trigger is sufficient alone — the sweep catches cadence drift and
/// counterparty relabeling that no event names for this address, the consumer
/// catches the incident/label changes that must not wait a whole sweep
/// interval (see [`intelligence::embedding_consumer`]'s module docs). They run
/// in one process because they share one bounded compute path against one
/// connection pool: splitting them would double the store load and silently
/// double the configured page concurrency.
///
/// The `address_embeddings` ClickHouse table must be applied first
/// (`intelligence migrate up`), the same out-of-band migration convention as
/// the adjacency graph.
async fn embedding(cfg: &Config, client: Client) -> Result<()> {
    let embed_cfg = &cfg.embedding;
    tracing::info!(
        group = %embed_cfg.group_id,
        chain = %embed_cfg.chain,
        shard = %embed_cfg.sweep.shard,
        sweep_interval_s = embed_cfg.sweep.interval.as_secs(),
        history_cap = embed_cfg.limits.history_cap,
        "starting intelligence behavior-embedding job"
    );

    // Export the §19 embedding counters (computed/written-by-reason/skipped,
    // sweep budget and lap time) — the data behind "is the sweep keeping up".
    // A no-op if the addr is unset.
    if let Some(addr) = cfg.metrics_addr {
        telemetry::metrics::init(addr).context("starting the metrics exporter")?;
        tracing::info!(%addr, "serving embedding metrics");
    }

    let shutdown = CancellationToken::new();
    // K8s probes (§20): /livez immediately; /readyz flips on below, once this
    // mode's wiring completes. Opt-in via HEALTH_ADDR.
    let health = telemetry::health::HealthState::new();
    telemetry::health::spawn_from_env(health.clone(), shutdown.clone())
        .await
        .context("starting the health endpoints")?;
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    let embedder = build_embedder(cfg, client, shutdown.clone()).await?;
    tracing::info!(
        versions = ?embedder.versions().iter().map(|v| v.version()).collect::<Vec<_>>(),
        "embedding versions enabled"
    );

    let dlq =
        event_bus::dlq::DeadLetterQueue::ensure_from_env(&cfg.kafka.brokers, "intel-embedding")
            .await
            .context("provisioning the embedding DLQ topic")?;
    let kafka_consumer =
        embedding_consumer::build_consumer(&cfg.kafka.brokers, &embed_cfg.group_id)
            .context("building the embedding Kafka consumer")?;

    // The sweep is supervised, not fire-and-forget: if its task dies the
    // process must not keep serving a half-job that silently stops refreshing
    // dormant addresses while the consumer still looks healthy.
    let sweep =
        tokio::spawn(EmbeddingSweep::new(embedder.clone(), embed_cfg.sweep).run(shutdown.clone()));

    health.set_ready(true);
    let consumer_result = EmbeddingConsumer::new(embedder)
        .run(kafka_consumer, PUBLISH_BACKOFF, Some(&dlq), &shutdown)
        .await;

    // Either half exiting takes the other down — a drain, not a leak.
    shutdown.cancel();
    if let Err(err) = sweep.await {
        tracing::error!(error = %err, "the embedding sweep task did not shut down cleanly");
    }
    consumer_result.context("embedding consumer exited with error")?;

    tracing::info!("intelligence behavior-embedding job shut down");
    Ok(())
}

/// Recompute the §20.3 population baseline: the per-feature median and scaled
/// MAD a similarity search standardizes against (§20.3 — without it a raw
/// distance is dominated by the log-magnitude family, and "behaviorally
/// similar" degrades into "similar transaction count").
///
/// A periodic operator action rather than part of the long-running job: the
/// population statistics move on a much slower clock than individual vectors
/// do, and re-deriving one is a *ranking* change that an operator should make
/// deliberately. Read-only with respect to `address_embeddings` — it samples
/// them and writes one `behavior_baselines` row.
async fn embedding_baseline(cfg: &Config, client: Client) -> Result<()> {
    let embed_cfg = &cfg.embedding;
    let store = ClickhouseEmbeddingStore::new(client);

    for embedder in resolve_versions(&embed_cfg.versions)? {
        let schema = embedder.schema();
        let sample = store
            .sample_vectors(embed_cfg.chain, embedder.version(), BASELINE_SAMPLE_SIZE)
            .await
            .with_context(|| format!("sampling {} vectors", embedder.version()))?;

        let Some(computed) = baseline::compute(schema, &sample, chrono::Utc::now()) else {
            println!(
                "⚠️  {}: no vectors stored yet on chain {} — nothing to baseline",
                embedder.version(),
                embed_cfg.chain
            );
            continue;
        };

        if computed.sample_count < baseline::MIN_SAMPLES {
            // Stored anyway, and refused at *use* time by `standardize`: an
            // operator should be able to see the thin baseline that exists
            // rather than wonder whether the command ran.
            println!(
                "⚠️  {}: only {} vectors sampled (minimum {}) — stored, but too thin to \
                 standardize against",
                embedder.version(),
                computed.sample_count,
                baseline::MIN_SAMPLES
            );
        }

        store
            .put_baseline(embed_cfg.chain, &computed)
            .await
            .with_context(|| format!("storing the {} baseline", embedder.version()))?;

        println!(
            "✅ {} baseline over {} vectors (schema {})",
            computed.embedding_version,
            computed.sample_count,
            &computed.schema_hash[..12],
        );
        // The widest-spread features are the ones that will dominate a
        // standardized distance — worth seeing at a glance.
        let mut ranked: Vec<(&str, f32)> = schema
            .features()
            .iter()
            .zip(computed.spread.iter().copied())
            .map(|(def, spread)| (def.name, spread))
            .collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        for (name, spread) in ranked.iter().take(5) {
            println!("   spread {spread:>10.4}  {name}");
        }
    }
    Ok(())
}

/// How many stored vectors a baseline refresh samples. A population median
/// does not get materially better past a few tens of thousands of addresses,
/// and reading the whole table to compute one would be the most expensive
/// query this service issues.
const BASELINE_SAMPLE_SIZE: u32 = 50_000;

/// Prove all three stores are reachable and schema'd — the boot-time fail-fast
/// probe, runnable on its own for deploy smoke checks.
async fn ping(cfg: &Config, client: Client) -> Result<()> {
    ch_migrate::MIGRATOR
        .run(&client)
        .await
        .context("running ClickHouse adjacency migrations")?;

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    PgIntelligenceStore::new(pool)
        .ping()
        .await
        .context("probing the Postgres intelligence schema (run `just migrate-up`?)")?;
    println!("✅ postgres: reachable, intelligence schema applied");

    RedisHotCache::connect(cfg.redis.url.expose_secret(), cfg.redis.cache_ttl)
        .await
        .context("connecting to Redis")?;
    println!("✅ redis: reachable");

    ClickhouseAdjacency::new(client)
        .ping()
        .await
        .context("probing ClickHouse")?;
    println!("✅ clickhouse: reachable, adjacency schema applied");
    Ok(())
}

/// Run the t4 attribution consumer: connect the three stores + the Kafka event
/// sink, then drain `PreliminaryAlertCreated`/`IncidentCreated` until shutdown.
async fn attribute(cfg: &Config, client: Client) -> Result<()> {
    tracing::info!(
        group = %cfg.kafka.group_id,
        "starting intelligence attribution consumer"
    );

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let store = Arc::new(PgIntelligenceStore::new(pool));

    let cache = Arc::new(
        RedisHotCache::connect(cfg.redis.url.expose_secret(), cfg.redis.cache_ttl)
            .await
            .context("connecting to Redis")?,
    );

    let graph = Arc::new(ClickhouseAdjacency::new(client));

    let sink =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka event sink")?);

    let shutdown = CancellationToken::new();
    // K8s probes (§20): /livez immediately; /readyz flips on below, once this
    // mode's wiring completes. Opt-in via HEALTH_ADDR.
    let health = telemetry::health::HealthState::new();
    telemetry::health::spawn_from_env(health.clone(), shutdown.clone())
        .await
        .context("starting the health endpoints")?;
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    let attributor = Attributor::new(
        StoreSeams::single(store),
        graph,
        cache,
        sink,
        shutdown.clone(),
        // One actor for the process's life, serializing every cluster pass
        // this consumer runs against every other (§17, t5) — see
        // `merge_actor`'s module docs.
        MergeActor::spawn(),
    );

    let dlq =
        event_bus::dlq::DeadLetterQueue::ensure_from_env(&cfg.kafka.brokers, "intel-attribution")
            .await
            .context("provisioning the attribution DLQ topic")?;
    let consumer = build_consumer(&cfg.kafka.brokers, &cfg.kafka.group_id)
        .context("building the attribution Kafka consumer")?;
    health.set_ready(true);
    attributor
        .run(consumer, PUBLISH_BACKOFF, Some(&dlq), &shutdown)
        .await
        .context("attribution consumer exited with error")?;

    tracing::info!("intelligence attribution consumer shut down");
    Ok(())
}

/// Run the Sprint 17 t4 cross-chain attribution consumer (§8, §24): connect
/// the same seams `attribute` uses (Postgres store, Redis hot cache,
/// ClickHouse adjacency, Kafka sink), then drain `BridgeMevDetected`/
/// `CrossChainMevDetected` until shutdown — clustering each finding's
/// `entity_hint` across its legs' chains into one entity and running the
/// association flywheel against it, publishing `EntityCreated`/`EntityMerged`/
/// `LabelAdded`/`SanctionHit` for the existing `score`/`reorg` consumers to
/// react to exactly as if an incident had triggered them. Its own consumer
/// group (`cfg.kafka.cross_chain_group_id`) — an independently deployable
/// process from `attribute`, reading a disjoint pair of topics — see
/// [`intelligence::cross_chain_attribution`].
async fn cross_chain_attribute(cfg: &Config, client: Client) -> Result<()> {
    tracing::info!(
        group = %cfg.kafka.cross_chain_group_id,
        "starting intelligence cross-chain attribution consumer"
    );

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let store = Arc::new(PgIntelligenceStore::new(pool));

    let cache = Arc::new(
        RedisHotCache::connect(cfg.redis.url.expose_secret(), cfg.redis.cache_ttl)
            .await
            .context("connecting to Redis")?,
    );

    let graph = Arc::new(ClickhouseAdjacency::new(client));

    let sink =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka event sink")?);

    let shutdown = CancellationToken::new();
    // K8s probes (§20): /livez immediately; /readyz flips on below, once this
    // mode's wiring completes. Opt-in via HEALTH_ADDR.
    let health = telemetry::health::HealthState::new();
    telemetry::health::spawn_from_env(health.clone(), shutdown.clone())
        .await
        .context("starting the health endpoints")?;
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    let attributor = CrossChainAttributor::new(
        StoreSeams::single(store),
        graph,
        cache,
        sink,
        shutdown.clone(),
        // This process's own actor — a separate deployment from `attribute`,
        // so there is no in-process caller to share it with (§17).
        MergeActor::spawn(),
    );

    let dlq = event_bus::dlq::DeadLetterQueue::ensure_from_env(
        &cfg.kafka.brokers,
        "intel-cross-chain-attribution",
    )
    .await
    .context("provisioning the cross-chain attribution DLQ topic")?;
    let consumer = cross_chain_attribution::build_consumer(
        &cfg.kafka.brokers,
        &cfg.kafka.cross_chain_group_id,
    )
    .context("building the cross-chain attribution Kafka consumer")?;
    health.set_ready(true);
    attributor
        .run(consumer, PUBLISH_BACKOFF, Some(&dlq), &shutdown)
        .await
        .context("cross-chain attribution consumer exited with error")?;

    tracing::info!("intelligence cross-chain attribution consumer shut down");
    Ok(())
}

/// Run the t2 risk-score cache-invalidation consumer (§8.3): connect the four
/// store seams + the Redis hot cache + the Kafka event sink, then drain
/// `LabelAdded`/`LabelUpdated`/`LabelRevoked`/`SanctionHit`/`EntityCreated`/
/// `EntityMerged`/`EntitySplit`/`AttributionUpdated` until shutdown,
/// invalidating and recomputing the `(address, model_version)` cache entry and
/// publishing `RiskScoreUpdated` for every address each event touches. Its own
/// consumer group (`cfg.kafka.risk_group_id`) — an independently deployable
/// process from `attribute`, not a ClickHouse-adjacency reader, so no `Client`
/// is needed here.
async fn score(cfg: &Config) -> Result<()> {
    tracing::info!(
        group = %cfg.kafka.risk_group_id,
        "starting intelligence risk-score consumer"
    );

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let store = Arc::new(PgIntelligenceStore::new(pool));

    let cache = Arc::new(
        RedisHotCache::connect(cfg.redis.url.expose_secret(), cfg.redis.cache_ttl)
            .await
            .context("connecting to Redis")?,
    );

    let sink =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka event sink")?);

    let shutdown = CancellationToken::new();
    // K8s probes (§20): /livez immediately; /readyz flips on below, once this
    // mode's wiring completes. Opt-in via HEALTH_ADDR.
    let health = telemetry::health::HealthState::new();
    telemetry::health::spawn_from_env(health.clone(), shutdown.clone())
        .await
        .context("starting the health endpoints")?;
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    let scorer = RiskScorer::new(StoreSeams::single(store), cache, sink, shutdown.clone());

    let dlq =
        event_bus::dlq::DeadLetterQueue::ensure_from_env(&cfg.kafka.brokers, "intel-risk-scorer")
            .await
            .context("provisioning the risk-scorer DLQ topic")?;
    let consumer = risk_scorer::build_consumer(&cfg.kafka.brokers, &cfg.kafka.risk_group_id)
        .context("building the risk-score Kafka consumer")?;
    health.set_ready(true);
    scorer
        .run(consumer, PUBLISH_BACKOFF, Some(&dlq), &shutdown)
        .await
        .context("risk-score consumer exited with error")?;

    tracing::info!("intelligence risk-score consumer shut down");
    Ok(())
}

/// Run the t3 reorg-rollback consumer (§15): connect the four store seams +
/// the Kafka event sink, then drain `IncidentRetracted` until shutdown,
/// withdrawing the retracted incident's attributions and reversing every
/// merge it caused — publishing `AttributionRetracted`/`EntitySplit` for the
/// t2 risk-scorer to react to. Its own consumer group
/// (`cfg.kafka.reorg_group_id`) — an independently deployable process from
/// `attribute`/`score`, not a ClickHouse/Redis reader, so neither `Client`
/// nor a hot cache is needed here.
async fn reorg_cmd(cfg: &Config) -> Result<()> {
    tracing::info!(
        group = %cfg.kafka.reorg_group_id,
        "starting intelligence reorg-rollback consumer"
    );

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let store = Arc::new(PgIntelligenceStore::new(pool));

    let sink =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka event sink")?);

    let shutdown = CancellationToken::new();
    // K8s probes (§20): /livez immediately; /readyz flips on below, once this
    // mode's wiring completes. Opt-in via HEALTH_ADDR.
    let health = telemetry::health::HealthState::new();
    telemetry::health::spawn_from_env(health.clone(), shutdown.clone())
        .await
        .context("starting the health endpoints")?;
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    let consumer = ReorgConsumer::new(StoreSeams::single(store), sink, shutdown.clone());

    let dlq = event_bus::dlq::DeadLetterQueue::ensure_from_env(&cfg.kafka.brokers, "intel-reorg")
        .await
        .context("provisioning the reorg DLQ topic")?;
    let kafka_consumer = reorg::build_consumer(&cfg.kafka.brokers, &cfg.kafka.reorg_group_id)
        .context("building the reorg Kafka consumer")?;
    health.set_ready(true);
    consumer
        .run(kafka_consumer, PUBLISH_BACKOFF, Some(&dlq), &shutdown)
        .await
        .context("reorg consumer exited with error")?;

    tracing::info!("intelligence reorg-rollback consumer shut down");
    Ok(())
}

/// Run the §10 block-production consumer (Sprint 11 t1): connect the chain
/// RPC + relay data-API sources, the label store it reads/mints through, the
/// ClickHouse snapshot store and the Kafka event sink, then drain the five
/// block/incident topics until shutdown — building the builder/relay-attributed
/// `BlockProductionRecord` per canonical block. Its own consumer group
/// (`cfg.block_production.group_id`) — an independently deployable process,
/// like `attribute`/`score`/`reorg`. The `block_production` ClickHouse table
/// must be applied first (`intelligence migrate up`), the same out-of-band
/// migration convention as the adjacency graph.
async fn block_production(cfg: &Config, client: Client) -> Result<()> {
    let bp = &cfg.block_production;
    let Some(rpc_url) = bp.rpc_url.clone() else {
        bail!("INTEL_ETH_RPC_URL is required for `block-production` (full-block reads)");
    };
    tracing::info!(
        group = %bp.group_id,
        relays = bp.relays.len(),
        "starting intelligence block-production consumer"
    );
    if bp.relays.is_empty() {
        tracing::warn!(
            "MEV_RELAY_ENDPOINTS is empty — records will carry header facts only, \
             no relay attribution and no heuristic builder labels"
        );
    }

    // Export the §19 block-production counters (relay hit/miss, snapshots,
    // labels minted, incidents buffered) — the data behind the builder/relay
    // dashboard. A no-op if `INTELLIGENCE_METRICS_ADDR` is unset.
    if let Some(addr) = cfg.metrics_addr {
        telemetry::metrics::init(addr).context("starting the metrics exporter")?;
        tracing::info!(%addr, "serving block-production metrics");
    }

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let labels = Arc::new(PgIntelligenceStore::new(pool));

    let cache = Arc::new(
        RedisHotCache::connect(cfg.redis.url.expose_secret(), cfg.redis.cache_ttl)
            .await
            .context("connecting to Redis")?,
    );

    let sink =
        Arc::new(KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka event sink")?);

    let shutdown = CancellationToken::new();
    // K8s probes (§20): /livez immediately; /readyz flips on below, once this
    // mode's wiring completes. Opt-in via HEALTH_ADDR.
    let health = telemetry::health::HealthState::new();
    telemetry::health::spawn_from_env(health.clone(), shutdown.clone())
        .await
        .context("starting the health endpoints")?;
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    let consumer = ProductionConsumer::new(
        bp.chain,
        Arc::new(RpcBlockFacts::new(rpc_url)),
        Arc::new(
            HttpRelaySource::new(bp.relays.clone(), bp.relay_timeout)
                .context("building the relay data-API client")?,
        ),
        labels,
        cache,
        Arc::new(ClickhouseProductionStore::new(client)),
        sink,
        shutdown.clone(),
        BookCapacity::default(),
    );

    let dlq = event_bus::dlq::DeadLetterQueue::ensure_from_env(
        &cfg.kafka.brokers,
        "intel-block-production",
    )
    .await
    .context("provisioning the block-production DLQ topic")?;
    let kafka_consumer = production_consumer::build_consumer(&cfg.kafka.brokers, &bp.group_id)
        .context("building the block-production Kafka consumer")?;
    health.set_ready(true);
    consumer
        .run(kafka_consumer, PUBLISH_BACKOFF, Some(&dlq), &shutdown)
        .await
        .context("block-production consumer exited with error")?;

    tracing::info!("intelligence block-production consumer shut down");
    Ok(())
}

/// Run the `IntelligenceRead` gRPC server (§11): connect the four store seams,
/// the Redis hot cache and the ClickHouse block-production reader, then serve
/// `GetRiskScore`/`GetLabels`/`GetBuilderLeaderboard` until shutdown.
/// Independently deployable from `attribute`/`score`/`reorg` — pure reads, no
/// Kafka consumer group of its own.
async fn grpc_serve(cfg: &Config, client: Client) -> Result<()> {
    tracing::info!(addr = %cfg.grpc_addr, "starting intelligence gRPC server");

    // Export the §19 read-path counters (entity graph/timeline) when a metrics
    // address is configured — a no-op if `INTELLIGENCE_METRICS_ADDR` is unset,
    // the same optional-exporter stance as the block-production run mode.
    if let Some(addr) = cfg.metrics_addr {
        telemetry::metrics::init(addr).context("starting the metrics exporter")?;
        tracing::info!(%addr, "serving intelligence read metrics");
    }

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let store = Arc::new(PgIntelligenceStore::new(pool));

    let cache = Arc::new(
        RedisHotCache::connect(cfg.redis.url.expose_secret(), cfg.redis.cache_ttl)
            .await
            .context("connecting to Redis")?,
    );

    // The §10 builder/relay leaderboard reads the same append-only ClickHouse
    // `block_production` table the block-production consumer writes. The
    // entity-graph hop query (§8.2) reads the `address_adjacency` table in the
    // same ClickHouse — the client is `Arc`-cheap to clone, so both share it.
    let graph = Arc::new(ClickhouseAdjacency::new(client.clone()));
    let leaderboard = Arc::new(ClickhouseLeaderboard::new(client));

    let shutdown = CancellationToken::new();
    // K8s probes (§20): /livez immediately; /readyz flips on below, once this
    // mode's wiring completes. Opt-in via HEALTH_ADDR.
    let health = telemetry::health::HealthState::new();
    telemetry::health::spawn_from_env(health.clone(), shutdown.clone())
        .await
        .context("starting the health endpoints")?;
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    let service = IntelligenceReadService::new(
        StoreSeams::single(store),
        cache,
        leaderboard,
        graph,
        cfg.graph_limits,
    );
    health.set_ready(true);
    tonic::transport::Server::builder()
        .add_service(IntelligenceReadServer::new(service))
        .serve_with_shutdown(cfg.grpc_addr, shutdown.cancelled())
        .await
        .context("gRPC server error")?;

    tracing::info!("intelligence gRPC server shut down");
    Ok(())
}

/// Correct an existing label's display value in place (an operator fixing a
/// typo'd/stale tag, not a new conflicting claim — see
/// [`LabelStore::update_label_value`](intelligence::store::LabelStore::update_label_value)).
/// Emits `LabelUpdated`.
async fn label_update(cfg: &Config, mut args: impl Iterator<Item = String>) -> Result<()> {
    let chain = parse_chain_arg(&mut args)?;
    let label_id = parse_label_id_arg(&mut args)?;
    let Some(new_value) = args.next() else {
        bail!("missing new value; {USAGE}");
    };

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let store = PgIntelligenceStore::new(pool);
    let cache = RedisHotCache::connect(cfg.redis.url.expose_secret(), cfg.redis.cache_ttl)
        .await
        .context("connecting to Redis")?;
    let sink = KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka event sink")?;

    let Some(before) = store.update_label_value(label_id, &new_value).await? else {
        println!("no active label {label_id} to update (missing, or already revoked)");
        return Ok(());
    };
    cache
        .evict(&before.address)
        .await
        .context("evicting the hot cache")?;

    publish_once(
        &sink,
        chain,
        DomainEvent::LabelUpdated(LabelUpdated {
            address: before.address,
            label_id,
            old_value: before.value.clone(),
            new_value: new_value.clone(),
            source: <&str>::from(before.source).to_owned(),
        }),
    )
    .await;
    println!("✅ label {label_id}: {:?} → {new_value:?}", before.value);
    Ok(())
}

/// Soft-revoke a label (the row is kept for audit). Emits `LabelRevoked`.
async fn label_revoke(cfg: &Config, mut args: impl Iterator<Item = String>) -> Result<()> {
    let chain = parse_chain_arg(&mut args)?;
    let label_id = parse_label_id_arg(&mut args)?;
    let reason = args.collect::<Vec<_>>().join(" ");
    if reason.is_empty() {
        bail!("missing reason; {USAGE}");
    }

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let store = PgIntelligenceStore::new(pool);
    let cache = RedisHotCache::connect(cfg.redis.url.expose_secret(), cfg.redis.cache_ttl)
        .await
        .context("connecting to Redis")?;
    let sink = KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka event sink")?;

    let Some(label) = store.label(label_id).await? else {
        bail!("label {label_id} does not exist");
    };
    if !store
        .revoke_label(label_id, &reason, chrono::Utc::now())
        .await?
    {
        println!("label {label_id} was already revoked (no-op)");
        return Ok(());
    }
    cache
        .evict(&label.address)
        .await
        .context("evicting the hot cache")?;

    publish_once(
        &sink,
        chain,
        DomainEvent::LabelRevoked(LabelRevoked {
            address: label.address,
            label_id,
            reason: reason.clone(),
        }),
    )
    .await;
    println!("✅ label {label_id} revoked: {reason}");
    Ok(())
}

/// Reverse an earlier, incorrect merge: split `entity_id`'s current membership
/// into one fresh entity per `group` (comma-separated addresses; every current
/// member must appear in exactly one group). Emits `EntitySplit`.
async fn entity_split(cfg: &Config, mut args: impl Iterator<Item = String>) -> Result<()> {
    let chain = parse_chain_arg(&mut args)?;
    let Some(raw_entity_id) = args.next() else {
        bail!("missing entity id; {USAGE}");
    };
    let entity_id = EntityId(
        raw_entity_id
            .parse()
            .map_err(|_| anyhow::anyhow!("entity id {raw_entity_id:?} is not a UUID; {USAGE}"))?,
    );
    let Some(reason) = args.next() else {
        bail!("missing reason; {USAGE}");
    };
    let groups: Vec<Vec<_>> = args
        .map(|group| {
            group
                .split(',')
                .map(|raw| {
                    raw.parse()
                        .map_err(|_| anyhow::anyhow!("address {raw:?} is not 0x-hex; {USAGE}"))
                })
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;
    if groups.len() < 2 {
        bail!("need at least two groups to split into; {USAGE}");
    }

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let store = PgIntelligenceStore::new(pool);
    let sink = KafkaEventSink::new(&cfg.kafka.brokers).context("building the Kafka event sink")?;

    match store
        .split(entity_id, &groups, "cli:entity-split", chrono::Utc::now())
        .await?
    {
        SplitOutcome::Split { new_ids } => {
            publish_once(
                &sink,
                chain,
                DomainEvent::EntitySplit(EntitySplit {
                    original_id: entity_id,
                    new_ids: new_ids.clone(),
                    reason,
                }),
            )
            .await;
            println!("✅ entity {entity_id} split into {new_ids:?}");
        }
        SplitOutcome::NotActive => {
            println!(
                "entity {entity_id} is not active (missing, already split, or absorbed) — no-op"
            );
        }
        SplitOutcome::Invalid => bail!(
            "groups must exactly partition entity {entity_id}'s current membership \
             (no duplicates, no outsiders, none missing)"
        ),
    }
    Ok(())
}

/// Parse the `<label-id>` positional argument shared by the label CLI commands.
fn parse_label_id_arg(args: &mut impl Iterator<Item = String>) -> Result<LabelId> {
    let Some(raw) = args.next() else {
        bail!("missing label id; {USAGE}");
    };
    Ok(LabelId(raw.parse().map_err(|_| {
        anyhow::anyhow!("label id {raw:?} is not a UUID; {USAGE}")
    })?))
}

/// Resolve when the process receives Ctrl+C or (on Unix) SIGTERM.
async fn wait_for_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
