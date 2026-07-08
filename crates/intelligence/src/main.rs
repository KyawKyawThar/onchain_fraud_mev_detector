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
use intelligence::merge_actor::MergeActor;
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
                     `risk <address>`, `score`, `reorg`, \
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

    let consumer = build_consumer(&cfg.kafka.brokers, &cfg.kafka.group_id)
        .context("building the attribution Kafka consumer")?;
    attributor
        .run(consumer, PUBLISH_BACKOFF, &shutdown)
        .await
        .context("attribution consumer exited with error")?;

    tracing::info!("intelligence attribution consumer shut down");
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
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    let scorer = RiskScorer::new(StoreSeams::single(store), cache, sink, shutdown.clone());

    let consumer = risk_scorer::build_consumer(&cfg.kafka.brokers, &cfg.kafka.risk_group_id)
        .context("building the risk-score Kafka consumer")?;
    scorer
        .run(consumer, PUBLISH_BACKOFF, &shutdown)
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
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    let consumer = ReorgConsumer::new(StoreSeams::single(store), sink, shutdown.clone());

    let kafka_consumer = reorg::build_consumer(&cfg.kafka.brokers, &cfg.kafka.reorg_group_id)
        .context("building the reorg Kafka consumer")?;
    consumer
        .run(kafka_consumer, PUBLISH_BACKOFF, &shutdown)
        .await
        .context("reorg consumer exited with error")?;

    tracing::info!("intelligence reorg-rollback consumer shut down");
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
