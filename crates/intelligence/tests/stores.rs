//! Integration tests for the intelligence data stores (Sprint 7 t1) against
//! *real* Postgres, Redis and ClickHouse, spun up on demand via testcontainers.
//! Marked `#[ignore]` so the default `cargo test` stays hermetic; CI's
//! integration job (and `just test-integration`) run them.
//!
//! What is proven here — the §8 storage semantics the unit-tested doubles
//! promise, honoured by the real stores:
//!   1. conflicting labels coexist (never overwritten) and revocation is soft
//!      + idempotent (§8.1),
//!   2. entities version on merge, membership *moves* atomically, and the
//!      one-entity-per-address invariant holds (§8.2),
//!   3. attribution + sanctions writes are keyed upserts (idempotent
//!      re-import, §8.5),
//!   4. the Redis cache round-trips, expires by TTL and evicts whole
//!      addresses (§8),
//!   5. the ClickHouse graph reads degree-capped, direction-blind
//!      neighborhoods (§8.2 — the hub-node cap).

use alloy_primitives::Address;
use chrono::{DateTime, Utc};
use events::primitives::{Chain, EntityId, IncidentId};
use intelligence::adjacency::{AdjacencyStore, ClickhouseAdjacency};
use intelligence::cache::{CachedScore, HotCache, RedisHotCache};
use intelligence::model::{
    AdjacencyEdge, AttributionRecord, EdgeKind, EntityStatus, LabelKind, LabelRecord, LabelSource,
    SanctionEntry,
};
use intelligence::store::{
    AttributionStore, CreateOutcome, EntityStore, LabelStore, LinkOutcome, MergeOutcome,
    PgIntelligenceStore, SanctionsStore,
};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::clickhouse::{ClickHouse, CLICKHOUSE_PORT};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::redis::{Redis, REDIS_PORT};

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
}

fn addr(byte: u8) -> Address {
    Address::repeat_byte(byte)
}

/// Start a Postgres container, apply the workspace migrations, hand back the
/// store (plus the container guard — dropping it kills the database).
async fn pg_store() -> (
    PgIntelligenceStore,
    testcontainers::ContainerAsync<Postgres>,
) {
    let container = Postgres::default()
        .start()
        .await
        .expect("start Postgres container");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Postgres port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

    let pool = db::connect(&url).await.expect("connect");
    // The same migrations the `just migrate-*` recipes apply.
    sqlx::migrate!("../db/migrations")
        .run(&pool)
        .await
        .expect("apply migrations");
    (PgIntelligenceStore::new(pool), container)
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn conflicting_labels_coexist_and_revocation_is_soft() {
    let (store, _pg) = pg_store().await;
    let wallet = addr(0x11);

    // A heuristic and a manual claim about the same address: both stored,
    // both returned — §8.1's "stored, not overwritten".
    let heuristic = LabelRecord::new(
        wallet,
        LabelKind::MevBot,
        "searcher-42",
        LabelSource::Heuristic,
        "funding-cluster-v1",
        at(100),
    );
    let manual = LabelRecord::new(
        wallet,
        LabelKind::CexWallet,
        "binance 14",
        LabelSource::Manual,
        "operator:kkt",
        at(200),
    );
    assert!(store.add_label(&heuristic).await.expect("add heuristic"));
    assert!(store.add_label(&manual).await.expect("add manual"));
    // Redelivered LabelAdded (same label_id) is a no-op.
    assert!(!store.add_label(&manual).await.expect("redelivered add"));

    // A label valid only during [100, 150).
    let mut expiring = LabelRecord::new(
        wallet,
        LabelKind::Deployer,
        "old",
        LabelSource::ExternalFeed,
        "etherscan",
        at(100),
    );
    expiring.valid_until = Some(at(150));
    assert!(store.add_label(&expiring).await.expect("add expiring"));

    // `as_of` is an explicit input, so the read is deterministic: at t=250 the
    // expiring label has lapsed, both standing claims coexist.
    let active = store.labels_for(&wallet, at(250)).await.expect("read");
    assert_eq!(active.len(), 2, "conflicting labels coexist");
    assert_eq!(active[0], heuristic, "ordered by created_at");
    assert_eq!(active[1], manual);

    // At t=120 the expiring label is still valid and `manual` (created at
    // t=200) does not exist yet — the replay view of that instant.
    let past = store.labels_for(&wallet, at(120)).await.expect("read");
    assert_eq!(past.len(), 2);
    assert!(past.iter().any(|l| l.label_id == expiring.label_id));
    assert!(past.iter().all(|l| l.label_id != manual.label_id));

    // Revocation is soft (the row survives for audit), idempotent, and
    // authoritative — the revoked label vanishes for *every* as_of.
    assert!(store
        .revoke_label(heuristic.label_id, "false positive", at(300))
        .await
        .expect("revoke"));
    assert!(!store
        .revoke_label(heuristic.label_id, "again", at(301))
        .await
        .expect("re-revoke is a no-op"));
    let active = store.labels_for(&wallet, at(250)).await.expect("read");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].label_id, manual.label_id);
    let past = store.labels_for(&wallet, at(120)).await.expect("read");
    assert_eq!(
        past.iter().map(|l| l.label_id).collect::<Vec<_>>(),
        vec![expiring.label_id],
        "a withdrawn label must not resurface in replay"
    );

    // A different address sees nothing.
    assert!(store
        .labels_for(&addr(0x99), at(250))
        .await
        .expect("read other")
        .is_empty());
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn entities_version_on_merge_and_membership_moves_atomically() {
    let (store, _pg) = pg_store().await;
    let (e1, e2) = (EntityId::new(), EntityId::new());
    let (a1, a2, a3) = (addr(0x01), addr(0x02), addr(0x03));

    // Create + idempotent redelivery.
    assert_eq!(
        store
            .create_entity(e1, &a1, "seed", at(10))
            .await
            .expect("create e1"),
        CreateOutcome::Created
    );
    assert_eq!(
        store
            .create_entity(e1, &a1, "seed", at(10))
            .await
            .expect("recreate e1"),
        CreateOutcome::AlreadyExists
    );
    // A create over an owned seed reports the owner and writes nothing.
    let stolen = EntityId::new();
    assert_eq!(
        store
            .create_entity(stolen, &a1, "seed", at(11))
            .await
            .expect("create over owned seed"),
        CreateOutcome::SeedOwnedBy(e1)
    );
    assert!(
        store.entity(stolen).await.expect("read").is_none(),
        "rolled back — no half-created entity"
    );

    // Second entity with two members.
    assert_eq!(
        store
            .create_entity(e2, &a2, "seed", at(20))
            .await
            .expect("create e2"),
        CreateOutcome::Created
    );
    assert_eq!(
        store
            .link_address(e2, &a3, "common funder 0x02", at(21))
            .await
            .expect("link a3"),
        LinkOutcome::Linked
    );
    assert_eq!(
        store
            .link_address(e2, &a3, "again", at(22))
            .await
            .expect("relink a3"),
        LinkOutcome::AlreadyMember
    );
    // The membership invariant: a1 belongs to e1, e2 can't take it.
    assert_eq!(
        store
            .link_address(e2, &a1, "grab", at(23))
            .await
            .expect("link owned"),
        LinkOutcome::OwnedBy(e1)
    );

    // Merge e2 into e1: both versions bump, membership moves, e2 tombstones.
    assert_eq!(
        store.absorb(e1, e2).await.expect("merge"),
        MergeOutcome::Merged {
            survivor_version: 2
        }
    );
    let survivor = store.entity(e1).await.expect("read").expect("e1 exists");
    assert_eq!(survivor.version, 2);
    assert_eq!(survivor.status, EntityStatus::Active);
    let mut members = survivor.addresses.clone();
    members.sort();
    assert_eq!(members, vec![a1, a2, a3], "membership moved to survivor");

    let tombstone = store.entity(e2).await.expect("read").expect("e2 kept");
    assert_eq!(tombstone.status, EntityStatus::Absorbed);
    assert_eq!(tombstone.absorbed_into, Some(e1));
    assert_eq!(tombstone.version, 2, "absorbed version bumped too");
    assert!(tombstone.addresses.is_empty(), "no addresses left behind");
    assert_eq!(
        store.entity_for_address(&a2).await.expect("owner"),
        Some(e1)
    );

    // Merge edge cases: redelivery, merging into a tombstone, self-merge.
    assert_eq!(
        store.absorb(e1, e2).await.expect("redelivered merge"),
        MergeOutcome::AbsorbedInactive
    );
    assert_eq!(
        store.absorb(e2, e1).await.expect("merge into tombstone"),
        MergeOutcome::SurvivorInactive
    );
    assert_eq!(
        store.absorb(e1, e1).await.expect("self merge"),
        MergeOutcome::SelfMerge
    );
    let survivor = store.entity(e1).await.expect("read").expect("e1");
    assert_eq!(survivor.version, 2, "failed merges bump nothing");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn attribution_upserts_and_sanctions_reimport_idempotently() {
    let (store, _pg) = pg_store().await;

    // Attribution needs a real entity (FK).
    let entity = EntityId::new();
    let incident = IncidentId::new();
    store
        .create_entity(entity, &addr(0x21), "seed", at(10))
        .await
        .expect("create entity");

    let first = AttributionRecord {
        incident_id: incident,
        entity_id: entity,
        confidence: events::primitives::Confidence::new(0.6),
        evidence: "label:heuristic".to_string(),
        attributed_at: at(100),
    };
    store
        .record_attribution(&first)
        .await
        .expect("first attribution");
    // Re-attribution (redelivered IncidentCreated, fresher evidence) upserts.
    let fresher = AttributionRecord {
        confidence: events::primitives::Confidence::new(0.9),
        evidence: "label:manual + sim:confirmed".to_string(),
        attributed_at: at(200),
        ..first
    };
    store
        .record_attribution(&fresher)
        .await
        .expect("upsert attribution");

    let by_incident = store
        .attributions_for_incident(incident)
        .await
        .expect("by incident");
    assert_eq!(by_incident.len(), 1, "keyed upsert: one link");
    assert_eq!(by_incident[0], fresher);
    let by_entity = store
        .attributions_for_entity(entity)
        .await
        .expect("by entity");
    assert_eq!(by_entity, by_incident);

    // Sanctions: one address on two lists; a feed refresh upserts in place.
    let sanctioned = addr(0x66);
    let entries = vec![
        SanctionEntry {
            address: sanctioned,
            list_name: "ofac_sdn".into(),
            entry: "LAZARUS GROUP".into(),
            listed_at: Some(at(1_000)),
        },
        SanctionEntry {
            address: sanctioned,
            list_name: "eu_consolidated".into(),
            entry: "Lazarus".into(),
            listed_at: None,
        },
    ];
    store.seed_sanctions(&entries).await.expect("seed");
    store.seed_sanctions(&entries).await.expect("re-import");

    let matches = store
        .sanction_matches(&sanctioned)
        .await
        .expect("match sanctioned");
    assert_eq!(matches.len(), 2, "re-import added nothing");
    assert_eq!(matches[0].list_name, "eu_consolidated");
    assert_eq!(matches[1].entry, "LAZARUS GROUP");
    assert!(
        store
            .sanction_matches(&addr(0x67))
            .await
            .expect("clean address")
            .is_empty(),
        "no false positives"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Redis)"]
async fn hot_cache_round_trips_expires_and_evicts() {
    let container = Redis::default().start().await.expect("start Redis");
    let port = container
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("Redis port");
    let url = format!("redis://127.0.0.1:{port}");

    let cache = RedisHotCache::connect(&url, std::time::Duration::from_secs(60))
        .await
        .expect("connect");
    let wallet = addr(0x31);

    // Labels round-trip.
    assert_eq!(cache.labels(&wallet).await.expect("cold read"), None);
    let labels = vec![LabelRecord::new(
        wallet,
        LabelKind::MevBot,
        "searcher-42",
        LabelSource::Heuristic,
        "funding-cluster-v1",
        at(100),
    )];
    cache.put_labels(&wallet, &labels).await.expect("put");
    assert_eq!(
        cache.labels(&wallet).await.expect("warm read"),
        Some(labels)
    );

    // Scores are keyed (address, model_version) — §8.3.
    let v1 = CachedScore {
        score: 87,
        confidence: events::primitives::Confidence::new(0.91),
        model_version: "1.4.2".into(),
        computed_at: at(500),
    };
    let v2 = CachedScore {
        score: 42,
        confidence: events::primitives::Confidence::new(0.4),
        model_version: "2.0.0".into(),
        computed_at: at(600),
    };
    cache.put_score(&wallet, &v1).await.expect("put v1");
    cache.put_score(&wallet, &v2).await.expect("put v2");
    assert_eq!(
        cache.score(&wallet, "1.4.2").await.expect("read v1"),
        Some(v1)
    );
    assert_eq!(
        cache.score(&wallet, "2.0.0").await.expect("read v2"),
        Some(v2.clone())
    );
    assert_eq!(cache.score(&wallet, "9.9.9").await.expect("unknown"), None);

    // Evict drops *everything* for the address — the on-update semantics.
    cache.evict(&wallet).await.expect("evict");
    assert_eq!(cache.labels(&wallet).await.expect("evicted"), None);
    assert_eq!(cache.score(&wallet, "2.0.0").await.expect("evicted"), None);

    // The TTL backstop: a 1s-TTL entry expires on its own.
    let brief = RedisHotCache::connect(&url, std::time::Duration::from_secs(1))
        .await
        .expect("connect brief");
    brief
        .put_score(&wallet, &v2)
        .await
        .expect("put with 1s ttl");
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    assert_eq!(
        brief.score(&wallet, "2.0.0").await.expect("expired"),
        None,
        "TTL reaped the entry"
    );

    // evict_many (the pipelined seed-import path) drops every listed address
    // in one round-trip and leaves others alone.
    let (a, b, untouched) = (addr(0x41), addr(0x42), addr(0x43));
    for wallet in [&a, &b, &untouched] {
        cache
            .put_score(wallet, &v2)
            .await
            .expect("put for evict_many");
    }
    cache.evict_many(&[a, b]).await.expect("evict_many");
    assert_eq!(cache.score(&a, "2.0.0").await.expect("evicted a"), None);
    assert_eq!(cache.score(&b, "2.0.0").await.expect("evicted b"), None);
    assert_eq!(
        cache.score(&untouched, "2.0.0").await.expect("kept"),
        Some(v2),
        "evict_many must not touch unlisted addresses"
    );
}

/// The batched label insert (`add_labels`, the seed-import path) honours the
/// same keyed-idempotency contract as `add_label`: a re-imported slice inserts
/// nothing, a partially-new slice inserts exactly the new rows, an in-slice
/// duplicate id neither errors nor double-counts — and conflicting claims
/// coexist (§8.1).
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn label_batch_insert_is_keyed_idempotent_and_coexists() {
    let (store, _pg) = pg_store().await;
    let wallet = addr(0x51);

    let bot_a = LabelRecord::new(
        wallet,
        LabelKind::MevBot,
        "bot-a",
        LabelSource::ExternalFeed,
        "community_mev_list",
        at(10),
    );
    // A later created_at than bot-a: `labels_for` orders by (created_at,
    // label_id), and the ids here are random v4s — same-instant order would
    // be nondeterministic.
    let bot_b = LabelRecord::new(
        wallet,
        LabelKind::MevBot,
        "bot-b",
        LabelSource::ExternalFeed,
        "community_mev_list",
        at(11),
    );

    let batch = vec![bot_a.clone(), bot_b.clone()];
    assert_eq!(store.add_labels(&batch).await.expect("first import"), 2);
    assert_eq!(
        store.add_labels(&batch).await.expect("re-import"),
        0,
        "a re-imported batch is a keyed no-op"
    );

    // A refreshed feed: one old claim, one new — only the new row lands, and
    // both values coexist afterwards (stored, not overwritten).
    let renamed = LabelRecord::new(
        wallet,
        LabelKind::MevBot,
        "bot-a (renamed)",
        LabelSource::ExternalFeed,
        "community_mev_list",
        at(20),
    );
    assert_eq!(
        store
            .add_labels(&[bot_a.clone(), renamed.clone()])
            .await
            .expect("refresh"),
        1
    );
    let values: Vec<String> = store
        .labels_for(&wallet, at(1_000))
        .await
        .expect("read back")
        .into_iter()
        .map(|label| label.value)
        .collect();
    assert_eq!(values, ["bot-a", "bot-b", "bot-a (renamed)"]);

    // An in-slice duplicate id is tolerated by ON CONFLICT DO NOTHING and
    // counts once (the parsers dedup, but the store must not depend on it).
    let dup = LabelRecord::new(
        addr(0x52),
        LabelKind::Protocol,
        "Router",
        LabelSource::ExternalFeed,
        "protocol_registry",
        at(30),
    );
    assert_eq!(
        store
            .add_labels(&[dup.clone(), dup.clone()])
            .await
            .expect("duplicate slice"),
        1
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers ClickHouse)"]
async fn adjacency_neighborhoods_are_degree_capped_and_direction_blind() {
    let container = ClickHouse::default()
        .start()
        .await
        .expect("start ClickHouse container");
    let http_port = container
        .get_host_port_ipv4(CLICKHOUSE_PORT)
        .await
        .expect("ClickHouse port");
    let client = clickhouse::Client::default()
        .with_url(format!("http://127.0.0.1:{http_port}"))
        .with_user("default")
        .with_database("default");

    intelligence::ch_migrate::MIGRATOR
        .run(&client)
        .await
        .expect("apply adjacency migration");
    let graph = ClickhouseAdjacency::new(client);

    let hub = addr(0xAA);
    let edge = |src: Address, dst: Address, kind: EdgeKind, block: u64| AdjacencyEdge {
        chain: Chain::ETHEREUM,
        src,
        dst,
        kind,
        evidence: format!("0xtx{block:02x}"),
        block_number: block,
        observed_at: at(block as i64),
    };

    // Five outbound edges, one inbound, one duplicate observation, one on
    // another chain.
    let mut edges: Vec<AdjacencyEdge> = (1..=5)
        .map(|n| edge(hub, addr(n), EdgeKind::Funded, n as u64))
        .collect();
    edges.push(edge(addr(0x10), hub, EdgeKind::ProfitReceiver, 6));
    edges.push(edge(hub, addr(1), EdgeKind::Funded, 1)); // duplicate fact
    edges.push(AdjacencyEdge {
        chain: Chain(10),
        ..edge(hub, addr(0x77), EdgeKind::Deployed, 7)
    });
    graph.append(&edges).await.expect("append edges");

    // Uncapped: all six distinct neighbors, both directions, one chain.
    let all = graph
        .neighbors(Chain::ETHEREUM, &hub, 10)
        .await
        .expect("read neighborhood");
    assert!(!all.capped);
    assert_eq!(all.neighbors.len(), 6, "distinct + direction-blind");
    assert!(all.neighbors.contains(&addr(0x10)), "inbound edge counted");
    assert!(
        !all.neighbors.contains(&addr(0x77)),
        "other chain invisible"
    );
    assert_eq!(
        graph
            .degree(Chain::ETHEREUM, &hub)
            .await
            .expect("hub degree"),
        6
    );

    // The §8.2 hub cap: at cap 3 the walk gets 3 neighbors and a stop signal.
    let capped = graph
        .neighbors(Chain::ETHEREUM, &hub, 3)
        .await
        .expect("read capped");
    assert!(capped.capped, "hub reported as capped");
    assert_eq!(capped.neighbors.len(), 3);
    let mut sorted = capped.neighbors.clone();
    sorted.sort();
    assert_eq!(capped.neighbors, sorted, "deterministic order");

    // A leaf sees only the hub.
    let leaf = graph
        .neighbors(Chain::ETHEREUM, &addr(1), 10)
        .await
        .expect("leaf neighborhood");
    assert_eq!(leaf.neighbors, vec![hub]);
    assert!(!leaf.capped);
}
