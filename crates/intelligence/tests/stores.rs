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
use events::primitives::{Chain, EntityId, IncidentId, LabelId};
use intelligence::adjacency::{AdjacencyStore, ClickhouseAdjacency, Shard};
use intelligence::cache::{CachedScore, HotCache, RedisHotCache};
use intelligence::model::{
    AdjacencyEdge, AttributionRecord, EdgeKind, EntityStatus, LabelKind, LabelRecord, LabelSource,
    SanctionEntry,
};
use intelligence::store::{
    AttributionStore, CreateOutcome, EntityStore, LabelStore, LinkOutcome, MergeOutcome,
    PgIntelligenceStore, SanctionsStore, SplitOutcome,
};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::clickhouse::{ClickHouse, CLICKHOUSE_PORT};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::redis::{Redis, REDIS_PORT};

/// ClickHouse image tag these tests run against — pinned to the tag the K8s
/// manifests deploy (`deploy/k8s/base/infra/clickhouse.yaml`), not the
/// testcontainers module's default.
///
/// The default is `23.3`, which predates the `vector_similarity` index type
/// entirely: migration 0007 would fail to apply and take *every* ClickHouse
/// test here down with it. Testing schema migrations against an older server
/// than production runs is how a migration that cannot apply ships green.
const CLICKHOUSE_TAG: &str = "25.6";

/// Start a ClickHouse matching the deployed version and hand back a client for
/// it. The container is returned so the caller keeps it alive for the test.
///
/// `CLICKHOUSE_SKIP_USER_SETUP` is required from 25.x on: newer images refuse
/// to start a passwordless `default` user without it, and the failure surfaces
/// as an authentication error on the first query rather than a startup one.
async fn start_clickhouse() -> (
    testcontainers::ContainerAsync<ClickHouse>,
    clickhouse::Client,
) {
    use testcontainers::ImageExt;

    let container = ClickHouse::default()
        .with_tag(CLICKHOUSE_TAG)
        .with_env_var("CLICKHOUSE_SKIP_USER_SETUP", "1")
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
    (container, client)
}

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
async fn label_lookup_and_value_correction_are_narrow_mutations() {
    let (store, _pg) = pg_store().await;
    let wallet = addr(0x22);

    let label = LabelRecord::new(
        wallet,
        LabelKind::CexWallet,
        "Binance 14 (typo)",
        LabelSource::Manual,
        "operator:kkt",
        at(100),
    );
    store.add_label(&label).await.expect("add");

    // `label()` is the identity read: found regardless of revocation.
    assert_eq!(
        store.label(label.label_id).await.expect("lookup"),
        Some(label.clone())
    );
    assert_eq!(
        store.label(LabelId::new()).await.expect("lookup unknown"),
        None
    );

    // Correcting the value in place keeps the same label_id — one row, not a
    // new coexisting claim.
    let before = store
        .update_label_value(label.label_id, "Binance 14")
        .await
        .expect("correct")
        .expect("label exists");
    assert_eq!(before.value, "Binance 14 (typo)");
    let active = store.labels_for(&wallet, at(1_000)).await.expect("read");
    assert_eq!(active.len(), 1, "corrected in place, not duplicated");
    assert_eq!(active[0].value, "Binance 14");
    assert_eq!(active[0].label_id, label.label_id);

    // A revoked row is frozen: the correction is refused, not silently
    // applied to dead history.
    store
        .revoke_label(label.label_id, "withdrawn", at(200))
        .await
        .expect("revoke");
    assert_eq!(
        store
            .update_label_value(label.label_id, "should not land")
            .await
            .expect("attempt correction on revoked"),
        None
    );
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
        store
            .absorb(e1, e2, None, "test", at(30))
            .await
            .expect("merge"),
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
        store
            .absorb(e1, e2, None, "test", at(31))
            .await
            .expect("redelivered merge"),
        MergeOutcome::AbsorbedInactive
    );
    assert_eq!(
        store
            .absorb(e2, e1, None, "test", at(32))
            .await
            .expect("merge into tombstone"),
        MergeOutcome::SurvivorInactive
    );
    assert_eq!(
        store
            .absorb(e1, e1, None, "test", at(33))
            .await
            .expect("self merge"),
        MergeOutcome::SelfMerge
    );
    let survivor = store.entity(e1).await.expect("read").expect("e1");
    assert_eq!(survivor.version, 2, "failed merges bump nothing");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn split_reverses_a_merge_atomically_and_is_idempotent_against_redelivery() {
    let (store, _pg) = pg_store().await;
    let entity_id = EntityId::new();
    let (a1, a2, a3) = (addr(0x31), addr(0x32), addr(0x33));

    store
        .create_entity(entity_id, &a1, "seed", at(1))
        .await
        .expect("create");
    store
        .link_address(entity_id, &a2, "cluster", at(1))
        .await
        .expect("link a2");
    store
        .link_address(entity_id, &a3, "cluster", at(1))
        .await
        .expect("link a3");

    let groups = vec![vec![a1, a2], vec![a3]];
    let SplitOutcome::Split { new_ids } = store
        .split(entity_id, &groups, "operator:kkt", at(10))
        .await
        .expect("split")
    else {
        panic!("expected a successful split");
    };
    assert_eq!(new_ids.len(), 2);

    // The original is tombstoned `Split` and owns nothing.
    let original = store.entity(entity_id).await.expect("read").expect("kept");
    assert_eq!(original.status, EntityStatus::Split);
    assert!(original.addresses.is_empty());

    // Membership moved exactly along the requested groups.
    assert_eq!(
        store.entity_for_address(&a1).await.expect("owner"),
        Some(new_ids[0])
    );
    assert_eq!(
        store.entity_for_address(&a2).await.expect("owner"),
        Some(new_ids[0])
    );
    assert_eq!(
        store.entity_for_address(&a3).await.expect("owner"),
        Some(new_ids[1])
    );
    let first = store
        .entity(new_ids[0])
        .await
        .expect("read")
        .expect("exists");
    let mut members = first.addresses.clone();
    members.sort();
    assert_eq!(members, vec![a1, a2]);

    // A redelivered split request against the now-tombstoned original is a
    // no-op, not a second split — at-least-once safe.
    assert_eq!(
        store
            .split(entity_id, &groups, "operator:kkt", at(20))
            .await
            .expect("redelivered split"),
        SplitOutcome::NotActive
    );

    // An invalid partition (missing a3) is rejected before anything is
    // written, and a self-merge-style no-op leaves membership untouched.
    let other = EntityId::new();
    store
        .create_entity(other, &addr(0x44), "seed", at(1))
        .await
        .expect("create other");
    assert_eq!(
        store
            .split(other, &[vec![addr(0x44), a1]], "op", at(30))
            .await
            .expect("invalid split"),
        SplitOutcome::Invalid,
        "a1 no longer belongs to `other` — not a valid partition of its membership"
    );
    assert_eq!(
        store
            .entity(other)
            .await
            .expect("read")
            .expect("kept")
            .status,
        EntityStatus::Active,
        "a rejected split must not have tombstoned the entity"
    );
}

/// The regression test for the race `lock_entities` closes: a `link_address`
/// racing a `split` on the same entity must never strand a membership row on
/// a tombstoned entity. Before the entity-row locking was added, this could
/// interleave as: `split` reads membership (missing the new address, since
/// `link_address` hasn't committed yet) → `link_address` commits the new
/// member → `split` tombstones the original using its stale read — leaving
/// the new member's `entity_addresses` row pointing at a dead entity forever.
///
/// With the lock, the two transactions strictly serialize per entity, so
/// only two outcome pairs are possible regardless of scheduling — asserted
/// across many trials (real thread/tokio scheduling, not simulated) to shake
/// out both orderings rather than relying on one lucky interleaving:
///   - `link_address` commits first → `split`'s membership read now includes
///     the new address, which isn't in any requested group, so `split`
///     correctly rejects as `Invalid` (nothing tombstoned, nothing stranded).
///   - `split` locks first → it tombstones the original using the *prior*
///     (correct) membership; `link_address` then sees the entity is no
///     longer active and refuses with `TargetInactive` — the address is
///     never linked anywhere, not stranded.
/// Any *other* pairing (both succeeding) would mean a membership row got
/// orphaned, which is exactly the bug this test guards against.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn concurrent_split_and_link_address_never_strands_a_membership_row() {
    let (store, _pg) = pg_store().await;

    for trial in 0u8..20 {
        let entity_id = EntityId::new();
        let base = trial.wrapping_mul(4);
        let (a1, a2, a3, new_addr) = (
            addr(base + 1),
            addr(base + 2),
            addr(base + 3),
            addr(base + 4),
        );
        store
            .create_entity(entity_id, &a1, "seed", at(1))
            .await
            .expect("create");
        store
            .link_address(entity_id, &a2, "cluster", at(1))
            .await
            .expect("link a2");
        store
            .link_address(entity_id, &a3, "cluster", at(1))
            .await
            .expect("link a3");

        let groups = vec![vec![a1, a2], vec![a3]];
        let (store_a, groups_a) = (store.clone(), groups.clone());
        let store_b = store.clone();

        let (link_outcome, split_outcome) = tokio::join!(
            async move {
                store_a
                    .link_address(entity_id, &new_addr, "racing link", at(10))
                    .await
                    .expect("link_address")
            },
            async move {
                store_b
                    .split(entity_id, &groups_a, "racing split", at(10))
                    .await
                    .expect("split")
            },
        );

        match (link_outcome, split_outcome) {
            (LinkOutcome::Linked, SplitOutcome::Invalid) => {
                // The link won: it must have landed on the still-active
                // original entity, not been silently dropped.
                assert_eq!(
                    store.entity_for_address(&new_addr).await.expect("owner"),
                    Some(entity_id),
                    "trial {trial}: link won the race but its member vanished"
                );
                assert_eq!(
                    store.entity(entity_id).await.expect("read").unwrap().status,
                    EntityStatus::Active,
                    "trial {trial}: a rejected split must not tombstone the entity"
                );
            }
            (LinkOutcome::TargetInactive, SplitOutcome::Split { new_ids }) => {
                // The split won: the new address must never have landed
                // anywhere — not stranded on the now-dead original.
                assert_eq!(
                    store.entity_for_address(&new_addr).await.expect("owner"),
                    None,
                    "trial {trial}: split won the race but the late link still stranded a row"
                );
                assert_eq!(new_ids.len(), 2);
            }
            other => panic!(
                "trial {trial}: impossible interleaving {other:?} — a membership \
                 row was orphaned on a tombstoned entity"
            ),
        }
    }
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

    // The screening bundle (§11) round-trips whole.
    assert_eq!(
        cache.screening_facts(&wallet).await.expect("cold read"),
        None
    );
    let facts = intelligence::cache::CachedScreeningFacts {
        score: 87,
        confidence: events::primitives::Confidence::new(0.91),
        model_version: "1.4.2".into(),
        computed_at: at(500),
        sanctions: vec![intelligence::model::SanctionEntry {
            address: wallet,
            list_name: "ofac_sdn".into(),
            entry: "Evil Corp".into(),
            listed_at: None,
        }],
        labels: cache.labels(&wallet).await.expect("labels").unwrap(),
        entity_id: Some(events::primitives::EntityId::new()),
        entity_size: 3,
        factors: vec![events::intelligence::RiskFactor {
            name: "sanctions-match".into(),
            delta: 45.0,
            evidence_ref: "sanction:ofac_sdn:Evil Corp".into(),
        }],
    };
    cache
        .put_screening_facts(&wallet, &facts)
        .await
        .expect("put screening facts");
    assert_eq!(
        cache.screening_facts(&wallet).await.expect("warm read"),
        Some(facts)
    );

    // Evict drops *everything* for the address — the on-update semantics.
    cache.evict(&wallet).await.expect("evict");
    assert_eq!(cache.labels(&wallet).await.expect("evicted"), None);
    assert_eq!(cache.score(&wallet, "2.0.0").await.expect("evicted"), None);
    assert_eq!(
        cache.screening_facts(&wallet).await.expect("evicted"),
        None,
        "evict clears the screening bundle too"
    );

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
    let (_container, client) = start_clickhouse().await;

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

    // The batched read (`neighbors_many`, the entity-graph walk's hot path)
    // must agree with looping single `neighbors` for every input — including a
    // capped hub, a leaf, and an address with no edges at all — and return one
    // entry per requested address.
    let frontier = [hub, addr(1), addr(0xEE)];
    let batched = graph
        .neighbors_many(Chain::ETHEREUM, &frontier, 3)
        .await
        .expect("batched neighborhoods");
    assert_eq!(batched.len(), frontier.len(), "one entry per input address");
    for a in frontier {
        let single = graph
            .neighbors(Chain::ETHEREUM, &a, 3)
            .await
            .expect("single neighborhood");
        assert_eq!(batched[&a], single, "batched disagrees with single for {a}");
    }
    assert!(batched[&hub].capped, "the hub is capped in the batch too");
    assert!(
        !batched[&addr(0xEE)].capped && batched[&addr(0xEE)].neighbors.is_empty(),
        "an edgeless address maps to an empty, un-capped neighborhood"
    );
}

/// The two §20.3 adjacency reads the behavior embedding is built on, against a
/// real ClickHouse — the queries the in-memory double only *promises* to
/// mirror.
///
/// What's proven here and cannot be by a double: the `DISTINCT`-inside/
/// project-outside shape actually collapses a re-appended observation while
/// keeping two genuine ones; the `UNION ALL` direction projection really does
/// resolve `src`/`dst` into subject-relative `outbound`; the truncation order
/// is the one the SQL declares; and the cursor-paged sweep read makes
/// monotonic progress rather than re-serving its own prefix.
#[tokio::test]
#[ignore = "requires Docker (testcontainers ClickHouse)"]
async fn adjacency_edge_history_and_active_addresses_back_the_embedding_job() {
    let (_container, client) = start_clickhouse().await;

    intelligence::ch_migrate::MIGRATOR
        .run(&client)
        .await
        .expect("apply intelligence migrations");
    let graph = ClickhouseAdjacency::new(client);

    let subject = addr(0xAA);
    let edge = |src: Address, dst: Address, kind: EdgeKind, block: u64| AdjacencyEdge {
        chain: Chain::ETHEREUM,
        src,
        dst,
        kind,
        evidence: format!("0xtx{block:02x}"),
        block_number: block,
        observed_at: at(block as i64 * 3_600),
    };

    let mut edges = vec![
        edge(subject, addr(1), EdgeKind::Funded, 1),
        edge(addr(2), subject, EdgeKind::ProfitReceiver, 2),
        edge(subject, addr(1), EdgeKind::Interacted, 3),
    ];
    // A *re-appended* observation (identical in every column) — one fact.
    edges.push(edge(subject, addr(1), EdgeKind::Funded, 1));
    // Another chain, and an edge that doesn't touch the subject.
    edges.push(AdjacencyEdge {
        chain: Chain(10),
        ..edge(subject, addr(0x77), EdgeKind::Funded, 4)
    });
    edges.push(edge(addr(3), addr(4), EdgeKind::Interacted, 5));
    graph.append(&edges).await.expect("append edges");

    let history = graph
        .edge_history(Chain::ETHEREUM, &subject, 10)
        .await
        .expect("read edge history");
    assert!(!history.truncated);
    assert_eq!(
        history.edges.len(),
        3,
        "the re-appended observation collapsed; the other chain is invisible"
    );
    // Most recent first — the truncation order the cap depends on.
    assert!(history.edges[0].observed_at >= history.edges[1].observed_at);
    assert!(history.edges[1].observed_at >= history.edges[2].observed_at);
    // Direction is resolved relative to the subject, not to src/dst.
    let inbound = history
        .edges
        .iter()
        .find(|e| e.kind == EdgeKind::ProfitReceiver)
        .expect("the inbound edge is present");
    assert!(!inbound.outbound);
    assert_eq!(inbound.counterparty, addr(2));
    assert!(history
        .edges
        .iter()
        .any(|e| e.outbound && e.counterparty == addr(1)));

    // The cap reports truncation and keeps the *most recent* window.
    let capped = graph
        .edge_history(Chain::ETHEREUM, &subject, 2)
        .await
        .expect("read capped history");
    assert!(capped.truncated);
    assert_eq!(capped.edges.len(), 2);
    assert_eq!(capped.edges[0].observed_at, history.edges[0].observed_at);

    // The sweep read: every address with an observation in the window, paged
    // by cursor, making monotonic progress.
    let all = graph
        .active_addresses(Chain::ETHEREUM, at(0), None, 100, Shard::SINGLE)
        .await
        .expect("active addresses");
    assert!(all.contains(&subject) && all.contains(&addr(3)) && all.contains(&addr(4)));
    assert!(
        !all.contains(&addr(0x77)),
        "the other chain's addresses are invisible"
    );
    let mut sorted = all.clone();
    sorted.sort();
    assert_eq!(
        all, sorted,
        "ascending address order — the cursor's ordering"
    );

    let first_page = graph
        .active_addresses(Chain::ETHEREUM, at(0), None, 2, Shard::SINGLE)
        .await
        .expect("first page");
    assert_eq!(first_page.len(), 2);
    let next_page = graph
        .active_addresses(
            Chain::ETHEREUM,
            at(0),
            first_page.last().copied(),
            2,
            Shard::SINGLE,
        )
        .await
        .expect("second page");
    assert!(
        next_page.iter().all(|a| a > first_page.last().unwrap()),
        "the cursor advances strictly — a sweep cannot re-serve its own prefix"
    );

    // The recency floor is what bounds a sweep's work.
    let recent = graph
        .active_addresses(Chain::ETHEREUM, at(5 * 3_600), None, 100, Shard::SINGLE)
        .await
        .expect("recent-only");
    assert_eq!(recent, vec![addr(3), addr(4)]);
}

/// The §20.3 embedding store against a real ClickHouse: an append-only table
/// whose latest-per-`(chain, address, version)` read is what a similarity
/// search and a recompute both stand on.
#[tokio::test]
#[ignore = "requires Docker (testcontainers ClickHouse)"]
async fn embedding_store_reads_back_the_latest_vector_per_version() {
    use intelligence::embedding::v1::{SCHEMA as V1_SCHEMA, VERSION as EMBEDDING_VERSION};
    use intelligence::embedding::{default_embedder, BehaviorInputs};
    use intelligence::embedding_store::{ClickhouseEmbeddingStore, EmbeddingStore};

    let (_container, client) = start_clickhouse().await;

    intelligence::ch_migrate::MIGRATOR
        .run(&client)
        .await
        .expect("apply intelligence migrations");
    let store = ClickhouseEmbeddingStore::new(client);

    let subject = addr(0xBB);
    let entity_id = EntityId(uuid::Uuid::from_u128(0xE1));

    // Two computations of the same address, and one of a different address —
    // the older one first, so "latest" cannot be "last inserted by accident".
    let newer = default_embedder().embed(
        subject,
        Some(entity_id),
        &BehaviorInputs::default(),
        at(2_000),
    );
    let older = default_embedder().embed(subject, None, &BehaviorInputs::default(), at(1_000));
    let other = default_embedder().embed(addr(0xCC), None, &BehaviorInputs::default(), at(3_000));
    store
        .append(Chain::ETHEREUM, &[newer.clone(), older, other])
        .await
        .expect("append vectors");

    let latest = store
        .latest(Chain::ETHEREUM, &subject, EMBEDDING_VERSION)
        .await
        .expect("read latest")
        .expect("the address has been embedded");

    assert_eq!(latest.computed_at, newer.computed_at);
    assert_eq!(latest.values, newer.values);
    assert_eq!(latest.entity_id, Some(entity_id));
    assert_eq!(latest.top_factors, newer.to_event().top_factors);
    assert!(latest.matches(EMBEDDING_VERSION, newer.schema_hash()));
    assert_eq!(latest.values.len(), V1_SCHEMA.dimension());

    // A version nobody has written under is a miss, not a wrong-space answer.
    assert!(store
        .latest(Chain::ETHEREUM, &subject, "behavior-v99")
        .await
        .expect("read unknown version")
        .is_none());
    // …and so is an address nobody has embedded.
    assert!(store
        .latest(Chain::ETHEREUM, &addr(0xDD), EMBEDDING_VERSION)
        .await
        .expect("read unknown address")
        .is_none());

    // Append-only: re-appending the identical vector is a harmless extra row
    // the latest-per-key read collapses (an idempotent recompute).
    store
        .append(Chain::ETHEREUM, std::slice::from_ref(&newer))
        .await
        .expect("re-append");
    let again = store
        .latest(Chain::ETHEREUM, &subject, EMBEDDING_VERSION)
        .await
        .expect("read latest again")
        .expect("still present");
    assert_eq!(again.values, newer.values);
}

/// The §20.3 similarity search against a real ClickHouse — the one place the
/// `vector_similarity` index, the query that must use it, and the exact
/// re-rank above it are exercised together.
///
/// Three things here cannot be checked anywhere else:
///
/// 1. **Migration 0007 applies at all.** `vector_similarity` is an
///    experimental index type whose DDL is rejected without a query-level
///    setting, and the setting rides in the migration's own SQL. A unit test
///    cannot tell whether ClickHouse accepted it.
/// 2. **The index does not reject the embedding job's writes.** An indexed
///    vector column hard-refuses any array of a different length, so an
///    ordinary `append` after the index exists is the regression this guards.
/// 3. **The candidate query is the one the index can serve.** The float
///    rendering in `vector_literal` is the difference between an
///    index-accelerated read and a silent full scan that returns the same
///    rows — so the plan itself is asserted, not just the answer.
#[tokio::test]
#[ignore = "requires Docker (testcontainers ClickHouse)"]
async fn similarity_search_ranks_against_a_real_clickhouse_vector_index() {
    use intelligence::embedding::v1::VERSION as EMBEDDING_VERSION;
    use intelligence::embedding::{baseline, default_embedder, BehaviorInputs};
    use intelligence::embedding_store::{ClickhouseEmbeddingStore, EmbeddingStore};
    use intelligence::similarity::{self, SimilarityLimits, INDEXED_DIMENSION};

    let (_container, client) = start_clickhouse().await;
    intelligence::ch_migrate::MIGRATOR
        .run(&client)
        .await
        .expect("apply intelligence migrations (0007 adds the vector index)");

    // The index really is on the column, with the arity the code believes.
    let create: String = client
        .query("SHOW CREATE TABLE address_embeddings")
        .fetch_one()
        .await
        .expect("read the table definition");
    assert!(
        create.contains("idx_embedding_vector"),
        "migration 0007 did not add the vector index: {create}"
    );
    assert!(
        create.contains(&format!("cosineDistance', {INDEXED_DIMENSION}")),
        "the index arity must match INDEXED_DIMENSION: {create}"
    );

    let store = ClickhouseEmbeddingStore::new(client.clone());
    let embedder = default_embedder();
    let schema = embedder.schema();

    // A population varying along one legible axis: the subject at 5.0, its
    // nearest behavioral neighbour at 4.0, and an opposite at -5.0.
    let population: Vec<(u8, f32)> = vec![
        (0xB1, 5.0),
        (0xB2, 4.0),
        (0xB3, -5.0),
        (0xB4, 1.0),
        (0xB5, 2.5),
        (0xB6, -1.0),
    ];
    let vectors: Vec<_> = population
        .iter()
        .map(|(byte, first)| {
            let mut vector =
                embedder.embed(addr(*byte), None, &BehaviorInputs::default(), at(1_000));
            vector.values[0] = *first;
            vector
        })
        .collect();
    // Writing through an indexed column at all is assertion (2).
    store
        .append(Chain::ETHEREUM, &vectors)
        .await
        .expect("append into the indexed column");

    let sample: Vec<Vec<f32>> = vectors.iter().map(|v| v.values.clone()).collect();
    let mut population_baseline =
        baseline::compute(schema, &sample, at(0)).expect("a baseline over the sample");
    population_baseline.sample_count = baseline::MIN_SAMPLES;
    store
        .put_baseline(Chain::ETHEREUM, &population_baseline)
        .await
        .expect("store the baseline");

    let baseline_now = Utc::now();
    let found = similarity::similar_addresses(similarity::SearchRequest {
        store: &store,
        chain: Chain::ETHEREUM,
        address: &addr(0xB1),
        schema,
        baseline: Some(std::sync::Arc::new(population_baseline.clone())),
        limits: SimilarityLimits::default(),
        requested_results: 3,
        now: baseline_now,
    })
    .await
    .expect("the search runs")
    .expect("the subject is embedded");

    assert_eq!(found.embedding_version, EMBEDDING_VERSION);
    assert_eq!(found.results.len(), 3);
    assert_eq!(
        found.results[0].address,
        addr(0xB2),
        "the nearest behavior wins"
    );
    assert!(
        found.results.iter().all(|hit| hit.address != addr(0xB1)),
        "an address is not its own neighbour"
    );
    let scores: Vec<f32> = found.results.iter().map(|h| h.similarity.get()).collect();
    assert!(scores.windows(2).all(|w| w[0] >= w[1]), "{scores:?}");

    // Every hit explains itself, and the explanation is the score's exact
    // decomposition — the property the whole endpoint rests on, re-checked
    // here on values that came back out of ClickHouse rather than out of a
    // constructor.
    for hit in &found.results {
        assert!(!hit.factors.is_empty());
        let summed: f32 = hit.factors.iter().map(|f| f.contribution).sum();
        assert!(
            (summed - hit.similarity.get()).abs() < 1e-4,
            "factors {summed} must sum to similarity {}",
            hit.similarity
        );
    }
    assert!(
        !found.approximate,
        "a population this small fits inside the shortlist cap, so the ranking is exact"
    );

    // (3) The plan. `vector_literal`'s float rendering is what keeps this in
    // the plan at all: an integer-typed array literal returns the same rows
    // with the index skipped entirely, which no assertion on the *answer*
    // could ever catch.
    let query_vector = vectors[0]
        .values
        .iter()
        .map(|v| format!("{v:?}"))
        .collect::<Vec<_>>()
        .join(",");
    let plan: Vec<String> = client
        .query(&format!(
            "EXPLAIN indexes = 1 SELECT address FROM address_embeddings \
             WHERE chain = 1 AND embedding_version = ? \
             ORDER BY cosineDistance(vector, [{query_vector}]) ASC LIMIT 3"
        ))
        .bind(EMBEDDING_VERSION)
        .fetch_all()
        .await
        .expect("explain the candidate query");
    let plan = plan.join("\n");
    assert!(
        plan.contains("idx_embedding_vector"),
        "the candidate query must use the vector index, not scan:\n{plan}"
    );
}

/// The **batched** reads the embedding sweep depends on, against real stores.
///
/// These matter more than most integration tests: the Postgres batch queries are
/// *runtime-checked* (`query_as`, not `query_as!`) because they were added
/// without regenerating the offline `.sqlx` cache — exactly like the
/// pre-existing `labels_for_many`. That means the compiler never sees them, and
/// this test is the only thing standing between a typo'd column and production.
///
/// What is asserted is agreement, not shape: for every input, the batched read
/// must return exactly what looping the single read returns. A batch that
/// silently disagreed with its single-address sibling would make a page-computed
/// vector differ from a CLI-computed one for the same address — the kind of bug
/// that surfaces as "similarity search gives different answers than the
/// inspector" months later.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn batched_store_reads_agree_with_their_single_address_siblings() {
    let (store, _pg) = pg_store().await;

    let members = [addr(0xB1), addr(0xB2), addr(0xB3)];
    let loner = addr(0xB4);
    let unknown = addr(0xB5);

    let entity_id = EntityId(uuid::Uuid::from_u128(0xBEEF));
    assert_eq!(
        store
            .create_entity(entity_id, &members[0], "batch-test", at(10))
            .await
            .expect("create"),
        CreateOutcome::Created
    );
    for member in &members[1..] {
        assert_eq!(
            store
                .link_address(entity_id, member, "batch-test", at(11))
                .await
                .expect("link"),
            LinkOutcome::Linked
        );
    }
    let lone_entity = EntityId(uuid::Uuid::from_u128(0xCAFE));
    store
        .create_entity(lone_entity, &loner, "batch-test", at(12))
        .await
        .expect("create loner");

    for (n, incident) in [0xA1u128, 0xA2].into_iter().enumerate() {
        store
            .record_attribution(&AttributionRecord {
                incident_id: IncidentId(uuid::Uuid::from_u128(incident)),
                entity_id,
                confidence: events::primitives::Confidence::new(0.9),
                evidence: format!("batch-test-{n}"),
                attributed_at: at(20 + n as i64),
            })
            .await
            .expect("record attribution");
    }

    store
        .seed_sanctions(&[
            SanctionEntry {
                address: members[0],
                list_name: "ofac_sdn".into(),
                entry: "Evil Corp".into(),
                listed_at: None,
            },
            SanctionEntry {
                address: members[0],
                list_name: "eu_consolidated".into(),
                entry: "Evil Corp".into(),
                listed_at: None,
            },
        ])
        .await
        .expect("seed sanctions");

    let all: Vec<Address> = members.iter().copied().chain([loner, unknown]).collect();

    // entities_for_addresses
    let batched = store
        .entities_for_addresses(&all)
        .await
        .expect("batched entity lookup");
    for address in &all {
        let single = store
            .entity_for_address(address)
            .await
            .expect("single entity lookup");
        assert_eq!(batched.get(address).copied(), single, "for {address}");
    }
    assert!(
        !batched.contains_key(&unknown),
        "an unclustered address is absent, not mapped to a placeholder"
    );

    // entities — including membership *order*, which decides the vector
    let batched = store
        .entities(&[
            entity_id,
            lone_entity,
            EntityId(uuid::Uuid::from_u128(0xDEAD)),
        ])
        .await
        .expect("batched entities");
    for id in [entity_id, lone_entity] {
        let single = store
            .entity(id)
            .await
            .expect("single entity")
            .expect("exists");
        let from_batch = batched.get(&id).expect("present in batch");
        assert_eq!(from_batch, &single, "batched and single entity must agree");
    }
    assert!(
        !batched.contains_key(&EntityId(uuid::Uuid::from_u128(0xDEAD))),
        "an unknown entity is simply absent"
    );

    // attributions_for_entities
    let batched = store
        .attributions_for_entities(&[entity_id, lone_entity])
        .await
        .expect("batched attributions");
    for id in [entity_id, lone_entity] {
        let single = store
            .attributions_for_entity(id)
            .await
            .expect("single attributions");
        let from_batch = batched.get(&id).cloned().unwrap_or_default();
        assert_eq!(from_batch, single, "batched and single attributions differ");
    }

    // sanction_matches_many
    let batched = store
        .sanction_matches_many(&all)
        .await
        .expect("batched sanctions");
    for address in &all {
        let single = store
            .sanction_matches(address)
            .await
            .expect("single sanctions");
        let from_batch = batched.get(address).cloned().unwrap_or_default();
        assert_eq!(from_batch, single, "for {address}");
    }
    assert_eq!(batched.get(&members[0]).map(Vec::len), Some(2));

    // An empty input must not produce a malformed `= ANY(...)`.
    assert!(store.entities_for_addresses(&[]).await.unwrap().is_empty());
    assert!(store.entities(&[]).await.unwrap().is_empty());
    assert!(store
        .attributions_for_entities(&[])
        .await
        .unwrap()
        .is_empty());
    assert!(store.sanction_matches_many(&[]).await.unwrap().is_empty());
}

/// The batched ClickHouse reads: `edge_history_many` must agree with looping
/// `edge_history` (including truncation), `latest_many` with looping `latest`,
/// and the real `cityHash64` shard predicate must partition the keyspace.
#[tokio::test]
#[ignore = "requires Docker (testcontainers ClickHouse)"]
async fn batched_graph_and_embedding_reads_agree_and_shards_partition() {
    use intelligence::embedding::v1::VERSION as EMBEDDING_VERSION;
    use intelligence::embedding::{default_embedder, BehaviorInputs};
    use intelligence::embedding_store::{ClickhouseEmbeddingStore, EmbeddingStore};
    use std::collections::BTreeSet;

    let (_container, client) = start_clickhouse().await;

    intelligence::ch_migrate::MIGRATOR
        .run(&client)
        .await
        .expect("apply intelligence migrations");
    let graph = ClickhouseAdjacency::new(client.clone());
    let store = ClickhouseEmbeddingStore::new(client);

    // A spread of subjects with differing observation counts, so the cap bites
    // some and not others.
    let mut edges = Vec::new();
    for subject in 1..=12u8 {
        for n in 0..u64::from(subject) {
            edges.push(AdjacencyEdge {
                chain: Chain::ETHEREUM,
                src: addr(subject),
                dst: addr(0xF0 + (n % 4) as u8),
                kind: EdgeKind::Interacted,
                evidence: format!("0xtx{subject:02x}{n:02x}"),
                block_number: n,
                observed_at: at(n as i64 * 60),
            });
        }
    }
    graph.append(&edges).await.expect("append edges");

    let subjects: Vec<Address> = (1..=12u8).map(addr).collect();

    // edge_history_many == looping edge_history, uncapped and capped.
    for cap in [100u32, 3] {
        let batched = graph
            .edge_history_many(Chain::ETHEREUM, &subjects, cap)
            .await
            .expect("batched history");
        assert_eq!(
            batched.len(),
            subjects.len(),
            "one entry per input address, even for one with no rows"
        );
        for subject in &subjects {
            let single = graph
                .edge_history(Chain::ETHEREUM, subject, cap)
                .await
                .expect("single history");
            let from_batch = batched.get(subject).expect("present");
            assert_eq!(
                from_batch, &single,
                "batched and single history disagree for {subject} at cap {cap}"
            );
        }
    }
    // An address with no observations at all still gets an entry.
    let empty = graph
        .edge_history_many(Chain::ETHEREUM, &[addr(0xEE)], 10)
        .await
        .expect("batched history");
    assert_eq!(empty.get(&addr(0xEE)), Some(&Default::default()));

    // The real cityHash64 shard predicate partitions the active set.
    let unsharded: BTreeSet<Address> = graph
        .active_addresses(Chain::ETHEREUM, at(0), None, 1_000, Shard::SINGLE)
        .await
        .expect("unsharded")
        .into_iter()
        .collect();
    let total = 4u32;
    let mut covered: Vec<Address> = Vec::new();
    for index in 0..total {
        let slice = graph
            .active_addresses(
                Chain::ETHEREUM,
                at(0),
                None,
                1_000,
                Shard::new(index, total).unwrap(),
            )
            .await
            .expect("sharded");
        covered.extend(slice);
    }
    let covered_set: BTreeSet<Address> = covered.iter().copied().collect();
    assert_eq!(
        covered.len(),
        covered_set.len(),
        "shards must not overlap — an address swept twice is wasted work"
    );
    assert_eq!(
        covered_set, unsharded,
        "shards must cover the whole keyspace — a gap is an address never embedded"
    );

    // latest_many == looping latest, and it collapses to the newest per address.
    let embedder = default_embedder();
    let mut written = Vec::new();
    for (n, subject) in subjects.iter().enumerate() {
        written.push(embedder.embed(*subject, None, &BehaviorInputs::default(), at(1_000)));
        // A newer one for half of them, appended *before* the older in the
        // slice so "latest" cannot be "last inserted".
        if n % 2 == 0 {
            written.push(embedder.embed(*subject, None, &BehaviorInputs::default(), at(2_000)));
        }
    }
    store
        .append(Chain::ETHEREUM, &written)
        .await
        .expect("append vectors");

    let batched = store
        .latest_many(Chain::ETHEREUM, &subjects, EMBEDDING_VERSION)
        .await
        .expect("batched latest");
    for subject in &subjects {
        let single = store
            .latest(Chain::ETHEREUM, subject, EMBEDDING_VERSION)
            .await
            .expect("single latest");
        assert_eq!(
            batched.get(subject).cloned(),
            single,
            "batched and single latest disagree for {subject}"
        );
    }
    assert_eq!(
        batched.get(&subjects[0]).map(|v| v.computed_at),
        Some(at(2_000)),
        "latest_many must take the newest, not the first stored"
    );
    assert!(store
        .latest_many(Chain::ETHEREUM, &[], EMBEDDING_VERSION)
        .await
        .expect("empty batch")
        .is_empty());

    // The baseline round-trip: sample -> compute -> store -> read back.
    let sample = store
        .sample_vectors(Chain::ETHEREUM, EMBEDDING_VERSION, 1_000)
        .await
        .expect("sample");
    assert_eq!(
        sample.len(),
        subjects.len(),
        "the sample is latest-per-address, not every stored row"
    );

    let baseline =
        intelligence::embedding::baseline::compute(embedder.schema(), &sample, at(5_000))
            .expect("a non-empty sample yields a baseline");
    store
        .put_baseline(Chain::ETHEREUM, &baseline)
        .await
        .expect("store baseline");

    let read_back = store
        .latest_baseline(Chain::ETHEREUM, EMBEDDING_VERSION)
        .await
        .expect("read baseline")
        .expect("one was stored");
    assert_eq!(read_back, baseline);
    assert!(read_back.matches(embedder.schema()));
    assert!(store
        .latest_baseline(Chain::ETHEREUM, "behavior-v99")
        .await
        .expect("unknown version")
        .is_none());
}

/// The §20.3 candidate-link table against a real Postgres (Sprint 19 t3).
///
/// Every query over `entity_link_candidates` is **runtime-checked** — the table
/// is new and `query_as!` would need a regenerated offline cache — so nothing
/// in the unit suite proves the SQL parses, the check constraints hold, or that
/// the three-way upsert distinguishes its outcomes. That is exactly the class
/// of bug that only appears in production, which is what this test is for.
///
/// The load-bearing assertion is the last one: a re-proposal must **not**
/// reopen a decided row. The `WHERE status = 'proposed'` on the upsert's
/// `DO UPDATE` arm is what enforces it, and it is invisible to every in-memory
/// double that reimplements the rule rather than executing it.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn candidate_links_are_keyed_refreshable_and_never_reopen_a_decision() {
    use intelligence::link_candidate::{
        link_candidate_id, Decision, LinkCandidateStore, LinkFactor, LinkStatus, Proposal,
        ProposalOutcome,
    };
    use intelligence::similarity::Similarity;

    let (store, _pg) = pg_store().await;
    let (subject, anchor) = (addr(0x11), addr(0x22));

    let proposal = |similarity: f64, at_secs: i64| Proposal {
        candidate_id: link_candidate_id(&subject, &anchor, "behavior-v1"),
        // Canonically ordered, as the CHECK constraint requires: 0x11… < 0x22….
        address_a: subject,
        address_b: anchor,
        anchor,
        anchor_labels: vec![LabelKind::KnownScammer, LabelKind::SanctionedEntity],
        entity_a: None,
        entity_b: None,
        similarity: Similarity::new(similarity),
        confidence: events::primitives::Confidence::new(0.42),
        embedding_version: "behavior-v1".into(),
        schema_hash: "abc123".into(),
        factors: vec![LinkFactor {
            feature: "edge_count_log".into(),
            subject_value: 1.5,
            candidate_value: 1.6,
            contribution: 0.25,
        }],
        proposed_at: at(at_secs),
        last_seen_at: at(at_secs),
    };

    // First sighting: the row is inserted and owes an announcement.
    let first = proposal(0.91, 1_000);
    assert_eq!(
        store.propose_link(&first).await.unwrap(),
        ProposalOutcome::New
    );

    // THE CRASH WINDOW. The row committed; the process dies before the publish.
    // Redelivery must re-announce, NOT fall through to `Refreshed` — that
    // fall-through is exactly how the event would be lost permanently and
    // silently, and it is invisible to every test that only exercises the
    // happy path.
    assert_eq!(
        store.propose_link(&first).await.unwrap(),
        ProposalOutcome::ReAnnounce,
        "an unannounced row still owes its event, however many times it is stored"
    );
    assert_eq!(
        store.unannounced_links(10).await.unwrap().len(),
        1,
        "and the recovery sweep can find it without a redelivery at all"
    );

    // The publish succeeds and is recorded.
    store
        .mark_announced(first.candidate_id, at(1_500))
        .await
        .expect("stamp");
    assert!(store.unannounced_links(10).await.unwrap().is_empty());

    // NOW the same link rediscovered — from the anchor's end, on a later sweep,
    // scored a little differently. One row, re-scored, and silent.
    assert_eq!(
        store.propose_link(&proposal(0.94, 2_000)).await.unwrap(),
        ProposalOutcome::Refreshed
    );

    let stored = store
        .links_for_address(&anchor, 10)
        .await
        .expect("read by the other endpoint too");
    assert_eq!(stored.len(), 1, "one row, not two mirror images");
    let row = &stored[0];
    assert_eq!(row.similarity.get(), Similarity::new(0.94).get());
    assert_eq!(row.last_seen_at, at(2_000), "refreshed");
    assert_eq!(row.proposed_at, at(1_000), "first sighting is preserved");
    // The two JSONB columns survive the round trip as domain types.
    assert_eq!(
        row.anchor_labels,
        vec![LabelKind::KnownScammer, LabelKind::SanctionedEntity]
    );
    assert_eq!(row.factors[0].feature, "edge_count_log");
    assert_eq!(row.status, LinkStatus::Proposed);
    assert!(row.decision.is_none());
    assert_eq!(row.announced_at, Some(at(1_500)));

    // The open queue picks it up…
    assert_eq!(store.open_links(10).await.unwrap().len(), 1);

    // …an operator rules on it, and is handed the row as it stood before.
    let before = store
        .decide_link(
            row.candidate_id,
            LinkStatus::Rejected,
            &Decision {
                by: "analyst-7".into(),
                note: Some("same off-the-shelf strategy, unrelated operators".into()),
                at: at(3_000),
            },
        )
        .await
        .expect("decide")
        .expect("the row exists");
    assert_eq!(before.status, LinkStatus::Proposed);

    let decided = store
        .link(row.candidate_id)
        .await
        .unwrap()
        .expect("still stored");
    assert_eq!(decided.status, LinkStatus::Rejected);
    let ruling = decided.decision.as_ref().expect("a decided row has one");
    assert_eq!(ruling.by, "analyst-7");
    assert_eq!(ruling.at, at(3_000));
    assert!(ruling.note.is_some());
    assert!(store.open_links(10).await.unwrap().is_empty());

    // THE RULE: the signal rediscovers the pair on the next sweep. The decision
    // stands — untouched similarity, untouched timestamp, still rejected.
    // Without this, a rejection would silently reopen and the triage queue
    // could never be emptied.
    assert_eq!(
        store.propose_link(&proposal(0.99, 4_000)).await.unwrap(),
        ProposalOutcome::Decided
    );
    let after = store
        .link(row.candidate_id)
        .await
        .unwrap()
        .expect("still stored");
    assert_eq!(after.status, LinkStatus::Rejected);
    assert_eq!(after.similarity.get(), Similarity::new(0.94).get());
    assert_eq!(after.last_seen_at, at(2_000));

    // An unknown id is a typed miss, not an error.
    assert!(store
        .decide_link(
            link_candidate_id(&addr(0xAA), &addr(0xBB), "behavior-v1"),
            LinkStatus::Confirmed,
            &Decision {
                by: "analyst-7".into(),
                note: None,
                at: at(5_000),
            },
        )
        .await
        .unwrap()
        .is_none());
}
