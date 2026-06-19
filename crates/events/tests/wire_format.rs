//! Wire-format lock for the domain event schema (§2).
//!
//! Sprint 1's first task is to *lock the contract every other sprint depends
//! on*. The §2 types live in `src/`; this test is what makes them a contract:
//! every [`DomainEvent`] variant is pinned to an exact, byte-for-byte JSON
//! shape. Rename a field, change a tag, reorder a struct, or drop a variant and
//! one of these assertions fails — turning the sprint-plan's #1 risk ("schema
//! churn ripples to every downstream service") into a loud CI failure instead
//! of a silent break.
//!
//! Two independent guards work together:
//!
//! 1. **Exhaustiveness** — [`GOLDENS`] must cover every variant in
//!    [`DomainEvent::VARIANTS`] exactly once (checked against
//!    [`DomainEvent::COUNT`]). Add a variant and forget its golden → the count
//!    and coverage tests fail.
//! 2. **Byte-stability** — each variant serializes to its pinned JSON and that
//!    JSON deserializes back to the identical value (a true round trip).
//!
//! ## Changing the schema on purpose
//!
//! A failure here is the system working. If the change is intentional and
//! backwards-compatible, update the golden string. If it is *not* backwards
//! compatible, bump [`events::SCHEMA_VERSION`] first (see `SCHEMA.md`) — the
//! golden then documents the new version's shape.

use std::collections::BTreeSet;

use alloy_primitives::{Address, B256};
use chrono::{DateTime, Utc};
use events::chain::{
    BlockAssembled, BlockCanonicalized, BlockFinalized, BlockReverted, RawBlockReceived,
};
use events::detection::{DetectorTriggered, PreliminaryAlertCreated};
use events::intelligence::{
    AttributionUpdated, EntityCreated, EntityMerged, EntitySplit, LabelAdded, LabelRevoked,
    LabelUpdated, RiskFactor, RiskScoreUpdated, SanctionHit,
};
use events::primitives::{
    AccountAddress, AlertId, AlertKind, BlockRef, Chain, Confidence, CustomerId, DetectorRef,
    EntityId, IncidentId, LabelId, RuleId, Severity,
};
use events::rule_engine::{RuleAlertCreated, RuleCreated, RuleTriggered};
use events::simulation::{
    IncidentCreated, IncidentFinalized, IncidentRetracted, SimulationCompleted, SimulationRequested,
};
use events::system::UsageRecorded;
use events::{DomainEvent, EventEnvelope};
use serde_json::json;
use strum::{EnumCount, VariantNames};

// ── Deterministic fixtures ───────────────────────────────────────
// Every value below is fixed so the serialized bytes are stable across runs.
// Don't reach for randomness or `now()` here — a golden test must be
// reproducible.

fn block() -> BlockRef {
    BlockRef::new(19_800_000, B256::repeat_byte(0x11))
}

fn tx() -> B256 {
    B256::repeat_byte(0x22)
}

fn addr() -> AccountAddress {
    Address::repeat_byte(0x33)
}

fn detector() -> DetectorRef {
    DetectorRef {
        id: "sandwich".into(),
        version: "1.2".into(),
        config_hash: "cfg-abc".into(),
    }
}

fn ts() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap()
}

fn alert_id() -> AlertId {
    AlertId(uuid::Uuid::from_u128(0xA1))
}

fn incident_id() -> IncidentId {
    IncidentId(uuid::Uuid::from_u128(0x1C))
}

fn entity_id() -> EntityId {
    EntityId(uuid::Uuid::from_u128(0xE1))
}

fn label_id() -> LabelId {
    LabelId(uuid::Uuid::from_u128(0x1B))
}

fn rule_id() -> RuleId {
    RuleId(uuid::Uuid::from_u128(0x4E))
}

fn customer_id() -> CustomerId {
    CustomerId(uuid::Uuid::from_u128(0xC0))
}

/// One representative value for every [`DomainEvent`] variant. The exhaustiveness
/// test proves this covers all of them.
fn sample_events() -> Vec<DomainEvent> {
    vec![
        // Chain (§5)
        DomainEvent::RawBlockReceived(RawBlockReceived {
            block: block(),
            timestamp: 1_700_000_000,
        }),
        DomainEvent::BlockAssembled(BlockAssembled {
            block: block(),
            tx_count: 142,
            trace_available: true,
        }),
        DomainEvent::BlockCanonicalized(BlockCanonicalized { block: block() }),
        DomainEvent::BlockReverted(BlockReverted {
            block: block(),
            replaced_by: B256::repeat_byte(0x44),
        }),
        DomainEvent::BlockFinalized(BlockFinalized { block: block() }),
        // Detection (§6)
        DomainEvent::DetectorTriggered(DetectorTriggered {
            detector: detector(),
            block: block(),
            txs: vec![tx()],
            raw_confidence: Confidence::new(0.9),
            evidence: json!({ "pool": "0xpool", "profit_wei": "1000" }),
        }),
        DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
            alert_id: alert_id(),
            detector: detector(),
            addresses: vec![addr()],
            kind: AlertKind::Sandwich,
            confidence: Confidence::new(0.8),
            provisional: true,
        }),
        // Simulation (§7)
        DomainEvent::SimulationRequested(SimulationRequested {
            alert_id: alert_id(),
            evidence: json!({ "txs": ["0xaa"] }),
        }),
        DomainEvent::SimulationCompleted(SimulationCompleted {
            alert_id: alert_id(),
            profit: 1234.5,
            victim_loss: 678.9,
            confirmed: true,
        }),
        DomainEvent::IncidentCreated(IncidentCreated {
            incident_id: incident_id(),
            alert_id: alert_id(),
            kind: AlertKind::Sandwich,
            txs: vec![tx()],
            profit: 1234.5,
            victim_loss: 678.9,
            severity: Severity::High,
        }),
        DomainEvent::IncidentRetracted(IncidentRetracted {
            incident_id: incident_id(),
            reason: "block reverted".into(),
        }),
        DomainEvent::IncidentFinalized(IncidentFinalized {
            incident_id: incident_id(),
            block_hash: B256::repeat_byte(0x11),
        }),
        // Intelligence (§8)
        DomainEvent::LabelAdded(LabelAdded {
            address: addr(),
            kind: "exchange".into(),
            value: "binance".into(),
            confidence: Confidence::new(0.95),
            source: "etherscan".into(),
        }),
        DomainEvent::LabelUpdated(LabelUpdated {
            address: addr(),
            label_id: label_id(),
            old_value: "binance".into(),
            new_value: "binance-14".into(),
            source: "etherscan".into(),
        }),
        DomainEvent::LabelRevoked(LabelRevoked {
            address: addr(),
            label_id: label_id(),
            reason: "source retracted".into(),
        }),
        DomainEvent::EntityCreated(EntityCreated {
            entity_id: entity_id(),
            seed_address: addr(),
        }),
        DomainEvent::EntityMerged(EntityMerged {
            surviving_id: entity_id(),
            absorbed_id: EntityId(uuid::Uuid::from_u128(0xE2)),
            evidence_ref: "common-funder".into(),
        }),
        DomainEvent::EntitySplit(EntitySplit {
            original_id: entity_id(),
            new_ids: vec![
                EntityId(uuid::Uuid::from_u128(0xE3)),
                EntityId(uuid::Uuid::from_u128(0xE4)),
            ],
            reason: "false merge".into(),
        }),
        DomainEvent::AttributionUpdated(AttributionUpdated {
            incident_id: incident_id(),
            entity_ids: vec![entity_id()],
            labels: vec!["mev-bot".into()],
        }),
        DomainEvent::RiskScoreUpdated(RiskScoreUpdated {
            address: addr(),
            entity_id: Some(entity_id()),
            score: 87,
            confidence: Confidence::new(0.7),
            factors: vec![RiskFactor {
                name: "sandwich-incidents".into(),
                delta: 30.0,
                evidence_ref: "incident:1c".into(),
            }],
            model_version: "risk-v1".into(),
        }),
        DomainEvent::SanctionHit(SanctionHit {
            address: addr(),
            list: "OFAC".into(),
            entry: "SDN-123".into(),
        }),
        // Rule engine (§9)
        DomainEvent::RuleCreated(RuleCreated {
            rule_id: rule_id(),
            owner: customer_id(),
            definition: json!({ "when": "receives > 1M then touches mixer" }),
        }),
        DomainEvent::RuleTriggered(RuleTriggered {
            rule_id: rule_id(),
            address: addr(),
            matched_events: vec!["IncidentCreated".into()],
            context: json!({ "window_s": 3600 }),
        }),
        DomainEvent::RuleAlertCreated(RuleAlertCreated {
            alert_id: alert_id(),
            rule_id: rule_id(),
            address: addr(),
            explanation: "large inflow then mixer".into(),
        }),
        // System (§13)
        DomainEvent::UsageRecorded(UsageRecorded {
            customer_id: customer_id(),
            event_type: "api_query".into(),
            quantity: 1,
            timestamp: ts(),
        }),
    ]
}

/// The locked wire form of every variant: `event_type` → exact JSON of the
/// adjacently-tagged [`DomainEvent`]. This is the contract. See the module docs
/// before changing any string here.
const GOLDENS: &[(&str, &str)] = &[
    (
        "RawBlockReceived",
        r#"{"type":"RawBlockReceived","payload":{"block":{"number":19800000,"hash":"0x1111111111111111111111111111111111111111111111111111111111111111"},"timestamp":1700000000}}"#,
    ),
    (
        "BlockAssembled",
        r#"{"type":"BlockAssembled","payload":{"block":{"number":19800000,"hash":"0x1111111111111111111111111111111111111111111111111111111111111111"},"tx_count":142,"trace_available":true}}"#,
    ),
    (
        "BlockCanonicalized",
        r#"{"type":"BlockCanonicalized","payload":{"block":{"number":19800000,"hash":"0x1111111111111111111111111111111111111111111111111111111111111111"}}}"#,
    ),
    (
        "BlockReverted",
        r#"{"type":"BlockReverted","payload":{"block":{"number":19800000,"hash":"0x1111111111111111111111111111111111111111111111111111111111111111"},"replaced_by":"0x4444444444444444444444444444444444444444444444444444444444444444"}}"#,
    ),
    (
        "BlockFinalized",
        r#"{"type":"BlockFinalized","payload":{"block":{"number":19800000,"hash":"0x1111111111111111111111111111111111111111111111111111111111111111"}}}"#,
    ),
    (
        "DetectorTriggered",
        r#"{"type":"DetectorTriggered","payload":{"detector":{"id":"sandwich","version":"1.2","config_hash":"cfg-abc"},"block":{"number":19800000,"hash":"0x1111111111111111111111111111111111111111111111111111111111111111"},"txs":["0x2222222222222222222222222222222222222222222222222222222222222222"],"raw_confidence":0.9,"evidence":{"pool":"0xpool","profit_wei":"1000"}}}"#,
    ),
    (
        "PreliminaryAlertCreated",
        r#"{"type":"PreliminaryAlertCreated","payload":{"alert_id":"00000000-0000-0000-0000-0000000000a1","detector":{"id":"sandwich","version":"1.2","config_hash":"cfg-abc"},"addresses":["0x3333333333333333333333333333333333333333"],"kind":"sandwich","confidence":0.8,"provisional":true}}"#,
    ),
    (
        "SimulationRequested",
        r#"{"type":"SimulationRequested","payload":{"alert_id":"00000000-0000-0000-0000-0000000000a1","evidence":{"txs":["0xaa"]}}}"#,
    ),
    (
        "SimulationCompleted",
        r#"{"type":"SimulationCompleted","payload":{"alert_id":"00000000-0000-0000-0000-0000000000a1","profit":1234.5,"victim_loss":678.9,"confirmed":true}}"#,
    ),
    (
        "IncidentCreated",
        r#"{"type":"IncidentCreated","payload":{"incident_id":"00000000-0000-0000-0000-00000000001c","alert_id":"00000000-0000-0000-0000-0000000000a1","kind":"sandwich","txs":["0x2222222222222222222222222222222222222222222222222222222222222222"],"profit":1234.5,"victim_loss":678.9,"severity":"high"}}"#,
    ),
    (
        "IncidentRetracted",
        r#"{"type":"IncidentRetracted","payload":{"incident_id":"00000000-0000-0000-0000-00000000001c","reason":"block reverted"}}"#,
    ),
    (
        "IncidentFinalized",
        r#"{"type":"IncidentFinalized","payload":{"incident_id":"00000000-0000-0000-0000-00000000001c","block_hash":"0x1111111111111111111111111111111111111111111111111111111111111111"}}"#,
    ),
    (
        "LabelAdded",
        r#"{"type":"LabelAdded","payload":{"address":"0x3333333333333333333333333333333333333333","kind":"exchange","value":"binance","confidence":0.95,"source":"etherscan"}}"#,
    ),
    (
        "LabelUpdated",
        r#"{"type":"LabelUpdated","payload":{"address":"0x3333333333333333333333333333333333333333","label_id":"00000000-0000-0000-0000-00000000001b","old_value":"binance","new_value":"binance-14","source":"etherscan"}}"#,
    ),
    (
        "LabelRevoked",
        r#"{"type":"LabelRevoked","payload":{"address":"0x3333333333333333333333333333333333333333","label_id":"00000000-0000-0000-0000-00000000001b","reason":"source retracted"}}"#,
    ),
    (
        "EntityCreated",
        r#"{"type":"EntityCreated","payload":{"entity_id":"00000000-0000-0000-0000-0000000000e1","seed_address":"0x3333333333333333333333333333333333333333"}}"#,
    ),
    (
        "EntityMerged",
        r#"{"type":"EntityMerged","payload":{"surviving_id":"00000000-0000-0000-0000-0000000000e1","absorbed_id":"00000000-0000-0000-0000-0000000000e2","evidence_ref":"common-funder"}}"#,
    ),
    (
        "EntitySplit",
        r#"{"type":"EntitySplit","payload":{"original_id":"00000000-0000-0000-0000-0000000000e1","new_ids":["00000000-0000-0000-0000-0000000000e3","00000000-0000-0000-0000-0000000000e4"],"reason":"false merge"}}"#,
    ),
    (
        "AttributionUpdated",
        r#"{"type":"AttributionUpdated","payload":{"incident_id":"00000000-0000-0000-0000-00000000001c","entity_ids":["00000000-0000-0000-0000-0000000000e1"],"labels":["mev-bot"]}}"#,
    ),
    (
        "RiskScoreUpdated",
        r#"{"type":"RiskScoreUpdated","payload":{"address":"0x3333333333333333333333333333333333333333","entity_id":"00000000-0000-0000-0000-0000000000e1","score":87,"confidence":0.7,"factors":[{"name":"sandwich-incidents","delta":30.0,"evidence_ref":"incident:1c"}],"model_version":"risk-v1"}}"#,
    ),
    (
        "SanctionHit",
        r#"{"type":"SanctionHit","payload":{"address":"0x3333333333333333333333333333333333333333","list":"OFAC","entry":"SDN-123"}}"#,
    ),
    (
        "RuleCreated",
        r#"{"type":"RuleCreated","payload":{"rule_id":"00000000-0000-0000-0000-00000000004e","owner":"00000000-0000-0000-0000-0000000000c0","definition":{"when":"receives > 1M then touches mixer"}}}"#,
    ),
    (
        "RuleTriggered",
        r#"{"type":"RuleTriggered","payload":{"rule_id":"00000000-0000-0000-0000-00000000004e","address":"0x3333333333333333333333333333333333333333","matched_events":["IncidentCreated"],"context":{"window_s":3600}}}"#,
    ),
    (
        "RuleAlertCreated",
        r#"{"type":"RuleAlertCreated","payload":{"alert_id":"00000000-0000-0000-0000-0000000000a1","rule_id":"00000000-0000-0000-0000-00000000004e","address":"0x3333333333333333333333333333333333333333","explanation":"large inflow then mixer"}}"#,
    ),
    (
        "UsageRecorded",
        r#"{"type":"UsageRecorded","payload":{"customer_id":"00000000-0000-0000-0000-0000000000c0","event_type":"api_query","quantity":1,"timestamp":"2023-11-14T22:13:20Z"}}"#,
    ),
];

#[test]
fn goldens_cover_every_variant_exactly_once() {
    // Guard 1a: count. strum::EnumCount tracks the variant total, so an added
    // variant without a golden trips this immediately.
    assert_eq!(
        GOLDENS.len(),
        DomainEvent::COUNT,
        "GOLDENS has {} entries but DomainEvent has {} variants — add the new variant's golden",
        GOLDENS.len(),
        DomainEvent::COUNT,
    );

    // Guard 1b: coverage by name (catches a duplicate masking a missing one).
    let golden_names: BTreeSet<&str> = GOLDENS.iter().map(|(name, _)| *name).collect();
    let variant_names: BTreeSet<&str> = DomainEvent::VARIANTS.iter().copied().collect();
    assert_eq!(
        golden_names, variant_names,
        "GOLDENS keys must match DomainEvent::VARIANTS one-for-one"
    );

    // And the in-code samples must line up with the goldens, so neither side
    // can silently drift from the variant set.
    let sample_names: BTreeSet<&str> = sample_events()
        .iter()
        .map(|e| e.event_type())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        sample_names, variant_names,
        "sample_events() must produce exactly one of every variant"
    );
}

#[test]
fn every_variant_matches_its_locked_wire_form() {
    // Guard 2: byte-stability. Each variant must serialize to its pinned JSON.
    let goldens: std::collections::BTreeMap<&str, &str> = GOLDENS.iter().copied().collect();

    for event in sample_events() {
        let name = event.event_type();
        let expected = goldens
            .get(name)
            .unwrap_or_else(|| panic!("no golden for variant {name}"));
        let actual = serde_json::to_string(&event).expect("serialize");
        assert_eq!(
            &actual, expected,
            "wire format for {name} changed — if intentional, update the golden \
             (and bump SCHEMA_VERSION if not backwards compatible)",
        );
    }
}

#[test]
fn locked_wire_form_round_trips_back_to_value() {
    // The golden isn't just a string we emit — it must parse back to the exact
    // same value, proving the contract is readable as well as writable.
    //
    // Note: this compares via the derived `PartialEq`, which compares the `f64`
    // fields (profit, victim_loss, delta) for *exact* equality. Every float in
    // `sample_events()` is therefore deliberately chosen to be exactly
    // representable (e.g. 1234.5, 30.0); don't introduce a sample float like 0.1
    // or this round trip becomes flaky.
    let by_name: std::collections::BTreeMap<&str, DomainEvent> = sample_events()
        .into_iter()
        .map(|e| (e.event_type(), e))
        .collect();

    for (name, json) in GOLDENS {
        let parsed: DomainEvent = serde_json::from_str(json).expect("deserialize golden");
        assert_eq!(
            &parsed, &by_name[name],
            "golden for {name} did not round-trip back to its sample value",
        );
    }
}

// ── Envelope wire form ───────────────────────────────────────────
// The GOLDENS above pin each event *body*. The envelope is the *wrapper* that
// actually lands on Kafka and in the event store, and its field names are the
// columns Sprint 1's storage schema keys on (event_id, schema_version, chain,
// occurred_at). A payload golden wouldn't notice if one of those were renamed,
// so the wrapper gets its own lock.

/// Fixed-metadata envelope around a simple payload. Like the samples above, all
/// inputs are constant so the bytes are reproducible.
fn sample_envelope() -> EventEnvelope {
    EventEnvelope::with_metadata(
        uuid::Uuid::from_u128(0xE2E),
        ts(),
        Chain::ETHEREUM,
        DomainEvent::BlockFinalized(BlockFinalized { block: block() }),
    )
}

/// The locked wire form of [`sample_envelope`]. `chain` is a transparent u64 and
/// `schema_version` is the current [`events::SCHEMA_VERSION`] — both load-bearing
/// for routing/partitioning (§4, §20).
const ENVELOPE_GOLDEN: &str = r#"{"event_id":"00000000-0000-0000-0000-000000000e2e","schema_version":1,"chain":1,"occurred_at":"2023-11-14T22:13:20Z","payload":{"type":"BlockFinalized","payload":{"block":{"number":19800000,"hash":"0x1111111111111111111111111111111111111111111111111111111111111111"}}}}"#;

#[test]
fn envelope_wire_form_is_locked() {
    let actual = serde_json::to_string(&sample_envelope()).expect("serialize");
    assert_eq!(
        actual, ENVELOPE_GOLDEN,
        "envelope wire format changed — these are the event-store columns; update \
         the golden only if intentional (and bump SCHEMA_VERSION if incompatible)",
    );

    // Readable as well as writable, via the crate's own decode path.
    let parsed = EventEnvelope::from_json_slice(ENVELOPE_GOLDEN.as_bytes()).expect("deserialize");
    assert_eq!(parsed, sample_envelope());
}

// ── Regenerating goldens ─────────────────────────────────────────
// When a schema change is intentional, don't hand-edit ~200-char JSON strings —
// run this to print the new GOLDENS body and the envelope golden, then paste:
//
//     cargo test -p events --test wire_format -- --ignored --nocapture print_goldens
#[test]
#[ignore = "manual: prints regenerated goldens for copy-paste"]
fn print_goldens() {
    println!("\n// ── GOLDENS ──");
    for event in sample_events() {
        let json = serde_json::to_string(&event).expect("serialize");
        println!("(\n    {:?},\n    r#\"{json}\"#,\n),", event.event_type());
    }
    println!("\n// ── ENVELOPE_GOLDEN ──");
    println!(
        "r#\"{}\"#",
        serde_json::to_string(&sample_envelope()).expect("serialize"),
    );
}
