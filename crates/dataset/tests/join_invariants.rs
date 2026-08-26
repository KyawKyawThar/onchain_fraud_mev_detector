//! The join's safety property, stated over *all* interleavings rather than a
//! table of examples.
//!
//! # The property
//!
//! > **A trusted binding is never a wrong one.**
//!
//! The trigger→alert edge does not exist in the schema and has to be
//! reconstructed (see `dataset::join`). The reconstruction is allowed to give
//! up — marking a finding `Ambiguous` or `Conflicted`, which the export then
//! excludes — but it must never hand back a *confident* binding to an alert
//! that did not belong to that finding. A wrong-but-confident binding is the
//! one failure mode that silently poisons a training set: the row looks
//! perfect and carries the other finding's label.
//!
//! # Why a property test
//!
//! The hazard is an ordering hazard. The event store's total order is
//! `(occurred_at, event_id)`, `occurred_at` has millisecond resolution, and
//! `event_id` is a random v4 UUID — so when a detector emits several findings
//! inside one millisecond, the *stored* order is an arbitrary permutation of
//! the emitted one. Examples can only ever pin the permutations someone
//! thought of. Generating them is the point.
//!
//! The generator deliberately maximises collisions — few distinct
//! milliseconds, few distinct confidences, few detectors — because that is
//! precisely the region where adjacency-based pairing is at risk. `ml-features`
//! sets the precedent for this style with its attribution-blindness proptest.

use std::collections::BTreeMap;

use alloy_primitives::B256;
use chrono::{DateTime, TimeZone, Utc};
use proptest::prelude::*;
use uuid::Uuid;

use dataset::join::join;
use dataset::label::Outcome;
use events::detection::{DetectorTriggered, PreliminaryAlertCreated};
use events::primitives::{
    AlertId, AlertKind, BlockRef, Chain, Confidence, DetectorRef, Severity, SuggestedAction,
};
use events::simulation::SimulationCompleted;
use events::{DomainEvent, EventEnvelope};

const CHAIN: Chain = Chain::ETHEREUM;
const BASE_MILLIS: i64 = 1_700_000_000_000;

/// One finding the generator will emit: which detector build raised it, at what
/// confidence, in which millisecond, and whether simulation confirmed it.
#[derive(Debug, Clone, Copy)]
struct Planned {
    detector: u8,
    confidence_step: u8,
    millis: u8,
    confirmed: bool,
    /// Where the trigger and its alert each land in the stored order among
    /// everything sharing their millisecond. Generated **independently**: the
    /// store's tie-break is a random `event_id`, so an alert really can be
    /// stored ahead of its own trigger, and a generator that kept each pair
    /// adjacent would never explore the interleavings that make pairing hard.
    trigger_key: u64,
    alert_key: u64,
}

fn planned() -> impl Strategy<Value = Planned> {
    // Small ranges on purpose: collisions are the interesting case.
    (
        0u8..3,
        0u8..3,
        0u8..3,
        any::<bool>(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(
            |(detector, confidence_step, millis, confirmed, trigger_key, alert_key)| Planned {
                detector,
                confidence_step,
                millis,
                confirmed,
                trigger_key,
                alert_key,
            },
        )
}

fn detector_ref(index: u8) -> DetectorRef {
    DetectorRef {
        id: format!("detector-{index}"),
        version: "1.0.0".to_owned(),
        config_hash: "cafe".to_owned(),
    }
}

fn confidence_of(step: u8) -> f64 {
    // Exact binary fractions, so the emitter's copy-through and the join's
    // equality test compare identical bits — as they do in production, where
    // the alert's confidence is a literal copy of the trigger's.
    0.25 + f64::from(step) * 0.25
}

fn at(millis: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(BASE_MILLIS + millis).unwrap()
}

/// Every finding is on one block; each gets its own transaction, so a tx hash
/// identifies the finding uniquely and gives the assertion its ground truth.
fn block() -> BlockRef {
    BlockRef::new(19_800_000, B256::repeat_byte(0xab))
}

/// What the stream *actually* meant, for the assertion to compare against.
struct Truth {
    /// tx hash → the alert that finding really raised, and its real outcome.
    by_tx: BTreeMap<B256, (AlertId, bool)>,
}

/// Build the stored stream for `plan`, in the order the event store would
/// return it: sorted by `(occurred_at, event_id)`, with the event ids derived
/// from each finding's `order_key` so the generator explores the permutations
/// a millisecond collision can produce.
fn stored_stream(plan: &[Planned]) -> (Vec<EventEnvelope>, Truth) {
    let mut events: Vec<EventEnvelope> = Vec::new();
    let mut by_tx = BTreeMap::new();

    for (index, p) in plan.iter().enumerate() {
        let tx = B256::from(alloy_primitives::U256::from(index as u64 + 1));
        let alert_id = AlertId(Uuid::from_u128(0x1000 + index as u128));
        by_tx.insert(tx, (alert_id, p.confirmed));

        // The event ids place each event within its millisecond: high bits
        // carry the generated position, low bits keep every id distinct so the
        // sort is total. Trigger and alert are placed independently, so every
        // interleaving a millisecond collision can produce is reachable —
        // including an alert stored ahead of its own trigger.
        let trigger_id = (u128::from(p.trigger_key) << 32) | ((index as u128) << 1);
        let alert_id_key = (u128::from(p.alert_key) << 32) | ((index as u128) << 1) | 1;
        let occurred_at = at(i64::from(p.millis));

        events.push(EventEnvelope::with_metadata(
            Uuid::from_u128(trigger_id),
            occurred_at,
            CHAIN,
            DomainEvent::DetectorTriggered(DetectorTriggered {
                detector: detector_ref(p.detector),
                block: block(),
                txs: vec![tx],
                raw_confidence: Confidence::new(confidence_of(p.confidence_step)),
                evidence: serde_json::json!({}),
            }),
        ));
        events.push(EventEnvelope::with_metadata(
            Uuid::from_u128(alert_id_key),
            occurred_at,
            CHAIN,
            DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
                alert_id,
                detector: detector_ref(p.detector),
                addresses: vec![],
                kind: AlertKind::Sandwich,
                confidence: Confidence::new(confidence_of(p.confidence_step)),
                provisional: true,
                impact_usd: None,
                severity: Severity::Low,
                suggested_action: SuggestedAction::Monitor,
            }),
        ));

        // Outcomes land later, well clear of the trigger/alert milliseconds, so
        // they never interleave with the pairing under test.
        events.push(EventEnvelope::with_metadata(
            Uuid::from_u128(0x9000_0000 + index as u128),
            at(10_000 + index as i64),
            CHAIN,
            DomainEvent::SimulationCompleted(SimulationCompleted {
                alert_id,
                profit: if p.confirmed { 100.0 } else { 0.0 },
                victim_loss: 0.0,
                confirmed: p.confirmed,
            }),
        ));
    }

    // The store's own total order.
    events.sort_by_key(|e| (e.occurred_at, e.event_id));
    (events, Truth { by_tx })
}

proptest! {
    // Higher than proptest's default: the hazard needs several findings to
    // collide in one millisecond *and* an unlucky permutation, so the
    // interesting region is a small slice of the input space. 512 cases missed
    // a real cascade that CI then hit. Still ~1s.
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// The safety property: whenever the join reports a *trusted* binding, it
    /// is the right one — and therefore so is the label derived from it.
    #[test]
    fn a_trusted_binding_is_never_a_wrong_one(plan in prop::collection::vec(planned(), 1..12)) {
        let (events, truth) = stored_stream(&plan);
        let result = join(CHAIN, &events);

        for finding in &result.findings {
            if !finding.binding.is_trusted() {
                continue; // Giving up is allowed; being confidently wrong is not.
            }
            let tx = finding.txs[0];
            let (true_alert, confirmed) = truth.by_tx[&tx];

            prop_assert_eq!(
                finding.alert_id,
                Some(true_alert),
                "finding on tx {:?} was trusted ({:?}) but bound to the wrong alert",
                tx,
                finding.binding
            );

            // The label follows the binding, so a correct binding must yield
            // the correct outcome — this is the assertion that actually
            // protects the training set.
            let expected = if confirmed {
                Outcome::Confirmed { profit: 100.0, victim_loss: 0.0 }
            } else {
                Outcome::Refuted
            };
            prop_assert_eq!(finding.effective_outcome(false), expected);
        }
    }

    /// Every emitted trigger is accounted for, whatever the interleaving: the
    /// join never loses a finding, it only ever declines to trust one.
    #[test]
    fn no_finding_is_lost_however_the_stream_is_permuted(
        plan in prop::collection::vec(planned(), 1..12)
    ) {
        let (events, _) = stored_stream(&plan);
        let result = join(CHAIN, &events);

        prop_assert_eq!(result.findings.len(), plan.len());
        prop_assert_eq!(result.stats.triggers, plan.len() as u64);
        // Each alert either binds to some finding or is counted as orphaned;
        // none may simply vanish.
        let bound = result.findings.iter().filter(|f| f.alert_id.is_some()).count() as u64;
        prop_assert_eq!(bound + result.stats.alerts_without_trigger, plan.len() as u64);
    }

    /// Determinism, over arbitrary streams: the same stored order always folds
    /// to the same findings. This is the assumption the manifest's content
    /// hash rests on.
    #[test]
    fn the_fold_is_deterministic(plan in prop::collection::vec(planned(), 1..12)) {
        let (events, _) = stored_stream(&plan);
        prop_assert_eq!(join(CHAIN, &events), join(CHAIN, &events));
    }
}

/// A regression pinning the exact hazard the property exists to catch: two
/// findings of one detector, same confidence, same millisecond, stored with
/// their pairs interleaved. Neither binding may claim to be exact.
#[test]
fn interleaved_identical_pairs_are_never_both_trusted() {
    let plan = [
        Planned {
            detector: 0,
            confidence_step: 1,
            millis: 0,
            confirmed: true,
            trigger_key: 0,
            alert_key: 2,
        },
        Planned {
            detector: 0,
            confidence_step: 1,
            millis: 0,
            confirmed: false,
            // Stored order becomes t0, t1, a0, a1 — the pairs interleave, so
            // neither alert can be matched to its trigger by adjacency.
            trigger_key: 1,
            alert_key: 3,
        },
    ];
    let (events, truth) = stored_stream(&plan);
    let result = join(CHAIN, &events);

    for finding in &result.findings {
        if finding.binding.is_trusted() {
            let (true_alert, _) = truth.by_tx[&finding.txs[0]];
            assert_eq!(
                finding.alert_id,
                Some(true_alert),
                "a trusted binding under interleaving must still be correct"
            );
        }
    }
    assert!(
        result.stats.ambiguous_bindings > 0,
        "two indistinguishable findings must register as ambiguous, not resolve silently"
    );
}
