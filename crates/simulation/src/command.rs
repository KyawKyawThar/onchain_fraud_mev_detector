//! The `SimulationJob` **command** (§2/§7) and the pure mapping from a
//! provisional alert to the work it dispatches.
//!
//! `SimulationJob` is the system's *one* command — an instruction ("run this
//! simulation"), consumed exactly once by one worker. It is deliberately **not** a
//! [`events::DomainEvent`] and never enters the event store: the audit log records
//! what *happened*, and "we decided to simulate" is not a fact worth replaying —
//! only the outcome (`SimulationCompleted`/`IncidentCreated`) is (§7). So the type
//! lives here, on the simulation service, and travels only on RabbitMQ.
//!
//! [`job_for_alert`] is the **core**: a `PreliminaryAlertCreated` (plus the
//! envelope's chain) becomes a `(SimulationJob, SimulationRequested)` pair — the
//! command to queue and the domain event to emit alongside it for audit. It is
//! free of Kafka and RabbitMQ, so the dispatch decision is `assert_eq!`-testable.

use events::detection::PreliminaryAlertCreated;
use events::primitives::{AccountAddress, AlertId, AlertKind, Chain, Confidence, DetectorRef};
use events::simulation::SimulationRequested;
use serde::{Deserialize, Serialize};

/// RabbitMQ message priority, `0..=9` (§7). Enterprise-tier and high-provisional-
/// profit alerts ride a higher priority so they jump the free-tier backlog; the
/// `sim.jobs` queue is declared with `x-max-priority = 9` (Sprint 5 t2) to honour
/// it.
///
/// Constructed clamped so an out-of-range value can never reach the wire and be
/// silently dropped by the broker (RabbitMQ caps anything above the queue's max).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Priority(u8);

impl Priority {
    /// The queue's maximum priority (§7 — priority `0..=9`).
    pub const MAX: u8 = 9;

    /// Clamp `value` into `0..=9`.
    pub fn new(value: u8) -> Self {
        Self(value.min(Self::MAX))
    }

    /// Provisional priority derived from the fast-path confidence: map `[0.0,
    /// 1.0]` onto `0..=9`, so a more confident alert is simulated sooner.
    ///
    /// A **placeholder** policy, the same shape as detection's boot-placeholder
    /// `config_hash`: the real driver is customer tier + provisional profit (§7,
    /// §13), which needs billing context the dispatcher does not yet have. Tier-
    /// aware priority is a follow-up; confidence is the honest signal available now.
    pub fn from_confidence(confidence: Confidence) -> Self {
        // `confidence` is already in [0.0, 1.0]; round to the nearest bucket.
        Self::new((confidence.get() * Self::MAX as f64).round() as u8)
    }

    /// The raw `0..=9` value, for the AMQP message `priority` property.
    pub fn get(self) -> u8 {
        self.0
    }
}

/// The one command in the system (§2): an instruction to simulate one provisional
/// alert. Keyed by `alert_id` — the worker's result re-enters Kafka under the same
/// id, so a redelivered job (RabbitMQ is at-least-once) confirms the same alert and
/// downstream projections dedup it (§7).
///
/// Carries the alert-level facts a worker needs to *start*; it deliberately does
/// **not** carry the `(block, tx_set)` — `PreliminaryAlertCreated` doesn't, and the
/// dispatcher is thin (§7). The worker resolves the implicated block + transactions
/// from the alert's `DetectorTriggered` evidence via the event store (§4 audit
/// query) before simulating, and caches by `(block, tx_set)` there (§7 hardening).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationJob {
    /// The provisional alert this job confirms or retracts. The result's key, and
    /// the idempotency key for a redelivered job.
    pub alert_id: AlertId,
    /// Which chain to simulate on (from the source envelope; the worker needs it
    /// to pick the right fork/RPC).
    pub chain: Chain,
    /// The behaviour to confirm (sandwich, arbitrage, …) — selects the simulation
    /// strategy (§7 "what simulation confirms").
    pub kind: AlertKind,
    /// The detector that raised the alert, carried through for provenance so the
    /// confirmed incident stays reproducible against an exact build (§6, §18).
    pub detector: DetectorRef,
    /// The on-chain accounts implicated by the alert (attribution-blind facts —
    /// the alert's `addresses`, §6).
    pub addresses: Vec<AccountAddress>,
    /// The fast-path confidence, carried so a worker can prioritise/threshold.
    pub confidence: Confidence,
    /// Work-queue priority `0..=9` (§7).
    pub priority: Priority,
}

impl SimulationJob {
    /// Serialize to JSON bytes for the RabbitMQ message body. The worker decodes
    /// the inverse.
    pub fn to_json_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

/// Map a provisional alert to the work it dispatches: the `SimulationJob` command
/// to queue on RabbitMQ, and the `SimulationRequested` domain event to publish on
/// Kafka alongside it so the *request* is auditable even though the command is not
/// (§7). `chain` comes from the source envelope.
///
/// Pure — no Kafka, no RabbitMQ — so the dispatch decision is unit-testable.
pub fn job_for_alert(
    chain: Chain,
    alert: &PreliminaryAlertCreated,
) -> (SimulationJob, SimulationRequested) {
    let job = SimulationJob {
        alert_id: alert.alert_id,
        chain,
        kind: alert.kind,
        detector: alert.detector.clone(),
        addresses: alert.addresses.clone(),
        confidence: alert.confidence,
        priority: Priority::from_confidence(alert.confidence),
    };
    let requested = SimulationRequested {
        alert_id: alert.alert_id,
        // The request's evidence as the dispatcher sees it — the alert-level facts
        // it queued the job on. (The detector's own evidence lives on the alert's
        // `DetectorTriggered`; the worker resolves that from the event store.)
        evidence: request_evidence(&job),
    };
    (job, requested)
}

/// A small JSON summary of what was dispatched, stamped onto the audit event so an
/// operator can see *why* a job was queued without joining back to the trigger.
/// `serde_json`'s default object is a sorted map, so the keys are stable across runs.
fn request_evidence(job: &SimulationJob) -> serde_json::Value {
    serde_json::json!({
        "kind": job.kind,
        "confidence": job.confidence.get(),
        "priority": job.priority.get(),
        "detector": job.detector,
        "addresses": job.addresses,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;

    fn an_alert() -> PreliminaryAlertCreated {
        PreliminaryAlertCreated {
            alert_id: AlertId::new(),
            detector: DetectorRef {
                id: "sandwich".into(),
                version: "1.2.0".into(),
                config_hash: "deadbeef".into(),
            },
            addresses: vec![Address::repeat_byte(0x11), Address::repeat_byte(0x22)],
            kind: AlertKind::Sandwich,
            confidence: Confidence::new(0.8),
            provisional: true,
        }
    }

    #[test]
    fn priority_clamps_to_the_queue_max() {
        assert_eq!(Priority::new(3).get(), 3);
        assert_eq!(Priority::new(42).get(), Priority::MAX);
    }

    #[test]
    fn priority_from_confidence_maps_onto_the_0_9_band() {
        assert_eq!(Priority::from_confidence(Confidence::new(0.0)).get(), 0);
        assert_eq!(Priority::from_confidence(Confidence::new(1.0)).get(), 9);
        // 0.8 * 9 = 7.2 → 7; a high-confidence alert outranks a low one.
        assert_eq!(Priority::from_confidence(Confidence::new(0.8)).get(), 7);
        assert!(
            Priority::from_confidence(Confidence::new(0.9))
                > Priority::from_confidence(Confidence::new(0.1))
        );
    }

    #[test]
    fn job_for_alert_projects_the_alert_and_keys_both_outputs_by_alert_id() {
        let alert = an_alert();
        let (job, requested) = job_for_alert(Chain::ETHEREUM, &alert);

        // The command is a faithful projection of the alert + envelope chain.
        assert_eq!(job.alert_id, alert.alert_id);
        assert_eq!(job.chain, Chain::ETHEREUM);
        assert_eq!(job.kind, alert.kind);
        assert_eq!(job.detector, alert.detector);
        assert_eq!(job.addresses, alert.addresses);
        assert_eq!(job.confidence, alert.confidence);
        assert_eq!(job.priority, Priority::from_confidence(alert.confidence));

        // The audit event shares the alert_id so the request is findable by alert.
        assert_eq!(requested.alert_id, alert.alert_id);
        assert_eq!(requested.evidence["kind"], serde_json::json!(alert.kind));
        assert_eq!(requested.evidence["priority"], serde_json::json!(7));
    }

    #[test]
    fn job_round_trips_through_json() {
        let (job, _) = job_for_alert(Chain::ETHEREUM, &an_alert());
        let bytes = job.to_json_vec().unwrap();
        let back: SimulationJob = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(job, back);
    }
}
