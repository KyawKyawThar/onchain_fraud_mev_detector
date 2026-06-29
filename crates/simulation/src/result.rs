//! The pure mapping from a [`SimulationOutcome`] to the domain events the worker
//! publishes back onto the Kafka backbone (§7) — the result counterpart to
//! [`command::job_for_alert`](crate::command::job_for_alert), and shaped like
//! detection's `emit.rs`: no I/O, no async, `assert_eq!`-testable, backtest-safe.
//!
//! A finished simulation always emits a [`SimulationCompleted`] (the audit fact that
//! the slow path ran, carrying the profit/loss figures). When the run **confirms**
//! the alert it additionally emits an [`IncidentCreated`] — the confirmed incident
//! that the intelligence and notification services upgrade the provisional alert
//! from (§7 fast/slow data flow).
//!
//! Everything is keyed by `alert_id`, so a redelivered job's duplicate result is a
//! no-op the downstream projections dedup (§7 idempotency) — which is exactly why
//! the worker pool can ack-after-publish at-least-once without exactly-once
//! machinery.

use events::primitives::IncidentId;
use events::simulation::{IncidentCreated, SimulationCompleted};
use events::DomainEvent;

use crate::simulator::SimulationOutcome;

/// Project a simulation outcome onto the domain events to publish, in order:
/// `SimulationCompleted` first (always), then `IncidentCreated` (only when
/// confirmed). The `IncidentId` is minted here — a fresh confirmed-incident
/// identity (§7) — while the `alert_id` linkage flows through `SimulationCompleted`
/// so the projection can join the incident back to its provisional alert.
///
/// Pure: a deterministic function of the outcome, so the same backtest replay
/// produces the same events.
pub fn events_for_outcome(outcome: &SimulationOutcome) -> Vec<DomainEvent> {
    let completed = SimulationCompleted {
        alert_id: outcome.alert_id,
        profit: outcome.profit,
        victim_loss: outcome.victim_loss,
        confirmed: outcome.confirmed,
    };
    let mut events = vec![DomainEvent::SimulationCompleted(completed)];

    if outcome.confirmed {
        events.push(DomainEvent::IncidentCreated(IncidentCreated {
            incident_id: IncidentId::new(),
            alert_id: outcome.alert_id,
            kind: outcome.kind,
            txs: outcome.txs.clone(),
            profit: outcome.profit,
            victim_loss: outcome.victim_loss,
            severity: outcome.severity,
        }));
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use events::primitives::{AlertId, AlertKind, Severity};
    use revm::primitives::B256;

    use crate::simulator::SimulationOutcome;

    fn outcome(confirmed: bool) -> SimulationOutcome {
        SimulationOutcome {
            alert_id: AlertId::new(),
            kind: AlertKind::Sandwich,
            profit: 5.0,
            victim_loss: 3.0,
            confirmed,
            severity: Severity::Medium,
            txs: vec![B256::repeat_byte(0x01)],
        }
    }

    #[test]
    fn a_confirmed_outcome_emits_completed_then_incident() {
        let out = outcome(true);
        let events = events_for_outcome(&out);
        assert_eq!(events.len(), 2);

        match &events[0] {
            DomainEvent::SimulationCompleted(c) => {
                assert_eq!(c.alert_id, out.alert_id);
                assert_eq!(c.profit, 5.0);
                assert_eq!(c.victim_loss, 3.0);
                assert!(c.confirmed);
            }
            other => panic!("expected SimulationCompleted, got {}", other.event_type()),
        }
        match &events[1] {
            DomainEvent::IncidentCreated(i) => {
                // Linked to the same alert, carrying the confirmed figures + txs.
                assert_eq!(i.alert_id, out.alert_id);
                assert_eq!(i.kind, out.kind);
                assert_eq!(i.txs, out.txs);
                assert_eq!(i.severity, Severity::Medium);
            }
            other => panic!("expected IncidentCreated, got {}", other.event_type()),
        }
    }

    #[test]
    fn a_retracted_outcome_emits_only_completed() {
        let events = events_for_outcome(&outcome(false));
        assert_eq!(events.len(), 1, "no incident for an unconfirmed alert");
        assert!(matches!(events[0], DomainEvent::SimulationCompleted(_)));
    }

    #[test]
    fn every_result_is_keyed_by_alert_id() {
        // The dedup key (§7): both events carry the outcome's alert_id.
        let out = outcome(true);
        for event in events_for_outcome(&out) {
            let alert_id = match event {
                DomainEvent::SimulationCompleted(c) => c.alert_id,
                DomainEvent::IncidentCreated(i) => i.alert_id,
                other => panic!("unexpected event {}", other.event_type()),
            };
            assert_eq!(alert_id, out.alert_id);
        }
    }
}
