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
//! ## Restamping the scoring triple (§7)
//!
//! An [`IncidentCreated`] carries the same scoring triple a `PreliminaryAlertCreated`
//! does — `impact_usd`, `severity`, `suggested_action` — but *restamped from the
//! confirmed figures*, superseding the fast path's provisional estimate. The
//! provisional band was a coarse pre-trade guess (the detector's `impact_usd`
//! discounted by `confidence`, §6); the confirmed band is revm-measured harm at
//! **full confidence** — the money is known to have moved, so nothing is discounted.
//! Both bands come from the one shared policy ([`events::scoring`]), so the confirmed
//! incident can never disagree with the provisional alert on the banding *rule*, only
//! on the *figures* — which is the whole point of confirming.
//!
//! The engine works in ETH (balance diffs); the bands are USD. The bridge is the
//! operator-configured [`EthUsdPrice`] reference (the coarse valuation §7 defers the
//! real feed for), applied here at the result seam rather than in the pure engine —
//! keeping the simulator a price-free function of its scenario.
//!
//! Everything is keyed by `alert_id`, so a redelivered job's duplicate result is a
//! no-op the downstream projections dedup (§7 idempotency) — which is exactly why
//! the worker pool can ack-after-publish at-least-once without exactly-once
//! machinery.

use events::primitives::{Confidence, IncidentId, UsdAmount};
use events::scoring::{severity_band, suggested_action};
use events::simulation::{IncidentCreated, SimulationCompleted};
use events::DomainEvent;

use crate::simulator::SimulationOutcome;

/// A confirmed simulation figure is *measured*, not estimated, so its restamp
/// bands the raw USD impact at full confidence — no likelihood discount, unlike
/// the fast path's provisional estimate ([`events::scoring::severity_band`]).
const CONFIRMED_CONFIDENCE: Confidence = Confidence::CERTAIN;

/// A validated ETH→USD reference price for restamping confirmed figures onto the
/// scoring bands (§7). A newtype (mirrors [`MinProfit`](crate::simulator::MinProfit)):
/// a negative or non-finite price is rejected at construction, so a fat-fingered
/// `SIMULATION_ETH_USD_PRICE=-1` fails at boot rather than silently scoring every
/// incident `Low`. Deliberately coarse — a single operator-set reference, the
/// placeholder §7 keeps until a real price feed lands, exactly the discipline
/// `impact_usd` is documented as ("coarse, lossy estimate fit for banding").
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct EthUsdPrice(f64);

/// An [`EthUsdPrice`] was constructed from a value that isn't a finite,
/// non-negative number.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
#[error("eth/usd price {value} is not a finite, non-negative number")]
pub struct InvalidEthUsdPrice {
    pub value: f64,
}

impl EthUsdPrice {
    /// Validate `usd` is finite and `>= 0.0`.
    pub fn try_new(usd: f64) -> Result<Self, InvalidEthUsdPrice> {
        if usd.is_finite() && usd >= 0.0 {
            Ok(Self(usd))
        } else {
            Err(InvalidEthUsdPrice { value: usd })
        }
    }

    pub fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for EthUsdPrice {
    type Error = InvalidEthUsdPrice;

    fn try_from(usd: f64) -> Result<Self, Self::Error> {
        Self::try_new(usd)
    }
}

/// Project a simulation outcome onto the domain events to publish, in order:
/// `SimulationCompleted` first (always), then `IncidentCreated` (only when
/// confirmed) with the scoring triple restamped from the confirmed figures via
/// `eth_usd_price` (see the module docs). The `IncidentId` is minted here — a
/// fresh confirmed-incident identity (§7) — while the `alert_id` linkage flows
/// through both events so the projection can join the incident back to its
/// provisional alert.
///
/// Pure: a deterministic function of `(outcome, eth_usd_price)`, so the same
/// backtest replay produces the same events.
pub fn events_for_outcome(
    outcome: &SimulationOutcome,
    eth_usd_price: EthUsdPrice,
) -> Vec<DomainEvent> {
    let completed = SimulationCompleted {
        alert_id: outcome.alert_id,
        profit: outcome.profit,
        victim_loss: outcome.victim_loss,
        confirmed: outcome.confirmed,
    };
    let mut events = vec![DomainEvent::SimulationCompleted(completed)];

    if outcome.confirmed {
        let impact_usd = confirmed_impact_usd(outcome, eth_usd_price);
        let severity = severity_band(Some(impact_usd), CONFIRMED_CONFIDENCE);
        let victim_loss_usd = outcome
            .victim
            .map(|_| UsdAmount::new(outcome.victim_loss * eth_usd_price.get()));
        events.push(DomainEvent::IncidentCreated(IncidentCreated {
            incident_id: IncidentId::new(),
            alert_id: outcome.alert_id,
            kind: outcome.kind,
            txs: outcome.txs.clone(),
            profit: outcome.profit,
            victim_loss: outcome.victim_loss,
            impact_usd: Some(impact_usd),
            severity,
            suggested_action: suggested_action(severity),
            victim_address: outcome.victim,
            victim_loss_usd,
        }));
    }
    events
}

/// The confirmed incident's headline USD impact: the larger of attacker profit
/// and victim loss (the blast radius §7 confirms), valued at `eth_usd_price`.
/// `UsdAmount::new` sanitizes the product, so a sign-aware negative figure (the
/// engine can report one) collapses to `0.0` rather than poisoning the band.
fn confirmed_impact_usd(outcome: &SimulationOutcome, eth_usd_price: EthUsdPrice) -> UsdAmount {
    let headline_eth = outcome.profit.max(outcome.victim_loss);
    UsdAmount::new(headline_eth * eth_usd_price.get())
}

#[cfg(test)]
mod tests {
    use super::*;
    use events::primitives::{AlertId, AlertKind, Severity, SuggestedAction};
    use revm::primitives::B256;

    /// A reference price where 1 ETH = $2,000, so the USD bands sit at round ETH
    /// figures: Medium ≥ 5 ETH, High ≥ 50 ETH, Critical ≥ 500 ETH.
    fn price() -> EthUsdPrice {
        EthUsdPrice::try_new(2_000.0).unwrap()
    }

    fn outcome(confirmed: bool, profit: f64, victim_loss: f64) -> SimulationOutcome {
        outcome_with_victim(confirmed, profit, victim_loss, Some(victim_address()))
    }

    fn victim_address() -> events::primitives::AccountAddress {
        events::primitives::AccountAddress::repeat_byte(0x55)
    }

    fn outcome_with_victim(
        confirmed: bool,
        profit: f64,
        victim_loss: f64,
        victim: Option<events::primitives::AccountAddress>,
    ) -> SimulationOutcome {
        SimulationOutcome {
            alert_id: AlertId::new(),
            kind: AlertKind::Sandwich,
            profit,
            victim_loss,
            confirmed,
            txs: vec![B256::repeat_byte(0x01)],
            victim,
        }
    }

    #[test]
    fn a_confirmed_outcome_emits_completed_then_incident() {
        let out = outcome(true, 5.0, 3.0);
        let events = events_for_outcome(&out, price());
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
            }
            other => panic!("expected IncidentCreated, got {}", other.event_type()),
        }
    }

    #[test]
    fn a_retracted_outcome_emits_only_completed() {
        let events = events_for_outcome(&outcome(false, 5.0, 3.0), price());
        assert_eq!(events.len(), 1, "no incident for an unconfirmed alert");
        assert!(matches!(events[0], DomainEvent::SimulationCompleted(_)));
    }

    #[test]
    fn every_result_is_keyed_by_alert_id() {
        // The dedup key (§7): both events carry the outcome's alert_id.
        let out = outcome(true, 5.0, 3.0);
        for event in events_for_outcome(&out, price()) {
            let alert_id = match event {
                DomainEvent::SimulationCompleted(c) => c.alert_id,
                DomainEvent::IncidentCreated(i) => i.alert_id,
                other => panic!("unexpected event {}", other.event_type()),
            };
            assert_eq!(alert_id, out.alert_id);
        }
    }

    /// The scoring triple is restamped from the confirmed figures at full
    /// confidence and the configured price: 60 ETH profit × $2,000 = $120,000,
    /// which clears the High USD band — regardless of the (larger) victim loss
    /// being what would set the headline here.
    #[test]
    fn incident_scoring_is_restamped_from_confirmed_figures() {
        // Headline is max(profit, victim_loss) = 60 ETH → $120k → High.
        let events = events_for_outcome(&outcome(true, 60.0, 10.0), price());
        let DomainEvent::IncidentCreated(i) = &events[1] else {
            panic!("expected an incident");
        };
        assert_eq!(i.impact_usd, Some(UsdAmount::new(120_000.0)));
        assert_eq!(i.severity, Severity::High);
        assert_eq!(i.suggested_action, SuggestedAction::Escalate);
    }

    /// Victim loss, not profit, can set the headline — a honeypot confirms with
    /// zero attacker profit but real trapped value, and the restamp must reflect
    /// the victim's harm, not the (zero) profit.
    #[test]
    fn victim_loss_sets_the_headline_when_it_exceeds_profit() {
        // 8 ETH trapped × $2,000 = $16,000 → Medium (profit is 0).
        let events = events_for_outcome(&outcome(true, 0.0, 8.0), price());
        let DomainEvent::IncidentCreated(i) = &events[1] else {
            panic!("expected an incident");
        };
        assert_eq!(i.impact_usd, Some(UsdAmount::new(16_000.0)));
        assert_eq!(i.severity, Severity::Medium);
        assert_eq!(i.suggested_action, SuggestedAction::Investigate);
    }

    /// A sign-aware negative figure (the engine can report one) sanitizes to a
    /// `$0` impact and a conservative `Low` band, never a poisoned comparison.
    #[test]
    fn a_negative_figure_sanitizes_to_low() {
        let events = events_for_outcome(&outcome(true, -3.0, -1.0), price());
        let DomainEvent::IncidentCreated(i) = &events[1] else {
            panic!("expected an incident");
        };
        assert_eq!(i.impact_usd, Some(UsdAmount::new(0.0)));
        assert_eq!(i.severity, Severity::Low);
        assert_eq!(i.suggested_action, SuggestedAction::Monitor);
    }

    /// A named victim is stamped onto the incident with its own USD-valued loss —
    /// distinct from `impact_usd`, which here is profit-driven (60 ETH > 10 ETH).
    #[test]
    fn a_named_victim_is_stamped_with_its_usd_loss() {
        let out = outcome(true, 60.0, 10.0);
        let events = events_for_outcome(&out, price());
        let DomainEvent::IncidentCreated(i) = &events[1] else {
            panic!("expected an incident");
        };
        assert_eq!(i.victim_address, Some(victim_address()));
        assert_eq!(i.victim_loss_usd, Some(UsdAmount::new(20_000.0)));
        assert_ne!(
            i.victim_loss_usd, i.impact_usd,
            "victim_loss_usd is the victim's own loss, not the profit-driven headline"
        );
    }

    /// A scenario with no named victim (e.g. `Honeypot`'s synthetic prober) stamps
    /// neither field — `None`, not a guessed `$0`.
    #[test]
    fn no_named_victim_leaves_both_fields_unset() {
        let out = outcome_with_victim(true, 0.0, 8.0, None);
        let events = events_for_outcome(&out, price());
        let DomainEvent::IncidentCreated(i) = &events[1] else {
            panic!("expected an incident");
        };
        assert_eq!(i.victim_address, None);
        assert_eq!(i.victim_loss_usd, None);
        assert_eq!(
            i.impact_usd,
            Some(UsdAmount::new(16_000.0)),
            "the headline impact is unaffected by there being no named victim"
        );
    }

    #[test]
    fn eth_usd_price_rejects_non_finite_and_negative() {
        assert!(EthUsdPrice::try_new(-1.0).is_err());
        assert!(EthUsdPrice::try_new(f64::NAN).is_err());
        assert!(EthUsdPrice::try_new(f64::INFINITY).is_err());
        assert_eq!(EthUsdPrice::try_new(2_500.0).unwrap().get(), 2_500.0);
    }
}
