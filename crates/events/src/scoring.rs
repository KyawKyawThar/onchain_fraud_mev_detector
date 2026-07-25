//! The shared alert-scoring policy (§6, §7) — the one place that bands a USD
//! impact into a [`Severity`] and maps that band to a [`SuggestedAction`].
//!
//! Both paths score against *this* policy so a provisional alert and the
//! incident it confirms into can't drift onto two different banding rules:
//!
//! - the **fast path** (`detection::emit::preliminary_alert`, §6) scores the
//!   provisional estimate — the detector's coarse `impact_usd` discounted by
//!   the finding's `confidence`;
//! - the **slow path** (`simulation::result`, §7) *restamps* the confirmed
//!   figures — revm-measured harm, at full confidence — superseding the
//!   provisional estimate on `IncidentCreated`.
//!
//! Everything here is pure and total: no I/O, no attribution, every input maps
//! to exactly one band. It lives in `events` (not `detection`) precisely so the
//! simulation service can reuse it without depending on the detection engine —
//! it operates only on `events::primitives` types.

use crate::primitives::{Confidence, Severity, SuggestedAction, UsdAmount};

/// USD-impact thresholds for [`severity_band`], applied to `impact_usd *
/// confidence` — a low-confidence high-impact finding and a high-confidence
/// low-impact one land in the same band once discounted by likelihood. Named
/// consts rather than inline literals so the bands are one place to retune.
pub const SEVERITY_CRITICAL_USD: f64 = 1_000_000.0;
pub const SEVERITY_HIGH_USD: f64 = 100_000.0;
pub const SEVERITY_MEDIUM_USD: f64 = 10_000.0;

/// Derive a [`Severity`] band from `impact_usd` discounted by `confidence`
/// (§6) — never from attribution or labels, so a `Critical` band means
/// "high-harm, well-evidenced," not "involves a known bad actor" (that
/// reweighting happens later, in the intelligence service). Pure and total:
/// every input maps to exactly one band.
///
/// `impact_usd` of `None` (the source couldn't price the finding) is
/// conservative, not alarming — it reads as [`Severity::Low`] rather than
/// guessing at a dollar figure that isn't there.
///
/// A confirmed figure (simulation, §7) is measured rather than estimated, so
/// its restamp bands the raw USD at full confidence — see
/// [`Confidence`]-of-`1.0`; the same function serves both paths.
pub fn severity_band(impact_usd: Option<UsdAmount>, confidence: Confidence) -> Severity {
    let Some(impact) = impact_usd else {
        return Severity::Low;
    };
    let weighted = impact.get() * confidence.get();
    if weighted >= SEVERITY_CRITICAL_USD {
        Severity::Critical
    } else if weighted >= SEVERITY_HIGH_USD {
        Severity::High
    } else if weighted >= SEVERITY_MEDIUM_USD {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// The operator-facing next step for a [`Severity`] band (§6) — a closed,
/// total mapping so every alert carries an actionable recommendation rather
/// than leaving each consumer to interpret the band ad hoc.
pub fn suggested_action(severity: Severity) -> SuggestedAction {
    match severity {
        Severity::Low => SuggestedAction::Monitor,
        Severity::Medium => SuggestedAction::Investigate,
        Severity::High => SuggestedAction::Escalate,
        Severity::Critical => SuggestedAction::EscalateImmediately,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_band_is_conservative_when_impact_is_unknown() {
        assert_eq!(
            severity_band(None, Confidence::new(1.0)),
            Severity::Low,
            "no priced impact reads Low, not a guessed dollar figure",
        );
    }

    #[test]
    fn severity_band_discounts_impact_by_confidence() {
        // At full confidence the raw impact bands directly.
        assert_eq!(
            severity_band(
                Some(UsdAmount::new(SEVERITY_CRITICAL_USD)),
                Confidence::new(1.0)
            ),
            Severity::Critical,
        );
        assert_eq!(
            severity_band(
                Some(UsdAmount::new(SEVERITY_HIGH_USD)),
                Confidence::new(1.0)
            ),
            Severity::High,
        );
        assert_eq!(
            severity_band(
                Some(UsdAmount::new(SEVERITY_MEDIUM_USD)),
                Confidence::new(1.0)
            ),
            Severity::Medium,
        );
        assert_eq!(
            severity_band(Some(UsdAmount::new(1.0)), Confidence::new(1.0)),
            Severity::Low,
        );
        // Half confidence pulls a Critical-scale impact down into the High band.
        assert_eq!(
            severity_band(
                Some(UsdAmount::new(SEVERITY_CRITICAL_USD)),
                Confidence::new(0.5)
            ),
            Severity::High,
        );
    }

    #[test]
    fn suggested_action_is_a_total_one_to_one_mapping_from_severity() {
        assert_eq!(suggested_action(Severity::Low), SuggestedAction::Monitor);
        assert_eq!(
            suggested_action(Severity::Medium),
            SuggestedAction::Investigate
        );
        assert_eq!(suggested_action(Severity::High), SuggestedAction::Escalate);
        assert_eq!(
            suggested_action(Severity::Critical),
            SuggestedAction::EscalateImmediately,
        );
    }
}
