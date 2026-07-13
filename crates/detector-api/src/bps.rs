//! [`Bps`] — a ratio expressed in basis points (1 bp = 0.01%), the shared unit the
//! detectors measure fractional signals in (a liquidation bonus, a pool-drain
//! fraction, a wash-trader's net/gross churn).
//!
//! A validated newtype rather than a bare `u32`, for the same reason [`UsdPrice`]
//! and [`Confidence`] are newtypes: the *conversion* from a raw on-chain ratio into
//! bps carries an invariant — a divide-by-zero guard and a saturating clamp so a
//! degenerate ratio (an amount decoded larger than the reserve it drained) can't
//! overflow the wire `u32`. Centralising that here means the three detectors that
//! compute a bps figure can't each re-derive the clamp slightly differently, and
//! the figure they put on the wire is a self-describing type, not an anonymous int.
//!
//! [`UsdPrice`]: crate::enrichment::UsdPrice
//! [`Confidence`]: events::primitives::Confidence

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

/// A ratio in basis points (1 bp = 0.01%, so `10_000` bp = 100%).
///
/// `#[serde(transparent)]` so the wire form is a bare integer — a detector's typed
/// `*Detail` payload carries a `Bps` field that serialises identically to the plain
/// `u32` it replaced, and a config threshold deserialises from a plain number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Bps(u32);

impl Bps {
    /// Wrap a known bps figure (a config threshold declared in code).
    pub const fn new(bps: u32) -> Self {
        Self(bps)
    }

    /// The raw basis-point count.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// `num / den` as basis points, rounded down. `None` when `den` is zero — a
    /// ratio of nothing is undefined, and the caller (a detector gate) treats it as
    /// "no signal" rather than a fabricated zero.
    ///
    /// Saturating: with `num > den` (e.g. an outflow decoded alongside a same-block
    /// deposit, exceeding the recorded reserve) the figure is clamped to `u32::MAX`
    /// rather than wrapping — the wire field stays a sane, monotone fraction.
    pub fn from_ratio_u256(num: U256, den: U256) -> Option<Self> {
        if den.is_zero() {
            return None;
        }
        let bps = f64::from(num) / f64::from(den) * 10_000.0;
        Some(Self(bps.min(f64::from(u32::MAX)) as u32))
    }

    /// `num / den` as basis points from valued (`f64`) quantities — the USD-space
    /// analogue of [`from_ratio_u256`](Self::from_ratio_u256). `None` unless `den`
    /// is a positive, finite number and `num` is non-negative, so a malformed or
    /// negative ratio surfaces as "no signal" instead of a nonsense figure.
    pub fn from_ratio_f64(num: f64, den: f64) -> Option<Self> {
        // Reject a non-positive or non-finite denominator and a negative or
        // non-finite numerator, so only a well-formed ratio produces a figure.
        if !den.is_finite() || den <= 0.0 || !num.is_finite() || num < 0.0 {
            return None;
        }
        let bps = num / den * 10_000.0;
        bps.is_finite()
            .then(|| Self(bps.min(f64::from(u32::MAX)) as u32))
    }
}

impl std::fmt::Display for Bps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}bps", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_ratio_u256_rounds_down_and_guards_zero() {
        // 900_000 / 1_000_000 = 90% = 9_000 bp.
        assert_eq!(
            Bps::from_ratio_u256(U256::from(900_000u64), U256::from(1_000_000u64)),
            Some(Bps::new(9_000))
        );
        // A zero denominator is "no signal", not a divide panic.
        assert_eq!(Bps::from_ratio_u256(U256::from(1u64), U256::ZERO), None);
    }

    #[test]
    fn from_ratio_u256_saturates_beyond_full() {
        // num > den (decoded outflow exceeds the recorded reserve): clamp, don't wrap.
        let bps = Bps::from_ratio_u256(U256::from(3u64), U256::from(1u64)).unwrap();
        assert_eq!(bps, Bps::new(30_000));
        // Astronomically lopsided still clamps to u32::MAX, never overflows.
        let huge = Bps::from_ratio_u256(U256::MAX, U256::from(1u64)).unwrap();
        assert_eq!(huge.get(), u32::MAX);
    }

    #[test]
    fn from_ratio_f64_bonus_semantics() {
        // A liquidation bonus: (2160 - 2000) / 2000 = 8% = 800 bp.
        assert_eq!(Bps::from_ratio_f64(160.0, 2000.0), Some(Bps::new(800)));
        // Zero numerator is a real 0 bp (a par trade), not "no signal".
        assert_eq!(Bps::from_ratio_f64(0.0, 2000.0), Some(Bps::new(0)));
    }

    #[test]
    fn from_ratio_f64_rejects_degenerate_inputs() {
        assert_eq!(Bps::from_ratio_f64(1.0, 0.0), None); // divide by zero
        assert_eq!(Bps::from_ratio_f64(1.0, -1.0), None); // negative denominator
        assert_eq!(Bps::from_ratio_f64(-1.0, 1.0), None); // negative ratio
        assert_eq!(Bps::from_ratio_f64(1.0, f64::NAN), None); // NaN
    }

    #[test]
    fn serializes_transparently_as_a_bare_integer() {
        assert_eq!(serde_json::to_string(&Bps::new(500)).unwrap(), "500");
        assert_eq!(serde_json::from_str::<Bps>("500").unwrap(), Bps::new(500));
    }

    #[test]
    fn orders_by_magnitude_for_threshold_gates() {
        // The whole point: a computed bps compares against a config threshold.
        assert!(Bps::new(100) < Bps::new(300));
    }
}
