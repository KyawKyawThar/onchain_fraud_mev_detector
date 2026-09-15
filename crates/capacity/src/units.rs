//! Numbers that cannot hold an invalid value (conventions §4).
//!
//! The likeliest bug in a capacity model is not arithmetic but a quantity in
//! the wrong domain: a fill ceiling of 75 instead of 0.75, a negative rate, a
//! compression ratio below one that silently *inflates* storage. Each of those
//! is a distinct type here, validated where `model.json` is parsed, so the
//! stages downstream take a `Fraction` and cannot be handed a percentage.

use serde::{Deserialize, Serialize};

macro_rules! bounded {
    ($(#[$doc:meta])* $name:ident, |$v:ident| $ok:expr, $msg:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(try_from = "f64", into = "f64")]
        pub struct $name(f64);

        impl $name {
            pub fn new($v: f64) -> Result<Self, String> {
                if $v.is_finite() && $ok {
                    Ok(Self($v))
                } else {
                    Err(format!(concat!("{} ", $msg), $v))
                }
            }

            pub fn get(self) -> f64 {
                self.0
            }
        }

        impl TryFrom<f64> for $name {
            type Error = String;
            fn try_from(v: f64) -> Result<Self, String> {
                Self::new(v)
            }
        }

        impl From<$name> for f64 {
            fn from(v: $name) -> f64 {
                v.0
            }
        }
    };
}

bounded!(
    /// A share in `[0, 1]`.
    Fraction,
    |v| (0.0..=1.0).contains(&v),
    "is not a fraction within 0..=1"
);
bounded!(
    /// A finite quantity above zero.
    Positive,
    |v| v > 0.0,
    "is not positive"
);
bounded!(
    /// A finite quantity at or above zero.
    NonNegative,
    |v| v >= 0.0,
    "is negative"
);
bounded!(
    /// A multiplier that cannot shrink: a compression ratio, a peak-to-mean.
    AtLeastOne,
    |v| v >= 1.0,
    "is below 1"
);
bounded!(
    /// A disk fill ceiling in `(0, 1]` — zero would plan an infinite cluster.
    FillCeiling,
    |v| v > 0.0 && v <= 1.0,
    "is not a fill ceiling within (0, 1]"
);
bounded!(
    /// Gibibytes, above zero.
    Gib,
    |v| v > 0.0,
    "GiB is not positive"
);

/// Bytes in a GiB.
pub const BYTES_PER_GIB: f64 = 1024.0 * 1024.0 * 1024.0;

/// A byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Bytes(pub u64);

impl Bytes {
    pub fn get(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_percentage_is_not_a_fraction() {
        assert!(Fraction::new(75.0).is_err());
        assert!(serde_json::from_str::<Fraction>("0.75").is_ok());
        assert!(serde_json::from_str::<Fraction>("75").is_err());
    }

    #[test]
    fn a_compression_ratio_below_one_is_refused() {
        assert!(AtLeastOne::new(0.5).is_err());
        assert!(FillCeiling::new(0.0).is_err());
        assert!(Positive::new(f64::NAN).is_err());
    }
}
