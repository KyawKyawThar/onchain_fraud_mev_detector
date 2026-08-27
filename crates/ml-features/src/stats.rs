//! Total, order-safe numeric helpers for the extractors.
//!
//! Every function here is **total over all f64 inputs and returns a finite
//! value** — empty input, zero denominator, and non-finite intermediates all
//! collapse to `0.0` rather than propagating a `NaN`/`inf` into a model
//! input. `0.0` is the honest "nothing to measure" for every feature these
//! feed (all are non-negative by construction), which is also what keeps the
//! empty-block and header-only-source vectors well-defined.

/// `log10(1 + x)` for a non-negative magnitude; `0.0` for anything else
/// (including non-finite). Compresses heavy-tailed on-chain quantities
/// (counts, USD amounts, gas) into a scale a model can use.
///
/// Routed through the pure-Rust `libm` rather than `f64::log10` (the host C
/// library): C libms differ in the last ulp across platforms, and this is the
/// one non-IEEE-exact operation in the extractors — pinning it is what makes
/// "same context ⇒ same bits" hold across OSes, not just per binary. (The
/// `sqrt` in [`std_dev`] stays std: IEEE 754 requires it correctly rounded.)
pub(crate) fn log10_1p(x: f64) -> f64 {
    if x.is_finite() && x > 0.0 {
        libm::log10(1.0 + x)
    } else {
        0.0
    }
}

/// `num / den` as a count fraction; `0.0` when `den == 0`.
pub(crate) fn fraction(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

/// `num / den` guarded: `0.0` unless both are finite, `den > 0`, and the
/// quotient is finite.
pub(crate) fn ratio(num: f64, den: f64) -> f64 {
    if !num.is_finite() || !den.is_finite() || den <= 0.0 {
        return 0.0;
    }
    let r = num / den;
    if r.is_finite() {
        r
    } else {
        0.0
    }
}

/// Arithmetic mean; `0.0` on empty.
pub(crate) fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

/// Population standard deviation; `0.0` for fewer than two values.
pub(crate) fn std_dev(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let m = mean(values);
    let var = values.iter().map(|v| (v - m) * (v - m)).sum::<f64>() / values.len() as f64;
    var.sqrt()
}

/// Median (sorts its input in place with `total_cmp`, so the result does not
/// depend on the caller's iteration order); `0.0` on empty.
pub(crate) fn median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_unstable_by(f64::total_cmp);
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

/// Median absolute deviation about `center` (sorts its input in place, so it
/// is caller-order independent); `0.0` on empty.
///
/// The robust twin of [`std_dev`], and the spread a [`crate::FeatureBaseline`]
/// carries: on-chain feature columns are heavy-tailed, and one extreme sample
/// inflates a standard deviation enough to hide every subsequent outlier
/// behind it. A MAD is unmoved by up to half the samples being extreme.
pub(crate) fn mad(values: &mut [f64], center: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    for value in values.iter_mut() {
        *value = (*value - center).abs();
    }
    median(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log10_1p_is_total_and_zero_floored() {
        assert_eq!(log10_1p(0.0), 0.0);
        assert_eq!(log10_1p(9.0), 1.0);
        assert_eq!(log10_1p(-5.0), 0.0);
        assert_eq!(log10_1p(f64::NAN), 0.0);
        assert_eq!(log10_1p(f64::INFINITY), 0.0);
    }

    #[test]
    fn empty_and_degenerate_inputs_yield_zero() {
        assert_eq!(fraction(0, 0), 0.0);
        assert_eq!(ratio(1.0, 0.0), 0.0);
        assert_eq!(ratio(f64::NAN, 2.0), 0.0);
        assert_eq!(ratio(1.0, f64::NAN), 0.0);
        assert_eq!(mean(&[]), 0.0);
        assert_eq!(std_dev(&[]), 0.0);
        assert_eq!(std_dev(&[3.0]), 0.0);
        assert_eq!(median(&mut []), 0.0);
    }

    #[test]
    fn the_happy_paths_compute() {
        assert_eq!(fraction(1, 4), 0.25);
        assert_eq!(ratio(9.0, 3.0), 3.0);
        assert_eq!(mean(&[1.0, 2.0, 3.0]), 2.0);
        assert_eq!(std_dev(&[2.0, 2.0, 2.0]), 0.0);
        assert!((std_dev(&[1.0, 3.0]) - 1.0).abs() < 1e-12);
        assert_eq!(median(&mut [3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&mut [4.0, 1.0, 2.0, 3.0]), 2.5);
    }

    #[test]
    fn mad_is_robust_and_order_independent() {
        // Absolute deviations about 3.0 are {2,1,0,1,2} → median 1.0 …
        assert_eq!(mad(&mut [1.0, 2.0, 3.0, 4.0, 5.0], 3.0), 1.0);
        // … and stay 1.0 when one sample explodes, which is the whole point.
        assert_eq!(mad(&mut [1.0, 2.0, 3.0, 4.0, 1e12], 3.0), 1.0);
        assert_eq!(
            mad(&mut [5.0, 1.0, 4.0, 2.0, 3.0], 3.0),
            mad(&mut [3.0, 2.0, 1.0, 5.0, 4.0], 3.0)
        );
        assert_eq!(mad(&mut [], 0.0), 0.0);
        // A column that never varied has no spread at all.
        assert_eq!(mad(&mut [7.0, 7.0, 7.0], 7.0), 0.0);
    }

    #[test]
    fn median_is_iteration_order_independent() {
        let mut a = [5.0, 1.0, 9.0, 3.0];
        let mut b = [9.0, 3.0, 5.0, 1.0];
        assert_eq!(median(&mut a), median(&mut b));
    }
}
