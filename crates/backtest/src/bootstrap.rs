//! A moving-block bootstrap for a false-positive rate over replay windows
//! (§18; Epic E).
//!
//! # Why the Wilson bound is not enough on its own
//!
//! The Wilson interval assumes each adjudicated alert is an independent
//! draw. Alerts on mainnet are not: one bot repeats one strategy across a
//! run of blocks, one mispriced pool produces a burst of refutations. Twelve
//! refutations in one block are closer to one event than to twelve, and the
//! Wilson bound over them is optimistic. (The unit test below shows a case
//! where Wilson reads 3.1% and this reads 5.7% against a 4% target.)
//!
//! A moving-block bootstrap keeps that correlation: it resamples *runs* of
//! consecutive blocks, not single alerts, so a burst is resampled whole.
//! Runs never cross a window boundary, since windows are separate stretches of
//! time. The claim requires both bounds to clear ([`crate::claim`]).
//!
//! # Deterministic by construction
//!
//! The generator is a seeded SplitMix64, written here rather than pulled in,
//! so a verdict is a pure function of `(corpus, policy)`. A claim whose truth
//! depends on the run is not one a README can quote.

/// One block's adjudicated alerts, in block order within its window.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BlockTally {
    pub confirmed: u32,
    pub refuted: u32,
}

/// Bootstrap parameters. Part of the committed [`crate::claim::ClaimPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockBootstrap {
    /// Blocks per resampled run. Long enough to hold a typical burst (25
    /// Ethereum blocks is five minutes), short enough that a window yields
    /// several runs.
    pub block_len: usize,
    pub replicates: u32,
    pub seed: u64,
}

impl BlockBootstrap {
    /// The upper `quantile` of the resampled false-positive rate across
    /// `windows`, or `None` when the evidence cannot support one: no windows,
    /// or too many replicates with no adjudicated alert at all (more than
    /// `1 - quantile` of them, which would make the quantile undefined).
    pub fn upper_bound(&self, windows: &[&[BlockTally]], quantile: f64) -> Option<f64> {
        let windows: Vec<&[BlockTally]> =
            windows.iter().copied().filter(|w| !w.is_empty()).collect();
        if windows.is_empty() || self.replicates == 0 {
            return None;
        }
        let mut rng = SplitMix64(self.seed);
        let mut rates = Vec::with_capacity(self.replicates as usize);
        let mut undefined = 0u32;
        for _ in 0..self.replicates {
            let (mut confirmed, mut refuted) = (0u64, 0u64);
            for window in &windows {
                let n = window.len();
                let len = self.block_len.clamp(1, n);
                let starts = n - len + 1;
                let mut filled = 0;
                while filled < n {
                    let start = rng.below(starts);
                    let take = len.min(n - filled);
                    for block in &window[start..start + take] {
                        confirmed += u64::from(block.confirmed);
                        refuted += u64::from(block.refuted);
                    }
                    filled += take;
                }
            }
            match confirmed + refuted {
                0 => undefined += 1,
                total => rates.push(refuted as f64 / total as f64),
            }
        }
        let allowed_undefined = ((1.0 - quantile) * f64::from(self.replicates)).floor();
        if f64::from(undefined) > allowed_undefined {
            return None;
        }
        // Undefined replicates carry no refutation, so they sit at the bottom
        // of the distribution: count them as zeros for the quantile's rank.
        rates.sort_by(f64::total_cmp);
        let rank = (quantile * f64::from(self.replicates)).ceil() as usize;
        let index = rank.saturating_sub(1).saturating_sub(undefined as usize);
        rates.get(index.min(rates.len().saturating_sub(1))).copied()
    }
}

/// SplitMix64 (Steele, Lea & Flood): tiny, fast, and well mixed. Not for
/// cryptography, which this is not.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..bound` (Lemire's multiply-shift; the bias at these
    /// bounds is far below anything a percentile can see).
    fn below(&mut self, bound: usize) -> usize {
        ((u128::from(self.next()) * bound as u128) >> 64) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: BlockBootstrap = BlockBootstrap {
        block_len: 25,
        replicates: 2_000,
        seed: 7,
    };

    fn steady(blocks: usize, confirmed: u32) -> Vec<BlockTally> {
        vec![
            BlockTally {
                confirmed,
                refuted: 0
            };
            blocks
        ]
    }

    #[test]
    fn clean_windows_bound_at_zero() {
        let w = steady(100, 2);
        assert_eq!(BOOT.upper_bound(&[&w, &w, &w], 0.95), Some(0.0));
    }

    #[test]
    fn a_burst_widens_the_bound_past_what_wilson_reports() {
        // 600 confirmed alerts and one block with 12 refutations: Wilson
        // (independent alerts) reads 3.1%, under a 4% target.
        let mut burst = steady(100, 2);
        burst[50].refuted = 12;
        let quiet = steady(100, 2);
        let wilson = crate::claim::ClaimPolicy::COMMITTED
            .wilson_interval(12, 612)
            .unwrap()
            .1;
        assert!(wilson < 0.04, "{wilson}");

        let clustered = BOOT.upper_bound(&[&burst, &quiet, &quiet], 0.95).unwrap();
        assert!(
            clustered > 0.04,
            "the burst must be resampled whole: {clustered}"
        );
    }

    #[test]
    fn the_same_seed_gives_the_same_bound() {
        let mut w = steady(60, 1);
        w[3].refuted = 1;
        w[40].refuted = 2;
        let a = BOOT.upper_bound(&[&w], 0.95);
        let b = BOOT.upper_bound(&[&w], 0.95);
        assert_eq!(a, b);
        assert!(a.is_some());
    }

    #[test]
    fn mostly_empty_evidence_has_no_bound() {
        // One alert in 1,000 quiet blocks: most replicates see nothing.
        let mut w = steady(1_000, 0);
        w[500].confirmed = 1;
        assert_eq!(BOOT.upper_bound(&[&w], 0.95), None);
        assert_eq!(BOOT.upper_bound(&[], 0.95), None);
    }

    #[test]
    fn a_window_shorter_than_the_run_is_resampled_whole() {
        let mut short = steady(5, 1);
        short[0].refuted = 1;
        // Every replicate is the whole window: 1 refuted of 6.
        let bound = BOOT.upper_bound(&[&short], 0.95).unwrap();
        assert!((bound - 1.0 / 6.0).abs() < 1e-12, "{bound}");
    }

    #[test]
    fn draws_stay_in_range() {
        let mut rng = SplitMix64(1);
        for bound in [1usize, 2, 3, 76, 1_000] {
            for _ in 0..1_000 {
                assert!(rng.below(bound) < bound);
            }
        }
    }
}
