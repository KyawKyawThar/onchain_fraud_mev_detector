//! The temporal state machine (§9, the pure core of Sprint 9 t3):
//! per-`(rule_id, address)` windowed matching for `Sequence` and `Frequency`
//! rules, as **pure transitions** — `(state, event) → (state', fired?)` and
//! `(state, reverted block) → state'`. No Redis, no clock, no I/O.
//!
//! Functional core / imperative shell: the t3 worker is a thin shell that
//! does `GET → step → SETEX` against Redis (TTL-bounded, keyed by
//! rule + address, §9) and owns partitioning (§17: the event stream is
//! partitioned by address so one worker owns an address's state). Everything
//! that can be wrong — window expiry, ordering, the §15 reorg rewind — lives
//! here, table-testable with zero infrastructure.
//!
//! State is serde-serializable because Redis stores it as JSON; blocks are
//! recorded per hit because the rewind needs to know *which* progress a
//! reverted block contributed (§15: "rewind temporal rule state windows that
//! included events from reverted blocks").

use serde::{Deserialize, Serialize};

use crate::compile::CompiledTemporal;
use crate::ctx::EventCtx;

/// In-flight progress of one temporal rule for one address. `None` (no state
/// stored) is the idle machine — the Redis TTL expiring is equivalent to the
/// window closing, which is what makes TTL-bounded storage sound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemporalState {
    /// Blocks at which the sequence's next-expected steps matched, in step
    /// order. `matched.len()` is the index of the next step to satisfy; the
    /// window is anchored at the first entry.
    Sequence { matched: Vec<u64> },
    /// Blocks at which the frequency condition matched, ascending; pruned to
    /// the sliding window on every step.
    Frequency { hits: Vec<u64> },
}

/// A temporal rule completed: what [`step`] hands back for the shell to raise
/// `RuleTriggered`/`RuleAlertCreated` from. Carries the matched blocks so the
/// alert's audit context can name the evidence window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fired {
    pub matched_blocks: Vec<u64>,
}

/// Advance one rule's machine by one event. Pure — same inputs, same outputs,
/// in live serving and in replay (§18).
///
/// Semantics, pinned by the tests below:
/// * A sequence's window is anchored at its **first** matched step; an event
///   past the window resets the machine, and the *same* event is then offered
///   as a fresh first step (an expired window shouldn't eat a new start).
/// * One event advances a sequence by at most one step (steps are distinct
///   observations; a single event satisfying two steps at once would make
///   "then" meaningless).
/// * Frequency prunes hits older than the window *before* testing the event,
///   so the count is always over a current window.
/// * On fire the state resets to idle (`None`): §9 rules alert per completed
///   window, they don't re-fire on every further event.
pub fn step(
    temporal: &CompiledTemporal,
    state: Option<TemporalState>,
    ctx: &EventCtx,
) -> (Option<TemporalState>, Option<Fired>) {
    match temporal {
        CompiledTemporal::Sequence {
            steps,
            within_blocks,
        } => {
            let mut matched = match state {
                Some(TemporalState::Sequence { matched }) => matched,
                // Wrong-variant state (a rule edit changed the clause kind
                // under a live key): discard rather than misinterpret.
                _ => Vec::new(),
            };
            // Window expiry, anchored at the first matched step.
            if let Some(first) = matched.first() {
                if ctx.block.saturating_sub(*first) > *within_blocks {
                    matched.clear();
                }
            }
            // Defensive: state persisted under an older definition of this
            // rule id could claim more progress than this clause has steps —
            // treat as corrupt and restart rather than index past the end.
            if matched.len() >= steps.len() {
                matched.clear();
            }
            // Offer the event to the next expected step only (see above).
            if steps[matched.len()](ctx) {
                matched.push(ctx.block);
                if matched.len() == steps.len() {
                    return (
                        None,
                        Some(Fired {
                            matched_blocks: matched,
                        }),
                    );
                }
            }
            let state = if matched.is_empty() {
                None
            } else {
                Some(TemporalState::Sequence { matched })
            };
            (state, None)
        }
        CompiledTemporal::Frequency {
            matcher,
            count,
            within_blocks,
        } => {
            let mut hits = match state {
                Some(TemporalState::Frequency { hits }) => hits,
                _ => Vec::new(),
            };
            // Slide the window up to this event's block.
            hits.retain(|hit| ctx.block.saturating_sub(*hit) < *within_blocks);
            if matcher(ctx) {
                hits.push(ctx.block);
                if hits.len() >= *count as usize {
                    return (
                        None,
                        Some(Fired {
                            matched_blocks: hits,
                        }),
                    );
                }
            }
            let state = if hits.is_empty() {
                None
            } else {
                Some(TemporalState::Frequency { hits })
            };
            (state, None)
        }
    }
}

/// Roll one machine back past a reverted block (§15): drop the progress that
/// block contributed, as if its events never happened. Pure, like [`step`];
/// the t3 shell applies it to every in-flight key whose state includes the
/// block (and re-SETs or DELs accordingly — `None` means delete the key).
///
/// The two variants rewind differently, on purpose:
/// * **Sequence** truncates from the first hit at `reverted_block` *onward* —
///   later steps only matched because that step preceded them, so their
///   ordering evidence is gone too.
/// * **Frequency** removes only hits *at* the reverted block — the remaining
///   hits are independent observations and still count. (A deeper reorg
///   delivers one `BlockReverted` per block, each rewound in turn.)
pub fn rewind(state: TemporalState, reverted_block: u64) -> Option<TemporalState> {
    match state {
        TemporalState::Sequence { mut matched } => {
            if let Some(cut) = matched.iter().position(|block| *block >= reverted_block) {
                matched.truncate(cut);
            }
            (!matched.is_empty()).then_some(TemporalState::Sequence { matched })
        }
        TemporalState::Frequency { mut hits } => {
            hits.retain(|block| *block != reverted_block);
            (!hits.is_empty()).then_some(TemporalState::Frequency { hits })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::{Enrichment, EventCtx, EventFacts};
    use crate::test_support::{compliance_rule, frequency_rule};
    use events::primitives::{AccountAddress, Chain, LabelKind};
    use rust_decimal::Decimal;

    fn addr(byte: u8) -> AccountAddress {
        AccountAddress::repeat_byte(byte)
    }

    /// A large USDC transfer at `block` (matches the compliance rule's step 1).
    fn big_transfer(block: u64) -> EventCtx {
        EventCtx {
            address: addr(0x01),
            block,
            facts: EventFacts::Transfer {
                chain: Chain::ETHEREUM,
                token: Some(addr(0xAA)),
                amount: Decimal::new(2_000_000, 0),
                counterparty: addr(0x02),
            },
            enrichment: Enrichment::default(),
        }
    }

    /// A transfer to a mixer-labeled counterparty at `block` (step 2).
    fn mixer_touch(block: u64) -> EventCtx {
        let mut ctx = EventCtx {
            address: addr(0x01),
            block,
            facts: EventFacts::Transfer {
                chain: Chain::ETHEREUM,
                token: None,
                amount: Decimal::new(1, 0),
                counterparty: addr(0x99),
            },
            enrichment: Enrichment::default(),
        };
        ctx.enrichment
            .counterparty_labels
            .insert(LabelKind::MixerUser);
        ctx
    }

    /// An event matching neither step.
    fn noise(block: u64) -> EventCtx {
        EventCtx {
            address: addr(0x01),
            block,
            facts: EventFacts::StateChanged,
            enrichment: Enrichment::default(),
        }
    }

    fn sequence() -> CompiledTemporal {
        crate::compile::temporal_clause(&compliance_rule())
    }

    #[test]
    fn sequence_fires_in_order_within_window() {
        let seq = sequence();
        // Step 1 matches: machine starts.
        let (state, fired) = step(&seq, None, &big_transfer(100));
        assert_eq!(state, Some(TemporalState::Sequence { matched: vec![100] }));
        assert!(fired.is_none());

        // Noise leaves the machine untouched.
        let (state, fired) = step(&seq, state, &noise(120));
        assert_eq!(state, Some(TemporalState::Sequence { matched: vec![100] }));
        assert!(fired.is_none());

        // Step 2 within the window: fires, machine resets.
        let (state, fired) = step(&seq, state, &mixer_touch(150));
        assert_eq!(state, None);
        assert_eq!(
            fired,
            Some(Fired {
                matched_blocks: vec![100, 150]
            })
        );
    }

    #[test]
    fn sequence_out_of_order_does_not_fire() {
        let seq = sequence();
        // Step 2's event first: the machine doesn't start ("then" is ordered).
        let (state, fired) = step(&seq, None, &mixer_touch(100));
        assert_eq!(state, None);
        assert!(fired.is_none());
    }

    #[test]
    fn sequence_window_expires_and_can_restart_on_same_event() {
        let seq = sequence();
        let (state, _) = step(&seq, None, &big_transfer(100));
        // 150 blocks later (window is 100): progress expired…
        let (state, fired) = step(&seq, state, &mixer_touch(250));
        assert!(fired.is_none());
        assert_eq!(state, None);

        // …and an expired window doesn't eat a fresh start: a new step-1
        // event past the window begins a new run.
        let (state, _) = step(
            &seq,
            Some(TemporalState::Sequence { matched: vec![100] }),
            &big_transfer(250),
        );
        assert_eq!(state, Some(TemporalState::Sequence { matched: vec![250] }));
    }

    #[test]
    fn frequency_counts_within_sliding_window() {
        let freq = crate::compile::temporal_clause(&frequency_rule(3, 50));

        let (state, fired) = step(&freq, None, &big_transfer(100));
        assert!(fired.is_none());
        let (state, fired) = step(&freq, state, &big_transfer(120));
        assert!(fired.is_none());
        // Third hit, but the first slid out of the 50-block window: no fire.
        let (state, fired) = step(&freq, state, &big_transfer(160));
        assert!(fired.is_none());
        assert_eq!(
            state,
            Some(TemporalState::Frequency {
                hits: vec![120, 160]
            })
        );
        // Third hit inside the window: fires with the evidence blocks.
        let (state, fired) = step(&freq, state, &big_transfer(165));
        assert_eq!(state, None);
        assert_eq!(
            fired,
            Some(Fired {
                matched_blocks: vec![120, 160, 165]
            })
        );
    }

    #[test]
    fn rewind_sequence_truncates_from_reverted_block() {
        // Steps matched at 100 and 150; block 100 reverts → everything after
        // it depended on its ordering, so the whole run unwinds.
        let state = TemporalState::Sequence {
            matched: vec![100, 150],
        };
        assert_eq!(rewind(state, 100), None);

        // Only the later step reverts: the prefix survives.
        let state = TemporalState::Sequence {
            matched: vec![100, 150],
        };
        assert_eq!(
            rewind(state, 150),
            Some(TemporalState::Sequence { matched: vec![100] })
        );
    }

    #[test]
    fn rewind_frequency_drops_only_the_reverted_block() {
        let state = TemporalState::Frequency {
            hits: vec![100, 120, 140],
        };
        assert_eq!(
            rewind(state, 120),
            Some(TemporalState::Frequency {
                hits: vec![100, 140]
            })
        );
        let state = TemporalState::Frequency { hits: vec![100] };
        assert_eq!(rewind(state, 100), None);
    }

    /// The state round-trips through its Redis (JSON) form exactly.
    #[test]
    fn state_round_trips_through_json() {
        for state in [
            TemporalState::Sequence {
                matched: vec![100, 150],
            },
            TemporalState::Frequency {
                hits: vec![1, 2, 3],
            },
        ] {
            let json = serde_json::to_string(&state).expect("serialize");
            let back: TemporalState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(state, back);
        }
    }
}
