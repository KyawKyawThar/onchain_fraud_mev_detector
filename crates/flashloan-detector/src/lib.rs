//! `flashloan-v2.1` — the flash-loan detector (§6, §22 Phase 3).
//!
//! A flash loan borrows and repays within a **single transaction**: a lending
//! facility (an AMM pool, an Aave-style pool) hands the borrower a large amount of
//! a token and, before the same tx ends, receives that amount back plus a fee. If
//! the repayment doesn't land, the whole tx reverts — so on-chain a completed flash
//! loan is a *same-token round trip through one counterparty in one tx*.
//!
//! That round trip is the structural signature this detector keys on, read off the
//! enrichment's decoded [`TokenTransfer`]s: for one address `L` (the lender) and
//! one token `T`, `T` flows **out of** `L` (the loan) and an at-least-as-large
//! amount of `T` flows **back into** `L` (the repayment + fee) within the same tx.
//! The lender nets non-negative in `T`; the borrower — who receives then repays
//! *more* — nets negative and is deliberately not the anchor. This cleanly
//! separates a flash loan from an ordinary swap, where a pool receives one token
//! and sends a *different* one (no same-token round trip).
//!
//! Pure, single-tx, [`Scope::Block`] and parallel-safe (§17); **attribution-blind**
//! (§6) — the lender/borrower addresses are on-chain facts used to pair the loan
//! with its repayment, never labels. The USD notional gate
//! ([`FlashloanConfig::min_loan_usd`]) suppresses dust; output is behaviour-only
//! [`Evidence`] with a typed [`FlashloanDetail`], stamped with this build's
//! `(id, version, config_hash)` on emission.
//!
//! # Known limitation (v2.1)
//!
//! A flash loan is a *tool*, not inherently an attack — this detector names the
//! borrow/repay behaviour, and downstream correlation (a flash loan wrapping a
//! price-manipulation or governance exploit) is where the harm is judged. The
//! same-token round-trip rule also matches the rare in-tx add-then-remove of the
//! same liquidity; that's an acceptable v2.1 stance, revisited against labeled
//! history with the backtest harness (Sprint 10 §18), not loosened on a hunch.

use std::collections::BTreeMap;

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

use detector_api::{
    DetectionCtx, DetectorId, DetectorPlugin, Evidence, ModelKind, Scope, SemVer, TxActions,
    UsdPrice,
};
use events::primitives::{AlertKind, Confidence};

/// Default notional gate: flash loans are large by construction, so a `$1,000`
/// floor filters dust round trips without touching real ones (§6).
const DEFAULT_MIN_LOAN_USD: f64 = 1_000.0;

// Confidence policy, facts-only (§6), gathered so the scoring is reviewable here.
/// Base confidence for a round trip whose notional we could value.
const CONF_VALUED: f64 = 0.70;
/// Base when the round trip is clean but the notional couldn't be valued (no price).
const CONF_UNVALUED: f64 = 0.55;
/// Added when the lender was repaid *more* than lent — a fee, the hallmark of a
/// real lending facility rather than an incidental self-transfer.
const CONF_FEE_BONUS: f64 = 0.05;

fn default_min_loan_usd() -> UsdPrice {
    UsdPrice::try_new(DEFAULT_MIN_LOAN_USD).expect("default min loan is a valid USD price")
}

/// Tunable thresholds for the flash-loan detector. Serialized into the model
/// registry's `config_hash` (§6) so two builds with different gates are
/// distinguishable on replay; deserializable so the service can load
/// `[detectors.flash_loan]` from config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlashloanConfig {
    /// Minimum borrowed notional (valued via enrichment) for a round trip to be
    /// reported. A validated [`UsdPrice`] — a NaN/negative can't slip in and
    /// silently disable the gate. Applied only when the borrowed token has a
    /// reference price; an unvalued-but-structural round trip is still reported, at
    /// lower confidence.
    #[serde(default = "default_min_loan_usd")]
    pub min_loan_usd: UsdPrice,
}

impl Default for FlashloanConfig {
    fn default() -> Self {
        Self {
            min_loan_usd: default_min_loan_usd(),
        }
    }
}

/// The `flashloan-v2.1` detector. Holds its [`FlashloanConfig`]; construct with
/// [`plugin`] for the default thresholds or [`FlashloanDetector::new`] to override.
#[derive(Debug, Clone)]
pub struct FlashloanDetector {
    config: FlashloanConfig,
}

impl FlashloanDetector {
    /// This detector's stable id.
    pub const ID: DetectorId = DetectorId::new("flashloan");
    /// This build's version: `2.1.0`.
    pub const VERSION: SemVer = SemVer::new(2, 1, 0);

    /// Build the detector with explicit thresholds.
    pub fn new(config: FlashloanConfig) -> Self {
        Self { config }
    }

    /// The active config — what the model registry hashes into `config_hash`.
    pub fn config(&self) -> &FlashloanConfig {
        &self.config
    }
}

/// Construct the detector with default config, ready to register.
pub fn plugin() -> FlashloanDetector {
    FlashloanDetector::new(FlashloanConfig::default())
}

/// The typed detail payload of a flash-loan [`Evidence`] — the on-chain facts that
/// justify the finding (§6). Addresses are facts, not identities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlashloanDetail {
    /// The counterparty that lent and was repaid the token — a fact, not a label.
    pub lender: Address,
    /// The borrowed/repaid token.
    pub token: Address,
    /// Amount lent out, in raw base units.
    pub borrowed: U256,
    /// Amount returned to the lender, in raw base units (`>= borrowed`).
    pub repaid: U256,
    /// The fee the lender kept (`repaid - borrowed`).
    pub fee: U256,
    /// The borrowed notional in USD, when the token has a reference price; else `null`.
    pub borrowed_usd: Option<f64>,
}

impl DetectorPlugin for FlashloanDetector {
    fn id(&self) -> DetectorId {
        Self::ID
    }

    fn version(&self) -> SemVer {
        Self::VERSION
    }

    fn kind(&self) -> ModelKind {
        ModelKind::Rule
    }

    fn scope(&self) -> Scope {
        // Decides from one tx in one block — no cross-block state.
        Scope::Block
    }

    fn detect(&self, ctx: &DetectionCtx) -> Vec<Evidence> {
        // A tx maps to zero or more findings (one per lender/token round trip).
        ctx.txs()
            .iter()
            .filter_map(|tx_hash| ctx.enrichment().tx(*tx_hash))
            .flat_map(|tx| self.detect_in_tx(ctx, tx))
            .collect()
    }
}

impl FlashloanDetector {
    /// Find every same-token round trip in one tx and, for each that clears the
    /// notional gate, build its [`Evidence`].
    fn detect_in_tx(&self, ctx: &DetectionCtx, tx: &TxActions) -> Vec<Evidence> {
        // Per (token, address): how much of the token left the address (out) and how
        // much returned to it (in). A lender lends `out` and is repaid `in >= out`.
        // The loan originator per token is the sender of that token's *first*
        // transfer (the disbursement) — anchoring on it means only the lender is
        // flagged, never the borrower, even in the degenerate fee-free round trip
        // where both sides satisfy `in >= out`.
        let mut flows: BTreeMap<(Address, Address), (U256, U256)> = BTreeMap::new();
        let mut originator: BTreeMap<Address, Address> = BTreeMap::new();
        for t in &tx.transfers {
            originator.entry(t.token).or_insert(t.from);
            let out = &mut flows.entry((t.token, t.from)).or_default().0;
            *out = out.saturating_add(t.amount);
            let inflow = &mut flows.entry((t.token, t.to)).or_default().1;
            *inflow = inflow.saturating_add(t.amount);
        }

        let mut findings = Vec::new();
        for ((token, lender), (out, inflow)) in flows {
            // Only the token's loan originator is a candidate lender …
            if originator.get(&token) != Some(&lender) {
                continue;
            }
            // … and it must have both sent (out > 0) and been repaid at least as
            // much (in >= out) — a completed, non-loss round trip.
            if out.is_zero() || inflow < out {
                continue;
            }
            let borrowed = out;
            let borrowed_usd = ctx.enrichment().usd_value(token, borrowed);
            if self.config.min_loan_usd.excludes(borrowed_usd) {
                continue;
            }
            findings.push(build_evidence(
                tx.hash,
                lender,
                token,
                borrowed,
                inflow,
                borrowed_usd,
            ));
        }
        findings
    }
}

/// Assemble the [`Evidence`] for one flash loan. Confidence is facts-only (§6): a
/// base set by whether the notional could be valued, lifted when the lender kept a
/// fee (a real lending facility, not an incidental self-transfer).
fn build_evidence(
    tx: alloy_primitives::B256,
    lender: Address,
    token: Address,
    borrowed: U256,
    repaid: U256,
    borrowed_usd: Option<f64>,
) -> Evidence {
    let fee = repaid.saturating_sub(borrowed);
    let mut score = if borrowed_usd.is_some() {
        CONF_VALUED
    } else {
        CONF_UNVALUED
    };
    if !fee.is_zero() {
        score += CONF_FEE_BONUS;
    }
    let confidence = Confidence::new(score);

    let detail = FlashloanDetail {
        lender,
        token,
        borrowed,
        repaid,
        fee,
        borrowed_usd,
    };
    Evidence::from_detail(AlertKind::Flashloan, vec![tx], confidence, &detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::{addr, b256, transfer, CtxBuilder};
    use detector_api::TokenTransfer;

    const WETH: u8 = 0xAA;
    const POOL: u8 = 0xCC; // the lender
    const BORROWER: u8 = 0x11;
    const ETH: u128 = 1_000_000_000_000_000_000;

    fn priced() -> CtxBuilder {
        CtxBuilder::new().priced_token(addr(WETH), 18, 2000.0)
    }

    fn detail_of(ev: &Evidence) -> FlashloanDetail {
        serde_json::from_value(ev.detail.clone()).expect("detail round-trips as FlashloanDetail")
    }

    /// Pool lends 100 WETH to the borrower, borrower repays 100.09 WETH (a 0.09%
    /// fee) — a textbook completed flash loan.
    fn flashloan_transfers(borrowed: u128, repaid: u128) -> Vec<TokenTransfer> {
        vec![
            transfer(addr(WETH), addr(POOL), addr(BORROWER), borrowed),
            transfer(addr(WETH), addr(BORROWER), addr(POOL), repaid),
        ]
    }

    #[test]
    fn flags_a_textbook_flash_loan() {
        let c = priced()
            .transfer_tx(
                b256(1),
                addr(BORROWER),
                flashloan_transfers(100 * ETH, 100 * ETH + ETH / 10),
            )
            .build();
        let found = plugin().detect(&c);
        assert_eq!(found.len(), 1);
        let ev = &found[0];
        assert_eq!(ev.kind, AlertKind::Flashloan);
        assert_eq!(ev.txs, vec![b256(1)]);
        // Valued + fee ⇒ base + bonus.
        assert!((ev.confidence.get() - (CONF_VALUED + CONF_FEE_BONUS)).abs() < 1e-9);

        let detail = detail_of(ev);
        assert_eq!(detail.lender, addr(POOL));
        assert_eq!(detail.token, addr(WETH));
        assert_eq!(detail.borrowed, U256::from(100 * ETH));
        assert_eq!(detail.fee, U256::from(ETH / 10));
        assert_eq!(detail.borrowed_usd, Some(200_000.0)); // 100 WETH @ $2000.
    }

    #[test]
    fn ignores_a_plain_swap_two_different_tokens() {
        // Pool receives WETH, sends USDC — different tokens, no same-token round
        // trip, so not a flash loan.
        const USDC: u8 = 0xBB;
        let c = priced()
            .priced_token(addr(USDC), 6, 1.0)
            .transfer_tx(
                b256(1),
                addr(BORROWER),
                vec![
                    transfer(addr(WETH), addr(BORROWER), addr(POOL), ETH),
                    transfer(addr(USDC), addr(POOL), addr(BORROWER), 2_000_000_000),
                ],
            )
            .build();
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn ignores_an_unrepaid_out_transfer() {
        // WETH leaves the pool and never returns — a payout, not a flash loan (a
        // real one would have reverted).
        let c = priced()
            .transfer_tx(
                b256(1),
                addr(BORROWER),
                vec![transfer(addr(WETH), addr(POOL), addr(BORROWER), 100 * ETH)],
            )
            .build();
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn notional_below_min_usd_is_filtered() {
        // A real round trip, but only 1 wei borrowed (~$2e-15) — below the gate.
        let c = priced()
            .transfer_tx(b256(1), addr(BORROWER), flashloan_transfers(1, 1))
            .build();
        assert!(plugin().detect(&c).is_empty());
        // …a permissive config admits it, proving the gate (not the structure)
        // rejected it.
        let permissive = FlashloanDetector::new(FlashloanConfig {
            min_loan_usd: UsdPrice::try_new(0.0).unwrap(),
        });
        assert_eq!(permissive.detect(&c).len(), 1);
    }

    #[test]
    fn unpriced_token_still_reports_structure_at_lower_confidence() {
        let c = CtxBuilder::new()
            .transfer_tx(
                b256(1),
                addr(BORROWER),
                flashloan_transfers(100 * ETH, 100 * ETH),
            )
            .build();
        let found = plugin().detect(&c);
        assert_eq!(found.len(), 1);
        assert_eq!(detail_of(&found[0]).borrowed_usd, None);
        // Unvalued, and no fee (repaid == borrowed) ⇒ the bare base.
        assert!((found[0].confidence.get() - CONF_UNVALUED).abs() < 1e-9);
    }

    #[test]
    fn empty_block_finds_nothing() {
        assert!(plugin().detect(&CtxBuilder::new().build()).is_empty());
    }

    #[test]
    fn config_round_trips_and_rejects_a_nonsense_threshold() {
        let cfg: FlashloanConfig = serde_json::from_str(r#"{"min_loan_usd": 5000.0}"#).unwrap();
        assert_eq!(cfg.min_loan_usd.get(), 5000.0);
        assert!(serde_json::from_str::<FlashloanConfig>(r#"{"min_loan_usd": -1.0}"#).is_err());
        let defaulted: FlashloanConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(defaulted, FlashloanConfig::default());
    }

    #[test]
    fn exposes_its_identity_through_the_plugin_seam() {
        let detector = plugin();
        let plug: &dyn DetectorPlugin = &detector;
        assert_eq!(plug.id().as_str(), "flashloan");
        assert_eq!(plug.id(), FlashloanDetector::ID);
        assert_eq!(plug.version(), FlashloanDetector::VERSION);
        assert_eq!(plug.version().to_string(), "2.1.0");
        assert_eq!(plug.kind(), ModelKind::Rule);
        assert_eq!(plug.scope(), Scope::Block);
    }
}
