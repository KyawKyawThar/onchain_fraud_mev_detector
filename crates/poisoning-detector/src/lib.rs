//! `address-poisoning-v1.0` — the address-poisoning detector (§6, §22 Phase 3).
//!
//! Address poisoning is a social-engineering attack on *copy-paste*. The attacker
//! generates a vanity address whose first and last hex characters match an address
//! the victim really transacts with, then sends the victim a **zero-value** (or
//! dust) transfer from it. The transfer's only purpose is to plant the lookalike
//! address in the victim's transaction history, hoping that next time the victim
//! copies "the address I paid last week" they grab the attacker's near-identical
//! one instead and send funds to it.
//!
//! The structural signature this detector keys on, read off the enrichment's
//! decoded [`TokenTransfer`]s, is exactly that setup within a block:
//!
//! 1. a **zero-value transfer** to a victim (the bait — legitimate transfers
//!    virtually never move zero), whose sender is the *spoofer*; and
//! 2. that spoofer is a **lookalike** — shares a long common prefix *and* suffix of
//!    hex nibbles, but is not equal — of a real counterparty the victim actually
//!    moved value with in the same block.
//!
//! The lookalike is the discriminator (an 8-nibble prefix+suffix collision by
//! chance is ~1 in 4 billion); the zero-value bait is the vector. Pure, single-tx,
//! [`Scope::Block`] and parallel-safe (§17); **attribution-blind** (§6) — the
//! spoofer/victim/counterparty are addresses (facts), and the finding names the
//! *behaviour* (a lookalike-address dust bait), never an actor. Output is
//! behaviour-only [`Evidence`] with a typed [`PoisoningDetail`].
//!
//! # Known limitation (v1.0)
//!
//! Tying the lookalike to a counterparty seen *in the same block* trades recall for
//! precision without needing history — a real campaign often baits against a
//! counterparty from days ago. The history-aware variant belongs in the
//! intelligence service (§8), which has the address's past; the fast path catches
//! the same-block case cheaply and with almost no false positives.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

use detector_api::{DetectionCtx, DetectorId, DetectorPlugin, Evidence, ModelKind, Scope, SemVer};
use events::primitives::{AlertKind, Confidence};

/// Default minimum matching leading hex nibbles between spoofer and target.
const DEFAULT_MIN_PREFIX_NIBBLES: u32 = 4;
/// Default minimum matching trailing hex nibbles.
const DEFAULT_MIN_SUFFIX_NIBBLES: u32 = 4;

// Confidence policy, facts-only (§6).
/// Base confidence for a zero-value bait with a minimally-matching lookalike.
const CONF_BASE: f64 = 0.55;
/// Added per matched nibble beyond the configured minimum (prefix + suffix) — a
/// longer vanity match is more deliberate and more convincing.
const CONF_PER_EXTRA_NIBBLE: f64 = 0.02;
/// Cap on the nibble contribution.
const MAX_NIBBLE_CONTRIB: f64 = 0.30;

fn default_min_prefix_nibbles() -> u32 {
    DEFAULT_MIN_PREFIX_NIBBLES
}

fn default_min_suffix_nibbles() -> u32 {
    DEFAULT_MIN_SUFFIX_NIBBLES
}

/// Tunable thresholds for the address-poisoning detector. Serialized into the model
/// registry's `config_hash` (§6); deserializable so the service can load
/// `[detectors.address_poisoning]` from config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoisoningConfig {
    /// Minimum matching leading hex nibbles for two addresses to read as lookalikes.
    #[serde(default = "default_min_prefix_nibbles")]
    pub min_prefix_nibbles: u32,
    /// Minimum matching trailing hex nibbles.
    #[serde(default = "default_min_suffix_nibbles")]
    pub min_suffix_nibbles: u32,
}

impl Default for PoisoningConfig {
    fn default() -> Self {
        Self {
            min_prefix_nibbles: default_min_prefix_nibbles(),
            min_suffix_nibbles: default_min_suffix_nibbles(),
        }
    }
}

/// The `address-poisoning-v1.0` detector. Holds its [`PoisoningConfig`]; construct
/// with [`plugin`] for defaults or [`PoisoningDetector::new`] to override.
#[derive(Debug, Clone)]
pub struct PoisoningDetector {
    config: PoisoningConfig,
}

impl PoisoningDetector {
    /// This detector's stable id.
    pub const ID: DetectorId = DetectorId::new("address-poisoning");
    /// This build's version: `1.0.0`.
    pub const VERSION: SemVer = SemVer::new(1, 0, 0);

    /// Build the detector with explicit thresholds.
    pub fn new(config: PoisoningConfig) -> Self {
        Self { config }
    }

    /// The active config — what the model registry hashes into `config_hash`.
    pub fn config(&self) -> &PoisoningConfig {
        &self.config
    }
}

/// Construct the detector with default config, ready to register.
pub fn plugin() -> PoisoningDetector {
    PoisoningDetector::new(PoisoningConfig::default())
}

/// The typed detail payload of an address-poisoning [`Evidence`] (§6). Addresses
/// are facts, not identities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoisoningDetail {
    /// The recipient of the bait — the address being poisoned.
    pub victim: Address,
    /// The lookalike ("vanity") address the bait was sent from.
    pub spoof_address: Address,
    /// The real counterparty the spoofer is mimicking (seen with the victim this
    /// block) — a fact, not a label.
    pub mimics: Address,
    /// The token the zero-value bait was sent in.
    pub token: Address,
    /// Bait amount, in raw base units (zero for the canonical poisoning transfer).
    pub amount: U256,
    /// Matching leading hex nibbles between `spoof_address` and `mimics`.
    pub prefix_nibbles: u32,
    /// Matching trailing hex nibbles.
    pub suffix_nibbles: u32,
}

impl DetectorPlugin for PoisoningDetector {
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
        Scope::Block
    }

    fn detect(&self, ctx: &DetectionCtx) -> Vec<Evidence> {
        // Who each address moved *value* with this block (zero-value baits excluded):
        // the pool of real counterparties a spoofer might be mimicking.
        let counterparties = self.value_counterparties(ctx);

        let mut findings = Vec::new();
        for tx_hash in ctx.txs() {
            let Some(tx) = ctx.enrichment().tx(*tx_hash) else {
                continue;
            };
            for t in &tx.transfers {
                // Bait = a zero-value transfer. The victim is the recipient, the
                // spoofer the sender.
                if !t.amount.is_zero() {
                    continue;
                }
                let (victim, spoofer) = (t.to, t.from);
                let Some(reals) = counterparties.get(&victim) else {
                    continue;
                };
                if let Some(best) = self.best_lookalike(spoofer, victim, reals) {
                    findings.push(build_evidence(
                        tx.hash, victim, spoofer, t.token, t.amount, best,
                    ));
                }
            }
        }
        findings
    }
}

/// A matched lookalike: the mimicked address and the nibble overlap that qualified.
struct Lookalike {
    mimics: Address,
    prefix: u32,
    suffix: u32,
}

impl PoisoningDetector {
    /// The victim's real counterparties this block: every address it exchanged a
    /// *non-zero* transfer with. Keyed by victim so a bait's lookalike is checked
    /// only against addresses that victim actually deals with.
    fn value_counterparties(&self, ctx: &DetectionCtx) -> BTreeMap<Address, BTreeSet<Address>> {
        let mut map: BTreeMap<Address, BTreeSet<Address>> = BTreeMap::new();
        for tx_hash in ctx.txs() {
            let Some(tx) = ctx.enrichment().tx(*tx_hash) else {
                continue;
            };
            for t in &tx.transfers {
                if t.amount.is_zero() || t.from == t.to {
                    continue;
                }
                map.entry(t.to).or_default().insert(t.from);
                map.entry(t.from).or_default().insert(t.to);
            }
        }
        map
    }

    /// The strongest lookalike of `spoofer` among the victim's `reals`, if any
    /// clears the configured nibble thresholds. "Strongest" = most total matched
    /// nibbles, so the detail names the address the bait most convincingly mimics.
    fn best_lookalike(
        &self,
        spoofer: Address,
        victim: Address,
        reals: &BTreeSet<Address>,
    ) -> Option<Lookalike> {
        reals
            .iter()
            .filter(|&&r| r != spoofer && r != victim)
            .filter_map(|&r| {
                let prefix = matching_prefix_nibbles(spoofer, r);
                let suffix = matching_suffix_nibbles(spoofer, r);
                (prefix >= self.config.min_prefix_nibbles
                    && suffix >= self.config.min_suffix_nibbles)
                    .then_some(Lookalike {
                        mimics: r,
                        prefix,
                        suffix,
                    })
            })
            .max_by_key(|l| l.prefix + l.suffix)
    }
}

/// Matching leading hex nibbles of two addresses (0–40).
fn matching_prefix_nibbles(a: Address, b: Address) -> u32 {
    let mut n = 0;
    for (x, y) in a.as_slice().iter().zip(b.as_slice().iter()) {
        if x == y {
            n += 2;
        } else {
            if x >> 4 == y >> 4 {
                n += 1;
            }
            break;
        }
    }
    n
}

/// Matching trailing hex nibbles of two addresses (0–40).
fn matching_suffix_nibbles(a: Address, b: Address) -> u32 {
    let mut n = 0;
    for (x, y) in a.as_slice().iter().rev().zip(b.as_slice().iter().rev()) {
        if x == y {
            n += 2;
        } else {
            if x & 0x0f == y & 0x0f {
                n += 1;
            }
            break;
        }
    }
    n
}

/// Assemble the [`Evidence`]. Confidence rises with how many nibbles the vanity
/// address matched beyond the minimum — a longer match is more deliberate — capped
/// so structure alone can't reach certainty.
fn build_evidence(
    tx: alloy_primitives::B256,
    victim: Address,
    spoofer: Address,
    token: Address,
    amount: U256,
    best: Lookalike,
) -> Evidence {
    let min = DEFAULT_MIN_PREFIX_NIBBLES + DEFAULT_MIN_SUFFIX_NIBBLES;
    let extra = f64::from((best.prefix + best.suffix).saturating_sub(min));
    let contrib = (CONF_PER_EXTRA_NIBBLE * extra).min(MAX_NIBBLE_CONTRIB);
    let confidence = Confidence::new(CONF_BASE + contrib);

    let detail = PoisoningDetail {
        victim,
        spoof_address: spoofer,
        mimics: best.mimics,
        token,
        amount,
        prefix_nibbles: best.prefix,
        suffix_nibbles: best.suffix,
    };
    Evidence::from_detail(AlertKind::AddressPoisoning, vec![tx], confidence, &detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::{addr, b256, transfer, CtxBuilder};

    const VICTIM: u8 = 0x22;
    const TOKEN: u8 = 0x33;

    /// The real counterparty: `0xAABB…11…CCDD`.
    fn real() -> Address {
        let mut b = [0x11u8; 20];
        b[0] = 0xAA;
        b[1] = 0xBB;
        b[18] = 0xCC;
        b[19] = 0xDD;
        Address::from(b)
    }

    /// A lookalike sharing the real address's first two and last two bytes
    /// (prefix 4 nibbles, suffix 4 nibbles) but differing in the middle.
    fn spoof() -> Address {
        let mut b = [0x99u8; 20];
        b[0] = 0xAA;
        b[1] = 0xBB;
        b[18] = 0xCC;
        b[19] = 0xDD;
        Address::from(b)
    }

    fn detail_of(ev: &Evidence) -> PoisoningDetail {
        serde_json::from_value(ev.detail.clone()).expect("detail round-trips as PoisoningDetail")
    }

    /// A block where the victim really pays `real()` and is baited by `spoof()`.
    fn poisoned_block() -> DetectionCtx {
        CtxBuilder::new()
            // Real value transfer establishing `real()` as the victim's counterparty.
            .transfer_tx(
                b256(1),
                real(),
                vec![transfer(addr(TOKEN), real(), addr(VICTIM), 1_000)],
            )
            // The zero-value bait from the lookalike.
            .transfer_tx(
                b256(2),
                spoof(),
                vec![transfer(addr(TOKEN), spoof(), addr(VICTIM), 0)],
            )
            .build()
    }

    #[test]
    fn flags_a_zero_value_lookalike_bait() {
        let found = plugin().detect(&poisoned_block());
        assert_eq!(found.len(), 1);
        let ev = &found[0];
        assert_eq!(ev.kind, AlertKind::AddressPoisoning);
        assert_eq!(ev.txs, vec![b256(2)]);

        let d = detail_of(ev);
        assert_eq!(d.victim, addr(VICTIM));
        assert_eq!(d.spoof_address, spoof());
        assert_eq!(d.mimics, real());
        assert_eq!(d.prefix_nibbles, 4);
        assert_eq!(d.suffix_nibbles, 4);
        assert_eq!(d.amount, U256::ZERO);
    }

    #[test]
    fn ignores_a_zero_value_transfer_with_no_lookalike() {
        // Bait present, but the victim's only counterparty shares nothing with the
        // spoofer — just an ordinary zero-value transfer, not poisoning.
        let c = CtxBuilder::new()
            .transfer_tx(
                b256(1),
                addr(0x44),
                vec![transfer(addr(TOKEN), addr(0x44), addr(VICTIM), 1_000)],
            )
            .transfer_tx(
                b256(2),
                spoof(),
                vec![transfer(addr(TOKEN), spoof(), addr(VICTIM), 0)],
            )
            .build();
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn ignores_a_real_value_transfer_from_a_lookalike() {
        // The lookalike sends *value*, not a zero bait — no poisoning setup.
        let c = CtxBuilder::new()
            .transfer_tx(
                b256(1),
                real(),
                vec![transfer(addr(TOKEN), real(), addr(VICTIM), 1_000)],
            )
            .transfer_tx(
                b256(2),
                spoof(),
                vec![transfer(addr(TOKEN), spoof(), addr(VICTIM), 500)],
            )
            .build();
        assert!(plugin().detect(&c).is_empty());
    }

    #[test]
    fn a_longer_vanity_match_scores_higher() {
        let base = plugin().detect(&poisoned_block())[0].confidence.get();
        // A spoofer matching three bytes each end (6+6 nibbles) beats the 4+4 floor.
        let mut r = [0x11u8; 20];
        r[0] = 0xAA;
        r[1] = 0xBB;
        r[2] = 0xCC;
        r[17] = 0x33;
        r[18] = 0x44;
        r[19] = 0x55;
        let real3 = Address::from(r);
        let mut s = [0x99u8; 20];
        s[0] = 0xAA;
        s[1] = 0xBB;
        s[2] = 0xCC;
        s[17] = 0x33;
        s[18] = 0x44;
        s[19] = 0x55;
        let spoof3 = Address::from(s);
        let c = CtxBuilder::new()
            .transfer_tx(
                b256(1),
                real3,
                vec![transfer(addr(TOKEN), real3, addr(VICTIM), 1_000)],
            )
            .transfer_tx(
                b256(2),
                spoof3,
                vec![transfer(addr(TOKEN), spoof3, addr(VICTIM), 0)],
            )
            .build();
        let found = plugin().detect(&c);
        assert_eq!(found.len(), 1);
        assert!(found[0].confidence.get() > base);
        assert_eq!(detail_of(&found[0]).prefix_nibbles, 6);
    }

    #[test]
    fn empty_block_finds_nothing() {
        assert!(plugin().detect(&CtxBuilder::new().build()).is_empty());
    }

    #[test]
    fn nibble_matchers_count_partial_bytes() {
        // Shared high nibble of the first differing byte counts as one prefix nibble.
        let mut a = [0x00u8; 20];
        let mut b = [0x00u8; 20];
        a[0] = 0xA1;
        b[0] = 0xA2; // high nibble A shared, low differs ⇒ 1 prefix nibble.
        assert_eq!(
            matching_prefix_nibbles(Address::from(a), Address::from(b)),
            1
        );

        let mut c = [0x00u8; 20];
        let mut d = [0x00u8; 20];
        c[19] = 0x1F;
        d[19] = 0x2F; // low nibble F shared ⇒ 1 suffix nibble (bytes 0..18 all equal
                      // would extend it, but byte 19 differs first from the tail).
        assert_eq!(
            matching_suffix_nibbles(Address::from(c), Address::from(d)),
            1
        );
    }

    #[test]
    fn config_round_trips_with_defaults() {
        let cfg: PoisoningConfig = serde_json::from_str(r#"{"min_prefix_nibbles": 6}"#).unwrap();
        assert_eq!(cfg.min_prefix_nibbles, 6);
        assert_eq!(cfg.min_suffix_nibbles, DEFAULT_MIN_SUFFIX_NIBBLES);
        let defaulted: PoisoningConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(defaulted, PoisoningConfig::default());
    }

    #[test]
    fn exposes_its_identity_through_the_plugin_seam() {
        let detector = plugin();
        let plug: &dyn DetectorPlugin = &detector;
        assert_eq!(plug.id().as_str(), "address-poisoning");
        assert_eq!(plug.id(), PoisoningDetector::ID);
        assert_eq!(plug.version(), PoisoningDetector::VERSION);
        assert_eq!(plug.version().to_string(), "1.0.0");
        assert_eq!(plug.kind(), ModelKind::Rule);
        assert_eq!(plug.scope(), Scope::Block);
    }
}
