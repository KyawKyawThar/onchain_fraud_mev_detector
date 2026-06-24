//! The [`DetectorPlugin`] seam (§6) and its value types.
//!
//! Every detector — sandwich, arbitrage, flashloan, … — is an independent crate
//! whose only obligation to the detection service is to implement this one
//! trait. The service holds detectors as `Arc<dyn DetectorPlugin>` (see
//! [`crate::registry`]) and never knows their concrete type, which is what lets
//! detectors live in separate, independently-tested, selectively-open-sourced
//! crates (§6).
//!
//! The trait is **attribution-blind** by construction: a detector is handed a
//! [`DetectionCtx`] that carries on-chain facts and enrichment (token/pool/price)
//! but *no labels*, and it returns [`Evidence`] describing *behaviour*, never an
//! actor (§6). Attribution happens later, off the hot path, in the intelligence
//! service (§8).

use alloy_primitives::B256;
use events::primitives::{AlertKind, Confidence};
use serde::{Deserialize, Serialize};

use crate::ctx::DetectionCtx;

/// A detector's stable, human-readable identity, e.g. `"sandwich"` or `"arb"`.
///
/// Detectors are compile-time plugins, so an id is a `&'static str` baked into
/// the detector crate — it never changes across that crate's life and pairs with
/// a [`SemVer`] to form the `(id, version)` key the [`crate::registry::Registry`]
/// dedupes on. Together with the config hash (added by the model registry, task
/// 2) it becomes the [`events::primitives::DetectorRef`] stamped onto every
/// `DetectorTriggered` so historical evidence is attributable to an exact build
/// (§6, §22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DetectorId(&'static str);

impl DetectorId {
    /// Wrap a static id. `const` so detector crates can declare it once as an
    /// associated const.
    pub const fn new(id: &'static str) -> Self {
        Self(id)
    }

    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for DetectorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// A detector's semantic version (`major.minor.patch`).
///
/// Hand-rolled rather than pulling in the `semver` crate: detectors carry a
/// fixed compile-time version (`sandwich-v1.2`, `arb-v1.0`), so all that's
/// needed is an orderable triple that renders as `"1.2.0"` for the
/// [`events::primitives::DetectorRef`] wire field. Safe rollouts compare two
/// versions of the same id (§6), which `Ord` gives for free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemVer {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl SemVer {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// `SemVer` failed to parse from a `major.minor.patch` string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid semver `{input}`: expected `major.minor.patch`")]
pub struct SemVerParseError {
    pub input: String,
}

impl std::str::FromStr for SemVer {
    type Err = SemVerParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || SemVerParseError {
            input: s.to_owned(),
        };
        let mut parts = s.split('.');
        let mut next = || {
            parts
                .next()
                .ok_or_else(err)?
                .parse::<u16>()
                .map_err(|_| err())
        };
        let v = Self::new(next()?, next()?, next()?);
        // Reject trailing junk like `1.2.3.4` — `split` would otherwise ignore it.
        if parts.next().is_some() {
            return Err(err());
        }
        Ok(v)
    }
}

/// What a detector *is*, for the model registry and reporting (§6). A `Rule`
/// detector is deterministic heuristics; `Ml` is a learned model; `Hybrid`
/// combines both. The fast path treats all three identically — this is metadata,
/// carried onto the registry entry (task 2), not a behavioural switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelKind {
    Rule,
    Ml,
    Hybrid,
}

impl std::fmt::Display for ModelKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ModelKind::Rule => "Rule",
            ModelKind::Ml => "Ml",
            ModelKind::Hybrid => "Hybrid",
        })
    }
}

/// The block window a detector needs to do its job — the scheduler's contract
/// with the detector (§6, §17).
///
/// `Block` detectors are pure functions of a single [`DetectionCtx`] and can be
/// fanned out per block with no shared state (the common case: sandwich, arb).
/// `CrossBlock` detectors accumulate state across a sliding window (e.g.
/// wash-trading over `window_blocks`), which is the state that must be
/// reorg-versioned and rewound on `BlockReverted` (task 5 / Sprint 4 §15). The
/// scope is declared up front so the scheduler knows which detectors are
/// parallel-safe before it runs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Decides from one block alone.
    Block,
    /// Needs the trailing `window_blocks` of history; carries cross-block state.
    CrossBlock { window_blocks: u32 },
}

/// One finding from a detector: a behaviour spotted in a block, with the
/// on-chain facts that justify it (§6).
///
/// Deliberately carries *no* detector identity. The id/version are the plugin's,
/// known to the [`crate::registry::Registry`] that invoked `detect`, so it stamps
/// each `Evidence` with the owning [`events::primitives::DetectorRef`] when it
/// builds the `DetectorTriggered` event (task 5) — a detector can't misattribute
/// its own output, and there's one source of truth for "who found this".
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    /// The behaviour observed — names the pattern, never the actor (§6).
    pub kind: AlertKind,
    /// Transactions implicated in the pattern (becomes `DetectorTriggered.txs`).
    pub txs: Vec<B256>,
    /// On-chain confidence in `[0.0, 1.0]`, from facts only — no attribution
    /// (§6). Becomes `DetectorTriggered.raw_confidence`.
    pub confidence: Confidence,
    /// Detector-specific supporting detail (profit estimate, pool, victim swap,
    /// …). Opaque here; each detector defines its own shape and serializes it
    /// through this field, matching `DetectorTriggered.evidence`.
    pub detail: serde_json::Value,
}

impl Evidence {
    /// Construct a finding with no extra detail payload (`detail` = JSON `null`).
    pub fn new(kind: AlertKind, txs: Vec<B256>, confidence: Confidence) -> Self {
        Self {
            kind,
            txs,
            confidence,
            detail: serde_json::Value::Null,
        }
    }

    /// Attach a detector-specific detail document.
    #[must_use]
    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = detail;
        self
    }
}

/// The compile-time plugin every detector implements (§6).
///
/// Object-safe — the registry stores `Arc<dyn DetectorPlugin>` and dispatches
/// dynamically, so detectors stay in separate crates behind one seam. All
/// methods are cheap, side-effect-free accessors except [`detect`](Self::detect),
/// which is the hot path: a pure function from a [`DetectionCtx`] to the
/// behaviours it found. Purity (no I/O, no clock, no labels) is what makes a
/// detector unit-testable on a fixed context and replayable in backtests (§18).
///
/// `Send + Sync` because the scheduler fans `Block`-scoped detectors across a
/// rayon pool (§17, Sprint 4 task 2).
pub trait DetectorPlugin: Send + Sync {
    /// Stable id, e.g. `DetectorId::new("sandwich")`.
    fn id(&self) -> DetectorId;

    /// This build's version. `(id, version)` is unique within a registry.
    fn version(&self) -> SemVer;

    /// Rule / ML / Hybrid — metadata for the registry and reporting.
    fn kind(&self) -> ModelKind;

    /// The block window this detector needs (declares parallel-safety).
    fn scope(&self) -> Scope;

    /// Run the detector over one context and return what it found. An empty
    /// vec means "nothing here" — the overwhelmingly common case on the hot
    /// path, so it must stay cheap.
    fn detect(&self, ctx: &DetectionCtx) -> Vec<Evidence>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_renders_as_dotted_triple() {
        assert_eq!(SemVer::new(1, 2, 0).to_string(), "1.2.0");
    }

    #[test]
    fn semver_round_trips_through_parse() {
        let v = SemVer::new(2, 13, 4);
        assert_eq!(v.to_string().parse::<SemVer>().unwrap(), v);
    }

    #[test]
    fn semver_orders_by_precedence() {
        assert!(SemVer::new(1, 2, 0) < SemVer::new(1, 3, 0));
        assert!(SemVer::new(1, 2, 0) < SemVer::new(2, 0, 0));
        assert!(SemVer::new(1, 2, 0) < SemVer::new(1, 2, 1));
    }

    #[test]
    fn semver_rejects_malformed_input() {
        for bad in ["1.2", "1", "1.2.3.4", "1.x.0", "", "a.b.c"] {
            assert!(bad.parse::<SemVer>().is_err(), "expected `{bad}` to fail");
        }
    }
}
