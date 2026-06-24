//! Test doubles for exercising the [`DetectorPlugin`](crate::DetectorPlugin)
//! seam (§6).
//!
//! Gated behind `#[cfg(any(test, feature = "test-util"))]`: available to this
//! crate's own unit tests, and — via the `test-util` feature — to the detector
//! crates (task 4) and service tests that need a stand-in detector without
//! re-rolling one. Never compiled into a normal build, so it can't bloat or leak
//! into the shipped binary.

use crate::ctx::DetectionCtx;
use crate::plugin::{DetectorId, DetectorPlugin, Evidence, ModelKind, Scope, SemVer};
use events::primitives::{AlertKind, Confidence};

/// A configurable stand-in for a real detector crate. It reports whatever
/// identity/kind/scope it was built with and returns a fixed list of findings
/// from [`detect`](DetectorPlugin::detect) regardless of context — enough to
/// drive registry, scheduler and wiring tests against the seam.
pub struct MockDetector {
    id: DetectorId,
    version: SemVer,
    kind: ModelKind,
    scope: Scope,
    findings: Vec<Evidence>,
}

impl MockDetector {
    /// A `Rule`/`Block` detector with the given identity that finds nothing.
    /// Layer on the builder methods to vary kind, scope, or output.
    pub fn new(id: &'static str, version: SemVer) -> Self {
        Self {
            id: DetectorId::new(id),
            version,
            kind: ModelKind::Rule,
            scope: Scope::Block,
            findings: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_kind(mut self, kind: ModelKind) -> Self {
        self.kind = kind;
        self
    }

    #[must_use]
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }

    /// Make `detect` return `findings` (cloned) for every context.
    #[must_use]
    pub fn returning(mut self, findings: Vec<Evidence>) -> Self {
        self.findings = findings;
        self
    }
}

impl DetectorPlugin for MockDetector {
    fn id(&self) -> DetectorId {
        self.id
    }
    fn version(&self) -> SemVer {
        self.version
    }
    fn kind(&self) -> ModelKind {
        self.kind
    }
    fn scope(&self) -> Scope {
        self.scope
    }
    fn detect(&self, _ctx: &DetectionCtx) -> Vec<Evidence> {
        self.findings.clone()
    }
}

/// A trivial finding for tests that care only about *how many* a detector
/// returns, not their content.
pub fn dummy_evidence() -> Evidence {
    Evidence::new(AlertKind::Sandwich, Vec::new(), Confidence::new(0.5))
}
