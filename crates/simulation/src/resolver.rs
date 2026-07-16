//! The `JobResolver` seam (§7) — how a worker turns a `SimulationJob` (alert-level
//! facts) into a [`SimulationRequest`] (a concrete `(block, tx_set)` scenario with
//! forked pre-state) the [`crate::simulator`] engine can run.
//!
//! ## Why this is a seam, and why the production impl is deferred
//!
//! The `SimulationJob` deliberately carries **no** `(block, tx_set)` — it forwards
//! only the alert (`alert_id`, `kind`, `addresses`, …), because
//! `PreliminaryAlertCreated` itself doesn't carry the implicated transactions; only
//! the detector's `DetectorTriggered` does (its `txs` + `block`). So a worker must
//! *resolve* the bundle: query the event store for the alert's `DetectorTriggered`
//! evidence (§4 audit query) to recover `(block, txs)`, then fork chain state at
//! that block to seed the simulation.
//!
//! That resolution is the one piece of this task deliberately left as a stub:
//!
//! - The event store has no by-alert read endpoint yet (only by-incident,
//!   by-address, and replay), so the evidence query needs a new read path.
//! - Forking chain state needs revm's `AlloyDB`, whose feature pins
//!   `alloy-provider` 2.0 — incompatible with ingestion's 1.x today. The live fork
//!   lands with the workspace alloy bump.
//!
//! Until then [`UnresolvedJobResolver`] returns [`ResolveError::Unresolvable`] for
//! every job. The worker treats that as **poison** and dead-letters the job (rather
//! than hot-looping), so the *pool plumbing* is exercised end-to-end — competing
//! consume, ack/redelivery, DLX — while the engine is independently real and tested
//! against synthetic scenarios. This mirrors detection's header-only no-op: the
//! wiring is complete; the meaningful payload is a scoped follow-up.

use async_trait::async_trait;

use crate::command::SimulationJob;
use crate::simulator::SimulationRequest;

/// Why a job could not be turned into a runnable scenario.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The bundle could not be recovered or the state could not be forked — and the
    /// same job would fail identically on retry. Treated as poison by the worker
    /// (dead-letter, don't requeue).
    #[error("job could not be resolved to a runnable scenario: {0}")]
    Unresolvable(String),

    /// A transient fault recovering the scenario (event-store/RPC blip). The worker
    /// requeues for redelivery.
    #[error("transient fault resolving job: {0}")]
    Transient(String),
}

impl event_bus::Transience for ResolveError {
    /// Whether re-resolving the same job could plausibly succeed later.
    fn is_transient(&self) -> bool {
        matches!(self, ResolveError::Transient(_))
    }
}

/// Turns a queued command into a runnable simulation scenario. Object-safe so the
/// worker holds `Arc<dyn JobResolver>` and a test swaps in a double that returns a
/// canned [`SimulationRequest`] with no event store or RPC.
#[async_trait]
pub trait JobResolver: Send + Sync {
    /// Resolve one job. Async because the production impl does I/O (event-store
    /// query + state fork); the engine it feeds is the only CPU-bound part and runs
    /// on rayon.
    async fn resolve(&self, job: &SimulationJob) -> Result<SimulationRequest, ResolveError>;
}

/// The deferred-production resolver: every job is `Unresolvable`. See the module
/// docs — this keeps the worker pool runnable end-to-end (each live job poisons to
/// the DLX) until the event-store evidence query + chain fork land.
#[derive(Debug, Default, Clone)]
pub struct UnresolvedJobResolver;

#[async_trait]
impl JobResolver for UnresolvedJobResolver {
    async fn resolve(&self, job: &SimulationJob) -> Result<SimulationRequest, ResolveError> {
        Err(ResolveError::Unresolvable(format!(
            "bundle resolution from alert evidence is not yet wired (alert {}); \
             dead-lettering for inspection",
            job.alert_id
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_bus::Transience;
    use events::primitives::{AlertId, AlertKind, Chain, Confidence, DetectorRef};

    use crate::command::{Priority, SimulationJob};

    fn a_job() -> SimulationJob {
        SimulationJob {
            alert_id: AlertId::new(),
            chain: Chain::ETHEREUM,
            kind: AlertKind::Sandwich,
            detector: DetectorRef {
                id: "sandwich".into(),
                version: "1.2.0".into(),
                config_hash: "deadbeef".into(),
            },
            addresses: vec![],
            confidence: Confidence::new(0.5),
            priority: Priority::new(5),
        }
    }

    #[tokio::test]
    async fn stub_resolver_reports_unresolvable_poison() {
        let err = UnresolvedJobResolver
            .resolve(&a_job())
            .await
            .expect_err("the stub resolves nothing");
        assert!(
            !err.is_transient(),
            "an unresolvable job is poison so the worker dead-letters it, not requeues"
        );
    }
}
