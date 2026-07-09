//! Shared test doubles for the simulation worker pool, behind the `test-util`
//! feature (mirroring `detector-api`'s `test_util`). The crate's own unit tests get
//! them for free under `#[cfg(test)]`; the integration tests in `tests/` get them by
//! enabling the feature via the self dev-dependency. One home for the doubles, so a
//! recording sink / canned scenario isn't re-written per test file.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use events::primitives::{AlertId, AlertKind, Chain, Confidence, DetectorRef};
use revm::primitives::Address;

/// The shared recording [`EventSink`](event_bus::EventSink), re-exported under
/// this crate's historical name so the worker/dispatcher/reorg tests keep using
/// `RecordingEventSink` while the double itself lives in `event-bus` (one copy
/// for the whole workspace). Its `events()` returns the published payloads, as
/// before.
pub use event_bus::test_util::RecordingSink as RecordingEventSink;

use crate::command::{Priority, SimulationJob};
use crate::consumer::{DeliveryAck, Disposition};
use crate::resolver::{JobResolver, ResolveError};
use crate::simulator::{BlockParams, Scenario, SimulationRequest};

/// A canonical `SimulationJob` for tests that just need *a* job.
pub fn sample_job() -> SimulationJob {
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

/// A trivial empty-bundle scenario for `job` — runs the real engine to a valid
/// no-op outcome without needing chain state. The unit and integration tests share
/// this so neither hand-builds a `SimulationRequest`.
pub fn empty_request(job: &SimulationJob) -> SimulationRequest {
    SimulationRequest {
        alert_id: job.alert_id,
        kind: job.kind,
        block: BlockParams::default(),
        accounts: vec![],
        scenario: Scenario::ValueExtraction {
            bundle: vec![],
            attacker: Address::ZERO,
            victim: None,
        },
        txs: vec![],
    }
}

/// A single-thread rayon pool for tests.
pub fn test_pool() -> Arc<rayon::ThreadPool> {
    Arc::new(
        rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("building a test rayon pool"),
    )
}

/// A [`JobResolver`] that resolves every job to [`empty_request`] — exercises the
/// worker/queue path without chain state.
pub struct EmptyScenarioResolver;

#[async_trait]
impl JobResolver for EmptyScenarioResolver {
    async fn resolve(&self, job: &SimulationJob) -> Result<SimulationRequest, ResolveError> {
        Ok(empty_request(job))
    }
}

/// A [`DeliveryAck`] that records the [`Disposition`] it was settled with, so a test
/// can assert the worker disposed of a delivery the right way.
#[derive(Clone, Default)]
pub struct AckRecorder {
    settled: Arc<Mutex<Option<Disposition>>>,
}

impl AckRecorder {
    /// The disposition this delivery was settled with, if any.
    pub fn settled(&self) -> Option<Disposition> {
        *self.settled.lock().unwrap()
    }
}

#[async_trait]
impl DeliveryAck for AckRecorder {
    async fn settle(&self, disposition: Disposition) -> anyhow::Result<()> {
        *self.settled.lock().unwrap() = Some(disposition);
        Ok(())
    }
}
