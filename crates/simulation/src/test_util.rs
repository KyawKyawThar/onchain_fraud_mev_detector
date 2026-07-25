//! Shared test doubles for the simulation worker pool, behind the `test-util`
//! feature (mirroring `detector-api`'s `test_util`). The crate's own unit tests get
//! them for free under `#[cfg(test)]`; the integration tests in `tests/` get them by
//! enabling the feature via the self dev-dependency. One home for the doubles, so a
//! recording sink / canned scenario isn't re-written per test file.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{
    AccountAddress, AlertId, AlertKind, Chain, Confidence, DetectorRef, Severity,
};
use revm::primitives::Address;

use crate::store::{ExposureRow, PersistError, TimingBucketRow, TimingStore, WalletExposureStore};

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

/// An in-memory [`WalletExposureStore`] returning canned rows — lets the HTTP
/// handler and integration tests exercise `GET /v1/wallet/{addr}/mev-exposure`
/// without ClickHouse, the same doubles-not-a-database discipline the rest of the
/// store seams follow.
#[derive(Clone, Default)]
pub struct InMemoryWalletExposure {
    rows: Vec<ExposureRow>,
}

impl InMemoryWalletExposure {
    /// A store that returns `rows` verbatim for any address/`since` (the pure
    /// [`crate::exposure::summarize`] fold and the handler wiring are what the
    /// tests exercise, not the ClickHouse-side filtering).
    pub fn new(rows: Vec<ExposureRow>) -> Self {
        Self { rows }
    }

    /// A canned confirmed-incident row (`incident_id`/`victim_loss_usd` present),
    /// so a test doesn't hand-build the ClickHouse-shaped struct.
    pub fn row(
        incident_id: uuid::Uuid,
        kind: &str,
        usd_lost: f64,
        at: DateTime<Utc>,
    ) -> ExposureRow {
        ExposureRow {
            incident_id: Some(incident_id),
            kind: kind.to_owned(),
            victim_loss_usd: Some(usd_lost),
            occurred_at: at,
        }
    }
}

#[async_trait]
impl WalletExposureStore for InMemoryWalletExposure {
    async fn mev_exposure(
        &self,
        _victim_address: &AccountAddress,
        _since: Option<DateTime<Utc>>,
    ) -> Result<Vec<ExposureRow>, PersistError> {
        Ok(self.rows.clone())
    }
}

/// An in-memory [`TimingStore`] returning canned rows — lets the HTTP handler
/// exercise `GET /v1/timing/recommendation` without ClickHouse (same
/// doubles-not-a-database discipline as [`InMemoryWalletExposure`]).
#[derive(Clone, Default)]
pub struct InMemoryTimingStore {
    rows: Vec<TimingBucketRow>,
}

impl InMemoryTimingStore {
    /// A store that returns `rows` verbatim for any chain/severity — the pure
    /// [`crate::timing::rank_windows`] fold and the handler wiring are what
    /// the tests exercise, not the ClickHouse-side filtering.
    pub fn new(rows: Vec<TimingBucketRow>) -> Self {
        Self { rows }
    }
}

#[async_trait]
impl TimingStore for InMemoryTimingStore {
    async fn timing_buckets(
        &self,
        _chain: Chain,
        _severity: Severity,
    ) -> Result<Vec<TimingBucketRow>, PersistError> {
        Ok(self.rows.clone())
    }
}
