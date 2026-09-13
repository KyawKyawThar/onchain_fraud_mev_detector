//! Graceful degradation for `POST /v1/address/{addr}/screen` (§11; readiness
//! Epic D, "Screening API critical-path SLO").
//!
//! `/screen` sits inline on a customer's withdrawal, so the case that matters
//! is intelligence being **slow**, not down. Before this module a stalled read
//! held the caller for the whole `SCREENING_DEADLINE_MS` and then 502'd: the
//! p50 < 100ms contract broken *and* the withdrawal blocked, the worst of both.
//!
//! The answer is a **last-known-good snapshot, flagged**:
//!
//! 1. Every fresh `GetScreeningFacts` reply is recorded as a snapshot in Redis,
//!    off the request path ([`SnapshotRecorder`] → [`run_snapshot_writer`]).
//! 2. A screening read races intelligence against a *fresh budget*
//!    (`SCREENING_FRESH_BUDGET_MS`), strictly inside the hard deadline. Inside
//!    the budget, fresh is the only answer.
//! 3. Past the budget — or on a *transient* fault — the snapshot is looked up.
//!    One no older than `SCREENING_STALE_MAX_AGE_SECS` answers, is run through
//!    the caller's **current** policy, and is flagged with a [`FactsStaleness`]
//!    on both the response and the access-audit record.
//! 4. No usable snapshot: the fresh read keeps the rest of its deadline, and a
//!    failure is still the fail-closed 502. Degradation widens what the
//!    endpoint can answer; it never turns "could not decide" into "allow".
//!
//! **What a stale answer keeps, and what it cannot.** The policy is current
//! (resolved per request), and a sanctions match inside the snapshot still
//! hard-blocks. What a snapshot cannot know is anything after `observed_at` —
//! an address designated since then screens as it did then. That exposure is
//! bounded by the max age, disclosed on every decision (`stale`,
//! `staleness.age_ms`), and written to the audit trail, so a customer that
//! cannot accept it holds on `stale: true`. It is the trade the readiness plan
//! asks for — a flagged score rather than a blocked withdrawal — made explicit
//! rather than hidden.
//!
//! **Only transient faults degrade** ([`intelligence_client::is_transient`], the
//! classification that already decides 502 vs 500). `NotFound`,
//! `InvalidArgument` or `Internal` mean intelligence answered and the answer
//! was "no"; covering that with an old snapshot would hide a bug or a bad
//! request behind a plausible verdict.
//!
//! **The substrate fails open, and says so (§15).** A lost snapshot write costs
//! a *future* stale answer, never a present decision, so the writer drops
//! rather than blocks — and counts every loss in
//! [`SNAPSHOT_WRITES_LOST_TOTAL`].

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::AccountAddress;
use events::system::{FactsStaleness, ScreeningStaleReason};
use intelligence::model::address_key;
use intelligence::pb::ScreeningFactsReply;
use prost::Message;
use redis::aio::ConnectionManager;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tonic::{Code, Status};

use crate::intelligence_client::{self, IntelligenceClient};

/// Gauge (§15b): `1` when degradation is armed, `0` when
/// `SCREENING_STALE_MAX_AGE_SECS=0` switched it off. Published at boot on both
/// paths — a disarmed fallback exports nothing else, and every rule watching it
/// would be green for that reason alone.
pub const DEGRADATION_ENABLED: &str = "screening_degradation_enabled";
/// Counter: the facts a screening decision was rendered over, by `freshness`
/// (`fresh` | `stale`). The stale share is the customer-visible cost of an
/// intelligence problem.
pub const FACTS_SERVED_TOTAL: &str = telemetry::metrics::SCREENING_FACTS_SERVED_TOTAL;
/// Counter: requests that left the fresh path, counted once each, by `reason`
/// (`intelligence_slow` | `intelligence_unavailable`) and `outcome`
/// (`served_stale` | `served_fresh_late` | `failed_closed`). `failed_closed` is
/// a withdrawal that got a 502.
pub const DEGRADED_TOTAL: &str = telemetry::metrics::SCREENING_DEGRADED_TOTAL;
/// Counter: snapshot lookups, by `result` (`usable` | `too_old` | `missing` |
/// `error`). A high `missing` share while degraded means the substrate is thin
/// — addresses never screened before, or writes being lost.
pub const SNAPSHOT_LOOKUPS_TOTAL: &str = "screening_snapshot_lookups_total";
/// Counter (§15): snapshots that never reached Redis, by `cause` (`queue` —
/// the writer is behind or gone | `store` — Redis refused the batch).
pub const SNAPSHOT_WRITES_LOST_TOTAL: &str = "screening_snapshot_writes_lost_total";

/// Upper bound on one snapshot lookup. A lookup only runs on a request that is
/// already off the fresh path, so whatever it costs is paid in full by exactly
/// the requests degradation exists for: a hung Redis must cost them this, not
/// the rest of the intelligence deadline.
pub const SNAPSHOT_READ_TIMEOUT: Duration = Duration::from_millis(25);

/// Snapshots written per Redis round-trip.
const WRITE_BATCH: usize = 64;

const FRESH: &str = "fresh";
const STALE: &str = "stale";
const SERVED_STALE: &str = "served_stale";
const SERVED_FRESH_LATE: &str = "served_fresh_late";
const FAILED_CLOSED: &str = "failed_closed";

/// The degradation policy, resolved once at boot (`crate::config`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Degradation {
    /// How long a fresh read has before a snapshot may answer instead. Strictly
    /// inside the hard screening deadline (validated at boot), or the fallback
    /// could only ever react to faults, never to slowness.
    pub fresh_budget: Duration,
    /// The oldest snapshot allowed to decide a withdrawal — the bound on what a
    /// stale answer can have missed. Also the snapshot's Redis TTL.
    pub max_stale_age: Duration,
}

/// Where fresh screening facts come from. [`IntelligenceClient`] in production;
/// a trait so the race below is tested against scripted latency and faults on
/// a paused clock rather than a real gRPC server.
#[async_trait]
pub trait FactsSource: Send + Sync {
    async fn screening_facts(&self, address: AccountAddress)
        -> Result<ScreeningFactsReply, Status>;
}

#[async_trait]
impl FactsSource for IntelligenceClient {
    async fn screening_facts(
        &self,
        address: AccountAddress,
    ) -> Result<ScreeningFactsReply, Status> {
        IntelligenceClient::screening_facts(self, address).await
    }
}

/// One address's facts as intelligence last served them fresh.
#[derive(Debug, Clone, PartialEq)]
pub struct FactsSnapshot {
    pub facts: ScreeningFactsReply,
    /// When this service received the reply. Staleness is measured from here,
    /// not from `facts.computed_at_unix_millis`: intelligence's own cache is
    /// evicted on every input change, so a fresh reply is current *as of
    /// receipt* however long ago its score was computed.
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("undecodable snapshot: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("corrupt snapshot: {0}")]
    Corrupt(&'static str),
}

/// The last-known-good store. Object-safe, `Arc<dyn _>` in the fallback, with
/// an in-memory double in [`test_util`] — same shape as `ScreeningRateLimiter`.
#[async_trait]
pub trait SnapshotStore: Send + Sync {
    async fn get(&self, address: &AccountAddress) -> Result<Option<FactsSnapshot>, SnapshotError>;

    /// Replace each address's snapshot. Takes ownership so the writer encodes
    /// without a second copy of every reply.
    async fn put_many(
        &self,
        snapshots: Vec<(AccountAddress, FactsSnapshot)>,
    ) -> Result<(), SnapshotError>;
}

/// The stored form: protobuf, wrapping the very `ScreeningFactsReply` message
/// the wire carries, so a snapshot and a live reply cannot drift apart and a
/// field added to the proto is snapshotted with no change here.
#[derive(Clone, PartialEq, prost::Message)]
struct SnapshotWire {
    #[prost(int64, tag = "1")]
    observed_at_unix_millis: i64,
    #[prost(message, optional, tag = "2")]
    facts: Option<ScreeningFactsReply>,
}

fn encode(snapshot: FactsSnapshot) -> Vec<u8> {
    SnapshotWire {
        observed_at_unix_millis: snapshot.observed_at.timestamp_millis(),
        facts: Some(snapshot.facts),
    }
    .encode_to_vec()
}

fn decode(bytes: &[u8]) -> Result<FactsSnapshot, SnapshotError> {
    let wire = SnapshotWire::decode(bytes)?;
    let observed_at = DateTime::from_timestamp_millis(wire.observed_at_unix_millis)
        .ok_or(SnapshotError::Corrupt("observed_at out of range"))?;
    let facts = wire.facts.ok_or(SnapshotError::Corrupt("no facts"))?;
    Ok(FactsSnapshot { facts, observed_at })
}

/// Redis-backed [`SnapshotStore`] — one `GET` per lookup, one pipelined
/// `SET ... PX` per write batch. The TTL is the max stale age, so a snapshot
/// too old to serve is also gone; the age check in [`ScreeningFallback`] stays
/// regardless, because a TTL is housekeeping and not a correctness bound.
#[derive(Clone)]
pub struct RedisSnapshotStore {
    conn: ConnectionManager,
    ttl: Duration,
}

impl RedisSnapshotStore {
    pub fn new(conn: ConnectionManager, ttl: Duration) -> Self {
        Self { conn, ttl }
    }

    fn key(address: &AccountAddress) -> String {
        format!("screen_lkg:{}", address_key(address))
    }
}

#[async_trait]
impl SnapshotStore for RedisSnapshotStore {
    async fn get(&self, address: &AccountAddress) -> Result<Option<FactsSnapshot>, SnapshotError> {
        let mut conn = self.conn.clone();
        let bytes: Option<Vec<u8>> = redis::cmd("GET")
            .arg(Self::key(address))
            .query_async(&mut conn)
            .await?;
        bytes.as_deref().map(decode).transpose()
    }

    async fn put_many(
        &self,
        snapshots: Vec<(AccountAddress, FactsSnapshot)>,
    ) -> Result<(), SnapshotError> {
        if snapshots.is_empty() {
            return Ok(());
        }
        let ttl_millis = u64::try_from(self.ttl.as_millis()).unwrap_or(u64::MAX);
        let mut pipe = redis::pipe();
        for (address, snapshot) in snapshots {
            pipe.cmd("SET")
                .arg(Self::key(&address))
                .arg(encode(snapshot))
                .arg("PX")
                .arg(ttl_millis)
                .ignore();
        }
        let mut conn = self.conn.clone();
        let result: redis::RedisResult<()> = pipe.query_async(&mut conn).await;
        Ok(result?)
    }
}

/// The request path's non-blocking handle onto the snapshot writer.
#[derive(Clone)]
pub struct SnapshotRecorder {
    tx: mpsc::Sender<(AccountAddress, FactsSnapshot)>,
}

impl SnapshotRecorder {
    /// A recorder and the receiver [`run_snapshot_writer`] drains.
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<(AccountAddress, FactsSnapshot)>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
    }

    /// Queue one snapshot. Never blocks the screening call; a full or closed
    /// queue loses the snapshot and counts it.
    fn record(
        &self,
        address: AccountAddress,
        facts: &ScreeningFactsReply,
        observed_at: DateTime<Utc>,
    ) {
        let snapshot = FactsSnapshot {
            facts: facts.clone(),
            observed_at,
        };
        if self.tx.try_send((address, snapshot)).is_err() {
            metrics::counter!(SNAPSHOT_WRITES_LOST_TOTAL, "cause" => "queue").increment(1);
        }
    }
}

/// Drain the recorder into the store in pipelined batches until shutdown or
/// until every recorder is gone.
///
/// No graceful flush on shutdown, unlike `crate::audit`: a snapshot is a cache
/// of something intelligence still holds, and the next fresh call for that
/// address rewrites it. The audit trail is evidence; this is not.
pub async fn run_snapshot_writer(
    store: Arc<dyn SnapshotStore>,
    mut rx: mpsc::Receiver<(AccountAddress, FactsSnapshot)>,
    shutdown: CancellationToken,
) {
    let mut batch = Vec::with_capacity(WRITE_BATCH);
    loop {
        let received = tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            received = rx.recv_many(&mut batch, WRITE_BATCH) => received,
        };
        if received == 0 {
            return;
        }
        let snapshots = latest_per_address(batch.drain(..));
        let count = snapshots.len() as u64;
        if let Err(err) = store.put_many(snapshots).await {
            metrics::counter!(SNAPSHOT_WRITES_LOST_TOTAL, "cause" => "store").increment(count);
            tracing::warn!(
                error = %err,
                lost = count,
                "screening snapshot write failed; the stale fallback for these addresses is older"
            );
        }
    }
}

/// One entry per address, the newest winning — a hot address screened twice
/// inside one batch is only worth its latest observation.
fn latest_per_address(
    batch: impl DoubleEndedIterator<Item = (AccountAddress, FactsSnapshot)>,
) -> Vec<(AccountAddress, FactsSnapshot)> {
    let mut seen = HashSet::new();
    let mut latest: Vec<_> = batch
        .rev()
        .filter(|(address, _)| seen.insert(*address))
        .collect();
    latest.reverse();
    latest
}

/// The facts one screening decision is rendered over.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedFacts {
    pub facts: ScreeningFactsReply,
    /// `None`: fresh from intelligence on this request.
    pub staleness: Option<FactsStaleness>,
}

/// The armed fallback: its policy, the store it reads, the recorder it feeds.
#[derive(Clone)]
pub struct ScreeningFallback {
    degradation: Degradation,
    snapshots: Arc<dyn SnapshotStore>,
    recorder: SnapshotRecorder,
    /// When set, the fresh budget follows recent intelligence latency
    /// (`crate::facts_source::AdaptiveBudget`), with
    /// [`Degradation::fresh_budget`] as its ceiling.
    budget: Option<crate::facts_source::AdaptiveBudget>,
}

impl ScreeningFallback {
    pub fn new(
        degradation: Degradation,
        snapshots: Arc<dyn SnapshotStore>,
        recorder: SnapshotRecorder,
    ) -> Self {
        Self {
            degradation,
            snapshots,
            recorder,
            budget: None,
        }
    }

    /// Follow recent intelligence latency instead of a fixed budget.
    #[must_use]
    pub fn with_adaptive_budget(mut self, budget: crate::facts_source::AdaptiveBudget) -> Self {
        self.budget = Some(budget);
        self
    }

    fn fresh_budget(&self) -> Duration {
        self.budget
            .as_ref()
            .map_or(self.degradation.fresh_budget, |budget| budget.current())
    }
}

/// Publish the §15b arming state. Call once at boot, armed or not.
pub fn publish_arming(armed: bool) {
    metrics::gauge!(DEGRADATION_ENABLED).set(f64::from(u8::from(armed)));
}

/// Resolve the facts for one screening decision.
///
/// `fallback: None` is the disarmed path — fresh or fail closed, exactly the
/// behaviour before degradation existed.
pub async fn resolve_facts(
    source: &dyn FactsSource,
    fallback: Option<&ScreeningFallback>,
    address: AccountAddress,
) -> Result<ResolvedFacts, Status> {
    match fallback {
        Some(fallback) => fallback.resolve(source, address).await,
        None => {
            let facts = source.screening_facts(address).await?;
            served(FRESH);
            Ok(ResolvedFacts {
                facts,
                staleness: None,
            })
        }
    }
}

/// The outcome of a snapshot lookup, with its metric already recorded.
enum Lookup {
    Usable(FactsSnapshot, Duration),
    Unusable,
}

impl ScreeningFallback {
    async fn resolve(
        &self,
        source: &dyn FactsSource,
        address: AccountAddress,
    ) -> Result<ResolvedFacts, Status> {
        let fresh = source.screening_facts(address);
        tokio::pin!(fresh);

        // Inside the budget, fresh is the only answer.
        let within_budget = tokio::select! {
            biased;
            result = &mut fresh => Some(result),
            () = tokio::time::sleep(self.fresh_budget()) => None,
        };
        match within_budget {
            Some(Ok(facts)) => return Ok(self.fresh(address, facts)),
            Some(Err(status)) if !intelligence_client::is_transient(&status) => return Err(status),
            Some(Err(status)) => {
                let found = self.lookup(address).await;
                return self.stale_or_fail(found, reason_for(&status), status);
            }
            None => {}
        }

        // Over budget: look for a snapshot while the fresh read runs on toward
        // its own deadline. `biased` prefers fresh whenever both are ready.
        let lookup = self.lookup(address);
        tokio::pin!(lookup);
        tokio::select! {
            biased;
            result = &mut fresh => match result {
                Ok(facts) => {
                    degraded(ScreeningStaleReason::IntelligenceSlow, SERVED_FRESH_LATE);
                    Ok(self.fresh(address, facts))
                }
                Err(status) if !intelligence_client::is_transient(&status) => Err(status),
                Err(status) => {
                    let found = lookup.await;
                    self.stale_or_fail(found, reason_for(&status), status)
                }
            },
            found = &mut lookup => match found {
                // Returning drops `fresh`, which cancels the RPC; its
                // `grpc-timeout` already told intelligence when to give up.
                Lookup::Usable(snapshot, age) => {
                    Ok(self.stale(snapshot, age, ScreeningStaleReason::IntelligenceSlow))
                }
                // Nothing better to serve: the fresh read keeps its deadline.
                Lookup::Unusable => match fresh.await {
                    Ok(facts) => {
                        degraded(ScreeningStaleReason::IntelligenceSlow, SERVED_FRESH_LATE);
                        Ok(self.fresh(address, facts))
                    }
                    Err(status) => {
                        if intelligence_client::is_transient(&status) {
                            degraded(reason_for(&status), FAILED_CLOSED);
                        }
                        Err(status)
                    }
                },
            },
        }
    }

    fn fresh(&self, address: AccountAddress, facts: ScreeningFactsReply) -> ResolvedFacts {
        self.recorder.record(address, &facts, Utc::now());
        served(FRESH);
        ResolvedFacts {
            facts,
            staleness: None,
        }
    }

    fn stale(
        &self,
        snapshot: FactsSnapshot,
        age: Duration,
        reason: ScreeningStaleReason,
    ) -> ResolvedFacts {
        degraded(reason, SERVED_STALE);
        served(STALE);
        ResolvedFacts {
            facts: snapshot.facts,
            staleness: Some(FactsStaleness {
                reason,
                observed_at: snapshot.observed_at,
                age_ms: u64::try_from(age.as_millis()).unwrap_or(u64::MAX),
            }),
        }
    }

    fn stale_or_fail(
        &self,
        found: Lookup,
        reason: ScreeningStaleReason,
        status: Status,
    ) -> Result<ResolvedFacts, Status> {
        match found {
            Lookup::Usable(snapshot, age) => Ok(self.stale(snapshot, age, reason)),
            Lookup::Unusable => {
                degraded(reason, FAILED_CLOSED);
                Err(status)
            }
        }
    }

    async fn lookup(&self, address: AccountAddress) -> Lookup {
        let read = tokio::time::timeout(SNAPSHOT_READ_TIMEOUT, self.snapshots.get(&address)).await;
        let (result, lookup) = match read {
            Ok(Ok(Some(snapshot))) => {
                match age_within(
                    snapshot.observed_at,
                    Utc::now(),
                    self.degradation.max_stale_age,
                ) {
                    Some(age) => ("usable", Lookup::Usable(snapshot, age)),
                    None => ("too_old", Lookup::Unusable),
                }
            }
            Ok(Ok(None)) => ("missing", Lookup::Unusable),
            Ok(Err(err)) => {
                tracing::warn!(%address, error = %err, "screening snapshot read failed");
                ("error", Lookup::Unusable)
            }
            Err(_elapsed) => {
                tracing::warn!(%address, timeout = ?SNAPSHOT_READ_TIMEOUT, "screening snapshot read timed out");
                ("error", Lookup::Unusable)
            }
        };
        metrics::counter!(SNAPSHOT_LOOKUPS_TOTAL, "result" => result).increment(1);
        lookup
    }
}

/// How old a snapshot is at `now`, if it is still young enough to decide on
/// (inclusive at `max_age`). A snapshot stamped in the future — clock skew
/// between API pods — counts as age zero: the skew is milliseconds, and the
/// alternative is failing closed on a healthy snapshot.
pub fn age_within(
    observed_at: DateTime<Utc>,
    now: DateTime<Utc>,
    max_age: Duration,
) -> Option<Duration> {
    let age = (now - observed_at).to_std().unwrap_or(Duration::ZERO);
    (age <= max_age).then_some(age)
}

/// A deadline-class fault is slowness; every other transient fault is
/// unavailability.
fn reason_for(status: &Status) -> ScreeningStaleReason {
    match status.code() {
        Code::DeadlineExceeded | Code::Cancelled => ScreeningStaleReason::IntelligenceSlow,
        _ => ScreeningStaleReason::IntelligenceUnavailable,
    }
}

/// The metric label for a reason — its serde wire form, pinned by a test.
fn reason_label(reason: ScreeningStaleReason) -> &'static str {
    match reason {
        ScreeningStaleReason::IntelligenceSlow => "intelligence_slow",
        ScreeningStaleReason::IntelligenceUnavailable => "intelligence_unavailable",
    }
}

fn served(freshness: &'static str) {
    metrics::counter!(FACTS_SERVED_TOTAL, "freshness" => freshness).increment(1);
}

fn degraded(reason: ScreeningStaleReason, outcome: &'static str) {
    metrics::counter!(DEGRADED_TOTAL, "reason" => reason_label(reason), "outcome" => outcome)
        .increment(1);
}

/// In-memory [`SnapshotStore`] double, for this crate's unit tests and (behind
/// `test-util`) its integration tests — mirrors `rate_limit::test_util`.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    pub struct InMemorySnapshotStore {
        snapshots: Mutex<HashMap<AccountAddress, FactsSnapshot>>,
        read_delay: Option<Duration>,
        failing: bool,
    }

    impl InMemorySnapshotStore {
        pub fn new() -> Self {
            Self::default()
        }

        /// Every read waits this long first (a slow Redis).
        pub fn with_read_delay(mut self, delay: Duration) -> Self {
            self.read_delay = Some(delay);
            self
        }

        /// Every read and write fails (a dead Redis).
        pub fn failing() -> Self {
            Self {
                failing: true,
                ..Self::default()
            }
        }

        pub fn insert(&self, address: AccountAddress, snapshot: FactsSnapshot) {
            self.snapshots
                .lock()
                .expect("snapshot lock")
                .insert(address, snapshot);
        }

        pub fn snapshot(&self, address: &AccountAddress) -> Option<FactsSnapshot> {
            self.snapshots
                .lock()
                .expect("snapshot lock")
                .get(address)
                .cloned()
        }
    }

    #[async_trait]
    impl SnapshotStore for InMemorySnapshotStore {
        async fn get(
            &self,
            address: &AccountAddress,
        ) -> Result<Option<FactsSnapshot>, SnapshotError> {
            if let Some(delay) = self.read_delay {
                tokio::time::sleep(delay).await;
            }
            if self.failing {
                return Err(SnapshotError::Corrupt("injected failure"));
            }
            Ok(self.snapshot(address))
        }

        async fn put_many(
            &self,
            snapshots: Vec<(AccountAddress, FactsSnapshot)>,
        ) -> Result<(), SnapshotError> {
            if self.failing {
                return Err(SnapshotError::Corrupt("injected failure"));
            }
            for (address, snapshot) in snapshots {
                self.insert(address, snapshot);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::InMemorySnapshotStore;
    use super::*;

    use intelligence::pb::SanctionMatch;
    use tokio::time::Instant;

    const BUDGET: Duration = Duration::from_millis(150);
    /// Stands in for `SCREENING_DEADLINE_MS`: a scripted source that fails at
    /// this point is intelligence timing out.
    const DEADLINE: Duration = Duration::from_millis(500);
    const MAX_AGE: Duration = Duration::from_secs(900);

    struct ScriptedSource {
        after: Duration,
        result: Result<ScreeningFactsReply, Status>,
    }

    #[async_trait]
    impl FactsSource for ScriptedSource {
        async fn screening_facts(
            &self,
            _address: AccountAddress,
        ) -> Result<ScreeningFactsReply, Status> {
            tokio::time::sleep(self.after).await;
            self.result.clone()
        }
    }

    fn answers(after: Duration, score: u32) -> ScriptedSource {
        ScriptedSource {
            after,
            result: Ok(facts(score)),
        }
    }

    fn fails(after: Duration, status: Status) -> ScriptedSource {
        ScriptedSource {
            after,
            result: Err(status),
        }
    }

    fn facts(score: u32) -> ScreeningFactsReply {
        ScreeningFactsReply {
            score,
            model_version: "risk-v1".into(),
            ..Default::default()
        }
    }

    fn address() -> AccountAddress {
        alloy_primitives::Address::repeat_byte(0xAB)
    }

    fn snapshot_aged(age: Duration, score: u32) -> FactsSnapshot {
        FactsSnapshot {
            facts: facts(score),
            observed_at: Utc::now() - chrono::Duration::from_std(age).unwrap(),
        }
    }

    type Recorded = mpsc::Receiver<(AccountAddress, FactsSnapshot)>;

    fn armed(store: InMemorySnapshotStore) -> (ScreeningFallback, Recorded) {
        let (recorder, rx) = SnapshotRecorder::channel(16);
        let fallback = ScreeningFallback::new(
            Degradation {
                fresh_budget: BUDGET,
                max_stale_age: MAX_AGE,
            },
            Arc::new(store),
            recorder,
        );
        (fallback, rx)
    }

    fn with_snapshot(age: Duration, score: u32) -> InMemorySnapshotStore {
        let store = InMemorySnapshotStore::new();
        store.insert(address(), snapshot_aged(age, score));
        store
    }

    #[tokio::test(start_paused = true)]
    async fn a_fresh_answer_inside_the_budget_is_served_and_snapshotted() {
        let (fallback, mut recorded) = armed(with_snapshot(Duration::from_secs(60), 99));

        let resolved = resolve_facts(
            &answers(Duration::from_millis(40), 12),
            Some(&fallback),
            address(),
        )
        .await
        .unwrap();

        assert_eq!(resolved.staleness, None);
        assert_eq!(resolved.facts.score, 12, "fresh wins over any snapshot");
        let (snapshotted, snapshot) = recorded.try_recv().expect("a fresh reply is snapshotted");
        assert_eq!(snapshotted, address());
        assert_eq!(snapshot.facts, facts(12));
    }

    /// The case the module exists for: intelligence is slow, a snapshot
    /// exists, and the answer arrives at the budget instead of the deadline.
    #[tokio::test(start_paused = true)]
    async fn a_slow_read_is_answered_from_the_snapshot_at_the_budget() {
        let (fallback, mut recorded) = armed(with_snapshot(Duration::from_secs(60), 55));
        let started = Instant::now();

        let resolved = resolve_facts(
            &answers(Duration::from_secs(5), 12),
            Some(&fallback),
            address(),
        )
        .await
        .unwrap();

        assert_eq!(
            started.elapsed(),
            BUDGET,
            "bounded by the budget, not the read"
        );
        assert_eq!(resolved.facts.score, 55);
        let staleness = resolved.staleness.expect("flagged stale");
        assert_eq!(staleness.reason, ScreeningStaleReason::IntelligenceSlow);
        assert!(staleness.age_ms >= 60_000);
        assert!(
            recorded.try_recv().is_err(),
            "a stale answer must never be written back as if it were fresh"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_read_with_no_snapshot_waits_for_the_fresh_answer() {
        let (fallback, _recorded) = armed(InMemorySnapshotStore::new());
        let started = Instant::now();

        let resolved = resolve_facts(
            &answers(Duration::from_millis(300), 12),
            Some(&fallback),
            address(),
        )
        .await
        .unwrap();

        assert_eq!(started.elapsed(), Duration::from_millis(300));
        assert_eq!(resolved.staleness, None);
        assert_eq!(resolved.facts.score, 12);
    }

    /// Degradation never turns "could not decide" into an answer: with nothing
    /// to fall back on, a timeout is still the fail-closed error.
    #[tokio::test(start_paused = true)]
    async fn a_timeout_with_no_snapshot_still_fails_closed() {
        let (fallback, _recorded) = armed(InMemorySnapshotStore::new());

        let status = resolve_facts(
            &fails(DEADLINE, Status::deadline_exceeded("slow")),
            Some(&fallback),
            address(),
        )
        .await
        .unwrap_err();

        assert_eq!(status.code(), Code::DeadlineExceeded);
    }

    #[tokio::test(start_paused = true)]
    async fn a_transient_fault_is_answered_from_the_snapshot_immediately() {
        let (fallback, _recorded) = armed(with_snapshot(Duration::from_secs(1), 55));
        let started = Instant::now();

        let resolved = resolve_facts(
            &fails(
                Duration::from_millis(2),
                Status::unavailable("connection refused"),
            ),
            Some(&fallback),
            address(),
        )
        .await
        .unwrap();

        assert_eq!(
            started.elapsed(),
            Duration::from_millis(2),
            "a fault needs no budget to expire"
        );
        assert_eq!(
            resolved.staleness.unwrap().reason,
            ScreeningStaleReason::IntelligenceUnavailable
        );
    }

    /// A slow read that then *fails* after the budget, while the lookup is
    /// still in flight, still gets the snapshot — with the fault's reason.
    #[tokio::test(start_paused = true)]
    async fn a_fault_after_the_budget_still_reaches_the_snapshot() {
        let store =
            with_snapshot(Duration::from_secs(1), 55).with_read_delay(Duration::from_millis(20));
        let (fallback, _recorded) = armed(store);

        let resolved = resolve_facts(
            &fails(
                BUDGET + Duration::from_millis(5),
                Status::unavailable("reset"),
            ),
            Some(&fallback),
            address(),
        )
        .await
        .unwrap();

        assert_eq!(resolved.facts.score, 55);
        assert_eq!(
            resolved.staleness.unwrap().reason,
            ScreeningStaleReason::IntelligenceUnavailable
        );
    }

    /// Intelligence answering "no" is not intelligence being unavailable —
    /// a snapshot must not paper over a bug or a bad request.
    #[tokio::test(start_paused = true)]
    async fn a_permanent_fault_never_degrades() {
        for status in [
            Status::internal("bug"),
            Status::not_found("x"),
            Status::invalid_argument("bad address"),
        ] {
            let (fallback, _recorded) = armed(with_snapshot(Duration::from_secs(1), 55));
            let err = resolve_facts(
                &fails(Duration::from_millis(1), status.clone()),
                Some(&fallback),
                address(),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), status.code());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_snapshot_older_than_the_max_age_is_not_served() {
        let (fallback, _recorded) = armed(with_snapshot(MAX_AGE + Duration::from_secs(1), 55));

        let status = resolve_facts(
            &fails(Duration::from_millis(1), Status::unavailable("down")),
            Some(&fallback),
            address(),
        )
        .await
        .unwrap_err();

        assert_eq!(status.code(), Code::Unavailable);
    }

    /// A hung Redis costs a degraded request the lookup timeout, not the rest
    /// of the intelligence deadline — and the fresh answer still lands.
    #[tokio::test(start_paused = true)]
    async fn a_hung_snapshot_store_is_bounded_and_falls_through_to_fresh() {
        let store =
            with_snapshot(Duration::from_secs(1), 55).with_read_delay(Duration::from_secs(30));
        let (fallback, _recorded) = armed(store);
        let started = Instant::now();

        let resolved = resolve_facts(
            &answers(Duration::from_millis(300), 12),
            Some(&fallback),
            address(),
        )
        .await
        .unwrap();

        assert_eq!(resolved.staleness, None);
        assert_eq!(started.elapsed(), Duration::from_millis(300));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_snapshot_store_degrades_to_fail_closed_not_to_a_panic() {
        let (fallback, _recorded) = armed(InMemorySnapshotStore::failing());

        let status = resolve_facts(
            &fails(Duration::from_millis(1), Status::unavailable("down")),
            Some(&fallback),
            address(),
        )
        .await
        .unwrap_err();

        assert_eq!(status.code(), Code::Unavailable);
    }

    /// The snapshot carries the sanctions matches it was taken with, so the
    /// §8.5 hard block survives a stale answer.
    #[tokio::test(start_paused = true)]
    async fn a_stale_answer_keeps_its_sanctions_matches() {
        let store = InMemorySnapshotStore::new();
        let mut sanctioned = snapshot_aged(Duration::from_secs(10), 0);
        sanctioned.facts.sanctions = vec![SanctionMatch {
            list: "ofac_sdn".into(),
            entry: "Evil Corp".into(),
        }];
        store.insert(address(), sanctioned);
        let (fallback, _recorded) = armed(store);

        let resolved = resolve_facts(
            &fails(Duration::from_millis(1), Status::unavailable("down")),
            Some(&fallback),
            address(),
        )
        .await
        .unwrap();
        let input = crate::screen::ScreeningInput::from(&resolved.facts);
        let verdict = crate::screen::decide(
            input,
            &crate::screen::builtin_policy("monitor-only").unwrap(),
            crate::screen::Freshness::Fresh,
        );

        assert_eq!(verdict.decision, crate::screen::Decision::Block);
    }

    #[tokio::test(start_paused = true)]
    async fn disarmed_is_the_pre_degradation_behaviour() {
        let started = Instant::now();
        let resolved = resolve_facts(&answers(Duration::from_millis(400), 12), None, address())
            .await
            .unwrap();
        assert_eq!(started.elapsed(), Duration::from_millis(400));
        assert_eq!(resolved.staleness, None);

        let status = resolve_facts(
            &fails(Duration::from_millis(1), Status::unavailable("down")),
            None,
            address(),
        )
        .await
        .unwrap_err();
        assert_eq!(status.code(), Code::Unavailable);
    }

    #[tokio::test]
    async fn the_writer_keeps_the_newest_observation_per_address() {
        let store = Arc::new(InMemorySnapshotStore::new());
        let (recorder, rx) = SnapshotRecorder::channel(16);
        let other = alloy_primitives::Address::repeat_byte(0xCD);
        let at = Utc::now();

        recorder.record(address(), &facts(1), at);
        recorder.record(other, &facts(7), at);
        recorder.record(address(), &facts(2), at);
        drop(recorder);

        run_snapshot_writer(store.clone(), rx, CancellationToken::new()).await;

        assert_eq!(store.snapshot(&address()).unwrap().facts.score, 2);
        assert_eq!(store.snapshot(&other).unwrap().facts.score, 7);
    }

    #[test]
    fn latest_per_address_preserves_first_seen_order_of_the_survivors() {
        let a = alloy_primitives::Address::repeat_byte(1);
        let b = alloy_primitives::Address::repeat_byte(2);
        let at = Utc::now();
        let snap = |score| FactsSnapshot {
            facts: facts(score),
            observed_at: at,
        };
        let batch = vec![(a, snap(1)), (b, snap(2)), (a, snap(3))];

        let latest = latest_per_address(batch.into_iter());

        let scores: Vec<(AccountAddress, u32)> = latest
            .iter()
            .map(|(addr, s)| (*addr, s.facts.score))
            .collect();
        assert_eq!(scores, vec![(b, 2), (a, 3)]);
    }

    #[test]
    fn a_snapshot_round_trips_through_its_stored_form() {
        let snapshot = FactsSnapshot {
            facts: ScreeningFactsReply {
                score: 87,
                confidence: 0.7,
                sanctions: vec![SanctionMatch {
                    list: "ofac_sdn".into(),
                    entry: "Evil Corp".into(),
                }],
                entity_id: Some("e-1".into()),
                entity_size: 3,
                ..facts(87)
            },
            // Millisecond precision is what is stored.
            observed_at: DateTime::from_timestamp_millis(1_700_000_000_123).unwrap(),
        };

        assert_eq!(decode(&encode(snapshot.clone())).unwrap(), snapshot);
    }

    #[test]
    fn an_undecodable_or_empty_snapshot_is_an_error_not_an_empty_answer() {
        assert!(decode(b"\xff\xff\xff").is_err());
        // Valid protobuf with no facts: must not decode as a zero-score "clean"
        // address, which would be a fabricated allow.
        assert!(matches!(decode(&[]), Err(SnapshotError::Corrupt(_))));
    }

    #[test]
    fn age_is_inclusive_at_the_bound_and_tolerates_clock_skew() {
        let now = Utc::now();
        let max = Duration::from_secs(900);
        let ago = |secs| now - chrono::Duration::seconds(secs);

        assert_eq!(age_within(ago(900), now, max), Some(max));
        assert_eq!(age_within(ago(901), now, max), None);
        assert_eq!(
            age_within(now + chrono::Duration::seconds(2), now, max),
            Some(Duration::ZERO),
            "a future stamp is skew, not a reason to fail closed"
        );
    }

    #[test]
    fn deadline_class_faults_are_slowness_and_the_rest_unavailability() {
        assert_eq!(
            reason_for(&Status::deadline_exceeded("")),
            ScreeningStaleReason::IntelligenceSlow
        );
        assert_eq!(
            reason_for(&Status::cancelled("Timeout expired")),
            ScreeningStaleReason::IntelligenceSlow
        );
        assert_eq!(
            reason_for(&Status::unavailable("")),
            ScreeningStaleReason::IntelligenceUnavailable
        );
    }

    #[test]
    fn reason_labels_are_the_wire_form() {
        for reason in [
            ScreeningStaleReason::IntelligenceSlow,
            ScreeningStaleReason::IntelligenceUnavailable,
        ] {
            assert_eq!(serde_json::to_value(reason).unwrap(), reason_label(reason));
        }
    }
}
