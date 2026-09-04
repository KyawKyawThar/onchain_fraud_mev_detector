//! The rebuild driver: the procedure, written once.
//!
//! ```text
//!   pin watermark → fingerprint live → stage → replay+fold → fingerprint staged
//!                                                    → diff → promote | discard
//! ```
//!
//! ## Why a watermark
//!
//! The event store is *appended to while the rebuild runs*. Stopping the live
//! consumer does not stop the producers. Without an upper bound, each per-type
//! replay lane walks to whatever the tail happens to be at the moment that lane
//! drains — so lanes finish at different points in the log, the rebuilt model
//! is a torn read belonging to no single instant, and every event that landed
//! during the run shows up as a spurious `gained` divergence, in proportion to
//! run duration × event rate.
//!
//! So a rebuild pins a [`Watermark`] first and replays `[from, W)`. The bound
//! is on **ingest time** (`appended_at`), not event time: an event's
//! `occurred_at` can be older than `W` while it is appended after `W`, so an
//! event-time bound is not a cut of the log at all — it is a filter a late
//! arrival slips straight through.
//!
//! ### The residual race, closed by idempotency rather than by a bigger lock
//!
//! `appended_at` is stamped by the server at insert, so an insert already in
//! flight when `W` is taken can carry a timestamp below `W` and become visible
//! *after* the replay has passed that point. A rebuild can therefore miss a
//! narrow band of events around `W`. That is closed the way the rest of this
//! pipeline closes at-least-once delivery: after promotion the live consumer
//! resumes **from its own committed Kafka offsets**, which are behind `W`, and
//! re-applies those events idempotently. The rebuild produces "the read model
//! as of `W`"; the consumer carries it forward. Both halves are load-bearing,
//! which is why restarting the consumer is a step of the procedure and not an
//! afterthought.
//!
//! ## Two verdicts, one path
//!
//! * **[`verify`] (the drill).** Builds the replacement, compares, and
//!   **discards** it. Non-destructive, so it can run on a timer against
//!   production instead of needing an outage window. A divergence is a
//!   failure: projections are supposed to be derived.
//! * **[`rebuild`] (the recovery).** The same run, then **promotes**. The event
//!   store is the system of record, so the rebuilt state wins by definition and
//!   the diff is a damage report.
//!
//! Because nothing is ever wiped, a fault mid-replay discards the staging area
//! and leaves production exactly as it was. There is no partially-rebuilt state
//! to explain to anyone.

use std::time::Instant;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::digest::{Divergence, ModelDigest, RowDigest};
use crate::model::{ReadModel, Scope, ScopeSupport, Snapshotter, Staging};
use crate::source::{MergedReplay, PageRequest, ReplaySource, Watermark, DEFAULT_PAGE};

/// A failure of the procedure itself.
#[derive(Debug, thiserror::Error)]
pub enum RebuildError {
    /// The plan was not confirmed. See [`RebuildPlan::confirmed`].
    #[error("refusing to promote `{model}`: the plan is not confirmed")]
    Unconfirmed { model: &'static str },

    /// The plan narrowed a scope this model's storage cannot honour. Caught
    /// before anything is created.
    #[error(
        "read model `{model}` supports only a full rebuild: a staged replacement built from a \
         narrowed scope would be promoted missing everything outside it"
    )]
    UnsupportedScope { model: &'static str },

    /// Pulling the replay stream failed.
    #[error("replaying from the event store failed")]
    Replay(#[from] crate::source::ReplayError),

    /// The read model's storage failed. **The live model is untouched**; the
    /// staging area has been discarded, or its id is named here for cleanup.
    #[error("read model `{model}` failed after {applied} event(s); live state is UNCHANGED{}",
            .staging.as_ref().map(|s| format!(" (staging area `{s}` may need dropping)")).unwrap_or_default())]
    Model {
        model: &'static str,
        applied: u64,
        staging: Option<String>,
        #[source]
        source: crate::model::ModelError,
    },

    /// The operator cancelled the run. The staging area is discarded; the live
    /// model is untouched.
    #[error("rebuild of `{model}` cancelled after {applied} event(s); live state is UNCHANGED")]
    Cancelled { model: &'static str, applied: u64 },
}

/// What to rebuild, over what slice of history.
#[derive(Debug, Clone)]
pub struct RebuildPlan {
    /// The slice of history to replay and to fingerprint.
    pub scope: Scope,
    /// Events per replay page.
    pub page_size: u64,
    /// **Explicit authorization to promote.** Nothing in this crate sets it —
    /// the operator's `--yes` does. [`verify`] never promotes and so never
    /// requires it.
    pub confirmed: bool,
}

impl Default for RebuildPlan {
    fn default() -> Self {
        Self {
            scope: Scope::everything(),
            page_size: DEFAULT_PAGE,
            confirmed: false,
        }
    }
}

impl RebuildPlan {
    /// A full rebuild of everything, not yet authorized to promote.
    pub fn full() -> Self {
        Self::default()
    }

    /// Authorize promotion.
    pub fn confirm(mut self) -> Self {
        self.confirmed = true;
        self
    }

    /// Replace the scope.
    pub fn scoped(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }
}

/// Whether the staged replacement went live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The staged model replaced the live one (a recovery).
    Promoted,
    /// The staged model was compared and thrown away (a drill).
    Discarded,
}

/// What one run did.
#[derive(Debug, Clone)]
pub struct RebuildReport {
    pub model: &'static str,
    /// The ingest-time cut this rebuild is "as of".
    pub watermark: Watermark,
    /// Events replayed out of the event store and folded.
    pub events_replayed: u64,
    /// Rows in the live model before the run.
    pub live_rows: usize,
    /// Rows in the staged replacement.
    pub staged_rows: usize,
    /// Fingerprint of the live model.
    pub live_root: RowDigest,
    /// Fingerprint of the staged replacement.
    pub staged_root: RowDigest,
    /// Live versus staged.
    ///
    /// Only the divergence survives — not both full [`ModelDigest`]s, which are
    /// each O(rows) and would double the memory peak at exactly the moment the
    /// run is largest.
    pub divergence: Divergence,
    /// Whether the staged model was promoted or discarded.
    pub outcome: Outcome,
    /// Wall-clock duration.
    pub elapsed: std::time::Duration,
}

impl RebuildReport {
    /// Whether the rebuild reproduced the live read model exactly.
    pub fn is_identical(&self) -> bool {
        self.divergence.is_identical()
    }

    /// A one-screen summary, safe to paste into an incident channel. Bounded to
    /// `max_keys` diverging keys per class.
    pub fn summarize(&self, max_keys: usize) -> String {
        format!(
            "rebuild `{}` as of {}: {} events replayed, {} live row(s) -> {} staged, {:.1}s ({})\n\
             live root:   {}\n\
             staged root: {}\n\
             verdict: {}",
            self.model,
            self.watermark,
            self.events_replayed,
            self.live_rows,
            self.staged_rows,
            self.elapsed.as_secs_f64(),
            match self.outcome {
                Outcome::Promoted => "PROMOTED — the staged model is now live",
                Outcome::Discarded => "discarded — live model untouched",
            },
            self.live_root.to_hex(),
            self.staged_root.to_hex(),
            self.divergence.summarize(max_keys),
        )
    }
}

/// Build a replacement from the log and **promote** it — the recovery.
///
/// Returns `Ok` with a divergent report when the rebuild succeeded but did not
/// reproduce the live state: that is a finding, not a failure of the procedure.
pub async fn rebuild(
    model: &dyn ReadModel,
    source: &dyn ReplaySource,
    plan: &RebuildPlan,
    shutdown: &CancellationToken,
) -> Result<RebuildReport, RebuildError> {
    if !plan.confirmed {
        return Err(RebuildError::Unconfirmed {
            model: model.name(),
        });
    }
    run(model, source, plan, Outcome::Promoted, shutdown).await
}

/// Build a replacement from the log, compare it, and **discard** it — the drill.
///
/// Non-destructive: the live read model is never written to, so this is safe to
/// run on a schedule against production. Any divergence is an error, because
/// the whole point is the assertion that projections are derived.
pub async fn verify(
    model: &dyn ReadModel,
    source: &dyn ReplaySource,
    plan: &RebuildPlan,
    shutdown: &CancellationToken,
) -> Result<RebuildReport, VerifyFailure> {
    let report = run(model, source, plan, Outcome::Discarded, shutdown)
        .await
        .map_err(VerifyFailure::Procedure)?;
    if report.is_identical() {
        Ok(report)
    } else {
        Err(VerifyFailure::Diverged(Box::new(report)))
    }
}

/// Why a [`verify`] did not pass.
#[derive(Debug, thiserror::Error)]
pub enum VerifyFailure {
    /// The rebuild itself could not complete.
    #[error(transparent)]
    Procedure(#[from] RebuildError),

    /// The rebuild completed and the result differs from what is live — the
    /// read model is **not** purely derived from the event store.
    #[error("rebuilt read model differs from the live one:\n{}", .0.summarize(20))]
    Diverged(Box<RebuildReport>),
}

/// Fingerprint the live read model without touching it — the baseline an
/// operator takes before a risky deploy.
///
/// Takes only a [`Snapshotter`]: fingerprinting cannot fold an event or promote
/// anything, and the type says so.
pub async fn fingerprint(
    model: &dyn Snapshotter,
    scope: &Scope,
) -> Result<ModelDigest, RebuildError> {
    model
        .digest(scope)
        .await
        .map_err(|source| RebuildError::Model {
            model: model.name(),
            applied: 0,
            staging: None,
            source,
        })
}

/// The shared body of [`rebuild`] and [`verify`]. The only difference is what
/// happens to the staging area at the end, which is why they are one function
/// and not two similar ones that could drift.
async fn run(
    model: &dyn ReadModel,
    source: &dyn ReplaySource,
    plan: &RebuildPlan,
    outcome: Outcome,
    shutdown: &CancellationToken,
) -> Result<RebuildReport, RebuildError> {
    let name = model.name();

    // 0. Refuse a scope this storage cannot honour — before anything exists.
    if model.scope_support() == ScopeSupport::FullOnly && !plan.scope.is_everything() {
        return Err(RebuildError::UnsupportedScope { model: name });
    }
    let started = Instant::now();

    // 1. Pin the cut. Everything below is "as of" this ingest-time watermark;
    //    see the module docs for why it is ingest time and not event time.
    let watermark = source.watermark().await?;
    info!(model = name, %watermark, "pinned the replay watermark");

    // 2. Fingerprint what is live. Read-only.
    let live = model
        .digest(&plan.scope)
        .await
        .map_err(|source| RebuildError::Model {
            model: name,
            applied: 0,
            staging: None,
            source,
        })?;
    let (live_rows, live_root) = (live.len(), live.root());
    info!(
        model = name,
        rows = live_rows,
        root = %live_root.to_hex(),
        "fingerprinted the live read model"
    );

    // 3. Create the staging area and take the projector that writes into it.
    //    From here on, every failure path must discard it.
    let staging = Staging::new(name);
    let projector = model
        .stage(&staging)
        .await
        .map_err(|source| RebuildError::Model {
            model: name,
            applied: 0,
            staging: Some(staging.id().to_string()),
            source,
        })?;
    info!(model = name, %staging, "created the staging area");

    // 4. Replay and fold into staging.
    let event_types = projector.event_types();
    let template = PageRequest {
        chain: plan.scope.chain,
        event_type: None,
        from: plan.scope.from,
        to: plan.scope.to,
        appended_before: Some(watermark),
        cursor: None,
        limit: plan.page_size,
    };
    let mut stream = MergedReplay::new(source, template, &event_types);
    let mut applied = 0u64;
    let mut last_logged = Instant::now();

    loop {
        if shutdown.is_cancelled() {
            discard(model, &staging).await;
            return Err(RebuildError::Cancelled {
                model: name,
                applied,
            });
        }
        let next = match stream.next().await {
            Ok(next) => next,
            Err(err) => {
                discard(model, &staging).await;
                return Err(err.into());
            }
        };
        let Some(envelope) = next else { break };

        // Read what the progress line needs before handing the envelope over —
        // `apply` takes it by value, so there is no clone on this path.
        let occurred_at = envelope.occurred_at;
        if let Err(source) = projector.apply(envelope).await {
            discard(model, &staging).await;
            return Err(RebuildError::Model {
                model: name,
                applied,
                staging: None,
                source,
            });
        }
        applied += 1;
        if last_logged.elapsed() >= std::time::Duration::from_secs(30) {
            info!(model = name, applied, at = %occurred_at, "replaying");
            last_logged = Instant::now();
        }
    }

    if let Err(source) = projector.flush().await {
        discard(model, &staging).await;
        return Err(RebuildError::Model {
            model: name,
            applied,
            staging: None,
            source,
        });
    }

    // 5. Fingerprint the staged replacement and diff.
    let staged = match model.digest_staged(&staging, &plan.scope).await {
        Ok(staged) => staged,
        Err(source) => {
            discard(model, &staging).await;
            return Err(RebuildError::Model {
                model: name,
                applied,
                staging: None,
                source,
            });
        }
    };
    let (staged_rows, staged_root) = (staged.len(), staged.root());
    let divergence = live.diff(&staged);
    // Both full digests die here; only the divergence and the two roots survive
    // into the report.
    drop(live);
    drop(staged);

    // 6. Promote or discard.
    match outcome {
        Outcome::Promoted => {
            let rows = model
                .promote(&staging)
                .await
                .map_err(|source| RebuildError::Model {
                    model: name,
                    applied,
                    staging: Some(staging.id().to_string()),
                    source,
                })?;
            info!(model = name, rows, %staging, "promoted the staged read model");
        }
        Outcome::Discarded => discard(model, &staging).await,
    }

    let report = RebuildReport {
        model: name,
        watermark,
        events_replayed: applied,
        live_rows,
        staged_rows,
        live_root,
        staged_root,
        divergence,
        outcome,
        elapsed: started.elapsed(),
    };
    info!(
        model = name,
        events = report.events_replayed,
        identical = report.is_identical(),
        diverging = report.divergence.len(),
        outcome = ?report.outcome,
        "rebuild complete"
    );
    Ok(report)
}

/// Best-effort cleanup on every failure path. A staging area that outlives its
/// run costs disk and nothing else, so a failed discard is logged loudly (with
/// its id, so an operator can drop it) rather than masking the original error
/// that brought us here.
async fn discard(model: &dyn ReadModel, staging: &Staging) {
    if let Err(err) = model.discard(staging).await {
        warn!(
            model = model.name(),
            %staging,
            error = %err,
            "could not drop the staging area; drop it manually (it holds no live data)"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use events::primitives::{AlertId, Chain};
    use events::simulation::SimulationCompleted;
    use events::{DomainEvent, EventEnvelope};

    use super::*;
    use crate::digest::RowEncoder;
    use crate::model::{ModelError, Projector, Stageable};
    use crate::source::{ReplayError, ReplayPage};

    /// A read model that sums profit per alert. Small, but with the properties
    /// that matter: it is a fold over events, it is stored, and it stages.
    #[derive(Default)]
    struct SumModel {
        live: Mutex<BTreeMap<String, f64>>,
        staged: Mutex<BTreeMap<String, BTreeMap<String, f64>>>,
        /// Fail the Nth `apply`. Interior-mutable so a test can arm it *after*
        /// seeding the live model — arming it at construction would trip during
        /// the seed and test nothing.
        fail_after: Mutex<Option<u64>>,
        applied: Mutex<u64>,
    }

    /// The projector half, bound to one staging area.
    struct SumProjector {
        model: Arc<SumModel>,
        staging: String,
    }

    #[async_trait]
    impl Projector for SumProjector {
        fn event_types(&self) -> Vec<String> {
            vec!["SimulationCompleted".to_string()]
        }

        async fn apply(&self, envelope: EventEnvelope) -> Result<(), ModelError> {
            {
                let mut applied = self.model.applied.lock().unwrap();
                *applied += 1;
                if *self.model.fail_after.lock().unwrap() == Some(*applied) {
                    return Err(ModelError::new("storage exploded"));
                }
            }
            if let DomainEvent::SimulationCompleted(done) = &envelope.payload {
                let mut staged = self.model.staged.lock().unwrap();
                let area = staged.entry(self.staging.clone()).or_default();
                *area.entry(done.alert_id.0.to_string()).or_default() += done.profit;
            }
            Ok(())
        }

        async fn flush(&self) -> Result<(), ModelError> {
            Ok(())
        }
    }

    fn digest_of(rows: &BTreeMap<String, f64>) -> Result<ModelDigest, ModelError> {
        let mut digest = ModelDigest::new();
        for (key, profit) in rows {
            digest
                .insert(
                    format!("sum/{key}"),
                    RowEncoder::new().float(*profit).finish(),
                )
                .map_err(|key| ModelError::new(format!("duplicate row key {key}")))?;
        }
        Ok(digest)
    }

    #[async_trait]
    impl Snapshotter for Arc<SumModel> {
        fn name(&self) -> &'static str {
            "sum"
        }

        fn scope_support(&self) -> ScopeSupport {
            ScopeSupport::FullOnly
        }

        async fn digest(&self, _scope: &Scope) -> Result<ModelDigest, ModelError> {
            digest_of(&self.live.lock().unwrap())
        }
    }

    #[async_trait]
    impl Stageable for Arc<SumModel> {
        async fn stage(&self, staging: &Staging) -> Result<Arc<dyn Projector>, ModelError> {
            self.staged
                .lock()
                .unwrap()
                .insert(staging.id().to_string(), BTreeMap::new());
            Ok(Arc::new(SumProjector {
                model: Arc::clone(self),
                staging: staging.id().to_string(),
            }))
        }

        async fn digest_staged(
            &self,
            staging: &Staging,
            _scope: &Scope,
        ) -> Result<ModelDigest, ModelError> {
            let staged = self.staged.lock().unwrap();
            let rows = staged
                .get(staging.id())
                .ok_or_else(|| ModelError::new("no such staging area"))?;
            digest_of(rows)
        }

        async fn promote(&self, staging: &Staging) -> Result<u64, ModelError> {
            let rows = self
                .staged
                .lock()
                .unwrap()
                .remove(staging.id())
                .ok_or_else(|| ModelError::new("no such staging area"))?;
            let count = rows.len() as u64;
            *self.live.lock().unwrap() = rows;
            Ok(count)
        }

        async fn discard(&self, staging: &Staging) -> Result<(), ModelError> {
            self.staged.lock().unwrap().remove(staging.id());
            Ok(())
        }
    }

    struct Canned(Vec<EventEnvelope>);

    #[async_trait]
    impl ReplaySource for Canned {
        async fn watermark(&self) -> Result<Watermark, ReplayError> {
            Ok(Watermark::at(
                DateTime::<Utc>::from_timestamp(1_000, 0).unwrap(),
            ))
        }

        async fn page(&self, request: &PageRequest) -> Result<ReplayPage, ReplayError> {
            if request.cursor.is_some() {
                return Ok(ReplayPage {
                    events: vec![],
                    next_cursor: None,
                });
            }
            Ok(ReplayPage {
                events: self.0.clone(),
                next_cursor: None,
            })
        }
    }

    fn completed(alert: AlertId, profit: f64, secs: i64, byte: u8) -> EventEnvelope {
        EventEnvelope::with_metadata(
            uuid::Uuid::from_bytes([byte; 16]),
            DateTime::<Utc>::from_timestamp(secs, 0).unwrap(),
            Chain::ETHEREUM,
            DomainEvent::SimulationCompleted(SimulationCompleted {
                alert_id: alert,
                profit,
                victim_loss: 0.0,
                confirmed: true,
            }),
        )
    }

    fn events() -> Vec<EventEnvelope> {
        let a = AlertId(uuid::Uuid::from_bytes([0xaa; 16]));
        let b = AlertId(uuid::Uuid::from_bytes([0xbb; 16]));
        vec![
            completed(a, 1.0, 10, 1),
            completed(b, 2.0, 20, 2),
            completed(a, 3.0, 30, 3),
        ]
    }

    /// Populate the live model the way the live consumer would have.
    async fn seed_live(model: &Arc<SumModel>) {
        let staging = Staging::new("seed");
        let projector = model.stage(&staging).await.unwrap();
        for envelope in events() {
            projector.apply(envelope).await.unwrap();
        }
        model.promote(&staging).await.unwrap();
        *model.applied.lock().unwrap() = 0;
    }

    fn token() -> CancellationToken {
        CancellationToken::new()
    }

    #[tokio::test]
    async fn a_derived_model_rebuilds_to_the_identical_fingerprint() {
        let model = Arc::new(SumModel::default());
        seed_live(&model).await;
        let source = Canned(events());

        let report = rebuild(&model, &source, &RebuildPlan::full().confirm(), &token())
            .await
            .unwrap();

        assert!(report.is_identical(), "{}", report.summarize(10));
        assert_eq!(report.events_replayed, 3);
        assert_eq!(report.live_root, report.staged_root);
        assert_eq!(report.outcome, Outcome::Promoted);
    }

    /// The property that makes the drill runnable on a timer: `verify` compares
    /// and throws the replacement away, leaving production untouched.
    #[tokio::test]
    async fn verify_is_non_destructive_and_leaves_no_staging_area_behind() {
        let model = Arc::new(SumModel::default());
        seed_live(&model).await;
        let before = model.live.lock().unwrap().clone();
        let source = Canned(events());

        let report = verify(&model, &source, &RebuildPlan::full(), &token())
            .await
            .expect("a derived model passes the drill");

        assert_eq!(report.outcome, Outcome::Discarded);
        assert_eq!(*model.live.lock().unwrap(), before, "live model untouched");
        assert!(
            model.staged.lock().unwrap().is_empty(),
            "the staging area must be cleaned up"
        );
    }

    /// `verify` needs no `--yes`: it cannot promote, so there is nothing to
    /// authorize. `rebuild` does.
    #[tokio::test]
    async fn only_promotion_requires_confirmation() {
        let model = Arc::new(SumModel::default());
        seed_live(&model).await;
        let source = Canned(events());

        verify(&model, &source, &RebuildPlan::full(), &token())
            .await
            .expect("verify never promotes, so it needs no confirmation");

        let err = rebuild(&model, &source, &RebuildPlan::full(), &token())
            .await
            .expect_err("promotion requires confirmation");
        assert!(matches!(err, RebuildError::Unconfirmed { .. }));
    }

    /// A row nothing in the log produced is what "projections are derived"
    /// forbids — and the drill must name it, not merely fail.
    #[tokio::test]
    async fn a_row_with_no_events_behind_it_is_reported_as_lost() {
        let model = Arc::new(SumModel::default());
        seed_live(&model).await;
        model
            .live
            .lock()
            .unwrap()
            .insert("deadbeef".to_string(), 99.0);
        let source = Canned(events());

        let failure = verify(&model, &source, &RebuildPlan::full(), &token())
            .await
            .expect_err("a hand-written row is not derived");
        let VerifyFailure::Diverged(report) = failure else {
            panic!("expected a divergence, not a procedure failure");
        };
        assert_eq!(report.divergence.lost, vec!["sum/deadbeef".to_string()]);
        assert!(report.divergence.gained.is_empty());
    }

    #[tokio::test]
    async fn a_drifted_value_is_reported_as_changed_and_the_recovery_repairs_it() {
        let model = Arc::new(SumModel::default());
        seed_live(&model).await;
        let key = AlertId(uuid::Uuid::from_bytes([0xbb; 16])).0.to_string();
        *model.live.lock().unwrap().get_mut(&key).unwrap() = 999.0;
        let source = Canned(events());

        let report = rebuild(&model, &source, &RebuildPlan::full().confirm(), &token())
            .await
            .unwrap();
        assert_eq!(report.divergence.changed, vec![format!("sum/{key}")]);
        assert!(!report.is_identical());
        assert_eq!(*model.live.lock().unwrap().get(&key).unwrap(), 2.0);
    }

    /// The failure mode staging exists to delete: a fault mid-replay must leave
    /// production intact, not wiped and half-filled.
    #[tokio::test]
    async fn a_storage_fault_mid_replay_leaves_the_live_model_untouched() {
        let model = Arc::new(SumModel::default());
        seed_live(&model).await;
        let before = model.live.lock().unwrap().clone();
        // Armed only now: during the seed it would have failed the seed itself.
        *model.fail_after.lock().unwrap() = Some(2);
        let source = Canned(events());

        let err = rebuild(&model, &source, &RebuildPlan::full().confirm(), &token())
            .await
            .expect_err("a storage fault must not be swallowed");
        assert!(err.to_string().contains("UNCHANGED"), "{err}");
        assert_eq!(*model.live.lock().unwrap(), before);
        assert!(
            model.staged.lock().unwrap().is_empty(),
            "the failed staging area must be cleaned up"
        );
    }

    /// A rebuild runs for hours; it must stop when asked, and stopping must not
    /// leave a half-built replacement or a wiped model.
    #[tokio::test]
    async fn a_cancelled_rebuild_stops_and_leaves_the_live_model_untouched() {
        let model = Arc::new(SumModel::default());
        seed_live(&model).await;
        let before = model.live.lock().unwrap().clone();
        let source = Canned(events());

        let shutdown = CancellationToken::new();
        shutdown.cancel();

        let err = rebuild(&model, &source, &RebuildPlan::full().confirm(), &shutdown)
            .await
            .expect_err("a cancelled run must not report success");
        assert!(matches!(err, RebuildError::Cancelled { .. }));
        assert_eq!(*model.live.lock().unwrap(), before);
        assert!(model.staged.lock().unwrap().is_empty());
    }

    /// A scope the storage cannot honour is refused *before* a staging area is
    /// created — declared once, enforced once.
    #[tokio::test]
    async fn an_unsupported_scope_is_refused_before_anything_is_created() {
        let model = Arc::new(SumModel::default());
        seed_live(&model).await;
        let source = Canned(events());
        let plan = RebuildPlan::full()
            .scoped(Scope::everything().for_chain(1))
            .confirm();

        let err = rebuild(&model, &source, &plan, &token())
            .await
            .expect_err("a narrowed scope this model cannot express must fail");
        assert!(matches!(err, RebuildError::UnsupportedScope { .. }));
        assert!(model.staged.lock().unwrap().is_empty());
    }

    /// The watermark is pinned once and pushed into every replay lane — the
    /// consistent cut that stops a live tail from producing phantom `gained`
    /// rows.
    #[tokio::test]
    async fn every_replay_page_is_bounded_by_the_one_pinned_watermark() {
        struct Recording {
            inner: Canned,
            seen: Mutex<Vec<Option<Watermark>>>,
        }

        #[async_trait]
        impl ReplaySource for Recording {
            async fn watermark(&self) -> Result<Watermark, ReplayError> {
                self.inner.watermark().await
            }
            async fn page(&self, request: &PageRequest) -> Result<ReplayPage, ReplayError> {
                self.seen.lock().unwrap().push(request.appended_before);
                self.inner.page(request).await
            }
        }

        let model = Arc::new(SumModel::default());
        let source = Recording {
            inner: Canned(events()),
            seen: Mutex::new(vec![]),
        };
        let report = rebuild(&model, &source, &RebuildPlan::full().confirm(), &token())
            .await
            .unwrap();

        let seen = source.seen.lock().unwrap();
        assert!(!seen.is_empty());
        assert!(
            seen.iter().all(|w| *w == Some(report.watermark)),
            "every page must carry the one pinned cut: {seen:?}"
        );
    }
}
