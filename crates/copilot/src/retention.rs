//! Enforcing the regulatory retention policy's *artifact* half — the drafts
//! themselves (engineering conventions §18).
//!
//! [`retention::Policy`] decides how long a SAR narrative lives; this module is
//! where that becomes true of `copilot_drafts`. Its counterpart is
//! `event_store::retention`, which does the same for the evidence, and the two
//! read the *same* policy value from the *same* environment variables —
//! anything else and the platform has two retention decisions that agree until
//! the day they do not.
//!
//! # The anchor: five years from *what*
//!
//! The obligation is five years from filing. This platform does not file — a
//! reviewer approves a narrative and files from it elsewhere — so the closest
//! honest instant it owns is the draft's **disposition**:
//!
//! ```text
//!   reviewed_at   a human decided: approved (filed from) or rejected
//!                 (decided not to file — equally a record of a decision)
//!   completed_at  an answer landed and nobody ever decided
//!   created_at    no answer ever landed
//! ```
//!
//! [`anchor`] is that `COALESCE`, and it is deliberately *one* function shared
//! with the grounding audit: the audit's whole new job is to hold a draft to
//! the standard of a live artifact until the moment the purge would be allowed
//! to destroy it, and two implementations of "when is that" would put a window
//! in between where a draft is both too old to check and too young to delete.
//!
//! # The purge is a plan and an apply, and the plan is the whole truth
//!
//! Four properties, each one load-bearing:
//!
//! * **A job, not a background task.** Like the grounding audit it sweeps the
//!   whole table occasionally; unlike the audit it *deletes*, so it must be
//!   runnable by hand with its output in front of a person.
//! * **[`scan`] is the dry run and the apply's input.** Not two code paths
//!   behind a flag — one [`PurgePlan`], printed either way. The counts come
//!   from a `COUNT(*)` over the purge's own predicate, so a preview cannot
//!   under-report what an apply would destroy.
//! * **[`apply`] takes a [`DestructiveIntent`].** The only way to destroy an
//!   artifact is from a call site that names the witness; nothing on a timer,
//!   a boot path or a background task can reach it by accident.
//! * **A legal hold is checked twice** — once in the scan and again inside the
//!   `DELETE`. A hold placed between the two is exactly the case that matters:
//!   somebody is placing it *because* they just learned the record is wanted.
//!
//! Deleting a draft cascades its `copilot_outbox` row (the announcement
//! envelope). That is intended: the announcement's durable copy is the
//! `IncidentNarrativeDrafted` event in event-store, which is under the
//! evidence half of the same policy and outlives the draft by the margin.

use chrono::{DateTime, Utc};
// `::` is load-bearing: this module is *also* called `retention`, so a bare
// path here would be ambiguous between the shared crate and itself.
use ::retention::{DestructiveIntent, Disposition, Policy};
use tokio_util::sync::CancellationToken;

use events::primitives::Chain;
use events::{DomainEvent, EventEnvelope};

use crate::model::Draft;
use crate::store::{DraftRetention, ExpiredDraft, StoreError};

/// Rows deleted per statement. Small enough that a purge over a five-year
/// backlog is a series of short transactions rather than one long lock on the
/// table a live worker pool is claiming from.
pub const DEFAULT_BATCH_SIZE: i64 = 500;

/// Ceiling on rows one run destroys. A purge that has deleted a hundred
/// thousand drafts has either found five years of backlog on its first run or
/// is acting on a policy somebody just mis-typed, and the two look identical
/// from inside the loop — so the run stops and says so, and the operator runs
/// it again if the first answer was right.
pub const DEFAULT_MAX_PURGED: usize = 100_000;

/// How many ids a plan names. Bounded: a plan that lists fifty thousand drafts
/// lists none of them, as far as a reader is concerned.
pub const DEFAULT_SAMPLE: i64 = 20;

/// When this draft's retention clock started.
///
/// Total by construction — every draft has a `created_at`, so there is no
/// draft this cannot date and therefore none that silently escapes the policy.
pub fn anchor(draft: &Draft) -> Disposition {
    Disposition::at(
        draft
            .review
            .as_ref()
            .map(|review| review.at)
            .or_else(|| draft.answer.as_ref().map(|answer| answer.completed_at))
            .unwrap_or(draft.created_at),
    )
}

/// When this draft may be destroyed.
pub fn deadline(draft: &Draft, policy: &Policy) -> DateTime<Utc> {
    policy.artifact_deadline(anchor(draft))
}

/// Whether the policy would allow this draft to be destroyed as of `now`.
///
/// The audit's question and the purge's are the same question, asked of
/// different things — a `Draft` here, a row's anchor in SQL — which is why the
/// comparison itself lives in [`retention::Policy::is_expired`] and neither
/// caller re-derives it.
pub fn is_expired(draft: &Draft, policy: &Policy, now: DateTime<Utc>) -> bool {
    policy.is_expired(anchor(draft), now)
}

/// A backfill window the policy will not allow.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "a backfill from {requested} would draft narratives over evidence that expires \
     before they do: under the current policy the earliest defendable start is \
     {earliest}. Either pass `--from {earliest}`, or raise \
     RETENTION_EVIDENCE_MARGIN_DAYS — which is the same knob that lengthens the \
     event store's TTL, and so is what actually makes the older archive draftable"
)]
pub struct WindowTooOld {
    pub requested: DateTime<Utc>,
    pub earliest: DateTime<Utc>,
}

/// Hold a backfill window to the policy before it spends a token.
///
/// An unbounded `from` is refused for the same reason an old one is: "the whole
/// archive" reaches evidence that will expire before the narratives written
/// from it, and the run would produce — deliberately, at scale — exactly the
/// document [`retention::Policy`] exists to prevent. There is intentionally no
/// override flag; the way to draft further back is to keep the evidence longer,
/// and that is one environment variable that does both.
pub fn check_backfill_window(
    from: Option<DateTime<Utc>>,
    policy: &Policy,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, WindowTooOld> {
    let earliest = policy.oldest_draftable(now).instant();
    match from {
        Some(from) if from >= earliest => Ok(from),
        Some(from) => Err(WindowTooOld {
            requested: from,
            earliest,
        }),
        // "The whole archive" is a window that starts at the beginning of time.
        None => Err(WindowTooOld {
            requested: DateTime::UNIX_EPOCH,
            earliest,
        }),
    }
}

// ── plan ─────────────────────────────────────────────────────────

/// **What the purge would do**, computed before anything is destroyed.
///
/// The dry run *is* this value printed, and the apply consumes this exact
/// value — which is the property the previous shape lacked. That version
/// branched on an `apply: bool` deep inside the loop and took a different
/// path on each side: the preview read one page and reported what it found
/// there, while the apply paged to the end. So "would purge 500" and "purged
/// 40,000" were both honest reports of different computations, and the number a
/// human approved was not the number that happened. For a destructive
/// compliance action that is the wrong failure direction.
///
/// Now: one scan, one plan, and `--apply` decides only whether [`apply`] is
/// called at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgePlan {
    /// The disposition bound every row in the plan is at or before.
    pub cutoff: Disposition,
    /// **Every** draft the policy has released, not a page of them.
    pub due: i64,
    /// Past-deadline drafts a legal hold is preserving. Counted, never
    /// deleted, and reported — an unnoticed hold is how a table quietly stops
    /// obeying its policy.
    pub held: i64,
    /// How many this run is permitted to destroy.
    pub budget: usize,
    /// The oldest few, named. Bounded; [`PurgePlan::due`] is not.
    pub sample: Vec<ExpiredDraft>,
}

impl PurgePlan {
    /// Whether carrying this out would destroy anything.
    pub fn is_destructive(&self) -> bool {
        self.due > 0
    }

    /// How many this run would actually reach, budget included.
    pub fn reachable(&self) -> i64 {
        self.due.min(self.budget as i64)
    }

    /// Whether the budget stops this run short of the whole backlog.
    pub fn budget_bound(&self) -> bool {
        self.due > self.budget as i64
    }
}

impl std::fmt::Display for PurgePlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "retention plan: {} draft(s) past their deadline ({}), {} held by a legal hold",
            self.due, self.cutoff, self.held,
        )?;
        if self.budget_bound() {
            write!(
                f,
                "\n  ! this run would destroy {} of them ({}); re-run to continue",
                self.budget, "--limit bounds one invocation"
            )?;
        }
        for draft in &self.sample {
            write!(f, "\n  {draft}")?;
        }
        if self.due > self.sample.len() as i64 {
            write!(f, "\n  … and {} more", self.due - self.sample.len() as i64)?;
        }
        Ok(())
    }
}

/// Read the backlog and decide what a run would do. Does not destroy anything.
pub async fn scan(
    store: &dyn DraftRetention,
    policy: &Policy,
    now: DateTime<Utc>,
    budget: usize,
) -> Result<PurgePlan, StoreError> {
    let cutoff = policy.purge_cutoff(now);
    let scan = store.scan(cutoff, DEFAULT_SAMPLE).await?;
    Ok(PurgePlan {
        cutoff,
        due: scan.due,
        held: scan.held,
        budget: budget.max(1),
        sample: scan.sample,
    })
}

// ── apply ────────────────────────────────────────────────────────

/// What carrying a plan out actually did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeOutcome {
    /// Artifacts destroyed. This is the number that goes in the ticket.
    pub purged: u64,
    /// Whether the run stopped on its budget or a shutdown signal rather than
    /// on an empty backlog.
    pub truncated: bool,
}

/// **Destroy the artifacts a plan named.**
///
/// Takes the [`DestructiveIntent`] witness and passes it to every write, so the
/// only way into this function is from a call site that names it — grep for the
/// type to enumerate them. A CronJob's `args` are where a human puts `--apply`,
/// and that arm is the only place in the copilot that mints one.
///
/// The loop re-queries rather than walking a cursor: rows are *disappearing*
/// under the query, so "the oldest N still past the cutoff" is stable while a
/// keyset position is not — the opposite of the grounding audit's walk, which
/// deletes nothing and therefore needs the cursor.
pub async fn apply(
    plan: &PurgePlan,
    store: &dyn DraftRetention,
    intent: DestructiveIntent,
    batch_size: i64,
    shutdown: &CancellationToken,
) -> Result<PurgeOutcome, StoreError> {
    let mut outcome = PurgeOutcome::default();
    let batch_size = batch_size.max(1);

    loop {
        if shutdown.is_cancelled() {
            outcome.truncated = true;
            break;
        }
        if outcome.purged as usize >= plan.budget {
            outcome.truncated = plan.budget_bound();
            break;
        }
        let remaining = (plan.budget - outcome.purged as usize) as i64;
        let batch = store
            .expired(plan.cutoff, batch_size.min(remaining))
            .await?;
        if batch.is_empty() {
            break;
        }

        let ids: Vec<_> = batch.iter().map(|draft| draft.draft_id).collect();
        let purged = store.purge(&ids, intent).await?;
        outcome.purged += purged;
        crate::metrics::record_retention_purged(purged);

        // A batch that came back full of rows the DELETE then refused to touch
        // means every one of them was put under legal hold between the two
        // statements — vanishingly unlikely, but the loop would spin on it
        // forever, so it ends the run rather than hanging a CronJob.
        if purged == 0 {
            outcome.truncated = true;
            break;
        }
    }
    Ok(outcome)
}

/// The §18 governance fact this run announces.
///
/// Built from the plan and the outcome so the event and the printed report can
/// never disagree — they are two renderings of one value, not two summaries of
/// one loop. Returned rather than published here: this module computes, and the
/// binary owns the `EventSink` (§1).
pub fn purge_announcement(
    report: &PurgeReport,
    policy: &Policy,
    chain: Chain,
    completed_at: DateTime<Utc>,
) -> Option<EventEnvelope> {
    let outcome = report.outcome.as_ref()?;
    Some(EventEnvelope::new(
        chain,
        DomainEvent::RetentionPurgeCompleted(events::system::RetentionPurgeCompleted {
            store: PURGE_STORE.to_owned(),
            cutoff: report.plan.cutoff.instant(),
            artifact_days: policy.artifact_days(),
            destroyed: outcome.purged,
            held_back: report.plan.held,
            truncated: outcome.truncated,
            completed_at,
        }),
    ))
}

/// The artifact store this service sweeps, as the §18 record names it.
pub const PURGE_STORE: &str = "copilot_drafts";

/// A plan and, if it was carried out, what happened.
///
/// One report type for both paths so `--apply` cannot change what the numbers
/// mean — only whether `outcome` is `Some`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeReport {
    pub plan: PurgePlan,
    pub outcome: Option<PurgeOutcome>,
}

impl PurgeReport {
    pub fn applied(&self) -> bool {
        self.outcome.is_some()
    }

    pub fn purged(&self) -> u64 {
        self.outcome.as_ref().map_or(0, |o| o.purged)
    }
}

impl std::fmt::Display for PurgeReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.plan)?;
        match &self.outcome {
            None => write!(
                f,
                "\n  (dry run — nothing was destroyed; re-run with `--apply` to carry this out)"
            ),
            Some(outcome) => {
                write!(f, "\n  destroyed {} draft(s)", outcome.purged)?;
                if outcome.truncated {
                    write!(f, " — stopped early, more remain; run again")?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use chrono::TimeDelta;
    use events::primitives::IncidentId;
    use llm::cache::CacheKey;

    use super::*;
    use crate::model::{DraftJob, DraftKind, Review};
    use crate::store::LegalHold;
    use crate::store::{DraftAttempt, DraftOutcome, DraftQueue, DraftReview, DraftWorkQueue};
    use crate::test_util::{completion, request, InMemoryDraftStore};

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn intent() -> DestructiveIntent {
        DestructiveIntent::from_operator_flag()
    }

    fn hold(at_instant: DateTime<Utc>) -> LegalHold {
        LegalHold {
            matter: "SUBPOENA-2026-0042".into(),
            placed_at: at_instant,
            placed_by: "compliance@example.test".into(),
        }
    }

    /// Drive a narrative through the real landing path, optionally approving
    /// it, and hand back the stored row.
    ///
    /// The citation is not decoration: the landing boundary blocks a narrative
    /// that cites nothing (§20.4), and a `blocked` draft is not reviewable —
    /// so a fixture without one silently stops exercising the approved path
    /// this module anchors its clock on.
    async fn landed(
        store: &InMemoryDraftStore,
        subject: IncidentId,
        created: DateTime<Utc>,
        reviewed: Option<DateTime<Utc>>,
    ) -> Draft {
        let cited = uuid::Uuid::new_v4();
        let job = DraftJob::narrative(subject, Chain::ETHEREUM);
        let draft_id = store.enqueue(&job, created).await.unwrap().draft_id();
        store
            .claim_batch(
                &[DraftKind::IncidentNarrative],
                1,
                Duration::from_secs(600),
                3,
                created,
            )
            .await
            .unwrap();
        store
            .begin_attempt(
                draft_id,
                &CacheKey::new("claude-opus-5", &request()),
                Some(crate::prompts::incident_narrative()),
                &[cited],
                created,
            )
            .await
            .unwrap();
        store
            .finish(
                draft_id,
                DraftOutcome::Completed(Box::new(completion(&format!(
                    "The attacker front-ran the victim's swap [{cited}]."
                )))),
                created,
            )
            .await
            .unwrap();
        if let Some(reviewed) = reviewed {
            store
                .review(draft_id, Review::Approve, "auditor", None, reviewed)
                .await
                .unwrap();
        }
        store.get(draft_id).await.unwrap().expect("stored")
    }

    // ── the anchor ───────────────────────────────────────────────

    /// The anchor is the *decision*, not the drafting — a narrative approved
    /// six months after it was written is retained from the approval, because
    /// that is the instant a filer's five years starts.
    #[tokio::test]
    async fn a_reviewed_draft_is_anchored_on_the_review() {
        let store = InMemoryDraftStore::default();
        let created = at("2026-01-01T00:00:00Z");
        let reviewed = at("2026-07-01T00:00:00Z");
        let draft = landed(&store, IncidentId::new(), created, Some(reviewed)).await;
        assert_eq!(anchor(&draft), Disposition::at(reviewed));
    }

    #[tokio::test]
    async fn an_unreviewed_draft_is_anchored_on_the_answer() {
        let store = InMemoryDraftStore::default();
        let created = at("2026-01-01T00:00:00Z");
        let draft = landed(&store, IncidentId::new(), created, None).await;
        assert_eq!(anchor(&draft), Disposition::at(created));
    }

    // ── plan / apply ─────────────────────────────────────────────

    /// **The property the previous shape did not have.** The preview and the
    /// deletion are one value: a scan over a backlog larger than a page still
    /// reports the whole backlog, so the number a human approves is the number
    /// that happens.
    #[tokio::test]
    async fn the_plan_reports_the_whole_backlog_not_one_page() {
        let store = Arc::new(InMemoryDraftStore::default());
        let created = at("2020-01-01T00:00:00Z");
        for _ in 0..25 {
            landed(&store, IncidentId::new(), created, None).await;
        }

        let now = at("2026-01-01T00:00:00Z");
        let plan = scan(store.as_ref(), &Policy::default(), now, DEFAULT_MAX_PURGED)
            .await
            .unwrap();

        assert_eq!(plan.due, 25, "the count is complete, the sample is not");
        assert_eq!(plan.sample.len(), DEFAULT_SAMPLE as usize);
        assert!(plan.is_destructive());

        // And applying that same plan destroys exactly what it said.
        let outcome = apply(
            &plan,
            store.as_ref(),
            intent(),
            /* batch_size */ 4,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.purged, 25);
        assert!(!outcome.truncated);
    }

    #[tokio::test]
    async fn a_plan_alone_destroys_nothing() {
        let store = Arc::new(InMemoryDraftStore::default());
        landed(&store, IncidentId::new(), at("2020-01-01T00:00:00Z"), None).await;

        let now = at("2026-01-01T00:00:00Z");
        let plan = scan(store.as_ref(), &Policy::default(), now, DEFAULT_MAX_PURGED)
            .await
            .unwrap();

        assert_eq!(plan.due, 1);
        let report = PurgeReport {
            plan,
            outcome: None,
        };
        assert!(!report.applied());
        assert_eq!(
            store
                .expired(Policy::default().purge_cutoff(now), 10)
                .await
                .unwrap()
                .len(),
            1,
            "still there"
        );
    }

    #[tokio::test]
    async fn applying_destroys_the_expired_draft_and_leaves_the_live_one() {
        let store = Arc::new(InMemoryDraftStore::default());
        let old = landed(&store, IncidentId::new(), at("2020-01-01T00:00:00Z"), None).await;
        let fresh = landed(&store, IncidentId::new(), at("2025-12-01T00:00:00Z"), None).await;

        let now = at("2026-01-01T00:00:00Z");
        let plan = scan(store.as_ref(), &Policy::default(), now, DEFAULT_MAX_PURGED)
            .await
            .unwrap();
        let outcome = apply(
            &plan,
            store.as_ref(),
            intent(),
            DEFAULT_BATCH_SIZE,
            &CancellationToken::new(),
        )
        .await
        .unwrap();

        assert_eq!(outcome.purged, 1);
        assert!(store.get(old.draft_id).await.unwrap().is_none());
        assert!(store.get(fresh.draft_id).await.unwrap().is_some());
    }

    /// The budget bounds one invocation, and the plan says so *before* the run
    /// rather than the report saying so after.
    #[tokio::test]
    async fn the_budget_bounds_one_run_and_the_plan_declares_it() {
        let store = Arc::new(InMemoryDraftStore::default());
        for _ in 0..10 {
            landed(&store, IncidentId::new(), at("2020-01-01T00:00:00Z"), None).await;
        }

        let now = at("2026-01-01T00:00:00Z");
        let plan = scan(store.as_ref(), &Policy::default(), now, 4)
            .await
            .unwrap();
        assert_eq!(plan.due, 10);
        assert_eq!(plan.reachable(), 4);
        assert!(plan.budget_bound());

        let outcome = apply(
            &plan,
            store.as_ref(),
            intent(),
            DEFAULT_BATCH_SIZE,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.purged, 4);
        assert!(outcome.truncated);
    }

    // ── legal hold ───────────────────────────────────────────────

    /// The whole reason a hold exists — and it is a record, not a bit.
    #[tokio::test]
    async fn a_held_draft_survives_its_deadline_and_is_reported() {
        let store = Arc::new(InMemoryDraftStore::default());
        let held = landed(&store, IncidentId::new(), at("2020-01-01T00:00:00Z"), None).await;
        let placed = at("2025-06-01T00:00:00Z");
        store
            .set_legal_hold(held.draft_id, Some(hold(placed)))
            .await
            .unwrap();

        let now = at("2026-01-01T00:00:00Z");
        let plan = scan(store.as_ref(), &Policy::default(), now, DEFAULT_MAX_PURGED)
            .await
            .unwrap();
        assert_eq!(plan.due, 0);
        assert_eq!(plan.held, 1, "an unnoticed hold is a policy nobody keeps");

        let outcome = apply(
            &plan,
            store.as_ref(),
            intent(),
            DEFAULT_BATCH_SIZE,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(outcome.purged, 0);
        assert!(store.get(held.draft_id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn a_hold_carries_its_matter_and_can_be_lifted() {
        let store = Arc::new(InMemoryDraftStore::default());
        let draft = landed(&store, IncidentId::new(), at("2020-01-01T00:00:00Z"), None).await;
        let placed = at("2025-06-01T00:00:00Z");

        let in_force = store
            .set_legal_hold(draft.draft_id, Some(hold(placed)))
            .await
            .unwrap()
            .expect("a hold was placed");
        assert_eq!(in_force.matter, "SUBPOENA-2026-0042");
        assert_eq!(in_force.placed_by, "compliance@example.test");
        assert_eq!(in_force.placed_at, placed);

        assert!(store
            .set_legal_hold(draft.draft_id, None)
            .await
            .unwrap()
            .is_none());
        let now = at("2026-01-01T00:00:00Z");
        let plan = scan(store.as_ref(), &Policy::default(), now, DEFAULT_MAX_PURGED)
            .await
            .unwrap();
        assert_eq!(plan.due, 1, "lifting the hold releases it to the policy");
    }

    // ── the shared deadline ──────────────────────────────────────

    /// A draft one second inside its window is not a candidate — the purge and
    /// the audit share `Policy::is_expired`, so this is also the instant the
    /// audit stops calling missing evidence a violation.
    #[tokio::test]
    async fn the_deadline_is_the_same_instant_for_the_purge_and_the_audit() {
        let store = Arc::new(InMemoryDraftStore::default());
        let created = at("2021-01-01T00:00:00Z");
        let draft = landed(&store, IncidentId::new(), created, None).await;
        let policy = Policy::default();
        let deadline = deadline(&draft, &policy);

        let just_before = deadline - TimeDelta::seconds(1);
        assert!(!is_expired(&draft, &policy, just_before));
        let plan = scan(store.as_ref(), &policy, just_before, DEFAULT_MAX_PURGED)
            .await
            .unwrap();
        assert_eq!(plan.due, 0, "not due yet");

        assert!(is_expired(&draft, &policy, deadline));
        let plan = scan(store.as_ref(), &policy, deadline, DEFAULT_MAX_PURGED)
            .await
            .unwrap();
        assert_eq!(plan.due, 1, "due now");
    }

    // ── the backfill guard ───────────────────────────────────────

    #[test]
    fn a_backfill_inside_the_margin_is_allowed_and_one_outside_is_not() {
        let policy = Policy::default();
        let now = at("2026-09-05T00:00:00Z");
        let earliest = policy.oldest_draftable(now).instant();

        assert_eq!(
            check_backfill_window(Some(earliest), &policy, now),
            Ok(earliest)
        );
        assert_eq!(
            check_backfill_window(Some(earliest - TimeDelta::days(1)), &policy, now),
            Err(WindowTooOld {
                requested: earliest - TimeDelta::days(1),
                earliest,
            })
        );
    }

    /// "The whole archive" is the dangerous default, not the safe one: it
    /// reaches evidence that expires before the narratives written from it.
    #[test]
    fn an_unbounded_backfill_is_refused_and_the_message_names_the_remedy() {
        let policy = Policy::default();
        let now = at("2026-09-05T00:00:00Z");
        let err = check_backfill_window(None, &policy, now).expect_err("refused");
        assert_eq!(err.earliest, policy.oldest_draftable(now).instant());
        assert!(err.to_string().contains("RETENTION_EVIDENCE_MARGIN_DAYS"));
    }

    // ── the governance record ────────────────────────────────────

    /// A destruction is a fact the audit trail carries, not a counter somebody
    /// sampled. The event is built from the same plan the report prints, so the
    /// two cannot disagree about what happened.
    #[tokio::test]
    async fn a_purge_announces_what_it_destroyed() {
        let store = Arc::new(InMemoryDraftStore::default());
        landed(&store, IncidentId::new(), at("2020-01-01T00:00:00Z"), None).await;
        let held_draft = landed(&store, IncidentId::new(), at("2020-01-01T00:00:00Z"), None).await;
        store
            .set_legal_hold(held_draft.draft_id, Some(hold(at("2025-06-01T00:00:00Z"))))
            .await
            .unwrap();

        let policy = Policy::default();
        let now = at("2026-01-01T00:00:00Z");
        let plan = scan(store.as_ref(), &policy, now, DEFAULT_MAX_PURGED)
            .await
            .unwrap();
        let outcome = apply(
            &plan,
            store.as_ref(),
            intent(),
            DEFAULT_BATCH_SIZE,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        let report = PurgeReport {
            plan,
            outcome: Some(outcome),
        };

        let envelope = purge_announcement(&report, &policy, Chain::ETHEREUM, now)
            .expect("an applied run announces");
        match envelope.payload {
            DomainEvent::RetentionPurgeCompleted(fact) => {
                assert_eq!(fact.store, PURGE_STORE);
                assert_eq!(fact.destroyed, 1);
                assert_eq!(fact.held_back, 1, "the hold is on the record too");
                assert_eq!(fact.artifact_days, policy.artifact_days());
                assert_eq!(fact.cutoff, policy.purge_cutoff(now).instant());
                assert!(!fact.truncated);
            }
            other => panic!("expected RetentionPurgeCompleted, got {other:?}"),
        }
    }

    /// A dry run announces nothing: it destroyed nothing, and a record of a
    /// destruction that did not happen is worse than no record.
    #[tokio::test]
    async fn a_plan_announces_nothing() {
        let store = Arc::new(InMemoryDraftStore::default());
        landed(&store, IncidentId::new(), at("2020-01-01T00:00:00Z"), None).await;
        let policy = Policy::default();
        let now = at("2026-01-01T00:00:00Z");
        let plan = scan(store.as_ref(), &policy, now, DEFAULT_MAX_PURGED)
            .await
            .unwrap();
        let report = PurgeReport {
            plan,
            outcome: None,
        };
        assert!(purge_announcement(&report, &policy, Chain::ETHEREUM, now).is_none());
    }
}
