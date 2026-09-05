//! The grounding audit (§20.4) — re-checking landed narratives against the
//! store that is supposed to back them.
//!
//! # What this proves that the landing check does not
//!
//! [`crate::grounding`] runs at landing time and asks: *does this text cite
//! ids from the window we showed the model?* That is the right question then,
//! and it is answered against a `Vec<Uuid>` the worker was holding in memory.
//!
//! This module asks the same question of the same text, months later, against
//! **the event store itself**:
//!
//! ```text
//!   landing:  evaluate(body, window the worker recorded)
//!   audit:    evaluate(body, ids event-store returns for the subject today)
//! ```
//!
//! It is deliberately the *same pure function* with a different second
//! argument — an audit that re-implemented the citation parser would be
//! checking a second parser's opinion of the text, not the platform's. Four
//! things that the landing check structurally cannot catch fall out of it:
//!
//! * **A draft that was never checked at all.** A row with no grounding
//!   summary landed `ready` without the boundary having run — the exact state
//!   §20.4 exists to prevent, whether it came from an older build, a
//!   deployment running with `COPILOT_REQUIRE_GROUNDING=false`, or a landing
//!   path someone added that skipped `write_landing`.
//! * **A citation that no longer resolves.** A deletion, a
//!   replayed-and-rewritten stream, or evidence that expired *early*: the
//!   narrative still reads as verifiable, and is not.
//! * **Drift between the row and the text.** `grounded_event_ids` is what the
//!   reviewer's UI, the `IncidentNarrativeDrafted` event and any downstream
//!   consumer treat as "what this document stands on". If it disagrees with
//!   what the prose actually cites, then one of the two is lying and both are
//!   stored.
//! * **A stream that can no longer answer.** Reported as
//!   [`Verdict::Unverifiable`] rather than as a pass, because "we could not
//!   check" and "we checked and it was fine" are different sentences and only
//!   one of them is true.
//!
//! # The retention policy is what makes an empty stream mean something
//!
//! Until engineering conventions §18 there was no retention decision, and this
//! module could only report an empty stream as *unknown*: a SAR narrative whose
//! evidence was gone might be a policy working as intended or a policy that
//! never existed, and nothing here could tell those apart. That is what the
//! `CopilotGroundingAuditUnverifiable` alert was written against, and it is why
//! the alert said "if retention is the cause, that is a decision to make
//! deliberately".
//!
//! With a [`retention::Policy`] the same observation splits cleanly in two, on
//! one comparison — has this artifact passed the deadline at which the purge
//! would have been allowed to destroy it?
//!
//! ```text
//!   evidence gone, artifact past its deadline   → Expired          (a pass:
//!                                                  retention working, and the
//!                                                  row is only still here
//!                                                  because the purge has not
//!                                                  reached it)
//!   evidence gone, artifact still retained      → EvidenceMissing  (a
//!                                                  FAILURE: the policy says
//!                                                  both halves live, and one
//!                                                  of them does not)
//! ```
//!
//! So `Unverifiable` no longer covers "the evidence is gone" at all — it is
//! left with the cases where *this sweep* could not look (an unreadable stream,
//! a ceiling, a draft with no body), which are operational and not
//! compliance findings. [`Verdict::EvidenceMissing`] is the one the alert
//! points at now, and it means exactly one thing: **the retention policy has
//! been violated.**
//!
//! The audit also reports the violation *before* it happens.
//! [`Finding::evidence_shortfall`] compares the artifact's deadline against the
//! deadline of the oldest event it cites: when a narrative is drafted further
//! back than the policy's margin (a backfill over an old archive, say), it is
//! **already** destined to outlive its evidence, and there is a year of runway
//! in which to raise `RETENTION_EVIDENCE_MARGIN_DAYS` and actually keep it. A
//! draft can be perfectly `Grounded` and at risk at the same time — the two are
//! orthogonal questions ("does it check out today", "will the policy hold for
//! it"), which is why the shortfall is a field and not a verdict.
//!
//! # Why it is a job and not a monitor
//!
//! It reads every landed narrative and one audit stream per narrative. That is
//! a bounded, occasional, *expensive* sweep — a CronJob or a hand-run command
//! before an audit, not something on a request path. It therefore reports
//! through an **exit code and a printed report** first and metrics second: a
//! short-lived process is not reliably scraped, and an audit whose result only
//! exists in a counter nobody sampled has not audited anything.
//!
//! # Paging is a keyset walk, and that is load-bearing
//!
//! The table is being written to while the sweep runs. An `OFFSET` walk
//! re-reads or — worse — *skips* rows every time the newest page shifts, and a
//! grounding audit that silently skips drafts is worse than no grounding audit,
//! because it produces a clean report over an unknown subset. The cursor is a
//! full `(created_at, draft_id)` position ([`DraftCursor`]) for the same
//! reason: a batch enqueue writes many rows in one transaction, and a
//! timestamp-only cursor either loops on those forever or steps over them.

use std::collections::BTreeSet;
use std::sync::Arc;

use ::retention::{Occurrence, Policy};
use chrono::{DateTime, TimeDelta, Utc};
use futures_util::stream::{self, StreamExt};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::audit::{AuditSource, AuditStream};
use crate::grounding::{self, GroundingSummary};
use crate::model::{Draft, DraftId, DraftKind, DraftStatus};
use crate::store::{DraftCursor, DraftFilter, DraftReview, StoreError, MAX_LIST_LIMIT};

/// Default ceiling on drafts examined in one run. Generous, and present so an
/// unattended CronJob against a table with a year of narratives in it finishes.
pub const DEFAULT_MAX_DRAFTS: usize = 10_000;

/// Default drafts read per page.
pub const DEFAULT_PAGE_SIZE: i64 = 100;

/// Default ceiling on findings kept in the report. The counts are always
/// complete; only the per-draft detail is capped, because an operator reading
/// 40,000 findings reads none of them.
pub const DEFAULT_MAX_FINDINGS: usize = 100;

/// Default audit-stream reads in flight. Timid on purpose: the sweep is
/// off every hot path and has hours to finish, while event-store is serving
/// live traffic the whole time it runs.
pub const DEFAULT_CONCURRENCY: usize = 4;

/// Hard ceiling on [`AuditConfig::concurrency`]. A fat-fingered env var is the
/// realistic way this becomes an incident — nobody means to open ten thousand
/// concurrent reads, and the failure would look like event-store falling over
/// rather than like a bad audit.
pub const MAX_CONCURRENCY: usize = 64;

/// **Which drafts a run looks at.** A property of the invocation — an operator
/// narrowing a sweep — which is why it is on the command line and not in the
/// environment.
#[derive(Debug, Clone)]
pub struct AuditScope {
    /// Which statuses to audit. Defaults to the two that matter: `ready` (a
    /// reviewer may still act on it) and `approved` (a human already did, and
    /// the document has left the platform).
    pub statuses: Vec<DraftStatus>,
    /// Only drafts created at or after this instant. `None` audits the whole
    /// table.
    pub since: Option<DateTime<Utc>>,
    pub max_drafts: usize,
}

impl Default for AuditScope {
    fn default() -> Self {
        Self {
            statuses: vec![DraftStatus::Ready, DraftStatus::Approved],
            since: None,
            max_drafts: DEFAULT_MAX_DRAFTS,
        }
    }
}

/// **How hard the run pushes, and how much it prints.** Deployment shape, so
/// these come from the environment: the CronJob passes `args: ["audit"]` and
/// configures the rest through its pod spec.
#[derive(Debug, Clone)]
pub struct AuditLimits {
    pub page_size: i64,
    /// Findings kept in the report. The counts are always complete; only the
    /// per-draft detail is capped, because an operator reading 40,000 findings
    /// reads none of them.
    pub max_findings: usize,
    /// Audit-stream reads in flight at once.
    ///
    /// This fans out onto *another service's* read path, so it is a bulkhead
    /// and not a throughput dial: the ceiling is what keeps a sweep over a
    /// year of narratives from becoming a self-inflicted load test on
    /// event-store while a live worker pool is drafting against it. Resolved
    /// from `COPILOT_AUDIT_CONCURRENCY` and clamped at boot
    /// ([`MAX_CONCURRENCY`]).
    pub concurrency: usize,
    /// Ceiling on events read per subject — the same knob the worker's reads
    /// use, and for the same reason.
    pub max_audit_events: usize,
}

impl Default for AuditLimits {
    fn default() -> Self {
        Self {
            page_size: DEFAULT_PAGE_SIZE,
            max_findings: DEFAULT_MAX_FINDINGS,
            concurrency: DEFAULT_CONCURRENCY,
            max_audit_events: crate::audit::DEFAULT_MAX_EVENTS,
        }
    }
}

/// What one run covers.
///
/// Three fields and not eleven: the previous flat struct mixed *scope* (which
/// drafts), *mechanics* (how hard to push), *presentation* (how much to print)
/// and *policy* (what counts as expired) at one level, so every reader had to
/// re-derive which knobs travelled together. They do not change for the same
/// reasons or come from the same places — scope is an operator's flag, mechanics
/// are a pod spec, policy is a compliance decision — and a struct that says so
/// is the cheapest documentation available.
#[derive(Debug, Clone, Default)]
pub struct AuditConfig {
    pub scope: AuditScope,
    pub limits: AuditLimits,
    /// The regulatory retention policy (engineering conventions §18) — what
    /// turns "this narrative's evidence is gone" from an observation into a
    /// verdict.
    ///
    /// The *same* policy value the purge enforces and event-store's TTL is set
    /// from, resolved from the same environment. An audit holding its own copy
    /// of the window would eventually report violations of a policy nothing
    /// enforces, or miss violations of the one that is.
    pub retention: Policy,
}

/// What the audit concluded about one draft.
///
/// [`Unverifiable`](Verdict::Unverifiable) carries its reason rather than
/// leaving it in a sibling `Option` field: a reason is meaningless on any other
/// verdict, and a struct that can hold `{ verdict: Grounded, reason:
/// Some(StreamTruncated) }` is a struct every reader has to check twice (§4 —
/// make illegal states unrepresentable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Every id the narrative cites resolves in the subject's stream today,
    /// and the row agrees with the text about which ids those are.
    Grounded,
    /// The narrative cites ids the store does not have. **The finding this
    /// whole module exists for.**
    Unresolved,
    /// `grounded_event_ids` and the narrative's own citations disagree. The
    /// text is the document; the column is what every consumer reads instead
    /// of the text.
    Drifted,
    /// The row carries no grounding summary, so the citation boundary never
    /// ran on it. Not "probably fine" — unexamined.
    Unchecked,
    /// **The retention policy has been violated**: the store holds no evidence
    /// for a subject whose artifact is still inside its retention window
    /// (engineering conventions §18).
    ///
    /// Distinct from [`Verdict::Unresolved`] — nothing was fabricated, the
    /// document is exactly as good as the day it was written — and distinct
    /// from [`Verdict::Unverifiable`], because nothing here is unknown: the
    /// store answered, and the answer was "nothing". The two possible causes
    /// are a TTL shorter than the policy and a deletion nobody recorded, and
    /// both are findings.
    EvidenceMissing,
    /// The evidence is gone and the policy allows it: this artifact is past
    /// the deadline at which the purge may destroy it.
    ///
    /// A pass, not a finding — retention doing its job. It is *counted*
    /// nonetheless, because an artifact past its deadline should not still be
    /// in the table: a rising `expired` count is how the platform finds out
    /// that the purge (`copilot retention --apply`) is not running.
    Expired,
    /// The store could not answer for this subject, so nothing was proven
    /// either way — and the reason it could not is part of the verdict.
    ///
    /// Since engineering conventions §18 this covers only cases where *this
    /// sweep* could not look. "The evidence is gone" is no longer one of them;
    /// it is [`Verdict::EvidenceMissing`] or [`Verdict::Expired`].
    Unverifiable(UnverifiableReason),
}

impl Verdict {
    /// A closed metrics label. The *reason* is deliberately not folded in: it
    /// would turn one series into five, and it is already in the report and
    /// the log line.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Grounded => "grounded",
            Verdict::Unresolved => "unresolved",
            Verdict::Drifted => "drifted",
            Verdict::Unchecked => "unchecked",
            Verdict::EvidenceMissing => "evidence_missing",
            Verdict::Expired => "expired",
            Verdict::Unverifiable(_) => "unverifiable",
        }
    }

    /// Whether this verdict is a finding — a stored draft making a claim that
    /// does not hold, or a retention policy that has not been kept.
    ///
    /// [`Verdict::Unverifiable`] deliberately does not count: it means this
    /// sweep could not look, which is an operational fact about the run and not
    /// a fact about the document. [`Verdict::Expired`] does not either — an
    /// artifact past its deadline is retention working, and treating it as a
    /// fabrication is exactly the conflation engineering conventions §18 was
    /// written to end.
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            Verdict::Unresolved | Verdict::Drifted | Verdict::Unchecked | Verdict::EvidenceMissing
        )
    }
}

/// Why a draft could not be verified. A closed set — it goes in the report and
/// in a log line, so it must not be a free-text sentence per draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnverifiableReason {
    /// The ceiling cut the read short, so an id could be beyond it.
    StreamTruncated,
    /// The read itself failed.
    StreamUnreadable,
    /// The draft is `ready`/`approved` but holds no body to check.
    NoBody,
}

impl UnverifiableReason {
    pub fn as_str(self) -> &'static str {
        match self {
            UnverifiableReason::StreamTruncated => "stream_truncated",
            UnverifiableReason::StreamUnreadable => "stream_unreadable",
            UnverifiableReason::NoBody => "no_body",
        }
    }
}

/// One draft's audit result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub draft_id: DraftId,
    pub subject_id: Uuid,
    pub status: DraftStatus,
    pub verdict: Verdict,
    pub claims: usize,
    pub cited_claims: usize,
    /// Ids the narrative cites that the store does not have.
    pub unresolved: Vec<Uuid>,
    /// Ids where the row and the text disagree, in either direction.
    pub drifted: Vec<Uuid>,
    /// How long this artifact is on course to outlive the evidence under it
    /// (engineering conventions §18), if it is.
    ///
    /// `None` is the good case and the common one. `Some(gap)` means the
    /// oldest event this narrative cites expires *before* the narrative may be
    /// destroyed — the document is already destined to become undefendable,
    /// and this is the only window in which anyone can do something about it
    /// (raise `RETENTION_EVIDENCE_MARGIN_DAYS`, which lengthens the evidence
    /// TTL that makes it defendable).
    ///
    /// Orthogonal to [`Finding::verdict`] on purpose: a `Grounded` draft can be
    /// at risk, and usually is when it is.
    pub evidence_shortfall: Option<TimeDelta>,
}

impl Finding {
    /// A verdict reached without anything to count — the draft's identity and
    /// nothing else.
    fn bare(draft: &Draft, verdict: Verdict) -> Self {
        Self {
            draft_id: draft.draft_id,
            subject_id: draft.subject_id,
            status: draft.status,
            verdict,
            claims: 0,
            cited_claims: 0,
            unresolved: Vec::new(),
            drifted: Vec::new(),
            evidence_shortfall: None,
        }
    }

    /// Whether this draft is on course to outlive its own evidence.
    pub fn is_at_risk(&self) -> bool {
        self.evidence_shortfall.is_some()
    }

    /// Whether a human should see this line.
    ///
    /// Wider than [`Verdict::is_failure`] by exactly one case: a draft this
    /// sweep *could not check* is not a finding, but it is the thing an
    /// operator most needs the ids of — "which ones did you skip" is the first
    /// question a clean-looking report invites. Only the two verdicts that
    /// resolve to "this is fine" stay silent: `Grounded`, and `Expired` (an
    /// artifact the policy released, whose count is the signal, not its rows).
    fn is_reportable(&self) -> bool {
        !matches!(self.verdict, Verdict::Grounded | Verdict::Expired) || self.is_at_risk()
    }

    fn unverifiable(draft: &Draft, reason: UnverifiableReason) -> Self {
        Self::bare(draft, Verdict::Unverifiable(reason))
    }

    /// Why this draft could not be checked, if that is what happened.
    pub fn unverifiable_reason(&self) -> Option<UnverifiableReason> {
        match self.verdict {
            Verdict::Unverifiable(reason) => Some(reason),
            _ => None,
        }
    }
}

/// One line, for the report and for a log — `Display` rather than a
/// `describe()` method so a finding can go straight into `format!`, a
/// `tracing` field, or a collected report without three renderings of the
/// same thing drifting apart.
impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} draft={} subject={} status={} claims={}/{}",
            self.verdict.as_str(),
            self.draft_id,
            self.subject_id,
            self.status.as_wire_str(),
            self.cited_claims,
            self.claims,
        )?;
        if let Some(reason) = self.unverifiable_reason() {
            write!(f, " reason={}", reason.as_str())?;
        }
        if !self.unresolved.is_empty() {
            write!(f, " unresolved=[{}]", render(&self.unresolved))?;
        }
        if !self.drifted.is_empty() {
            write!(f, " drifted=[{}]", render(&self.drifted))?;
        }
        if let Some(gap) = self.evidence_shortfall {
            write!(f, " outlives-its-evidence-by={}d", gap.num_days())?;
        }
        Ok(())
    }
}

fn render(ids: &[Uuid]) -> String {
    ids.iter()
        .take(5)
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// What a whole run found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditReport {
    pub examined: usize,
    pub grounded: usize,
    pub unresolved: usize,
    pub drifted: usize,
    pub unchecked: usize,
    /// **Retention violations**: artifacts still under retention whose evidence
    /// the store no longer has.
    pub evidence_missing: usize,
    /// Artifacts past their own deadline whose evidence has legitimately gone.
    /// A pass — but see [`Verdict::Expired`]: a rising number here means the
    /// purge is not running.
    pub expired: usize,
    pub unverifiable: usize,
    /// Drafts on course to outlive their evidence — counted independently of
    /// the verdict, because most of them check out today.
    pub at_risk: usize,
    /// Distinct cited ids that did not resolve, summed over drafts.
    pub unresolved_ids: usize,
    /// Lines worth a human's attention — every failure, plus every draft whose
    /// evidence will expire before it does — capped at `max_findings`.
    pub findings: Vec<Finding>,
    /// Findings the cap dropped. The *counts* above are always complete.
    pub omitted_findings: usize,
    /// Whether the run stopped early on a shutdown signal — the counts then
    /// describe a prefix of the table, not the table.
    pub interrupted: bool,
}

/// A run's overall answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Everything examined checks out.
    Clean,
    /// At least one stored draft makes a claim that does not hold.
    Findings,
    /// Drafts were examined and none of them could be verified — the store
    /// could not answer. **Not a pass:** an audit that proved nothing must not
    /// exit like one that proved everything.
    Inconclusive,
}

impl AuditReport {
    /// Fold one finding in.
    ///
    /// **Pure**: it counts, it does not emit. The §19 counters are the
    /// *runner's* job ([`GroundingAuditor::run`]), for the same reason
    /// [`crate::capability::Landing`] carries its rejection reason instead of
    /// counting it — a fold that also increments a counter cannot be used to
    /// ask a hypothetical ("what would a stricter reading have found over this
    /// same set of findings"), and it makes every unit test that builds a
    /// report emit production metrics as a side effect.
    fn record(&mut self, finding: Finding, max_findings: usize) {
        self.examined += 1;
        match finding.verdict {
            Verdict::Grounded => self.grounded += 1,
            Verdict::Unresolved => self.unresolved += 1,
            Verdict::Drifted => self.drifted += 1,
            Verdict::Unchecked => self.unchecked += 1,
            Verdict::EvidenceMissing => self.evidence_missing += 1,
            Verdict::Expired => self.expired += 1,
            Verdict::Unverifiable(_) => self.unverifiable += 1,
        }
        self.unresolved_ids += finding.unresolved.len();
        if finding.is_at_risk() {
            self.at_risk += 1;
        }

        if !finding.is_reportable() {
            return;
        }
        if self.findings.len() < max_findings {
            self.findings.push(finding);
        } else {
            self.omitted_findings += 1;
        }
    }

    pub fn outcome(&self) -> Outcome {
        if self.unresolved + self.drifted + self.unchecked + self.evidence_missing > 0 {
            Outcome::Findings
        // `grounded + expired`, not `grounded`: a sweep over an archive the
        // retention policy has caught up with proved something about every
        // draft in it — that each one was released — and exiting `2` there
        // would make a correct, quiet result look like an event-store outage.
        // At-risk drafts deliberately do not change the exit code: a shortfall
        // is a future violation with a year of runway, and a weekly job that
        // goes red for it teaches an operator to ignore red.
        } else if self.examined > 0 && self.grounded + self.expired == 0 {
            Outcome::Inconclusive
        } else {
            Outcome::Clean
        }
    }

    /// Whether every draft the run could check, checked out.
    pub fn is_clean(&self) -> bool {
        self.outcome() == Outcome::Clean
    }
}

/// The printed report — what `copilot audit` writes to stdout and what a
/// failed CronJob leaves in its pod log.
impl std::fmt::Display for AuditReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "grounding audit: examined {}, grounded {}, unresolved {}, drifted {}, \
             unchecked {}, evidence-missing {}, expired {}, unverifiable {} \
             ({} unresolved event id(s), {} draft(s) on course to outlive their evidence)",
            self.examined,
            self.grounded,
            self.unresolved,
            self.drifted,
            self.unchecked,
            self.evidence_missing,
            self.expired,
            self.unverifiable,
            self.unresolved_ids,
            self.at_risk,
        )?;
        if self.interrupted {
            write!(
                f,
                "\n  ! interrupted: these counts cover only part of the table"
            )?;
        }
        for finding in &self.findings {
            write!(f, "\n  {finding}")?;
        }
        if self.omitted_findings > 0 {
            write!(
                f,
                "\n  … and {} more (raise --max-findings to see them)",
                self.omitted_findings
            )?;
        }
        Ok(())
    }
}

/// Sweeps landed narratives and re-resolves their citations against the store.
///
/// Holds the two read seams and nothing else: no writes, no model, no clock of
/// its own. An audit that could change what it audits is not an audit.
#[derive(Debug)]
pub struct GroundingAuditor {
    drafts: Arc<dyn DraftReview>,
    events: Arc<dyn AuditSource>,
    config: AuditConfig,
}

impl GroundingAuditor {
    pub fn new(
        drafts: Arc<dyn DraftReview>,
        events: Arc<dyn AuditSource>,
        config: AuditConfig,
    ) -> Self {
        Self {
            drafts,
            events,
            config,
        }
    }

    /// Walk the landed narratives and check every one.
    ///
    /// Each status is walked separately, so a draft that a reviewer approves
    /// *while* the sweep is running can be examined twice — once in the `ready`
    /// walk and once in the `approved` one. That is a counting artifact of a
    /// live table and not a correctness problem: the second look reaches the
    /// same verdict, and the alternative (a snapshot) would mean holding a
    /// transaction open across thousands of HTTP reads.
    ///
    /// A failed audit-stream read is a per-draft [`Verdict::Unverifiable`],
    /// not an aborted run: one 500 from event-store must not throw away the
    /// findings from the ten thousand drafts that did resolve. A run in which
    /// *nothing* resolved is caught by [`Outcome::Inconclusive`] instead —
    /// which is the shape this should fail in, since "event-store is down" and
    /// "one incident expired" are the same error and different situations.
    ///
    /// `now` is passed in and not read from the clock. It is the input to every
    /// retention judgement this sweep makes ("is this artifact still under
    /// retention?"), and a sweep that took its own reading would be one whose
    /// verdicts cannot be reproduced — which is not a property an audit is
    /// allowed to lack.
    pub async fn run(
        &self,
        now: DateTime<Utc>,
        shutdown: &CancellationToken,
    ) -> Result<AuditReport, StoreError> {
        let mut report = AuditReport::default();
        // Clamped once, and compared against once: a page-size above the
        // store's own ceiling would come back short of what was asked for, and
        // "a short page means the end" would then stop the walk on its first
        // full page.
        let page_size = self.config.limits.page_size.clamp(1, MAX_LIST_LIMIT);
        // Clamped here as well as at boot: `buffered(0)` is a stream that
        // never yields, which would be an audit that hangs rather than one
        // that reports — the worst possible way for a governance job to fail.
        let concurrency = self.config.limits.concurrency.clamp(1, MAX_CONCURRENCY);

        for status in &self.config.scope.statuses {
            let mut cursor: Option<DraftCursor> = None;
            loop {
                if shutdown.is_cancelled() || report.examined >= self.config.scope.max_drafts {
                    report.interrupted = shutdown.is_cancelled();
                    return Ok(report);
                }
                let page = self
                    .drafts
                    .list(&DraftFilter {
                        status: Some(*status),
                        // The only kind that makes citable claims: a rule
                        // draft's boundary is the compiler, and it is checked
                        // where it is applied.
                        kind: Some(DraftKind::IncidentNarrative),
                        source: None,
                        subject_id: None,
                        before: cursor,
                        limit: page_size,
                    })
                    .await?;
                let Some(last) = page.last() else { break };
                cursor = Some(DraftCursor::after(last));

                let reached_window_start = self
                    .config
                    .scope
                    .since
                    .is_some_and(|since| last.created_at < since);

                // The page's drafts, narrowed to the window and to what is
                // left of this run's budget, before any I/O is started.
                let remaining = self.config.scope.max_drafts.saturating_sub(report.examined);
                let batch: Vec<&Draft> = page
                    .iter()
                    .filter(|draft| {
                        self.config
                            .scope
                            .since
                            .is_none_or(|since| draft.created_at >= since)
                    })
                    .take(remaining)
                    .collect();

                // One audit-stream read per draft, `concurrency` at a time.
                // Serially, a table with a year of narratives in it takes
                // longer than the CronJob's own deadline; unbounded, this
                // becomes a self-inflicted load test on event-store. Bounded
                // fan-out is the same shape `simulation::exposure_report`
                // uses, with one deliberate difference below.
                //
                // `buffered`, not `buffer_unordered`: findings stay in walk
                // order, which is chronological, which is what makes the
                // printed report readable by a human going down a list.
                let mut examined = stream::iter(batch.into_iter().map(|d| self.examine(d, now)))
                    .buffered(concurrency);

                loop {
                    tokio::select! {
                        // Cancellation wins a tie: dropping `examined` aborts
                        // the in-flight reads, which is safe *here* precisely
                        // because this sweep writes nothing. The wallet
                        // exposure report drains its page instead — it
                        // publishes per item, so abandoning one loses work.
                        // An audit abandons nothing but its own answer.
                        biased;
                        () = shutdown.cancelled() => {
                            report.interrupted = true;
                            return Ok(report);
                        }
                        next = examined.next() => {
                            let Some(finding) = next else { break };
                            if finding.verdict.is_failure() {
                                // Logged as well as reported: an audit's
                                // findings should also land wherever this
                                // deployment's logs are read.
                                tracing::warn!(
                                    draft_id = %finding.draft_id,
                                    subject_id = %finding.subject_id,
                                    verdict = finding.verdict.as_str(),
                                    "grounding audit finding: {finding}"
                                );
                            }
                            // §19 lives here and not in the fold: `record` is
                            // a pure accumulator (see its docs).
                            crate::metrics::record_grounding_audit(
                                finding.verdict.as_str(),
                                finding.unresolved.len(),
                                finding.is_at_risk(),
                            );
                            report.record(finding, self.config.limits.max_findings);
                        }
                    }
                }

                // The walk is newest-first, so once a page ends before the
                // window there is nothing older to find.
                if reached_window_start || page.len() < page_size as usize {
                    break;
                }
            }
        }
        Ok(report)
    }

    /// Check one draft: read the subject's stream, then decide.
    ///
    /// The I/O shell (§1). Everything that is a *judgement* lives in
    /// [`verdict_for`], which is pure — so the precedence between "the stream
    /// was cut short", "an id does not resolve" and "the row disagrees with
    /// the prose" (the part most likely to be got wrong by a later edit) is
    /// testable with no async, no store and no HTTP double.
    async fn examine(&self, draft: &Draft, now: DateTime<Utc>) -> Finding {
        // Decided before any read: no answer to check, or a row the boundary
        // never ran on. No stream response would change either.
        if draft.body().is_none() {
            return Finding::unverifiable(draft, UnverifiableReason::NoBody);
        }
        if draft.grounding.is_none() {
            return Finding::bare(draft, Verdict::Unchecked);
        }

        let stream = match self
            .events
            .audit_stream(
                events::primitives::IncidentId(draft.subject_id),
                self.config.limits.max_audit_events,
            )
            .await
        {
            Ok(stream) => stream,
            Err(err) => {
                tracing::warn!(
                    draft_id = %draft.draft_id,
                    subject_id = %draft.subject_id,
                    error = %err,
                    "grounding audit could not read the subject's stream"
                );
                return Finding::unverifiable(draft, UnverifiableReason::StreamUnreadable);
            }
        };
        verdict_for(draft, &stream, &self.config.retention, now)
    }
}

/// **The judgement.** Pure and total: a draft, the stream the store answers
/// with today, the retention policy, and the instant to judge them at.
///
/// Public because it is the reusable half — a dry run, a threshold sweep, or a
/// future "what would this find" endpoint asks exactly this question and must
/// not have to fetch, spawn, or count anything to ask it. Passing the policy
/// and the clock in rather than reading either is what lets a test state
/// "one second before this artifact's deadline" as a value.
///
/// The precedence is deliberate and is the whole subtlety of the module:
///
/// 1. **An empty stream** is not a wall of fabrications, and since engineering
///    conventions §18 it is not an unknown either: past the artifact's deadline
///    it is [`Verdict::Expired`] (retention working), and inside the window it
///    is [`Verdict::EvidenceMissing`] — the policy violated.
/// 2. **A past-deadline artifact whose citations no longer all resolve** is
///    `Expired` too, for the same reason: partial expiry of a record the purge
///    was already entitled to destroy is retention, not fabrication. The row
///    being here at all says the purge has not caught up, which the `expired`
///    count is what surfaces. It outranks a drift finding on the same row the
///    way `Unresolved` does — the more fundamental observation wins, and this
///    one is about a row the purge may delete before anybody reads the report.
/// 3. **A truncated stream with unresolved ids** is unverifiable — the ceiling
///    cannot be distinguished from a deletion, and guessing in the accusing
///    direction is how a safety check earns a reputation for crying wolf. A
///    truncated stream where everything *did* resolve is still a perfectly good
///    pass.
/// 4. **Unresolved** outranks **drifted**: if an id does not exist, that is the
///    sentence to put in front of a human, not the bookkeeping disagreement
///    that comes with it.
///
/// The shortfall is computed independently of all four (see
/// [`Finding::evidence_shortfall`]) — it is a statement about the future, and
/// every verdict above except the ones with no stream to measure can carry one.
pub fn verdict_for(
    draft: &Draft,
    stream: &AuditStream,
    policy: &Policy,
    now: DateTime<Utc>,
) -> Finding {
    let Some(body) = draft.body() else {
        return Finding::unverifiable(draft, UnverifiableReason::NoBody);
    };
    if draft.grounding.is_none() {
        return Finding::bare(draft, Verdict::Unchecked);
    }

    // The one comparison the whole retention half turns on — and it is the
    // *purge's* comparison, through the same `Policy::is_expired`, so there is
    // no instant at which this module holds a draft to a live artifact's
    // standard that the purge would already have been allowed to delete.
    let released = crate::retention::is_expired(draft, policy, now);

    if stream.is_empty() {
        let verdict = if released {
            Verdict::Expired
        } else {
            Verdict::EvidenceMissing
        };
        return Finding::bare(draft, verdict);
    }

    // The landing check, re-run with the store in place of the window the
    // worker held. `unknown_event_ids` therefore means "cited, and the store
    // does not have it" — which is exactly the audit's question.
    let summary = grounding::evaluate(body, &stream.event_ids());
    let drifted = drift(draft, &summary);

    // Measured over the ids the narrative *cites*, since those are the events
    // it cannot be defended without; the oldest is the first to expire and so
    // the one that decides.
    let cited: BTreeSet<Uuid> = summary.cited_event_ids.iter().copied().collect();
    let evidence_shortfall = stream
        .earliest_occurrence_of(&cited)
        .map(Occurrence::at)
        .and_then(|oldest| policy.shortfall(crate::retention::anchor(draft), oldest));

    let verdict = if released && !summary.unknown_event_ids.is_empty() {
        Verdict::Expired
    } else if stream.truncated && !summary.unknown_event_ids.is_empty() {
        Verdict::Unverifiable(UnverifiableReason::StreamTruncated)
    } else if !summary.unknown_event_ids.is_empty() {
        Verdict::Unresolved
    } else if !drifted.is_empty() {
        Verdict::Drifted
    } else {
        Verdict::Grounded
    };

    Finding {
        claims: summary.claims,
        cited_claims: summary.cited_claims,
        // An expired artifact's missing citations are retention, not a finding:
        // listing them would put ids in front of a human as though they were
        // fabrications.
        unresolved: if verdict == Verdict::Expired {
            Vec::new()
        } else {
            summary.unknown_event_ids
        },
        drifted,
        evidence_shortfall,
        ..Finding::bare(draft, verdict)
    }
}

/// Ids the row and the text disagree about, in either direction.
///
/// The landing narrows `grounded_event_ids` to what the narrative cites, so on
/// a correctly-landed draft these two sets are *equal*. A symmetric difference
/// therefore means one of two things, and both are worth a look: the column
/// claims grounding the prose does not assert (a draft landed before the
/// narrowing, or by a path that skipped it), or the prose cites what the column
/// omits (the reviewer's UI and the drafting event are understating what the
/// document rests on).
fn drift(draft: &Draft, summary: &GroundingSummary) -> Vec<Uuid> {
    let stored: BTreeSet<Uuid> = draft.grounded_event_ids.iter().copied().collect();
    let cited: BTreeSet<Uuid> = summary
        .cited_event_ids
        .iter()
        .chain(summary.unknown_event_ids.iter())
        .copied()
        .collect();
    stored.symmetric_difference(&cited).copied().collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use events::primitives::{Chain, IncidentId};
    use llm::cache::CacheKey;

    use super::*;
    use crate::audit::VecAuditSource;
    use crate::model::DraftJob;
    use crate::store::{DraftAttempt, DraftOutcome, DraftQueue, DraftWorkQueue};
    use crate::test_util::{completion, envelope, request, FailingAuditSource, InMemoryDraftStore};

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    /// Drive one narrative through the real landing path — enqueue, claim,
    /// declare the window, land the answer. Building the row by hand would
    /// audit a fixture; this audits what the service actually writes.
    async fn landed(store: &InMemoryDraftStore, subject: IncidentId, window: &[Uuid], text: &str) {
        let job = DraftJob::narrative(subject, Chain::ETHEREUM);
        let draft_id = store
            .enqueue(&job, now())
            .await
            .expect("enqueue")
            .draft_id();
        store
            .claim_batch(
                &[DraftKind::IncidentNarrative],
                1,
                Duration::from_secs(600),
                3,
                now(),
            )
            .await
            .expect("claim");
        store
            .begin_attempt(
                draft_id,
                &CacheKey::new("claude-opus-5", &request()),
                Some(crate::prompts::incident_narrative()),
                window,
                now(),
            )
            .await
            .expect("attempt");
        store
            .finish(
                draft_id,
                DraftOutcome::Completed(Box::new(completion(text))),
                now(),
            )
            .await
            .expect("finish");
    }

    fn auditor(store: Arc<InMemoryDraftStore>, events: VecAuditSource) -> GroundingAuditor {
        GroundingAuditor::new(store, Arc::new(events), AuditConfig::default())
    }

    /// The same, over any [`AuditSource`] — the unreadable-stream case needs a
    /// double that fails rather than one that answers with nothing, which is
    /// precisely the distinction the retention policy made meaningful.
    fn auditor_with(
        store: Arc<InMemoryDraftStore>,
        events: Arc<dyn AuditSource>,
        config: AuditConfig,
    ) -> GroundingAuditor {
        GroundingAuditor::new(store, events, config)
    }

    /// A landed draft, built as a value — no store, no async, no doubles.
    ///
    /// The point of [`verdict_for`] being pure is that the precedence rules
    /// below can be stated without any of that machinery. Building the row by
    /// hand is what makes them *rules* rather than observations about whatever
    /// the in-memory store happens to write.
    fn landed_draft(body: &str, grounded: Vec<Uuid>) -> Draft {
        Draft {
            draft_id: DraftId::new(),
            kind: DraftKind::IncidentNarrative,
            subject_id: Uuid::new_v4(),
            customer_id: None,
            chain: Chain::ETHEREUM,
            source: crate::model::DraftSource::Live,
            source_text: None,
            status: DraftStatus::Ready,
            attempts: 1,
            provenance: Some(crate::model::Provenance {
                prompt_id: "incident_narrative@v2".into(),
                prompt_digest: "0".repeat(64),
            }),
            answer: Some(crate::model::DraftAnswer {
                body: body.to_owned(),
                model: "claude-opus-5".into(),
                stop_reason: llm::StopReason::EndTurn,
                usage: llm::TokenUsage::default(),
                completed_at: now(),
            }),
            review: None,
            grounded_event_ids: grounded,
            // Present, so the draft counts as one the boundary *did* run on.
            grounding: Some(GroundingSummary::default()),
            batch_id: None,
            last_error: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn stream(events: Vec<events::EventEnvelope>, truncated: bool) -> AuditStream {
        AuditStream {
            incident_id: None,
            events,
            truncated,
        }
    }

    #[test]
    fn only_a_stored_claim_that_does_not_hold_fails_the_audit() {
        // The distinction the exit code rests on. Note where the retention
        // policy put the line: evidence gone *inside* the window is a finding
        // (the policy was violated); evidence gone *after* the window is not
        // (the policy was kept); and "this sweep could not look" is neither.
        assert!(Verdict::Unresolved.is_failure());
        assert!(Verdict::Drifted.is_failure());
        assert!(Verdict::Unchecked.is_failure());
        assert!(Verdict::EvidenceMissing.is_failure());
        assert!(!Verdict::Expired.is_failure());
        assert!(!Verdict::Unverifiable(UnverifiableReason::StreamUnreadable).is_failure());
        assert!(!Verdict::Grounded.is_failure());
    }

    /// A narrative that cites what the store still holds — the shape every
    /// other test is a deviation from.
    #[tokio::test]
    async fn a_narrative_whose_citations_all_resolve_is_clean() {
        let subject = IncidentId::new();
        let event = envelope(0);
        let store = Arc::new(InMemoryDraftStore::default());
        landed(
            &store,
            subject,
            &[event.event_id],
            &format!(
                "The attacker's transaction preceded the victim's swap in the same block [{}].",
                event.event_id
            ),
        )
        .await;

        let report = auditor(store, VecAuditSource::new(subject, vec![event]))
            .run(now(), &CancellationToken::new())
            .await
            .expect("the sweep reads");

        assert_eq!((report.examined, report.grounded), (1, 1));
        assert!(report.findings.is_empty());
        assert_eq!(report.outcome(), Outcome::Clean);
    }

    /// The audit's own reason to exist: the citation resolved against the
    /// window when the draft landed, and does not resolve against the store
    /// now.
    #[tokio::test]
    async fn a_citation_the_store_no_longer_holds_is_a_finding() {
        let subject = IncidentId::new();
        let kept = envelope(0);
        let gone = envelope(1);
        let store = Arc::new(InMemoryDraftStore::default());
        landed(
            &store,
            subject,
            &[kept.event_id, gone.event_id],
            &format!(
                "The attacker front-ran the victim's swap [{}]. \
                 The funds were later moved through a mixer [{}].",
                kept.event_id, gone.event_id
            ),
        )
        .await;

        // The stream event-store answers with today has lost one of the two.
        let report = auditor(store, VecAuditSource::new(subject, vec![kept]))
            .run(now(), &CancellationToken::new())
            .await
            .expect("the sweep reads");

        assert_eq!(report.examined, 1);
        assert_eq!(report.unresolved, 1);
        assert_eq!(report.unresolved_ids, 1);
        assert_eq!(report.findings[0].unresolved, vec![gone.event_id]);
        assert_eq!(report.findings[0].verdict, Verdict::Unresolved);
        assert_eq!(report.outcome(), Outcome::Findings);
        assert!(
            report.to_string().contains(&gone.event_id.to_string()),
            "the report must name *which* id: {report}"
        );
    }

    /// **The one the brief is about.** Before there was a retention policy,
    /// an empty stream could only be reported as "unverifiable" — the audit
    /// could see that a SAR narrative's evidence was gone and had nothing to
    /// say about whether that was allowed. It is now a *decided* answer, and
    /// this is the side of the decision that is a violation: the artifact is
    /// still inside its five-year window, so the record was supposed to be
    /// there.
    #[tokio::test]
    async fn evidence_gone_while_the_artifact_is_still_retained_is_a_violation() {
        let subject = IncidentId::new();
        let event = envelope(0);
        let store = Arc::new(InMemoryDraftStore::default());
        landed(
            &store,
            subject,
            &[event.event_id],
            &format!(
                "The victim's swap executed at a worse price [{}].",
                event.event_id
            ),
        )
        .await;

        // event-store has nothing for this incident any more, and the draft
        // was written moments ago.
        let report = auditor(store, VecAuditSource::default())
            .run(now(), &CancellationToken::new())
            .await
            .expect("the sweep reads");

        assert_eq!(report.evidence_missing, 1);
        assert_eq!(report.expired, 0);
        assert_eq!(
            report.unresolved, 0,
            "a missing stream is not a fabrication — the document is unchanged"
        );
        assert_eq!(report.findings[0].verdict, Verdict::EvidenceMissing);
        assert_eq!(
            report.outcome(),
            Outcome::Findings,
            "a retention violation is a finding, not an inconclusive run"
        );
        assert!(!report.is_clean());
    }

    /// The other side of the same decision: past the deadline at which the
    /// purge may destroy this artifact, its evidence being gone is retention
    /// *working*. Reporting it as a finding would make every released record
    /// look like a fabrication — the conflation the policy exists to end.
    #[tokio::test]
    async fn evidence_gone_after_the_artifact_was_released_is_not_a_finding() {
        let subject = IncidentId::new();
        let event = envelope(0);
        let store = Arc::new(InMemoryDraftStore::default());
        landed(
            &store,
            subject,
            &[event.event_id],
            &format!(
                "The victim's swap executed at a worse price [{}].",
                event.event_id
            ),
        )
        .await;

        let policy = Policy::default();
        // One day after the purge would have been entitled to delete it.
        let later = now() + TimeDelta::days(i64::from(policy.artifact_days()) + 1);
        let report = auditor(store, VecAuditSource::default())
            .run(later, &CancellationToken::new())
            .await
            .expect("the sweep reads");

        assert_eq!(report.expired, 1);
        assert_eq!(report.evidence_missing, 0);
        assert!(report.findings.is_empty());
        assert_eq!(
            report.outcome(),
            Outcome::Clean,
            "an archive the policy has caught up with is a clean sweep, not an \
             inconclusive one"
        );
    }

    /// A stream that could not be *read* is still neither: nothing about the
    /// document was established, and event-store being down must not be
    /// reported as five thousand compliance violations.
    #[tokio::test]
    async fn a_stream_the_sweep_could_not_read_is_unverifiable() {
        let subject = IncidentId::new();
        let event = envelope(0);
        let store = Arc::new(InMemoryDraftStore::default());
        landed(
            &store,
            subject,
            &[event.event_id],
            &format!("The victim's swap executed [{}].", event.event_id),
        )
        .await;

        let report = auditor_with(
            store,
            Arc::new(FailingAuditSource::permanent()),
            AuditConfig::default(),
        )
        .run(now(), &CancellationToken::new())
        .await
        .expect("the sweep reads");

        assert_eq!(report.unverifiable, 1);
        assert_eq!(report.evidence_missing, 0, "unreadable is not missing");
        assert_eq!(
            report.findings[0].verdict,
            Verdict::Unverifiable(UnverifiableReason::StreamUnreadable),
        );
        assert_eq!(
            report.outcome(),
            Outcome::Inconclusive,
            "an audit that proved nothing must not exit like one that proved everything"
        );
    }

    /// Drift: the column every consumer reads disagrees with the document.
    /// Built by mutating the row *after* it landed, which is exactly the
    /// situation the check exists to notice — a second writer, an older build,
    /// or a landing path that skipped the narrowing.
    #[tokio::test]
    async fn a_row_that_disagrees_with_its_own_text_is_a_finding() {
        let subject = IncidentId::new();
        let cited = envelope(0);
        let extra = envelope(1);
        let store = Arc::new(InMemoryDraftStore::default());
        landed(
            &store,
            subject,
            &[cited.event_id],
            &format!("The two transactions shared a block [{}].", cited.event_id),
        )
        .await;

        let draft = store.drafts().pop().expect("one draft");
        let mut drifted = draft.clone();
        // The column now claims grounding the prose does not assert.
        drifted.grounded_event_ids = vec![cited.event_id, extra.event_id];

        let extra_id = extra.event_id;
        let events = VecAuditSource::new(subject, vec![cited, extra]);
        let auditor = GroundingAuditor::new(
            Arc::new(InMemoryDraftStore::default()),
            Arc::new(events),
            AuditConfig::default(),
        );
        let finding = auditor.examine(&drifted, now()).await;

        assert_eq!(finding.verdict, Verdict::Drifted);
        assert_eq!(finding.drifted, vec![extra_id]);
        assert!(finding.unresolved.is_empty(), "both ids are in the store");
    }

    /// A `ready` narrative with no grounding summary never went through the
    /// boundary at all — the one state §20.4 exists to prevent, and the one
    /// the landing check by definition cannot report on.
    #[tokio::test]
    async fn a_draft_the_boundary_never_ran_on_is_a_finding() {
        let subject = IncidentId::new();
        let event = envelope(0);
        let store = Arc::new(InMemoryDraftStore::default());
        landed(
            &store,
            subject,
            &[event.event_id],
            &format!("The swap was sandwiched [{}].", event.event_id),
        )
        .await;

        let mut unchecked = store.drafts().pop().expect("one draft");
        unchecked.grounding = None;

        let auditor = GroundingAuditor::new(
            Arc::new(InMemoryDraftStore::default()),
            Arc::new(VecAuditSource::new(subject, vec![event])),
            AuditConfig::default(),
        );
        let finding = auditor.examine(&unchecked, now()).await;
        assert_eq!(finding.verdict, Verdict::Unchecked);
        assert!(finding.verdict.is_failure());
    }

    /// The two directions of drift, both meaning the row and the document
    /// disagree about what the document rests on.
    #[tokio::test]
    async fn drift_is_symmetric() {
        let store = Arc::new(InMemoryDraftStore::default());
        let subject = IncidentId::new();
        let event = envelope(0);
        landed(
            &store,
            subject,
            &[event.event_id],
            &format!("The two transactions shared a block [{}].", event.event_id),
        )
        .await;
        let mut draft = store.drafts().pop().expect("one draft");
        draft.grounded_event_ids = vec![Uuid::from_u128(1), Uuid::from_u128(2)];

        let summary = GroundingSummary {
            claims: 1,
            cited_claims: 1,
            cited_event_ids: vec![Uuid::from_u128(2), Uuid::from_u128(3)],
            unknown_event_ids: Vec::new(),
        };
        assert_eq!(
            drift(&draft, &summary),
            vec![Uuid::from_u128(1), Uuid::from_u128(3)],
            "an id the column omits is as much a disagreement as one it invents"
        );
    }

    /// The counts are the audit; the per-draft detail is a convenience, and
    /// only the convenience is capped.
    /// The leading indicator. A narrative drafted over evidence older than the
    /// policy's margin — a backfill reaching into the archive is how this
    /// happens — is *already* destined to outlive the record under it, years
    /// before the audit could observe the evidence actually gone. It checks out
    /// today, which is why the shortfall is a field and not a verdict.
    #[test]
    fn a_draft_that_will_outlive_its_evidence_is_flagged_while_it_still_checks_out() {
        let policy = Policy::default();
        // Two years back: a year past the margin.
        let occurred = now() - TimeDelta::days(730);
        let old = events::EventEnvelope::with_metadata(
            Uuid::from_u128(7),
            occurred,
            Chain::ETHEREUM,
            events::DomainEvent::BlockFinalized(events::chain::BlockFinalized {
                block: events::primitives::BlockRef::new(7, Default::default()),
            }),
        );
        let draft = landed_draft(
            &format!("The victim's swap was front-run [{}].", old.event_id),
            vec![old.event_id],
        );

        let finding = verdict_for(&draft, &stream(vec![old], false), &policy, now());

        assert_eq!(
            finding.verdict,
            Verdict::Grounded,
            "it resolves against the store today — that is the point"
        );
        assert_eq!(
            finding.evidence_shortfall,
            Some(TimeDelta::days(730 - 365)),
            "and it is still short by every day the drafting lag exceeded the margin"
        );
        assert!(finding.is_at_risk());
        assert!(
            finding
                .to_string()
                .contains("outlives-its-evidence-by=365d"),
            "the operator has to be told the number: {finding}"
        );
    }

    /// At risk is not a failure, and must not fail the job — there is a year of
    /// runway in which raising the margin actually fixes it, and a weekly
    /// CronJob that goes red for a future problem teaches an operator to ignore
    /// red. It still has to reach the printed report.
    #[test]
    fn an_at_risk_draft_is_reported_without_changing_the_exit_code() {
        let mut report = AuditReport::default();
        report.record(
            Finding {
                evidence_shortfall: Some(TimeDelta::days(10)),
                ..Finding::bare(&landed_draft("A sentence.", vec![]), Verdict::Grounded)
            },
            10,
        );

        assert_eq!(report.grounded, 1);
        assert_eq!(report.at_risk, 1);
        assert_eq!(report.findings.len(), 1, "it has to be named somewhere");
        assert_eq!(report.outcome(), Outcome::Clean);
    }

    #[tokio::test]
    async fn the_finding_cap_bounds_the_detail_and_never_the_counts() {
        let store = Arc::new(InMemoryDraftStore::default());
        for seq in 0..5u32 {
            // Properly cited, so each lands `ready` and is in scope for the
            // sweep — an uncited draft is refused by the *landing* check and
            // would never reach the audit at all.
            let event = envelope(seq);
            landed(
                &store,
                IncidentId::new(),
                &[event.event_id],
                &format!("The two transactions shared a block [{}].", event.event_id),
            )
            .await;
        }

        let report = GroundingAuditor::new(
            store,
            // No stream for any of them: five unverifiable findings.
            Arc::new(VecAuditSource::default()),
            AuditConfig {
                limits: AuditLimits {
                    max_findings: 2,
                    ..AuditLimits::default()
                },
                ..AuditConfig::default()
            },
        )
        .run(now(), &CancellationToken::new())
        .await
        .expect("the sweep reads");

        assert_eq!(report.examined, 5);
        assert_eq!(report.evidence_missing, 5);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.omitted_findings, 3);
        assert!(report.to_string().contains("and 3 more"));
    }

    /// The keyset walk has to reach every page. A page-size of 1 over several
    /// drafts is the cheapest way to prove the cursor advances rather than
    /// re-reading its own first page forever.
    #[tokio::test]
    async fn the_keyset_walk_covers_every_page() {
        let store = Arc::new(InMemoryDraftStore::default());
        let mut events = VecAuditSource::default();
        for seq in 0..5u32 {
            let subject = IncidentId::new();
            let event = envelope(seq);
            landed(
                &store,
                subject,
                &[event.event_id],
                &format!("The transactions shared a block [{}].", event.event_id),
            )
            .await;
            events = events.with_stream(subject, vec![event]);
        }

        let report = GroundingAuditor::new(
            store,
            Arc::new(events),
            AuditConfig {
                limits: AuditLimits {
                    page_size: 1,
                    ..AuditLimits::default()
                },
                ..AuditConfig::default()
            },
        )
        .run(now(), &CancellationToken::new())
        .await
        .expect("the sweep reads");

        assert_eq!(
            (report.examined, report.grounded),
            (5, 5),
            "every draft must be visited exactly once"
        );
    }

    /// The precedence the module turns on, stated once, with no I/O in sight —
    /// this is what extracting [`verdict_for`] bought.
    ///
    /// A ceiling that cut the stream short cannot be told apart from a
    /// deletion, so a truncated stream with an unresolved id is *unverifiable*,
    /// not an accusation. Guessing in the accusing direction is how a safety
    /// check earns a reputation for crying wolf and gets switched off.
    #[test]
    fn a_truncated_stream_outranks_an_unresolved_citation() {
        let shown = envelope(0);
        let missing = envelope(1);
        let draft = landed_draft(
            &format!(
                "The swap was sandwiched [{}]. The funds moved on [{}].",
                shown.event_id, missing.event_id
            ),
            vec![shown.event_id, missing.event_id],
        );

        // Same draft, same missing id — the only difference is the ceiling.
        let complete = verdict_for(
            &draft,
            &stream(vec![shown.clone()], false),
            &Policy::default(),
            now(),
        );
        assert_eq!(complete.verdict, Verdict::Unresolved);
        assert_eq!(complete.unresolved, vec![missing.event_id]);

        let cut_short = verdict_for(
            &draft,
            &stream(vec![shown.clone()], true),
            &Policy::default(),
            now(),
        );
        assert_eq!(
            cut_short.verdict,
            Verdict::Unverifiable(UnverifiableReason::StreamTruncated),
        );
        // The counts survive the downgrade: a reviewer still learns how much
        // of the narrative was cited.
        assert_eq!(cut_short.claims, 2);

        // A truncated stream where everything resolved is still a pass — the
        // ceiling only clouds the *unresolved* case.
        let all_resolved = landed_draft(
            &format!("The swap was sandwiched [{}].", shown.event_id),
            vec![shown.event_id],
        );
        assert_eq!(
            verdict_for(
                &all_resolved,
                &stream(vec![shown], true),
                &Policy::default(),
                now()
            )
            .verdict,
            Verdict::Grounded,
        );
    }

    /// If an id does not exist, that is the sentence to put in front of a
    /// human — not the bookkeeping disagreement that comes with it.
    #[test]
    fn an_unresolved_citation_outranks_drift() {
        let shown = envelope(0);
        let missing = envelope(1);
        let draft = landed_draft(
            &format!(
                "The swap was sandwiched [{}]. The funds moved on [{}].",
                shown.event_id, missing.event_id
            ),
            // The column also disagrees with the prose: both faults at once.
            vec![shown.event_id],
        );

        let finding = verdict_for(
            &draft,
            &stream(vec![shown], false),
            &Policy::default(),
            now(),
        );
        assert_eq!(finding.verdict, Verdict::Unresolved);
        assert_eq!(
            finding.drifted,
            vec![missing.event_id],
            "the drift is still reported, it just does not name the verdict"
        );
    }

    /// The fan-out is a bulkhead on *another service's* read path, so the
    /// bound is a property worth a test rather than a comment — and the order
    /// findings come back in is what makes the printed report readable.
    #[tokio::test]
    async fn the_sweep_bounds_its_concurrency_and_keeps_walk_order() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Counts how many reads are in flight at once, and stalls briefly so
        /// they actually overlap.
        #[derive(Debug, Default)]
        struct CountingSource {
            in_flight: AtomicUsize,
            peak: AtomicUsize,
        }

        #[async_trait::async_trait]
        impl AuditSource for CountingSource {
            async fn audit_stream(
                &self,
                incident_id: events::primitives::IncidentId,
                _max_events: usize,
            ) -> Result<AuditStream, crate::audit::AuditError> {
                let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(AuditStream {
                    incident_id: Some(incident_id),
                    // Empty: this test is about the fan-out, not the verdict.
                    events: Vec::new(),
                    truncated: false,
                })
            }
        }

        let store = Arc::new(InMemoryDraftStore::default());
        for seq in 0..8u32 {
            let event = envelope(seq);
            landed(
                &store,
                IncidentId::new(),
                &[event.event_id],
                &format!("The transactions shared a block [{}].", event.event_id),
            )
            .await;
        }

        // The order the *store* hands them back, whatever it is. Asserting
        // against insertion order would encode a guess: these drafts share a
        // `created_at`, so the walk falls through to `draft_id DESC` — a
        // random v4, arbitrary but *stable*, which is all the cursor needs.
        // What matters here is that findings follow the walk, not what the
        // walk decided.
        let walk_order: Vec<Uuid> = store
            .list(&DraftFilter {
                status: Some(DraftStatus::Ready),
                kind: Some(DraftKind::IncidentNarrative),
                ..DraftFilter::with_limit(16)
            })
            .await
            .expect("the store lists")
            .iter()
            .map(|draft| draft.subject_id)
            .collect();

        let source = Arc::new(CountingSource::default());
        let report = GroundingAuditor::new(
            store,
            source.clone(),
            AuditConfig {
                limits: AuditLimits {
                    concurrency: 3,
                    ..AuditLimits::default()
                },
                ..AuditConfig::default()
            },
        )
        .run(now(), &CancellationToken::new())
        .await
        .expect("the sweep reads");

        assert_eq!(report.examined, 8);
        let peak = source.peak.load(Ordering::SeqCst);
        assert!(
            (2..=3).contains(&peak),
            "reads must overlap but never exceed the bulkhead: peak {peak}"
        );

        // `buffered`, not `buffer_unordered`: concurrent reads complete in
        // whatever order they finish, and the findings still come back in the
        // order the drafts were walked — which is what makes the printed
        // report readable down the page.
        let reported: Vec<Uuid> = report.findings.iter().map(|f| f.subject_id).collect();
        assert_eq!(
            reported, walk_order,
            "findings must follow the walk order, not completion order"
        );
    }

    /// An empty table is genuinely clean: there is nothing ungrounded in it.
    #[tokio::test]
    async fn an_empty_table_is_clean() {
        let report = auditor(
            Arc::new(InMemoryDraftStore::default()),
            VecAuditSource::default(),
        )
        .run(now(), &CancellationToken::new())
        .await
        .expect("the sweep reads");
        assert_eq!(report.examined, 0);
        assert_eq!(report.outcome(), Outcome::Clean);
    }
}
