//! **How long a regulatory artifact and the evidence under it must both live.**
//!
//! A SAR narrative drafted by the copilot (§20.4) is a regulatory artifact: a
//! human reviews it, approves it, and files from it. Two different stores hold
//! the two halves of that document —
//!
//! ```text
//!   the artifact   copilot's Postgres  `copilot_drafts`  (the narrative, its
//!                                       citations, who approved it and when)
//!   the evidence   event-store's ClickHouse `events`      (the event ids the
//!                                       narrative cites, and nothing else)
//! ```
//!
//! — and until this crate existed, neither store had a retention decision at
//! all. That is not the same as "we keep everything forever": it is the
//! *absence* of a decision, which is exactly what
//! [`crate::Policy::validate`]'s existence is meant to end. The
//! `CopilotGroundingAuditUnverifiable` alert was written against that absence
//! ("if retention is the cause, that is a decision to make deliberately"); with
//! a policy in place the same condition means something much sharper, and the
//! audit says so — see `copilot::grounding_audit`.
//!
//! # The decision
//!
//! **Five years, from the artifact's disposition.** A financial institution
//! that files a SAR must retain a copy of the report *and the supporting
//! documentation* for five years from the date of filing (31 CFR 1020.320(d) in
//! the US; art. 40 of Directive (EU) 2015/849 sets the same five-year floor in
//! the EU, extensible to ten by a member state). This platform does not file —
//! its customers do — so the obligation it can actually discharge is: **never
//! be the reason a filer cannot produce the record.** Hence
//! [`STATUTORY_ARTIFACT_DAYS`] is a **floor**, not a default to be tuned down:
//! [`Policy::validate`] refuses a shorter one, and the constructor is the only
//! way to build a policy.
//!
//! The number is 1827 days rather than `5 * 365`. Five calendar years span one
//! or two leap days depending on where they start, and the direction to round a
//! retention floor is *up* — a policy that expires evidence a day early is
//! worthless in exactly the situation it exists for.
//!
//! # The part that is not obvious: the two clocks are different
//!
//! The artifact's clock starts when the artifact is *disposed of* — approved,
//! rejected, or left unreviewed. The evidence's clock started when the event
//! **occurred**, which is earlier, and which nothing can change: the event
//! store is append-only (§4), so an event's retention cannot be extended after
//! the fact without mutating a store whose immutability is load-bearing.
//!
//! So expiring both on "five years" would quietly under-retain every artifact:
//!
//! ```text
//!   evidence occurs ─────► narrative drafted ─────────► evidence expires
//!        E                        T                          E + 5y
//!                                 └──────────────────────────────► artifact expires
//!                                                                     T + 5y
//!                                        the gap: (T - E) of undefendable document
//! ```
//!
//! The whole policy is therefore one inequality:
//!
//! ```text
//!   E + evidence_days  >=  T + artifact_days
//!             ⇔   T - E  <=  evidence_days - artifact_days
//! ```
//!
//! and the right-hand side has a name: [`Policy::max_drafting_lag`]. Evidence is
//! kept for the artifact window **plus a margin**, and that margin *is* the
//! furthest back a narrative may be drafted. One knob does both jobs, which is
//! the point — [`EVIDENCE_MARGIN_DAYS`] cannot be raised to unlock an older
//! backfill without also lengthening the evidence TTL that makes the older
//! backfill defendable. There is no flag that skips this, deliberately: an
//! "--allow-unretained-evidence" escape hatch produces exactly the document
//! this crate exists to prevent, and produces it on purpose.
//!
//! # Where it is enforced
//!
//! Nowhere in this crate — it computes, it does not delete. Two enforcement
//! sites read it and they are the two stores:
//!
//! * `event_store::retention` reconciles the `events` table's ClickHouse `TTL`
//!   against [`Policy::evidence_days`] at boot, **extending only**: shortening
//!   destroys evidence and is refused, not applied.
//! * `copilot::retention` purges `copilot_drafts` past
//!   [`Policy::artifact_deadline`], dry-run by default, never touching a row
//!   under legal hold.
//!
//! Both destructive directions — shortening the evidence window, and destroying
//! an artifact — take a [`DestructiveIntent`] witness, so a boot path or a
//! background task cannot reach them *by signature*.
//!
//! A third site *reads* it as a judgement rather than an action:
//! `copilot::grounding_audit` uses it to tell a draft whose evidence
//! legitimately aged out (`Expired` — retention working) from one whose
//! evidence is gone while the artifact is still under retention
//! (`EvidenceMissing` — **the policy violated**).

use std::fmt;

use chrono::{DateTime, TimeDelta, Utc};
use uuid::Uuid;

/// The floor on how long a filed artifact and its supporting documentation are
/// kept: five years, rounded up over leap days.
///
/// A floor and not a default: [`Policy::new`] refuses anything shorter, so the
/// only way to reduce it is to edit this constant in a reviewed diff — which is
/// the correct amount of friction for a number a regulator names.
pub const STATUTORY_ARTIFACT_DAYS: u32 = 1827;

/// How much longer than the artifact window evidence is kept — and therefore
/// the furthest back in time a narrative may be drafted (see the module docs'
/// inequality).
///
/// One year. Sized from the backfill, which is the only writer that drafts over
/// old evidence: a year of archive is what §20.4's historical backfill is for,
/// and anything older is a deliberate policy change rather than a flag.
pub const EVIDENCE_MARGIN_DAYS: u32 = 365;

/// Sanity ceiling (100 years). Not a policy statement — a typo guard, so
/// `RETENTION_ARTIFACT_DAYS=18270000` fails at boot instead of writing a TTL
/// that silently means "forever".
pub const MAX_ARTIFACT_DAYS: u32 = 36_500;

/// **The artifact clock's zero.** When a regulatory artifact was *disposed of*
/// — approved, rejected, or simply answered and left. Retention of the artifact
/// runs from here.
///
/// A newtype and not a bare instant because this crate exists to keep two
/// clocks apart, and handing them to each other as the same type is how they
/// get confused. [`Policy::shortfall`] takes one of each; before this existed,
/// swapping its arguments compiled and returned a plausible wrong number —
/// which is precisely the under-retention the whole module is written to
/// prevent (§4 — make illegal states unrepresentable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Disposition(DateTime<Utc>);

impl Disposition {
    pub fn at(instant: DateTime<Utc>) -> Self {
        Self(instant)
    }

    pub fn instant(self) -> DateTime<Utc> {
        self.0
    }
}

impl fmt::Display for Disposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_rfc3339())
    }
}

/// **The evidence clock's zero.** When an event *occurred*. Retention of the
/// evidence runs from here, and — unlike a disposition — nothing can move it:
/// the event store is append-only (§4), so an event's window cannot be extended
/// after the fact. That asymmetry is the entire reason the policy carries a
/// margin rather than one number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Occurrence(DateTime<Utc>);

impl Occurrence {
    pub fn at(instant: DateTime<Utc>) -> Self {
        Self(instant)
    }

    pub fn instant(self) -> DateTime<Utc> {
        self.0
    }
}

impl fmt::Display for Occurrence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_rfc3339())
    }
}

/// **A witness that a human asked for something irreversible.**
///
/// Carried by every operation in this workspace that destroys a regulatory
/// artifact or shortens the window protecting one — the purge's writes, and the
/// event store's TTL when the new window is narrower than the old. Unforgeable
/// by accident: the field is private, so the only way to obtain one is to call
/// [`DestructiveIntent::from_operator_flag`], and the only caller of *that* is
/// a CLI arm parsing a flag somebody typed.
///
/// It is **not** a security boundary — any code in the workspace could call the
/// constructor. It is a *signature* boundary, which is the useful one: a boot
/// path, a CronJob's default arm, or a background task physically cannot reach
/// a destructive apply without taking this parameter, so the reviewer's
/// question changes from "does this delete anything?" (unanswerable without
/// reading the body) to "does this signature mention `DestructiveIntent`?".
/// Same shape as `backup`'s `Scratch`, and for the same reason.
///
/// Grep for it to enumerate every irreversible operation in the platform.
#[derive(Debug, Clone, Copy)]
pub struct DestructiveIntent(());

impl DestructiveIntent {
    /// Mint the witness. **Call this from a CLI flag arm and nowhere else.**
    pub fn from_operator_flag() -> Self {
        Self(())
    }
}

/// A policy that could not be built.
///
/// Every variant is a boot failure. A retention policy that is wrong is worse
/// than one that is missing: the missing one leaves the data alone, and the
/// wrong one deletes it on a schedule.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    /// Below the statutory floor — the one thing this crate will not do,
    /// whatever the environment says.
    #[error(
        "retention of {days} day(s) is below the {STATUTORY_ARTIFACT_DAYS}-day statutory floor \
         for a filed report and its supporting documentation (31 CFR 1020.320(d) / \
         Directive (EU) 2015/849 art. 40)"
    )]
    BelowFloor { days: u32 },
    /// Past the typo guard.
    #[error("retention of {days} day(s) exceeds the {MAX_ARTIFACT_DAYS}-day ceiling")]
    AboveCeiling { days: u32 },
    /// A margin of zero makes the inequality unsatisfiable: drafting takes
    /// non-zero time, so *every* artifact would outlive its evidence and the
    /// policy would be self-violating from the first draft.
    #[error(
        "the evidence margin must be at least 1 day — with a margin of zero every artifact \
         outlives the evidence it cites, because drafting is never instantaneous"
    )]
    ZeroMargin,
}

/// The retention decision, as a value.
///
/// Constructed through [`Policy::new`] or [`Policy::from_env`] only: the fields
/// are private because a `Policy { artifact_days: 30, .. }` assembled by hand
/// somewhere in a test helper is precisely the under-retention this type
/// exists to make impossible (§4 — parse, don't validate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    artifact_days: u32,
    evidence_margin_days: u32,
}

impl Default for Policy {
    /// The decision as shipped: the statutory floor, plus a year of margin.
    fn default() -> Self {
        Self {
            artifact_days: STATUTORY_ARTIFACT_DAYS,
            evidence_margin_days: EVIDENCE_MARGIN_DAYS,
        }
    }
}

impl Policy {
    /// Build and validate. The only constructor.
    pub fn new(artifact_days: u32, evidence_margin_days: u32) -> Result<Self, PolicyError> {
        if artifact_days < STATUTORY_ARTIFACT_DAYS {
            return Err(PolicyError::BelowFloor {
                days: artifact_days,
            });
        }
        if artifact_days > MAX_ARTIFACT_DAYS {
            return Err(PolicyError::AboveCeiling {
                days: artifact_days,
            });
        }
        if evidence_margin_days == 0 {
            return Err(PolicyError::ZeroMargin);
        }
        Ok(Self {
            artifact_days,
            evidence_margin_days,
        })
    }

    /// Resolve from the environment (§9 — once, at boot, fail-fast).
    ///
    /// Both knobs are read by *every* service that enforces the policy, so they
    /// are unprefixed by service: `RETENTION_ARTIFACT_DAYS` and
    /// `RETENTION_EVIDENCE_MARGIN_DAYS` mean the same thing in event-store's
    /// pod and in the copilot's, and a deployment that sets them differently
    /// per service has split the decision in two — which is the failure mode
    /// this crate was extracted to prevent.
    ///
    /// Behind the `env` feature: the arithmetic above is the crate's reason to
    /// exist and needs nothing but `chrono`, while *reading* it pulls in the
    /// whole observability stack through `telemetry`. A future consumer that
    /// only wants to compute a deadline (a report, a migration tool, a test
    /// fixture) should not link an OTLP exporter to do it.
    #[cfg(feature = "env")]
    pub fn from_env() -> anyhow::Result<Self> {
        use anyhow::Context as _;

        let artifact_days =
            telemetry::env::parse_or("RETENTION_ARTIFACT_DAYS", STATUTORY_ARTIFACT_DAYS)?;
        let evidence_margin_days =
            telemetry::env::parse_or("RETENTION_EVIDENCE_MARGIN_DAYS", EVIDENCE_MARGIN_DAYS)?;
        Self::new(artifact_days, evidence_margin_days)
            .context("resolving the regulatory retention policy")
    }

    /// How long an artifact is kept after its disposition.
    pub fn artifact_days(&self) -> u32 {
        self.artifact_days
    }

    /// The margin — equivalently, [`Policy::max_drafting_lag`] in days.
    pub fn evidence_margin_days(&self) -> u32 {
        self.evidence_margin_days
    }

    /// How long an event is kept after it **occurred**.
    ///
    /// This is the number the event store's TTL is set from, and it is
    /// deliberately not independently configurable: an evidence window shorter
    /// than the artifact window is not a stricter policy, it is a broken one.
    pub fn evidence_days(&self) -> u32 {
        self.artifact_days + self.evidence_margin_days
    }

    /// The furthest back a narrative may be drafted and still be defendable for
    /// its whole life.
    pub fn max_drafting_lag(&self) -> TimeDelta {
        days(self.evidence_margin_days)
    }

    /// When an artifact disposed of at `disposed` may be destroyed.
    pub fn artifact_deadline(&self, disposed: Disposition) -> DateTime<Utc> {
        disposed.instant() + days(self.artifact_days)
    }

    /// When an event that occurred at `occurred` will be destroyed by the
    /// store's own TTL.
    pub fn evidence_deadline(&self, occurred: Occurrence) -> DateTime<Utc> {
        occurred.instant() + days(self.evidence_days())
    }

    /// The disposition instant at or before which an artifact may be destroyed
    /// as of `now` — the purge's `WHERE` bound, and the audit's.
    ///
    /// The arithmetic lives here rather than at the call site so there is
    /// exactly one definition of the cutoff. It used to be computed inline in
    /// the purge runner, which meant the enforcer and the checker each did
    /// their own subtraction and could disagree by a day after any edit.
    pub fn purge_cutoff(&self, now: DateTime<Utc>) -> Disposition {
        Disposition::at(now - days(self.artifact_days))
    }

    /// The earliest evidence a narrative may be drafted over today and still be
    /// defendable for its whole life — `now` minus the margin.
    pub fn oldest_draftable(&self, now: DateTime<Utc>) -> Occurrence {
        Occurrence::at(now - self.max_drafting_lag())
    }

    /// Whether an artifact anchored at `anchored_at` outlives its own evidence,
    /// and by how much.
    ///
    /// `None` is the good case. `Some(delta)` is the gap in the module docs'
    /// diagram: for that long, a stored, approved narrative will cite events
    /// the store has already deleted — a document nobody can defend, and one
    /// the platform created on purpose. The audit reports this **before** the
    /// evidence actually expires, which is the only useful time to hear it.
    pub fn shortfall(
        &self,
        disposed: Disposition,
        oldest_evidence: Occurrence,
    ) -> Option<TimeDelta> {
        let gap = self.artifact_deadline(disposed) - self.evidence_deadline(oldest_evidence);
        (gap > TimeDelta::zero()).then_some(gap)
    }

    /// Whether the policy holds for this pairing — the inequality, named.
    pub fn covers(&self, disposed: Disposition, oldest_evidence: Occurrence) -> bool {
        self.shortfall(disposed, oldest_evidence).is_none()
    }

    /// Whether an artifact disposed of at `anchored_at` may be destroyed as of
    /// `now`. The purge's predicate, and the audit's — one function, so a row
    /// the purge would have deleted can never be one the audit still holds to
    /// the standard of a live artifact.
    pub fn is_expired(&self, disposed: Disposition, now: DateTime<Utc>) -> bool {
        now >= self.artifact_deadline(disposed)
    }
}

/// **Every policy a deployment enforces, and the one number the store can hold.**
///
/// Today this is one uniform policy, and [`PolicySet::uniform`] is the only
/// constructor. It exists as a type anyway because of an asymmetry that will
/// bite the moment a second policy appears, and that is much cheaper to design
/// for than to discover:
///
/// * **The artifact side scales per owner.** A draft has a `customer_id`, so
///   "this customer's jurisdiction requires ten years" is a lookup, and the
///   purge simply asks for that artifact's policy.
/// * **The evidence side cannot.** ClickHouse's `TTL` is a property of the
///   *table*, not of a row's owner. With two policies in play there is exactly
///   one legal window for the `events` table: **the widest one**. Anything
///   narrower silently under-retains the evidence under the longest-lived
///   artifact — and it under-retains it invisibly, because the artifact is
///   still sitting there looking perfectly well retained.
///
/// So the store reads [`PolicySet::widest_evidence_days`] and never a single
/// `Policy::evidence_days`. Getting that edge wrong later means discovering it
/// as "why is our ten-year customer's evidence gone", which is not a bug report
/// anyone wants to receive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySet {
    default: Policy,
}

impl Default for PolicySet {
    fn default() -> Self {
        Self::uniform(Policy::default())
    }
}

impl PolicySet {
    /// One policy for every artifact — the shipped configuration.
    pub fn uniform(policy: Policy) -> Self {
        Self { default: policy }
    }

    /// The policy governing one artifact.
    ///
    /// `owner` is ignored today and is in the signature deliberately: it is the
    /// parameter a per-jurisdiction lookup needs, and adding it now costs one
    /// unused argument while adding it later costs an edit at every call site
    /// on the enforcement path.
    pub fn for_artifact(&self, _owner: Option<Uuid>) -> Policy {
        self.default
    }

    /// The window the **evidence store** must use: the widest artifact policy
    /// in the set. See the type's docs for why this is not per-owner.
    pub fn widest_evidence_days(&self) -> u32 {
        self.policies()
            .map(Policy::evidence_days)
            .max()
            .unwrap_or_else(|| self.default.evidence_days())
    }

    /// Every distinct policy in the set. One entry today.
    pub fn policies(&self) -> impl Iterator<Item = &Policy> {
        std::iter::once(&self.default)
    }

    /// The policy every artifact gets when no owner-specific one applies.
    pub fn default_policy(&self) -> Policy {
        self.default
    }
}

impl fmt::Display for PolicySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.default)
    }
}

/// One line, for a boot log and for the runbook's "what is this cluster set
/// to" question. Both windows, because quoting one without the other is how
/// the two stores drift apart in an operator's head.
impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "artifacts {}d from disposition, evidence {}d from occurrence \
             (max drafting lag {}d)",
            self.artifact_days,
            self.evidence_days(),
            self.evidence_margin_days,
        )
    }
}

/// `u32` days as a `TimeDelta`, total by construction: the ceiling above keeps
/// the product far inside `TimeDelta`'s range, so this cannot be the `unwrap`
/// that fails at 3am.
fn days(n: u32) -> TimeDelta {
    TimeDelta::days(i64::from(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn disposed(s: &str) -> Disposition {
        Disposition::at(at(s))
    }

    fn occurred(s: &str) -> Occurrence {
        Occurrence::at(at(s))
    }

    #[test]
    fn the_shipped_policy_is_the_statutory_floor_plus_a_year() {
        let policy = Policy::default();
        assert_eq!(policy.artifact_days(), STATUTORY_ARTIFACT_DAYS);
        assert_eq!(policy.evidence_days(), STATUTORY_ARTIFACT_DAYS + 365);
        assert_eq!(policy.max_drafting_lag(), TimeDelta::days(365));
    }

    /// The floor is the whole reason the fields are private.
    #[test]
    fn a_shorter_window_than_the_statute_is_refused() {
        assert_eq!(
            Policy::new(365, 30),
            Err(PolicyError::BelowFloor { days: 365 })
        );
        assert!(Policy::new(STATUTORY_ARTIFACT_DAYS, 30).is_ok());
    }

    #[test]
    fn a_zero_margin_is_refused_because_drafting_takes_time() {
        assert_eq!(
            Policy::new(STATUTORY_ARTIFACT_DAYS, 0),
            Err(PolicyError::ZeroMargin)
        );
    }

    #[test]
    fn a_typo_sized_window_is_refused() {
        assert!(matches!(
            Policy::new(MAX_ARTIFACT_DAYS + 1, 365),
            Err(PolicyError::AboveCeiling { .. })
        ));
    }

    /// The inequality, stated as the property it is: evidence outlives the
    /// artifact **iff** the drafting lag is inside the margin. Checked at the
    /// exact boundary, because the boundary is where a policy is either sound
    /// or off by a day.
    #[test]
    fn the_margin_is_exactly_the_maximum_drafting_lag() {
        let policy = Policy::default();
        let evidence = occurred("2026-01-01T00:00:00Z");

        let inside = Disposition::at(evidence.instant() + policy.max_drafting_lag());
        assert!(
            policy.covers(inside, evidence),
            "a lag of exactly the margin"
        );

        let outside = Disposition::at(inside.instant() + TimeDelta::seconds(1));
        assert_eq!(
            policy.shortfall(outside, evidence),
            Some(TimeDelta::seconds(1)),
            "one second past the margin is one second of undefendable document"
        );
    }

    #[test]
    fn a_narrative_drafted_the_day_of_the_incident_is_covered_with_room_to_spare() {
        let policy = Policy::default();
        let evidence = occurred("2026-01-01T00:00:00Z");
        assert!(policy.covers(
            Disposition::at(evidence.instant() + TimeDelta::hours(2)),
            evidence
        ));
    }

    /// A backfill reaching two years back is the case the margin refuses, and
    /// the number in the message is what an operator would have to add to
    /// `RETENTION_EVIDENCE_MARGIN_DAYS` to make it legitimate.
    #[test]
    fn a_two_year_old_backfill_is_short_by_a_year() {
        let policy = Policy::default();
        assert_eq!(
            policy.shortfall(
                disposed("2026-01-01T00:00:00Z"),
                occurred("2024-01-01T00:00:00Z")
            ),
            Some(TimeDelta::days(731 - 365)),
        );
    }

    /// The reason the two clocks are newtypes: this is the call that used to
    /// compile with its arguments the wrong way round.
    #[test]
    fn the_two_clocks_cannot_be_swapped() {
        let policy = Policy::default();
        let d = disposed("2026-01-01T00:00:00Z");
        let o = occurred("2024-01-01T00:00:00Z");
        assert!(policy.shortfall(d, o).is_some());
        // `policy.shortfall(o, d)` does not compile — Occurrence is not a
        // Disposition, which is the entire point of the pair.
        let _ = (d, o);
    }

    #[test]
    fn the_purge_cutoff_is_the_deadline_read_backwards() {
        let policy = Policy::default();
        let now = at("2026-09-05T00:00:00Z");
        let cutoff = policy.purge_cutoff(now);
        // Anything disposed at the cutoff is exactly due; a second later is not.
        assert!(policy.is_expired(cutoff, now));
        assert!(!policy.is_expired(
            Disposition::at(cutoff.instant() + TimeDelta::seconds(1)),
            now
        ));
    }

    /// The store gets the widest window in the set, never a per-owner one —
    /// ClickHouse TTL is per table, so anything else under-retains the evidence
    /// beneath the longest-lived artifact.
    #[test]
    fn the_evidence_window_is_the_widest_policy_in_the_set() {
        let set = PolicySet::uniform(Policy::default());
        assert_eq!(
            set.widest_evidence_days(),
            Policy::default().evidence_days()
        );
        assert_eq!(set.for_artifact(None), Policy::default());
    }

    #[test]
    fn expiry_is_measured_from_disposition_and_is_inclusive() {
        let policy = Policy::default();
        let anchored = disposed("2026-01-01T00:00:00Z");
        let deadline = policy.artifact_deadline(anchored);
        assert!(!policy.is_expired(anchored, deadline - TimeDelta::seconds(1)));
        assert!(policy.is_expired(anchored, deadline));
    }

    #[test]
    fn display_names_both_windows() {
        assert_eq!(
            Policy::default().to_string(),
            "artifacts 1827d from disposition, evidence 2192d from occurrence \
             (max drafting lag 365d)"
        );
    }
}
