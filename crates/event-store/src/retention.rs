//! Enforcing the regulatory evidence window on the `events` table
//! (engineering conventions §18).
//!
//! The [`retention::Policy`] says how long an event must live; ClickHouse's
//! `TTL` clause is how this store makes that true. The awkward part is that the
//! two live in different places: the policy is env-resolved and may be raised,
//! and a migration is a static file that cannot be. So the split is —
//!
//! * **the migration** (`0003_events_retention`) installs the *floor*, so no
//!   freshly-migrated store is ever unbounded, and
//! * **this module** reconciles the live table against the configured policy at
//!   boot, so raising `RETENTION_ARTIFACT_DAYS` actually reaches the store
//!   instead of living in a config map nobody applied.
//!
//! # Plan, then apply — and only one direction applies itself
//!
//! [`observe`] reads the store, [`plan`] decides purely, and each destructive
//! variant of the plan carries a value whose `apply` demands a
//! [`DestructiveIntent`]. The boot path ([`reconcile_safe`]) takes no witness
//! and therefore **cannot** narrow a window, bind an archive, or overwrite a
//! clause it failed to parse — not by convention, by signature. The reviewer's
//! question stops being "does this delete anything?" and becomes "does this
//! signature mention `DestructiveIntent`?".
//!
//! # Reconciliation extends; it never shortens
//!
//! `ALTER TABLE ... MODIFY TTL` is not a metadata edit — ClickHouse
//! materialises the new expression and background merges then drop everything
//! past it. Applied in the lengthening direction that is free; applied in the
//! shortening direction it **deletes regulatory evidence**, irreversibly, at
//! boot, because of a typo in an env var.
//!
//! So a shortening is [`Reconciliation::Shortening`] and the boot path treats
//! it as a fatal misconfiguration: the service refuses to start and names the
//! deliberate command. This is the same stance the rest of the platform takes
//! toward destructive automation (the backup crate's restore, `rebuild`'s
//! wipe): the machine may do the safe direction unattended, and a human types
//! the other one.
//!
//! # Three store states, not two
//!
//! An earlier version of this module modelled the live TTL as `Option<u32>`,
//! and that shortcut cost data: `None` stood for both "no TTL" and "a TTL I
//! cannot read", the planner treated both as "unbounded, free to widen into",
//! and a table carrying `INTERVAL 10 YEAR` was quietly rewritten to six years
//! at boot. [`TtlState`] separates them, and `Absent` is its own *destructive*
//! case besides — imposing a first bound on an eight-year archive deletes two
//! years of it, so it is checked against the store's oldest row rather than
//! assumed free.
//!
//! # Why the current window is read back rather than assumed
//!
//! The TTL is table state, not process state. It can have been set by an older
//! build, by a hand-run `ALTER` during an incident, or by a migration that ran
//! on a replica and not here. An audit that says "the policy is 2192 days"
//! because that is what this pod's environment said is an audit of a config
//! map; reading `system.tables` audits the store.

use std::fmt;

use chrono::{DateTime, TimeDelta, Utc};
use clickhouse::Client;
// `::` is load-bearing: this module is *also* called `retention`.
use ::retention::{DestructiveIntent, PolicySet};

/// The table the retention policy governs. One table, named once: the events
/// are the evidence, and nothing else in this store is a regulatory artifact.
const TABLE: &str = "events";

/// **What the live table's TTL actually is**, as three distinguishable states.
///
/// This used to be an `Option<u32>`, and that shortcut cost data. `None` was
/// standing for two situations with *opposite* safety properties — "there is no
/// TTL" and "there is a TTL I cannot read" — and the planner folded both into
/// "unbounded, safe to widen into", so a table carrying
/// `TTL occurred_at + INTERVAL 10 YEAR` was silently rewritten to the policy's
/// six years at boot, destroying four years of evidence. The one thing this
/// module promises never to do, done by the path documented as safe.
///
/// Three states, three plans. A window this build cannot express in days is
/// never overwritten — it is a refusal, because the only honest thing to say
/// about a bound you cannot read is that you will not touch it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TtlState {
    /// No `TTL` clause at all. Evidence is unbounded — and note that *imposing*
    /// a first bound is destructive for anything already older than it, which
    /// is why [`Reconciliation::Bind`] is its own variant and not an extension.
    Absent,
    /// A window expressed in days, which is the only form this store writes.
    Days(u32),
    /// There is a TTL and it is not in days (`INTERVAL 10 YEAR`,
    /// `toIntervalMonth(72)`, a `GROUP BY`/`TO VOLUME` form, an expression over
    /// a different column). Carries the clause verbatim so the refusal can
    /// print what it found.
    Unreadable(String),
}

impl fmt::Display for TtlState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TtlState::Absent => write!(f, "no TTL (evidence unbounded)"),
            TtlState::Days(days) => write!(f, "{days} day(s) from occurrence"),
            TtlState::Unreadable(clause) => write!(f, "an unreadable TTL: {clause}"),
        }
    }
}

/// A safe widening: the table already bounds evidence, and the policy wants a
/// longer window. Deletes nothing, so it needs no witness and boot applies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extension {
    pub from: u32,
    pub to: u32,
}

/// **Imposing the first bound** on a table that had none.
///
/// Filed separately from [`Extension`] because "extending from nothing" is not
/// extending — every row already older than the new window is deleted by the
/// next merge. On an empty or young table it is free; on an eight-year archive
/// it destroys two years. The plan cannot tell which without asking the store,
/// so it does not guess: [`FirstBound::assess`] takes the store's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirstBound {
    pub to: u32,
}

/// A narrowing. Always destructive; never automatic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shortening {
    pub from: u32,
    pub to: u32,
}

/// What the live table's TTL is, relative to the configured policy.
///
/// A plan, in the Terraform sense: computed purely from an observation, fully
/// printable, and separated from the act of carrying it out. Each destructive
/// variant carries a value whose `apply` demands a
/// [`DestructiveIntent`] — so the boot path is not *trusted* to skip them, it
/// is unable to reach them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciliation {
    /// The table already expires evidence exactly when the policy says.
    Unchanged { days: u32 },
    /// Safe to apply unattended.
    Extend(Extension),
    /// Needs the store's oldest row before anyone can say whether it is safe.
    Bind(FirstBound),
    /// The policy asks for a shorter window than the table holds.
    Shorten(Shortening),
    /// The table carries a TTL this build cannot read. **Never overwritten.**
    Refuse { found: String },
}

impl Reconciliation {
    /// Whether this outcome must stop the process.
    ///
    /// Boot may widen a bound and may leave a matching one alone. Everything
    /// else — narrowing, imposing a first bound, or finding a window it cannot
    /// parse — is a human's decision, so the service refuses to start rather
    /// than guess with five years of evidence on the table.
    pub fn is_fatal(&self) -> bool {
        !matches!(
            self,
            Reconciliation::Unchanged { .. } | Reconciliation::Extend(_)
        )
    }

    /// The window this plan would leave the table at.
    pub fn target_days(&self) -> Option<u32> {
        match self {
            Reconciliation::Unchanged { days } => Some(*days),
            Reconciliation::Extend(e) => Some(e.to),
            Reconciliation::Bind(b) => Some(b.to),
            Reconciliation::Shorten(s) => Some(s.to),
            Reconciliation::Refuse { .. } => None,
        }
    }
}

impl fmt::Display for Reconciliation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reconciliation::Unchanged { days } => {
                write!(f, "in line with the policy ({days} day(s))")
            }
            Reconciliation::Extend(e) => write!(
                f,
                "BEHIND — widen the window from {} to {} day(s) (safe; boot applies this)",
                e.from, e.to
            ),
            Reconciliation::Bind(b) => write!(
                f,
                "UNBOUNDED — bind the table to {} day(s). This DELETES anything already \
                 older than the window",
                b.to
            ),
            Reconciliation::Shorten(s) => write!(
                f,
                "the store holds {} day(s), longer than the policy's {}. Applying this \
                 DELETES evidence",
                s.from, s.to
            ),
            Reconciliation::Refuse { found } => write!(
                f,
                "REFUSING — the table's TTL is not a window this build can read ({found}); \
                 it will not be overwritten"
            ),
        }
    }
}

/// Whether imposing a first bound would destroy anything, given the store's
/// oldest row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindAssessment {
    /// The table holds nothing older than the new window. Free.
    Safe(SafeBind),
    /// Rows predate the window and would be deleted by the next merge.
    WouldDestroy {
        bound: FirstBound,
        oldest: DateTime<Utc>,
        cutoff: DateTime<Utc>,
    },
}

/// A [`FirstBound`] the store has confirmed destroys nothing. Only
/// [`FirstBound::assess`] can produce one, so "we checked" is carried in the
/// type rather than in a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeBind {
    to: u32,
}

/// A retention reconciliation that could not be carried out.
#[derive(Debug, thiserror::Error)]
pub enum RetentionError {
    #[error("reading the events table's TTL from system.tables")]
    Read(#[source] clickhouse::error::Error),
    #[error("reading the oldest event's occurrence time")]
    ReadOldest(#[source] clickhouse::error::Error),
    #[error("applying the events table's TTL")]
    Apply(#[source] clickhouse::error::Error),
    /// The table exists (migrations just ran) but `system.tables` did not
    /// describe it — a store this service cannot make claims about.
    #[error("the events table is not present in system.tables for database {database}")]
    TableMissing { database: String },
    /// Boot found a plan it is not allowed to carry out. The message names the
    /// deliberate command, because the next thing the operator does is type it.
    #[error(
        "refusing to apply a destructive retention change automatically: {plan}. \
         If it is intended, run `event-store retention apply --i-understand-this-deletes-evidence`"
    )]
    RefusedDestructive { plan: Reconciliation },
}

/// The TTL expression this store writes, for a given number of days.
///
/// Rendered in the normalised form ClickHouse itself stores (`toIntervalDay`,
/// not `INTERVAL n DAY`), so a reconciled table reads back byte-identical to
/// what was written and the common case is a string compare that never
/// re-`ALTER`s a table that is already correct.
pub fn ttl_expression(days: u32) -> String {
    format!("toDateTime(occurred_at) + toIntervalDay({days})")
}

/// Pull the retention window out of a `system.tables.engine_full` string.
///
/// Pure and total, which is the point: the fragile half of this module is
/// reading someone else's SQL rendering back, and it is testable against
/// literal strings with no ClickHouse in the loop.
///
/// Two things it does *not* do, both learned the hard way. It does not scan the
/// whole string — the clause is bounded at `SETTINGS`/`TO `/`GROUP BY`, so a
/// `toIntervalDay(` appearing in a column default or a settings value cannot be
/// read as the retention window. And it does not return "absent" for a form it
/// fails to parse: an unrecognised clause is [`TtlState::Unreadable`], which the
/// planner refuses rather than overwrites.
pub fn read_ttl(engine_full: &str) -> TtlState {
    let Some(start) = engine_full.find(" TTL ") else {
        return TtlState::Absent;
    };
    let tail = &engine_full[start + " TTL ".len()..];

    // Bound the clause: everything a MergeTree can put *after* TTL.
    let end = ["SETTINGS", " TO DISK", " TO VOLUME", " GROUP BY", " WHERE"]
        .iter()
        .filter_map(|marker| tail.find(marker))
        .min()
        .unwrap_or(tail.len());
    let clause = tail[..end].trim();

    match parse_days(clause) {
        Some(days) => TtlState::Days(days),
        None => TtlState::Unreadable(clause.to_owned()),
    }
}

/// `toIntervalDay(n)` or `INTERVAL n DAY`, and nothing else.
///
/// `None` here means "not a day count", which the caller turns into
/// [`TtlState::Unreadable`] — never into "absent". A number too large for `u32`
/// lands here too: an unrepresentable window is one this build cannot reason
/// about, and reasoning about it anyway is how the old code overwrote one.
fn parse_days(clause: &str) -> Option<u32> {
    if let Some(rest) = clause.split("toIntervalDay(").nth(1) {
        let digits = leading_digits(rest);
        // The closing paren must follow immediately, so a truncated or
        // unexpected rendering is unreadable rather than misread.
        return rest[digits.len()..]
            .starts_with(')')
            .then(|| digits.parse().ok())
            .flatten();
    }
    let rest = clause.split("INTERVAL ").nth(1)?;
    let digits = leading_digits(rest);
    rest[digits.len()..]
        .trim_start()
        .starts_with("DAY")
        .then(|| digits.parse().ok())
        .flatten()
}

fn leading_digits(s: &str) -> String {
    s.chars().take_while(char::is_ascii_digit).collect()
}

/// Read the live table's TTL. The I/O half of [`read_ttl`].
pub async fn observe(client: &Client, database: &str) -> Result<TtlState, RetentionError> {
    // `?` is a bind placeholder to the clickhouse crate — everywhere, including
    // inside a comment, which is why this query carries none of its own.
    let engine_full: Vec<String> = client
        .query("SELECT engine_full FROM system.tables WHERE database = ? AND name = ?")
        .bind(database)
        .bind(TABLE)
        .fetch_all()
        .await
        .map_err(RetentionError::Read)?;

    let described = engine_full
        .first()
        .ok_or_else(|| RetentionError::TableMissing {
            database: database.to_owned(),
        })?;
    Ok(read_ttl(described))
}

/// The oldest event the store holds, if it holds any. Read only on the
/// [`Reconciliation::Bind`] path, where it decides whether a first bound is
/// free or destructive.
pub async fn oldest_event(client: &Client) -> Result<Option<DateTime<Utc>>, RetentionError> {
    let rows: Vec<i64> = client
        .query("SELECT toUnixTimestamp(min(occurred_at)) FROM events WHERE notEmpty(event_type)")
        .fetch_all()
        .await
        .map_err(RetentionError::ReadOldest)?;
    Ok(rows
        .first()
        .copied()
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0)))
}

/// **The judgement.** Pure (§1): the store's answer in, the decision out.
///
/// Everything that makes this module worth reviewing is decided here and is
/// testable as arithmetic — that a missing TTL is a *bind* and not a free
/// extension, that an unreadable one is a refusal and not an absence, that
/// equality is a no-op, and that shrinking is never automatic.
pub fn plan(observed: &TtlState, policies: &PolicySet) -> Reconciliation {
    let desired = policies.widest_evidence_days();
    match observed {
        TtlState::Days(days) if *days == desired => Reconciliation::Unchanged { days: *days },
        TtlState::Days(days) if *days > desired => Reconciliation::Shorten(Shortening {
            from: *days,
            to: desired,
        }),
        TtlState::Days(days) => Reconciliation::Extend(Extension {
            from: *days,
            to: desired,
        }),
        TtlState::Absent => Reconciliation::Bind(FirstBound { to: desired }),
        TtlState::Unreadable(clause) => Reconciliation::Refuse {
            found: clause.clone(),
        },
    }
}

impl FirstBound {
    /// Decide whether binding an unbounded table destroys anything, given the
    /// oldest row it holds.
    pub fn assess(self, oldest: Option<DateTime<Utc>>, now: DateTime<Utc>) -> BindAssessment {
        let cutoff = now - TimeDelta::days(i64::from(self.to));
        match oldest {
            Some(oldest) if oldest < cutoff => BindAssessment::WouldDestroy {
                bound: self,
                oldest,
                cutoff,
            },
            // Either the table is empty, or everything in it is inside the new
            // window. Binding it is free.
            _ => BindAssessment::Safe(SafeBind { to: self.to }),
        }
    }

    /// Bind a table whose contents this would delete. The witness is the point.
    pub async fn apply_destructive(
        self,
        client: &Client,
        _intent: DestructiveIntent,
    ) -> Result<(), RetentionError> {
        tracing::warn!(
            to_days = self.to,
            "binding the events table's retention as explicitly requested; evidence older \
             than the new window will be deleted by background merges"
        );
        write_ttl(client, self.to).await
    }
}

impl SafeBind {
    /// Bind a table that holds nothing older than the window. No witness: by
    /// construction there is nothing to destroy.
    pub async fn apply(self, client: &Client) -> Result<(), RetentionError> {
        write_ttl(client, self.to).await
    }
}

impl Extension {
    /// Widen the window. Deletes nothing, so boot may do this unattended.
    pub async fn apply(self, client: &Client) -> Result<(), RetentionError> {
        write_ttl(client, self.to).await
    }
}

impl Shortening {
    /// Narrow the window — and therefore delete every event between the old
    /// bound and the new one. Only reachable with the witness.
    pub async fn apply(
        self,
        client: &Client,
        _intent: DestructiveIntent,
    ) -> Result<(), RetentionError> {
        tracing::warn!(
            from_days = self.from,
            to_days = self.to,
            "shortening the events table's retention as explicitly requested; evidence past \
             the new window will be deleted by background merges"
        );
        write_ttl(client, self.to).await
    }
}

/// Bring the live table in line with the policy **in the safe direction only**.
///
/// The boot path. It cannot be given a [`DestructiveIntent`] because it takes
/// none: a narrowing, a first bound over old data, or an unreadable clause all
/// come back as [`RetentionError::RefusedDestructive`], and the service does not
/// start. That is deliberate — a store whose retention this build cannot vouch
/// for should not be accepting evidence.
pub async fn reconcile_safe(
    client: &Client,
    database: &str,
    policies: &PolicySet,
    now: DateTime<Utc>,
) -> Result<Reconciliation, RetentionError> {
    let observed = observe(client, database).await?;
    let decision = plan(&observed, policies);

    match decision.clone() {
        Reconciliation::Unchanged { .. } => {}
        Reconciliation::Extend(extension) => extension.apply(client).await?,
        Reconciliation::Bind(bound) => {
            // The one extra query, on the one path that needs it.
            let oldest = oldest_event(client).await?;
            match bound.assess(oldest, now) {
                BindAssessment::Safe(safe) => safe.apply(client).await?,
                BindAssessment::WouldDestroy { .. } => {
                    return Err(RetentionError::RefusedDestructive { plan: decision })
                }
            }
        }
        Reconciliation::Shorten(_) | Reconciliation::Refuse { .. } => {
            return Err(RetentionError::RefusedDestructive { plan: decision })
        }
    }
    Ok(decision)
}

/// The deliberate path: apply whatever the plan says, given a witness that a
/// human asked for it. Behind `event-store retention apply
/// --i-understand-this-deletes-evidence`.
///
/// [`Reconciliation::Refuse`] is *still* refused, witness or not: a window this
/// build cannot read is one it must not overwrite, and no flag makes an
/// unparsed clause parsed.
pub async fn reconcile_with_intent(
    client: &Client,
    database: &str,
    policies: &PolicySet,
    now: DateTime<Utc>,
    intent: DestructiveIntent,
) -> Result<Reconciliation, RetentionError> {
    let observed = observe(client, database).await?;
    let decision = plan(&observed, policies);

    match decision.clone() {
        Reconciliation::Unchanged { .. } => {}
        Reconciliation::Extend(extension) => extension.apply(client).await?,
        Reconciliation::Bind(bound) => match bound.assess(oldest_event(client).await?, now) {
            BindAssessment::Safe(safe) => safe.apply(client).await?,
            BindAssessment::WouldDestroy { bound, .. } => {
                bound.apply_destructive(client, intent).await?
            }
        },
        Reconciliation::Shorten(shortening) => shortening.apply(client, intent).await?,
        Reconciliation::Refuse { .. } => {
            return Err(RetentionError::RefusedDestructive { plan: decision })
        }
    }
    Ok(decision)
}

/// The §18 governance fact a carried-out change announces.
///
/// The audit trail has to cover changes to its own governance: a gauge is
/// sampled and a boot log has rotated, but "on this date this platform's
/// evidence window moved from X to Y, applied by Z" is a question asked with a
/// lawyer in the room. The record lands in the event store, which is itself
/// under the policy it describes — so it outlives the change by the margin.
///
/// `None` for [`Reconciliation::Unchanged`]: nothing moved, and a stream of
/// "the policy is still the policy" facts on every pod restart would bury the
/// one record that matters.
pub fn policy_change_announcement(
    decision: &Reconciliation,
    applied_by: &str,
    at: DateTime<Utc>,
    chain: events::primitives::Chain,
) -> Option<events::EventEnvelope> {
    let (previous_days, current_days, destructive) = match decision {
        Reconciliation::Unchanged { .. } | Reconciliation::Refuse { .. } => return None,
        Reconciliation::Extend(e) => (Some(e.from), e.to, false),
        // A first bound reaching an existing archive is destructive, and the
        // caller knows which it was — but the *record* errs toward saying so,
        // because "we imposed a bound" is the sentence a reader has to be able
        // to find later either way.
        Reconciliation::Bind(b) => (None, b.to, true),
        Reconciliation::Shorten(s) => (Some(s.from), s.to, true),
    };

    Some(events::EventEnvelope::new(
        chain,
        events::DomainEvent::RetentionPolicyChanged(events::system::RetentionPolicyChanged {
            store: EVIDENCE_STORE.to_owned(),
            previous_days,
            current_days,
            destructive,
            applied_by: applied_by.to_owned(),
            applied_at: at,
        }),
    ))
}

/// The evidence store this service owns, as the §18 record names it.
pub const EVIDENCE_STORE: &str = "event_store_events";

/// How a change reached the store, for the §18 record.
pub const APPLIED_BY_BOOT: &str = "boot";
/// A human typed the flag.
pub const APPLIED_BY_OPERATOR: &str = "operator";

/// The one write this module makes.
async fn write_ttl(client: &Client, days: u32) -> Result<(), RetentionError> {
    // Not a bound parameter: `MODIFY TTL` takes an *expression*, and a bind
    // would arrive as a literal argument rather than as part of it. The value
    // is a `u32` this crate computed, so there is nothing to inject.
    client
        .query(&format!(
            "ALTER TABLE {TABLE} MODIFY TTL {} DELETE",
            ttl_expression(days)
        ))
        .execute()
        .await
        .map_err(RetentionError::Apply)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What ClickHouse actually hands back for the migrated table.
    const ENGINE_FULL: &str = "MergeTree PARTITION BY (chain, event_type, toDate(occurred_at)) \
         ORDER BY (chain, event_type, occurred_at, event_id) \
         TTL toDateTime(occurred_at) + toIntervalDay(2192) \
         SETTINGS index_granularity = 8192";

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn policies() -> PolicySet {
        PolicySet::default()
    }

    // ── reading the store ────────────────────────────────────────

    #[test]
    fn the_written_expression_reads_back_as_the_same_number() {
        let engine_full = format!("MergeTree ORDER BY x TTL {}", ttl_expression(2192));
        assert_eq!(read_ttl(&engine_full), TtlState::Days(2192));
    }

    #[test]
    fn parses_the_form_clickhouse_stores() {
        assert_eq!(read_ttl(ENGINE_FULL), TtlState::Days(2192));
    }

    /// The realistic reason the live TTL did not come from `ttl_expression`:
    /// somebody typed it during an incident.
    #[test]
    fn parses_the_form_a_human_types() {
        assert_eq!(
            read_ttl("MergeTree ORDER BY x TTL occurred_at + INTERVAL 900 DAY DELETE"),
            TtlState::Days(900)
        );
    }

    #[test]
    fn a_table_without_a_ttl_clause_is_absent() {
        assert_eq!(
            read_ttl("MergeTree PARTITION BY toDate(occurred_at) ORDER BY event_id"),
            TtlState::Absent
        );
    }

    /// **The bug this module was rewritten for.** A window in a unit this build
    /// does not write is not "no window" — it is a window we cannot read, and
    /// the difference is four years of evidence.
    #[test]
    fn a_window_in_another_unit_is_unreadable_and_never_absent() {
        let state = read_ttl("MergeTree ORDER BY x TTL occurred_at + INTERVAL 10 YEAR");
        assert!(
            matches!(state, TtlState::Unreadable(_)),
            "got {state:?} — treating this as Absent silently overwrites a longer window"
        );
        assert!(plan(&state, &policies()).is_fatal());
    }

    #[test]
    fn a_month_interval_is_unreadable_too() {
        assert!(matches!(
            read_ttl("MergeTree ORDER BY x TTL occurred_at + toIntervalMonth(72)"),
            TtlState::Unreadable(_)
        ));
    }

    /// A day count that does not fit the type is unreadable, not absent — the
    /// old `.parse().ok()` swallowed it into "safe to overwrite".
    #[test]
    fn an_unrepresentable_window_is_unreadable() {
        assert!(matches!(
            read_ttl("MergeTree ORDER BY x TTL occurred_at + toIntervalDay(99999999999)"),
            TtlState::Unreadable(_)
        ));
    }

    /// The clause is bounded, so a `toIntervalDay(` after `SETTINGS` cannot be
    /// mistaken for the retention window.
    #[test]
    fn the_clause_is_bounded_at_settings() {
        assert_eq!(
            read_ttl(
                "MergeTree ORDER BY x TTL toDateTime(occurred_at) + toIntervalDay(2192) \
                 SETTINGS merge_with_ttl_timeout = toIntervalDay(1)"
            ),
            TtlState::Days(2192)
        );
    }

    // ── the plan ─────────────────────────────────────────────────

    #[test]
    fn a_matching_window_is_a_no_op() {
        let decision = plan(&TtlState::Days(2192), &policies());
        assert_eq!(decision, Reconciliation::Unchanged { days: 2192 });
        assert!(!decision.is_fatal());
    }

    #[test]
    fn a_raised_policy_extends_the_table_and_boot_may_do_it() {
        let set = PolicySet::uniform(::retention::Policy::new(2000, 365).expect("above the floor"));
        let decision = plan(&TtlState::Days(2192), &set);
        assert_eq!(
            decision,
            Reconciliation::Extend(Extension {
                from: 2192,
                to: 2365
            })
        );
        assert!(!decision.is_fatal(), "widening deletes nothing");
    }

    /// The one that must never be automatic.
    #[test]
    fn a_lowered_policy_is_fatal_and_not_applied() {
        let decision = plan(&TtlState::Days(3000), &policies());
        assert_eq!(
            decision,
            Reconciliation::Shorten(Shortening {
                from: 3000,
                to: 2192
            })
        );
        assert!(decision.is_fatal());
    }

    /// **The second half of the bug.** "Extending from nothing" is not
    /// extending: it imposes a bound, and everything already older than the
    /// bound is deleted by the next merge. It is its own plan, and it is fatal
    /// at boot until the store says it destroys nothing.
    #[test]
    fn an_unbounded_table_is_a_bind_and_not_a_free_extension() {
        let decision = plan(&TtlState::Absent, &policies());
        assert_eq!(decision, Reconciliation::Bind(FirstBound { to: 2192 }));
        assert!(
            decision.is_fatal(),
            "boot must not impose a first bound without checking what it deletes"
        );
    }

    // ── binding an unbounded table ───────────────────────────────

    #[test]
    fn binding_an_empty_table_is_safe() {
        let bound = FirstBound { to: 2192 };
        assert!(matches!(
            bound.assess(None, at("2026-09-05T00:00:00Z")),
            BindAssessment::Safe(_)
        ));
    }

    #[test]
    fn binding_a_young_table_is_safe() {
        let bound = FirstBound { to: 2192 };
        let now = at("2026-09-05T00:00:00Z");
        let oldest = now - TimeDelta::days(30);
        assert!(matches!(
            bound.assess(Some(oldest), now),
            BindAssessment::Safe(_)
        ));
    }

    /// An eight-year archive, bound to six years, loses two — and the plan says
    /// so instead of discovering it in a merge log.
    #[test]
    fn binding_an_old_archive_would_destroy_and_says_so() {
        let bound = FirstBound { to: 2192 };
        let now = at("2026-09-05T00:00:00Z");
        let oldest = now - TimeDelta::days(2920);
        match bound.assess(Some(oldest), now) {
            BindAssessment::WouldDestroy {
                oldest: reported,
                cutoff,
                ..
            } => {
                assert_eq!(reported, oldest);
                assert_eq!(cutoff, now - TimeDelta::days(2192));
            }
            other => panic!("expected a destructive bind, got {other:?}"),
        }
    }

    /// The boundary: a row exactly at the cutoff is inside the window.
    #[test]
    fn the_bind_boundary_keeps_a_row_exactly_at_the_cutoff() {
        let bound = FirstBound { to: 2192 };
        let now = at("2026-09-05T00:00:00Z");
        let cutoff = now - TimeDelta::days(2192);
        assert!(matches!(
            bound.assess(Some(cutoff), now),
            BindAssessment::Safe(_)
        ));
        assert!(matches!(
            bound.assess(Some(cutoff - TimeDelta::seconds(1)), now),
            BindAssessment::WouldDestroy { .. }
        ));
    }

    // ── the governance record ────────────────────────────────────

    #[test]
    fn a_no_op_announces_nothing() {
        assert!(policy_change_announcement(
            &Reconciliation::Unchanged { days: 2192 },
            APPLIED_BY_BOOT,
            at("2026-09-05T00:00:00Z"),
            events::primitives::Chain::ETHEREUM,
        )
        .is_none());
    }

    /// A widening is a real change and is recorded — non-destructive, and the
    /// record says which direction it went so a later reader can tell
    /// "we lengthened retention" from "we deleted history".
    #[test]
    fn a_widening_is_recorded_as_non_destructive() {
        let envelope = policy_change_announcement(
            &Reconciliation::Extend(Extension {
                from: 2192,
                to: 2365,
            }),
            APPLIED_BY_BOOT,
            at("2026-09-05T00:00:00Z"),
            events::primitives::Chain::ETHEREUM,
        )
        .expect("a change is announced");
        match envelope.payload {
            events::DomainEvent::RetentionPolicyChanged(fact) => {
                assert_eq!(fact.store, EVIDENCE_STORE);
                assert_eq!(fact.previous_days, Some(2192));
                assert_eq!(fact.current_days, 2365);
                assert!(!fact.destructive);
                assert_eq!(fact.applied_by, APPLIED_BY_BOOT);
            }
            other => panic!("expected RetentionPolicyChanged, got {other:?}"),
        }
    }

    #[test]
    fn a_narrowing_is_recorded_as_destructive() {
        let envelope = policy_change_announcement(
            &Reconciliation::Shorten(Shortening {
                from: 3000,
                to: 2192,
            }),
            APPLIED_BY_OPERATOR,
            at("2026-09-05T00:00:00Z"),
            events::primitives::Chain::ETHEREUM,
        )
        .expect("a change is announced");
        match envelope.payload {
            events::DomainEvent::RetentionPolicyChanged(fact) => {
                assert!(fact.destructive, "this deletes evidence and must say so");
                assert_eq!(fact.applied_by, APPLIED_BY_OPERATOR);
            }
            other => panic!("expected RetentionPolicyChanged, got {other:?}"),
        }
    }

    /// A first bound has no previous window to name, and that `None` is the
    /// signal a reader needs: the store was unbounded until this instant.
    #[test]
    fn a_first_bound_records_no_previous_window() {
        let envelope = policy_change_announcement(
            &Reconciliation::Bind(FirstBound { to: 2192 }),
            APPLIED_BY_OPERATOR,
            at("2026-09-05T00:00:00Z"),
            events::primitives::Chain::ETHEREUM,
        )
        .expect("a change is announced");
        match envelope.payload {
            events::DomainEvent::RetentionPolicyChanged(fact) => {
                assert_eq!(fact.previous_days, None);
                assert!(fact.destructive);
            }
            other => panic!("expected RetentionPolicyChanged, got {other:?}"),
        }
    }

    /// The evidence window comes from the whole set, never one policy — with a
    /// second jurisdiction in play, anything narrower under-retains the evidence
    /// beneath the longest-lived artifact.
    #[test]
    fn the_plan_targets_the_widest_policy_in_the_set() {
        assert_eq!(
            plan(&TtlState::Absent, &policies()).target_days(),
            Some(policies().widest_evidence_days())
        );
    }
}
