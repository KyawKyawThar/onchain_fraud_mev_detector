//! Typed failures that carry **the decision**, not just the message
//! (conventions §3).
//!
//! Every failure in this crate answers one operational question, and the
//! answer is the whole reason the type exists:
//!
//! > *Will retrying this on the next cycle plausibly succeed without a human?*
//!
//! * [`BackupError::Transient`] — yes. A ClickHouse restart, a connection
//!   reset, a 503. The scheduled agent logs it, counts it, and tries again in
//!   fifteen minutes; the RPO gauge climbing is the escalation path if it keeps
//!   happening. **This must not page.**
//! * [`BackupError::Permanent`] — no. `pg_dump` is an older major than the
//!   server, the artifact directory is unwritable, a table's DDL cannot be
//!   replayed. The next hundred cycles fail identically, so silence here is a
//!   silent loss of the entire control. **This should page immediately**, long
//!   before the RPO budget expires.
//! * [`BackupError::Cancelled`] — neither. A drain during a rolling deploy is
//!   not a failure, and counting it as one would make every deployment look
//!   like a backup incident.
//!
//! Before this split, the agent logged all three identically and
//! `backup_runs_total{outcome="failure"}` could not tell "the database blipped"
//! from "no backup has been possible since the Postgres upgrade".
//!
//! ## Which way to guess
//!
//! Classification is a judgement, and the two mistakes are not symmetric.
//! Calling a permanent fault transient means the control quietly stops working
//! and nobody is told until the RPO budget expires — a silent gap in the one
//! thing standing between an incident and permanent data loss. Calling a
//! transient fault permanent means a spurious page. **So anything genuinely
//! ambiguous is classified `Permanent`**, and that bias is stated at each site
//! that guesses rather than left for a reader to infer.
//!
//! The Postgres side does not guess where it does not have to: `db::is_permanent`
//! is the workspace's one classifier for `sqlx::Error`, and using it here is
//! why this crate carries the `db` edge that arch-conformance requires — the
//! rule exists so retry decisions cannot drift between crates, and satisfying
//! it with an unused import would have been satisfying the lint instead of the
//! reason for it.

use std::fmt::Display;

/// A failure, plus what an operator should do about it.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// Shutdown was requested mid-operation. Not a failure.
    #[error("cancelled: {0}")]
    Cancelled(&'static str),

    /// Retrying later may work without human action.
    #[error("{0:#}")]
    Transient(anyhow::Error),

    /// Retrying will fail the same way. Needs a person.
    #[error("{0:#}")]
    Permanent(anyhow::Error),
}

impl BackupError {
    pub fn transient(err: impl Into<anyhow::Error>) -> Self {
        Self::Transient(err.into())
    }

    pub fn permanent(err: impl Into<anyhow::Error>) -> Self {
        Self::Permanent(err.into())
    }

    /// Build from a message alone, when there is no underlying error value.
    pub fn permanent_msg(msg: impl Display) -> Self {
        Self::Permanent(anyhow::anyhow!("{msg}"))
    }

    pub fn transient_msg(msg: impl Display) -> Self {
        Self::Transient(anyhow::anyhow!("{msg}"))
    }

    /// Add context **without losing the classification** — the reason this is
    /// a method and not a `.context()` on the inner `anyhow::Error`.
    pub fn context(self, msg: impl Display) -> Self {
        match self {
            Self::Cancelled(what) => Self::Cancelled(what),
            Self::Transient(err) => Self::Transient(err.context(msg.to_string())),
            Self::Permanent(err) => Self::Permanent(err.context(msg.to_string())),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }

    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_))
    }

    /// The `outcome` label for `backup_runs_total` / `backup_drill_runs_total`.
    /// Kept beside the type so a new variant cannot quietly go unlabelled.
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Cancelled(_) => "cancelled",
            Self::Transient(_) => "transient",
            Self::Permanent(_) => "permanent",
        }
    }
}

pub type Result<T> = std::result::Result<T, BackupError>;

/// Classify a `sqlx` failure through the workspace's one classifier.
pub fn from_sqlx(err: sqlx::Error, context: impl Display) -> BackupError {
    let permanent = db::is_permanent(&err);
    let err = anyhow::Error::new(err).context(context.to_string());
    if permanent {
        BackupError::Permanent(err)
    } else {
        BackupError::Transient(err)
    }
}

/// Classify a `reqwest` transport failure.
///
/// Connect/timeout/request errors are the network being the network. A body or
/// decode error is a response this build could not understand, which will not
/// improve on retry.
pub fn from_reqwest(err: reqwest::Error, context: impl Display) -> BackupError {
    let transient = err.is_timeout() || err.is_connect() || err.is_request();
    let err = anyhow::Error::new(err).context(context.to_string());
    if transient {
        BackupError::Transient(err)
    } else {
        BackupError::Permanent(err)
    }
}

/// Classify an HTTP status from ClickHouse.
///
/// 5xx and 429 are the server saying "not now"; ClickHouse answers a bad query
/// or an unknown table with 400, and no amount of waiting fixes SQL.
pub fn from_status(status: reqwest::StatusCode, body: &str, context: impl Display) -> BackupError {
    let err = anyhow::anyhow!("ClickHouse returned {status}: {}", body.trim())
        .context(context.to_string());
    if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        BackupError::Transient(err)
    } else {
        BackupError::Permanent(err)
    }
}

/// Classify an `std::io` failure around the artifact store.
///
/// A full or read-only volume is `Permanent` on purpose even though someone
/// could free space: the agent cannot fix it, and a backup that has been
/// failing on ENOSPC for a week is exactly the silence this crate exists to
/// break.
pub fn from_io(err: std::io::Error, context: impl Display) -> BackupError {
    BackupError::Permanent(anyhow::Error::new(err).context(context.to_string()))
}

/// Adapt an `anyhow`-shaped internal helper at the seam, choosing the safer
/// classification. See "Which way to guess" in the module docs.
pub fn permanent_unless_known(err: anyhow::Error) -> BackupError {
    BackupError::Permanent(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_survives_classification() {
        // The bug this method prevents: `.context()` on the inner anyhow error
        // returns an anyhow::Error, so the natural spelling silently downgrades
        // a Permanent to whatever the next `?` decides.
        let err = BackupError::permanent_msg("pg_dump is too old").context("snapshotting postgres");
        assert!(err.is_permanent());
        assert!(err.to_string().contains("snapshotting postgres"));

        let err = BackupError::transient_msg("connection reset").context("reading events");
        assert!(!err.is_permanent());
        assert_eq!(err.outcome(), "transient");
    }

    #[test]
    fn a_drain_is_not_a_failure() {
        // Counting a rolling deploy as a backup failure makes every deployment
        // look like an incident, which is how a real one gets ignored.
        let err = BackupError::Cancelled("snapshot");
        assert!(err.is_cancelled());
        assert!(!err.is_permanent());
        assert_eq!(err.outcome(), "cancelled");
    }

    #[test]
    fn http_statuses_split_on_who_can_fix_them() {
        assert!(!from_status(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "dumping events"
        )
        .is_permanent());
        assert!(!from_status(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            "slow down",
            "dumping events"
        )
        .is_permanent());
        // ClickHouse answers a malformed query with 400 — waiting never helps.
        assert!(from_status(
            reqwest::StatusCode::BAD_REQUEST,
            "Cannot parse input",
            "restoring events"
        )
        .is_permanent());
    }

    #[test]
    fn a_full_disk_is_permanent_because_the_agent_cannot_fix_it() {
        let err = from_io(
            std::io::Error::new(std::io::ErrorKind::StorageFull, "no space left on device"),
            "writing dump.pgc",
        );
        assert!(err.is_permanent());
        assert!(err.to_string().contains("writing dump.pgc"));
    }
}
