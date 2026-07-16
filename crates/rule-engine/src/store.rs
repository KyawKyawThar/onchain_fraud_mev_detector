//! The Postgres rule-definition store (§9, §14, Sprint 9 t1), behind the
//! object-safe [`RuleStore`] seam so the t2–t5 consumers (compiler, temporal
//! state machines, the `POST /v1/rules` surface) are tested against the
//! in-memory double with no database — mirroring `intelligence::store`.
//!
//! **Customer isolation is the store's contract, not the caller's care.**
//! Every customer-facing operation takes the acting `owner` and keys the query
//! on `(owner, rule_id)`; a probe against another customer's rule id reads as
//! "not found", indistinguishable from a rule that never existed — no
//! existence leak, no cross-customer mutation, regardless of what a buggy or
//! hostile caller passes. The one deliberate exception is
//! [`RuleStore::enabled_rules`], the engine's internal evaluation-load path:
//! it crosses owners by design (the engine evaluates every customer's rules)
//! and must never back a public endpoint.
//!
//! Write discipline mirrors the other stores: creates are keyed on `rule_id`
//! so a redelivered create is an idempotent no-op; deletes are soft
//! (`deleted_at`, audit-preserving); an invalid rule is rejected *here*
//! ([`Rule::validate`]) so bad definitions can never land in the table.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{CustomerId, RuleId};
use sqlx::types::Uuid;
use sqlx::PgPool;

use crate::model::{InvalidRule, LogicOp, Rule};

/// A failure reading or writing the rule store. Carries the retry/skip
/// *decision* (its [`event_bus::Transience`] impl) so every consumer handles
/// faults uniformly — the same contract as the intelligence and simulation
/// stores.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A Postgres round-trip failed. Usually transient (connection/pool/
    /// server), but an encoding/schema fault is a bug that fails identically
    /// on every retry.
    #[error("postgres round-trip failed")]
    Postgres(#[from] sqlx::Error),

    /// The rule definition failed [`Rule::validate`] — rejected before any
    /// write. Permanent: the same definition fails the same way every time.
    #[error("rule definition is invalid: {0}")]
    Invalid(#[from] InvalidRule),

    /// A stored value no longer parses into its domain type (a JSONB document
    /// or logic string written by a newer/older build). Permanent: the row
    /// itself is bad, retrying re-reads the same bytes.
    #[error("stored value is malformed: {what}")]
    Malformed { what: String },
}

impl StoreError {
    fn malformed(what: impl Into<String>) -> Self {
        StoreError::Malformed { what: what.into() }
    }
}

impl event_bus::Transience for StoreError {
    /// Whether retrying the same operation could plausibly succeed later.
    /// Postgres faults classify through the shared [`db::is_permanent`] so the
    /// decision can't drift across services (§4).
    fn is_transient(&self) -> bool {
        match self {
            StoreError::Invalid(_) | StoreError::Malformed { .. } => false,
            StoreError::Postgres(err) => !db::is_permanent(err),
        }
    }
}

/// What creating a rule did. Speaks the domain so the `POST /v1/rules`
/// surface (t4) can branch (201/200/409) without decoding SQL constraint
/// violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateRuleOutcome {
    /// The rule was written.
    Created,
    /// This `rule_id` is already stored (live or soft-deleted — ids are never
    /// reused): an idempotent redelivery no-op. Nothing was overwritten.
    AlreadyExists,
    /// The owner already has a *different* live rule with this name (the
    /// per-customer unique-name constraint); nothing was written.
    NameTaken,
}

/// Customer-defined rule definitions (§9), customer-isolated by construction —
/// see the module docs for the isolation contract.
#[async_trait]
pub trait RuleStore: Send + Sync {
    /// Insert a rule, keyed by its `rule_id`, after validating it
    /// ([`Rule::validate`] — an invalid definition is a [`StoreError::Invalid`]
    /// and never touches the table). The rule's own `owner` field is the
    /// isolation scope; `at` stamps `created_at`/`updated_at`.
    async fn create_rule(
        &self,
        rule: &Rule,
        at: DateTime<Utc>,
    ) -> Result<CreateRuleOutcome, StoreError>;

    /// One of `owner`'s live rules by id. `None` when the id doesn't exist,
    /// is deleted, **or belongs to another customer** — deliberately
    /// indistinguishable.
    async fn rule(&self, owner: CustomerId, rule_id: RuleId) -> Result<Option<Rule>, StoreError>;

    /// All of `owner`'s live rules (enabled and disabled — this is the
    /// customer's management view, not the evaluation set), oldest first.
    async fn rules_for_owner(&self, owner: CustomerId) -> Result<Vec<Rule>, StoreError>;

    /// Enable/disable one of `owner`'s live rules. Returns `false` when the
    /// rule doesn't exist for this owner (or is deleted) — and also when it
    /// already had the requested state, so a redelivered toggle is a visible
    /// no-op either way.
    async fn set_enabled(
        &self,
        owner: CustomerId,
        rule_id: RuleId,
        enabled: bool,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError>;

    /// Soft-delete one of `owner`'s rules (the row is kept for audit; the
    /// name becomes reusable). Returns `false` when there was nothing live to
    /// delete for this owner — idempotent.
    async fn delete_rule(
        &self,
        owner: CustomerId,
        rule_id: RuleId,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError>;

    /// Every enabled, live rule across **all** customers — the engine's
    /// evaluation-load path (boot + refresh), the one deliberate crossing of
    /// the owner boundary. Internal only: never expose through a
    /// customer-facing surface.
    async fn enabled_rules(&self) -> Result<Vec<Rule>, StoreError>;
}

/// Postgres-backed [`RuleStore`]. Cheap to clone (the pool is an `Arc`
/// internally).
#[derive(Clone)]
pub struct PgRuleStore {
    pool: PgPool,
}

impl PgRuleStore {
    /// Wrap a connection pool (see [`db::connect`]).
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Liveness probe for boot-time fail-fast: proves the database is
    /// reachable and the rule schema is applied.
    pub async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query!("SELECT 1 AS one FROM rules LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Raw row type ─────────────────────────────────────────────────
// The single boundary where stored JSONB/strings become the validated model
// ("parse, don't validate"), shared by every query over the table.

/// A `rules` row as stored.
struct RuleRow {
    rule_id: Uuid,
    owner: Uuid,
    name: String,
    enabled: bool,
    conditions: serde_json::Value,
    logic: String,
    temporal: Option<serde_json::Value>,
    actions: serde_json::Value,
}

impl TryFrom<RuleRow> for Rule {
    type Error = StoreError;

    fn try_from(row: RuleRow) -> Result<Self, StoreError> {
        let logic: LogicOp = row.logic.parse().map_err(|_| {
            StoreError::malformed(format!("logic {:?} is not a known variant", row.logic))
        })?;
        Ok(Rule {
            id: RuleId(row.rule_id),
            owner: CustomerId(row.owner),
            name: row.name,
            enabled: row.enabled,
            conditions: serde_json::from_value(row.conditions)
                .map_err(|err| StoreError::malformed(format!("stored conditions: {err}")))?,
            logic,
            temporal: row
                .temporal
                .map(serde_json::from_value)
                .transpose()
                .map_err(|err| StoreError::malformed(format!("stored temporal clause: {err}")))?,
            actions: serde_json::from_value(row.actions)
                .map_err(|err| StoreError::malformed(format!("stored actions: {err}")))?,
        })
    }
}

/// The name-uniqueness partial index (see the migration); a 23505 on it means
/// [`CreateRuleOutcome::NameTaken`], anything else is a real fault.
const OWNER_NAME_LIVE_IDX: &str = "rules_owner_name_live_idx";

#[async_trait]
impl RuleStore for PgRuleStore {
    async fn create_rule(
        &self,
        rule: &Rule,
        at: DateTime<Utc>,
    ) -> Result<CreateRuleOutcome, StoreError> {
        rule.validate()?;
        let conditions = serde_json::to_value(&rule.conditions)
            .map_err(|err| StoreError::malformed(format!("encoding conditions: {err}")))?;
        let temporal = rule
            .temporal
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|err| StoreError::malformed(format!("encoding temporal clause: {err}")))?;
        let actions = serde_json::to_value(&rule.actions)
            .map_err(|err| StoreError::malformed(format!("encoding actions: {err}")))?;

        let result = sqlx::query!(
            "INSERT INTO rules (rule_id, owner, name, enabled, conditions, logic,
                                temporal, actions, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
             ON CONFLICT (rule_id) DO NOTHING",
            rule.id.0,
            rule.owner.0,
            rule.name,
            rule.enabled,
            conditions,
            <&str>::from(rule.logic),
            temporal,
            actions,
            at,
        )
        .execute(&self.pool)
        .await;

        match result {
            Ok(done) if done.rows_affected() == 1 => Ok(CreateRuleOutcome::Created),
            Ok(_) => Ok(CreateRuleOutcome::AlreadyExists),
            // The partial unique index on (owner, name) fired: same owner,
            // different rule_id, same live name.
            Err(sqlx::Error::Database(db_err))
                if db_err.constraint() == Some(OWNER_NAME_LIVE_IDX) =>
            {
                Ok(CreateRuleOutcome::NameTaken)
            }
            Err(err) => Err(err.into()),
        }
    }

    async fn rule(&self, owner: CustomerId, rule_id: RuleId) -> Result<Option<Rule>, StoreError> {
        // `owner` in the WHERE clause *is* the isolation guarantee: another
        // customer's rule id reads as absent.
        let Some(row) = sqlx::query_as!(
            RuleRow,
            r#"SELECT rule_id, owner, name, enabled,
                      conditions AS "conditions: serde_json::Value", logic,
                      temporal AS "temporal: serde_json::Value",
                      actions AS "actions: serde_json::Value"
               FROM rules
               WHERE rule_id = $1 AND owner = $2 AND deleted_at IS NULL"#,
            rule_id.0,
            owner.0,
        )
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        Ok(Some(row.try_into()?))
    }

    async fn rules_for_owner(&self, owner: CustomerId) -> Result<Vec<Rule>, StoreError> {
        let rows = sqlx::query_as!(
            RuleRow,
            r#"SELECT rule_id, owner, name, enabled,
                      conditions AS "conditions: serde_json::Value", logic,
                      temporal AS "temporal: serde_json::Value",
                      actions AS "actions: serde_json::Value"
               FROM rules
               WHERE owner = $1 AND deleted_at IS NULL
               ORDER BY created_at, rule_id"#,
            owner.0,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn set_enabled(
        &self,
        owner: CustomerId,
        rule_id: RuleId,
        enabled: bool,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query!(
            "UPDATE rules SET enabled = $3, updated_at = $4
             WHERE rule_id = $1 AND owner = $2 AND deleted_at IS NULL
               AND enabled IS DISTINCT FROM $3",
            rule_id.0,
            owner.0,
            enabled,
            at,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete_rule(
        &self,
        owner: CustomerId,
        rule_id: RuleId,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query!(
            "UPDATE rules SET deleted_at = $3, updated_at = $3
             WHERE rule_id = $1 AND owner = $2 AND deleted_at IS NULL",
            rule_id.0,
            owner.0,
            at,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn enabled_rules(&self) -> Result<Vec<Rule>, StoreError> {
        let rows = sqlx::query_as!(
            RuleRow,
            r#"SELECT rule_id, owner, name, enabled,
                      conditions AS "conditions: serde_json::Value", logic,
                      temporal AS "temporal: serde_json::Value",
                      actions AS "actions: serde_json::Value"
               FROM rules
               WHERE enabled AND deleted_at IS NULL
               ORDER BY created_at, rule_id"#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }
}
