//! Customer-authored decision-policy store (§11, Sprint 14 t2): the
//! Postgres-backed home for the named policies a customer defines beyond the
//! built-in catalog (`crate::screen::builtin_policy`) — behind the
//! object-safe [`PolicyStore`] seam so `screen_address` and the
//! policy-management handlers are tested against the in-memory double with
//! no database, mirroring `rule_engine::store`.
//!
//! **Versions are immutable and append-only.** [`PolicyStore::upsert_policy`]
//! never updates a row in place — a genuine change inserts a new `version`
//! for `(owner, name)`, one greater than whatever came before, and nothing
//! here ever deletes or overwrites one. This is what lets a screening
//! verdict's `(policy_name, policy_version)` (see `crate::screen::Verdict`)
//! always resolve back to the exact thresholds that produced it, even after
//! the customer retunes the policy. `resolve` reads the latest version.
//! Because the history is meant to capture *changes*, `upsert_policy` is
//! idempotent: re-submitting the current thresholds mints no new version
//! (`PUT` semantics), so a retry or a double-submit can't inflate the trail.
//! The read-latest → dedup → append sequence is serialised per `(owner,
//! name)` (a Postgres transaction-scoped advisory lock) so concurrent
//! writers can't race the version.
//!
//! **Customer isolation** follows the same discipline as `RuleStore`: every
//! operation is keyed on the acting `owner`, so a probe against another
//! customer's policy name reads as "not defined" — indistinguishable from a
//! name nobody has ever used.
//!
//! **Built-in names are reserved.** [`resolve`](PolicyStore::resolve) checks
//! `crate::screen::builtin_policy` first (no I/O) and only falls through to
//! this store for everything else; [`upsert_policy`](PolicyStore::upsert_policy)
//! refuses to let a customer create or shadow `default`/`strict`/
//! `monitor-only`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::CustomerId;
use sqlx::PgPool;

use crate::screen::{InvalidPolicy, Policy, Thresholds};

/// A failure reading or writing the policy store. Carries the retry/skip
/// *decision* (its [`event_bus::Transience`] impl) so every consumer handles
/// faults uniformly — the same contract as the rule and intelligence stores.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A Postgres round-trip failed. Usually transient (connection/pool/
    /// server), but an encoding/schema fault is a bug that fails identically
    /// on every retry.
    #[error("postgres round-trip failed")]
    Postgres(#[from] sqlx::Error),

    /// The threshold pair failed [`Policy::new`]'s validation — rejected
    /// before any write.
    #[error("policy definition is invalid: {0}")]
    Invalid(#[from] InvalidPolicy),

    /// The requested name belongs to the built-in catalog
    /// (`crate::screen::BUILTIN_POLICY_NAMES`) — a customer can never create
    /// or overwrite one of these.
    #[error("policy name {0:?} is reserved for the built-in catalog")]
    ReservedName(String),

    /// A stored row no longer parses into [`Policy`] (out-of-range threshold
    /// written by a newer/older build). Permanent: the row itself is bad,
    /// retrying re-reads the same bytes.
    #[error("stored value is malformed: {what}")]
    Malformed { what: String },
}

impl StoreError {
    fn malformed(what: impl Into<String>) -> Self {
        StoreError::Malformed { what: what.into() }
    }
}

impl event_bus::Transience for StoreError {
    fn is_transient(&self) -> bool {
        match self {
            StoreError::Invalid(_) | StoreError::ReservedName(_) | StoreError::Malformed { .. } => {
                false
            }
            StoreError::Postgres(err) => !db::is_permanent(err),
        }
    }
}

/// Map a [`StoreError`] to the caller's HTTP error, the same discipline as
/// `crate::intelligence_client::to_api_error`: 400 for anything the caller
/// could have avoided (bad thresholds, a reserved name), 502 for a
/// transient storage fault (retry may help), 500 for anything else (a
/// platform bug, never an invitation to retry).
pub fn to_api_error(err: StoreError) -> api_error::ApiError {
    use event_bus::Transience;
    match err {
        StoreError::Invalid(_) | StoreError::ReservedName(_) => api_error::ApiError::bad_request(err),
        StoreError::Postgres(_) if err.is_transient() => api_error::ApiError::bad_gateway(err),
        StoreError::Postgres(_) | StoreError::Malformed { .. } => api_error::ApiError::internal(err),
    }
}

/// Reject a customer-authored policy write before it ever reaches storage:
/// the name must not be one of the built-ins, and the threshold pair must
/// pass [`Thresholds::new`]'s validation. Returns the validated
/// [`Thresholds`] value object so the caller writes (and dedup-compares)
/// against a pair that's already provably in range — no fake version, no
/// re-validation. Shared by every [`PolicyStore`] implementation so the two
/// never drift.
fn validate_custom_policy(
    name: &str,
    review_at: u8,
    block_at: Option<u8>,
) -> Result<Thresholds, StoreError> {
    if Policy::is_builtin_name(name) {
        return Err(StoreError::ReservedName(name.to_owned()));
    }
    Ok(Thresholds::new(review_at, block_at)?)
}

/// Customer-authored decision policies (§11, Sprint 14 t2), customer-isolated
/// and append-only versioned — see the module docs for both contracts.
#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// Resolve the policy `owner` means by `name`: the built-in catalog first
    /// (no I/O), then `owner`'s latest version of a custom policy by that
    /// name. `None` when `name` is neither.
    async fn resolve(&self, owner: CustomerId, name: &str) -> Result<Option<Policy>, StoreError> {
        if let Some(builtin) = crate::screen::builtin_policy(name) {
            return Ok(Some(builtin));
        }
        self.custom_policy(owner, name).await
    }

    /// `owner`'s latest version of a custom policy named `name` — `None`
    /// when they've never defined one by that name. Implementers only need
    /// to know their own table; [`resolve`](Self::resolve)'s default method
    /// is what checks the built-in catalog first.
    async fn custom_policy(&self, owner: CustomerId, name: &str)
        -> Result<Option<Policy>, StoreError>;

    /// Create or retune one of `owner`'s custom policies.
    ///
    /// **Idempotent** (`PUT` semantics): if `name`'s current latest version
    /// already carries these exact thresholds, no new version is written and
    /// the current one is returned unchanged — a retry or a double-submit
    /// isn't a "change", and the append-only history records only real
    /// changes. Otherwise a **new** version is written, one greater than the
    /// current latest (or 1 if none exists yet); see the module docs on why
    /// versions are append-only.
    ///
    /// Rejects a built-in name or an invalid threshold pair before writing
    /// anything ([`validate_custom_policy`]).
    async fn upsert_policy(
        &self,
        owner: CustomerId,
        name: &str,
        review_at: u8,
        block_at: Option<u8>,
        at: DateTime<Utc>,
    ) -> Result<Policy, StoreError>;

    /// `owner`'s custom policies, each at its latest version — the
    /// management view (`GET /v1/policies`). Never includes the built-in
    /// catalog (it's static and needs no listing) and never crosses owners.
    async fn policies_for_owner(&self, owner: CustomerId) -> Result<Vec<Policy>, StoreError>;
}

/// Postgres-backed [`PolicyStore`]. Cheap to clone (the pool is an `Arc`
/// internally).
#[derive(Clone)]
pub struct PgPolicyStore {
    pool: PgPool,
}

impl PgPolicyStore {
    /// Wrap a connection pool (see [`db::connect`]).
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Liveness probe for boot-time fail-fast: proves the database is
    /// reachable and the policy schema is applied.
    pub async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query!("SELECT 1 AS one FROM screening_policies LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Raw row type ─────────────────────────────────────────────────
// The single boundary where stored SMALLINTs become the validated `Policy`
// ("parse, don't validate"), shared by every query over the table.

struct PolicyRow {
    name: String,
    version: i32,
    review_at: i16,
    block_at: Option<i16>,
}

impl TryFrom<PolicyRow> for Policy {
    type Error = StoreError;

    fn try_from(row: PolicyRow) -> Result<Self, StoreError> {
        let review_at = u8::try_from(row.review_at).map_err(|_| {
            StoreError::malformed(format!("review_at {} out of 0..=255 range", row.review_at))
        })?;
        let block_at = row
            .block_at
            .map(u8::try_from)
            .transpose()
            .map_err(|_| StoreError::malformed("block_at out of 0..=255 range"))?;
        Policy::new(row.name, row.version, review_at, block_at).map_err(StoreError::from)
    }
}

#[async_trait]
impl PolicyStore for PgPolicyStore {
    async fn custom_policy(
        &self,
        owner: CustomerId,
        name: &str,
    ) -> Result<Option<Policy>, StoreError> {
        let Some(row) = sqlx::query_as!(
            PolicyRow,
            r#"SELECT name, version, review_at, block_at
               FROM screening_policies
               WHERE owner = $1 AND name = $2
               ORDER BY version DESC
               LIMIT 1"#,
            owner.0,
            name,
        )
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        Ok(Some(row.try_into()?))
    }

    async fn upsert_policy(
        &self,
        owner: CustomerId,
        name: &str,
        review_at: u8,
        block_at: Option<u8>,
        at: DateTime<Utc>,
    ) -> Result<Policy, StoreError> {
        let thresholds = validate_custom_policy(name, review_at, block_at)?;

        let mut tx = self.pool.begin().await?;

        // Serialize concurrent upserts of the *same* (owner, name): the
        // read-latest → dedup → insert-next-version sequence below has to be
        // atomic, or two racing writers both read the same latest, both
        // compute the same next version (one then fails the unique index with
        // a 23505 the caller sees as a misleading 502), and — worse for the
        // idempotency contract — two identical-threshold writers could both
        // decide to append. A transaction-scoped advisory lock keyed on
        // (owner, name) serialises exactly that pair; it's released at
        // commit/rollback. `hashtext` is computed in Postgres (not in the
        // app) so the key is stable across a rolling deploy of mixed binary
        // versions. A hash collision between two *different* pairs only ever
        // over-serialises (harmless), never corrupts; the hot read path
        // (`custom_policy`/`resolve`) takes no lock and is never blocked.
        sqlx::query!(
            "SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))",
            owner.0.to_string(),
            name,
        )
        .execute(&mut *tx)
        .await?;

        let latest = sqlx::query_as!(
            PolicyRow,
            r#"SELECT name, version, review_at, block_at
               FROM screening_policies
               WHERE owner = $1 AND name = $2
               ORDER BY version DESC
               LIMIT 1"#,
            owner.0,
            name,
        )
        .fetch_optional(&mut *tx)
        .await?;

        let next_version = match latest {
            Some(row) => {
                let current: Policy = row.try_into()?;
                // Idempotent PUT: identical thresholds don't mint a new
                // version (see the trait docs) — return the current one.
                if current.thresholds == thresholds {
                    tx.commit().await?;
                    return Ok(current);
                }
                current.version + 1
            }
            None => 1,
        };

        let row = sqlx::query_as!(
            PolicyRow,
            r#"INSERT INTO screening_policies (owner, name, version, review_at, block_at, created_at)
               VALUES ($1, $2, $3, $4, $5, $6)
               RETURNING name, version, review_at, block_at"#,
            owner.0,
            name,
            next_version,
            i16::from(thresholds.review_at()),
            thresholds.block_at().map(i16::from),
            at,
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        row.try_into()
    }

    async fn policies_for_owner(&self, owner: CustomerId) -> Result<Vec<Policy>, StoreError> {
        // DISTINCT ON (name), ordered (name, version DESC): exactly one row
        // per name, the highest version.
        let rows = sqlx::query_as!(
            PolicyRow,
            r#"SELECT DISTINCT ON (name) name, version, review_at, block_at
               FROM screening_policies
               WHERE owner = $1
               ORDER BY name, version DESC"#,
            owner.0,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }
}

/// The in-memory [`PolicyStore`] double — honours the same semantics the
/// Postgres implementation promises (append-only versioning, per-owner
/// isolation, reserved built-in names) so a test that passes here means the
/// consumer logic is right. Compiled for this crate's own unit tests and,
/// behind the `test-util` feature, for its integration tests
/// (`tests/ws_stream.rs`) — mirrors `rule_engine::test_util`.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    pub struct InMemoryPolicyStore {
        inner: Mutex<Vec<(CustomerId, Policy)>>,
    }

    impl InMemoryPolicyStore {
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl PolicyStore for InMemoryPolicyStore {
        async fn custom_policy(
            &self,
            owner: CustomerId,
            name: &str,
        ) -> Result<Option<Policy>, StoreError> {
            let state = self.inner.lock().expect("store lock");
            Ok(state
                .iter()
                .filter(|(o, p)| *o == owner && p.name == name)
                .max_by_key(|(_, p)| p.version)
                .map(|(_, p)| p.clone()))
        }

        async fn upsert_policy(
            &self,
            owner: CustomerId,
            name: &str,
            review_at: u8,
            block_at: Option<u8>,
            _at: DateTime<Utc>,
        ) -> Result<Policy, StoreError> {
            let thresholds = validate_custom_policy(name, review_at, block_at)?;
            let mut state = self.inner.lock().expect("store lock");
            // The `Mutex` is this double's analogue of the Pg advisory lock:
            // the read-latest → dedup → append sequence runs uncontended.
            let latest = state
                .iter()
                .filter(|(o, p)| *o == owner && p.name == name)
                .max_by_key(|(_, p)| p.version)
                .map(|(_, p)| p.clone());
            if let Some(current) = &latest {
                // Idempotent PUT: identical thresholds → no new version.
                if current.thresholds == thresholds {
                    return Ok(current.clone());
                }
            }
            let next_version = latest.map(|p| p.version).unwrap_or(0) + 1;
            let policy = Policy::with_thresholds(name, next_version, thresholds)?;
            state.push((owner, policy.clone()));
            Ok(policy)
        }

        async fn policies_for_owner(&self, owner: CustomerId) -> Result<Vec<Policy>, StoreError> {
            let state = self.inner.lock().expect("store lock");
            let mut names: Vec<String> = state
                .iter()
                .filter(|(o, _)| *o == owner)
                .map(|(_, p)| p.name.clone())
                .collect();
            names.sort();
            names.dedup();
            Ok(names
                .into_iter()
                .filter_map(|name| {
                    state
                        .iter()
                        .filter(|(o, p)| *o == owner && p.name == name)
                        .max_by_key(|(_, p)| p.version)
                        .map(|(_, p)| p.clone())
                })
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::InMemoryPolicyStore;
    use super::*;

    fn owner(n: u8) -> CustomerId {
        CustomerId(uuid::Uuid::from_u128(n as u128))
    }

    #[tokio::test]
    async fn resolve_finds_builtins_without_touching_the_store() {
        let store = InMemoryPolicyStore::new();
        let policy = store.resolve(owner(1), "strict").await.unwrap().unwrap();
        assert_eq!(policy.name, "strict");
        assert_eq!(policy.version, 1);
    }

    #[tokio::test]
    async fn resolve_falls_through_to_a_customers_own_policy() {
        let store = InMemoryPolicyStore::new();
        store
            .upsert_policy(owner(1), "acme-strict", 10, Some(60), Utc::now())
            .await
            .unwrap();

        let policy = store
            .resolve(owner(1), "acme-strict")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(policy.version, 1);
        assert_eq!(policy.thresholds.review_at(), 10);
        assert_eq!(policy.thresholds.block_at(), Some(60));

        // Unknown to both the catalog and this owner.
        assert!(store.resolve(owner(1), "nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn upsert_is_append_only_and_versions_climb() {
        let store = InMemoryPolicyStore::new();
        let v1 = store
            .upsert_policy(owner(1), "acme", 10, Some(60), Utc::now())
            .await
            .unwrap();
        assert_eq!(v1.version, 1);

        let v2 = store
            .upsert_policy(owner(1), "acme", 15, Some(70), Utc::now())
            .await
            .unwrap();
        assert_eq!(v2.version, 2);

        // resolve/custom_policy read the latest version only.
        let latest = store.resolve(owner(1), "acme").await.unwrap().unwrap();
        assert_eq!(latest.version, 2);
        assert_eq!(latest.thresholds.review_at(), 15);
    }

    /// Idempotent PUT: re-submitting the *same* thresholds is a no-op that
    /// returns the current version — the append-only history records changes,
    /// not retries. A genuine change still climbs.
    #[tokio::test]
    async fn upsert_with_unchanged_thresholds_does_not_mint_a_new_version() {
        let store = InMemoryPolicyStore::new();
        let v1 = store
            .upsert_policy(owner(1), "acme", 10, Some(60), Utc::now())
            .await
            .unwrap();
        assert_eq!(v1.version, 1);

        // Same thresholds again → still version 1, nothing appended.
        let again = store
            .upsert_policy(owner(1), "acme", 10, Some(60), Utc::now())
            .await
            .unwrap();
        assert_eq!(again.version, 1);
        assert_eq!(store.policies_for_owner(owner(1)).await.unwrap().len(), 1);

        // A real change climbs to version 2.
        let v2 = store
            .upsert_policy(owner(1), "acme", 10, Some(55), Utc::now())
            .await
            .unwrap();
        assert_eq!(v2.version, 2);
    }

    #[tokio::test]
    async fn upsert_rejects_a_reserved_builtin_name() {
        let store = InMemoryPolicyStore::new();
        let err = store
            .upsert_policy(owner(1), "default", 10, Some(60), Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::ReservedName(name) if name == "default"));
    }

    #[tokio::test]
    async fn upsert_rejects_an_invalid_threshold_pair() {
        let store = InMemoryPolicyStore::new();
        let err = store
            .upsert_policy(owner(1), "acme", 80, Some(40), Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)));
    }

    #[tokio::test]
    async fn policies_are_isolated_per_owner() {
        let store = InMemoryPolicyStore::new();
        store
            .upsert_policy(owner(1), "acme", 10, Some(60), Utc::now())
            .await
            .unwrap();

        assert!(store
            .policies_for_owner(owner(2))
            .await
            .unwrap()
            .is_empty());
        assert!(store.resolve(owner(2), "acme").await.unwrap().is_none());
        assert_eq!(store.policies_for_owner(owner(1)).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn policies_for_owner_lists_each_name_at_its_latest_version_only() {
        let store = InMemoryPolicyStore::new();
        store
            .upsert_policy(owner(1), "acme", 10, Some(60), Utc::now())
            .await
            .unwrap();
        store
            .upsert_policy(owner(1), "acme", 20, Some(70), Utc::now())
            .await
            .unwrap();
        store
            .upsert_policy(owner(1), "beta", 5, None, Utc::now())
            .await
            .unwrap();

        let mut policies = store.policies_for_owner(owner(1)).await.unwrap();
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].name, "acme");
        assert_eq!(policies[0].version, 2);
        assert_eq!(policies[1].name, "beta");
        assert_eq!(policies[1].version, 1);
    }
}
