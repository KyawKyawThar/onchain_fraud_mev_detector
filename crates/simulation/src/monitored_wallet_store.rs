//! The opt-in "monitored wallet" list (§25, Sprint 15 t5): a customer names
//! an address they want a scheduled MEV-exposure report pushed for
//! (`crate::exposure_report`). Owned here — not `crates/server` — because the
//! scheduler that reads it runs in this crate's `simulation-projection`
//! binary, alongside the already-connected `WalletExposureStore` it feeds
//! into; the public API service reaches it over that binary's internal HTTP
//! surface (`crate::http`), the same proxy shape
//! `wallet_mev_exposure`/`timing_recommendation` already use for reads.
//!
//! Customer isolation follows the same discipline as `RuleStore`/`PolicyStore`:
//! every customer-facing operation is keyed on the acting `owner`, so a probe
//! against another customer's monitored address reads as "not found".
//! [`MonitoredWalletStore::list_all`] is the one deliberate exception — the
//! scheduler's own read, which by design crosses owners.
//!
//! [`list_all`](MonitoredWalletStore::list_all) is keyset-paginated
//! (`MonitoredWalletCursor`/`MonitoredWalletPage`), the same `(sort_key, id) >
//! (cursor)` discipline `store::IncidentCursor` uses for `GET /v1/incidents`
//! — a full unpaginated scan here would mean the scheduler (`crate::exposure_report`)
//! holds every monitored wallet in memory at once and a single slow page can't
//! be bounded, neither of which holds once the table is large.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, Chain, CustomerId};
use sqlx::PgPool;

use crate::store::PersistError;

/// Whether [`MonitoredWalletStore::add`] created a new row or the pair was
/// already monitored — lets the HTTP handler answer 201 vs 200 without a
/// separate existence check (mirrors `CreateRuleOutcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOutcome {
    Added,
    AlreadyMonitored,
}

/// One opted-in wallet. `id` is the row's own identity (never exposed on the
/// customer-facing wire form — see `http::MonitoredWalletDto`) — it exists so
/// [`MonitoredWalletCursor`] has a total tiebreaker: `created_at` alone isn't
/// unique, and two wallets opted in at the same wall-clock millisecond must
/// still resolve to a stable page order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitoredWallet {
    pub id: i64,
    pub owner: CustomerId,
    pub chain: Chain,
    pub address: AccountAddress,
    pub created_at: DateTime<Utc>,
}

/// A keyset cursor into [`MonitoredWalletStore::list_all`]'s `(created_at,
/// id)` sort order — mirrors `store::IncidentCursor`. Never crosses an HTTP
/// boundary (unlike `IncidentCursor`, which the customer-facing `/v1/incidents`
/// listing encodes as an opaque token) — it only ever travels from one
/// `list_all` call's [`MonitoredWalletPage::next_cursor`] to the next, inside
/// `crate::exposure_report::run_cycle`, so a plain struct is enough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitoredWalletCursor {
    pub created_at: DateTime<Utc>,
    pub id: i64,
}

/// One page of [`MonitoredWalletStore::list_all`] results plus where to
/// resume. `next_cursor` is `Some` iff this page was full and more rows may
/// follow, so a caller can always tell a complete result from a truncated one
/// (mirrors `store::IncidentPage`).
#[derive(Debug)]
pub struct MonitoredWalletPage {
    pub wallets: Vec<MonitoredWallet>,
    pub next_cursor: Option<MonitoredWalletCursor>,
}

#[async_trait]
pub trait MonitoredWalletStore: Send + Sync {
    /// Opt `address` in for `owner`. Idempotent: opting the same
    /// `(owner, chain, address)` in twice returns
    /// [`AddOutcome::AlreadyMonitored`] rather than erroring or duplicating
    /// the row.
    async fn add(
        &self,
        owner: CustomerId,
        chain: Chain,
        address: AccountAddress,
        at: DateTime<Utc>,
    ) -> Result<AddOutcome, PersistError>;

    /// Opt out. `true` if a row was removed, `false` if `owner` never had
    /// this pair monitored (indistinguishable, by design, from a pair that
    /// belongs to another owner).
    async fn remove(
        &self,
        owner: CustomerId,
        chain: Chain,
        address: AccountAddress,
    ) -> Result<bool, PersistError>;

    /// `owner`'s own monitored wallets — the management view
    /// (`GET /v1/monitored-wallets`). Never crosses owners. Unpaginated: this
    /// is bounded by one customer's own opt-in count, the same posture
    /// `PolicyStore::policies_for_owner` takes for a customer's own policies.
    async fn list_for_owner(&self, owner: CustomerId)
        -> Result<Vec<MonitoredWallet>, PersistError>;

    /// One page of every monitored wallet, across every owner, ordered by
    /// `(created_at, id)` — the scheduler's own read (`crate::exposure_report`).
    /// The one operation that deliberately crosses owners; never back a
    /// customer-facing endpoint with this. `after` resumes past a previous
    /// page's [`MonitoredWalletPage::next_cursor`]; `limit` bounds how many
    /// rows this call returns (the caller — `exposure_report::run_cycle` —
    /// owns looping across pages).
    async fn list_all(
        &self,
        after: Option<MonitoredWalletCursor>,
        limit: u64,
    ) -> Result<MonitoredWalletPage, PersistError>;
}

fn parse_address_column(raw: &str) -> Result<AccountAddress, PersistError> {
    raw.parse().map_err(|err| {
        PersistError::Postgres(sqlx::Error::ColumnDecode {
            index: "address".to_owned(),
            source: format!("{raw:?} is not a 0x-hex address: {err}").into(),
        })
    })
}

/// Canonicalize an address to lowercase `0x`-hex before it's written to or
/// matched against a stored column — mirrors `store::normalized_address` so
/// the same wallet always compares equal regardless of the casing it arrived
/// with.
fn normalized_address(address: &AccountAddress) -> String {
    format!("{address:#x}")
}

struct WalletRow {
    id: i64,
    owner: uuid::Uuid,
    chain_id: i64,
    address: String,
    created_at: DateTime<Utc>,
}

impl TryFrom<WalletRow> for MonitoredWallet {
    type Error = PersistError;

    fn try_from(row: WalletRow) -> Result<Self, PersistError> {
        Ok(MonitoredWallet {
            id: row.id,
            owner: CustomerId(row.owner),
            chain: Chain(row.chain_id as u64),
            address: parse_address_column(&row.address)?,
            created_at: row.created_at,
        })
    }
}

/// Postgres-backed [`MonitoredWalletStore`]. Cheap to clone (the pool is
/// `Arc`-cheap internally).
#[derive(Clone)]
pub struct PgMonitoredWalletStore {
    pool: PgPool,
}

impl PgMonitoredWalletStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MonitoredWalletStore for PgMonitoredWalletStore {
    async fn add(
        &self,
        owner: CustomerId,
        chain: Chain,
        address: AccountAddress,
        at: DateTime<Utc>,
    ) -> Result<AddOutcome, PersistError> {
        let address = normalized_address(&address);
        let chain_id = chain.id() as i64;
        let result = sqlx::query!(
            r#"INSERT INTO monitored_wallets (owner, chain_id, address, created_at)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (owner, chain_id, address) DO NOTHING"#,
            owner.0,
            chain_id,
            address,
            at,
        )
        .execute(&self.pool)
        .await?;

        Ok(if result.rows_affected() == 1 {
            AddOutcome::Added
        } else {
            AddOutcome::AlreadyMonitored
        })
    }

    async fn remove(
        &self,
        owner: CustomerId,
        chain: Chain,
        address: AccountAddress,
    ) -> Result<bool, PersistError> {
        let address = normalized_address(&address);
        let chain_id = chain.id() as i64;
        let result = sqlx::query!(
            "DELETE FROM monitored_wallets WHERE owner = $1 AND chain_id = $2 AND address = $3",
            owner.0,
            chain_id,
            address,
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn list_for_owner(
        &self,
        owner: CustomerId,
    ) -> Result<Vec<MonitoredWallet>, PersistError> {
        let rows = sqlx::query_as!(
            WalletRow,
            r#"SELECT id, owner, chain_id, address, created_at
               FROM monitored_wallets
               WHERE owner = $1
               ORDER BY created_at"#,
            owner.0,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn list_all(
        &self,
        after: Option<MonitoredWalletCursor>,
        limit: u64,
    ) -> Result<MonitoredWalletPage, PersistError> {
        let cursor_created_at = after.map(|c| c.created_at);
        let cursor_id = after.map(|c| c.id);
        // Fetch one row past `limit` so we can tell whether another page
        // exists without a second round-trip (mirrors
        // `PgIncidentStore::list_incidents`).
        let fetch_limit = (limit + 1) as i64;

        let mut rows = sqlx::query_as!(
            WalletRow,
            r#"SELECT id, owner, chain_id, address, created_at
               FROM monitored_wallets
               WHERE $1::timestamptz IS NULL OR $2::bigint IS NULL
                     OR (created_at, id) > ($1, $2)
               ORDER BY created_at, id
               LIMIT $3"#,
            cursor_created_at,
            cursor_id,
            fetch_limit,
        )
        .fetch_all(&self.pool)
        .await?;

        let has_more = rows.len() as u64 > limit;
        if has_more {
            rows.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            rows.last().map(|row| MonitoredWalletCursor {
                created_at: row.created_at,
                id: row.id,
            })
        } else {
            None
        };

        let wallets = rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(MonitoredWalletPage {
            wallets,
            next_cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(n: u8) -> CustomerId {
        CustomerId(uuid::Uuid::from_u128(n as u128))
    }

    fn addr(byte: u8) -> AccountAddress {
        AccountAddress::repeat_byte(byte)
    }

    #[test]
    fn normalized_address_is_lowercase_hex() {
        assert_eq!(
            normalized_address(&addr(0xAB)),
            format!("{:#x}", addr(0xAB))
        );
    }

    #[test]
    fn wallet_row_round_trips_through_try_from() {
        let row = WalletRow {
            id: 42,
            owner: owner(1).0,
            chain_id: Chain::ETHEREUM.id() as i64,
            address: normalized_address(&addr(9)),
            created_at: Utc::now(),
        };
        let wallet: MonitoredWallet = row.try_into().expect("valid row");
        assert_eq!(wallet.id, 42);
        assert_eq!(wallet.owner, owner(1));
        assert_eq!(wallet.chain, Chain::ETHEREUM);
        assert_eq!(wallet.address, addr(9));
    }

    #[test]
    fn wallet_row_rejects_a_malformed_address_column() {
        let row = WalletRow {
            id: 1,
            owner: owner(1).0,
            chain_id: Chain::ETHEREUM.id() as i64,
            address: "not-an-address".to_owned(),
            created_at: Utc::now(),
        };
        let err = MonitoredWallet::try_from(row).unwrap_err();
        assert!(matches!(err, PersistError::Postgres(_)));
    }
}
