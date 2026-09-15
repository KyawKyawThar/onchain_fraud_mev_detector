//! Replacing a table whose definition ClickHouse cannot `ALTER` — a partition
//! key, a sorting key, an engine — without a data copy inside a boot migration.
//!
//! A migration runs unattended, at boot, under a liveness probe. Copying a
//! production table there is the wrong shape at every size that matters: it
//! holds a pod in `CrashLoopBackOff` for as long as the copy takes, it restarts
//! from the beginning each time the probe kills it, and it moves regulatory
//! evidence with nobody watching. So the replacement is split in three:
//!
//! 1. **A migration creates the new table** under a derived name,
//!    `<table>__next`. DDL only; instant.
//! 2. **Boot swaps it in only when that moves no data** ([`TableSwap::swap_if_safe`]):
//!    the live table is empty (a fresh deployment, a CI container, a rebuild's
//!    staging database), or the staged table turns out to be redundant.
//! 3. **Anything with data is a Job** owned by the service — resumable, checked,
//!    with the old table kept as `<table>__retired` until a human drops it.
//!
//! The names are derived here and nowhere else, because two other things key on
//! them: the capacity plan replays every crate's DDL and treats `X__next` as the
//! future `X`, and a retired table is excluded from its partition gates.
//!
//! # Why `EXCHANGE`, not `RENAME`
//!
//! A materialized view attaches to its source table by name. Probed on
//! ClickHouse 26.5: after `EXCHANGE TABLES a AND b`, inserts into `a` (now the
//! new table) still fire the view, and inserts into the old table do not. So an
//! exchange carries a table's triggers across, where a rename chain would have
//! to re-attach them.

use anyhow::{bail, Context, Result};
use clickhouse::Client;

/// Suffix of the staged replacement a migration creates.
pub const STAGED_SUFFIX: &str = "__next";
/// Suffix the replaced table is kept under until an operator drops it.
pub const RETIRED_SUFFIX: &str = "__retired";

/// One live table and the names its replacement moves through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableSwap {
    live: &'static str,
}

/// What the store holds for one table, as [`decide`] needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableFacts {
    /// `system.tables.partition_key`, as ClickHouse renders it.
    pub partition_key: String,
    pub rows: u64,
}

/// Where a replacement stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapState {
    /// No staged table: nothing is waiting.
    Complete,
    /// A staged table exists, but the live one already has its partition key —
    /// a rebuild promoted a staged copy, or the swap already ran and a
    /// migration was replayed. The staged table is a leftover.
    Superseded { staged_rows: u64 },
    /// The live table is empty, so swapping moves no data.
    SwappableEmpty,
    /// The live table holds rows under the old definition: they must move first.
    Pending { live_rows: u64, staged_rows: u64 },
    /// Only the staged table exists.
    LiveMissing,
}

/// What [`TableSwap::swap_if_safe`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapOutcome {
    /// Nothing was waiting.
    Complete,
    /// The staged table is now live; the old one was empty and has been dropped.
    Swapped,
    /// A redundant, empty staged table was dropped.
    CleanedUpStage,
    /// A redundant staged table holds rows, so it was left for an operator.
    StagedLeftInPlace { staged_rows: u64 },
    /// Data has to move first: the service's own Job owns that.
    Pending { live_rows: u64, staged_rows: u64 },
}

/// **The judgement**, pure: the two tables' facts in, the state out.
pub fn decide(live: Option<&TableFacts>, staged: Option<&TableFacts>) -> SwapState {
    match (live, staged) {
        (_, None) => SwapState::Complete,
        (None, Some(_)) => SwapState::LiveMissing,
        (Some(live), Some(staged)) if live.partition_key == staged.partition_key => {
            SwapState::Superseded {
                staged_rows: staged.rows,
            }
        }
        (Some(live), Some(_)) if live.rows == 0 => SwapState::SwappableEmpty,
        (Some(live), Some(staged)) => SwapState::Pending {
            live_rows: live.rows,
            staged_rows: staged.rows,
        },
    }
}

impl TableSwap {
    /// The swap for `live`. A compile-time table name, never runtime input: it
    /// is interpolated into DDL.
    pub const fn new(live: &'static str) -> Self {
        Self { live }
    }

    pub fn live(&self) -> &'static str {
        self.live
    }

    pub fn staged(&self) -> String {
        format!("{}{STAGED_SUFFIX}", self.live)
    }

    pub fn retired(&self) -> String {
        format!("{}{RETIRED_SUFFIX}", self.live)
    }

    /// Whether `name` exists in the client's database.
    pub async fn exists(client: &Client, name: &str) -> Result<bool> {
        let n: u64 = client
            .query(
                "SELECT count() FROM system.tables WHERE database = currentDatabase() AND name = ?",
            )
            .bind(name)
            .fetch_one()
            .await
            .with_context(|| format!("checking whether {name} exists"))?;
        Ok(n > 0)
    }

    async fn facts(client: &Client, name: &str) -> Result<Option<TableFacts>> {
        if !Self::exists(client, name).await? {
            return Ok(None);
        }
        let partition_key: String = client
            .query("SELECT partition_key FROM system.tables WHERE database = currentDatabase() AND name = ?")
            .bind(name)
            .fetch_one()
            .await
            .with_context(|| format!("reading {name}'s partition key"))?;
        let rows: u64 = client
            .query(&format!("SELECT count() FROM {name}"))
            .fetch_one()
            .await
            .with_context(|| format!("counting {name}"))?;
        Ok(Some(TableFacts {
            partition_key,
            rows,
        }))
    }

    /// Read both tables and decide where the replacement stands.
    pub async fn observe(&self, client: &Client) -> Result<SwapState> {
        let live = Self::facts(client, self.live).await?;
        let staged = Self::facts(client, &self.staged()).await?;
        Ok(decide(live.as_ref(), staged.as_ref()))
    }

    /// The boot path: complete the replacement when doing so moves no data,
    /// and report `Pending` otherwise. Never copies, never drops a row.
    pub async fn swap_if_safe(&self, client: &Client) -> Result<SwapOutcome> {
        Ok(match self.observe(client).await? {
            SwapState::Complete => SwapOutcome::Complete,
            SwapState::Superseded { staged_rows: 0 } => {
                self.drop_table(client, &self.staged()).await?;
                SwapOutcome::CleanedUpStage
            }
            SwapState::Superseded { staged_rows } => SwapOutcome::StagedLeftInPlace { staged_rows },
            SwapState::SwappableEmpty => {
                self.exchange(client).await?;
                // Empty a moment ago. Re-counted, because a writer on another
                // pod could have landed a row between the observe and the swap.
                self.drop_retired_if_empty(client).await?;
                SwapOutcome::Swapped
            }
            SwapState::LiveMissing => {
                client
                    .query(&format!("RENAME TABLE {} TO {}", self.staged(), self.live))
                    .execute()
                    .await
                    .with_context(|| format!("promoting {} to {}", self.staged(), self.live))?;
                SwapOutcome::Swapped
            }
            SwapState::Pending {
                live_rows,
                staged_rows,
            } => SwapOutcome::Pending {
                live_rows,
                staged_rows,
            },
        })
    }

    /// Put the staged table in place and keep the old one as `__retired`.
    ///
    /// Two statements. Between them the live name always resolves to a table
    /// (after the exchange it is the new one), so no reader or writer ever
    /// sees it missing; only the staged name briefly points at the old data.
    pub async fn exchange(&self, client: &Client) -> Result<()> {
        let staged = self.staged();
        let retired = self.retired();
        if Self::exists(client, &retired).await? {
            bail!(
                "{retired} already exists — a previous replacement of {} was never \
                 finalized; drop it (after checking it) before swapping again",
                self.live
            );
        }
        client
            .query(&format!("EXCHANGE TABLES {} AND {staged}", self.live))
            .execute()
            .await
            .with_context(|| format!("exchanging {} and {staged}", self.live))?;
        client
            .query(&format!("RENAME TABLE {staged} TO {retired}"))
            .execute()
            .await
            .with_context(|| format!("retiring the replaced table as {retired}"))?;
        tracing::info!(table = self.live, retired = %retired, "table replaced; old definition retired");
        Ok(())
    }

    /// Drop the retired table if it holds nothing.
    pub async fn drop_retired_if_empty(&self, client: &Client) -> Result<bool> {
        let retired = self.retired();
        if !Self::exists(client, &retired).await? {
            return Ok(false);
        }
        let rows: u64 = client
            .query(&format!("SELECT count() FROM {retired}"))
            .fetch_one()
            .await
            .with_context(|| format!("counting {retired}"))?;
        if rows > 0 {
            return Ok(false);
        }
        self.drop_table(client, &retired).await?;
        Ok(true)
    }

    /// Drop the retired table **whatever it holds**. Destructive: the owning
    /// service gates this behind its own witness after proving the live table
    /// holds every row the retired one does.
    pub async fn drop_retired(&self, client: &Client) -> Result<()> {
        self.drop_table(client, &self.retired()).await
    }

    async fn drop_table(&self, client: &Client, name: &str) -> Result<()> {
        client
            .query(&format!("DROP TABLE IF EXISTS {name}"))
            .execute()
            .await
            .with_context(|| format!("dropping {name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(key: &str, rows: u64) -> TableFacts {
        TableFacts {
            partition_key: key.into(),
            rows,
        }
    }

    const DAILY: &str = "(chain, event_type, toDate(occurred_at))";
    const MONTHLY: &str = "toYYYYMM(occurred_at)";

    #[test]
    fn names_are_derived_from_the_live_table() {
        let swap = TableSwap::new("events");
        assert_eq!(swap.staged(), "events__next");
        assert_eq!(swap.retired(), "events__retired");
    }

    #[test]
    fn nothing_staged_is_complete() {
        assert_eq!(decide(Some(&facts(DAILY, 9)), None), SwapState::Complete);
        assert_eq!(decide(None, None), SwapState::Complete);
    }

    /// The boot path may only swap what moves no data.
    #[test]
    fn an_empty_live_table_is_swappable_and_a_full_one_is_pending() {
        assert_eq!(
            decide(Some(&facts(DAILY, 0)), Some(&facts(MONTHLY, 0))),
            SwapState::SwappableEmpty
        );
        assert_eq!(
            decide(Some(&facts(DAILY, 5)), Some(&facts(MONTHLY, 2))),
            SwapState::Pending {
                live_rows: 5,
                staged_rows: 2
            }
        );
    }

    /// After a rebuild promotes a staged copy, the migration's leftover must
    /// not read as a pending repartition forever.
    #[test]
    fn a_live_table_already_on_the_new_key_supersedes_the_stage() {
        assert_eq!(
            decide(Some(&facts(MONTHLY, 100)), Some(&facts(MONTHLY, 0))),
            SwapState::Superseded { staged_rows: 0 }
        );
    }

    #[test]
    fn a_missing_live_table_promotes_the_stage() {
        assert_eq!(
            decide(None, Some(&facts(MONTHLY, 0))),
            SwapState::LiveMissing
        );
    }
}
