//! Putting the capacity plan's `events` definition in place without a data
//! copy in a boot migration (readiness Epic D; docs/runbooks/capacity-plan.md §5).
//!
//! Migration `0004_create_events_next` creates the new definition as
//! `events__next`. From there:
//!
//! * **Boot** ([`reconcile_safe`]) swaps it in only when that moves no data —
//!   the live table is empty — and otherwise reports `Pending` (a gauge and a
//!   warning) and keeps serving on the old table. Never a copy, never a drop.
//! * **The Job** (`event-store repartition run`) moves the data: month by month
//!   into the new table, exchange, then catch up any row that reached the old
//!   table late. Resumable and idempotent, because the *state* is the data: a
//!   month is done when the target holds every `event_id` the source does.
//! * **Finalize** (`repartition finalize --i-understand-this-drops-the-retired-table`)
//!   drops the old table, and only after proving the live table holds every
//!   event the retired one does.
//!
//! # Why month by month
//!
//! Every statement here is bounded by one month of evidence: the copy's
//! `NOT IN` set, its insert block (one partition of the new table), and a
//! failure's blast radius. A copy of the whole table would hold every copied id
//! in memory and would restart from nothing when a pod is killed.
//!
//! # Why presence by `event_id` is the whole check
//!
//! An event is immutable and its `event_id` is its identity. The copy is
//! `INSERT … SELECT` of the stored columns, so a present id carries the same
//! bytes. What can go wrong is absence — a row the copy missed, or one a writer
//! on the old build landed after the copy — and that is exactly what the
//! anti-join counts.

use std::fmt;
use std::time::Duration;

use ch_migrate::swap::{SwapOutcome, SwapState, TableSwap};
use clickhouse::Client;

use crate::store::TABLE;

/// The swap for the event store's one table.
pub const SWAP: TableSwap = TableSwap::new(TABLE);

/// Every column, in table order, for `INSERT … SELECT` in both directions.
const COLUMNS: &str = "event_id, schema_version, chain, event_type, event_family, occurred_at, \
                       payload, appended_at, incident_id, addresses";

/// Catch-up passes per month before giving up. More than one because an insert
/// in flight at the exchange can commit into the retired table afterwards.
const CATCH_UP_PASSES: usize = 5;
/// Pause between catch-up passes, for exactly those in-flight inserts.
const CATCH_UP_PAUSE: Duration = Duration::from_secs(2);

#[derive(Debug, thiserror::Error)]
pub enum RepartitionError {
    #[error("clickhouse request failed")]
    Clickhouse(#[from] clickhouse::error::Error),
    #[error("{0:#}")]
    Swap(#[from] anyhow::Error),
    #[error(
        "month {month}: the retired table still holds {missing} event(s) the live table lacks \
         after {passes} catch-up passes — a writer may still be on the old table; re-run \
         `event-store repartition run`"
    )]
    CatchUpIncomplete {
        month: u32,
        missing: u64,
        passes: usize,
    },
    #[error("there is no retired events table to finalize (state: {0:?})")]
    NothingToFinalize(SwapState),
    #[error(
        "the retired table still holds {missing} event(s) the live table lacks, in month(s) \
         {months:?}; run `event-store repartition run` before finalizing"
    )]
    RetiredNotSubsumed { missing: u64, months: Vec<u32> },
}

/// The witness [`finalize`] demands. Only the CLI flag arm constructs one, so no
/// boot path or background task can drop the retired table — by signature.
pub struct DropRetiredIntent(());

impl DropRetiredIntent {
    pub fn from_operator_flag() -> Self {
        Self(())
    }
}

/// How many events of one month the target lacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonthGap {
    /// `YYYYMM`.
    pub month: u32,
    pub missing: u64,
}

/// The months still missing events.
pub fn outstanding(gaps: &[MonthGap]) -> Vec<MonthGap> {
    gaps.iter().copied().filter(|gap| gap.missing > 0).collect()
}

/// `event-store repartition` with no arguments.
#[derive(Debug)]
pub struct Plan {
    pub state: SwapState,
    pub retired_present: bool,
    /// Pending: live → staged. Complete with a retired table: retired → live.
    pub gaps: Vec<MonthGap>,
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let open = outstanding(&self.gaps);
        match &self.state {
            SwapState::Complete if self.retired_present && open.is_empty() => writeln!(
                f,
                "events is current; {} is fully contained in it and can be finalized",
                SWAP.retired()
            )?,
            SwapState::Complete if self.retired_present => writeln!(
                f,
                "events is current, but {} still holds events it lacks — run `repartition run`",
                SWAP.retired()
            )?,
            SwapState::Complete => writeln!(f, "events is current; nothing to do")?,
            SwapState::Pending {
                live_rows,
                staged_rows,
            } => writeln!(
                f,
                "PENDING — events holds {live_rows} row(s) on the old key, {} holds \
                 {staged_rows}; `repartition run` moves them",
                SWAP.staged()
            )?,
            other => writeln!(f, "{other:?} — boot completes this without moving data")?,
        }
        for gap in &open {
            writeln!(f, "  {}: {} event(s) to move", gap.month, gap.missing)?;
        }
        Ok(())
    }
}

/// What [`run`] did.
#[derive(Debug)]
pub enum RunOutcome {
    AlreadyComplete,
    Swapped(SwapOutcome),
    Repartitioned { months: usize },
    CaughtUp { months: usize },
}

impl fmt::Display for RunOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunOutcome::AlreadyComplete => write!(f, "events is current; nothing to do"),
            RunOutcome::Swapped(outcome) => write!(f, "completed without moving data: {outcome:?}"),
            RunOutcome::Repartitioned { months } => write!(
                f,
                "moved {months} month(s) and swapped; {} is kept until `repartition finalize`",
                SWAP.retired()
            ),
            RunOutcome::CaughtUp { months } => write!(
                f,
                "caught up {months} month(s) from {}; it can be finalized",
                SWAP.retired()
            ),
        }
    }
}

/// The boot path: complete the replacement when that moves no data.
pub async fn reconcile_safe(client: &Client) -> Result<SwapOutcome, RepartitionError> {
    Ok(SWAP.swap_if_safe(client).await?)
}

/// Report where the replacement stands, and what a run would move.
pub async fn plan(client: &Client) -> Result<Plan, RepartitionError> {
    let state = SWAP.observe(client).await?;
    let retired = SWAP.retired();
    let retired_present = TableSwap::exists(client, &retired).await?;
    let gaps = match &state {
        SwapState::Pending { .. } => gaps(client, SWAP.live(), &SWAP.staged()).await?,
        SwapState::Complete if retired_present => gaps(client, &retired, SWAP.live()).await?,
        _ => Vec::new(),
    };
    Ok(Plan {
        state,
        retired_present,
        gaps,
    })
}

/// Move the data and swap. Safe to re-run at any point: every step is keyed on
/// what the target already holds.
pub async fn run(client: &Client) -> Result<RunOutcome, RepartitionError> {
    match SWAP.observe(client).await? {
        SwapState::Pending { .. } => {
            let staged = SWAP.staged();
            let months = months(client, SWAP.live()).await?;
            // One pass per month, not a convergence loop: writers are still
            // appending to the live table, so its open month cannot be
            // "finished" before the exchange. The post-exchange catch-up is the
            // strict check, against a table nothing writes to any more.
            for &month in &months {
                copy_month(client, SWAP.live(), &staged, month).await?;
                tracing::info!(month, "copied month into {staged}");
            }
            SWAP.exchange(client).await?;
            catch_up(client).await?;
            Ok(RunOutcome::Repartitioned {
                months: months.len(),
            })
        }
        SwapState::Complete => {
            if TableSwap::exists(client, &SWAP.retired()).await? {
                Ok(RunOutcome::CaughtUp {
                    months: catch_up(client).await?,
                })
            } else {
                Ok(RunOutcome::AlreadyComplete)
            }
        }
        _ => Ok(RunOutcome::Swapped(SWAP.swap_if_safe(client).await?)),
    }
}

/// Drop the retired table once the live table provably holds all of it.
pub async fn finalize(
    client: &Client,
    _intent: DropRetiredIntent,
) -> Result<u64, RepartitionError> {
    let retired = SWAP.retired();
    if !TableSwap::exists(client, &retired).await? {
        return Err(RepartitionError::NothingToFinalize(
            SWAP.observe(client).await?,
        ));
    }
    let open = outstanding(&gaps(client, &retired, SWAP.live()).await?);
    if !open.is_empty() {
        return Err(RepartitionError::RetiredNotSubsumed {
            missing: open.iter().map(|gap| gap.missing).sum(),
            months: open.iter().map(|gap| gap.month).collect(),
        });
    }
    let rows: u64 = client
        .query(&format!("SELECT count() FROM {retired}"))
        .fetch_one()
        .await?;
    SWAP.drop_retired(client).await?;
    tracing::warn!(rows, table = %retired, "dropped the retired events table as explicitly requested");
    Ok(rows)
}

/// Converge the retired table into the live one, month by month.
async fn catch_up(client: &Client) -> Result<usize, RepartitionError> {
    let retired = SWAP.retired();
    let months = months(client, &retired).await?;
    for &month in &months {
        let mut passes = 0;
        loop {
            let gap = missing(client, &retired, SWAP.live(), month).await?;
            if gap == 0 {
                break;
            }
            if passes == CATCH_UP_PASSES {
                return Err(RepartitionError::CatchUpIncomplete {
                    month,
                    missing: gap,
                    passes,
                });
            }
            if passes > 0 {
                tokio::time::sleep(CATCH_UP_PAUSE).await;
            }
            copy_month(client, &retired, SWAP.live(), month).await?;
            passes += 1;
        }
    }
    Ok(months.len())
}

async fn months(client: &Client, table: &str) -> Result<Vec<u32>, clickhouse::error::Error> {
    client
        .query(&format!(
            "SELECT DISTINCT toYYYYMM(occurred_at) AS month FROM {table} ORDER BY month"
        ))
        .fetch_all::<u32>()
        .await
}

async fn missing(
    client: &Client,
    source: &str,
    target: &str,
    month: u32,
) -> Result<u64, clickhouse::error::Error> {
    client
        .query(&format!(
            "SELECT count() FROM {source} WHERE toYYYYMM(occurred_at) = ? AND event_id NOT IN \
             (SELECT event_id FROM {target} WHERE toYYYYMM(occurred_at) = ?)"
        ))
        .bind(month)
        .bind(month)
        .fetch_one()
        .await
}

async fn copy_month(
    client: &Client,
    source: &str,
    target: &str,
    month: u32,
) -> Result<(), clickhouse::error::Error> {
    client
        .query(&format!(
            "INSERT INTO {target} ({COLUMNS}) SELECT {COLUMNS} FROM {source} \
             WHERE toYYYYMM(occurred_at) = ? AND event_id NOT IN \
             (SELECT event_id FROM {target} WHERE toYYYYMM(occurred_at) = ?)"
        ))
        .bind(month)
        .bind(month)
        .execute()
        .await
}

async fn gaps(
    client: &Client,
    source: &str,
    target: &str,
) -> Result<Vec<MonthGap>, clickhouse::error::Error> {
    let mut out = Vec::new();
    for month in months(client, source).await? {
        out.push(MonthGap {
            month,
            missing: missing(client, source, target, month).await?,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outstanding_keeps_only_months_with_missing_events() {
        let gaps = [
            MonthGap {
                month: 202601,
                missing: 0,
            },
            MonthGap {
                month: 202602,
                missing: 3,
            },
        ];
        assert_eq!(outstanding(&gaps), vec![gaps[1]]);
    }

    #[test]
    fn the_swap_addresses_the_events_table() {
        assert_eq!(SWAP.live(), "events");
        assert_eq!(SWAP.staged(), "events__next");
        assert_eq!(SWAP.retired(), "events__retired");
    }

    /// The plan's copy must write every column the table has, or a copied row
    /// silently loses its index columns or its ingest watermark.
    #[test]
    fn the_copy_lists_every_column_of_the_migrated_table() {
        let ddl = include_str!("../migrations/0004_create_events_next.up.sql");
        for column in COLUMNS.split(',').map(str::trim) {
            assert!(
                ddl.contains(&format!("    {column} ")),
                "{column} missing from DDL"
            );
        }
        assert_eq!(COLUMNS.split(',').count(), 10);
    }
}
