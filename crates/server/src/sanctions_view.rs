//! A pod-local view of every sanctioned address (§8.5; §11 graceful
//! degradation, readiness Epic D).
//!
//! **Why it exists.** A stale screening answer (`crate::degrade`) is rendered
//! over a snapshot taken when intelligence last answered fresh. Risk scores may
//! reasonably be minutes old; a *sanctions designation* may not — it is the one
//! legally weighted signal on the path, and "the address was designated after
//! our snapshot" is not a defence. So sanctions membership does not come from
//! the snapshot: every decision, fresh or stale, is checked against this view,
//! which is refreshed from intelligence on a short interval and held in memory.
//!
//! **Why it is cheap enough to hold.** The sanctioned set is small (tens of
//! thousands of addresses across OFAC and the other lists) and changes rarely,
//! so a full copy costs a few megabytes per pod, a lookup is one hash probe, and
//! the view keeps answering while intelligence and Redis are both down.
//!
//! **Consistency.** Intelligence exposes a watermark over the sanctions table
//! (row count + latest import time). A refresh reads the watermark first and
//! does nothing if it has not moved. Otherwise it walks every page, and if the
//! watermark changes mid-walk — an import landed while it read — it starts
//! over, so a half-imported list is never installed. A failed refresh keeps the
//! previous view; how old that view is, is exported and alerted on.
//!
//! **List versions.** Every refresh's head read also carries each monitored
//! list's current version and freshness (§8.5): the digest a decision was
//! screened against, and whether that list is past its SLA. Every decision
//! records them ([`SanctionsView::list_provenance`]), and a stale list can hold
//! an `allow` under an `on_stale: review` policy. Delistings arrive like any
//! other change: intelligence promotes a new list version, the watermark
//! moves, and the next walk drops the address.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::AccountAddress;
use events::system::SanctionsListProvenance;
use intelligence::pb::SanctionMatch;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tonic::Status;

/// Gauge: addresses in the installed view.
pub const VIEW_ADDRESSES: &str = "screening_sanctions_view_addresses";
/// Gauge: Unix time of the last successful refresh (changed or not). Alert on
/// `time() - this`: a view that stopped refreshing looks identical to one with
/// nothing new to learn (§15).
pub const VIEW_SYNCED_TIMESTAMP: &str = "screening_sanctions_view_synced_timestamp_seconds";
/// Counter: refresh attempts, by `outcome` (`unchanged` | `reloaded` |
/// `failed`).
pub const REFRESH_TOTAL: &str = "screening_sanctions_refresh_total";
/// Gauge: the configured refresh interval, in seconds — exported so the
/// staleness rule compares the view's age against the deployment's own cadence
/// rather than a literal that would drift from it.
pub const REFRESH_INTERVAL_SECONDS: &str = "screening_sanctions_refresh_interval_seconds";

/// Rows per page while walking the list.
const PAGE_SIZE: u32 = 5_000;
/// How many refresh intervals old the view may be and still vouch that an
/// address it does not list is not sanctioned. Three, so one slow or failed
/// refresh does not flip every stale allow to review.
pub const VOUCH_INTERVALS: u32 = 3;

/// Walks restarted because an import moved the watermark mid-walk, before the
/// refresh gives up and keeps the previous view until the next tick.
const MAX_WALKS: usize = 3;

/// A point-in-time identity of intelligence's sanctions table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watermark {
    pub rows: u64,
    pub last_imported_unix_millis: i64,
}

/// One monitored sanctions list's current version and freshness, as
/// intelligence reported it on the head read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListState {
    pub list: String,
    /// Empty if the list has never synced.
    pub digest: String,
    /// The last confirmation against the source; `None` if never.
    pub synced_at: Option<DateTime<Utc>>,
    /// The list's SLA, from intelligence's configuration.
    pub max_age: Duration,
}

impl ListState {
    /// The provenance a decision made at `now` records. A list that never
    /// synced is stale, and reports the Unix epoch as its sync time.
    pub fn provenance(&self, now: DateTime<Utc>) -> SanctionsListProvenance {
        let stale = self.digest.is_empty()
            || self
                .synced_at
                .is_none_or(|at| (now - at).to_std().is_ok_and(|age| age > self.max_age));
        SanctionsListProvenance {
            list: self.list.clone(),
            digest: self.digest.clone(),
            synced_at: self.synced_at.unwrap_or(DateTime::UNIX_EPOCH),
            stale,
        }
    }
}

/// One page of the sanctions list, already parsed at the transport edge.
#[derive(Debug, Clone)]
pub struct SanctionsPage {
    pub entries: Vec<(AccountAddress, Vec<SanctionMatch>)>,
    /// The cursor for the next page; `None` on the last.
    pub next_after: Option<String>,
    pub watermark: Watermark,
    /// Every monitored list's state — filled on the head read only.
    pub lists: Vec<ListState>,
}

/// Where the list comes from — `IntelligenceClient` in production.
#[async_trait]
pub trait SanctionsSource: Send + Sync {
    /// The page after `after` (from the start when `None`). `limit == 0` asks
    /// for the watermark alone.
    async fn page(&self, after: Option<String>, limit: u32) -> Result<SanctionsPage, Status>;
}

#[derive(Default)]
struct Installed {
    matches: HashMap<AccountAddress, Vec<SanctionMatch>>,
    watermark: Option<Watermark>,
    synced_at: Option<Instant>,
    lists: Vec<ListState>,
}

/// The view. Cloned into `AppState` as an `Arc`; lookups take a read lock for
/// one hash probe, and a reload swaps the whole map in one write.
#[derive(Default)]
pub struct SanctionsView {
    installed: RwLock<Arc<Installed>>,
    vouch_window: Duration,
}

/// What one refresh did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresh {
    Unchanged,
    Reloaded { addresses: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error("intelligence: {0}")]
    Source(#[from] Status),
    #[error(
        "the sanctions list changed on every one of {MAX_WALKS} walks; keeping the previous view"
    )]
    KeptChanging,
}

impl SanctionsView {
    /// A view refreshed every `interval`, vouching for
    /// [`VOUCH_INTERVALS`] of them. A default-constructed view never vouches.
    pub fn for_refresh_interval(interval: Duration) -> Self {
        Self {
            installed: RwLock::default(),
            vouch_window: interval * VOUCH_INTERVALS,
        }
    }

    /// Whether this view may vouch for the addresses it does not list right
    /// now — the `sanctions_verified` of a stale decision.
    pub fn vouches(&self) -> bool {
        self.is_current(self.vouch_window)
    }

    /// A view already loaded with `entries` and synced now — for tests of
    /// everything *around* the view.
    #[cfg(any(test, feature = "test-util"))]
    pub fn seeded(
        entries: Vec<(AccountAddress, Vec<SanctionMatch>)>,
        vouch_window: Duration,
    ) -> Self {
        let view = Self {
            installed: RwLock::default(),
            vouch_window,
        };
        view.install(
            entries.into_iter().collect(),
            Watermark {
                rows: 0,
                last_imported_unix_millis: 0,
            },
            Vec::new(),
        );
        view
    }

    /// A seeded view that also reports these list states — for tests.
    #[cfg(any(test, feature = "test-util"))]
    pub fn seeded_with_lists(
        entries: Vec<(AccountAddress, Vec<SanctionMatch>)>,
        lists: Vec<ListState>,
        vouch_window: Duration,
    ) -> Self {
        let view = Self::seeded(entries, vouch_window);
        view.mark_synced(lists);
        view
    }

    fn current(&self) -> Arc<Installed> {
        self.installed
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Which version of each monitored list a decision made at `now` is
    /// screened against, and whether each is past its SLA. Empty until the
    /// first head read succeeds, or when intelligence reports no lists: a
    /// decision then records no provenance, which is the truth — it cannot
    /// name a version it was never told.
    pub fn list_provenance(&self, now: DateTime<Utc>) -> Vec<SanctionsListProvenance> {
        self.current()
            .lists
            .iter()
            .map(|state| state.provenance(now))
            .collect()
    }

    /// The address's designations, if any.
    pub fn lookup(&self, address: &AccountAddress) -> Option<Vec<SanctionMatch>> {
        self.current().matches.get(address).cloned()
    }

    /// Whether the view has been confirmed against intelligence within
    /// `max_age` — i.e. whether it can vouch that an address *not* in it is not
    /// sanctioned. A view never synced cannot.
    pub fn is_current(&self, max_age: Duration) -> bool {
        self.current()
            .synced_at
            .is_some_and(|at| at.elapsed() <= max_age)
    }

    /// Bring the view up to date with `source`.
    pub async fn refresh(&self, source: &dyn SanctionsSource) -> Result<Refresh, RefreshError> {
        let head_page = source.page(None, 0).await?;
        let head = head_page.watermark;
        let lists = head_page.lists;
        if self.current().watermark == Some(head) {
            self.mark_synced(lists);
            return Ok(Refresh::Unchanged);
        }

        'walk: for _ in 0..MAX_WALKS {
            let mut matches = HashMap::new();
            let mut after = None;
            let mut walked: Option<Watermark> = None;
            loop {
                let page = source.page(after, PAGE_SIZE).await?;
                match walked {
                    None => walked = Some(page.watermark),
                    Some(started) if started != page.watermark => continue 'walk,
                    Some(_) => {}
                }
                // Extend, never overwrite: one address's designations can be
                // split across a page boundary.
                for (address, found) in page.entries {
                    matches
                        .entry(address)
                        .or_insert_with(Vec::new)
                        .extend(found);
                }
                match page.next_after {
                    Some(cursor) => after = Some(cursor),
                    None => break,
                }
            }
            let addresses = matches.len();
            self.install(matches, walked.expect("at least one page was read"), lists);
            return Ok(Refresh::Reloaded { addresses });
        }
        Err(RefreshError::KeptChanging)
    }

    fn install(
        &self,
        matches: HashMap<AccountAddress, Vec<SanctionMatch>>,
        watermark: Watermark,
        lists: Vec<ListState>,
    ) {
        metrics::gauge!(VIEW_ADDRESSES).set(matches.len() as f64);
        let installed = Arc::new(Installed {
            matches,
            watermark: Some(watermark),
            synced_at: Some(Instant::now()),
            lists,
        });
        *self
            .installed
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = installed;
        publish_synced(Utc::now());
    }

    fn mark_synced(&self, lists: Vec<ListState>) {
        let mut guard = self
            .installed
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = guard.clone();
        *guard = Arc::new(Installed {
            matches: previous.matches.clone(),
            watermark: previous.watermark,
            synced_at: Some(Instant::now()),
            lists,
        });
        drop(guard);
        publish_synced(Utc::now());
    }
}

fn publish_synced(at: DateTime<Utc>) {
    metrics::gauge!(VIEW_SYNCED_TIMESTAMP).set(at.timestamp_millis() as f64 / 1000.0);
}

/// Refresh at boot and then every `interval` until shutdown. A failure keeps the
/// previous view and is counted; the loop never exits on one.
pub async fn run_refresher(
    view: Arc<SanctionsView>,
    source: Arc<dyn SanctionsSource>,
    interval: Duration,
    shutdown: CancellationToken,
) {
    // Before the first refresh can succeed or fail (§15b): the interval the
    // staleness rule divides by, and a synced time of 0 so a view that never
    // loads reads as infinitely stale instead of absent.
    metrics::gauge!(REFRESH_INTERVAL_SECONDS).set(interval.as_secs_f64());
    if !view.is_current(interval) {
        metrics::gauge!(VIEW_SYNCED_TIMESTAMP).set(0.0);
        metrics::gauge!(VIEW_ADDRESSES).set(0.0);
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let outcome = match view.refresh(source.as_ref()).await {
            Ok(Refresh::Unchanged) => "unchanged",
            Ok(Refresh::Reloaded { addresses }) => {
                tracing::info!(addresses, "sanctions view reloaded");
                "reloaded"
            }
            Err(err) => {
                tracing::warn!(error = %err, "sanctions view refresh failed; keeping the previous view");
                "failed"
            }
        };
        metrics::counter!(REFRESH_TOTAL, "outcome" => outcome).increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    /// A list of `(address byte, list)` rows served in pages, with a watermark
    /// that can be scripted to move after a given number of page reads.
    struct ScriptedList {
        rows: Mutex<Vec<(u8, &'static str)>>,
        watermark: Mutex<Watermark>,
        page_size: usize,
        /// After this many *non-empty-limit* page reads, apply `import`.
        import_after: Mutex<Option<(usize, (u8, &'static str))>>,
        reads: Mutex<usize>,
        failing: bool,
        lists: Mutex<Vec<ListState>>,
    }

    impl ScriptedList {
        fn new(rows: Vec<(u8, &'static str)>, page_size: usize) -> Self {
            let watermark = Watermark {
                rows: rows.len() as u64,
                last_imported_unix_millis: 1,
            };
            Self {
                rows: Mutex::new(rows),
                watermark: Mutex::new(watermark),
                page_size,
                import_after: Mutex::new(None),
                reads: Mutex::new(0),
                failing: false,
                lists: Mutex::new(Vec::new()),
            }
        }

        fn import(&self, row: (u8, &'static str)) {
            let mut rows = self.rows.lock().unwrap();
            rows.push(row);
            let mut watermark = self.watermark.lock().unwrap();
            watermark.rows = rows.len() as u64;
            watermark.last_imported_unix_millis += 1;
        }
    }

    #[async_trait]
    impl SanctionsSource for ScriptedList {
        async fn page(&self, after: Option<String>, limit: u32) -> Result<SanctionsPage, Status> {
            if self.failing {
                return Err(Status::unavailable("down"));
            }
            if limit > 0 {
                let mut reads = self.reads.lock().unwrap();
                *reads += 1;
                let due = self
                    .import_after
                    .lock()
                    .unwrap()
                    .filter(|(n, _)| *reads == *n);
                drop(reads);
                if let Some((_, row)) = due {
                    self.import(row);
                    *self.import_after.lock().unwrap() = None;
                }
            }
            let watermark = *self.watermark.lock().unwrap();
            if limit == 0 {
                return Ok(SanctionsPage {
                    entries: vec![],
                    next_after: None,
                    watermark,
                    lists: self.lists.lock().unwrap().clone(),
                });
            }
            let mut rows = self.rows.lock().unwrap().clone();
            rows.sort();
            let start = after.map(|a| a.parse::<usize>().unwrap()).unwrap_or(0);
            let page: Vec<_> = rows.iter().skip(start).take(self.page_size).collect();
            let next = start + page.len();
            Ok(SanctionsPage {
                entries: page
                    .into_iter()
                    .map(|(byte, list)| {
                        (
                            alloy_primitives::Address::repeat_byte(*byte),
                            vec![SanctionMatch {
                                list: (*list).into(),
                                entry: "entry".into(),
                            }],
                        )
                    })
                    .collect(),
                next_after: (next < rows.len()).then(|| next.to_string()),
                watermark,
                lists: Vec::new(),
            })
        }
    }

    fn addr(byte: u8) -> AccountAddress {
        alloy_primitives::Address::repeat_byte(byte)
    }

    fn state(digest: &str, synced_secs: Option<i64>, max_age_secs: u64) -> ListState {
        ListState {
            list: "ofac_sdn".into(),
            digest: digest.into(),
            synced_at: synced_secs.map(|s| DateTime::<Utc>::from_timestamp(s, 0).unwrap()),
            max_age: Duration::from_secs(max_age_secs),
        }
    }

    /// Stale past the SLA, inclusive at it; never-synced is stale and
    /// reports the epoch.
    #[test]
    fn list_provenance_is_stale_past_the_sla_or_when_never_synced() {
        let now = DateTime::<Utc>::from_timestamp(1_000, 0).unwrap();
        assert!(!state("d", Some(900), 100).provenance(now).stale);
        assert!(state("d", Some(899), 100).provenance(now).stale);
        let never = state("", None, 100).provenance(now);
        assert!(never.stale);
        assert_eq!(never.synced_at, DateTime::UNIX_EPOCH);
        // A future stamp (skew) is not stale.
        assert!(!state("d", Some(2_000), 100).provenance(now).stale);
    }

    /// List states ride the head read, so they refresh even when the list
    /// itself is unchanged — a list going stale is visible without a re-walk.
    #[tokio::test]
    async fn list_states_refresh_on_every_head_read() {
        let source = ScriptedList::new(vec![(1, "ofac_sdn")], 10);
        let view = SanctionsView::for_refresh_interval(Duration::from_secs(60));
        *source.lists.lock().unwrap() = vec![state("d1", Some(1), 60)];
        view.refresh(&source).await.unwrap();
        assert_eq!(view.list_provenance(Utc::now())[0].digest, "d1");

        *source.lists.lock().unwrap() = vec![state("d2", Some(1), 60)];
        assert_eq!(view.refresh(&source).await.unwrap(), Refresh::Unchanged);
        assert_eq!(view.list_provenance(Utc::now())[0].digest, "d2");
    }

    #[tokio::test]
    async fn a_reload_walks_every_page_and_answers_lookups() {
        let source = ScriptedList::new(vec![(1, "ofac_sdn"), (2, "ofac_sdn"), (3, "eu")], 2);
        let view = SanctionsView::default();

        assert_eq!(
            view.refresh(&source).await.unwrap(),
            Refresh::Reloaded { addresses: 3 }
        );
        assert_eq!(view.lookup(&addr(3)).unwrap()[0].list, "eu");
        assert!(view.lookup(&addr(9)).is_none());
    }

    #[tokio::test]
    async fn an_unmoved_watermark_skips_the_walk() {
        let source = ScriptedList::new(vec![(1, "ofac_sdn")], 10);
        let view = SanctionsView::default();
        view.refresh(&source).await.unwrap();
        let reads = *source.reads.lock().unwrap();

        assert_eq!(view.refresh(&source).await.unwrap(), Refresh::Unchanged);
        assert_eq!(*source.reads.lock().unwrap(), reads, "no page was read");
    }

    #[tokio::test]
    async fn a_new_designation_is_picked_up_on_the_next_refresh() {
        let source = ScriptedList::new(vec![(1, "ofac_sdn")], 10);
        let view = SanctionsView::default();
        view.refresh(&source).await.unwrap();
        assert!(view.lookup(&addr(7)).is_none());

        source.import((7, "ofac_sdn"));
        assert_eq!(
            view.refresh(&source).await.unwrap(),
            Refresh::Reloaded { addresses: 2 }
        );
        assert!(view.lookup(&addr(7)).is_some());
    }

    /// An import landing mid-walk restarts the walk, so a half-imported list is
    /// never installed — and the restarted walk includes the new row.
    #[tokio::test]
    async fn an_import_during_the_walk_restarts_it() {
        let source = ScriptedList::new(vec![(1, "a"), (2, "a"), (3, "a"), (4, "a")], 2);
        *source.import_after.lock().unwrap() = Some((2, (5, "a")));
        let view = SanctionsView::default();

        assert_eq!(
            view.refresh(&source).await.unwrap(),
            Refresh::Reloaded { addresses: 5 }
        );
        assert!(view.lookup(&addr(5)).is_some());
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_previous_view() {
        let healthy = ScriptedList::new(vec![(1, "ofac_sdn")], 10);
        let view = SanctionsView::default();
        view.refresh(&healthy).await.unwrap();

        let down = ScriptedList {
            failing: true,
            ..ScriptedList::new(vec![], 10)
        };
        assert!(view.refresh(&down).await.is_err());
        assert!(
            view.lookup(&addr(1)).is_some(),
            "the last good view still answers"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_view_vouches_only_within_its_max_age() {
        let source = ScriptedList::new(vec![(1, "ofac_sdn")], 10);
        let view = SanctionsView::default();
        assert!(
            !view.is_current(Duration::from_secs(60)),
            "never synced cannot vouch"
        );

        view.refresh(&source).await.unwrap();
        assert!(view.is_current(Duration::from_secs(60)));

        tokio::time::advance(Duration::from_secs(61)).await;
        assert!(!view.is_current(Duration::from_secs(60)));

        // An unchanged refresh still counts as confirmation.
        view.refresh(&source).await.unwrap();
        assert!(view.is_current(Duration::from_secs(60)));
    }
}
