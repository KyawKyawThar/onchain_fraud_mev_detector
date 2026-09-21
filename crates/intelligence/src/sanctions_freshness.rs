//! The sanctions freshness SLA (§8.5, readiness Epic E): per list, how long
//! it may go unconfirmed against its source, and the gauges that alert on
//! it.
//!
//! **The monitor reads the ledger, not the job.** The scheduled sync
//! ([`crate::sanctions_sync`]) is a short-lived CronJob that nothing reliably
//! scrapes, and the failures that matter most never produce a failing Job at
//! all: a suspended CronJob, a schedule typo, an image that no longer pulls,
//! a namespace nobody deployed it to. So a long-running process (the `grpc`
//! run mode, which is always up because screening needs it) reads
//! `sanctions_list_syncs` on a timer and publishes timestamps, and Prometheus
//! does the arithmetic against `time()`.
//!
//! Publishing *timestamps* rather than ages is load-bearing: if this poller
//! wedges or its reads fail, the last synced time stays put and the age
//! Prometheus computes keeps growing, so the alert still fires. An age gauge
//! would freeze at a healthy value instead.
//!
//! §15b arming: every configured list's timestamps are published as 0 before
//! the first read, so a list that has never synced — or a ledger this pod
//! cannot read from boot — fires the staleness alert rather than satisfying
//! it by absence. The SLA itself is exported as a gauge
//! (`intel_sanctions_list_max_age_seconds`), so the deployment's config is the
//! alert's threshold and the two cannot drift. An empty SLA list is a boot
//! error, not a monitor with nothing to watch.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use strum::IntoEnumIterator;
use tokio_util::sync::CancellationToken;

use crate::model::{ListSyncRecord, SanctionsList};
use crate::store::SanctionsListStore;

// ── Metrics (§19) ────────────────────────────────────────────────

/// Gauge `{list}`: fetch time of the last sync that applied in full, as Unix
/// seconds; 0 if the list never synced.
pub const SANCTIONS_LIST_SYNCED_TIMESTAMP: &str = "intel_sanctions_list_synced_timestamp_seconds";
/// Gauge `{list}`: the most recent failed attempt, as Unix seconds; 0 if none.
pub const SANCTIONS_LIST_FAILED_TIMESTAMP: &str = "intel_sanctions_list_failed_timestamp_seconds";
/// Gauge `{list}`: the SLA — the longest a list may go unconfirmed.
pub const SANCTIONS_LIST_MAX_AGE: &str = "intel_sanctions_list_max_age_seconds";
/// Gauge `{list}`: distinct addresses at the last successful sync.
pub const SANCTIONS_LIST_ENTRIES: &str = "intel_sanctions_list_entries";
/// Gauge `{list}`: when the list's address set last changed, as Unix seconds;
/// 0 if never synced. Dashboard only: a long-flat content clock on a fresh list
/// is how a dead upstream extraction looks, but no publication cadence is
/// promised by any list, so there is no principled threshold to alert on.
pub const SANCTIONS_LIST_CONTENT_CHANGED_TIMESTAMP: &str =
    "intel_sanctions_list_content_changed_timestamp_seconds";
/// Gauge `{list}`: 1 while a promotion of the list has not finished its
/// post-commit effects (labels, hot-cache evictions), else 0. The next sync
/// resumes them, so a value that stays at 1 means syncs are not completing.
pub const SANCTIONS_LIST_EFFECTS_PENDING: &str = "intel_sanctions_list_effects_pending";
/// Gauge: when the oldest unpublished sanctions announcement was queued, as
/// Unix seconds; 0 when the outbox is drained. It carries retroactive
/// `SanctionHit`s, so an announcement that waits is a hard alert delayed.
pub const SANCTIONS_OUTBOX_OLDEST_PENDING_TIMESTAMP: &str =
    "intel_sanctions_outbox_oldest_pending_timestamp_seconds";
/// Counter: ledger reads that failed. Should be zero.
pub const SANCTIONS_FRESHNESS_READ_FAILURES_TOTAL: &str =
    "intel_sanctions_freshness_read_failures_total";

// ── SLA configuration (pure) ─────────────────────────────────────

/// One list's freshness SLA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSla {
    pub list: SanctionsList,
    pub max_age: Duration,
}

/// Parse `INTEL_SANCTIONS_LISTS`: comma-separated `list[=max_age_secs]`, e.g.
/// `ofac_sdn,eu_consolidated=43200`; a bare name takes `default_max_age`.
///
/// Rejects, rather than ignores: an empty set (a monitor watching nothing
/// passes every check), a name that is not a [`SanctionsList`] (it could
/// never sync, and would page forever for a typo), a duplicate, and a zero
/// SLA.
pub fn parse_list_slas(raw: &str, default_max_age: Duration) -> anyhow::Result<Vec<ListSla>> {
    let mut seen = HashSet::new();
    let mut slas = Vec::new();
    for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (name, max_age) = match item.split_once('=') {
            Some((name, secs)) => {
                let secs: u64 = secs.trim().parse().map_err(|_| {
                    anyhow::anyhow!("INTEL_SANCTIONS_LISTS: {item:?} has a non-integer max age")
                })?;
                (name.trim(), Duration::from_secs(secs))
            }
            None => (item, default_max_age),
        };
        let Ok(list) = name.parse::<SanctionsList>() else {
            let known: Vec<&str> = SanctionsList::iter().map(SanctionsList::as_str).collect();
            anyhow::bail!(
                "INTEL_SANCTIONS_LISTS: {name:?} is not a sanctions list (known: {})",
                known.join(", ")
            );
        };
        anyhow::ensure!(
            !max_age.is_zero(),
            "INTEL_SANCTIONS_LISTS: {name:?} has a zero max age"
        );
        anyhow::ensure!(
            seen.insert(list),
            "INTEL_SANCTIONS_LISTS: {name:?} is listed twice"
        );
        slas.push(ListSla { list, max_age });
    }
    anyhow::ensure!(
        !slas.is_empty(),
        "INTEL_SANCTIONS_LISTS is empty: at least one sanctions list must be monitored"
    );
    Ok(slas)
}

// ── Judging one list (pure) ──────────────────────────────────────

/// Where a list stands against its SLA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    NeverSynced,
    Fresh { age: Duration },
    Stale { age: Duration },
}

impl Freshness {
    pub fn is_within_sla(self) -> bool {
        matches!(self, Freshness::Fresh { .. })
    }
}

/// Judge a list against its SLA — the same comparison the
/// `SanctionsListStale` alert makes, for the `sanctions-status` command. A
/// sync stamped in the future (clock skew) reads as age zero.
pub fn assess(sla: &ListSla, record: Option<&ListSyncRecord>, now: DateTime<Utc>) -> Freshness {
    let Some(synced_at) = record.and_then(|r| r.synced_at) else {
        return Freshness::NeverSynced;
    };
    let age = (now - synced_at).to_std().unwrap_or(Duration::ZERO);
    if age > sla.max_age {
        Freshness::Stale { age }
    } else {
        Freshness::Fresh { age }
    }
}

// ── Publishing ───────────────────────────────────────────────────

fn unix_seconds(at: Option<DateTime<Utc>>) -> f64 {
    at.map_or(0.0, |at| at.timestamp() as f64)
}

/// Publish every configured list's gauges from the ledger rows. A list with
/// no row publishes zeros, which is what arms the alert for it.
pub fn publish(slas: &[ListSla], records: &[ListSyncRecord]) {
    for sla in slas {
        let record = records.iter().find(|r| r.list == sla.list);
        let list = sla.list.as_str();
        metrics::gauge!(SANCTIONS_LIST_MAX_AGE, "list" => list).set(sla.max_age.as_secs_f64());
        metrics::gauge!(SANCTIONS_LIST_SYNCED_TIMESTAMP, "list" => list)
            .set(unix_seconds(record.and_then(|r| r.synced_at)));
        metrics::gauge!(SANCTIONS_LIST_FAILED_TIMESTAMP, "list" => list)
            .set(unix_seconds(record.and_then(|r| r.failed_at)));
        metrics::gauge!(SANCTIONS_LIST_CONTENT_CHANGED_TIMESTAMP, "list" => list)
            .set(unix_seconds(record.and_then(|r| r.content_changed_at)));
        metrics::gauge!(SANCTIONS_LIST_ENTRIES, "list" => list)
            .set(record.and_then(|r| r.entries).unwrap_or(0) as f64);
        metrics::gauge!(SANCTIONS_LIST_EFFECTS_PENDING, "list" => list).set(
            if record.is_some_and(|r| r.effects_pending) {
                1.0
            } else {
                0.0
            },
        );
    }
}

/// Poll the ledger every `interval` and republish, until `shutdown`.
/// Publishes the armed zeros first. A failed read is counted and logged and
/// the previous gauges stay: they are timestamps, so the computed age keeps
/// growing and a persistent failure still ends in `SanctionsListStale`.
pub async fn run_monitor(
    ledger: Arc<dyn SanctionsListStore>,
    slas: Vec<ListSla>,
    interval: Duration,
    shutdown: CancellationToken,
) {
    publish(&slas, &[]);
    metrics::gauge!(SANCTIONS_OUTBOX_OLDEST_PENDING_TIMESTAMP).set(0.0);
    let configured: HashSet<SanctionsList> = slas.iter().map(|sla| sla.list).collect();
    let mut warned_unmonitored = HashSet::new();
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            _ = ticker.tick() => {}
        }
        match ledger.list_syncs().await {
            Ok(records) => {
                publish(&slas, &records);
                for record in &records {
                    if !configured.contains(&record.list) && warned_unmonitored.insert(record.list)
                    {
                        tracing::warn!(
                            list = %record.list,
                            "a sanctions list is being synced but has no freshness SLA; \
                             add it to INTEL_SANCTIONS_LISTS"
                        );
                    }
                }
            }
            Err(err) => {
                metrics::counter!(SANCTIONS_FRESHNESS_READ_FAILURES_TOTAL).increment(1);
                tracing::warn!(error = %err, "reading the sanctions freshness ledger failed");
            }
        }
        match ledger.oldest_pending_announcement().await {
            Ok(oldest) => {
                metrics::gauge!(SANCTIONS_OUTBOX_OLDEST_PENDING_TIMESTAMP).set(unix_seconds(oldest))
            }
            Err(err) => {
                metrics::counter!(SANCTIONS_FRESHNESS_READ_FAILURES_TOTAL).increment(1);
                tracing::warn!(error = %err, "reading the sanctions outbox backlog failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::InMemoryIntelligenceStore;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    const DAY: Duration = Duration::from_secs(86_400);

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    const OFAC: SanctionsList = SanctionsList::OfacSdn;
    const EU: SanctionsList = SanctionsList::EuConsolidated;

    fn synced(list: SanctionsList, secs: i64) -> ListSyncRecord {
        ListSyncRecord {
            list,
            synced_at: Some(at(secs)),
            entries: Some(7),
            content_digest: Some("d".into()),
            content_changed_at: Some(at(secs - 10)),
            source: None,
            validators: Default::default(),
            failed_at: None,
            failure_reason: None,
            effects_pending: true,
        }
    }

    // ── Parsing ─────────────────────────────────────────────────

    #[test]
    fn slas_parse_with_defaults_and_overrides() {
        let slas = parse_list_slas(" ofac_sdn , eu_consolidated=600 ", DAY).unwrap();
        assert_eq!(
            slas,
            vec![
                ListSla {
                    list: OFAC,
                    max_age: DAY
                },
                ListSla {
                    list: EU,
                    max_age: Duration::from_secs(600)
                },
            ]
        );
    }

    #[test]
    fn slas_reject_what_would_silently_disarm_or_never_clear() {
        for bad in [
            "",
            " , ",
            "ofac",
            "etherscan_tags",
            "ofac_sdn,ofac_sdn",
            "ofac_sdn=0",
            "ofac_sdn=soon",
        ] {
            assert!(
                parse_list_slas(bad, DAY).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    // ── Assessing ───────────────────────────────────────────────

    #[test]
    fn assess_is_inclusive_at_the_sla() {
        let sla = ListSla {
            list: OFAC,
            max_age: Duration::from_secs(100),
        };
        let row = synced(OFAC, 1_000);
        assert_eq!(assess(&sla, None, at(0)), Freshness::NeverSynced);
        assert_eq!(
            assess(&sla, Some(&row), at(1_100)),
            Freshness::Fresh {
                age: Duration::from_secs(100)
            }
        );
        assert_eq!(
            assess(&sla, Some(&row), at(1_101)),
            Freshness::Stale {
                age: Duration::from_secs(101)
            }
        );
        // Future-stamped (skew): age zero, not a panic or a negative.
        assert!(assess(&sla, Some(&row), at(900)).is_within_sla());
    }

    /// A row with only failures is still never-synced.
    #[test]
    fn failures_alone_are_never_synced() {
        let sla = ListSla {
            list: EU,
            max_age: DAY,
        };
        let row = ListSyncRecord {
            synced_at: None,
            entries: None,
            failed_at: Some(at(5)),
            failure_reason: Some("503".into()),
            ..synced(EU, 0)
        };
        assert_eq!(assess(&sla, Some(&row), at(10)), Freshness::NeverSynced);
        assert!(row.last_attempt_failed());
    }

    // ── Publishing ──────────────────────────────────────────────

    /// One recorded gauge: name, labels, value.
    type Gauge = (String, Vec<(String, String)>, f64);

    fn gauge(snapshot: &[Gauge], name: &str, list: &str) -> f64 {
        snapshot
            .iter()
            .find(|(n, labels, _)| {
                n == name && labels.iter().any(|(k, v)| k == "list" && v == list)
            })
            .map(|(_, _, v)| *v)
            .unwrap_or_else(|| panic!("no {name}{{list={list}}}"))
    }

    fn gauges(recorder: &DebuggingRecorder) -> Vec<Gauge> {
        recorder
            .snapshotter()
            .snapshot()
            .into_vec()
            .into_iter()
            .filter_map(|(key, _, _, value)| match value {
                DebugValue::Gauge(v) => Some((
                    key.key().name().to_owned(),
                    key.key()
                        .labels()
                        .map(|l| (l.key().to_owned(), l.value().to_owned()))
                        .collect(),
                    v.into_inner(),
                )),
                _ => None,
            })
            .collect()
    }

    /// A configured list with no ledger row publishes zeros — the §15b arming
    /// — and a synced one publishes its timestamps and SLA.
    #[test]
    fn publish_arms_unsynced_lists_with_zeros() {
        let recorder = DebuggingRecorder::new();
        let slas = vec![
            ListSla {
                list: OFAC,
                max_age: Duration::from_secs(3_600),
            },
            ListSla {
                list: EU,
                max_age: DAY,
            },
        ];
        metrics::with_local_recorder(&recorder, || {
            publish(&slas, &[synced(OFAC, 5_000)]);
        });
        let snap = gauges(&recorder);
        assert_eq!(
            gauge(&snap, SANCTIONS_LIST_SYNCED_TIMESTAMP, OFAC.as_str()),
            5_000.0
        );
        assert_eq!(gauge(&snap, SANCTIONS_LIST_MAX_AGE, OFAC.as_str()), 3_600.0);
        assert_eq!(gauge(&snap, SANCTIONS_LIST_ENTRIES, OFAC.as_str()), 7.0);
        assert_eq!(
            gauge(&snap, SANCTIONS_LIST_EFFECTS_PENDING, OFAC.as_str()),
            1.0
        );
        assert_eq!(
            gauge(&snap, SANCTIONS_LIST_EFFECTS_PENDING, EU.as_str()),
            0.0
        );
        assert_eq!(
            gauge(
                &snap,
                SANCTIONS_LIST_CONTENT_CHANGED_TIMESTAMP,
                OFAC.as_str()
            ),
            4_990.0
        );
        assert_eq!(
            gauge(&snap, SANCTIONS_LIST_SYNCED_TIMESTAMP, EU.as_str()),
            0.0
        );
        assert_eq!(
            gauge(&snap, SANCTIONS_LIST_FAILED_TIMESTAMP, EU.as_str()),
            0.0
        );
        assert_eq!(gauge(&snap, SANCTIONS_LIST_MAX_AGE, EU.as_str()), 86_400.0);
    }

    /// The monitor loop reads the ledger and stops on shutdown. Uses the
    /// global-free path: publish is what it calls, so this checks the loop's
    /// control flow, not the gauges again.
    #[tokio::test]
    async fn the_monitor_stops_on_shutdown() {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        store
            .record_sync_failure(OFAC, at(1), "boot")
            .await
            .unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run_monitor(
            store,
            parse_list_slas("ofac_sdn", DAY).unwrap(),
            Duration::from_millis(5),
            shutdown.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(20)).await;
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("monitor stops on shutdown")
            .unwrap();
    }
}
