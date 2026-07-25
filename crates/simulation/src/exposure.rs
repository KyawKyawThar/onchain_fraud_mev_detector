//! Wallet MEV-exposure aggregation (§11) — the pure fold from a wallet's raw
//! [`ExposureRow`](crate::store::ExposureRow) rows (as read by
//! [`WalletExposureStore::mev_exposure`](crate::store::WalletExposureStore::mev_exposure))
//! into the `GET /v1/wallet/{addr}/mev-exposure` summary ([`crate::http`]).
//!
//! No I/O, no async — a deterministic function of the rows it's given, so it's
//! `assert_eq!`-testable without ClickHouse, mirroring [`crate::result`]'s
//! outcome→events mapping.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::store::ExposureRow;

/// One confirmed incident in the wallet's exposure list, linked to its existing
/// `GET /v1/audit/incident/{incident_id}` audit trail via `incident_id` — callers
/// resolve the full event sequence there rather than this summary duplicating it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct IncidentExposure {
    pub incident_id: Uuid,
    pub kind: String,
    pub usd_lost: f64,
    pub occurred_at: DateTime<Utc>,
}

/// Aggregate counts/totals for one `AlertKind` wire string.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct KindBreakdown {
    pub kind: String,
    pub count: u64,
    pub total_usd_lost: f64,
    pub worst_usd_lost: f64,
}

/// The full `GET /v1/wallet/{addr}/mev-exposure` response body: totals across
/// every confirmed incident, a per-kind breakdown, and the per-incident list each
/// entry links to its audit trail.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct MevExposureSummary {
    pub incident_count: u64,
    pub total_usd_lost: f64,
    pub worst_usd_lost: f64,
    pub by_kind: Vec<KindBreakdown>,
    pub incidents: Vec<IncidentExposure>,
}

/// Fold a wallet's raw exposure rows into the summary. A row with no
/// `incident_id`/`victim_loss_usd` (shouldn't happen for a store-correct
/// `IncidentCreated` snapshot, but the columns are nullable) is
/// skipped rather than panicking — one malformed row can't take down the whole
/// summary (§4).
pub fn summarize(rows: Vec<ExposureRow>) -> MevExposureSummary {
    let mut total_usd_lost = 0.0;
    let mut worst_usd_lost: f64 = 0.0;
    let mut by_kind: BTreeMap<String, KindBreakdown> = BTreeMap::new();
    let mut incidents = Vec::with_capacity(rows.len());

    for row in rows {
        let (Some(incident_id), Some(usd_lost)) = (row.incident_id, row.victim_loss_usd) else {
            continue;
        };

        total_usd_lost += usd_lost;
        worst_usd_lost = worst_usd_lost.max(usd_lost);

        let entry = by_kind.entry(row.kind.clone()).or_insert(KindBreakdown {
            kind: row.kind.clone(),
            count: 0,
            total_usd_lost: 0.0,
            worst_usd_lost: 0.0,
        });
        entry.count += 1;
        entry.total_usd_lost += usd_lost;
        entry.worst_usd_lost = entry.worst_usd_lost.max(usd_lost);

        incidents.push(IncidentExposure {
            incident_id,
            kind: row.kind,
            usd_lost,
            occurred_at: row.occurred_at,
        });
    }

    MevExposureSummary {
        incident_count: incidents.len() as u64,
        total_usd_lost,
        worst_usd_lost,
        by_kind: by_kind.into_values().collect(),
        incidents,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(incident_id: Uuid, kind: &str, usd_lost: f64, secs: i64) -> ExposureRow {
        ExposureRow {
            incident_id: Some(incident_id),
            kind: kind.to_owned(),
            victim_loss_usd: Some(usd_lost),
            occurred_at: DateTime::<Utc>::from_timestamp(secs, 0).unwrap(),
        }
    }

    #[test]
    fn empty_rows_summarize_to_zeroes() {
        let summary = summarize(vec![]);
        assert_eq!(summary.incident_count, 0);
        assert_eq!(summary.total_usd_lost, 0.0);
        assert_eq!(summary.worst_usd_lost, 0.0);
        assert!(summary.by_kind.is_empty());
        assert!(summary.incidents.is_empty());
    }

    #[test]
    fn totals_and_worst_aggregate_across_kinds() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let c = Uuid::from_u128(3);
        let summary = summarize(vec![
            row(a, "sandwich", 100.0, 10),
            row(b, "sandwich", 900.0, 20),
            row(c, "honeypot", 50.0, 30),
        ]);

        assert_eq!(summary.incident_count, 3);
        assert_eq!(summary.total_usd_lost, 1_050.0);
        assert_eq!(
            summary.worst_usd_lost, 900.0,
            "the single largest loss overall"
        );

        assert_eq!(summary.by_kind.len(), 2);
        let sandwich = summary
            .by_kind
            .iter()
            .find(|k| k.kind == "sandwich")
            .expect("sandwich breakdown");
        assert_eq!(sandwich.count, 2);
        assert_eq!(sandwich.total_usd_lost, 1_000.0);
        assert_eq!(sandwich.worst_usd_lost, 900.0);

        let honeypot = summary
            .by_kind
            .iter()
            .find(|k| k.kind == "honeypot")
            .expect("honeypot breakdown");
        assert_eq!(honeypot.count, 1);
        assert_eq!(honeypot.total_usd_lost, 50.0);
    }

    #[test]
    fn each_incident_carries_its_own_id_for_the_audit_trail_link() {
        let id = Uuid::from_u128(42);
        let summary = summarize(vec![row(id, "sandwich", 12.5, 1)]);
        assert_eq!(summary.incidents.len(), 1);
        assert_eq!(summary.incidents[0].incident_id, id);
        assert_eq!(summary.incidents[0].usd_lost, 12.5);
    }

    /// A row missing `incident_id`/`victim_loss_usd` (shouldn't happen for a
    /// well-formed `IncidentCreated` snapshot, but the columns are nullable) is
    /// skipped, not a panic.
    #[test]
    fn a_malformed_row_is_skipped_not_fatal() {
        let malformed = ExposureRow {
            incident_id: None,
            kind: "sandwich".into(),
            victim_loss_usd: Some(10.0),
            occurred_at: DateTime::<Utc>::from_timestamp(1, 0).unwrap(),
        };
        let summary = summarize(vec![malformed]);
        assert_eq!(summary.incident_count, 0);
        assert_eq!(summary.total_usd_lost, 0.0);
    }
}
