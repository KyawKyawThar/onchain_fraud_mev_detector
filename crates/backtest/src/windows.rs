//! Committed mainnet replay windows (§18, §20.1; Epic E) → open-world
//! [`Fixture`]s.
//!
//! The files live in `crates/backtest/corpus/mainnet/` and are written by
//! `dataset window` — never by hand, and never synthesised. A window here is
//! the only evidence [`crate::claim`] accepts, so a fabricated one would be a
//! fabricated accuracy number. The directory's README says how to capture one.
//!
//! Loading is all-or-nothing: a malformed, gapped or overlapping window fails
//! the run (see [`corpus::load_dir`]) instead of being skipped, because a
//! skipped window is a silently smaller sample.

use std::path::{Path, PathBuf};

use corpus::{Adjudication, CorpusError, Window};

use crate::fixture::{ExpectedIncident, Fixture};
use crate::Roster;

/// `crates/backtest/corpus/mainnet`, resolved at compile time so the harness
/// works from any CWD.
pub fn default_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/mainnet")
}

/// Why the committed windows could not be turned into fixtures.
#[derive(Debug, thiserror::Error)]
pub enum WindowError {
    #[error(transparent)]
    Corpus(#[from] CorpusError),
    #[error("{path}: {problem}")]
    Invalid {
        path: PathBuf,
        problem: corpus::Invalid,
    },
}

/// Every window in `dir`, as fixtures, in file-name order, with labels
/// resolved against `roster`.
pub fn load_dir(dir: &Path, roster: &Roster) -> Result<Vec<Fixture>, WindowError> {
    corpus::load_dir(dir)?
        .into_iter()
        .map(|(path, window)| to_fixture(&path, &window, roster))
        .collect()
}

/// One window as an open-world fixture: confirmed verdicts become expected
/// incidents, refuted and retracted ones become known false positives, and
/// anything else the replay raises is left unadjudicated. Verdicts for a
/// detector `roster` does not link are orphaned (see [`Roster::resolve`]).
pub fn to_fixture(path: &Path, window: &Window, roster: &Roster) -> Result<Fixture, WindowError> {
    let blocks = window.contexts().map_err(|problem| WindowError::Invalid {
        path: path.to_path_buf(),
        problem,
    })?;

    let mut confirmed = Vec::new();
    let mut refuted = Vec::new();
    let mut orphaned = 0;
    for adj in &window.adjudications {
        let Some(incident) = incident(adj, roster) else {
            orphaned += 1;
            continue;
        };
        if adj.verdict.is_confirmed() {
            confirmed.push(incident);
        } else {
            refuted.push(incident);
        }
    }

    let source = path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    Ok(Fixture::replay(
        window.name.clone(),
        source,
        blocks,
        confirmed,
        refuted,
        orphaned,
    ))
}

fn incident(adj: &Adjudication, roster: &Roster) -> Option<ExpectedIncident> {
    Some(ExpectedIncident {
        block: adj.block,
        detector: roster.resolve(&adj.detector)?,
        kind: adj.kind,
        txs: Some(adj.txs.clone()),
        description: format!(
            "simulation {} this finding from {} {} (config {})",
            adj.verdict.as_str(),
            adj.detector,
            adj.detector_version,
            adj.config_hash
        )
        .into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::GroundTruth;
    use chrono::TimeZone;
    use corpus::{BlockRecord, Provenance as WindowProvenance, Verdict, FORMAT_VERSION};
    use events::primitives::{AlertKind, Chain};

    fn window() -> Window {
        let blocks: Vec<BlockRecord> = crate::fixtures::sandwich()
            .blocks
            .iter()
            .map(BlockRecord::from_ctx)
            .collect();
        let block = blocks[0].number;
        let txs = blocks[0].txs.clone();
        let adj = |verdict| Adjudication {
            block,
            detector: "sandwich".into(),
            detector_version: "1.2.0".into(),
            config_hash: "cfg".into(),
            kind: AlertKind::Sandwich,
            txs: txs.clone(),
            verdict,
        };
        Window {
            format_version: FORMAT_VERSION,
            name: "w".into(),
            provenance: WindowProvenance {
                chain: Chain::ETHEREUM,
                from: chrono::Utc.timestamp_opt(0, 0).unwrap(),
                to: chrono::Utc.timestamp_opt(1, 0).unwrap(),
                lookahead_secs: 1,
                label_rule: "sim-outcome-v1".into(),
                captured_by: "test".into(),
            },
            blocks,
            adjudications: vec![adj(Verdict::Confirmed), adj(Verdict::Retracted)],
            unadjudicated_findings: Default::default(),
        }
    }

    fn roster() -> Roster {
        crate::boot().expect("the built-in roster links cleanly")
    }

    #[test]
    fn verdicts_split_into_expected_and_refuted_with_their_txs_pinned() {
        let fixture = to_fixture(Path::new("corpus/mainnet/w.json"), &window(), &roster()).unwrap();
        assert!(!fixture.provenance().is_closed_world());
        let GroundTruth::Replay {
            source,
            confirmed,
            refuted,
            orphaned,
        } = fixture.truth()
        else {
            panic!("a window is a replay");
        };
        assert_eq!(source, "w.json");
        assert_eq!((confirmed.len(), refuted.len(), *orphaned), (1, 1, 0));
        assert!(confirmed[0].txs.is_some());
        assert_eq!(confirmed[0].detector.as_str(), "sandwich");
    }

    #[test]
    fn a_verdict_for_an_unlinked_detector_is_orphaned_not_scored() {
        // `anomaly` is not linked without a model bundle: its verdicts must
        // not become false negatives for a detector this run cannot see.
        let mut w = window();
        w.adjudications[0].detector = "anomaly".into();
        let fixture = to_fixture(Path::new("w.json"), &w, &roster()).unwrap();
        let GroundTruth::Replay {
            confirmed,
            orphaned,
            ..
        } = fixture.truth()
        else {
            panic!("a window is a replay");
        };
        assert!(confirmed.is_empty());
        assert_eq!(*orphaned, 1);
    }

    #[test]
    fn a_confirmed_verdict_scores_through_the_whole_harness() {
        // End to end: the sandwich window's confirmed verdict is caught, its
        // retracted twin has no second alert to claim and is cleared.
        let roster = roster();
        let fixture = to_fixture(Path::new("w.json"), &window(), &roster).unwrap();
        let result = crate::run_fixture(&fixture, &roster);
        assert_eq!(result.caught.len(), 1);
        assert!(result.unexpected.is_empty());
        assert!(result.unadjudicated.is_empty());
        assert_eq!(result.refutations_cleared, 1);
    }

    #[test]
    fn the_committed_corpus_directory_loads() {
        // Empty today (no enriched mainnet source is wired — see its README),
        // but it must exist and every file in it must be a valid window.
        load_dir(&default_dir(), &roster()).expect("the committed mainnet corpus loads");
    }
}
