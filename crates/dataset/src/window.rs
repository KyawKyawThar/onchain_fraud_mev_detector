//! `dataset window`: capture a **replay window** for the backtest corpus
//! (§18, §20.1; Hardening Epic E).
//!
//! A training export ([`crate::export`]) wants one row per finding. A replay
//! window wants something stricter: *every* canonical block in a range,
//! exactly as the detectors saw it, plus simulation's verdict on each finding
//! the live roster raised. The backtest harness replays those blocks through
//! today's roster and scores its alerts against the verdicts. That is the only
//! way this repository can measure a false-positive rate on real traffic.
//!
//! The stages reuse the export's building blocks:
//!
//! ```text
//!   replay     source::replay_window   [from, to + lookahead), joined types
//!   blocks     BlockAssembled − BlockReverted, consecutive, one per height
//!   context    ctx::CtxSource          every block, Enriched and complete
//!   join       join::join              DetectorTriggered → outcome
//!   verdict    label::LabelRule        trusted bindings only
//!   write      corpus::Window          validated before it is returned
//! ```
//!
//! # Stricter than an export, on purpose
//!
//! An export may carry lower-fidelity rows and stamps each one. A window may
//! not. Its whole value is that a replay reproduces the detectors' input, and
//! a block with missing enrichment would make every detector quiet on it. That
//! reads as perfect precision, the most flattering wrong answer available. So:
//!
//! - every block must resolve at [`Fidelity::Enriched`] and hold exactly
//!   `BlockAssembled.tx_count` transactions;
//! - the canonical blocks must be consecutive, with one per height;
//! - only trusted bindings ([`Binding::is_trusted`]) become verdicts, since
//!   `include_ambiguous` has no equivalent here. A mislabelled verdict is a
//!   wrong accuracy number, not a noisy training row.
//!
//! Any violation is an error, never a skipped block. There is no "partial
//! window".
//!
//! # Where enriched contexts come from
//!
//! [`crate::archive::ArchiveCtxSource`], which reads every block and receipt
//! from an archive node through `chain-enrich`. It is the only source that
//! claims `Enriched`; [`ReplayCtxSource`] never does, so a capture over it
//! refuses on the first block, which is the point.
//!
//! [`Binding::is_trusted`]: crate::join::Binding::is_trusted
//! [`ReplayCtxSource`]: crate::ctx::ReplayCtxSource

use std::collections::{BTreeMap, BTreeSet, HashMap};

use alloy_primitives::B256;
use chrono::{DateTime, Utc};
use corpus::{Adjudication, BlockRecord, Provenance, Verdict, Window, FORMAT_VERSION};
use events::primitives::{AlertId, AlertKind, BlockRef, Chain};
use events::DomainEvent;

use futures_util::{stream, StreamExt, TryStreamExt};

use crate::ctx::{CtxError, CtxSource, CtxSourceFactory, Fidelity};
use crate::join::{self, JOINED_EVENT_TYPES};
use crate::label::{LabelRule, Outcome, LABEL_RULE_ID};
use crate::source::{self, EventSource, SourceError};

/// Which window to capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowSpec {
    pub chain: Chain,
    /// Blocks assembled at or after this instant…
    pub from: DateTime<Utc>,
    /// …and strictly before this one.
    pub to: DateTime<Utc>,
    /// How far past `to` outcomes are read. Same meaning and reason as
    /// [`crate::DatasetSpec::lookahead_secs`]: without it, the findings near
    /// the end of the window lose their verdicts.
    pub lookahead_secs: u64,
    pub name: String,
}

impl WindowSpec {
    fn replay_end(&self) -> DateTime<Utc> {
        self.to + chrono::Duration::seconds(self.lookahead_secs as i64)
    }

    fn covers(&self, at: DateTime<Utc>) -> bool {
        at >= self.from && at < self.to
    }
}

/// Why a window could not be captured.
#[derive(Debug, thiserror::Error)]
pub enum WindowError {
    #[error("window must be non-empty and ordered: from ({from}) < to ({to})")]
    EmptyRange {
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    },
    #[error("lookahead must be non-zero, or findings near the end lose their verdicts")]
    NoLookahead,
    #[error("a window needs a name")]
    Unnamed,
    #[error(transparent)]
    Source(#[from] SourceError),
    #[error(transparent)]
    Ctx(#[from] CtxError),
    #[error("no canonical block was assembled in the range")]
    NoBlocks,
    #[error(
        "block {found} follows block {previous} with no BlockAssembled in between — the store is \
         missing blocks for this range, and a window with a hole is a biased sample"
    )]
    Gap { previous: u64, found: u64 },
    #[error(
        "height {number} has {count} unreverted blocks — the reorg is unresolved in this range"
    )]
    AmbiguousHeight { number: u64, count: usize },
    #[error("block {block}: the context source has no context for it")]
    MissingContext { block: u64 },
    #[error(
        "block {block}: context fidelity is {fidelity}, and a replay window needs enriched — a \
         block without its decoded actions makes every detector silent, which scores as perfect \
         precision. Capture with `--context-source archive` and an archive node in \
         DATASET_ARCHIVE_RPC_URL (crates/backtest/corpus/mainnet/README.md)"
    )]
    InsufficientFidelity { block: u64, fidelity: Fidelity },
    #[error(
        "block {block}: the context holds {found} transactions but BlockAssembled says {expected}"
    )]
    IncompleteBundle {
        block: u64,
        found: usize,
        expected: u32,
    },
    #[error("block {block}: the context source answered for block {answered}")]
    WrongBlock { block: B256, answered: B256 },
    #[error("the captured window failed validation: {0}")]
    Invalid(#[from] corpus::Invalid),
}

/// Knobs for *how* a capture runs, as opposed to *which* window it produces.
/// Nothing here may change the output, which is why these are not on
/// [`WindowSpec`] (the `ExportOptions` split).
#[derive(Debug, Clone, Copy)]
pub struct CaptureOptions {
    /// Ceiling on events held in memory for the replay.
    pub max_events: usize,
    /// How many block contexts are resolved at once. Results are consumed in
    /// block order whatever the completion order, so any value writes the same
    /// bytes. It trades archive-node load against wall time: an hour of
    /// mainnet is ~300 blocks, and resolving them one round trip at a time is
    /// the slow path this exists to avoid.
    pub ctx_concurrency: usize,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            max_events: crate::export::DEFAULT_MAX_EVENTS,
            ctx_concurrency: 16,
        }
    }
}

/// Capture one window. The returned [`Window`] has already passed
/// [`Window::validate`].
///
/// `ctx_factory` is the same seam the export uses: it builds the context
/// source from the replayed events, so a window-derived source and an
/// archive-backed one plug in the same way.
pub async fn capture_window(
    spec: &WindowSpec,
    events: &dyn EventSource,
    ctx_factory: &dyn CtxSourceFactory,
    options: CaptureOptions,
) -> Result<Window, WindowError> {
    if spec.from >= spec.to {
        return Err(WindowError::EmptyRange {
            from: spec.from,
            to: spec.to,
        });
    }
    if spec.lookahead_secs == 0 {
        return Err(WindowError::NoLookahead);
    }
    if spec.name.trim().is_empty() {
        return Err(WindowError::Unnamed);
    }

    let replay = source::replay_window(
        events,
        spec.chain,
        spec.from,
        spec.replay_end(),
        JOINED_EVENT_TYPES,
        options.max_events,
    )
    .await?;

    let canonical = canonical_blocks(spec, &replay)?;
    let ctx_source = ctx_factory.for_window(&replay).await?;

    // `buffered` (not `buffer_unordered`) yields in input order, and
    // `try_collect` stops at the first refusal, so the first failing block in
    // *block order* is the one reported, whatever finished first.
    let ctx_source = ctx_source.as_ref();
    let blocks: Vec<BlockRecord> = stream::iter(canonical.iter().copied())
        .map(|(block, tx_count)| resolve_block(spec.chain, ctx_source, block, tx_count))
        .buffered(options.ctx_concurrency.max(1))
        .try_collect()
        .await?;

    let (adjudications, unadjudicated_findings) = verdicts(spec, &replay, &canonical);

    let window = Window {
        format_version: FORMAT_VERSION,
        name: spec.name.clone(),
        provenance: Provenance {
            chain: spec.chain,
            from: spec.from,
            to: spec.to,
            lookahead_secs: spec.lookahead_secs,
            label_rule: LABEL_RULE_ID.to_owned(),
            captured_by: format!("dataset {}", env!("CARGO_PKG_VERSION")),
        },
        blocks,
        adjudications,
        unadjudicated_findings,
    };
    window.validate()?;
    Ok(window)
}

/// Resolve one block's context and hold it to the window's bar: present,
/// enriched, the block asked for, and complete.
async fn resolve_block(
    chain: Chain,
    ctx_source: &dyn CtxSource,
    block: BlockRef,
    tx_count: u32,
) -> Result<BlockRecord, WindowError> {
    let resolved = ctx_source
        .ctx_for(chain, block)
        .await?
        .ok_or(WindowError::MissingContext {
            block: block.number,
        })?;
    if resolved.fidelity < Fidelity::Enriched {
        return Err(WindowError::InsufficientFidelity {
            block: block.number,
            fidelity: resolved.fidelity,
        });
    }
    if resolved.ctx.block() != block {
        return Err(WindowError::WrongBlock {
            block: block.hash,
            answered: resolved.ctx.block().hash,
        });
    }
    if resolved.ctx.txs().len() as u64 != u64::from(tx_count) {
        return Err(WindowError::IncompleteBundle {
            block: block.number,
            found: resolved.ctx.txs().len(),
            expected: tx_count,
        });
    }
    Ok(BlockRecord::from_ctx(&resolved.ctx))
}

/// The canonical blocks assembled in `[from, to)`, ascending, with their true
/// transaction counts. Refuses gaps and unresolved reorgs.
fn canonical_blocks(
    spec: &WindowSpec,
    replay: &[events::EventEnvelope],
) -> Result<Vec<(BlockRef, u32)>, WindowError> {
    // Reverts anywhere in the replay count, lookahead included: a block
    // orphaned a minute after the window ends was still never canonical.
    let reverted: BTreeSet<B256> = replay
        .iter()
        .filter_map(|e| match &e.payload {
            DomainEvent::BlockReverted(r) => Some(r.block.hash),
            _ => None,
        })
        .collect();

    let mut by_height: BTreeMap<u64, BTreeMap<B256, u32>> = BTreeMap::new();
    for envelope in replay {
        if !spec.covers(envelope.occurred_at) {
            continue;
        }
        if let DomainEvent::BlockAssembled(assembled) = &envelope.payload {
            if !reverted.contains(&assembled.block.hash) {
                by_height
                    .entry(assembled.block.number)
                    .or_default()
                    .insert(assembled.block.hash, assembled.tx_count);
            }
        }
    }

    let mut out = Vec::with_capacity(by_height.len());
    for (number, hashes) in by_height {
        if hashes.len() != 1 {
            return Err(WindowError::AmbiguousHeight {
                number,
                count: hashes.len(),
            });
        }
        if let Some((previous, _)) = out.last().map(|(b, c): &(BlockRef, u32)| (b.number, c)) {
            if number != previous + 1 {
                return Err(WindowError::Gap {
                    previous,
                    found: number,
                });
            }
        }
        let (hash, tx_count) = hashes.into_iter().next().expect("checked len == 1");
        out.push((BlockRef::new(number, hash), tx_count));
    }
    if out.is_empty() {
        return Err(WindowError::NoBlocks);
    }
    Ok(out)
}

/// Simulation's verdicts on the window's findings, plus a count of the ones
/// that got none, keyed by why.
fn verdicts(
    spec: &WindowSpec,
    replay: &[events::EventEnvelope],
    canonical: &[(BlockRef, u32)],
) -> (Vec<Adjudication>, BTreeMap<String, u64>) {
    let kinds: HashMap<AlertId, AlertKind> = replay
        .iter()
        .filter_map(|e| match &e.payload {
            DomainEvent::PreliminaryAlertCreated(a) => Some((a.alert_id, a.kind)),
            _ => None,
        })
        .collect();
    let in_window: BTreeSet<B256> = canonical.iter().map(|(b, _)| b.hash).collect();

    let joined = join::join(spec.chain, replay);
    let mut adjudications = Vec::new();
    let mut unadjudicated: BTreeMap<String, u64> = BTreeMap::new();
    let mut skip = |why: &str| *unadjudicated.entry(why.to_owned()).or_default() += 1;

    for finding in &joined.findings {
        // Findings in the lookahead tail only resolve outcomes; they belong to
        // the next window.
        if !spec.covers(finding.occurred_at) {
            continue;
        }
        // Never `include_ambiguous`: see the module docs.
        let outcome = finding.effective_outcome(false);
        let verdict = match outcome {
            Outcome::Confirmed { .. } => Verdict::Confirmed,
            Outcome::Refuted => Verdict::Refuted,
            Outcome::Retracted => Verdict::Retracted,
            other => {
                debug_assert!(LabelRule.apply(other).is_none());
                skip(other.as_str());
                continue;
            }
        };
        if !in_window.contains(&finding.block.hash) {
            // A late trigger for a block assembled before `from`.
            skip("block_outside_window");
            continue;
        }
        let Some(kind) = finding.alert_id.and_then(|id| kinds.get(&id).copied()) else {
            // A verdict implies a bound alert, and the alert came from this
            // replay. Unreachable, but a guess would be worse than a count.
            skip(Outcome::Unlinkable.as_str());
            continue;
        };
        adjudications.push(Adjudication {
            block: finding.block.number,
            detector: finding.detector.id.clone(),
            detector_version: finding.detector.version.clone(),
            config_hash: finding.detector.config_hash.clone(),
            kind,
            txs: finding.txs.clone(),
            verdict,
        });
    }
    (adjudications, unadjudicated)
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::TimeZone;
    use detector_api::test_util::{addr, transfer, CtxBuilder};
    use detector_api::{BlockBundle, DetectionCtx};
    use events::chain::{BlockAssembled, BlockReverted};
    use events::detection::{DetectorTriggered, PreliminaryAlertCreated};
    use events::primitives::{Confidence, DetectorRef, IncidentId, Severity, SuggestedAction};
    use events::simulation::{IncidentCreated, IncidentRetracted, SimulationCompleted};
    use events::EventEnvelope;
    use uuid::Uuid;

    use std::sync::Arc;

    use crate::ctx::{MapCtxSource, ReplayCtxFactory, StaticCtxFactory};
    use crate::source::VecEventSource;

    const CHAIN: Chain = Chain::ETHEREUM;
    const T0: i64 = 1_700_000_000;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    fn spec() -> WindowSpec {
        WindowSpec {
            chain: CHAIN,
            from: at(T0),
            to: at(T0 + 100),
            lookahead_secs: 3_600,
            name: "test window".into(),
        }
    }

    fn envelope(seq: u32, secs: i64, payload: DomainEvent) -> EventEnvelope {
        EventEnvelope::with_metadata(Uuid::from_u128(u128::from(seq)), at(secs), CHAIN, payload)
    }

    fn block(number: u64) -> BlockRef {
        BlockRef::new(number, B256::with_last_byte(number as u8))
    }

    fn tx(b: u8) -> B256 {
        B256::repeat_byte(b)
    }

    fn detector() -> DetectorRef {
        DetectorRef {
            id: "sandwich".into(),
            version: "1.2.0".into(),
            config_hash: "deadbeef".into(),
        }
    }

    /// An enriched context for `b` with the given transactions.
    fn enriched(b: BlockRef, txs: &[u8]) -> DetectionCtx {
        let mut builder = CtxBuilder::new()
            .at(CHAIN, b)
            .priced_token(addr(0x77), 18, 2.0);
        for &t in txs {
            builder = builder.transfer_tx(
                tx(t),
                addr(t),
                vec![transfer(addr(0x77), addr(t), addr(0xee), 1_000)],
            );
        }
        builder.build()
    }

    fn assembled(b: BlockRef, tx_count: u32) -> DomainEvent {
        DomainEvent::BlockAssembled(BlockAssembled {
            block: b,
            tx_count,
            trace_available: true,
        })
    }

    fn trigger(b: BlockRef, txs: Vec<B256>, confidence: f64) -> DomainEvent {
        DomainEvent::DetectorTriggered(DetectorTriggered {
            detector: detector(),
            block: b,
            txs,
            raw_confidence: Confidence::new(confidence),
            evidence: serde_json::json!({}),
        })
    }

    fn alert(id: u128, confidence: f64) -> DomainEvent {
        DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
            alert_id: AlertId(Uuid::from_u128(id)),
            detector: detector(),
            addresses: vec![],
            kind: AlertKind::Sandwich,
            confidence: Confidence::new(confidence),
            provisional: true,
            impact_usd: None,
            severity: Severity::Low,
            suggested_action: SuggestedAction::Monitor,
        })
    }

    fn sim(id: u128, confirmed: bool) -> DomainEvent {
        DomainEvent::SimulationCompleted(SimulationCompleted {
            alert_id: AlertId(Uuid::from_u128(id)),
            profit: 1.0,
            victim_loss: 0.0,
            confirmed,
        })
    }

    /// Blocks 100 (three txs, a confirmed and a refuted finding) and 101 (one
    /// tx, quiet), plus a trigger whose simulation never finished.
    fn history() -> Vec<EventEnvelope> {
        vec![
            envelope(0, T0, assembled(block(100), 3)),
            envelope(1, T0 + 1, trigger(block(100), vec![tx(1), tx(2)], 0.9)),
            envelope(2, T0 + 2, alert(0xa1, 0.9)),
            envelope(3, T0 + 3, trigger(block(100), vec![tx(3)], 0.4)),
            envelope(4, T0 + 4, alert(0xa2, 0.4)),
            envelope(5, T0 + 12, assembled(block(101), 1)),
            envelope(6, T0 + 13, trigger(block(101), vec![tx(9)], 0.7)),
            envelope(7, T0 + 14, alert(0xa3, 0.7)),
            // Outcomes land in the lookahead tail — still read.
            envelope(8, T0 + 200, sim(0xa1, true)),
            envelope(9, T0 + 201, sim(0xa2, false)),
        ]
    }

    fn contexts() -> MapCtxSource {
        MapCtxSource::new()
            .with(enriched(block(100), &[1, 2, 3]), Fidelity::Enriched)
            .with(enriched(block(101), &[9]), Fidelity::Enriched)
    }

    async fn capture(events: Vec<EventEnvelope>, ctx: MapCtxSource) -> Result<Window, WindowError> {
        let factory = StaticCtxFactory::new(Arc::new(ctx));
        capture_window(
            &spec(),
            &VecEventSource::new(events),
            &factory,
            CaptureOptions::default(),
        )
        .await
    }

    #[tokio::test]
    async fn captures_every_block_and_only_the_adjudicated_findings() {
        let window = capture(history(), contexts()).await.unwrap();

        let numbers: Vec<u64> = window.blocks.iter().map(|b| b.number).collect();
        assert_eq!(numbers, [100, 101], "the quiet block is kept too");
        assert_eq!(
            window.contexts().unwrap()[0],
            enriched(block(100), &[1, 2, 3])
        );

        let verdicts: Vec<(Verdict, Vec<B256>)> = window
            .adjudications
            .iter()
            .map(|a| (a.verdict, a.txs.clone()))
            .collect();
        assert_eq!(
            verdicts,
            [
                (Verdict::Confirmed, vec![tx(1), tx(2)]),
                (Verdict::Refuted, vec![tx(3)]),
            ]
        );
        assert!(window
            .adjudications
            .iter()
            .all(|a| a.kind == AlertKind::Sandwich && a.detector_version == "1.2.0"));
        assert_eq!(
            window.unadjudicated_findings.get("unresolved"),
            Some(&1),
            "the finding simulation never finished is counted, not labelled"
        );
        assert_eq!(window.provenance.label_rule, LABEL_RULE_ID);
    }

    #[tokio::test]
    async fn one_history_always_captures_the_same_bytes() {
        let a = serde_json::to_string(&capture(history(), contexts()).await.unwrap()).unwrap();
        let b = serde_json::to_string(&capture(history(), contexts()).await.unwrap()).unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn a_retraction_is_its_own_verdict() {
        let incident = IncidentId::new();
        let mut events = history();
        events.push(envelope(
            10,
            T0 + 202,
            DomainEvent::IncidentCreated(IncidentCreated {
                incident_id: incident,
                alert_id: AlertId(Uuid::from_u128(0xa1)),
                kind: AlertKind::Sandwich,
                txs: vec![tx(1), tx(2)],
                profit: 1.0,
                victim_loss: 0.0,
                impact_usd: None,
                severity: Severity::Low,
                suggested_action: SuggestedAction::Monitor,
                victim_address: None,
                victim_loss_usd: None,
            }),
        ));
        events.push(envelope(
            11,
            T0 + 203,
            DomainEvent::IncidentRetracted(IncidentRetracted {
                incident_id: incident,
                reason: "reorg".into(),
            }),
        ));
        let window = capture(events, contexts()).await.unwrap();
        assert_eq!(window.adjudications[0].verdict, Verdict::Retracted);
    }

    #[tokio::test]
    async fn concurrency_never_changes_the_bytes_or_the_reported_block() {
        let serial = CaptureOptions {
            ctx_concurrency: 1,
            ..CaptureOptions::default()
        };
        let wide = CaptureOptions {
            ctx_concurrency: 64,
            ..CaptureOptions::default()
        };
        let capture_with = |options, ctx: MapCtxSource| async move {
            let factory = StaticCtxFactory::new(Arc::new(ctx));
            capture_window(&spec(), &VecEventSource::new(history()), &factory, options).await
        };
        let a = capture_with(serial, contexts()).await.unwrap();
        let b = capture_with(wide, contexts()).await.unwrap();
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );

        // Both blocks are bad; the earlier one is the one named, at any width.
        let both_bad = || {
            MapCtxSource::new()
                .with(enriched(block(100), &[1, 2, 3]), Fidelity::FullBundle)
                .with(enriched(block(101), &[9]), Fidelity::HeaderOnly)
        };
        for options in [serial, wide] {
            assert!(matches!(
                capture_with(options, both_bad()).await,
                Err(WindowError::InsufficientFidelity { block: 100, .. })
            ));
        }
    }

    #[tokio::test]
    async fn anything_below_enriched_is_refused() {
        for fidelity in [
            Fidelity::HeaderOnly,
            Fidelity::PartialBundle,
            Fidelity::FullBundle,
        ] {
            let ctx = MapCtxSource::new()
                .with(enriched(block(100), &[1, 2, 3]), fidelity)
                .with(enriched(block(101), &[9]), Fidelity::Enriched);
            let err = capture(history(), ctx).await.unwrap_err();
            assert!(
                matches!(err, WindowError::InsufficientFidelity { block: 100, .. }),
                "{fidelity}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn the_replay_context_source_is_always_refused() {
        // Replay-rebuilt contexts never carry the enrichment a window needs.
        let err = capture_window(
            &spec(),
            &VecEventSource::new(history()),
            &ReplayCtxFactory,
            CaptureOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, WindowError::InsufficientFidelity { .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_missing_block_is_refused() {
        let mut events = history();
        events.push(envelope(20, T0 + 30, assembled(block(103), 0)));
        let ctx = contexts().with(
            DetectionCtx::new(BlockBundle::new(CHAIN, block(103), vec![])),
            Fidelity::Enriched,
        );
        assert!(matches!(
            capture(events, ctx).await,
            Err(WindowError::Gap {
                previous: 101,
                found: 103
            })
        ));
    }

    #[tokio::test]
    async fn a_block_with_no_context_is_refused() {
        let ctx = MapCtxSource::new().with(enriched(block(100), &[1, 2, 3]), Fidelity::Enriched);
        assert!(matches!(
            capture(history(), ctx).await,
            Err(WindowError::MissingContext { block: 101 })
        ));
    }

    #[tokio::test]
    async fn an_incomplete_bundle_is_refused_whatever_fidelity_it_claims() {
        let ctx = MapCtxSource::new()
            .with(enriched(block(100), &[1, 2]), Fidelity::Enriched)
            .with(enriched(block(101), &[9]), Fidelity::Enriched);
        assert!(matches!(
            capture(history(), ctx).await,
            Err(WindowError::IncompleteBundle {
                block: 100,
                found: 2,
                expected: 3
            })
        ));
    }

    #[tokio::test]
    async fn a_reverted_block_is_dropped_and_its_replacement_kept() {
        let orphan = BlockRef::new(101, B256::repeat_byte(0xde));
        let mut events = history();
        events.push(envelope(20, T0 + 11, assembled(orphan, 5)));
        events.push(envelope(
            21,
            T0 + 15,
            DomainEvent::BlockReverted(BlockReverted {
                block: orphan,
                replaced_by: block(101).hash,
            }),
        ));
        let window = capture(events, contexts()).await.unwrap();
        assert_eq!(window.blocks[1].hash, block(101).hash);
    }

    #[tokio::test]
    async fn two_live_blocks_at_one_height_are_refused() {
        let mut events = history();
        events.push(envelope(
            20,
            T0 + 11,
            assembled(BlockRef::new(101, B256::repeat_byte(0xde)), 5),
        ));
        assert!(matches!(
            capture(events, contexts()).await,
            Err(WindowError::AmbiguousHeight {
                number: 101,
                count: 2
            })
        ));
    }

    #[tokio::test]
    async fn an_ambiguous_binding_is_never_a_verdict() {
        // Two same-confidence triggers stamped the same instant: which alert
        // belongs to which is a guess, so neither gets a verdict.
        let events = vec![
            envelope(0, T0, assembled(block(100), 3)),
            envelope(1, T0 + 1, trigger(block(100), vec![tx(1)], 0.5)),
            envelope(2, T0 + 1, trigger(block(100), vec![tx(2)], 0.5)),
            envelope(3, T0 + 1, alert(0xb1, 0.5)),
            envelope(4, T0 + 1, alert(0xb2, 0.5)),
            envelope(5, T0 + 12, assembled(block(101), 1)),
            envelope(6, T0 + 50, sim(0xb1, true)),
            envelope(7, T0 + 51, sim(0xb2, false)),
        ];
        let window = capture(events, contexts()).await.unwrap();
        assert!(
            window.adjudications.is_empty(),
            "{:?}",
            window.adjudications
        );
        assert_eq!(window.unadjudicated_findings.get("unlinkable"), Some(&2));
    }

    #[tokio::test]
    async fn findings_in_the_lookahead_tail_belong_to_the_next_window() {
        let mut events = history();
        events.push(envelope(
            30,
            T0 + 150,
            trigger(block(101), vec![tx(9)], 0.3),
        ));
        events.push(envelope(31, T0 + 151, alert(0xc1, 0.3)));
        events.push(envelope(32, T0 + 152, sim(0xc1, false)));
        let window = capture(events, contexts()).await.unwrap();
        assert_eq!(window.adjudications.len(), 2);
    }

    #[tokio::test]
    async fn an_invalid_spec_is_refused_before_any_io() {
        let empty = VecEventSource::new(vec![]);
        let ctx = StaticCtxFactory::new(Arc::new(MapCtxSource::new()));
        let mut s = spec();
        s.to = s.from;
        assert!(matches!(
            capture_window(&s, &empty, &ctx, CaptureOptions::default()).await,
            Err(WindowError::EmptyRange { .. })
        ));
        let mut s = spec();
        s.lookahead_secs = 0;
        assert!(matches!(
            capture_window(&s, &empty, &ctx, CaptureOptions::default()).await,
            Err(WindowError::NoLookahead)
        ));
        let mut s = spec();
        s.name = " ".into();
        assert!(matches!(
            capture_window(&s, &empty, &ctx, CaptureOptions::default()).await,
            Err(WindowError::Unnamed)
        ));
    }
}
