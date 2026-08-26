//! The export pipeline: spec + event source + context factory + sink →
//! [`DatasetManifest`].
//!
//! Five stages, in order, each one already tested in its own module:
//!
//! ```text
//!   replay      source::replay_window   the window, in the store's total order
//!   context     ctx::CtxSource          one DetectionCtx per block
//!   join        join::join              DetectorTriggered → outcome
//!   extract     ml_features             one FeatureVector per row
//!   write       sink::DatasetSink       ClickHouse / Parquet / memory
//! ```
//!
//! Everything here is a total function of `(spec, stored events, ctx source)`.
//! There is no clock, no randomness and no iteration over a hash map's order in
//! the row-producing path — which is the whole reason a manifest's
//! `content_hash` means something.
//!
//! # Sharding: how a window bigger than memory gets exported
//!
//! A replay window is materialised in memory (the join needs to see a
//! finding's whole lifecycle, and two passes run over it), so a month of a busy
//! chain will not fit. [`ExportOptions::shard`] splits `[from, to)` into
//! consecutive sub-windows and runs each in turn against the **same** sink and
//! the **same** running digest. Peak memory becomes a function of the shard
//! duration rather than of the window, and a long export reports progress per
//! shard instead of going dark for hours.
//!
//! Sharding is deliberately **not** part of [`DatasetSpec`], because it must
//! not change the dataset. Two things make that true:
//!
//! - [`DatasetSpec::lookahead_secs`] makes a finding's label depend on events
//!   near the *finding*, not on where the window ends — so a shard boundary
//!   cannot truncate a label the way a window edge used to (see that field's
//!   docs for the bug this fixes).
//! - [`row::RowDigest`] streams, so shards fold into one hash in window order.
//!   The digest is over the rows; it never sees how they were sliced.
//!
//! Shards run **sequentially**. Running them concurrently would need a digest
//! that combines out of order — a Merkle root over per-shard hashes — which
//! would make the dataset's identity depend on the shard boundaries, exactly
//! the coupling the two points above remove. Parallelism is worth having, but
//! not at the cost of the property that makes the digest meaningful; the
//! honest version is a separate `dataset merge` over independently-exported
//! shard manifests.
//!
//! # Amortisation
//!
//! Findings are grouped by block before extraction, so each block's
//! [`BlockFeatureView`] is built **once** and every finding on that block reads
//! from it — the §17 amortisation discipline `ml-features` was shaped around
//! (its `extract_all_txs` went O(n²) → O(n) for exactly this call site). The
//! grouping is a `BTreeMap`, so it is ordered, and rows are then emitted back
//! in the *findings'* original order rather than block order: row order comes
//! from the store, always.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use ml_features::{FeatureVector, Granularity};

use crate::ctx::{CtxError, CtxSource, CtxSourceFactory, ResolvedCtx};
use crate::join::{self, Finding, JoinStats};
use crate::label::LabelRule;
use crate::manifest::{DatasetManifest, RowCounts};
use crate::row::{self, DatasetRow, RowDigest};
use crate::sink::{DatasetSink, SinkError};
use crate::source::{self, EventSource, SourceError};
use crate::spec::{DatasetSpec, SpecError};

/// Rows per sink write. Sized for ClickHouse's parts economics (few, large
/// inserts) while keeping the memory a single batch holds bounded.
pub const WRITE_BATCH_ROWS: usize = 10_000;

/// Default in-memory ceiling on **one shard's** replay. Overshooting is a clear
/// error rather than a swap-death; the fix is a smaller `--shard`, which the
/// message says.
pub const DEFAULT_MAX_EVENTS: usize = 2_000_000;

/// Anything that can stop an export.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error(transparent)]
    Spec(#[from] SpecError),
    #[error(transparent)]
    Source(#[from] SourceError),
    #[error(transparent)]
    Ctx(#[from] CtxError),
    #[error(transparent)]
    Sink(#[from] SinkError),

    /// Too large a share of the labeled findings could not be turned into rows
    /// for want of a usable context.
    ///
    /// This is a **data-quality** gate, not an ops one, and it is worth failing
    /// on. Both drop paths — a fidelity below `--min-fidelity`, and a
    /// reconstruction that happened to miss a finding's transactions —
    /// correlate with *busy, complex blocks*, which is exactly where MEV
    /// happens. So a high drop rate does not merely shrink the dataset, it
    /// biases it toward quiet blocks, and a model trained on it would
    /// underperform precisely where it matters. That damage is invisible in
    /// the output, so the export refuses rather than hands over a
    /// plausible-looking file.
    #[error(
        "{dropped} of {labeled} labeled findings ({percent:.1}%) had no usable context, over \
         the {limit:.1}% limit — the drops correlate with busy blocks, so the dataset would \
         be biased toward quiet ones; lower --min-fidelity, fix the context source, or raise \
         --max-drop-fraction deliberately"
    )]
    ExcessiveDrop {
        dropped: u64,
        labeled: u64,
        percent: f64,
        limit: f64,
    },
}

/// Knobs that describe *how* to run an export, as opposed to *which* dataset
/// it produces. Deliberately separate from [`DatasetSpec`]: nothing here may
/// change the rows, so nothing here is in the `dataset_id`.
#[derive(Debug, Clone, Copy)]
pub struct ExportOptions {
    /// Ceiling on events held in memory for **one shard's** replay.
    pub max_events: usize,
    pub write_batch_rows: usize,
    /// Split `[from, to)` into consecutive sub-windows of this length, run in
    /// order against one sink and one digest. `None` runs the whole window as a
    /// single shard. See the module docs for why this cannot change the
    /// dataset.
    pub shard: Option<Duration>,
    /// Refuse the export when more than this fraction of *labeled* findings
    /// were dropped for want of a usable context (see
    /// [`ExportError::ExcessiveDrop`]). `None` reports without gating.
    ///
    /// The library defaults to `None` — a mechanism reports, it does not decide
    /// policy — while the `dataset` binary sets a real value, because the
    /// operator running an export is who the gate protects.
    pub max_drop_fraction: Option<f64>,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            max_events: DEFAULT_MAX_EVENTS,
            write_batch_rows: WRITE_BATCH_ROWS,
            shard: None,
            max_drop_fraction: None,
        }
    }
}

impl ExportOptions {
    /// The consecutive sub-windows `[from, to)` is exported in: one per shard,
    /// or a single whole-window shard when unsharded. Always non-empty for a
    /// validated spec.
    fn shards(&self, spec: &DatasetSpec) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
        let Some(step) = self.shard.filter(|d| *d > Duration::zero()) else {
            return vec![(spec.from, spec.to)];
        };
        let mut shards = Vec::new();
        let mut cursor = spec.from;
        while cursor < spec.to {
            // `checked_add` guards a shard length that would overflow the
            // calendar; saturating at `to` is the right answer either way.
            let end = cursor
                .checked_add_signed(step)
                .unwrap_or(spec.to)
                .min(spec.to);
            shards.push((cursor, end));
            cursor = end;
        }
        shards
    }
}

/// Run an export end to end.
///
/// Returns the manifest, which the caller prints and/or persists. The sink has
/// already been [`finish`](DatasetSink::finish)ed by the time this returns.
///
/// Shards (if [`ExportOptions::shard`] is set) run in order against this one
/// sink and one running digest, so the result is identical to an unsharded run
/// — see the module docs.
#[must_use = "the manifest carries the content hash that makes the export checkable"]
pub async fn run_export(
    spec: &DatasetSpec,
    events: &dyn EventSource,
    ctx_factory: &dyn CtxSourceFactory,
    sink: &mut dyn DatasetSink,
    options: ExportOptions,
) -> Result<DatasetManifest, ExportError> {
    spec.validate()?;

    let schema = ml_features::extractor_for(spec.feature_version)
        .ok_or(SpecError::UnknownFeatureVersion {
            version: spec.feature_version,
        })?
        .schema(spec.granularity);

    let shards = options.shards(spec);
    let mut digest = RowDigest::new();
    let mut counts = RowCounts::default();
    let mut stats = JoinStats::default();

    for (index, (from, to)) in shards.iter().copied().enumerate() {
        // A shard is the same spec over a sub-window: same feature version,
        // same label rule, same filters — only the range moves.
        let shard_spec = DatasetSpec {
            from,
            to,
            ..spec.clone()
        };

        let window = source::replay_window_types(events, &shard_spec, options.max_events).await?;
        let joined = join::join(spec.chain, &window);
        tracing::info!(
            shard = index + 1,
            of = shards.len(),
            %from,
            %to,
            events = window.len(),
            findings = joined.findings.len(),
            "replayed and joined shard"
        );

        // Rows are attributed to the *whole* dataset, not the shard: the spec
        // is the identity, sharding is only how the work was done.
        let ctx_source = ctx_factory.for_window(&window).await?;
        let rows = extract_rows(
            spec,
            &shard_spec,
            &joined.findings,
            ctx_source.as_ref(),
            &mut counts,
        )
        .await?;

        // Write in batches so a large dataset is one part per batch rather than
        // one per row (ClickHouse) or one row group per row (Parquet).
        for batch in rows.chunks(options.write_batch_rows.max(1)) {
            sink.write(batch).await?;
            digest.update_all(batch);
        }
        // `rows` (and the shard's window, join and contexts) drop here — this
        // is what keeps peak memory a function of the shard, not the window.
        stats.merge(joined.stats);
    }

    check_drop_rate(&counts, options.max_drop_fraction)?;

    let manifest = DatasetManifest::new(
        spec,
        schema.content_hash(),
        schema.names().map(str::to_owned).collect(),
        digest,
        counts,
        stats,
    );
    sink.finish(&manifest).await?;
    Ok(manifest)
}

/// Fail the export when too many labeled findings had no usable context — see
/// [`ExportError::ExcessiveDrop`] for why this is a correctness gate.
fn check_drop_rate(counts: &RowCounts, limit: Option<f64>) -> Result<(), ExportError> {
    let Some(limit) = limit else { return Ok(()) };
    let dropped = counts.dropped_for_context();
    if counts.labeled == 0 || dropped == 0 {
        return Ok(());
    }
    let fraction = dropped as f64 / counts.labeled as f64;
    if fraction > limit {
        return Err(ExportError::ExcessiveDrop {
            dropped,
            labeled: counts.labeled,
            percent: fraction * 100.0,
            limit: limit * 100.0,
        });
    }
    Ok(())
}

/// Stages 2–4 for one shard: resolve each block's context once, extract, label.
///
/// `spec` is the *dataset's* spec (it owns the id and the policy); `shard_spec`
/// is the sub-window whose `[from, to)` decides which findings this call emits
/// rows for. The findings outside it came from the lookahead tail: they were
/// folded through the join to resolve in-window outcomes, and must not become
/// rows of their own or they would be exported twice — once here and once by
/// the next shard.
///
/// Counts accumulate into `counts` across shards.
async fn extract_rows(
    spec: &DatasetSpec,
    shard_spec: &DatasetSpec,
    findings: &[Finding],
    ctx_source: &dyn CtxSource,
    counts: &mut RowCounts,
) -> Result<Vec<DatasetRow>, ExportError> {
    // The extractor for this dataset's version, not necessarily the current
    // one — that is what keeps an old dataset regenerable after
    // `FEATURE_VERSION` moves on (§20.1).
    let extractor = ml_features::extractor_for(spec.feature_version).ok_or(
        SpecError::UnknownFeatureVersion {
            version: spec.feature_version,
        },
    )?;
    let schema = extractor.schema(spec.granularity);
    // Hoisted: `content_hash` is a real SHA-256 over the schema text, and every
    // row carries the same one. Computing it per row would be a digest per
    // example for a value that cannot change mid-export.
    let schema_hash = schema.content_hash();
    let dataset_id = spec.dataset_id();

    // Only findings inside this shard's own window produce rows.
    let emitted: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter_map(|(i, f)| shard_spec.emits(f.occurred_at).then_some(i))
        .collect();
    counts.lookahead_only += (findings.len() - emitted.len()) as u64;

    // Group finding indices by block so each block's view is built once.
    // `BTreeMap` keyed by (number, hash) so the *resolution* order is
    // deterministic too, not just the output order.
    let mut by_block: BTreeMap<(u64, alloy_primitives::B256), Vec<usize>> = BTreeMap::new();
    for &index in &emitted {
        let finding = &findings[index];
        by_block
            .entry((finding.block.number, finding.block.hash))
            .or_default()
            .push(index);
    }

    // Rows are collected against their finding index, then flattened in that
    // order — so output order is the trigger stream's order regardless of how
    // blocks were grouped.
    let mut rows_by_finding: BTreeMap<usize, Vec<DatasetRow>> = BTreeMap::new();

    for (_, indices) in by_block {
        let first = &findings[indices[0]];
        let resolved = ctx_source.ctx_for(first.chain, first.block).await?;

        // Accounting order matters: a finding with no ground truth is
        // `unlabeled` whether or not a context existed, so the label rule is
        // applied *before* the context is consulted. Only labeled findings can
        // be "dropped for want of a context", which is what makes
        // `dropped_for_context / labeled` an honest bias measure.
        let Some(ResolvedCtx { ctx, fidelity }) = resolved else {
            for &index in &indices {
                let outcome = findings[index].effective_outcome(spec.include_ambiguous);
                RowCounts::bump(&mut counts.by_outcome, outcome.as_str());
                match LabelRule.apply(outcome) {
                    None => counts.unlabeled += 1,
                    Some(_) => {
                        counts.labeled += 1;
                        counts.no_context += 1;
                    }
                }
            }
            continue;
        };

        // One view per block — the §17 amortisation this API exists for.
        let view = ml_features::BlockFeatureView::new(&ctx);
        let block_vector = view.block_vector();
        // Per-tx vectors are only built when the granularity needs them.
        let tx_vectors: BTreeMap<alloy_primitives::B256, FeatureVector> =
            if spec.granularity == Granularity::Tx {
                view.all_tx_vectors().into_iter().collect()
            } else {
                BTreeMap::new()
            };

        for &index in &indices {
            let finding = &findings[index];
            let outcome = finding.effective_outcome(spec.include_ambiguous);
            RowCounts::bump(&mut counts.by_outcome, outcome.as_str());
            RowCounts::bump(&mut counts.by_fidelity, fidelity.as_str());

            let Some(label) = LabelRule.apply(outcome) else {
                counts.unlabeled += 1;
                continue;
            };
            counts.labeled += 1;
            if fidelity < spec.min_fidelity {
                counts.below_min_fidelity += 1;
                continue;
            }

            let built = match spec.granularity {
                Granularity::Block => vec![row::build_row(
                    &dataset_id,
                    finding,
                    None,
                    &block_vector,
                    &schema_hash,
                    fidelity,
                    label,
                    outcome,
                )],
                Granularity::Tx => finding
                    .txs
                    .iter()
                    .filter_map(|tx| {
                        tx_vectors.get(tx).map(|vector| {
                            row::build_row(
                                &dataset_id,
                                finding,
                                Some(*tx),
                                vector,
                                &schema_hash,
                                fidelity,
                                label,
                                outcome,
                            )
                        })
                    })
                    .collect(),
            };

            if built.is_empty() {
                // Tx granularity, and the reconstructed bundle held none of the
                // implicated transactions — a partial context that happened to
                // miss exactly the txs this finding is about.
                counts.no_extractable_tx += 1;
                continue;
            }
            for _ in &built {
                RowCounts::bump(&mut counts.by_label, label.as_str());
            }
            counts.written += built.len() as u64;
            rows_by_finding.insert(index, built);
        }
    }

    // Keyed by finding index, so flattening restores the trigger stream's
    // order — the store's order — regardless of block grouping.
    Ok(rows_by_finding.into_values().flatten().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_primitives::B256;
    use chrono::{DateTime, TimeZone, Utc};
    use detector_api::test_util::{addr, transfer, CtxBuilder};
    use detector_api::DetectionCtx;
    use events::chain::BlockAssembled;
    use events::detection::{DetectorTriggered, PreliminaryAlertCreated};
    use events::primitives::{
        AlertId, AlertKind, BlockRef, Chain, Confidence, DetectorRef, Severity, SuggestedAction,
    };
    use events::simulation::SimulationCompleted;
    use events::{DomainEvent, EventEnvelope};
    use uuid::Uuid;

    use crate::ctx::{Fidelity, MapCtxSource, StaticCtxFactory};
    use crate::label::Label;
    use crate::sink::CollectingSink;
    use crate::source::VecEventSource;

    const CHAIN: Chain = Chain::ETHEREUM;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    fn spec(granularity: Granularity) -> DatasetSpec {
        DatasetSpec {
            chain: CHAIN,
            from: at(1_700_000_000),
            to: at(1_700_001_000),
            feature_version: ml_features::FEATURE_VERSION,
            granularity,
            min_fidelity: Fidelity::HeaderOnly,
            include_ambiguous: false,
            lookahead_secs: crate::spec::DEFAULT_LOOKAHEAD_SECS,
        }
    }

    fn envelope(seq: u32, payload: DomainEvent) -> EventEnvelope {
        EventEnvelope::with_metadata(
            Uuid::from_u128(u128::from(seq)),
            at(1_700_000_000 + i64::from(seq)),
            CHAIN,
            payload,
        )
    }

    fn detector() -> DetectorRef {
        DetectorRef {
            id: "sandwich".into(),
            version: "1.2.0".into(),
            config_hash: "deadbeef".into(),
        }
    }

    fn block() -> BlockRef {
        BlockRef::new(19_800_000, B256::repeat_byte(0xab))
    }

    fn tx(b: u8) -> B256 {
        B256::repeat_byte(b)
    }

    /// A fully-enriched context for `block()` holding three transactions —
    /// what an archive-backed `CtxSource` would produce, supplied here through
    /// the seam's in-memory double.
    fn enriched_ctx() -> DetectionCtx {
        let token = addr(0x77);
        let pool = addr(0xee);
        let mut builder = CtxBuilder::new()
            .at(CHAIN, block())
            .priced_token(token, 18, 2.0);
        for (i, hash) in [tx(1), tx(2), tx(3)].into_iter().enumerate() {
            let sender = addr(i as u8 + 1);
            builder = builder.transfer_tx(
                hash,
                sender,
                vec![transfer(token, sender, pool, 1_000 * (i as u128 + 1))],
            );
        }
        builder.build()
    }

    /// Fixed alert ids: the window is a stand-in for *stored* events, which
    /// are immutable, so minting fresh UUIDs per call would make two calls
    /// describe two different histories — and the determinism test below would
    /// then be testing the fixture, not the pipeline.
    const CONFIRMED_ALERT: AlertId = AlertId(Uuid::from_u128(0xa1));
    const REFUTED_ALERT: AlertId = AlertId(Uuid::from_u128(0xa2));

    /// A confirmed finding on `block()` implicating tx(1) and tx(2), plus a
    /// refuted one implicating tx(3).
    fn window() -> Vec<EventEnvelope> {
        let (confirmed, refuted) = (CONFIRMED_ALERT, REFUTED_ALERT);
        vec![
            envelope(
                0,
                DomainEvent::BlockAssembled(BlockAssembled {
                    block: block(),
                    tx_count: 3,
                    trace_available: false,
                }),
            ),
            envelope(
                1,
                DomainEvent::DetectorTriggered(DetectorTriggered {
                    detector: detector(),
                    block: block(),
                    txs: vec![tx(1), tx(2)],
                    raw_confidence: Confidence::new(0.9),
                    evidence: serde_json::json!({}),
                }),
            ),
            envelope(
                2,
                DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
                    alert_id: confirmed,
                    detector: detector(),
                    addresses: vec![],
                    kind: AlertKind::Sandwich,
                    confidence: Confidence::new(0.9),
                    provisional: true,
                    impact_usd: None,
                    severity: Severity::Low,
                    suggested_action: SuggestedAction::Monitor,
                }),
            ),
            envelope(
                3,
                DomainEvent::DetectorTriggered(DetectorTriggered {
                    detector: detector(),
                    block: block(),
                    txs: vec![tx(3)],
                    raw_confidence: Confidence::new(0.4),
                    evidence: serde_json::json!({}),
                }),
            ),
            envelope(
                4,
                DomainEvent::PreliminaryAlertCreated(PreliminaryAlertCreated {
                    alert_id: refuted,
                    detector: detector(),
                    addresses: vec![],
                    kind: AlertKind::Sandwich,
                    confidence: Confidence::new(0.4),
                    provisional: true,
                    impact_usd: None,
                    severity: Severity::Low,
                    suggested_action: SuggestedAction::Monitor,
                }),
            ),
            envelope(
                5,
                DomainEvent::SimulationCompleted(SimulationCompleted {
                    alert_id: confirmed,
                    profit: 250.0,
                    victim_loss: 90.0,
                    confirmed: true,
                }),
            ),
            envelope(
                6,
                DomainEvent::SimulationCompleted(SimulationCompleted {
                    alert_id: refuted,
                    profit: 0.0,
                    victim_loss: 0.0,
                    confirmed: false,
                }),
            ),
        ]
    }

    async fn export(
        spec: &DatasetSpec,
        ctx_factory: &dyn CtxSourceFactory,
    ) -> (Vec<DatasetRow>, DatasetManifest) {
        export_with(spec, ctx_factory, ExportOptions::default()).await
    }

    async fn export_with(
        spec: &DatasetSpec,
        ctx_factory: &dyn CtxSourceFactory,
        options: ExportOptions,
    ) -> (Vec<DatasetRow>, DatasetManifest) {
        let source = VecEventSource::new(window());
        let mut sink = CollectingSink::new();
        let manifest = run_export(spec, &source, ctx_factory, &mut sink, options)
            .await
            .expect("export succeeds");
        (sink.rows, manifest)
    }

    /// A window-independent source of the fully-enriched context, behind the
    /// factory seam.
    fn enriched_source() -> StaticCtxFactory {
        StaticCtxFactory::new(std::sync::Arc::new(
            MapCtxSource::new().with(enriched_ctx(), Fidelity::Enriched),
        ))
    }

    fn static_factory(source: MapCtxSource) -> StaticCtxFactory {
        StaticCtxFactory::new(std::sync::Arc::new(source))
    }

    #[tokio::test]
    async fn a_window_becomes_labeled_rows_with_the_features_of_their_block() {
        let spec = spec(Granularity::Tx);
        let (rows, manifest) = export(&spec, &enriched_source()).await;

        // tx(1), tx(2) from the confirmed finding; tx(3) from the refuted one.
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows.iter().filter(|r| r.label == Label::Positive).count(),
            2
        );
        assert_eq!(
            rows.iter().filter(|r| r.label == Label::Negative).count(),
            1
        );

        let positive = &rows[0];
        assert_eq!(positive.tx_hash, Some(tx(1)));
        assert_eq!(positive.outcome, "confirmed");
        assert_eq!(positive.profit, 250.0);
        assert_eq!(positive.fidelity, Fidelity::Enriched);
        assert_eq!(
            positive.features.len(),
            manifest.feature_names.len(),
            "a row's width matches the schema the manifest names"
        );
        assert!(
            positive.features.iter().all(|v| v.is_finite()),
            "no NaN can reach a model input"
        );

        // The negative carries no simulated figures — a refutation measured
        // nothing.
        let negative = rows.iter().find(|r| r.label == Label::Negative).unwrap();
        assert_eq!(negative.tx_hash, Some(tx(3)));
        assert_eq!((negative.profit, negative.victim_loss), (0.0, 0.0));
    }

    #[tokio::test]
    async fn the_manifest_accounts_for_every_finding() {
        let (_, manifest) = export(&spec(Granularity::Tx), &enriched_source()).await;
        assert_eq!(manifest.rows.written, 3);
        assert_eq!(manifest.rows.by_label.get("positive"), Some(&2));
        assert_eq!(manifest.rows.by_label.get("negative"), Some(&1));
        assert_eq!(manifest.rows.by_outcome.get("confirmed"), Some(&1));
        assert_eq!(manifest.rows.by_outcome.get("refuted"), Some(&1));
        assert_eq!(manifest.rows.by_fidelity.get("enriched"), Some(&2));
        assert_eq!(manifest.join.triggers, 2);
        assert_eq!(manifest.join.ambiguous_bindings, 0);
        assert_eq!(
            manifest.feature_schema_hash,
            ml_features::tx_schema().content_hash()
        );
    }

    #[tokio::test]
    async fn block_granularity_emits_one_row_per_finding_with_the_block_vector() {
        let spec = spec(Granularity::Block);
        let (rows, manifest) = export(&spec, &enriched_source()).await;
        assert_eq!(rows.len(), 2, "one row per finding, not per tx");
        assert!(rows.iter().all(|r| r.tx_hash.is_none()));
        assert_eq!(
            rows[0].features.len(),
            ml_features::block_schema().len(),
            "block granularity uses the block schema"
        );
        assert_eq!(
            manifest.feature_schema_hash,
            ml_features::block_schema().content_hash()
        );
        assert_eq!(
            rows[0].features, rows[1].features,
            "two findings on one block share its block vector — the view is built once"
        );
    }

    #[tokio::test]
    async fn the_same_spec_and_window_export_byte_identically_twice() {
        let spec = spec(Granularity::Tx);
        let (rows_a, manifest_a) = export(&spec, &enriched_source()).await;
        let (rows_b, manifest_b) = export(&spec, &enriched_source()).await;

        assert_eq!(rows_a, rows_b);
        assert_eq!(manifest_a.content_hash, manifest_b.content_hash);
        assert!(
            manifest_a.describes_same_dataset(&manifest_b),
            "reproducible by construction — same window, same version, same rule"
        );
        assert_ne!(
            manifest_a.generated_at, manifest_b.generated_at,
            "and the run timestamp differs, proving it is outside the hash"
        );
    }

    #[tokio::test]
    async fn a_min_fidelity_gate_drops_rows_rather_than_downgrading_them() {
        // The context source only offers a header-only reconstruction, but the
        // spec demands a full bundle.
        let ctx = DetectionCtx::new(detector_api::BlockBundle::new(CHAIN, block(), vec![]));
        let source = static_factory(MapCtxSource::new().with(ctx, Fidelity::HeaderOnly));

        let mut spec = spec(Granularity::Block);
        spec.min_fidelity = Fidelity::FullBundle;
        let (rows, manifest) = export(&spec, &source).await;

        assert!(rows.is_empty());
        assert_eq!(manifest.rows.below_min_fidelity, 2);
        assert_eq!(manifest.rows.written, 0);
        assert_eq!(
            manifest.rows.by_fidelity.get("header_only"),
            Some(&2),
            "the dropped rows are still accounted for"
        );
    }

    #[tokio::test]
    async fn a_block_the_context_source_does_not_know_is_counted_not_fatal() {
        let source = static_factory(MapCtxSource::new());
        let (rows, manifest) = export(&spec(Granularity::Tx), &source).await;
        assert!(rows.is_empty());
        assert_eq!(manifest.rows.no_context, 2);
    }

    #[tokio::test]
    async fn a_partial_context_missing_the_implicated_txs_is_counted_separately() {
        // A context for the right block, but holding a transaction none of the
        // findings implicate.
        let ctx = DetectionCtx::new(detector_api::BlockBundle::new(CHAIN, block(), vec![tx(9)]));
        let source = static_factory(MapCtxSource::new().with(ctx, Fidelity::PartialBundle));
        let (rows, manifest) = export(&spec(Granularity::Tx), &source).await;
        assert!(rows.is_empty());
        assert_eq!(manifest.rows.no_extractable_tx, 2);
        assert_eq!(manifest.rows.no_context, 0, "the block itself was known");
    }

    #[tokio::test]
    async fn the_replay_ctx_source_drives_a_real_export_end_to_end() {
        // No hand-built context at all: the source reconstructs bundles from
        // the window's own events. This is what the binary does today.
        let source = VecEventSource::new(window());
        let mut sink = CollectingSink::new();

        let manifest = run_export(
            &spec(Granularity::Tx),
            &source,
            &crate::ctx::ReplayCtxFactory,
            &mut sink,
            ExportOptions::default(),
        )
        .await
        .expect("export succeeds");

        assert_eq!(sink.rows.len(), 3);
        assert_eq!(
            manifest.rows.by_fidelity.get("full_bundle"),
            Some(&2),
            "the three implicated txs are the block's whole tx_count, so the \
             reconstruction is provably complete"
        );
        assert!(
            sink.rows.iter().all(|r| r.fidelity == Fidelity::FullBundle),
            "and every row says so"
        );
        assert_eq!(
            sink.manifest.as_ref().map(|m| &m.content_hash),
            Some(&manifest.content_hash)
        );
    }

    // ── the lookahead, sharding, and the bias gate ────────────────────

    #[tokio::test]
    async fn a_finding_near_the_window_end_keeps_its_outcome_via_the_lookahead() {
        // `to` lands between the last trigger and its SimulationCompleted. With
        // a lookahead the outcome is still found; the label is a property of
        // the finding, not of where the window happens to stop.
        let mut spec = spec(Granularity::Tx);
        spec.to = at(1_700_000_004); // after both alerts, before both outcomes
        let (_, manifest) = export(&spec, &enriched_source()).await;

        assert_eq!(manifest.rows.by_outcome.get("confirmed"), Some(&1));
        assert_eq!(manifest.rows.by_outcome.get("refuted"), Some(&1));
        assert_eq!(
            manifest.rows.by_outcome.get("unresolved"),
            None,
            "the outcome events sit past `to` and must still be read"
        );
        assert_eq!(manifest.rows.written, 3);
    }

    #[tokio::test]
    async fn sharding_reproduces_the_unsharded_dataset_exactly() {
        // The property that makes sharding safe: how the work was sliced must
        // not reach the output. Shard boundaries deliberately cut between the
        // window's two findings.
        let spec = spec(Granularity::Tx);
        let (whole_rows, whole) = export(&spec, &enriched_source()).await;

        for shard_secs in [1i64, 2, 3, 100] {
            let (rows, sharded) = export_with(
                &spec,
                &enriched_source(),
                ExportOptions {
                    shard: Some(Duration::seconds(shard_secs)),
                    ..Default::default()
                },
            )
            .await;

            assert_eq!(rows, whole_rows, "shard={shard_secs}s changed the rows");
            assert_eq!(
                sharded.content_hash, whole.content_hash,
                "shard={shard_secs}s changed the dataset's identity"
            );
            assert_eq!(sharded.rows.written, whole.rows.written);
            assert_eq!(sharded.rows.by_label, whole.rows.by_label);
        }
    }

    #[tokio::test]
    async fn a_shard_boundary_does_not_emit_a_finding_twice() {
        // Each shard reads a lookahead tail past its own end, so the *next*
        // shard's findings are visible to it. They must resolve outcomes and
        // nothing more, or every finding near a boundary would be exported by
        // two shards.
        let spec = spec(Granularity::Tx);
        let (rows, manifest) = export_with(
            &spec,
            &enriched_source(),
            ExportOptions {
                shard: Some(Duration::seconds(1)),
                ..Default::default()
            },
        )
        .await;

        let mut keys: Vec<_> = rows
            .iter()
            .map(|r| (r.trigger_event_id, r.tx_hash))
            .collect();
        let before = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), before, "a row was emitted by two shards");
        assert_eq!(manifest.rows.written, before as u64);
        assert!(
            manifest.rows.lookahead_only > 0,
            "the tail findings should be seen and skipped, not never seen"
        );
    }

    #[tokio::test]
    async fn an_excessive_context_drop_rate_fails_the_export() {
        // Every labeled finding loses its context: a 100% drop rate, which
        // would hand back an empty-but-plausible dataset.
        let mut sink = CollectingSink::new();
        let err = run_export(
            &spec(Granularity::Tx),
            &VecEventSource::new(window()),
            &static_factory(MapCtxSource::new()),
            &mut sink,
            ExportOptions {
                max_drop_fraction: Some(0.25),
                ..Default::default()
            },
        )
        .await
        .expect_err("a fully-dropped dataset must not be handed over");

        let ExportError::ExcessiveDrop {
            dropped, labeled, ..
        } = err
        else {
            panic!("expected ExcessiveDrop, got {err}");
        };
        assert_eq!((dropped, labeled), (2, 2));
    }

    #[tokio::test]
    async fn the_drop_gate_passes_when_every_finding_has_a_context() {
        let (rows, manifest) = export_with(
            &spec(Granularity::Tx),
            &enriched_source(),
            ExportOptions {
                max_drop_fraction: Some(0.0),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(rows.len(), 3);
        assert_eq!(manifest.rows.drop_fraction(), 0.0);
        assert_eq!(
            manifest.rows.labeled, 2,
            "two findings carried ground truth"
        );
    }

    #[tokio::test]
    async fn an_invalid_spec_fails_before_the_source_is_touched() {
        struct Exploding;
        #[async_trait::async_trait]
        impl EventSource for Exploding {
            async fn page(
                &self,
                _: &crate::source::ReplayQuery,
            ) -> Result<crate::source::EventPage, SourceError> {
                panic!("the source must not be reached for an invalid spec");
            }
        }

        let mut spec = spec(Granularity::Tx);
        spec.to = spec.from;
        let err = run_export(
            &spec,
            &Exploding,
            &static_factory(MapCtxSource::new()),
            &mut CollectingSink::new(),
            ExportOptions::default(),
        )
        .await
        .expect_err("must refuse");
        assert!(
            matches!(err, ExportError::Spec(SpecError::EmptyWindow { .. })),
            "{err}"
        );
    }
}
