//! Emission (§6, task 5): turn a detector's [`Evidence`] into the wire events the
//! rest of the system records — [`DetectorTriggered`] and [`PreliminaryAlertCreated`].
//!
//! This is the fast path's payoff: run the roster over one assembled block and
//! produce, for every finding, the raw "a detector fired" fact ([`DetectorTriggered`],
//! stamped with the exact `(id, version, config_hash)` so it's reproducible on
//! replay — §6, §18) and the provisional alert raised from it ([`PreliminaryAlertCreated`],
//! `provisional = true` until simulation/finality confirm it — §7, §15).
//!
//! ## Pure mapping, returned as data
//!
//! Like the ingestion pipeline's `observed_events`/`canonical_events`, the mapping
//! is pure functions over plain data returning `Vec<DomainEvent>` — no Kafka, no
//! envelopes, no async. Envelope-wrapping and publishing are the effectful shell's
//! job (Sprint 4 task 2's async scheduler), so this layer stays unit-testable with
//! `assert_eq!` and replayable in backtests. [`DetectionPlan::detection_events`]
//! is the top-level entry point — it runs the roster, validated once by
//! [`DetectionPlan::link`] so it can't emit an unreproducible event; the smaller
//! functions it composes are public so each is testable and reusable on its own.
//!
//! ## Attribution-blind, end to end
//!
//! The whole fast path names *behaviour*, never *actors* (§6). [`Evidence`] carries
//! no identity, and the addresses [`PreliminaryAlertCreated`] reports are pulled
//! from the block's enrichment — they are on-chain *facts* (the senders/recipients
//! of the implicated txs), not *labels*. Attribution happens later, off the hot
//! path, in the intelligence service (§8).

use std::sync::Arc;

use alloy_primitives::B256;

use events::detection::{DetectorTriggered, PreliminaryAlertCreated};
use events::primitives::{
    AccountAddress, AlertId, AlertKind, BlockRef, Confidence, DetectorRef, UsdAmount,
};
use events::DomainEvent;

use detector_api::{DetectionCtx, DetectorId, DetectorPlugin, Enrichment, Evidence, SemVer};

use crate::model::{LifecycleStatus, ModelRegistry};
use crate::registry::Registry;

/// Map one [`Evidence`] onto the `DetectorTriggered` it justifies — the raw fact
/// that `detector` fired on `block`, carrying the implicated txs, the
/// facts-only confidence, and the detector-specific evidence document verbatim.
///
/// `detector` is the resolved `(id, version, config_hash)` triple (from the model
/// registry); the [`Evidence`] deliberately doesn't know its own detector's
/// identity, so there's a single source of truth for "who found this" (§6).
pub fn detector_triggered(
    detector: DetectorRef,
    block: BlockRef,
    evidence: &Evidence,
) -> DetectorTriggered {
    DetectorTriggered {
        detector,
        block,
        txs: evidence.txs.clone(),
        raw_confidence: evidence.confidence,
        evidence: evidence.detail.clone(),
    }
}

/// Raise the provisional alert for a finding: a fresh [`AlertId`], the behaviour
/// `kind`, the on-chain `addresses` it involves, the carried `confidence`, and
/// `provisional = true` (the contract the API/WebSocket lifecycle depends on until
/// simulation or finality confirms — §7, §11, §15).
///
/// `confidence` is the detector's raw, facts-only confidence carried through
/// **unadjusted by design** — the fast path is attribution-blind (§6), and any
/// reweighting from attribution/labels happens later in the intelligence service
/// (§8). Don't "fix" this by folding label signal in here.
///
/// `impact_usd` (from [`impact_usd`]) drives `severity` ([`severity_band`]) and,
/// in turn, `suggested_action` ([`suggested_action`]) — both derived here so
/// every `PreliminaryAlertCreated` carries a self-consistent triple rather than
/// leaving each consumer to re-derive severity from confidence alone.
pub fn preliminary_alert(
    detector: DetectorRef,
    kind: AlertKind,
    addresses: Vec<AccountAddress>,
    confidence: Confidence,
    impact_usd: Option<UsdAmount>,
) -> PreliminaryAlertCreated {
    let severity = severity_band(impact_usd, confidence);
    PreliminaryAlertCreated {
        alert_id: AlertId::new(),
        detector,
        addresses,
        kind,
        confidence,
        provisional: true,
        impact_usd,
        severity,
        suggested_action: suggested_action(severity),
    }
}

// The severity banding and its action map now live in [`events::scoring`], the
// single scoring policy the fast path (here) and the slow-path restamp
// (`simulation::result`, §7) share so a provisional alert and the incident it
// confirms into can't drift onto two banding rules. Re-exported so this crate's
// call sites and its public API are unchanged.
pub use events::scoring::{
    severity_band, suggested_action, SEVERITY_CRITICAL_USD, SEVERITY_HIGH_USD, SEVERITY_MEDIUM_USD,
};

/// The on-chain addresses an alert is about: the `from`/`to` of every implicated
/// transaction, looked up in the block's [`Enrichment`], deduplicated in
/// first-seen order.
///
/// These are *facts* — the senders and recipients of the txs in the pattern — not
/// *labels*; who those addresses belong to is the intelligence service's job (§8).
/// A header-only source (empty enrichment) yields no addresses rather than a
/// guess, and a `from`/`to` is only reported if the tx was actually enriched.
pub fn implicated_addresses(enrichment: &Enrichment, txs: &[B256]) -> Vec<AccountAddress> {
    let mut addresses = Vec::new();
    for hash in txs {
        let Some(actions) = enrichment.tx(*hash) else {
            continue;
        };
        // `from`, then `to` if present (contract-creation txs have none).
        for addr in std::iter::once(actions.from).chain(actions.to) {
            if !addresses.contains(&addr) {
                addresses.push(addr);
            }
        }
    }
    addresses
}

/// The USD-scale impact for a finding, resolving the two sources in priority
/// order (§6): the detector's own priced figure ([`Evidence::impact_usd`]) when
/// it set one, else a coarse fallback summed from the block's enrichment
/// ([`impact_from_transfers`]).
///
/// Preferring the detector's number is the point of the [`Evidence`] seam: a
/// sandwich reports *attacker profit*, a rugpull *value drained*, a flashloan
/// *notional* — each its correct headline figure, which a blind transfer-sum
/// can't distinguish (and would over-count for multi-hop flows). The fallback
/// exists only so a detector that can't price a finding still yields *some*
/// estimate rather than nothing. Stays attribution-blind either way — both
/// inputs are value magnitudes, never actor identity.
///
/// [`Evidence::impact_usd`]: detector_api::Evidence::impact_usd
pub fn impact_usd(evidence: &Evidence, enrichment: &Enrichment) -> Option<UsdAmount> {
    evidence
        .impact_usd
        .or_else(|| impact_from_transfers(enrichment, &evidence.txs))
}

/// Fallback USD estimate: the sum of every priced [`TokenTransfer`] value among
/// the implicated txs' decoded actions, valued via [`Enrichment::usd_value`]
/// (§6). Used only when a detector didn't report its own [`Evidence::impact_usd`].
///
/// Like [`implicated_addresses`], this reads only on-chain facts — decoded
/// transfers and reference prices — never attribution, so it stays
/// attribution-blind end to end. `None` when nothing could be priced (no
/// enriched tx, no transfers, or an unknown token/price) — an honest
/// "unknown," not a `0.0` that would misread as "no impact." A transfer that
/// can't be priced is skipped rather than discarding the whole estimate, so a
/// partially-priced pattern (one known token among several) still yields a
/// (partial, undercounted) figure instead of nothing. It is a deliberately
/// coarse gross-flow proxy that can over-count — the authoritative harm figure
/// comes later from simulation (§7).
///
/// [`TokenTransfer`]: detector_api::TokenTransfer
/// [`Evidence::impact_usd`]: detector_api::Evidence::impact_usd
pub fn impact_from_transfers(enrichment: &Enrichment, txs: &[B256]) -> Option<UsdAmount> {
    let mut total = 0.0;
    let mut priced_any = false;
    for hash in txs {
        let Some(actions) = enrichment.tx(*hash) else {
            continue;
        };
        for transfer in &actions.transfers {
            if let Some(value) = enrichment.usd_value(transfer.token, transfer.amount) {
                total += value;
                priced_any = true;
            }
        }
    }
    // The summed transfers are each finite and non-negative, so `new` is a
    // no-op sanitize here — but it keeps a stray non-finite from ever reaching
    // a severity gate.
    priced_any.then(|| UsdAmount::new(total))
}

/// Map one detector's [`Evidence`] onto the events it emits: the raw
/// [`DetectorTriggered`] fact, immediately followed by the provisional
/// [`PreliminaryAlertCreated`] it raises — **unless** `status` is
/// [`Shadow`](LifecycleStatus::Shadow), in which case the finding is still
/// scored (the trigger fact is always emitted, so metrics/backtests see it) but
/// alerting is suppressed: a canary build is staged before it's promoted (§6,
/// §18). `Deprecated` is treated the same as `Shadow` here — a superseded build
/// shouldn't still be raising live alerts.
///
/// The single source of truth every emit path maps findings through — the
/// sequential [`detection_events`](DetectionPlan::detection_events), the rayon
/// [`detection_events_parallel`](DetectionPlan::detection_events_parallel), and the
/// cross-block slot ([`crate::reorg`]) — so the trigger→alert pairing, the
/// attribution-blind address lookup, and the Shadow-suppression rule can't drift
/// between them.
pub(crate) fn evidence_events(
    detector_ref: &DetectorRef,
    status: LifecycleStatus,
    block: BlockRef,
    enrichment: &Enrichment,
    evidence: &Evidence,
) -> Vec<DomainEvent> {
    let mut events = vec![DomainEvent::DetectorTriggered(detector_triggered(
        detector_ref.clone(),
        block,
        evidence,
    ))];

    if status == LifecycleStatus::Active {
        let addresses = implicated_addresses(enrichment, &evidence.txs);
        let impact = impact_usd(evidence, enrichment);
        events.push(DomainEvent::PreliminaryAlertCreated(preliminary_alert(
            detector_ref.clone(),
            evidence.kind,
            addresses,
            evidence.confidence,
            impact,
        )));
    }

    events
}

/// A live detector is in the [`Registry`] but absent from the [`ModelRegistry`],
/// so it has no `config_hash` to stamp onto its events.
///
/// This is a boot-time wiring bug, not a runtime condition: the two rosters are
/// assembled together (the model registry catalogues exactly the detectors
/// `register_builtins` links), so a gap means they drifted. Surfaced as an error
/// from [`DetectionPlan::link`] for the binary to fail fast on — running live with
/// a detector whose evidence can't be reproduced (§6, §18) is worse than not
/// booting.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "detector {id} v{version} is live in the registry but has no model card — \
     its config_hash can't be stamped; catalogue it in the model registry"
)]
pub struct UnlinkedDetector {
    pub id: DetectorId,
    pub version: SemVer,
}

/// One detector paired with its resolved, immutable [`DetectorRef`] and
/// [`LifecycleStatus`] — proven to exist at link time, so the per-block emit
/// path never has to look either up or handle their absence.
struct LinkedDetector {
    plugin: Arc<dyn DetectorPlugin>,
    detector_ref: DetectorRef,
    status: LifecycleStatus,
}

impl LinkedDetector {
    /// Run this detector over `ctx`, recording its latency + hit/miss (§19) around
    /// the seam call, and return the findings. The single instrumented call site
    /// both `Block` emit paths route through, so the per-detector metrics can't
    /// diverge between the sequential reference and the rayon fan-out.
    fn detect(&self, ctx: &DetectionCtx) -> Vec<Evidence> {
        let start = std::time::Instant::now();
        let evidence = self.plugin.detect(ctx);
        crate::metrics::record_detector_run(&self.detector_ref, start.elapsed(), evidence.len());
        evidence
    }
}

/// The emission roster: every live detector paired with its `(id, version,
/// config_hash)` triple, validated once at [`link`](Self::link) time (§6, task 5).
///
/// This is the "parse, don't validate" boundary for the fast path. Pairing the
/// live [`Registry`] with the [`ModelRegistry`] *once* — and failing if any
/// detector is uncatalogued — means [`detection_events`](Self::detection_events)
/// is **total**: it can't encounter a missing `config_hash`, so there's no
/// per-block lookup and no degraded "skip and warn" branch on the hot path. The
/// invariant "every emitted event carries a real triple" is enforced by
/// construction, the same fail-fast discipline as
/// [`register_builtins`](crate::registry::register_builtins) panicking on a
/// duplicate. The async scheduler (Sprint 4 task 2) builds one plan at startup and
/// reuses it for the process's life.
pub struct DetectionPlan {
    detectors: Vec<LinkedDetector>,
}

impl std::fmt::Debug for DetectionPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `dyn DetectorPlugin` isn't `Debug`; show the linked roster by its
        // resolved triples instead (mirrors `Registry`'s manual `Debug`).
        f.debug_struct("DetectionPlan")
            .field(
                "detectors",
                &self
                    .detectors
                    .iter()
                    .map(|l| &l.detector_ref)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl DetectionPlan {
    /// Pair every live detector in `registry` with its model card in `models`,
    /// preserving the registry's deterministic `(id, version)` order, or fail with
    /// the first [`UnlinkedDetector`] found.
    pub fn link(registry: &Registry, models: &ModelRegistry) -> Result<Self, UnlinkedDetector> {
        let mut detectors = Vec::with_capacity(registry.len());
        for plugin in registry.detectors() {
            let (id, version) = (plugin.id(), plugin.version());
            let card = models
                .card(id, version)
                .ok_or(UnlinkedDetector { id, version })?;
            detectors.push(LinkedDetector {
                plugin: Arc::clone(plugin),
                detector_ref: card.detector_ref(),
                status: card.status,
            });
        }
        Ok(Self { detectors })
    }

    /// The resolved `(id, version, config_hash)` triple this plan linked for
    /// `id` — the same one every event that detector produces is stamped with.
    ///
    /// A lookup by `id` alone rather than `(id, version)`: two builds of one
    /// detector coexist only during a staged rollout (§6), and a caller asking
    /// this question ("which triple is `anomaly` emitting under?") wants the
    /// one that is linked, not to restate a version it would have to keep in
    /// step by hand. `None` when the detector is not in this build's roster.
    pub fn detector_ref(&self, id: DetectorId) -> Option<&DetectorRef> {
        self.detectors
            .iter()
            .find(|linked| linked.detector_ref.id == id.as_str())
            .map(|linked| &linked.detector_ref)
    }

    /// How many detectors the plan will fan out over.
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// Run the whole roster over one block and emit its detection events (§6).
    ///
    /// For each linked detector (in registry `(id, version)` order), run
    /// [`detect`](detector_api::DetectorPlugin::detect) and, for every finding,
    /// emit its [`DetectorTriggered`] immediately followed by its
    /// [`PreliminaryAlertCreated`] — the causal trigger→alert pairing, grouped per
    /// finding. Detectors that find nothing (the common case) contribute nothing.
    ///
    /// Returns `Vec<DomainEvent>` payloads in emission order; the async shell wraps
    /// each in an [`EventEnvelope`](events::EventEnvelope) and publishes it (Sprint
    /// 4). This is the **sequential** path — deterministic and rayon-free, so it's
    /// the reference for replay/backtests (§18) and unit tests. The live scheduler
    /// runs [`detection_events_parallel`](Self::detection_events_parallel) instead;
    /// the two produce the same events in the same order (each `detect` is pure).
    pub fn detection_events(&self, ctx: &DetectionCtx) -> Vec<DomainEvent> {
        let mut events = Vec::new();
        for linked in &self.detectors {
            for evidence in linked.detect(ctx) {
                events.extend(evidence_events(
                    &linked.detector_ref,
                    linked.status,
                    ctx.block(),
                    ctx.enrichment(),
                    &evidence,
                ));
            }
        }
        events
    }

    /// Run the whole `Block`-scoped roster over one block **in parallel** on the
    /// rayon pool (§17, Sprint 4 task 2) — the live scheduler's hot path, invoked
    /// inside `spawn_blocking` so this CPU work never runs on the async reactor.
    ///
    /// Each detector's [`detect`](detector_api::DetectorPlugin::detect) is a pure
    /// function sharing only the `&DetectionCtx`, so they fan out with no
    /// coordination; rayon's `collect` preserves iteration order, so the emitted
    /// events come out in the **same** `(id, version)` roster order — and are
    /// byte-for-byte identical to [`detection_events`](Self::detection_events)
    /// except for each alert's freshly-minted [`AlertId`]. Cross-block detectors are
    /// *not* here: they thread `&mut` state and run serially (see [`crate::reorg`]).
    pub fn detection_events_parallel(&self, ctx: &DetectionCtx) -> Vec<DomainEvent> {
        use rayon::prelude::*;
        self.detectors
            .par_iter()
            .flat_map_iter(|linked| {
                linked.detect(ctx).into_iter().flat_map(|evidence| {
                    evidence_events(
                        &linked.detector_ref,
                        linked.status,
                        ctx.block(),
                        ctx.enrichment(),
                        &evidence,
                    )
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    use detector_api::test_util::MockDetector;
    use detector_api::{
        BlockBundle, EnrichmentBuilder, SemVer, TokenMeta, TokenTransfer, TxActions, UsdPrice,
    };
    use events::primitives::{BlockRef, Chain, Severity, SuggestedAction};

    use crate::model::{ConfigHash, ModelCard, ModelRegistry};
    use crate::registry::Registry;

    use alloy_primitives::{Address, U256};

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn hash(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    fn a_ref() -> DetectorRef {
        DetectorRef {
            id: "sandwich".into(),
            version: "1.2.0".into(),
            config_hash: "deadbeef".into(),
        }
    }

    fn evidence(kind: AlertKind, txs: Vec<B256>, confidence: f64) -> Evidence {
        Evidence::new(kind, txs, Confidence::new(confidence))
    }

    // ── detector_triggered ────────────────────────────────────────────

    #[test]
    fn detector_triggered_carries_the_triple_txs_confidence_and_detail() {
        let detail = serde_json::json!({ "profit_usd": 12.5, "pool": "0xabc" });
        let ev =
            evidence(AlertKind::Sandwich, vec![hash(1), hash(2)], 0.8).with_detail(detail.clone());
        let block = BlockRef::new(42, hash(0xbb));

        let dt = detector_triggered(a_ref(), block, &ev);

        assert_eq!(dt.detector, a_ref(), "exact (id, version, config_hash)");
        assert_eq!(dt.block, block);
        assert_eq!(dt.txs, vec![hash(1), hash(2)]);
        assert_eq!(dt.raw_confidence, Confidence::new(0.8));
        assert_eq!(dt.evidence, detail, "detail document carried verbatim");
    }

    // ── preliminary_alert ─────────────────────────────────────────────

    #[test]
    fn preliminary_alert_is_provisional_and_mints_distinct_ids() {
        let a = preliminary_alert(
            a_ref(),
            AlertKind::Arbitrage,
            vec![addr(1)],
            Confidence::new(0.6),
            None,
        );
        let b = preliminary_alert(
            a_ref(),
            AlertKind::Arbitrage,
            vec![],
            Confidence::new(0.6),
            None,
        );

        assert!(a.provisional, "always provisional on creation");
        assert_eq!(a.kind, AlertKind::Arbitrage);
        assert_eq!(a.addresses, vec![addr(1)]);
        assert_eq!(a.confidence, Confidence::new(0.6));
        assert_ne!(a.alert_id, b.alert_id, "each alert gets a fresh id");
    }

    #[test]
    fn preliminary_alert_carries_impact_and_its_derived_severity_and_action() {
        // impact 150_000 * confidence 0.8 = 120_000 ⇒ High ⇒ Escalate.
        let a = preliminary_alert(
            a_ref(),
            AlertKind::Sandwich,
            vec![],
            Confidence::new(0.8),
            Some(UsdAmount::new(150_000.0)),
        );
        assert_eq!(a.impact_usd, Some(UsdAmount::new(150_000.0)));
        assert_eq!(a.severity, Severity::High);
        assert_eq!(a.suggested_action, SuggestedAction::Escalate);
    }

    // The severity-band / suggested-action policy is exercised where it now
    // lives — see `events::scoring`. This crate's tests below cover how the
    // emit path *composes* that policy (the provisional scoring triple) and
    // resolves `impact_usd`.

    // ── impact_usd (resolver) / impact_from_transfers (fallback) ──────

    /// An enrichment pricing one 18-decimal token `0xee` at $2, with two txs
    /// transferring `whole0`/`whole1` whole tokens respectively.
    fn priced_ctx(whole0: u64, whole1: u64) -> Enrichment {
        let unit = U256::from(10u64).pow(U256::from(18u64));
        let mut b = EnrichmentBuilder::default();
        b.add_token(TokenMeta::new(addr(0xee), None, 18));
        b.set_price(addr(0xee), UsdPrice::try_new(2.0).unwrap());
        b.add_tx(
            TxActions::new(hash(1), addr(1), Some(addr(9))).with_transfers(vec![TokenTransfer {
                token: addr(0xee),
                from: addr(1),
                to: addr(9),
                amount: U256::from(whole0) * unit,
            }]),
        );
        b.add_tx(
            TxActions::new(hash(2), addr(2), Some(addr(8))).with_transfers(vec![TokenTransfer {
                token: addr(0xee),
                from: addr(2),
                to: addr(8),
                amount: U256::from(whole1) * unit,
            }]),
        );
        b.build()
    }

    #[test]
    fn impact_from_transfers_sums_priced_transfers_across_implicated_txs() {
        // 3 tokens @ $2 + 1 token @ $2 = $8.
        assert_eq!(
            impact_from_transfers(&priced_ctx(3, 1), &[hash(1), hash(2)]),
            Some(UsdAmount::new(8.0))
        );
    }

    #[test]
    fn impact_from_transfers_is_none_without_any_priced_transfer() {
        let enr = Enrichment::default();
        assert_eq!(
            impact_from_transfers(&enr, &[hash(1)]),
            None,
            "no enrichment at all"
        );

        // Enriched tx, but the token has no known price — still unknown, not zero.
        let mut b = EnrichmentBuilder::default();
        b.add_token(TokenMeta::new(addr(0xee), None, 18));
        b.add_tx(
            TxActions::new(hash(1), addr(1), Some(addr(9))).with_transfers(vec![TokenTransfer {
                token: addr(0xee),
                from: addr(1),
                to: addr(9),
                amount: U256::from(1u64),
            }]),
        );
        assert_eq!(impact_from_transfers(&b.build(), &[hash(1)]), None);
    }

    #[test]
    fn impact_from_transfers_skips_unpriceable_transfers_but_keeps_the_rest() {
        let mut b = EnrichmentBuilder::default();
        b.add_token(TokenMeta::new(addr(0xee), None, 18));
        b.set_price(addr(0xee), UsdPrice::try_new(2.0).unwrap());
        // addr(0xff) is never registered — its transfer can't be priced.
        b.add_tx(
            TxActions::new(hash(1), addr(1), Some(addr(9))).with_transfers(vec![
                TokenTransfer {
                    token: addr(0xee),
                    from: addr(1),
                    to: addr(9),
                    amount: U256::from(10u64).pow(U256::from(18u64)),
                },
                TokenTransfer {
                    token: addr(0xff),
                    from: addr(1),
                    to: addr(9),
                    amount: U256::from(1u64),
                },
            ]),
        );

        assert_eq!(
            impact_from_transfers(&b.build(), &[hash(1)]),
            Some(UsdAmount::new(2.0)),
            "the unpriceable transfer is skipped, not fatal to the whole estimate"
        );
    }

    #[test]
    fn impact_usd_prefers_the_detectors_own_figure_over_the_transfer_sum() {
        // The enrichment's transfers price to $8, but the detector reported
        // its own $50 (e.g. attacker profit, not gross flow) — the detector's
        // figure wins; the blind sum is a fallback only.
        let enr = priced_ctx(3, 1);
        let evidence = Evidence::new(
            AlertKind::Sandwich,
            vec![hash(1), hash(2)],
            Confidence::new(0.9),
        )
        .with_impact_usd(Some(UsdAmount::new(50.0)));
        assert_eq!(impact_usd(&evidence, &enr), Some(UsdAmount::new(50.0)));
    }

    #[test]
    fn impact_usd_falls_back_to_the_transfer_sum_when_the_detector_is_silent() {
        let enr = priced_ctx(3, 1);
        // Detector didn't price it (impact_usd left None) — resolve to the sum.
        let evidence = Evidence::new(
            AlertKind::Sandwich,
            vec![hash(1), hash(2)],
            Confidence::new(0.9),
        );
        assert_eq!(impact_usd(&evidence, &enr), Some(UsdAmount::new(8.0)));
    }

    // ── implicated_addresses ──────────────────────────────────────────

    #[test]
    fn implicated_addresses_collects_from_and_to_deduped_in_order() {
        let mut b = EnrichmentBuilder::default();
        // tx1: from 1 -> to 9 ; tx2: from 1 (repeat) -> to 8.
        b.add_tx(TxActions::new(hash(1), addr(1), Some(addr(9))));
        b.add_tx(TxActions::new(hash(2), addr(1), Some(addr(8))));
        let enr = b.build();

        let got = implicated_addresses(&enr, &[hash(1), hash(2)]);
        // First-seen order, sender 1 deduped across the two txs.
        assert_eq!(got, vec![addr(1), addr(9), addr(8)]);
    }

    #[test]
    fn implicated_addresses_is_empty_without_enrichment() {
        // Header-only source: no decoded txs ⇒ no addresses (not a guess).
        let enr = Enrichment::default();
        assert!(implicated_addresses(&enr, &[hash(1), hash(2)]).is_empty());

        // A contract-creation tx (to == None) reports only its sender.
        let mut b = EnrichmentBuilder::default();
        b.add_tx(TxActions::new(hash(1), addr(7), None));
        assert_eq!(implicated_addresses(&b.build(), &[hash(1)]), vec![addr(7)]);
    }

    #[test]
    fn implicated_addresses_ignores_a_tx_not_in_the_enrichment() {
        let mut b = EnrichmentBuilder::default();
        b.add_tx(TxActions::new(hash(1), addr(1), None));
        // hash(2) was never enriched — it contributes nothing.
        assert_eq!(
            implicated_addresses(&b.build(), &[hash(1), hash(2)]),
            vec![addr(1)]
        );
    }

    // ── DetectionPlan ─────────────────────────────────────────────────

    /// A context whose enrichment names tx `from`/`to`, so emitted alerts carry
    /// addresses.
    fn ctx_with(txs: &[(B256, Address, Address)]) -> DetectionCtx {
        let mut b = EnrichmentBuilder::default();
        let mut order = Vec::new();
        for (h, from, to) in txs {
            order.push(*h);
            b.add_tx(
                TxActions::new(*h, *from, Some(*to)).with_transfers(vec![TokenTransfer {
                    token: addr(0xee),
                    from: *from,
                    to: *to,
                    amount: U256::from(1u64),
                }]),
            );
        }
        DetectionCtx::with_enrichment(
            BlockBundle::new(Chain::ETHEREUM, BlockRef::new(7, hash(0x77)), order),
            b.build(),
        )
    }

    fn card(id: &'static str, version: SemVer) -> ModelCard {
        ModelCard::for_plugin(
            &MockDetector::new(id, version),
            ConfigHash::of_bytes(id.as_bytes()),
            Utc::now(),
        )
    }

    #[test]
    fn detection_events_pairs_trigger_then_alert_per_finding_in_roster_order() {
        // Two detectors, each returning one finding; "arb" sorts before "sandwich".
        let registry = Registry::builder()
            .register(
                MockDetector::new("arb", SemVer::new(1, 0, 0)).returning(vec![evidence(
                    AlertKind::Arbitrage,
                    vec![hash(1)],
                    0.7,
                )]),
            )
            .register(
                MockDetector::new("sandwich", SemVer::new(1, 2, 0)).returning(vec![evidence(
                    AlertKind::Sandwich,
                    vec![hash(2)],
                    0.9,
                )]),
            )
            .build()
            .unwrap();
        let models = ModelRegistry::builder()
            .record(card("arb", SemVer::new(1, 0, 0)))
            .record(card("sandwich", SemVer::new(1, 2, 0)))
            .build()
            .unwrap();
        let ctx = ctx_with(&[(hash(1), addr(1), addr(9)), (hash(2), addr(2), addr(8))]);

        let plan = DetectionPlan::link(&registry, &models).unwrap();
        assert_eq!(plan.len(), 2);
        let events = plan.detection_events(&ctx);

        let types: Vec<&str> = events.iter().map(DomainEvent::event_type).collect();
        assert_eq!(
            types,
            vec![
                "DetectorTriggered", // arb
                "PreliminaryAlertCreated",
                "DetectorTriggered", // sandwich
                "PreliminaryAlertCreated",
            ]
        );

        // The arb trigger carries arb's exact triple and its block.
        let DomainEvent::DetectorTriggered(arb_dt) = &events[0] else {
            panic!("expected DetectorTriggered");
        };
        assert_eq!(arb_dt.detector.id, "arb");
        assert_eq!(arb_dt.detector.version, "1.0.0");
        assert_eq!(
            arb_dt.detector.config_hash,
            ConfigHash::of_bytes(b"arb").to_hex()
        );
        assert_eq!(arb_dt.block, BlockRef::new(7, hash(0x77)));

        // The paired alert is provisional, kind/addresses/confidence from the
        // finding, with the same triple.
        let DomainEvent::PreliminaryAlertCreated(arb_alert) = &events[1] else {
            panic!("expected PreliminaryAlertCreated");
        };
        assert!(arb_alert.provisional);
        assert_eq!(arb_alert.kind, AlertKind::Arbitrage);
        assert_eq!(arb_alert.confidence, Confidence::new(0.7));
        assert_eq!(arb_alert.addresses, vec![addr(1), addr(9)]);
        assert_eq!(arb_alert.detector, arb_dt.detector);
    }

    /// Project an event stream to everything *except* the random `AlertId`, so the
    /// sequential and parallel paths can be compared for order + content (each alert
    /// mints a fresh id by design, so full `DomainEvent` equality never holds).
    fn projection(events: &[DomainEvent]) -> Vec<String> {
        events
            .iter()
            .map(|e| match e {
                DomainEvent::DetectorTriggered(d) => {
                    format!("T:{}:{}:{:?}", d.detector.id, d.detector.version, d.txs)
                }
                DomainEvent::PreliminaryAlertCreated(a) => format!(
                    "A:{}:{:?}:{:?}:{:?}",
                    a.detector.id, a.kind, a.addresses, a.confidence
                ),
                other => other.event_type().to_owned(),
            })
            .collect()
    }

    #[test]
    fn parallel_fan_out_matches_the_sequential_path_in_order_and_content() {
        // A multi-detector roster, each finding something — the parallel rayon
        // fan-out must emit the same events in the same `(id, version)` order as the
        // sequential reference (only the random AlertId differs, stripped here).
        let registry = Registry::builder()
            .register(
                MockDetector::new("arb", SemVer::new(1, 0, 0)).returning(vec![evidence(
                    AlertKind::Arbitrage,
                    vec![hash(1)],
                    0.7,
                )]),
            )
            .register(
                MockDetector::new("sandwich", SemVer::new(1, 2, 0)).returning(vec![
                    evidence(AlertKind::Sandwich, vec![hash(2)], 0.8),
                    evidence(AlertKind::Sandwich, vec![hash(3)], 0.9),
                ]),
            )
            .build()
            .unwrap();
        let models = ModelRegistry::builder()
            .record(card("arb", SemVer::new(1, 0, 0)))
            .record(card("sandwich", SemVer::new(1, 2, 0)))
            .build()
            .unwrap();
        let ctx = ctx_with(&[
            (hash(1), addr(1), addr(9)),
            (hash(2), addr(2), addr(8)),
            (hash(3), addr(3), addr(7)),
        ]);

        let plan = DetectionPlan::link(&registry, &models).unwrap();
        let sequential = plan.detection_events(&ctx);
        let parallel = plan.detection_events_parallel(&ctx);

        assert_eq!(
            projection(&sequential),
            projection(&parallel),
            "rayon fan-out must not reorder or change events"
        );
        assert_eq!(
            parallel.len(),
            6,
            "two findings + one finding ⇒ three pairs"
        );
    }

    #[test]
    fn a_detector_that_finds_nothing_emits_nothing() {
        let registry = Registry::builder()
            .register(MockDetector::new("arb", SemVer::new(1, 0, 0))) // returns []
            .build()
            .unwrap();
        let models = ModelRegistry::builder()
            .record(card("arb", SemVer::new(1, 0, 0)))
            .build()
            .unwrap();

        let ctx = DetectionCtx::new(BlockBundle::new(
            Chain::ETHEREUM,
            BlockRef::new(7, hash(0x77)),
            vec![],
        ));
        let plan = DetectionPlan::link(&registry, &models).unwrap();
        assert!(plan.detection_events(&ctx).is_empty());
    }

    #[test]
    fn a_finding_with_multiple_evidence_emits_a_pair_each() {
        let registry = Registry::builder()
            .register(
                MockDetector::new("sandwich", SemVer::new(1, 2, 0)).returning(vec![
                    evidence(AlertKind::Sandwich, vec![hash(1)], 0.8),
                    evidence(AlertKind::Sandwich, vec![hash(2)], 0.9),
                ]),
            )
            .build()
            .unwrap();
        let models = ModelRegistry::builder()
            .record(card("sandwich", SemVer::new(1, 2, 0)))
            .build()
            .unwrap();
        let ctx = ctx_with(&[(hash(1), addr(1), addr(9)), (hash(2), addr(2), addr(8))]);

        let plan = DetectionPlan::link(&registry, &models).unwrap();
        let events = plan.detection_events(&ctx);
        assert_eq!(events.len(), 4, "two findings ⇒ two trigger/alert pairs");
    }

    // ── Shadow rollout suppresses alerting, not scoring (§6, §18) ──────

    #[test]
    fn a_shadow_detector_still_triggers_but_raises_no_alert() {
        let registry = Registry::builder()
            .register(
                MockDetector::new("arb", SemVer::new(1, 0, 0)).returning(vec![evidence(
                    AlertKind::Arbitrage,
                    vec![hash(1)],
                    0.7,
                )]),
            )
            .build()
            .unwrap();
        let models = ModelRegistry::builder()
            .record(
                card("arb", SemVer::new(1, 0, 0))
                    .with_status(crate::model::LifecycleStatus::Shadow),
            )
            .build()
            .unwrap();
        let ctx = ctx_with(&[(hash(1), addr(1), addr(9))]);

        let plan = DetectionPlan::link(&registry, &models).unwrap();
        let events = plan.detection_events(&ctx);

        let types: Vec<&str> = events.iter().map(DomainEvent::event_type).collect();
        assert_eq!(
            types,
            vec!["DetectorTriggered"],
            "a Shadow build is still scored (DetectorTriggered) but doesn't alert"
        );
    }

    #[test]
    fn an_active_detector_alerts_normally_alongside_a_shadow_one() {
        let registry = Registry::builder()
            .register(
                MockDetector::new("arb", SemVer::new(1, 0, 0)).returning(vec![evidence(
                    AlertKind::Arbitrage,
                    vec![hash(1)],
                    0.7,
                )]),
            )
            .register(
                MockDetector::new("sandwich", SemVer::new(1, 2, 0)).returning(vec![evidence(
                    AlertKind::Sandwich,
                    vec![hash(2)],
                    0.9,
                )]),
            )
            .build()
            .unwrap();
        let models = ModelRegistry::builder()
            .record(
                card("arb", SemVer::new(1, 0, 0))
                    .with_status(crate::model::LifecycleStatus::Shadow),
            )
            .record(card("sandwich", SemVer::new(1, 2, 0))) // default Active
            .build()
            .unwrap();
        let ctx = ctx_with(&[(hash(1), addr(1), addr(9)), (hash(2), addr(2), addr(8))]);

        let plan = DetectionPlan::link(&registry, &models).unwrap();
        let events = plan.detection_events(&ctx);

        let types: Vec<&str> = events.iter().map(DomainEvent::event_type).collect();
        assert_eq!(
            types,
            vec![
                "DetectorTriggered", // arb (Shadow) — no alert follows
                "DetectorTriggered", // sandwich (Active)
                "PreliminaryAlertCreated",
            ]
        );
    }

    #[test]
    fn shadow_suppression_still_records_metrics() {
        let plan_events = || {
            let registry = Registry::builder()
                .register(
                    MockDetector::new("arb", SemVer::new(1, 0, 0)).returning(vec![evidence(
                        AlertKind::Arbitrage,
                        vec![hash(1)],
                        0.7,
                    )]),
                )
                .build()
                .unwrap();
            let models = ModelRegistry::builder()
                .record(
                    card("arb", SemVer::new(1, 0, 0))
                        .with_status(crate::model::LifecycleStatus::Shadow),
                )
                .build()
                .unwrap();
            let ctx = ctx_with(&[(hash(1), addr(1), addr(9))]);
            DetectionPlan::link(&registry, &models)
                .unwrap()
                .detection_events(&ctx)
        };

        // A Shadow finding still counts as a run+hit — metrics are unaffected by
        // alert suppression (§19).
        assert_eq!(runs_and_hits(|| drop(plan_events())), (1, 1));
    }

    #[test]
    fn link_fails_when_a_live_detector_has_no_model_card() {
        // "arb" is live and catalogued; "sandwich" is live but uncatalogued —
        // linking must fail loudly (fail-fast at boot) rather than run a detector
        // whose evidence can't carry a real config_hash. The two rosters drifting
        // is a wiring bug, caught here before the process serves live traffic.
        let registry = Registry::builder()
            .register(MockDetector::new("arb", SemVer::new(1, 0, 0)))
            .register(MockDetector::new("sandwich", SemVer::new(1, 2, 0)))
            .build()
            .unwrap();
        let models = ModelRegistry::builder()
            .record(card("arb", SemVer::new(1, 0, 0))) // sandwich deliberately absent
            .build()
            .unwrap();

        let err = DetectionPlan::link(&registry, &models).unwrap_err();
        assert_eq!(
            err,
            UnlinkedDetector {
                id: DetectorId::new("sandwich"),
                version: SemVer::new(1, 2, 0),
            }
        );
    }

    // ── per-detector metrics wiring (§19, task 3) ─────────────────────

    /// The `detect` seam is instrumented at the single [`LinkedDetector::detect`]
    /// call site **both** `Block` paths route through, so running a plan records a
    /// run per detector and a hit only for the one that found something. Asserted
    /// here on the sequential path; the rayon fan-out calls the identical
    /// `LinkedDetector::detect`, so it instruments by the same code (it can't be
    /// asserted with a thread-*local* recorder, since the rayon workers don't see
    /// it — in production the recorder is process-global, so they do).
    fn runs_and_hits(events: impl FnOnce()) -> (u64, u64) {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, events);

        let (mut runs, mut hits) = (0u64, 0u64);
        for (ck, _, _, value) in snapshotter.snapshot().into_vec() {
            if let DebugValue::Counter(n) = value {
                match ck.key().name() {
                    crate::metrics::RUNS_TOTAL => runs += n,
                    crate::metrics::HITS_TOTAL => hits += n,
                    _ => {}
                }
            }
        }
        (runs, hits)
    }

    /// A two-detector plan: "arb" fires once, "sandwich" finds nothing.
    fn plan_one_hit_one_miss() -> DetectionPlan {
        let registry = Registry::builder()
            .register(
                MockDetector::new("arb", SemVer::new(1, 0, 0)).returning(vec![evidence(
                    AlertKind::Arbitrage,
                    vec![hash(1)],
                    0.7,
                )]),
            )
            .register(MockDetector::new("sandwich", SemVer::new(1, 2, 0))) // returns []
            .build()
            .unwrap();
        let models = ModelRegistry::builder()
            .record(card("arb", SemVer::new(1, 0, 0)))
            .record(card("sandwich", SemVer::new(1, 2, 0)))
            .build()
            .unwrap();
        DetectionPlan::link(&registry, &models).unwrap()
    }

    #[test]
    fn detection_records_a_run_per_detector_and_a_hit_only_for_a_finding() {
        let plan = plan_one_hit_one_miss();
        let ctx = ctx_with(&[(hash(1), addr(1), addr(9))]);

        // Two detectors ran; only "arb" found something.
        assert_eq!(runs_and_hits(|| drop(plan.detection_events(&ctx))), (2, 1));
    }
}
