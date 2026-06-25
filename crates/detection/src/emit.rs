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
use events::primitives::{AccountAddress, AlertId, AlertKind, BlockRef, Confidence, DetectorRef};
use events::DomainEvent;

use detector_api::{DetectionCtx, DetectorId, DetectorPlugin, Enrichment, Evidence, SemVer};

use crate::model::ModelRegistry;
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
pub fn preliminary_alert(
    detector: DetectorRef,
    kind: AlertKind,
    addresses: Vec<AccountAddress>,
    confidence: Confidence,
) -> PreliminaryAlertCreated {
    PreliminaryAlertCreated {
        alert_id: AlertId::new(),
        detector,
        addresses,
        kind,
        confidence,
        provisional: true,
    }
}

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

/// One detector paired with its resolved, immutable [`DetectorRef`] — proven to
/// exist at link time, so the per-block emit path never has to look it up or
/// handle its absence.
struct LinkedDetector {
    plugin: Arc<dyn DetectorPlugin>,
    detector_ref: DetectorRef,
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
            let detector_ref = models
                .detector_ref(id, version)
                .ok_or(UnlinkedDetector { id, version })?;
            detectors.push(LinkedDetector {
                plugin: Arc::clone(plugin),
                detector_ref,
            });
        }
        Ok(Self { detectors })
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
    /// 4). The fan-out here is sequential — parallelizing `Block`-scoped detectors
    /// over a rayon pool is Sprint 4 task 2; the order and output are identical
    /// either way because each `detect` is pure.
    pub fn detection_events(&self, ctx: &DetectionCtx) -> Vec<DomainEvent> {
        let mut events = Vec::new();
        for linked in &self.detectors {
            for evidence in linked.plugin.detect(ctx) {
                events.push(DomainEvent::DetectorTriggered(detector_triggered(
                    linked.detector_ref.clone(),
                    ctx.block(),
                    &evidence,
                )));
                let addresses = implicated_addresses(ctx.enrichment(), &evidence.txs);
                events.push(DomainEvent::PreliminaryAlertCreated(preliminary_alert(
                    linked.detector_ref.clone(),
                    evidence.kind,
                    addresses,
                    evidence.confidence,
                )));
            }
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    use detector_api::test_util::MockDetector;
    use detector_api::{BlockBundle, EnrichmentBuilder, SemVer, TokenTransfer, TxActions};
    use events::primitives::{BlockRef, Chain};

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
        );
        let b = preliminary_alert(a_ref(), AlertKind::Arbitrage, vec![], Confidence::new(0.6));

        assert!(a.provisional, "always provisional on creation");
        assert_eq!(a.kind, AlertKind::Arbitrage);
        assert_eq!(a.addresses, vec![addr(1)]);
        assert_eq!(a.confidence, Confidence::new(0.6));
        assert_ne!(a.alert_id, b.alert_id, "each alert gets a fresh id");
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
}
