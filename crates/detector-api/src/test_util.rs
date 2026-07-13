//! Test doubles and fixtures for exercising the
//! [`DetectorPlugin`](crate::DetectorPlugin) seam (§6).
//!
//! Gated behind `#[cfg(any(test, feature = "test-util"))]`: available to this
//! crate's own unit tests, and — via the `test-util` feature — to the detector
//! crates (task 4) and service tests that need a stand-in detector or a quick
//! [`DetectionCtx`] without re-rolling the `EnrichmentBuilder` dance. Never
//! compiled into a normal build, so it can't bloat or leak into the shipped
//! binary.

use std::marker::PhantomData;

use alloy_primitives::{Address, B256, U256};

use crate::cross_block::CrossBlockDetector;
use crate::ctx::{BlockBundle, DetectionCtx};
use crate::enrichment::{
    EnrichmentBuilder, PoolState, Swap, TokenMeta, TokenTransfer, TxActions, UsdPrice,
};
use crate::plugin::{DetectorId, DetectorPlugin, Evidence, ModelKind, Scope, SemVer};
use events::primitives::{AlertKind, BlockRef, Chain, Confidence};

/// A configurable stand-in for a real detector crate. It reports whatever
/// identity/kind/scope it was built with and returns a fixed list of findings
/// from [`detect`](DetectorPlugin::detect) regardless of context — enough to
/// drive registry, scheduler and wiring tests against the seam.
pub struct MockDetector {
    id: DetectorId,
    version: SemVer,
    kind: ModelKind,
    scope: Scope,
    findings: Vec<Evidence>,
}

impl MockDetector {
    /// A `Rule`/`Block` detector with the given identity that finds nothing.
    /// Layer on the builder methods to vary kind, scope, or output.
    pub fn new(id: &'static str, version: SemVer) -> Self {
        Self {
            id: DetectorId::new(id),
            version,
            kind: ModelKind::Rule,
            scope: Scope::Block,
            findings: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_kind(mut self, kind: ModelKind) -> Self {
        self.kind = kind;
        self
    }

    #[must_use]
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }

    /// Make `detect` return `findings` (cloned) for every context.
    #[must_use]
    pub fn returning(mut self, findings: Vec<Evidence>) -> Self {
        self.findings = findings;
        self
    }
}

impl DetectorPlugin for MockDetector {
    fn id(&self) -> DetectorId {
        self.id
    }
    fn version(&self) -> SemVer {
        self.version
    }
    fn kind(&self) -> ModelKind {
        self.kind
    }
    fn scope(&self) -> Scope {
        self.scope
    }
    fn detect(&self, _ctx: &DetectionCtx) -> Vec<Evidence> {
        self.findings.clone()
    }
}

/// A trivial finding for tests that care only about *how many* a detector
/// returns, not their content.
pub fn dummy_evidence() -> Evidence {
    Evidence::new(AlertKind::Sandwich, Vec::new(), Confidence::new(0.5))
}

/// A configurable stand-in for a real [`CrossBlockDetector`], for exercising the
/// scheduler's per-block apply + reorg-rewind path without a production cross-block
/// detector (there is none yet — both built-ins are `Scope::Block`).
///
/// Generic over the state type `S` so tests can prove the type-erased slot roster
/// holds *heterogeneous* states. Its [`observe`](CrossBlockDetector::observe) folds
/// the block in by setting the state to the block's number (`S: From<u8>`), so a
/// rewind's effect on the accumulated value is observable; [`detect`] returns a
/// fixed finding list regardless of state.
pub struct MockCrossBlockDetector<S = u64> {
    id: DetectorId,
    version: SemVer,
    kind: ModelKind,
    window_blocks: u32,
    findings: Vec<Evidence>,
    _state: PhantomData<fn() -> S>,
}

impl<S> MockCrossBlockDetector<S> {
    /// A `Rule` cross-block detector with the given identity, a window of 16, and
    /// no findings. Layer on [`returning`](Self::returning) to vary output.
    pub fn new(id: &'static str, version: SemVer) -> Self {
        Self {
            id: DetectorId::new(id),
            version,
            kind: ModelKind::Rule,
            window_blocks: 16,
            findings: Vec::new(),
            _state: PhantomData,
        }
    }

    /// Set the trailing window the snapshot store is sized to.
    #[must_use]
    pub fn with_window(mut self, window_blocks: u32) -> Self {
        self.window_blocks = window_blocks;
        self
    }

    /// Make `detect` return `findings` (cloned) for every block.
    #[must_use]
    pub fn returning(mut self, findings: Vec<Evidence>) -> Self {
        self.findings = findings;
        self
    }
}

impl<S> CrossBlockDetector for MockCrossBlockDetector<S>
where
    S: Clone + Send + From<u8> + 'static,
{
    type State = S;

    fn id(&self) -> DetectorId {
        self.id
    }
    fn version(&self) -> SemVer {
        self.version
    }
    fn kind(&self) -> ModelKind {
        self.kind
    }
    fn window_blocks(&self) -> u32 {
        self.window_blocks
    }
    fn init_state(&self) -> S {
        S::from(0)
    }
    fn observe(&self, ctx: &DetectionCtx, state: &mut S) {
        // Fold = "remember this block's height", so a rewind's effect on the
        // accumulated value is directly observable in tests.
        *state = S::from(ctx.block().number as u8);
    }
    fn detect(&self, _ctx: &DetectionCtx, _state: &S) -> Vec<Evidence> {
        self.findings.clone()
    }
}

// ── Fixtures: building a `DetectionCtx` for detector tests ───────────────────
// Shared so every detector crate (sandwich, arb, and the five to come) stands up
// a context the same way instead of re-rolling addresses, hashes and an
// `EnrichmentBuilder` by hand.

/// A distinct, readable test address from one byte (`0xAB → 0xABAB…AB`).
pub fn addr(byte: u8) -> Address {
    Address::repeat_byte(byte)
}

/// A distinct, readable 32-byte test hash from one byte.
pub fn b256(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

/// A [`Swap`] with `u128` raw-base-unit amounts — saves the `U256::from` noise at
/// every call site.
pub fn swap(
    pool: Address,
    token_in: Address,
    token_out: Address,
    amount_in: u128,
    amount_out: u128,
) -> Swap {
    Swap {
        pool,
        token_in,
        token_out,
        amount_in: U256::from(amount_in),
        amount_out: U256::from(amount_out),
    }
}

/// A [`TokenTransfer`] with a `u128` raw-base-unit amount — the transfer analogue
/// of [`swap`], so the transfer-based detectors (flashloan, liquidation, rugpull,
/// poisoning) declare a decoded `Transfer` log without the `U256::from` noise.
pub fn transfer(token: Address, from: Address, to: Address, amount: u128) -> TokenTransfer {
    TokenTransfer {
        token,
        from,
        to,
        amount: U256::from(amount),
    }
}

/// Fluent builder for a [`DetectionCtx`]: declare priced tokens, pools, and the
/// per-tx swaps, then [`build`](Self::build). Defaults to Ethereum block 1; the
/// enrichment is assembled in one place so a detector test reads as a scenario,
/// not as plumbing.
pub struct CtxBuilder {
    chain: Chain,
    block: BlockRef,
    order: Vec<B256>,
    enrichment: EnrichmentBuilder,
}

impl Default for CtxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CtxBuilder {
    /// An empty context on Ethereum, block 1.
    pub fn new() -> Self {
        Self {
            chain: Chain::ETHEREUM,
            block: BlockRef::new(1, B256::repeat_byte(0xff)),
            order: Vec::new(),
            enrichment: EnrichmentBuilder::default(),
        }
    }

    /// Override the chain/block the context is for.
    #[must_use]
    pub fn at(mut self, chain: Chain, block: BlockRef) -> Self {
        self.chain = chain;
        self.block = block;
        self
    }

    /// Register a token with `decimals` and a reference USD price — so
    /// `usd_value` can value amounts of it.
    #[must_use]
    pub fn priced_token(mut self, token: Address, decimals: u8, price_usd: f64) -> Self {
        self.enrichment
            .add_token(TokenMeta::new(token, None, decimals));
        self.enrichment.set_price(
            token,
            UsdPrice::try_new(price_usd).expect("test price is valid"),
        );
        self
    }

    /// Register a token's `decimals` with **no** price — the "unpriced" path
    /// where `usd_value` returns `None`.
    #[must_use]
    pub fn token(mut self, token: Address, decimals: u8) -> Self {
        self.enrichment
            .add_token(TokenMeta::new(token, None, decimals));
        self
    }

    /// Register a constant-product pool's reserves.
    #[must_use]
    pub fn pool(
        mut self,
        pool: Address,
        token0: Address,
        token1: Address,
        r0: u128,
        r1: u128,
    ) -> Self {
        self.enrichment.add_pool(PoolState::new(
            pool,
            token0,
            token1,
            U256::from(r0),
            U256::from(r1),
        ));
        self
    }

    /// Append a transaction (in block order) with its decoded `swaps`.
    #[must_use]
    pub fn tx(mut self, hash: B256, from: Address, swaps: Vec<Swap>) -> Self {
        self.order.push(hash);
        self.enrichment
            .add_tx(TxActions::new(hash, from, None).with_swaps(swaps));
        self
    }

    /// Append a transaction (in block order) carrying decoded `transfers` and no
    /// swaps — the shape the transfer-based detectors (flashloan, liquidation,
    /// rugpull, poisoning) pattern-match on.
    #[must_use]
    pub fn transfer_tx(mut self, hash: B256, from: Address, transfers: Vec<TokenTransfer>) -> Self {
        self.order.push(hash);
        self.enrichment
            .add_tx(TxActions::new(hash, from, None).with_transfers(transfers));
        self
    }

    /// Append a fully-specified transaction (its own `hash`, sender, swaps *and*
    /// transfers) in block order — the escape hatch for a detector whose scenario
    /// needs both halves of a tx's decoded actions at once.
    #[must_use]
    pub fn tx_actions(mut self, tx: TxActions) -> Self {
        self.order.push(tx.hash);
        self.enrichment.add_tx(tx);
        self
    }

    /// Freeze into the [`DetectionCtx`] a detector runs over.
    pub fn build(self) -> DetectionCtx {
        DetectionCtx::with_enrichment(
            BlockBundle::new(self.chain, self.block, self.order),
            self.enrichment.build(),
        )
    }
}

// ── Scenario scaffolding for detector property tests ─────────────────────────
// The detector property tests (task 4) all share one shape: build a block of
// transactions, run the detector, and cross-check each finding against the tx it
// came from. Shared here — like `CtxBuilder` above — so every detector crate
// (sandwich, arb, and the five to come) expresses that the same way instead of
// re-rolling a `(B256, Address, Vec<Swap>)` tuple plus parallel look-up maps.
//
// The proptest *strategies* (which block noise to generate) stay in each detector
// crate's test: noise is detector-specific (a sandwich wants a dense shared pool,
// an arb wants multi-hop txs), and keeping them out leaves this seam crate free
// of a `proptest` dependency.

/// One transaction a test wants in a block: its hash, sender, and decoded swaps.
/// The unit [`Scenario`] threads through, replacing an ad-hoc
/// `(B256, Address, Vec<Swap>)` tuple so a finding's sender/swaps can be looked
/// up by name rather than tracked in a side map.
#[derive(Clone, Debug)]
pub struct TxSpec {
    pub hash: B256,
    pub from: Address,
    pub swaps: Vec<Swap>,
}

impl TxSpec {
    pub fn new(hash: B256, from: Address, swaps: Vec<Swap>) -> Self {
        Self { hash, from, swaps }
    }
}

/// A built block scenario: the [`DetectionCtx`] a detector runs over, plus an
/// index from tx hash back to its [`TxSpec`], so a property test can cross-check
/// a finding against the transaction it came from (the sender behind a swap, the
/// swaps behind a tx) without re-threading the inputs by hand.
pub struct Scenario {
    ctx: DetectionCtx,
    by_hash: std::collections::HashMap<B256, TxSpec>,
}

impl Scenario {
    /// Materialize `txs` (already in block order) into a context, pricing each
    /// token in `prices` as `(address, decimals, usd_per_whole)`. Tokens absent
    /// from `prices` are deliberately left *unpriced* — the honest "no reference
    /// price" path, where a structural finding is still reported but unvalued.
    ///
    /// Panics on a duplicate tx hash: that would silently overwrite an entry in
    /// the cross-check index and weaken the test, and it can only be a
    /// fixture-construction bug, never detector input.
    pub fn from_specs(prices: &[(Address, u8, f64)], txs: Vec<TxSpec>) -> Self {
        let mut builder = CtxBuilder::new();
        for &(token, decimals, usd) in prices {
            builder = builder.priced_token(token, decimals, usd);
        }
        let mut by_hash = std::collections::HashMap::with_capacity(txs.len());
        for tx in &txs {
            assert!(
                !by_hash.contains_key(&tx.hash),
                "scenario has two transactions with hash {} — colliding test fixtures",
                tx.hash,
            );
            by_hash.insert(tx.hash, tx.clone());
            builder = builder.tx(tx.hash, tx.from, tx.swaps.clone());
        }
        Self {
            ctx: builder.build(),
            by_hash,
        }
    }

    /// The context a detector runs over.
    pub fn ctx(&self) -> &DetectionCtx {
        &self.ctx
    }

    /// The sender of transaction `hash`. Panics if `hash` isn't in the scenario —
    /// a finding that names a tx outside its own block is a detector bug worth a
    /// loud failure, not a silent `None`.
    pub fn sender_of(&self, hash: B256) -> Address {
        self.tx(hash).from
    }

    /// The decoded swaps of transaction `hash` (same panic contract as
    /// [`sender_of`](Self::sender_of)).
    pub fn swaps_of(&self, hash: B256) -> &[Swap] {
        &self.tx(hash).swaps
    }

    fn tx(&self, hash: B256) -> &TxSpec {
        self.by_hash
            .get(&hash)
            .unwrap_or_else(|| panic!("tx {hash} is not in the scenario"))
    }
}

/// Splice a planted pattern into arbitrary block `noise`, returning the full
/// ordered tx list. Each noise entry is `(sender_byte, swaps)`; noise tx `i` is
/// assigned hash `b256(i as u8)`, so a caller must keep the noise count below its
/// planted hash bytes to avoid a collision (which [`Scenario::from_specs`]
/// asserts against regardless). `planted` is inserted as a contiguous run at
/// position `at` (clamped to the block length), preserving its internal order.
pub fn planted_in_noise(noise: &[(u8, Vec<Swap>)], at: usize, planted: &[TxSpec]) -> Vec<TxSpec> {
    let mut order: Vec<TxSpec> = noise
        .iter()
        .enumerate()
        .map(|(i, (from, swaps))| TxSpec::new(b256(i as u8), addr(*from), swaps.clone()))
        .collect();
    let at = at.min(order.len());
    for (offset, tx) in planted.iter().enumerate() {
        order.insert(at + offset, tx.clone());
    }
    order
}

/// Deserialize a finding's `detail` payload into a detector's typed evidence
/// struct (e.g. `SandwichDetail`/`ArbDetail`). Shared so each detector test
/// stops re-declaring the same one-liner.
pub fn detail<T: serde::de::DeserializeOwned>(ev: &Evidence) -> T {
    serde_json::from_value(ev.detail.clone()).expect("evidence detail deserializes into T")
}
