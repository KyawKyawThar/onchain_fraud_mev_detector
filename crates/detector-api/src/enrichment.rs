//! [`Enrichment`] — the decoded, normalized view of a block a detector reasons
//! over (§6, task 3): token metadata, AMM pool reserves at the block, reference
//! prices, and the per-transaction swaps/transfers decoded from raw calldata and
//! logs.
//!
//! This is the "enrichment (token/pool/price)" half of what [`DetectionCtx`]
//! carries. The other half — which block, which txs by hash — is the
//! [`BlockBundle`] of raw on-chain facts. Splitting them keeps the boundary
//! honest: the bundle is *what the chain said*, the enrichment is *what we
//! decoded from it*, and a detector reads both through one context.
//!
//! # The one invariant: no labels (§6, §8)
//!
//! Enrichment is **attribution-blind by construction**. Everything here is an
//! on-chain *fact* or a market *quantity* — an address, a reserve, a price — and
//! addresses are facts, not identities. There is deliberately no field naming
//! *who* an address belongs to ("Binance hot wallet", "known sandwich bot",
//! "sanctioned"). Attribution is the intelligence service's job, off the hot path
//! (§8); a detector physically cannot read a label because this type never
//! carries one. Anything tempted to add a `label`/`tag`/`entity` field here
//! belongs in the intelligence layer instead.
//!
//! # Built once per block
//!
//! The detection service assembles one [`Enrichment`] per [`BlockAssembled`] and
//! shares it by reference with every detector in the roster, so the cost of
//! decoding is amortised across the whole fan-out (§17). Detectors only *read*
//! it; [`detect`] is a pure function of the context (§6, §18), which is what
//! makes a detector replayable in backtests.
//!
//! [`DetectionCtx`]: crate::ctx::DetectionCtx
//! [`BlockBundle`]: crate::ctx::BlockBundle
//! [`BlockAssembled`]: events::chain::BlockAssembled
//! [`detect`]: crate::plugin::DetectorPlugin::detect

use std::collections::HashMap;

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

/// A reference price in US dollars per *whole* token (decimal-adjusted, not per
/// raw base unit), used to express on-chain quantities in a common numéraire —
/// e.g. a detector's `min_profit_usd` threshold (§6).
///
/// A validated newtype rather than a bare `f64` for the same reason
/// [`Confidence`] is: a plain float silently admits nonsense (a negative price, a
/// `NaN` from a divide-by-zero in an upstream feed). [`try_new`](Self::try_new)
/// rejects anything not finite and `>= 0.0`, so a bad feed value surfaces as an
/// error at the edge instead of poisoning a profit estimate deep in a detector.
///
/// This is *reference* attribution-blind market data (a token's USD price), never
/// anything about who holds it — see the module's no-labels invariant.
///
/// [`Confidence`]: events::primitives::Confidence
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct UsdPrice(f64);

/// A [`UsdPrice`] was constructed from a value that isn't a finite, non-negative
/// number.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
#[error("usd price {value} is not a finite, non-negative number")]
pub struct InvalidPrice {
    pub value: f64,
}

impl UsdPrice {
    /// Validate `value` is finite and `>= 0.0`. Use for prices from outside the
    /// process (an oracle/feed) where a bad value is a defect to surface.
    pub fn try_new(value: f64) -> Result<Self, InvalidPrice> {
        if value.is_finite() && value >= 0.0 {
            Ok(Self(value))
        } else {
            Err(InvalidPrice { value })
        }
    }

    pub fn get(self) -> f64 {
        self.0
    }

    /// Does a *known* USD `value` fall strictly below this threshold — i.e. should a
    /// dust gate reject it?
    ///
    /// The load-bearing subtlety, encoded once here so every detector's gate reads
    /// the same: an **unpriced** amount (`None`) is *not* excluded. The detectors
    /// deliberately report a structurally-unambiguous finding whose profit/notional
    /// couldn't be valued (at reduced confidence) rather than dropping it, so a
    /// missing price must never behave like "below the threshold". A gate is thus
    /// `if self.min_x_usd.excludes(value_usd) { skip }`.
    pub fn excludes(self, value: Option<f64>) -> bool {
        value.is_some_and(|v| v < self.0)
    }
}

impl TryFrom<f64> for UsdPrice {
    type Error = InvalidPrice;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl std::fmt::Display for UsdPrice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "${}", self.0)
    }
}

// Serde routes through `try_new` on the way *in*, so a `UsdPrice` deserialized
// from config/a feed (e.g. a detector's `min_profit_usd` threshold) is validated
// at the edge — a NaN or negative can't slip in and silently poison a `<`
// comparison later. Mirrors the validated-newtype discipline of `ConfigHash`.
impl Serialize for UsdPrice {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_f64(self.0)
    }
}

impl<'de> Deserialize<'de> for UsdPrice {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let value = f64::deserialize(deserializer)?;
        Self::try_new(value).map_err(D::Error::custom)
    }
}

/// What we know about an ERC-20 token: its address, decimals, and (when known)
/// symbol.
///
/// `decimals` is the load-bearing field — it's what lets a detector turn a raw
/// `U256` base-unit `amount` into a human/price-comparable quantity (USDC's 6 vs.
/// most tokens' 18). `symbol` is best-effort display only and `None` when the
/// token doesn't expose one; **never** branch detection logic on it (it's
/// attacker-controlled free text, and a spoofed "USDC" is a classic trick).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenMeta {
    pub address: Address,
    pub symbol: Option<String>,
    pub decimals: u8,
}

impl TokenMeta {
    pub fn new(address: Address, symbol: Option<String>, decimals: u8) -> Self {
        Self {
            address,
            symbol,
            decimals,
        }
    }

    /// Scale a raw base-unit `amount` to a whole-token `f64` using `decimals`
    /// (e.g. `1_500_000` of a 6-decimal token → `1.5`).
    ///
    /// Allocation-free: a direct `U256 → f64` widening divided by `10^decimals`,
    /// not a format-to-string-and-parse round trip — this runs in detector hot
    /// loops via [`Enrichment::usd_value`]. The result is a lossy estimate (an
    /// `f64` carries ~15–16 significant digits, so amounts above 2^53 base units
    /// lose low-order precision) fit for profit/threshold comparisons, **not**
    /// exact accounting — keep the raw `U256` for that. Total over all of `U256`:
    /// even `U256::MAX` (~1.2e77) is far inside `f64`'s range, so this never
    /// overflows or panics.
    pub fn to_whole(&self, amount: U256) -> f64 {
        f64::from(amount) / 10f64.powi(i32::from(self.decimals))
    }
}

/// A constant-product (Uniswap-v2-style) AMM pool's reserves *at this block* —
/// the spot state a detector needs to reason about price impact and the
/// profit of a swap (§6).
///
/// Reserves are raw base-unit `U256` (decimal-adjust via the tokens'
/// [`TokenMeta`]). v3/concentrated-liquidity pools don't reduce to two reserves;
/// this is the v2 shape that the first detectors (sandwich, arb — task 4) target,
/// and the richer shape lands additively when a detector needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolState {
    pub address: Address,
    pub token0: Address,
    pub token1: Address,
    pub reserve0: U256,
    pub reserve1: U256,
}

impl PoolState {
    pub fn new(
        address: Address,
        token0: Address,
        token1: Address,
        reserve0: U256,
        reserve1: U256,
    ) -> Self {
        Self {
            address,
            token0,
            token1,
            reserve0,
            reserve1,
        }
    }

    /// This pool's reserve of `token`, or `None` if `token` isn't one of the
    /// pair.
    pub fn reserve_of(&self, token: Address) -> Option<U256> {
        if token == self.token0 {
            Some(self.reserve0)
        } else if token == self.token1 {
            Some(self.reserve1)
        } else {
            None
        }
    }

    /// The *other* side of the pair given one token, or `None` if `token` isn't
    /// in the pool — convenient for "I swapped in X, what came out" reasoning.
    pub fn other_token(&self, token: Address) -> Option<Address> {
        if token == self.token0 {
            Some(self.token1)
        } else if token == self.token1 {
            Some(self.token0)
        } else {
            None
        }
    }
}

/// A decoded ERC-20 transfer (a `Transfer` log), normalized away from raw log
/// topics. Addresses are on-chain facts, not labels (see module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenTransfer {
    pub token: Address,
    pub from: Address,
    pub to: Address,
    pub amount: U256,
}

/// A decoded swap through an AMM pool: `amount_in` of `token_in` traded for
/// `amount_out` of `token_out` against `pool`. The unit a sandwich/arb detector
/// pattern-matches on (§6, §22).
///
/// Amounts are raw base units of their respective tokens; pair with
/// [`Enrichment::token`] / [`Enrichment::usd_value`] to compare or value them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Swap {
    pub pool: Address,
    pub token_in: Address,
    pub token_out: Address,
    pub amount_in: U256,
    pub amount_out: U256,
}

/// The decoded actions of one transaction: who sent it, where to, and the
/// swaps/transfers it produced. The enriched counterpart of a bare tx hash in the
/// [`BlockBundle`].
///
/// `to` is `None` for a contract-creation tx. `from`/`to` are addresses (facts),
/// never identities (§6 / §8).
///
/// [`BlockBundle`]: crate::ctx::BlockBundle
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxActions {
    pub hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub swaps: Vec<Swap>,
    pub transfers: Vec<TokenTransfer>,
}

impl TxActions {
    /// A transaction with `from`/`to` known but no decoded actions yet; layer
    /// swaps/transfers on with the `with_*` builders.
    pub fn new(hash: B256, from: Address, to: Option<Address>) -> Self {
        Self {
            hash,
            from,
            to,
            swaps: Vec::new(),
            transfers: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_swaps(mut self, swaps: Vec<Swap>) -> Self {
        self.swaps = swaps;
        self
    }

    #[must_use]
    pub fn with_transfers(mut self, transfers: Vec<TokenTransfer>) -> Self {
        self.transfers = transfers;
        self
    }
}

/// The enrichment attached to a [`DetectionCtx`](crate::ctx::DetectionCtx):
/// token metadata, pool reserves, reference prices, and per-tx decoded actions —
/// and **no labels** (module docs).
///
/// Assembled once per block via [`EnrichmentBuilder`] and read through the
/// accessors below. Maps are keyed by address/hash for O(1) lookup on the hot
/// path. An empty `Enrichment` ([`Default`]) is the honest representation of "not
/// enriched" — e.g. a header-only source where traces aren't available — so a
/// detector that needs enrichment it didn't get returns no findings rather than
/// guessing.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Enrichment {
    tokens: HashMap<Address, TokenMeta>,
    pools: HashMap<Address, PoolState>,
    prices: HashMap<Address, UsdPrice>,
    txs: HashMap<B256, TxActions>,
}

impl Enrichment {
    /// Start assembling enrichment for a block.
    pub fn builder() -> EnrichmentBuilder {
        EnrichmentBuilder::default()
    }

    /// Metadata for `token`, if known.
    pub fn token(&self, token: Address) -> Option<&TokenMeta> {
        self.tokens.get(&token)
    }

    /// Reserve state for `pool`, if known.
    pub fn pool(&self, pool: Address) -> Option<&PoolState> {
        self.pools.get(&pool)
    }

    /// Reference USD price for `token`, if known.
    pub fn price(&self, token: Address) -> Option<UsdPrice> {
        self.prices.get(&token).copied()
    }

    /// Decoded actions for transaction `hash`, if it was enriched.
    pub fn tx(&self, hash: B256) -> Option<&TxActions> {
        self.txs.get(&hash)
    }

    /// Every enriched transaction. Iteration order is unspecified (a `HashMap`);
    /// iterate the [`BlockBundle::txs`] hashes and look each up with [`tx`] when
    /// block order matters.
    ///
    /// [`BlockBundle::txs`]: crate::ctx::BlockBundle::txs
    /// [`tx`]: Self::tx
    pub fn txs(&self) -> impl ExactSizeIterator<Item = &TxActions> {
        self.txs.values()
    }

    /// Value a raw base-unit `amount` of `token` in USD, combining the token's
    /// [`decimals`](TokenMeta::decimals) and reference [`price`](Self::price).
    ///
    /// `None` if either the token's metadata or its price is unknown — the caller
    /// decides whether a missing price means "skip" or "low confidence". The
    /// result is a lossy estimate (see [`TokenMeta::to_whole`]), right for a
    /// `min_profit_usd` gate, not for exact accounting.
    ///
    /// Also `None` if the estimate isn't finite: with extreme inputs the
    /// `amount × price` product can overflow `f64` to infinity, and a non-finite
    /// value must never reach a `>` threshold comparison (where `inf` would fire
    /// every gate). The caller already handles `None`, so funnelling the
    /// degenerate case through the same path keeps the gate honest.
    pub fn usd_value(&self, token: Address, amount: U256) -> Option<f64> {
        let whole = self.token(token)?.to_whole(amount);
        let price = self.price(token)?;
        let value = whole * price.get();
        value.is_finite().then_some(value)
    }
}

/// Accumulates the decoded view of one block, then freezes it into an
/// [`Enrichment`]. Each `add_*`/`set_*` keys on address (or tx hash) and is
/// last-write-wins — the block is decoded once, in one place, so a later write
/// for the same key means a corrected value, not a conflict.
#[derive(Debug, Default)]
pub struct EnrichmentBuilder {
    tokens: HashMap<Address, TokenMeta>,
    pools: HashMap<Address, PoolState>,
    prices: HashMap<Address, UsdPrice>,
    txs: HashMap<B256, TxActions>,
}

impl EnrichmentBuilder {
    pub fn add_token(&mut self, token: TokenMeta) -> &mut Self {
        self.tokens.insert(token.address, token);
        self
    }

    pub fn add_pool(&mut self, pool: PoolState) -> &mut Self {
        self.pools.insert(pool.address, pool);
        self
    }

    pub fn set_price(&mut self, token: Address, price: UsdPrice) -> &mut Self {
        self.prices.insert(token, price);
        self
    }

    pub fn add_tx(&mut self, tx: TxActions) -> &mut Self {
        self.txs.insert(tx.hash, tx);
        self
    }

    /// Freeze into an immutable [`Enrichment`]. Infallible: the maps are already
    /// well-formed by construction.
    ///
    /// Consumes the builder so the maps *move* into the [`Enrichment`] rather
    /// than being cloned — the block is decoded once and the builder is spent on
    /// `build`, so there's nothing to keep it for. Use the two-step
    /// `let mut b = …; b.add_…(); b.build()` form (what the per-block decode loop
    /// does); a single fluent expression can't move out of the `&mut self`
    /// chain's borrow.
    pub fn build(self) -> Enrichment {
        Enrichment {
            tokens: self.tokens,
            pools: self.pools,
            prices: self.prices,
            txs: self.txs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Distinct, readable test addresses without pulling in a literal-address dep.
    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn hash(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    #[test]
    fn usd_price_rejects_nonsense() {
        assert!(UsdPrice::try_new(1234.56).is_ok());
        assert!(UsdPrice::try_new(0.0).is_ok());
        assert_eq!(
            UsdPrice::try_new(-1.0).unwrap_err(),
            InvalidPrice { value: -1.0 }
        );
        assert!(UsdPrice::try_new(f64::NAN).is_err());
        assert!(UsdPrice::try_new(f64::INFINITY).is_err());
    }

    #[test]
    fn usd_price_validates_on_deserialize() {
        // A good value round-trips through serde …
        let p = UsdPrice::try_new(12.5).unwrap();
        assert_eq!(serde_json::to_string(&p).unwrap(), "12.5");
        assert_eq!(serde_json::from_str::<UsdPrice>("12.5").unwrap(), p);
        // … and a nonsense one is rejected at the edge, not silently admitted.
        assert!(serde_json::from_str::<UsdPrice>("-1.0").is_err());
        assert!(serde_json::from_str::<UsdPrice>("null").is_err());
    }

    #[test]
    fn to_whole_respects_decimals() {
        let usdc = TokenMeta::new(addr(1), Some("USDC".into()), 6);
        // 1_500_000 base units of a 6-decimal token = 1.5 whole tokens.
        assert_eq!(usdc.to_whole(U256::from(1_500_000u64)), 1.5);

        let weth = TokenMeta::new(addr(2), Some("WETH".into()), 18);
        assert_eq!(weth.to_whole(U256::from(2_000_000_000_000_000_000u64)), 2.0);
    }

    #[test]
    fn to_whole_handles_zero_decimals_and_zero_amount() {
        // An integer-only token (decimals = 0): base units *are* whole tokens.
        let nft_like = TokenMeta::new(addr(1), None, 0);
        assert_eq!(nft_like.to_whole(U256::from(42u64)), 42.0);
        // Zero is zero at any scale.
        let weth = TokenMeta::new(addr(2), None, 18);
        assert_eq!(weth.to_whole(U256::ZERO), 0.0);
    }

    #[test]
    fn to_whole_is_total_over_huge_values() {
        // Locks the contract that scaling is total over all of U256 — a guard
        // against a future "optimisation" to `amount.to::<u128>()`, which panics
        // on overflow. `U256::MAX` (~1.2e77) still widens cleanly into a finite
        // f64; the function never panics or returns a non-finite value.
        let weth = TokenMeta::new(addr(1), None, 18);
        let scaled = weth.to_whole(U256::MAX);
        assert!(scaled.is_finite() && scaled > 0.0);
    }

    #[test]
    fn empty_enrichment_returns_nothing() {
        let e = Enrichment::default();
        assert!(e.token(addr(1)).is_none());
        assert!(e.pool(addr(1)).is_none());
        assert!(e.price(addr(1)).is_none());
        assert!(e.tx(hash(1)).is_none());
        assert_eq!(e.txs().len(), 0);
        assert!(e.usd_value(addr(1), U256::from(1u64)).is_none());
    }

    #[test]
    fn builder_collects_and_looks_up() {
        let token = addr(1);
        let pool_addr = addr(9);
        let other = addr(2);

        let mut b = Enrichment::builder();
        b.add_token(TokenMeta::new(token, Some("USDC".into()), 6))
            .add_pool(PoolState::new(
                pool_addr,
                token,
                other,
                U256::from(100u64),
                U256::from(200u64),
            ))
            .set_price(token, UsdPrice::try_new(1.0).unwrap())
            .add_tx(TxActions::new(hash(7), addr(3), Some(pool_addr)));
        let e = b.build();

        assert_eq!(e.token(token).unwrap().decimals, 6);
        assert_eq!(
            e.pool(pool_addr).unwrap().reserve_of(other),
            Some(U256::from(200u64))
        );
        assert_eq!(e.pool(pool_addr).unwrap().other_token(token), Some(other));
        assert_eq!(e.price(token).unwrap().get(), 1.0);
        assert_eq!(e.tx(hash(7)).unwrap().from, addr(3));
        assert_eq!(e.txs().len(), 1);
    }

    #[test]
    fn last_write_wins_per_key() {
        let token = addr(1);
        let mut b = Enrichment::builder();
        b.set_price(token, UsdPrice::try_new(1.0).unwrap())
            .set_price(token, UsdPrice::try_new(2.0).unwrap());
        assert_eq!(b.build().price(token).unwrap().get(), 2.0);
    }

    #[test]
    fn usd_value_combines_decimals_and_price() {
        let usdc = addr(1);
        let mut b = Enrichment::builder();
        b.add_token(TokenMeta::new(usdc, Some("USDC".into()), 6))
            .set_price(usdc, UsdPrice::try_new(1.0).unwrap());
        let e = b.build();

        // 2_000_000 base units = 2.0 USDC @ $1.00 = $2.00.
        assert_eq!(e.usd_value(usdc, U256::from(2_000_000u64)), Some(2.0));
    }

    #[test]
    fn usd_value_is_none_when_estimate_overflows() {
        // Degenerate but reachable: a colossal amount of a 0-decimal token at an
        // astronomical price overflows the f64 product to +inf. The gate must
        // see `None`, not `Some(inf)` (which would clear every threshold).
        let token = addr(1);
        let mut b = Enrichment::builder();
        b.add_token(TokenMeta::new(token, None, 0))
            .set_price(token, UsdPrice::try_new(1e300).unwrap());
        assert_eq!(b.build().usd_value(token, U256::MAX), None);
    }

    #[test]
    fn usd_value_of_zero_is_zero() {
        let usdc = addr(1);
        let mut b = Enrichment::builder();
        b.add_token(TokenMeta::new(usdc, Some("USDC".into()), 6))
            .set_price(usdc, UsdPrice::try_new(1.0).unwrap());
        assert_eq!(b.build().usd_value(usdc, U256::ZERO), Some(0.0));
    }

    #[test]
    fn usd_price_orders_for_threshold_comparisons() {
        // `PartialOrd` is what lets a detector compare an estimate to a config
        // threshold; lock that it orders by magnitude.
        let cheap = UsdPrice::try_new(0.5).unwrap();
        let dear = UsdPrice::try_new(2_500.0).unwrap();
        assert!(cheap < dear);
        assert_eq!(dear.to_string(), "$2500");
    }

    #[test]
    fn enrichment_and_ctx_are_send_and_sync() {
        // The context is built once per block and fanned across a rayon pool
        // (§17); a non-`Send`/`Sync` field would only fail at the call site, so
        // assert the bound here, at the type's home.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Enrichment>();
        assert_send_sync::<crate::ctx::DetectionCtx>();
    }

    #[test]
    fn usd_value_needs_both_metadata_and_price() {
        let token = addr(1);
        // Token known, price missing.
        let mut b = Enrichment::builder();
        b.add_token(TokenMeta::new(token, None, 18));
        assert!(b.build().usd_value(token, U256::from(1u64)).is_none());

        // Price known, token metadata missing.
        let mut b = Enrichment::builder();
        b.set_price(token, UsdPrice::try_new(5.0).unwrap());
        assert!(b.build().usd_value(token, U256::from(1u64)).is_none());
    }

    #[test]
    fn reserve_of_unknown_token_is_none() {
        let pool = PoolState::new(
            addr(9),
            addr(1),
            addr(2),
            U256::from(1u64),
            U256::from(2u64),
        );
        assert!(pool.reserve_of(addr(3)).is_none());
        assert!(pool.other_token(addr(3)).is_none());
    }

    #[test]
    fn tx_actions_carry_decoded_swaps_and_transfers() {
        let tx = TxActions::new(hash(1), addr(1), Some(addr(2)))
            .with_swaps(vec![Swap {
                pool: addr(9),
                token_in: addr(3),
                token_out: addr(4),
                amount_in: U256::from(10u64),
                amount_out: U256::from(9u64),
            }])
            .with_transfers(vec![TokenTransfer {
                token: addr(3),
                from: addr(1),
                to: addr(9),
                amount: U256::from(10u64),
            }]);

        assert_eq!(tx.swaps.len(), 1);
        assert_eq!(tx.swaps[0].amount_out, U256::from(9u64));
        assert_eq!(tx.transfers.len(), 1);
        assert_eq!(tx.transfers[0].token, addr(3));
    }
}
