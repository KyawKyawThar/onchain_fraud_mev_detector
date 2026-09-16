//! The replay-window format (§18, §20.1; Hardening Epic E).
//!
//! A [`Window`] is a run of **consecutive** blocks from one chain, each stored
//! as the full [`DetectionCtx`] a detector saw, together with the findings on
//! those blocks that simulation **adjudicated** — confirmed, refuted, or
//! confirmed and later retracted. It is the unit the backtest harness needs to
//! state a false-positive rate about real traffic rather than about scenarios
//! its authors wrote:
//!
//! ```text
//!   event store ──► dataset window ──► corpus/<name>.json ──► backtest
//!   (§16 replay)    (join + label,      (this format)          (replay through
//!                    enriched ctx only)                          today's roster)
//! ```
//!
//! # What an adjudication can and cannot tell you
//!
//! The labels come from the §20.1 flywheel: a `DetectorTriggered` joined to the
//! `SimulationCompleted` that confirmed or refuted it. That makes them good for
//! **precision** and structurally blind to **recall** — simulation only ever
//! ran on something a detector already flagged, so an incident nobody flagged
//! has no label here. A window is therefore *open-world*: a replayed alert with
//! no adjudication is **unadjudicated**, never a false positive, and the
//! backtest harness scores it that way. Hand-built fixtures are closed-world
//! (their authors listed every incident); a window is not, and the harness
//! must not pretend otherwise.
//!
//! # Why every block, not just the flagged ones
//!
//! A window holds every canonical block in its range, adjudicated or not, and
//! [`Window::validate`] refuses a gap. A file of only the flagged blocks would
//! be a sample selected *by the detectors being measured*: a new detector
//! version that fires on a quiet block could never be seen doing it. The quiet
//! blocks are where a regression in precision first shows up.
//!
//! # Exactness
//!
//! Replaying a window must reproduce the detector's input bit for bit, or a
//! threshold sitting on a boundary flips. Two encodings exist for that reason:
//! USD prices are stored as their shortest round-trip decimal string and parsed
//! with `f64::from_str` (correctly rounded, unlike a JSON number read through
//! a fast float parser), and gas prices, which are `u128`, are strings too.
//! Maps are written sorted by key, so one context always serialises to one
//! byte sequence and a committed window diffs cleanly.
//!
//! # Storage
//!
//! Windows are committed to git, so size is a design constraint, not a
//! detail. [`save`] writes gzip when the path ends in `.json.gz`
//! (deterministic: no timestamp or file name in the header), and both
//! directions enforce a [`Budget`]: a per-file limit well under the hosting
//! provider's hard limits, a total corpus limit, and a decompressed limit so a
//! corrupt or hostile archive cannot exhaust memory. Crossing the corpus
//! budget is the signal to move windows to an object store (or Git LFS) with
//! the digests kept in git. A Git LFS pointer checked out in place of its
//! object is recognised and named, rather than failing as bad JSON.
//!
//! # No labels
//!
//! The contexts carry no attribution — they cannot, the type has nowhere to put
//! one (§6). An [`Adjudication`] names a *behaviour* simulation checked, beside
//! the context, never inside it. Arch-conformance keeps this crate off every
//! store and off `intelligence`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use alloy_primitives::{Address, B256, U256};
use chrono::{DateTime, Utc};
use detector_api::{
    BlockBundle, DetectionCtx, Enrichment, PoolState, Swap, TokenMeta, TokenTransfer, TxActions,
    TxGas, UsdPrice,
};
use events::primitives::{AlertKind, BlockRef, Chain};
use serde::{Deserialize, Serialize};

/// The on-disk format revision. Bump it (and teach [`load`] the old one) for
/// any change a reader of the previous revision would misinterpret.
pub const FORMAT_VERSION: u32 = 1;

/// Everything that can make a window unusable. Every variant is a refusal:
/// a window that half-loads would be scored as if it were whole.
#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    #[error("reading {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("writing {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("serializing window")]
    Serialize(#[source] serde_json::Error),
    #[error("{path}: {problem}")]
    Invalid { path: PathBuf, problem: Invalid },
    /// A window file, or the corpus as a whole, is over its [`Budget`].
    #[error("{path}: {what} is {bytes} bytes, over the {limit}-byte budget — {remedy}")]
    TooLarge {
        path: PathBuf,
        what: &'static str,
        bytes: u64,
        limit: u64,
        remedy: &'static str,
    },
    /// The file is a Git LFS pointer, not the window it points at.
    #[error(
        "{path} is a Git LFS pointer, not a window — fetch the object (`git lfs pull`, or \
         `lfs: true` on the CI checkout) before replaying"
    )]
    LfsPointer { path: PathBuf },
    /// Two committed windows cover the same block. Scoring both would count
    /// every alert on the overlap twice — a false-positive rate over a sample
    /// that is not the sample it claims.
    #[error("{first} and {second} both cover block {block} on {chain}")]
    Overlap {
        first: PathBuf,
        second: PathBuf,
        chain: Chain,
        block: u64,
    },
}

/// Why a window failed [`Window::validate`].
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Invalid {
    #[error("format version {found} is not supported (this build reads {FORMAT_VERSION})")]
    FormatVersion { found: u32 },
    #[error("the window has no name")]
    Unnamed,
    #[error("the window has no blocks")]
    Empty,
    #[error(
        "block {found} follows block {previous}: a window must be consecutive, because a gap \
         is a sample the capture chose rather than the chain's"
    )]
    Gap { previous: u64, found: u64 },
    #[error("block {block}: actions for tx {tx} which is not in the block")]
    ForeignActions { block: u64, tx: B256 },
    #[error("block {block}: tx {tx} appears twice")]
    DuplicateTx { block: u64, tx: B256 },
    #[error("block {block}: price {raw:?} for {token} is not a finite, non-negative number")]
    BadPrice {
        block: u64,
        token: Address,
        raw: String,
    },
    #[error("block {block}: gas price {raw:?} is not a u128")]
    BadGasPrice { block: u64, raw: String },
    #[error("adjudication on block {block}, which is not in the window")]
    AdjudicationOutsideWindow { block: u64 },
    #[error("adjudication on block {block} implicates no transactions")]
    AdjudicationWithoutTxs { block: u64 },
    #[error("adjudication on block {block} implicates tx {tx}, which is not in that block")]
    AdjudicationForeignTx { block: u64, tx: B256 },
}

/// One replay window: see the crate docs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub format_version: u32,
    /// Stable, human-readable, and the name the backtest report prints.
    pub name: String,
    pub provenance: Provenance,
    /// Every canonical block in the range, ascending and consecutive.
    pub blocks: Vec<BlockRecord>,
    /// Simulation's verdicts on findings in these blocks, in the store's order.
    pub adjudications: Vec<Adjudication>,
    /// Findings in the window that could **not** be adjudicated, by outcome
    /// (`unalerted`, `unresolved`, `reverted`, `unlinkable`). Carried so that a
    /// window with few labels explains itself from its own file.
    #[serde(default)]
    pub unadjudicated_findings: BTreeMap<String, u64>,
}

/// Where a window came from — enough to re-capture it.
///
/// There is deliberately no capture timestamp: the same range captured twice
/// should produce the same bytes, and a timestamp would make every re-capture
/// a diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub chain: Chain,
    /// The replayed event-store range, `[from, to)`.
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// How far past `to` outcomes were read (see `dataset::DatasetSpec`).
    pub lookahead_secs: u64,
    /// The flywheel label rule the verdicts were derived under.
    pub label_rule: String,
    /// The tool that captured the window, e.g. `dataset 0.1.0`.
    pub captured_by: String,
}

/// One block: the [`DetectionCtx`] in a stable, exact serial form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockRecord {
    pub number: u64,
    pub hash: B256,
    /// Every transaction hash, in block order.
    pub txs: Vec<B256>,
    /// Decoded actions, in the block order of the transactions they describe.
    /// A tx with no entry was not decoded — the context says so the same way.
    pub actions: Vec<ActionsRecord>,
    /// Sorted by address.
    pub tokens: Vec<TokenRecord>,
    /// Sorted by address.
    pub pools: Vec<PoolRecord>,
    /// Sorted by token.
    pub prices: Vec<PriceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionsRecord {
    pub hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub swaps: Vec<SwapRecord>,
    pub transfers: Vec<TransferRecord>,
    pub gas: Option<GasRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwapRecord {
    pub pool: Address,
    pub token_in: Address,
    pub token_out: Address,
    pub amount_in: U256,
    pub amount_out: U256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferRecord {
    pub token: Address,
    pub from: Address,
    pub to: Address,
    pub amount: U256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GasRecord {
    pub gas_used: u64,
    /// Decimal `u128`, as a string (see the crate docs on exactness).
    pub effective_gas_price: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRecord {
    pub address: Address,
    pub symbol: Option<String>,
    pub decimals: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolRecord {
    pub address: Address,
    pub token0: Address,
    pub token1: Address,
    pub reserve0: U256,
    pub reserve1: U256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceRecord {
    pub token: Address,
    /// Shortest round-trip decimal form of the `f64` (see the crate docs).
    pub usd: String,
}

/// Simulation's verdict on one finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adjudication {
    pub block: u64,
    /// The detector build that raised the finding live. Scoring matches on the
    /// id; the version and config hash say which build the verdict was about,
    /// so a report can tell "the same build, re-measured" from "a new build,
    /// judged against an older build's labels".
    pub detector: String,
    pub detector_version: String,
    pub config_hash: String,
    pub kind: AlertKind,
    /// The transactions the finding implicated, in the order it reported them.
    pub txs: Vec<B256>,
    pub verdict: Verdict,
}

/// What simulation decided. `Retracted` is kept distinct from `Refuted` even
/// though both score as a false positive: a finding that survived simulation
/// and was still withdrawn is a different failure to investigate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Confirmed,
    Refuted,
    Retracted,
}

impl Verdict {
    /// Whether this verdict makes the finding a true positive.
    pub fn is_confirmed(self) -> bool {
        self == Verdict::Confirmed
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Confirmed => "confirmed",
            Verdict::Refuted => "refuted",
            Verdict::Retracted => "retracted",
        }
    }
}

impl BlockRecord {
    /// The exact serial form of `ctx`. Deterministic: map-backed parts of the
    /// enrichment are sorted, and actions follow block order.
    pub fn from_ctx(ctx: &DetectionCtx) -> Self {
        let enrichment = ctx.enrichment();
        let actions = ctx
            .txs()
            .iter()
            .filter_map(|hash| enrichment.tx(*hash))
            .map(ActionsRecord::from_actions)
            .collect();

        let mut tokens: Vec<TokenRecord> = enrichment
            .tokens()
            .map(|t| TokenRecord {
                address: t.address,
                symbol: t.symbol.clone(),
                decimals: t.decimals,
            })
            .collect();
        tokens.sort_by_key(|t| t.address);

        let mut pools: Vec<PoolRecord> = enrichment
            .pools()
            .map(|p| PoolRecord {
                address: p.address,
                token0: p.token0,
                token1: p.token1,
                reserve0: p.reserve0,
                reserve1: p.reserve1,
            })
            .collect();
        pools.sort_by_key(|p| p.address);

        let mut prices: Vec<PriceRecord> = enrichment
            .prices()
            .map(|(token, usd)| PriceRecord {
                token,
                // `{:?}` on an f64 is Rust's shortest round-trip form.
                usd: format!("{:?}", usd.get()),
            })
            .collect();
        prices.sort_by_key(|p| p.token);

        Self {
            number: ctx.block().number,
            hash: ctx.block().hash,
            txs: ctx.txs().to_vec(),
            actions,
            tokens,
            pools,
            prices,
        }
    }

    /// Rebuild the context this record was taken from. Fails only on a record
    /// that [`Window::validate`] would also refuse.
    pub fn to_ctx(&self, chain: Chain) -> Result<DetectionCtx, Invalid> {
        self.check()?;
        let mut builder = Enrichment::builder();
        for t in &self.tokens {
            builder.add_token(TokenMeta::new(t.address, t.symbol.clone(), t.decimals));
        }
        for p in &self.pools {
            builder.add_pool(PoolState::new(
                p.address, p.token0, p.token1, p.reserve0, p.reserve1,
            ));
        }
        for p in &self.prices {
            builder.set_price(p.token, parse_price(self.number, p)?);
        }
        for a in &self.actions {
            builder.add_tx(a.to_actions(self.number)?);
        }
        Ok(DetectionCtx::with_enrichment(
            BlockBundle::new(
                chain,
                BlockRef::new(self.number, self.hash),
                self.txs.clone(),
            ),
            builder.build(),
        ))
    }

    /// The record's internal consistency — everything [`to_ctx`](Self::to_ctx)
    /// relies on, checked before any of it is trusted.
    fn check(&self) -> Result<(), Invalid> {
        let block = self.number;
        let mut in_block = BTreeSet::new();
        for tx in &self.txs {
            if !in_block.insert(*tx) {
                return Err(Invalid::DuplicateTx { block, tx: *tx });
            }
        }
        let mut described = BTreeSet::new();
        for a in &self.actions {
            if !in_block.contains(&a.hash) {
                return Err(Invalid::ForeignActions { block, tx: a.hash });
            }
            if !described.insert(a.hash) {
                return Err(Invalid::DuplicateTx { block, tx: a.hash });
            }
            if let Some(gas) = &a.gas {
                parse_gas_price(block, &gas.effective_gas_price)?;
            }
        }
        for p in &self.prices {
            parse_price(block, p)?;
        }
        Ok(())
    }
}

impl ActionsRecord {
    fn from_actions(tx: &TxActions) -> Self {
        Self {
            hash: tx.hash,
            from: tx.from,
            to: tx.to,
            swaps: tx
                .swaps
                .iter()
                .map(|s| SwapRecord {
                    pool: s.pool,
                    token_in: s.token_in,
                    token_out: s.token_out,
                    amount_in: s.amount_in,
                    amount_out: s.amount_out,
                })
                .collect(),
            transfers: tx
                .transfers
                .iter()
                .map(|t| TransferRecord {
                    token: t.token,
                    from: t.from,
                    to: t.to,
                    amount: t.amount,
                })
                .collect(),
            gas: tx.gas.map(|g| GasRecord {
                gas_used: g.gas_used,
                effective_gas_price: g.effective_gas_price.to_string(),
            }),
        }
    }

    fn to_actions(&self, block: u64) -> Result<TxActions, Invalid> {
        let mut tx = TxActions::new(self.hash, self.from, self.to)
            .with_swaps(
                self.swaps
                    .iter()
                    .map(|s| Swap {
                        pool: s.pool,
                        token_in: s.token_in,
                        token_out: s.token_out,
                        amount_in: s.amount_in,
                        amount_out: s.amount_out,
                    })
                    .collect(),
            )
            .with_transfers(
                self.transfers
                    .iter()
                    .map(|t| TokenTransfer {
                        token: t.token,
                        from: t.from,
                        to: t.to,
                        amount: t.amount,
                    })
                    .collect(),
            );
        if let Some(gas) = &self.gas {
            tx = tx.with_gas(TxGas {
                gas_used: gas.gas_used,
                effective_gas_price: parse_gas_price(block, &gas.effective_gas_price)?,
            });
        }
        Ok(tx)
    }
}

fn parse_price(block: u64, record: &PriceRecord) -> Result<UsdPrice, Invalid> {
    record
        .usd
        .parse::<f64>()
        .ok()
        .and_then(|v| UsdPrice::try_new(v).ok())
        .ok_or_else(|| Invalid::BadPrice {
            block,
            token: record.token,
            raw: record.usd.clone(),
        })
}

fn parse_gas_price(block: u64, raw: &str) -> Result<u128, Invalid> {
    raw.parse::<u128>().map_err(|_| Invalid::BadGasPrice {
        block,
        raw: raw.to_owned(),
    })
}

impl Window {
    /// Every structural rule a window must satisfy to be scored.
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.format_version != FORMAT_VERSION {
            return Err(Invalid::FormatVersion {
                found: self.format_version,
            });
        }
        if self.name.trim().is_empty() {
            return Err(Invalid::Unnamed);
        }
        if self.blocks.is_empty() {
            return Err(Invalid::Empty);
        }
        for pair in self.blocks.windows(2) {
            if pair[1].number != pair[0].number + 1 {
                return Err(Invalid::Gap {
                    previous: pair[0].number,
                    found: pair[1].number,
                });
            }
        }
        for block in &self.blocks {
            block.check()?;
        }
        for adj in &self.adjudications {
            let Some(block) = self.block(adj.block) else {
                return Err(Invalid::AdjudicationOutsideWindow { block: adj.block });
            };
            if adj.txs.is_empty() {
                return Err(Invalid::AdjudicationWithoutTxs { block: adj.block });
            }
            if let Some(tx) = adj.txs.iter().find(|tx| !block.txs.contains(tx)) {
                return Err(Invalid::AdjudicationForeignTx {
                    block: adj.block,
                    tx: *tx,
                });
            }
        }
        Ok(())
    }

    /// The record for block `number`, if the window covers it.
    pub fn block(&self, number: u64) -> Option<&BlockRecord> {
        let first = self.blocks.first()?.number;
        let index = usize::try_from(number.checked_sub(first)?).ok()?;
        self.blocks.get(index).filter(|b| b.number == number)
    }

    /// The window's contexts, in block order, ready to replay.
    pub fn contexts(&self) -> Result<Vec<DetectionCtx>, Invalid> {
        self.blocks
            .iter()
            .map(|b| b.to_ctx(self.provenance.chain))
            .collect()
    }

    /// The inclusive block range covered.
    pub fn block_range(&self) -> Option<(u64, u64)> {
        Some((self.blocks.first()?.number, self.blocks.last()?.number))
    }
}

mod store;

pub use store::{load, load_dir, save, Budget, Encoding};

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use chrono::TimeZone;
    use detector_api::test_util::{addr, b256, swap, transfer, CtxBuilder};

    const ETH: u128 = 1_000_000_000_000_000_000;

    fn ctx(number: u64) -> DetectionCtx {
        let mut gas_tx = TxActions::new(b256(3), addr(0x33), Some(addr(0x44)))
            .with_transfers(vec![transfer(addr(0xAA), addr(0x33), addr(0x44), 7)]);
        gas_tx = gas_tx.with_gas(TxGas {
            gas_used: 21_000,
            // Above u64::MAX: the reason gas prices are strings.
            effective_gas_price: u128::from(u64::MAX) + 12_345,
        });
        CtxBuilder::new()
            .at(Chain::ETHEREUM, BlockRef::new(number, b256(number as u8)))
            // A price with no short exact decimal form.
            .priced_token(addr(0xAA), 18, 0.1 + 0.2)
            .priced_token(addr(0xBB), 6, 1.0)
            .pool(addr(0xCC), addr(0xAA), addr(0xBB), 1_000, 2_000)
            .tx(
                b256(1),
                addr(0x11),
                vec![swap(addr(0xCC), addr(0xAA), addr(0xBB), ETH, 1_900)],
            )
            .transfer_tx(
                b256(2),
                addr(0x22),
                vec![transfer(addr(0xBB), addr(0x22), addr(0x11), 5)],
            )
            .tx_actions(gas_tx)
            .build()
    }

    pub(crate) fn window(blocks: &[u64]) -> Window {
        Window {
            format_version: FORMAT_VERSION,
            name: "test window".into(),
            provenance: Provenance {
                chain: Chain::ETHEREUM,
                from: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
                to: Utc.timestamp_opt(1_700_003_600, 0).unwrap(),
                lookahead_secs: 3_600,
                label_rule: "sim-outcome-v1".into(),
                captured_by: "test".into(),
            },
            blocks: blocks
                .iter()
                .map(|n| BlockRecord::from_ctx(&ctx(*n)))
                .collect(),
            adjudications: vec![Adjudication {
                block: blocks[0],
                detector: "sandwich".into(),
                detector_version: "1.2.0".into(),
                config_hash: "cfg".into(),
                kind: AlertKind::Sandwich,
                txs: vec![b256(1)],
                verdict: Verdict::Refuted,
            }],
            unadjudicated_findings: BTreeMap::new(),
        }
    }

    pub(crate) fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("corpus-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_context_round_trips_exactly_through_json() {
        let original = ctx(7);
        let record = BlockRecord::from_ctx(&original);
        let text = serde_json::to_string(&record).unwrap();
        let back: BlockRecord = serde_json::from_str(&text).unwrap();
        let rebuilt = back.to_ctx(Chain::ETHEREUM).unwrap();

        assert_eq!(rebuilt, original);
        // Bit-exact, not merely `==`: a price one ulp off can flip a threshold.
        let price = |c: &DetectionCtx| c.enrichment().price(addr(0xAA)).unwrap().get().to_bits();
        assert_eq!(price(&rebuilt), price(&original));
    }

    #[test]
    fn one_context_always_serialises_to_the_same_bytes() {
        // HashMap-backed enrichment iterates in a per-process random order;
        // the record must not inherit it.
        let a = serde_json::to_string(&BlockRecord::from_ctx(&ctx(7))).unwrap();
        for _ in 0..16 {
            let b = serde_json::to_string(&BlockRecord::from_ctx(&ctx(7))).unwrap();
            assert_eq!(a, b);
        }
    }

    #[test]
    fn save_then_load_returns_the_same_window() {
        let dir = scratch("roundtrip");
        let path = dir.join("w.json");
        let original = window(&[10, 11, 12]);
        save(&original, &path).unwrap();
        assert_eq!(load(&path).unwrap(), original);
        assert_eq!(original.contexts().unwrap().len(), 3);
    }

    #[test]
    fn a_gap_is_refused() {
        assert_eq!(
            window(&[10, 12]).validate(),
            Err(Invalid::Gap {
                previous: 10,
                found: 12
            })
        );
    }

    #[test]
    fn an_adjudication_must_sit_on_a_covered_block_and_its_txs() {
        let mut w = window(&[10]);
        w.adjudications[0].block = 99;
        assert_eq!(
            w.validate(),
            Err(Invalid::AdjudicationOutsideWindow { block: 99 })
        );

        let mut w = window(&[10]);
        w.adjudications[0].txs = vec![b256(0xEE)];
        assert_eq!(
            w.validate(),
            Err(Invalid::AdjudicationForeignTx {
                block: 10,
                tx: b256(0xEE)
            })
        );

        let mut w = window(&[10]);
        w.adjudications[0].txs.clear();
        assert_eq!(
            w.validate(),
            Err(Invalid::AdjudicationWithoutTxs { block: 10 })
        );
    }

    #[test]
    fn a_non_finite_price_is_refused() {
        let mut w = window(&[10]);
        w.blocks[0].prices[0].usd = "NaN".into();
        assert!(matches!(w.validate(), Err(Invalid::BadPrice { .. })));
    }

    #[test]
    fn actions_for_a_tx_outside_the_block_are_refused() {
        let mut w = window(&[10]);
        w.blocks[0].actions[0].hash = b256(0xEE);
        assert!(matches!(w.validate(), Err(Invalid::ForeignActions { .. })));
    }

    #[test]
    fn an_unknown_format_version_is_refused() {
        let mut w = window(&[10]);
        w.format_version = FORMAT_VERSION + 1;
        assert!(matches!(w.validate(), Err(Invalid::FormatVersion { .. })));
    }

    #[test]
    fn save_refuses_to_write_what_load_would_refuse() {
        let dir = scratch("save-invalid");
        let path = dir.join("w.json");
        assert!(save(&window(&[10, 12]), &path).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn load_dir_reads_windows_in_name_order_and_ignores_other_files() {
        let dir = scratch("dir");
        save(&window(&[20]), &dir.join("b.json")).unwrap();
        save(&window(&[10]), &dir.join("a.json")).unwrap();
        std::fs::write(dir.join("README.md"), "not a window").unwrap();

        let loaded = load_dir(&dir).unwrap();
        let names: Vec<_> = loaded
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_owned())
            .collect();
        assert_eq!(names, ["a.json", "b.json"]);
    }

    #[test]
    fn overlapping_windows_are_refused() {
        let dir = scratch("overlap");
        save(&window(&[10, 11]), &dir.join("a.json")).unwrap();
        save(&window(&[11, 12]), &dir.join("b.json")).unwrap();
        assert!(matches!(
            load_dir(&dir),
            Err(CorpusError::Overlap { block: 11, .. })
        ));
    }

    #[test]
    fn a_missing_directory_is_an_error_not_an_empty_corpus() {
        assert!(load_dir(std::path::Path::new("/definitely/not/a/corpus/dir")).is_err());
    }
}
