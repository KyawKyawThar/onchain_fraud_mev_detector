//! [`FakeChain`] — an in-memory [`ArchiveRpc`] for tests here and downstream
//! (enable the `test-util` feature).
//!
//! Contract calls are answered from a table keyed by `(address, selector)`,
//! optionally narrowed to one state; anything unregistered returns empty bytes,
//! which is what a node says for an address with no code.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use alloy_primitives::{Address, Bytes, B256, U256};
use async_trait::async_trait;

use crate::abi;
use crate::config::EnrichConfig;
use crate::decode::{RawBlock, RawReceipt};
use crate::rpc::{ArchiveRpc, CallOutcome, RpcError, StateAt};

type CallKey = (Address, [u8; 4]);

#[derive(Default)]
pub struct FakeChain {
    chain_id: u64,
    blocks: HashMap<B256, (RawBlock, Vec<RawReceipt>)>,
    any_state: HashMap<CallKey, CallOutcome>,
    at_state: HashMap<(CallKey, StateAt), CallOutcome>,
    calls: AtomicUsize,
    failure: Mutex<Option<RpcError>>,
}

fn words(values: &[U256]) -> Bytes {
    values
        .iter()
        .flat_map(|v| v.to_be_bytes::<32>())
        .collect::<Vec<u8>>()
        .into()
}

fn string(text: &str) -> Bytes {
    let mut out = words(&[U256::from(32), U256::from(text.len())]).to_vec();
    let mut data = [0u8; 32];
    data[..text.len()].copy_from_slice(text.as_bytes());
    out.extend_from_slice(&data);
    out.into()
}

impl FakeChain {
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            ..Self::default()
        }
    }

    /// A chain whose every configured feed answers `description()` and
    /// `decimals()` (8) as `config` expects, so `Enricher::connect` passes.
    pub fn for_config(config: &EnrichConfig) -> Self {
        let mut chain = Self::new(config.chain.0);
        for feed in &config.feeds {
            chain = chain
                .answer(feed.feed, "description()", string(&feed.description))
                .answer(feed.feed, "decimals()", words(&[U256::from(8)]));
        }
        chain
    }

    #[must_use]
    pub fn block(mut self, block: RawBlock, receipts: Vec<RawReceipt>) -> Self {
        self.blocks.insert(block.hash, (block, receipts));
        self
    }

    /// Answer `signature` on `to` in every state.
    #[must_use]
    pub fn answer(mut self, to: Address, signature: &str, bytes: Bytes) -> Self {
        self.any_state
            .insert((to, abi::selector(signature)), CallOutcome::Returned(bytes));
        self
    }

    /// Answer `signature` on `to` only in `state`.
    #[must_use]
    pub fn answer_at(mut self, to: Address, signature: &str, state: StateAt, bytes: Bytes) -> Self {
        self.at_state.insert(
            ((to, abi::selector(signature)), state),
            CallOutcome::Returned(bytes),
        );
        self
    }

    #[must_use]
    pub fn revert(mut self, to: Address, signature: &str) -> Self {
        self.any_state
            .insert((to, abi::selector(signature)), CallOutcome::Reverted);
        self
    }

    /// An ERC-20 with `decimals` and `symbol`.
    #[must_use]
    pub fn token(self, token: Address, decimals: u8, symbol: &str) -> Self {
        self.answer(token, "decimals()", words(&[U256::from(decimals)]))
            .answer(token, "symbol()", string(symbol))
    }

    /// A V2 pair reporting `(token0, token1)`.
    #[must_use]
    pub fn pair(self, pool: Address, token0: Address, token1: Address) -> Self {
        self.answer(pool, "token0()", words(&[token0.into_word().into()]))
            .answer(pool, "token1()", words(&[token1.into_word().into()]))
    }

    /// The pair's reserves as of the block with hash `at`.
    #[must_use]
    pub fn reserves(self, pool: Address, at: B256, r0: u128, r1: u128) -> Self {
        self.answer_at(
            pool,
            "getReserves()",
            StateAt::Block(at),
            words(&[U256::from(r0), U256::from(r1), U256::ZERO]),
        )
    }

    /// A feed round as of the block with hash `at`; `answer` is signed.
    #[must_use]
    pub fn round(self, feed: Address, at: B256, answer: i128, updated_at: u64) -> Self {
        let answer = alloy_primitives::I256::try_from(answer)
            .expect("fits")
            .into_raw();
        self.answer_at(
            feed,
            "latestRoundData()",
            StateAt::Block(at),
            words(&[
                U256::from(1),
                answer,
                U256::from(updated_at),
                U256::from(updated_at),
                U256::from(1),
            ]),
        )
    }

    /// Fail every read from now on with `error`.
    pub fn fail_with(&self, error: RpcError) {
        *self.failure.lock().unwrap() = Some(error);
    }

    /// Contract calls made so far.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn check(&self) -> Result<(), RpcError> {
        match self.failure.lock().unwrap().clone() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

#[async_trait]
impl ArchiveRpc for FakeChain {
    async fn chain_id(&self) -> Result<u64, RpcError> {
        self.check()?;
        Ok(self.chain_id)
    }

    async fn block(&self, hash: B256) -> Result<Option<RawBlock>, RpcError> {
        self.check()?;
        Ok(self.blocks.get(&hash).map(|(b, _)| b.clone()))
    }

    async fn receipts(&self, hash: B256) -> Result<Option<Vec<RawReceipt>>, RpcError> {
        self.check()?;
        Ok(self.blocks.get(&hash).map(|(_, r)| r.clone()))
    }

    async fn call(&self, to: Address, data: Bytes, at: StateAt) -> Result<CallOutcome, RpcError> {
        self.check()?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        let selector: [u8; 4] = data
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .unwrap_or_default();
        let key = (to, selector);
        Ok(self
            .at_state
            .get(&(key, at))
            .or_else(|| self.any_state.get(&key))
            .cloned()
            .unwrap_or(CallOutcome::Returned(Bytes::new())))
    }
}
