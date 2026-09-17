//! [`ArchiveRpc`] over alloy's HTTP provider — the only module that knows the
//! node's wire shapes.
//!
//! Every read runs under a per-call timeout (a half-open connection otherwise
//! hangs a capture forever) and a jittered, bounded retry for transient
//! failures only ([`resilience::Backoff`]). A revert is an answer, not a
//! failure, and is never retried; a node without historical state is named as
//! such, because "use an archive node" is the fix and "RPC error" hides it.
//!
//! The endpoint URL usually carries a provider API key, so this type's `Debug`
//! never prints it.

use std::future::{Future, IntoFuture};
use std::time::Duration;

use alloy_consensus::Transaction as _;
use alloy_network_primitives::TransactionResponse;
use alloy_primitives::{Address, Bytes, B256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types_eth::{BlockId, TransactionInput, TransactionRequest};
use alloy_transport::{TransportError, TransportErrorKind};
use async_trait::async_trait;
use resilience::{Backoff, RetryDecision};
use url::Url;

use crate::decode::{RawBlock, RawLog, RawReceipt, RawTx};
use crate::rpc::{ArchiveRpc, CallOutcome, RpcError, StateAt};

/// Messages nodes use for "I no longer have that state" (geth, erigon, reth,
/// nethermind and hosted providers, lower-cased).
const NOT_ARCHIVE: &[&str] = &[
    "missing trie node",
    "header not found",
    "state not available",
    "historical state",
    "pruned",
    "state histories haven't been fully indexed",
    "distance to target block exceeds",
];

pub struct AlloyArchiveRpc {
    provider: RootProvider,
    timeout: Duration,
    backoff: Backoff,
}

impl std::fmt::Debug for AlloyArchiveRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlloyArchiveRpc")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl AlloyArchiveRpc {
    /// Default per-call timeout. Generous: `eth_getBlockReceipts` on a busy
    /// block is a large response.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    /// A client for `url`. No I/O happens until the first read.
    pub fn new(url: Url, timeout: Duration) -> Self {
        Self {
            provider: RootProvider::new_http(url),
            timeout,
            backoff: Backoff::new(
                Duration::from_millis(250),
                Duration::from_secs(5),
                Duration::from_secs(30),
                4,
            ),
        }
    }

    /// The same client with a different retry policy.
    #[must_use]
    pub fn with_backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// Run `read` under the timeout and retry policy. A revert comes back as
    /// `Ok(None)`, so only [`ArchiveRpc::call`] has to handle it.
    async fn read<T, F, Fut>(&self, op: &'static str, read: F) -> Result<Option<T>, RpcError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, TransportError>>,
    {
        let mut attempt = 1;
        loop {
            let error = match tokio::time::timeout(self.timeout, read()).await {
                Ok(Ok(value)) => return Ok(Some(value)),
                Ok(Err(err)) => match classify(op, &err) {
                    Failure::Reverted => return Ok(None),
                    Failure::Error(e) => e,
                },
                Err(_) => RpcError::Transient {
                    op,
                    detail: format!("no answer within {:?}", self.timeout),
                },
            };
            if !error.is_transient() {
                metrics::counter!("chain_enrich_rpc_failures_total", "op" => op, "class" => "permanent")
                    .increment(1);
                return Err(error);
            }
            match self.backoff.decide(attempt, None) {
                RetryDecision::Wait(delay) => {
                    metrics::counter!("chain_enrich_rpc_retries_total", "op" => op).increment(1);
                    tracing::debug!(op, attempt, ?delay, %error, "retrying archive read");
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
                RetryDecision::GiveUp => {
                    metrics::counter!("chain_enrich_rpc_failures_total", "op" => op, "class" => "transient")
                        .increment(1);
                    return Err(error);
                }
            }
        }
    }
}

enum Failure {
    Reverted,
    Error(RpcError),
}

fn classify(op: &'static str, err: &TransportError) -> Failure {
    let detail = err.to_string();
    let error = match err {
        alloy_transport::RpcError::ErrorResp(payload) => {
            let message = payload.message.to_lowercase();
            if payload.is_retry_err() {
                RpcError::Transient { op, detail }
            } else if payload.code == 3 || message.contains("revert") {
                return Failure::Reverted;
            } else if NOT_ARCHIVE.iter().any(|m| message.contains(m)) {
                RpcError::NotArchive { op, detail }
            } else {
                RpcError::Permanent { op, detail }
            }
        }
        alloy_transport::RpcError::Transport(TransportErrorKind::HttpError(http))
            if http.status != 429 && http.status < 500 =>
        {
            // 401/403/404: a wrong key or URL, which no retry fixes.
            RpcError::Permanent { op, detail }
        }
        alloy_transport::RpcError::Transport(_) => RpcError::Transient { op, detail },
        _ => RpcError::Permanent { op, detail },
    };
    Failure::Error(error)
}

fn at(state: StateAt) -> BlockId {
    match state {
        StateAt::Block(hash) => BlockId::hash(hash),
        StateAt::Latest => BlockId::latest(),
    }
}

fn not_a_call(op: &'static str) -> RpcError {
    RpcError::Permanent {
        op,
        detail: "the node reported a revert for a read that cannot revert".into(),
    }
}

#[async_trait]
impl ArchiveRpc for AlloyArchiveRpc {
    async fn chain_id(&self) -> Result<u64, RpcError> {
        self.read("eth_chainId", || self.provider.get_chain_id())
            .await?
            .ok_or_else(|| not_a_call("eth_chainId"))
    }

    async fn block(&self, hash: B256) -> Result<Option<RawBlock>, RpcError> {
        const OP: &str = "eth_getBlockByHash";
        let block = self
            .read(OP, || {
                self.provider.get_block_by_hash(hash).full().into_future()
            })
            .await?
            .ok_or_else(|| not_a_call(OP))?;
        let Some(block) = block else {
            return Ok(None);
        };
        let txs = block
            .transactions
            .as_transactions()
            .ok_or_else(|| RpcError::Permanent {
                op: OP,
                detail: "the node returned transaction hashes, not full transactions".into(),
            })?
            .iter()
            .map(|tx| RawTx {
                hash: tx.tx_hash(),
                from: TransactionResponse::from(tx),
                to: tx.to(),
            })
            .collect();
        Ok(Some(RawBlock {
            number: block.header.number,
            hash: block.header.hash,
            parent_hash: block.header.parent_hash,
            timestamp: block.header.timestamp,
            txs,
        }))
    }

    async fn receipts(&self, hash: B256) -> Result<Option<Vec<RawReceipt>>, RpcError> {
        const OP: &str = "eth_getBlockReceipts";
        let receipts = self
            .read(OP, || {
                self.provider
                    .get_block_receipts(BlockId::hash(hash))
                    .into_future()
            })
            .await?
            .ok_or_else(|| not_a_call(OP))?;
        Ok(receipts.map(|receipts| {
            receipts
                .iter()
                .map(|r| RawReceipt {
                    tx_hash: r.transaction_hash,
                    success: r.status(),
                    gas_used: r.gas_used,
                    effective_gas_price: r.effective_gas_price,
                    logs: r
                        .logs()
                        .iter()
                        .map(|log| RawLog {
                            address: log.inner.address,
                            topics: log.inner.data.topics().to_vec(),
                            data: log.inner.data.data.clone(),
                        })
                        .collect(),
                })
                .collect()
        }))
    }

    async fn call(
        &self,
        to: Address,
        data: Bytes,
        state: StateAt,
    ) -> Result<CallOutcome, RpcError> {
        let outcome = self
            .read("eth_call", || {
                let request = TransactionRequest::default()
                    .to(to)
                    .input(TransactionInput::new(data.clone()));
                self.provider.call(request).block(at(state)).into_future()
            })
            .await?;
        Ok(match outcome {
            Some(bytes) => CallOutcome::Returned(bytes),
            None => CallOutcome::Reverted,
        })
    }
}
