//! The mempool **source** adapter (§16): a single RPC endpoint polled for
//! pending transactions, mirroring `ingestion::source`'s hand-rolled-poller
//! shape (`ChainSource` + `run_head_poller`) but over `eth_newPendingTransactionFilter`
//! / `eth_getFilterChanges` instead of block heads.
//!
//! Deliberately a single endpoint, not a circuit-broken failover pool like
//! `ingestion::source::rpc::RpcFailoverPool` (§5 adapter #3): that pool is
//! `ChainSource`-shaped (block heads) and private to `ingestion`, and
//! duplicating its breaker/health-check machinery is more than this first
//! cut needs — a natural hardening follow-up, not a plumbing requirement.

use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::Transaction as ConsensusTransaction;
use alloy_network_primitives::TransactionResponse;
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types_eth::Transaction;
use alloy_transport::TransportError;
use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use url::Url;

/// A transaction observed in the public mempool, reduced to the fields
/// `decode::decode_tx` needs. Deliberately *not* the full RPC `Transaction` —
/// the source layer streams cheap facts, decoding happens on the caller's own
/// terms (mirrors `ingestion::source::ChainHead`'s "cheap heads" discipline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTx {
    pub hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub input: Bytes,
    pub value: U256,
}

impl From<&Transaction> for PendingTx {
    fn from(tx: &Transaction) -> Self {
        Self {
            hash: tx.tx_hash(),
            from: tx.from(),
            to: tx.to(),
            input: tx.input().clone(),
            value: tx.value(),
        }
    }
}

/// What can go wrong talking to the mempool source.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("mempool RPC call failed: {0}")]
    Transport(#[from] TransportError),
}

/// The seam the poller (below) is written against, so it's testable without a
/// live node — mirrors `ingestion::source::ChainSource`.
#[async_trait]
pub trait MempoolSource: Send + Sync {
    /// Open a new pending-transaction filter (`eth_newPendingTransactionFilter`,
    /// `full = true` so each poll returns whole transactions, not just hashes —
    /// avoiding a second `eth_getTransactionByHash` round trip per tx).
    async fn new_filter(&self) -> Result<U256, SourceError>;

    /// Drain everything queued for `filter_id` since the last call
    /// (`eth_getFilterChanges`).
    async fn filter_changes(&self, filter_id: U256) -> Result<Vec<PendingTx>, SourceError>;
}

/// The production [`MempoolSource`]: a single HTTP RPC endpoint.
pub struct RpcMempoolSource {
    provider: RootProvider,
}

impl RpcMempoolSource {
    /// Build a source over `url`. Constructing the provider does no I/O — the
    /// first poll is what actually touches the network.
    pub fn new(url: Url) -> Self {
        Self {
            provider: RootProvider::new_http(url),
        }
    }
}

#[async_trait]
impl MempoolSource for RpcMempoolSource {
    async fn new_filter(&self) -> Result<U256, SourceError> {
        Ok(self.provider.new_pending_transactions_filter(true).await?)
    }

    async fn filter_changes(&self, filter_id: U256) -> Result<Vec<PendingTx>, SourceError> {
        let txs: Vec<Transaction> = self.provider.get_filter_changes(filter_id).await?;
        Ok(txs.iter().map(PendingTx::from).collect())
    }
}

/// Poll `source` every `interval` and forward each pending transaction to
/// `tx`, in whatever order `eth_getFilterChanges` returns them. Returns when
/// `shutdown` is cancelled or `tx` is closed (the consumer went away).
///
/// The filter id is opened lazily and reopened on any poll error — a stale or
/// server-evicted filter id is the common failure mode of this RPC method
/// (mirrors `ingestion::source::head_stream::run_head_poller`'s "log and
/// retry next tick" discipline for transient fetch errors).
pub async fn run_mempool_poller(
    source: Arc<dyn MempoolSource>,
    interval: Duration,
    tx: mpsc::Sender<PendingTx>,
    shutdown: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut filter_id: Option<U256> = None;

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                tracing::info!("mempool poller shutting down");
                return;
            }
            _ = ticker.tick() => {}
        }

        let id = match filter_id {
            Some(id) => id,
            None => match source.new_filter().await {
                Ok(id) => {
                    filter_id = Some(id);
                    id
                }
                Err(err) => {
                    tracing::warn!(error = %err, "opening pending-tx filter failed; retrying next tick");
                    continue;
                }
            },
        };

        let pending = match source.filter_changes(id).await {
            Ok(pending) => pending,
            Err(err) => {
                tracing::warn!(error = %err, "polling pending-tx filter failed; reopening next tick");
                filter_id = None;
                continue;
            }
        };

        for tx_pending in pending {
            if tx.send(tx_pending).await.is_err() {
                tracing::info!("mempool consumer dropped; stopping poller");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::transaction::Recovered;
    use alloy_consensus::{Signed, TxEnvelope, TxLegacy};
    use alloy_primitives::{Signature, TxKind};

    /// A synthetic RPC transaction with deterministic, arbitrary field values —
    /// no real signature/recovery involved (`Recovered::new_unchecked` +
    /// `Signature::test_signature()`), since only the accessor mapping is under
    /// test, not signature validity.
    fn synthetic_tx(from: Address, to: Option<Address>, value: U256, input: Bytes) -> Transaction {
        let legacy = TxLegacy {
            to: to.map_or(TxKind::Create, TxKind::Call),
            value,
            input,
            ..Default::default()
        };
        let signed =
            Signed::new_unchecked(legacy, Signature::test_signature(), B256::repeat_byte(0x9));
        let envelope = TxEnvelope::Legacy(signed);
        let recovered = Recovered::new_unchecked(envelope, from);
        Transaction {
            inner: recovered,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            effective_gas_price: None,
        }
    }

    #[test]
    fn pending_tx_maps_every_field_from_the_rpc_transaction() {
        let from = Address::repeat_byte(0x11);
        let to = Address::repeat_byte(0x22);
        let value = U256::from(1_000u64);
        let input = Bytes::from_static(&[0xaa, 0xbb, 0xcc, 0xdd]);

        let rpc_tx = synthetic_tx(from, Some(to), value, input.clone());
        let pending = PendingTx::from(&rpc_tx);

        assert_eq!(pending.from, from);
        assert_eq!(pending.to, Some(to));
        assert_eq!(pending.value, value);
        assert_eq!(pending.input, input);
        assert_eq!(pending.hash, rpc_tx.tx_hash());
    }

    #[test]
    fn pending_tx_maps_contract_creation_as_no_recipient() {
        let from = Address::repeat_byte(0x33);
        let rpc_tx = synthetic_tx(from, None, U256::ZERO, Bytes::new());
        let pending = PendingTx::from(&rpc_tx);
        assert_eq!(pending.to, None);
    }
}
