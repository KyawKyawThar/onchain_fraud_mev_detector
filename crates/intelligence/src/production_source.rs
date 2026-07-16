//! The block-production pipeline's two effectful sources (§10): the chain
//! itself (header + full transactions, for feeRecipient / extraData graffiti /
//! coinbase transfers) and the MEV-Boost relay **data APIs** (which relay
//! delivered the block's payload, and for which builder pubkey).
//!
//! Both sit behind object-safe seams so the consumer is tested against doubles
//! ([`crate::test_util`]), the same discipline as every store seam in this
//! crate. The RPC impl is a single-endpoint `alloy` provider — the ingestion
//! service's failover pool (§5) stays where it is; this is a low-rate,
//! per-canonical-block read, not the hot head poll.
//!
//! ## Relay semantics
//!
//! A relay's `proposer_payload_delivered?block_number=N` endpoint returns the
//! bid trace when *that relay* delivered the payload the proposer signed. The
//! client asks each **configured** relay in order and takes the first whose
//! trace matches the block *hash* (same-height traces for an orphaned sibling
//! must not attribute). Relay identity comes from configuration
//! ([`RelayEndpoint::name`]) — no relay names are hardcoded (§10). A relay
//! that errors or times out is logged and skipped, never retried and never
//! fatal: relay data is best-effort public evidence, and a missing match is
//! itself a finding (`relay: None` ⇒ locally built, or an unconfigured relay).

use alloy_primitives::{B256, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types_eth::TransactionTrait;
use async_trait::async_trait;
use events::primitives::{AccountAddress, BlockRef};
use serde::Deserialize;
use url::Url;

use crate::production::{CoinbaseTransfer, RelayAttribution};

/// A failure fetching block facts. RPC faults are I/O — always transient (the
/// consumer leaves the offset and retries; a canonical block must eventually
/// be readable from the node).
#[derive(Debug, thiserror::Error)]
pub enum SourceFault {
    #[error("RPC round-trip failed: {0}")]
    Rpc(String),
}

/// One transaction, reduced to what block-production analysis needs. A
/// deliberate summary type (not the alloy RPC struct) so the coinbase-transfer
/// extraction is pure and testable without constructing signed envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSummary {
    pub hash: B256,
    pub from: AccountAddress,
    /// `None` for contract creations.
    pub to: Option<AccountAddress>,
    pub value_wei: U256,
}

/// The raw on-chain facts of one block the §10 record is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockFacts {
    /// The header's feeRecipient (coinbase) — the builder's payout address.
    pub fee_recipient: AccountAddress,
    /// The header's raw extraData bytes (sanitize with
    /// [`crate::production::sanitize_extra_data`]).
    pub extra_data: Vec<u8>,
    pub txs: Vec<TxSummary>,
}

/// Where block bodies come from. Production is [`RpcBlockFacts`]; tests use
/// the in-memory double in [`crate::test_util`].
#[async_trait]
pub trait BlockFactsSource: Send + Sync {
    /// The facts of the block with this exact hash — `None` when the node
    /// doesn't (yet) know it. Fetching by hash, not height, keeps the read
    /// reorg-safe: a record is always built from the block it names.
    async fn block_facts(&self, block: BlockRef) -> Result<Option<BlockFacts>, SourceFault>;
}

/// Pure: the direct coinbase transfers in a block — non-zero value sent
/// straight to the fee recipient by an ordinary transaction (§10's coinbase
/// tip channel). Internal transfers (via a contract) need execution traces the
/// platform doesn't ingest yet — a documented gap.
pub fn coinbase_transfers(facts: &BlockFacts) -> Vec<CoinbaseTransfer> {
    facts
        .txs
        .iter()
        .filter(|tx| tx.to == Some(facts.fee_recipient) && !tx.value_wei.is_zero())
        .map(|tx| CoinbaseTransfer {
            from: tx.from,
            tx: tx.hash,
            value_wei: tx.value_wei,
        })
        .collect()
}

/// [`BlockFactsSource`] over a single `alloy` HTTP provider.
#[derive(Debug)]
pub struct RpcBlockFacts {
    provider: RootProvider,
}

impl RpcBlockFacts {
    pub fn new(url: Url) -> Self {
        Self {
            provider: RootProvider::new_http(url),
        }
    }
}

#[async_trait]
impl BlockFactsSource for RpcBlockFacts {
    async fn block_facts(&self, block: BlockRef) -> Result<Option<BlockFacts>, SourceFault> {
        let fetched = self
            .provider
            .get_block_by_hash(block.hash)
            .full()
            .await
            .map_err(|err| SourceFault::Rpc(err.to_string()))?;
        let Some(fetched) = fetched else {
            return Ok(None);
        };

        let txs = fetched
            .transactions
            .as_transactions()
            .unwrap_or_default()
            .iter()
            .map(|tx| TxSummary {
                hash: *tx.inner.tx_hash(),
                from: tx.inner.signer(),
                to: tx.to(),
                value_wei: tx.value(),
            })
            .collect();

        Ok(Some(BlockFacts {
            fee_recipient: fetched.header.beneficiary,
            extra_data: fetched.header.extra_data.to_vec(),
            txs,
        }))
    }
}

// ── MEV-Boost relay data API ─────────────────────────────────────────────────

/// One configured relay: a display name (the identity recorded on the §10
/// record) and its data-API base URL. Comes from configuration
/// ([`crate::config`]) — the relay landscape shifts, so nothing is hardcoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEndpoint {
    pub name: String,
    pub url: Url,
}

/// Where relay attributions come from. Production is [`HttpRelaySource`];
/// tests use the in-memory double in [`crate::test_util`].
///
/// Infallible by design: a relay outage degrades to "no attribution", it never
/// stalls the pipeline (see the module docs).
#[async_trait]
pub trait RelaySource: Send + Sync {
    /// The first configured relay (in config order) whose data API reports
    /// having delivered this exact block (matched by hash), with the winning
    /// builder's pubkey.
    async fn attribution_for(&self, block: BlockRef) -> Option<RelayAttribution>;
}

/// The subset of a relay's `proposer_payload_delivered` bid trace this
/// pipeline reads. Every field arrives as a JSON string (the relay API's
/// convention for quantities); unknown fields are ignored.
#[derive(Debug, Deserialize)]
struct BidTrace {
    block_hash: String,
    builder_pubkey: String,
}

/// Pure: find the builder pubkey in a relay's `proposer_payload_delivered`
/// JSON response whose trace names exactly `block_hash`. `Err` on a malformed
/// body; `Ok(None)` when the relay didn't deliver this block.
pub fn match_bid_trace(body: &str, block_hash: B256) -> Result<Option<String>, serde_json::Error> {
    let traces: Vec<BidTrace> = serde_json::from_str(body)?;
    let wanted = format!("{block_hash:#x}");
    Ok(traces
        .into_iter()
        .find(|trace| trace.block_hash.eq_ignore_ascii_case(&wanted))
        .map(|trace| trace.builder_pubkey))
}

/// [`RelaySource`] over the public MEV-Boost relay data APIs.
#[derive(Debug)]
pub struct HttpRelaySource {
    relays: Vec<RelayEndpoint>,
    client: reqwest::Client,
}

/// Path of the delivered-payloads data-API endpoint, relative to a relay's
/// base URL (the standardized relay API, same across relays).
const PAYLOAD_DELIVERED_PATH: &str = "/relay/v1/data/bidtraces/proposer_payload_delivered";

impl HttpRelaySource {
    /// `timeout` is per relay call — a hung relay is skipped, not waited out.
    pub fn new(relays: Vec<RelayEndpoint>, timeout: std::time::Duration) -> anyhow::Result<Self> {
        Ok(Self {
            relays,
            client: reqwest::Client::builder().timeout(timeout).build()?,
        })
    }

    /// One relay's answer for one block; `None` on any failure (logged).
    async fn query_relay(&self, relay: &RelayEndpoint, block: BlockRef) -> Option<String> {
        let url = match relay.url.join(PAYLOAD_DELIVERED_PATH) {
            Ok(url) => url,
            Err(err) => {
                tracing::warn!(relay = %relay.name, error = %err, "relay URL join failed");
                return None;
            }
        };
        let response = self
            .client
            .get(url)
            .query(&[("block_number", block.number.to_string())])
            .send()
            .await;
        let body = match response {
            Ok(response) if response.status().is_success() => match response.text().await {
                Ok(body) => body,
                Err(err) => {
                    tracing::warn!(relay = %relay.name, error = %err, "relay body read failed; skipping");
                    return None;
                }
            },
            Ok(response) => {
                tracing::warn!(relay = %relay.name, status = %response.status(), "relay data API returned an error; skipping");
                return None;
            }
            Err(err) => {
                tracing::warn!(relay = %relay.name, error = %err, "relay data API unreachable; skipping");
                return None;
            }
        };
        match match_bid_trace(&body, block.hash) {
            Ok(pubkey) => pubkey,
            Err(err) => {
                tracing::warn!(relay = %relay.name, error = %err, "relay bid-trace body malformed; skipping");
                None
            }
        }
    }
}

#[async_trait]
impl RelaySource for HttpRelaySource {
    async fn attribution_for(&self, block: BlockRef) -> Option<RelayAttribution> {
        for relay in &self.relays {
            if let Some(builder_pubkey) = self.query_relay(relay, block).await {
                return Some(RelayAttribution {
                    relay: relay.name.clone(),
                    builder_pubkey,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> AccountAddress {
        AccountAddress::repeat_byte(byte)
    }

    #[test]
    fn coinbase_transfers_picks_direct_nonzero_value_to_the_fee_recipient() {
        let coinbase = addr(0xfe);
        let facts = BlockFacts {
            fee_recipient: coinbase,
            extra_data: vec![],
            txs: vec![
                // The MEV tip: direct, non-zero, to the coinbase.
                TxSummary {
                    hash: B256::repeat_byte(1),
                    from: addr(0x01),
                    to: Some(coinbase),
                    value_wei: U256::from(1_000_000u64),
                },
                // Zero-value call to the coinbase — not a transfer.
                TxSummary {
                    hash: B256::repeat_byte(2),
                    from: addr(0x02),
                    to: Some(coinbase),
                    value_wei: U256::ZERO,
                },
                // Ordinary transfer elsewhere.
                TxSummary {
                    hash: B256::repeat_byte(3),
                    from: addr(0x03),
                    to: Some(addr(0x04)),
                    value_wei: U256::from(5u64),
                },
                // Contract creation.
                TxSummary {
                    hash: B256::repeat_byte(4),
                    from: addr(0x05),
                    to: None,
                    value_wei: U256::from(5u64),
                },
            ],
        };

        let transfers = coinbase_transfers(&facts);
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].from, addr(0x01));
        assert_eq!(transfers[0].tx, B256::repeat_byte(1));
        assert_eq!(transfers[0].value_wei, U256::from(1_000_000u64));
    }

    /// A realistic `proposer_payload_delivered` response (the flashbots relay
    /// shape): quantities as strings, extra fields present.
    const BID_TRACE_FIXTURE: &str = r#"[
      {
        "slot": "9280450",
        "parent_hash": "0x8092bebc0f0a3116775c1d883e29a7e14a56f0e0b0016ec8e0685542a1a1e5cf",
        "block_hash": "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "builder_pubkey": "0x96a59d355b1a4266efb62bcd5a80c1034805e747b3ea90e603a86d5b3a76a1a56e6b28e21b0d24816cf9dfaf1cd0ceac",
        "proposer_pubkey": "0x8fb965979ae67c22e5d1d55f21b1b2d2a9b268e19c22f45b4d7de10dbd0da9d113d55d92ac30d000e8e63b3b62f01a2c",
        "proposer_fee_recipient": "0x388c818ca8b9251b393131c08a736a67ccb19297",
        "gas_limit": "30000000",
        "gas_used": "12345678",
        "value": "42000000000000000",
        "num_tx": "142",
        "block_number": "19800000"
      }
    ]"#;

    #[test]
    fn match_bid_trace_matches_the_block_hash_case_insensitively() {
        let hash = B256::repeat_byte(0xaa);
        let pubkey = match_bid_trace(BID_TRACE_FIXTURE, hash).expect("well-formed");
        assert_eq!(
            pubkey.as_deref(),
            Some("0x96a59d355b1a4266efb62bcd5a80c1034805e747b3ea90e603a86d5b3a76a1a56e6b28e21b0d24816cf9dfaf1cd0ceac")
        );
    }

    #[test]
    fn match_bid_trace_rejects_a_same_height_sibling() {
        // Same response, different hash wanted — an orphaned sibling at the
        // same height must not attribute.
        let other = B256::repeat_byte(0xbb);
        assert_eq!(match_bid_trace(BID_TRACE_FIXTURE, other).unwrap(), None);
    }

    #[test]
    fn match_bid_trace_handles_empty_and_malformed_bodies() {
        assert_eq!(
            match_bid_trace("[]", B256::repeat_byte(0xaa)).unwrap(),
            None,
            "relay that did not deliver returns an empty array"
        );
        assert!(match_bid_trace("not json", B256::repeat_byte(0xaa)).is_err());
    }
}
