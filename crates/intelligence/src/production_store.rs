//! The ClickHouse block-production store (§10, §14): append-only snapshots of
//! [`BlockProductionRecord`], one row per fold of the
//! [`crate::production::ProductionBook`].
//!
//! Same stance as [`crate::adjacency`] and simulation's `incident_analytics`:
//! no updates, no deletes — a record that changes (an incident folds in, a
//! retraction subtracts, a reorg reverts) appends a *new* snapshot, and a
//! reader takes the latest per `(chain, block_hash)` by `snapshot_at` (argMax).
//! That read is exactly what the Sprint 11 t2 builder leaderboard aggregates
//! over.

use async_trait::async_trait;
use clickhouse::Client;

use crate::model::address_key;
use crate::production::BlockProductionRecord;

/// A failure appending block-production snapshots. ClickHouse faults are I/O —
/// always transient (the consumer leaves the offset and retries; every fold is
/// idempotent, so a redelivery converges).
#[derive(Debug, thiserror::Error)]
pub enum ProductionStoreError {
    #[error("clickhouse round-trip failed")]
    Clickhouse(#[from] clickhouse::error::Error),
}

impl event_bus::Transience for ProductionStoreError {
    /// Whether retrying could plausibly succeed — the shared retry/skip
    /// contract.
    fn is_transient(&self) -> bool {
        matches!(self, ProductionStoreError::Clickhouse(_))
    }
}

/// The append-only store seam. Object-safe; production is
/// [`ClickhouseProductionStore`], tests use the recording double in
/// [`crate::test_util`].
#[async_trait]
pub trait BlockProductionStore: Send + Sync {
    /// Append snapshots in fold order (immutable; a redelivered fold's
    /// identical snapshot is a harmless extra row the latest-per-block read
    /// collapses).
    async fn append(&self, snapshots: &[BlockProductionRecord])
        -> Result<(), ProductionStoreError>;
}

/// One stored snapshot row. Field order mirrors the `block_production`
/// columns; `appended_at` is intentionally absent (ClickHouse fills its
/// `DEFAULT`).
#[derive(Debug, Clone, PartialEq, clickhouse::Row, serde::Serialize, serde::Deserialize)]
pub struct ProductionRow {
    pub chain: u64,
    pub block_number: u64,
    pub block_hash: String,
    pub fee_recipient: String,
    pub extra_data: String,
    pub builder_pubkey: String,
    pub builder_label: String,
    pub relay: String,
    pub mev_extracted_usd: f64,
    pub sandwich_count: u32,
    pub arb_count: u32,
    pub other_mev_count: u32,
    pub coinbase_transfer_count: u32,
    pub coinbase_transfers: String,
    pub reverted: u8,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub snapshot_at: chrono::DateTime<chrono::Utc>,
}

impl ProductionRow {
    /// Total mapping from the domain record. Options flatten to `''` (absent
    /// relay/label), the transfers to a JSON array — a `Vec` of plain structs,
    /// so serialization cannot fail.
    pub fn from_record(record: &BlockProductionRecord) -> Self {
        Self {
            chain: record.chain.id(),
            block_number: record.block.number,
            block_hash: format!("{:#x}", record.block.hash),
            fee_recipient: address_key(&record.fee_recipient),
            extra_data: record.extra_data.clone(),
            builder_pubkey: record
                .relay
                .as_ref()
                .map(|relay| relay.builder_pubkey.clone())
                .unwrap_or_default(),
            builder_label: record.builder_label.clone().unwrap_or_default(),
            relay: record
                .relay
                .as_ref()
                .map(|relay| relay.relay.clone())
                .unwrap_or_default(),
            mev_extracted_usd: record.mev_extracted_usd,
            sandwich_count: record.sandwich_count,
            arb_count: record.arb_count,
            other_mev_count: record.other_mev_count,
            coinbase_transfer_count: record.coinbase_transfers.len() as u32,
            coinbase_transfers: serde_json::to_string(&record.coinbase_transfers)
                .expect("Vec<CoinbaseTransfer> serialization is total"),
            reverted: u8::from(record.reverted),
            snapshot_at: record.snapshot_at,
        }
    }
}

/// ClickHouse-backed [`BlockProductionStore`]. Cheap to clone (the client is
/// `Arc`-cheap).
#[derive(Clone)]
pub struct ClickhouseProductionStore {
    client: Client,
}

impl ClickhouseProductionStore {
    /// Wrap a ClickHouse client (see
    /// [`crate::adjacency::build_clickhouse_client`]).
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl BlockProductionStore for ClickhouseProductionStore {
    async fn append(
        &self,
        snapshots: &[BlockProductionRecord],
    ) -> Result<(), ProductionStoreError> {
        if snapshots.is_empty() {
            return Ok(());
        }
        let mut insert = self
            .client
            .insert::<ProductionRow>("block_production")
            .await?;
        for snapshot in snapshots {
            insert.write(&ProductionRow::from_record(snapshot)).await?;
        }
        insert.end().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, U256};
    use chrono::{DateTime, Utc};
    use events::primitives::{AccountAddress, BlockRef, Chain};

    use crate::production::{CoinbaseTransfer, OpenFacts, RelayAttribution};

    fn at() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[test]
    fn row_maps_every_field_and_flattens_options() {
        let record = BlockProductionRecord::open(
            Chain::ETHEREUM,
            BlockRef::new(19_800_000, B256::repeat_byte(0xab)),
            OpenFacts {
                fee_recipient: AccountAddress::repeat_byte(0xfe),
                extra_data: "beaverbuild.org".to_owned(),
                relay: Some(RelayAttribution {
                    relay: "flashbots".to_owned(),
                    builder_pubkey: "0x96a5".to_owned(),
                }),
                builder_label: Some("beaverbuild".to_owned()),
                coinbase_transfers: vec![CoinbaseTransfer {
                    from: AccountAddress::repeat_byte(0x01),
                    tx: B256::repeat_byte(0x02),
                    value_wei: U256::from(42u64),
                }],
            },
            at(),
        );

        let row = ProductionRow::from_record(&record);
        assert_eq!(row.chain, 1);
        assert_eq!(row.block_number, 19_800_000);
        assert_eq!(row.block_hash, format!("{:#x}", B256::repeat_byte(0xab)));
        assert_eq!(
            row.fee_recipient,
            format!("{:#x}", AccountAddress::repeat_byte(0xfe))
        );
        assert_eq!(row.extra_data, "beaverbuild.org");
        assert_eq!(row.builder_pubkey, "0x96a5");
        assert_eq!(row.builder_label, "beaverbuild");
        assert_eq!(row.relay, "flashbots");
        assert_eq!(row.coinbase_transfer_count, 1);
        assert_eq!(row.reverted, 0);
        assert_eq!(row.snapshot_at, at());
        // The transfers survive a JSON round-trip through the string column.
        let back: Vec<CoinbaseTransfer> = serde_json::from_str(&row.coinbase_transfers).unwrap();
        assert_eq!(back, record.coinbase_transfers);
    }

    #[test]
    fn absent_relay_and_label_store_as_empty_strings() {
        let record = BlockProductionRecord::open(
            Chain::ETHEREUM,
            BlockRef::new(1, B256::repeat_byte(0x01)),
            OpenFacts {
                fee_recipient: AccountAddress::repeat_byte(0xfe),
                extra_data: String::new(),
                relay: None,
                builder_label: None,
                coinbase_transfers: vec![],
            },
            at(),
        );
        let row = ProductionRow::from_record(&record);
        assert_eq!(row.builder_pubkey, "");
        assert_eq!(row.builder_label, "");
        assert_eq!(row.relay, "");
        assert_eq!(row.coinbase_transfers, "[]");
        assert_eq!(row.coinbase_transfer_count, 0);
    }
}
