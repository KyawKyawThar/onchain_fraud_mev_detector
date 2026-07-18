//! The predict-engine (§16): scores one transaction's decoded [`TxActions`]
//! against intelligence's cached entity labels.
//!
//! **v1 heuristic**: a pending tx whose counterparty (its `from`, its `to`,
//! any decoded swap's pool, or any decoded transfer's recipient) already
//! carries the intelligence `MevBot` label is flagged as a predicted
//! `AlertKind::Sandwich` — a known sandwich bot's pending tx is a leading
//! indicator that it is positioning against this one. This is deliberately
//! the *only* heuristic today (see the crate's plan doc / §16 task scope):
//! it's what makes "cached entity labels" genuinely load-bearing rather than
//! decorative, without inventing a new `AlertKind` variant (which would
//! ripple through every exhaustive match over that closed enum across
//! `risk`/`rule-engine`/`notification`).

use alloy_primitives::B256;
use detector_api::TxActions;
use events::primitives::{AccountAddress, AlertKind, Confidence, LabelKind};
use futures_util::future::join_all;

use crate::intel_client::LabelLookup;

/// A forecast raised from one pending transaction (§16) — the pure value
/// [`predict`] returns; the caller wraps it into a `PredictedAlert` event.
#[derive(Debug, Clone, PartialEq)]
pub struct Prediction {
    pub kind: AlertKind,
    pub confidence: Confidence,
    pub addresses: Vec<AccountAddress>,
    pub tx_hash: B256,
}

/// Score `actions` against `intel`'s cached labels. `None` means "nothing to
/// forecast" — the overwhelming common case, so it must stay cheap on the
/// counterparties that don't carry a label.
///
/// Every counterparty is looked up **concurrently**, not one `.await` at a
/// time — this is the sub-block-latency-budget engine (§16, §17); serializing
/// N gRPC round trips per pending tx would defeat the point of it. `join_all`
/// preserves input order in its output, so ties still resolve to the first
/// counterparty in [`counterparties`]'s order, same as a sequential scan
/// would.
///
/// A label-lookup fault is treated as "no label" (the same cache-fallback
/// stance intelligence's own `HotCache` takes) rather than aborting the
/// whole prediction over one address.
pub async fn predict(actions: &TxActions, intel: &dyn LabelLookup) -> Option<Prediction> {
    let addresses = counterparties(actions);
    let lookups = addresses
        .iter()
        .map(|&address| async move { (address, intel.labels(address).await) });
    let results = join_all(lookups).await;

    for (address, labels) in results {
        let Ok(labels) = labels else {
            continue;
        };
        for label in labels {
            if label.kind.parse::<LabelKind>() == Ok(LabelKind::MevBot) {
                return Some(Prediction {
                    kind: AlertKind::Sandwich,
                    confidence: Confidence::new(label.confidence),
                    addresses: vec![address],
                    tx_hash: actions.hash,
                });
            }
        }
    }
    None
}

/// Every address this transaction's decoded actions touch, in the order
/// they're checked: sender, recipient, each swap's pool, each transfer's
/// recipient.
fn counterparties(actions: &TxActions) -> Vec<AccountAddress> {
    let mut addresses = vec![actions.from];
    addresses.extend(actions.to);
    addresses.extend(actions.swaps.iter().map(|swap| swap.pool));
    addresses.extend(actions.transfers.iter().map(|transfer| transfer.to));
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use async_trait::async_trait;
    use intelligence::pb::Label;
    use std::collections::HashMap;
    use tonic::Status;

    /// An in-memory [`LabelLookup`] double keyed by address, so `predict` is
    /// tested without a live intelligence service.
    #[derive(Default)]
    struct FakeLookup {
        labels: HashMap<AccountAddress, Vec<Label>>,
    }

    impl FakeLookup {
        fn with(mut self, address: AccountAddress, labels: Vec<Label>) -> Self {
            self.labels.insert(address, labels);
            self
        }
    }

    #[async_trait]
    impl LabelLookup for FakeLookup {
        async fn labels(&self, address: AccountAddress) -> Result<Vec<Label>, Status> {
            Ok(self.labels.get(&address).cloned().unwrap_or_default())
        }
    }

    fn mev_bot_label(confidence: f64) -> Label {
        Label {
            label_id: "l1".into(),
            kind: "mev_bot".into(),
            value: "known sandwich bot".into(),
            confidence,
            source: "test".into(),
            source_detail: String::new(),
            created_at_unix_millis: 0,
            valid_until_unix_millis: None,
        }
    }

    fn cex_label() -> Label {
        Label {
            label_id: "l2".into(),
            kind: "cex_wallet".into(),
            value: "binance".into(),
            confidence: 0.99,
            source: "test".into(),
            source_detail: String::new(),
            created_at_unix_millis: 0,
            valid_until_unix_millis: None,
        }
    }

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn actions(from: Address, to: Option<Address>) -> TxActions {
        TxActions::new(B256::repeat_byte(0x01), from, to)
    }

    #[tokio::test]
    async fn no_labels_predicts_nothing() {
        let intel = FakeLookup::default();
        let result = predict(&actions(addr(1), Some(addr(2))), &intel).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn non_risky_label_predicts_nothing() {
        let counterparty = addr(2);
        let intel = FakeLookup::default().with(counterparty, vec![cex_label()]);
        let result = predict(&actions(addr(1), Some(counterparty)), &intel).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn mev_bot_counterparty_predicts_a_sandwich() {
        let counterparty = addr(2);
        let intel = FakeLookup::default().with(counterparty, vec![mev_bot_label(0.77)]);
        let result = predict(&actions(addr(1), Some(counterparty)), &intel)
            .await
            .expect("expected a prediction");

        assert_eq!(result.kind, AlertKind::Sandwich);
        assert_eq!(result.confidence, Confidence::new(0.77));
        assert_eq!(result.addresses, vec![counterparty]);
    }

    #[tokio::test]
    async fn checks_every_counterparty_not_just_the_first() {
        // `from` carries no label; `to` carries the MevBot label — must still
        // be found even though it isn't the first address checked.
        let from = addr(1);
        let to = addr(2);
        let intel = FakeLookup::default()
            .with(from, vec![cex_label()])
            .with(to, vec![mev_bot_label(0.5)]);

        let result = predict(&actions(from, Some(to)), &intel).await;
        assert_eq!(result.map(|p| p.addresses), Some(vec![to]));
    }

    #[tokio::test]
    async fn a_lookup_fault_is_treated_as_no_label() {
        struct FailingLookup;
        #[async_trait]
        impl LabelLookup for FailingLookup {
            async fn labels(&self, _address: AccountAddress) -> Result<Vec<Label>, Status> {
                Err(Status::unavailable("redis down"))
            }
        }

        let result = predict(&actions(addr(1), Some(addr(2))), &FailingLookup).await;
        assert!(result.is_none());
    }
}
