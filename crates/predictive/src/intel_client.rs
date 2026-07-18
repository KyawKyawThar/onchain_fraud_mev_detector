//! The predictive pipeline's read into intelligence's cached entity labels
//! (§16): `IntelligenceRead.GetLabels`, already cache-aside over Redis on
//! intelligence's side (`crates/intelligence/src/cache.rs`). Reuses the
//! generated `pb` client stub straight from the `intelligence` crate — the
//! same `connect_lazy` pattern `server::intelligence_client` uses — so the
//! wire contract can never drift between the two callers.
//!
//! Exposed behind [`LabelLookup`] so `predict.rs` is unit-testable against an
//! in-memory double instead of a live intelligence service.

use async_trait::async_trait;
use events::primitives::AccountAddress;
use intelligence::model::address_key;
use intelligence::pb::intelligence_read_client::IntelligenceReadClient;
use intelligence::pb::{Label, LabelsRequest};
use tonic::transport::Channel;
use tonic::Status;

/// The one lookup predict-engine needs from intelligence — an address's
/// cached active labels. Object-safe so `predict::predict` takes a `&dyn
/// LabelLookup` and doesn't care whether it's talking to a live gRPC service
/// or a test double.
#[async_trait]
pub trait LabelLookup: Send + Sync {
    async fn labels(&self, address: AccountAddress) -> Result<Vec<Label>, Status>;
}

#[derive(Clone)]
pub struct IntelligenceClient {
    inner: IntelligenceReadClient<Channel>,
}

impl IntelligenceClient {
    /// Connect to `addr` (`http://host:port`). Lazy — tonic's `Channel::connect`
    /// resolves and dials on first RPC, same "fails at first use" trade-off as
    /// `server::intelligence_client::IntelligenceClient`.
    pub fn connect_lazy(addr: String) -> anyhow::Result<Self> {
        let channel = Channel::from_shared(addr)?.connect_lazy();
        Ok(Self {
            inner: IntelligenceReadClient::new(channel),
        })
    }
}

#[async_trait]
impl LabelLookup for IntelligenceClient {
    async fn labels(&self, address: AccountAddress) -> Result<Vec<Label>, Status> {
        let mut client = self.inner.clone();
        let response = client
            .get_labels(LabelsRequest {
                address: address_key(&address),
            })
            .await?;
        Ok(response.into_inner().labels)
    }
}
