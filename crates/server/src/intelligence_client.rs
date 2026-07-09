//! Thin gRPC client wrapper around intelligence's `IntelligenceRead` service
//! (§11) — reuses the generated `pb` client stub straight from that crate
//! rather than recompiling the proto here, so the wire contract can never
//! drift between the two.

use events::primitives::AccountAddress;
use intelligence::model::address_key;
use intelligence::pb::intelligence_read_client::IntelligenceReadClient;
use intelligence::pb::{Label, LabelsRequest, RiskScoreReply, RiskScoreRequest};
use tonic::transport::Channel;
use tonic::Status;

#[derive(Clone)]
pub struct IntelligenceClient {
    inner: IntelligenceReadClient<Channel>,
}

impl IntelligenceClient {
    /// Connect to `addr` (`http://host:port`). Lazy — tonic's `Channel::connect`
    /// resolves and dials on first RPC, same "fails at first use" trade-off the
    /// rest of this service's outbound clients make.
    pub fn connect_lazy(addr: String) -> anyhow::Result<Self> {
        let channel = Channel::from_shared(addr)?.connect_lazy();
        Ok(Self {
            inner: IntelligenceReadClient::new(channel),
        })
    }

    pub async fn risk_score(&self, address: AccountAddress) -> Result<RiskScoreReply, Status> {
        let mut client = self.inner.clone();
        let response = client
            .get_risk_score(RiskScoreRequest {
                address: address_key(&address),
            })
            .await?;
        Ok(response.into_inner())
    }

    pub async fn labels(&self, address: AccountAddress) -> Result<Vec<Label>, Status> {
        let mut client = self.inner.clone();
        let response = client
            .get_labels(LabelsRequest {
                address: address_key(&address),
            })
            .await?;
        Ok(response.into_inner().labels)
    }
}
