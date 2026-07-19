//! Thin gRPC client wrapper around intelligence's `IntelligenceRead` service
//! (§11) — reuses the generated `pb` client stub straight from that crate
//! rather than recompiling the proto here, so the wire contract can never
//! drift between the two.

use api_error::ApiError;
use events::primitives::AccountAddress;
use intelligence::model::address_key;
use intelligence::pb::intelligence_read_client::IntelligenceReadClient;
use intelligence::pb::{
    BuilderLeaderboardReply, BuilderLeaderboardRequest, EntityGraphReply, EntityGraphRequest,
    EntityTimelineReply, EntityTimelineRequest, Label, LabelsRequest, RiskScoreReply,
    RiskScoreRequest,
};
use tonic::transport::Channel;
use tonic::{Code, Status};

/// Classify a failed `IntelligenceRead` call into the caller's HTTP error —
/// the gRPC seam's analogue of `db::is_permanent` and the notification
/// channels' HTTP/SMTP split: the *class* of the failure decides the status,
/// because the status is the caller's retry contract.
///
/// * Caller-addressable — intelligence rejected the request itself
///   (`InvalidArgument`/`OutOfRange`) or the named thing doesn't exist
///   (`NotFound`) → 400/404 with the detail (authored by our own service,
///   safe to return). Retrying unchanged will never help.
/// * Transient — the read path is momentarily unavailable (`Unavailable`,
///   `DeadlineExceeded`, `ResourceExhausted`, `Aborted`, `Cancelled`) →
///   502, the "try again" signal. Blanket-mapping everything here (the old
///   behavior) told callers to retry requests that could never succeed.
/// * Everything else (`Internal`, `Unknown`, `DataLoss`, ...) is a platform
///   bug → 500: detail logged, generic body, and *not* an invitation to
///   retry.
pub fn to_api_error(status: Status) -> ApiError {
    match status.code() {
        Code::NotFound => ApiError::not_found(status.message()),
        Code::InvalidArgument | Code::OutOfRange => ApiError::bad_request(status.message()),
        Code::Unavailable
        | Code::DeadlineExceeded
        | Code::ResourceExhausted
        | Code::Aborted
        | Code::Cancelled => ApiError::bad_gateway(format!("intelligence: {status}")),
        _ => ApiError::internal(format!("intelligence: {status}")),
    }
}

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

    /// The §10 builder/relay leaderboard: top builders by sandwich volume and
    /// per-relay market share by MEV type.
    pub async fn builder_leaderboard(
        &self,
        chain: u64,
        limit: u32,
        since_unix_millis: Option<i64>,
    ) -> Result<BuilderLeaderboardReply, Status> {
        let mut client = self.inner.clone();
        let response = client
            .get_builder_leaderboard(BuilderLeaderboardRequest {
                chain,
                limit,
                since_unix_millis,
            })
            .await?;
        Ok(response.into_inner())
    }

    /// The entity's degree-capped connected-address subgraph (§8.2/§11), out to
    /// `hops` levels (`0` = server default).
    pub async fn entity_graph(
        &self,
        entity_id: String,
        chain: u64,
        hops: u32,
    ) -> Result<EntityGraphReply, Status> {
        let mut client = self.inner.clone();
        let response = client
            .get_entity_graph(EntityGraphRequest {
                entity_id,
                chain,
                hops,
            })
            .await?;
        Ok(response.into_inner())
    }

    /// The entity's curated milestone timeline (§8.4/§11).
    pub async fn entity_timeline(&self, entity_id: String) -> Result<EntityTimelineReply, Status> {
        let mut client = self.inner.clone();
        let response = client
            .get_entity_timeline(EntityTimelineRequest { entity_id })
            .await?;
        Ok(response.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_codes_classify_into_the_documented_error_classes() {
        // Caller-addressable: the detail (ours) is returned, retry won't help.
        assert!(matches!(
            to_api_error(Status::not_found("entity x")),
            ApiError::NotFound(m) if m == "entity x"
        ));
        assert!(matches!(
            to_api_error(Status::invalid_argument("bad hops")),
            ApiError::BadRequest(m) if m == "bad hops"
        ));
        assert!(matches!(
            to_api_error(Status::out_of_range("cursor")),
            ApiError::BadRequest(_)
        ));

        // Transient: 502 is the retry signal.
        for status in [
            Status::unavailable("connect refused"),
            Status::deadline_exceeded("slow"),
            Status::resource_exhausted("quota"),
            Status::aborted("conflict"),
            Status::cancelled("deadline"),
        ] {
            assert!(
                matches!(to_api_error(status.clone()), ApiError::BadGateway(_)),
                "{status:?} should be transient"
            );
        }

        // Permanent platform faults: 500, never an invitation to retry.
        for status in [
            Status::internal("bug"),
            Status::unknown("??"),
            Status::data_loss("gone"),
            Status::unimplemented("nope"),
            Status::failed_precondition("state"),
        ] {
            assert!(
                matches!(to_api_error(status.clone()), ApiError::Internal(_)),
                "{status:?} should be permanent"
            );
        }
    }
}
