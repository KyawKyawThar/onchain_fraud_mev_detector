//! Thin gRPC client wrapper around intelligence's `IntelligenceRead` service
//! (§11) — reuses the generated `pb` client stub straight from that crate
//! rather than recompiling the proto here, so the wire contract can never
//! drift between the two.
//!
//! This module is also the **anti-corruption seam** between the generated
//! wire types and the service's own domain: it owns `Status` → [`ApiError`]
//! ([`to_api_error`]) and `ScreeningFactsReply` → [`ScreeningInput`] (the
//! `From` impl below), so neither tonic statuses nor prost structs leak past
//! the transport edge into handler or policy code.

use std::time::Duration;

use api_error::ApiError;
use events::primitives::AccountAddress;
use intelligence::model::address_key;
use intelligence::pb::intelligence_read_client::IntelligenceReadClient;
use intelligence::pb::{
    BuilderLeaderboardReply, BuilderLeaderboardRequest, EntityGraphReply, EntityGraphRequest,
    EntityTimelineReply, EntityTimelineRequest, Label, LabelsRequest, RiskScoreReply,
    RiskScoreRequest, ScreeningFactsReply, ScreeningFactsRequest,
};
use tonic::transport::Channel;
use tonic::{Code, Request, Status};

use crate::screen::ScreeningInput;

/// Deadline on the screening RPC when none is configured
/// (`SCREENING_DEADLINE_MS`). Tight on purpose: `/screen` carries a
/// p50 < 100ms SLO (§19), so a stalled intelligence node must fail fast to
/// the endpoint's 502 — never queue the caller's withdrawal behind the
/// router-wide 30s `TimeoutLayer`.
pub const DEFAULT_SCREENING_DEADLINE: Duration = Duration::from_millis(500);

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

/// Distill the wire reply into the decision layer's input — the one place
/// `crate::screen` learns anything from a prost struct. The saturating clamp
/// lives here so the policy code can hold a plain `u8` invariant, and
/// "sanctioned" is *derived* once rather than re-computed at call sites.
impl From<&ScreeningFactsReply> for ScreeningInput {
    fn from(facts: &ScreeningFactsReply) -> Self {
        Self {
            // The wire is u32 for proto ergonomics; the domain is 0..=100.
            score: facts.score.min(100) as u8,
            sanctioned: !facts.sanctions.is_empty(),
        }
    }
}

#[derive(Clone)]
pub struct IntelligenceClient {
    inner: IntelligenceReadClient<Channel>,
    /// Client-side deadline on [`screening_facts`](Self::screening_facts) —
    /// the SLO-bearing RPC. The other reads ride the router-wide timeout.
    screening_deadline: Duration,
}

impl IntelligenceClient {
    /// Connect to `addr` (`http://host:port`). Lazy — tonic's `Channel::connect`
    /// resolves and dials on first RPC, same "fails at first use" trade-off the
    /// rest of this service's outbound clients make.
    pub fn connect_lazy(addr: String) -> anyhow::Result<Self> {
        let channel = Channel::from_shared(addr)?.connect_lazy();
        Ok(Self {
            inner: IntelligenceReadClient::new(channel),
            screening_deadline: DEFAULT_SCREENING_DEADLINE,
        })
    }

    /// Connect to `addr`, dialing **eagerly** (bounded by `dial_timeout`) so
    /// the first screening call after boot doesn't pay the connection
    /// handshake out of its latency budget. Falls back to a lazy channel with
    /// a `warn` if intelligence isn't reachable yet — warming is an
    /// optimization, never a boot-order coupling (a K8s rollout must not
    /// crash-loop this service behind intelligence).
    pub async fn connect_warm(addr: String, dial_timeout: Duration) -> anyhow::Result<Self> {
        let endpoint = Channel::from_shared(addr)?;
        let channel = match tokio::time::timeout(dial_timeout, endpoint.clone().connect()).await {
            Ok(Ok(channel)) => channel,
            Ok(Err(err)) => {
                tracing::warn!(
                    error = %err,
                    "intelligence unreachable at boot; continuing with a lazy channel"
                );
                endpoint.connect_lazy()
            }
            Err(_) => {
                tracing::warn!(
                    timeout = ?dial_timeout,
                    "dialing intelligence timed out at boot; continuing with a lazy channel"
                );
                endpoint.connect_lazy()
            }
        };
        Ok(Self {
            inner: IntelligenceReadClient::new(channel),
            screening_deadline: DEFAULT_SCREENING_DEADLINE,
        })
    }

    /// Override the screening deadline (from `SCREENING_DEADLINE_MS`).
    pub fn with_screening_deadline(mut self, deadline: Duration) -> Self {
        self.screening_deadline = deadline;
        self
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

    /// Every §11 screening-decision input for one address in a single
    /// round-trip (score, confidence, labels, sanctions matches, entity) —
    /// what `POST /v1/address/{addr}/screen` maps through the decision
    /// policy. One RPC because the caller is the one latency-critical
    /// blocking surface in the API (p50 < 100ms, §19).
    ///
    /// Deadline-bounded, belt and braces. `set_timeout` does two things:
    /// sends the `grpc-timeout` header (so the server stops working on a
    /// request whose caller has given up) *and* arms tonic's own client-side
    /// channel timeout, which surfaces as `CANCELLED: Timeout expired`. The
    /// `tokio::time::timeout` wrapper is the guarantee that doesn't depend
    /// on tonic internals, surfacing as `DEADLINE_EXCEEDED`. The two timers
    /// share one deadline, so which fires first under load is a benign race:
    /// both codes classify transient in [`to_api_error`] — the endpoint's
    /// contract either way is "fail fast and closed to a retryable 502,
    /// never hang open".
    pub async fn screening_facts(
        &self,
        address: AccountAddress,
    ) -> Result<ScreeningFactsReply, Status> {
        let mut client = self.inner.clone();
        let mut request = Request::new(ScreeningFactsRequest {
            address: address_key(&address),
        });
        request.set_timeout(self.screening_deadline);

        let response =
            tokio::time::timeout(self.screening_deadline, client.get_screening_facts(request))
                .await
                .map_err(|_elapsed| {
                    Status::deadline_exceeded(format!(
                        "screening deadline of {:?} exceeded",
                        self.screening_deadline
                    ))
                })??;
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
    use intelligence::pb::SanctionMatch;

    /// The wire→domain distillation: the u32 score clamps saturating into
    /// the domain's 0..=100, and "sanctioned" is any non-empty match list.
    #[test]
    fn screening_reply_distills_into_the_decision_input() {
        let sanctioned = ScreeningFactsReply {
            score: 150, // a buggy/newer upstream can't push the domain out of range
            sanctions: vec![SanctionMatch {
                list: "ofac_sdn".into(),
                entry: "Evil Corp".into(),
            }],
            ..Default::default()
        };
        let input = ScreeningInput::from(&sanctioned);
        assert_eq!(input.score, 100);
        assert!(input.sanctioned);

        let clean = ScreeningFactsReply {
            score: 39,
            ..Default::default()
        };
        let input = ScreeningInput::from(&clean);
        assert_eq!(input.score, 39);
        assert!(!input.sanctioned);
    }

    /// A stalled intelligence node (accepts TCP, never answers) trips the
    /// client-side screening deadline — the SLO surface fails fast to a
    /// retryable DEADLINE_EXCEEDED/502 instead of queueing behind the
    /// router-wide 30s timeout.
    #[tokio::test]
    async fn screening_deadline_fires_against_a_stalled_upstream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept and hold connections open without ever speaking HTTP/2.
        let hold = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                held.push(socket);
            }
        });

        let client = IntelligenceClient::connect_lazy(format!("http://{addr}"))
            .unwrap()
            .with_screening_deadline(Duration::from_millis(150));

        let started = std::time::Instant::now();
        let status = client
            .screening_facts(alloy_primitives::Address::ZERO)
            .await
            .expect_err("a stalled upstream must not hang the call");

        // Two timers share the one deadline (see `screening_facts`' docs):
        // ours surfaces DEADLINE_EXCEEDED, tonic's channel-internal one
        // CANCELLED — which fires first under load is a benign race, and
        // pinning one code would make this test flake on scheduler timing.
        // The contract is the *class*: a deadline-bounded, retryable fault.
        assert!(
            matches!(status.code(), Code::DeadlineExceeded | Code::Cancelled),
            "expected a deadline-class status, got {status:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the deadline, not some transport default, bounded the call"
        );
        // And the edge maps it to the transient 502, the caller's retry signal.
        assert!(matches!(to_api_error(status), ApiError::BadGateway(_)));

        hold.abort();
    }

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
