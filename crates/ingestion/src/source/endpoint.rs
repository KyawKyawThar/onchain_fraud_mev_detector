//! One RPC endpoint in the failover pool: an alloy HTTP provider plus the
//! per-endpoint health state ([`CircuitBreaker`] + a wrong-chain quarantine
//! flag) the pool consults before routing a call here.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use alloy_provider::RootProvider;
use alloy_transport::TransportError;
use url::Url;

use super::circuit::{BreakerConfig, CircuitBreaker};

/// Why a single call against one endpoint failed. Surfaced so the pool can
/// report the underlying cause; the breaker recording already happened.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CallError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("timed out after {0:?}")]
    Timeout(Duration),
}

/// A single upstream RPC node. `provider` is cheap to clone (an `Arc` inside),
/// so the pool hands a clone to each in-flight call rather than borrowing.
#[derive(Debug)]
pub struct RpcEndpoint {
    url: Url,
    provider: RootProvider,
    breaker: CircuitBreaker,
    /// Set when a health probe finds this endpoint on the *wrong* chain. Unlike
    /// the breaker (transient), this is sticky: a wrong-network endpoint is a
    /// config error, never routed until a probe clears it.
    ///
    /// `Relaxed` is sufficient: this flag guards no other shared memory, so
    /// there is no happens-before relationship to establish — only the flag's
    /// own most-recent value matters.
    quarantined: AtomicBool,
}

impl RpcEndpoint {
    /// Build an endpoint over HTTP. Constructing the provider does no I/O — the
    /// first request (or a health probe) is what actually touches the network.
    pub fn new(url: Url, breaker: BreakerConfig) -> Self {
        let provider = RootProvider::new_http(url.clone());
        Self {
            url,
            provider,
            breaker: CircuitBreaker::new(breaker),
            quarantined: AtomicBool::new(false),
        }
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Whether the pool may route a call here right now: not quarantined and the
    /// breaker admits it (which may flip open→half-open if the cooldown elapsed).
    pub fn is_routable(&self, now: Instant) -> bool {
        !self.is_quarantined() && self.breaker.allows(now)
    }

    /// Run one RPC against this endpoint under `timeout`, recording the outcome
    /// against the breaker. **The single place** the call-result → health policy
    /// lives, so the pool's traffic path and the active health probe can never
    /// drift apart. A timeout is treated as a failure (a hung endpoint must fail
    /// over, not stall).
    pub(crate) async fn guarded<T, Fut>(
        &self,
        timeout: Duration,
        call: impl FnOnce(RootProvider) -> Fut,
    ) -> Result<T, CallError>
    where
        Fut: Future<Output = Result<T, TransportError>>,
    {
        match tokio::time::timeout(timeout, call(self.provider.clone())).await {
            Ok(Ok(value)) => {
                self.breaker.on_success();
                Ok(value)
            }
            Ok(Err(err)) => {
                self.breaker.on_failure(Instant::now());
                Err(CallError::Transport(err))
            }
            Err(_elapsed) => {
                self.breaker.on_failure(Instant::now());
                Err(CallError::Timeout(timeout))
            }
        }
    }

    /// Mark the endpoint as serving the wrong chain (sticky until cleared).
    pub fn quarantine(&self) {
        self.quarantined.store(true, Ordering::Relaxed);
    }

    /// Clear the wrong-chain quarantine (a later probe found the right chain).
    pub fn clear_quarantine(&self) {
        self.quarantined.store(false, Ordering::Relaxed);
    }

    pub fn is_quarantined(&self) -> bool {
        self.quarantined.load(Ordering::Relaxed)
    }
}
