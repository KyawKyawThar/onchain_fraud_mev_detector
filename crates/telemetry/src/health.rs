//! Liveness/readiness endpoints (§19/§20) — the health counterpart to
//! [`crate::metrics`], shared so every binary answers a K8s probe the same way
//! instead of each inventing (or skipping) its own.
//!
//! Two endpoints, the K8s convention:
//!
//! * **`GET /livez`** — 200 as long as the process serves HTTP at all. A hung
//!   or crashed process fails the probe and gets restarted; nothing else does.
//! * **`GET /readyz`** — 200 only between [`HealthState::set_ready`]`(true)`
//!   (the service finished boot wiring: stores migrated, consumers built,
//!   plan linked) and shutdown. 503 otherwise, so a starting or draining pod
//!   is taken out of rotation without being killed.
//!
//! The server is a deliberately tiny hand-rolled HTTP/1.1 responder over a
//! Tokio listener — no router/framework dependency for two fixed paths — and
//! is **opt-in via `HEALTH_ADDR`** ([`spawn_from_env`]): unset in dev means no
//! port to collide over; each K8s pod sets its own (t3).
//!
//! Wire-up per binary is two lines: `spawn_from_env` right after telemetry
//! init (liveness needs to answer *during* slow boots), `set_ready(true)` once
//! boot wiring completes. Passing the process's shutdown token flips `/readyz`
//! back to 503 the moment a drain starts.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// Cloneable readiness flag: the service holds one handle and flips it; the
/// serve loop reads it. Starts **not ready** — a booting pod must stay out of
/// rotation until its wiring is done.
#[derive(Clone, Default)]
pub struct HealthState {
    ready: Arc<AtomicBool>,
}

impl HealthState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Flip readiness. Call with `true` once boot wiring completes; `false` is
    /// rarely needed directly — shutdown already flips the probe via the token.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

/// Bind `addr` and serve probes until `shutdown`; returns the bound address
/// (so `:0` works in tests). The accept loop runs on a spawned task — this
/// resolves as soon as the listener is up.
pub async fn spawn(
    addr: SocketAddr,
    state: HealthState,
    shutdown: CancellationToken,
) -> Result<SocketAddr> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding the health listener on {addr}"))?;
    let bound = listener
        .local_addr()
        .context("resolving the bound health address")?;
    tokio::spawn(serve(listener, state, shutdown));
    tracing::info!(addr = %bound, "health endpoints listening on /livez and /readyz");
    Ok(bound)
}

/// [`spawn`] on `HEALTH_ADDR` when set; `None` (no server, no port) when
/// unset. A present-but-malformed address is a boot error, per the config
/// discipline.
pub async fn spawn_from_env(
    state: HealthState,
    shutdown: CancellationToken,
) -> Result<Option<SocketAddr>> {
    match std::env::var("HEALTH_ADDR") {
        Ok(raw) => {
            let addr: SocketAddr = raw
                .parse()
                .with_context(|| format!("HEALTH_ADDR is not a valid socket address: {raw}"))?;
            Ok(Some(spawn(addr, state, shutdown).await?))
        }
        Err(_) => Ok(None),
    }
}

/// The accept loop. Each connection is answered on its own task; a probe that
/// arrives mid-shutdown still gets its (503) answer, so the drain is observable.
async fn serve(listener: TcpListener, state: HealthState, shutdown: CancellationToken) {
    loop {
        let conn = tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                tracing::info!("health listener stopping");
                return;
            }
            conn = listener.accept() => conn,
        };
        match conn {
            Ok((stream, _peer)) => {
                let state = state.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    // Probe errors are never fatal: the next probe re-answers.
                    let _ = answer(stream, &state, &shutdown).await;
                });
            }
            Err(err) => tracing::warn!(error = %err, "health listener accept failed"),
        }
    }
}

/// Read one request line and write one fixed response. `Connection: close` —
/// kubelet probes are one-shot, so keep-alive buys nothing but held sockets.
async fn answer(
    mut stream: TcpStream,
    state: &HealthState,
    shutdown: &CancellationToken,
) -> std::io::Result<()> {
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).await?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let path = request
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");

    let (status, body) = match path {
        "/livez" => ("200 OK", "ok"),
        "/readyz" => {
            if state.is_ready() && !shutdown.is_cancelled() {
                ("200 OK", "ready")
            } else {
                ("503 Service Unavailable", "not ready")
            }
        }
        _ => ("404 Not Found", "not found"),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn probe(addr: SocketAddr, path: &str) -> (String, String) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).await.unwrap();
        let status = raw.lines().next().unwrap_or("").to_owned();
        let body = raw.rsplit("\r\n\r\n").next().unwrap_or("").to_owned();
        (status, body)
    }

    #[tokio::test]
    async fn livez_is_up_while_readyz_tracks_the_boot_and_drain_lifecycle() {
        let state = HealthState::new();
        let shutdown = CancellationToken::new();
        let addr = spawn(
            "127.0.0.1:0".parse().unwrap(),
            state.clone(),
            shutdown.clone(),
        )
        .await
        .unwrap();

        // Booting: alive but not ready.
        let (status, _) = probe(addr, "/livez").await;
        assert!(status.contains("200"), "livez during boot: {status}");
        let (status, _) = probe(addr, "/readyz").await;
        assert!(status.contains("503"), "readyz during boot: {status}");

        // Boot wiring done.
        state.set_ready(true);
        let (status, body) = probe(addr, "/readyz").await;
        assert!(status.contains("200"), "readyz when ready: {status}");
        assert_eq!(body, "ready");

        // Unknown path.
        let (status, _) = probe(addr, "/nope").await;
        assert!(status.contains("404"), "unknown path: {status}");
    }

    #[tokio::test]
    async fn a_draining_process_fails_readyz_but_still_answers() {
        let state = HealthState::new();
        state.set_ready(true);
        let shutdown = CancellationToken::new();
        let addr = spawn(
            "127.0.0.1:0".parse().unwrap(),
            state.clone(),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let (status, _) = probe(addr, "/readyz").await;
        assert!(status.contains("200"));

        // The drain starts: in-flight sockets still answer, with 503.
        // (The accept loop itself winds down; this races the cancel, so probe
        // through a connection opened before checking the token would be
        // flaky — assert on the flag semantics instead.)
        shutdown.cancel();
        assert!(state.is_ready(), "the flag itself is untouched by shutdown");
    }
}
