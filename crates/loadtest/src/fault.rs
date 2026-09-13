//! Fault injection for the degraded-mode screening gates (readiness Epic D): a
//! TCP proxy placed between the API service and intelligence that adds a fixed
//! latency on command.
//!
//! **A delay line, not a slow pipe.** Each chunk read from the upstream is
//! stamped on arrival and forwarded at `arrival + delay`. The naive version —
//! read, sleep, write — serialises every response behind the previous one's
//! sleep, so under load the injected "fixed 300ms" grows without bound and the
//! run measures a saturated proxy, not a slow intelligence. The same rule as
//! the generator's due-time stamping (see [`crate::chain`]): delay relative to
//! when work *arrived*, never relative to when the previous item was handled.
//!
//! One delay applies to every connection, set at any time with
//! [`LatencyProxy::set_delay`], so a run can warm the snapshot substrate with
//! a healthy intelligence and degrade it only for the measurement window.
//! HTTP/2 multiplexes every stream onto one connection, so delaying the
//! upstream→client byte stream delays every response by the same amount.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Chunks read per direction before the reader is back-pressured by the writer.
const QUEUED_CHUNKS: usize = 1024;

pub struct LatencyProxy {
    local: SocketAddr,
    delay_micros: Arc<AtomicU64>,
    accept: JoinHandle<()>,
}

impl LatencyProxy {
    /// Listen on `listen` and forward every connection to `upstream`.
    pub async fn start(listen: SocketAddr, upstream: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding the fault proxy on {listen}"))?;
        let local = listener.local_addr()?;
        let delay_micros = Arc::new(AtomicU64::new(0));
        let accept = tokio::spawn({
            let delay_micros = delay_micros.clone();
            async move {
                loop {
                    let Ok((client, _)) = listener.accept().await else {
                        return;
                    };
                    let delay_micros = delay_micros.clone();
                    tokio::spawn(async move {
                        if let Err(err) = proxy(client, upstream, delay_micros).await {
                            tracing::debug!(error = %err, "fault proxy connection ended");
                        }
                    });
                }
            }
        });
        Ok(Self {
            local,
            delay_micros,
            accept,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The latency added to every upstream response from now on.
    pub fn set_delay(&self, delay: Duration) {
        self.delay_micros
            .store(delay.as_micros() as u64, Ordering::Relaxed);
    }
}

impl Drop for LatencyProxy {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

async fn proxy(
    client: TcpStream,
    upstream: SocketAddr,
    delay_micros: Arc<AtomicU64>,
) -> Result<()> {
    client.set_nodelay(true)?;
    let server = TcpStream::connect(upstream)
        .await
        .with_context(|| format!("connecting the fault proxy to {upstream}"))?;
    server.set_nodelay(true)?;
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();

    // Requests pass through untouched: the fault is a slow intelligence, and
    // delaying both directions would double it.
    let upstream_pump = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
        let _ = server_write.shutdown().await;
    });

    let (tx, mut rx) = mpsc::channel::<(Instant, Vec<u8>)>(QUEUED_CHUNKS);
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match server_read.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if tx.send((Instant::now(), buf[..n].to_vec())).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    while let Some((arrived, chunk)) = rx.recv().await {
        let delay = Duration::from_micros(delay_micros.load(Ordering::Relaxed));
        tokio::time::sleep_until(arrived + delay).await;
        if client_write.write_all(&chunk).await.is_err() {
            break;
        }
    }
    reader.abort();
    upstream_pump.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An upstream that echoes every byte back.
    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = socket.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    async fn round_trip(stream: &mut TcpStream) -> Duration {
        let started = std::time::Instant::now();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        started.elapsed()
    }

    #[tokio::test]
    async fn the_delay_applies_on_command_and_passes_bytes_intact() {
        let proxy = LatencyProxy::start("127.0.0.1:0".parse().unwrap(), echo_server().await)
            .await
            .unwrap();
        let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();

        assert!(round_trip(&mut stream).await < Duration::from_millis(100));
        proxy.set_delay(Duration::from_millis(200));
        let slowed = round_trip(&mut stream).await;
        assert!(
            slowed >= Duration::from_millis(200),
            "delay not applied: {slowed:?}"
        );
        proxy.set_delay(Duration::ZERO);
        assert!(round_trip(&mut stream).await < Duration::from_millis(100));
    }

    /// The delay-line property: concurrent responses each pay the delay once,
    /// rather than queueing behind each other's sleeps.
    #[tokio::test]
    async fn concurrent_traffic_is_delayed_once_not_cumulatively() {
        let proxy = LatencyProxy::start("127.0.0.1:0".parse().unwrap(), echo_server().await)
            .await
            .unwrap();
        proxy.set_delay(Duration::from_millis(150));
        let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();

        let started = std::time::Instant::now();
        for _ in 0..10 {
            stream.write_all(b"ping").await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut buf = [0u8; 40];
        stream.read_exact(&mut buf).await.unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(600),
            "ten chunks paid the delay cumulatively: {elapsed:?}"
        );
    }
}
