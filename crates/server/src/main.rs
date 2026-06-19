//! Placeholder service entrypoint. It exists so the workspace has a runnable
//! binary and a Docker target (`--build-arg BIN=server`) from Sprint 0; the real
//! domain services (ingestion, detection, …) land in their own sprints as
//! sibling crates under `crates/`.
//!
//! What it *does* demonstrate is the standard service skeleton every later
//! service follows: initialize observability via the shared `telemetry` crate,
//! then run. The `events` dependency is wired in so the binary links the locked
//! domain schema (§2) from day one.

use anyhow::Result;

fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    // The binary owns config resolution; the telemetry lib stays env-agnostic.
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("server"))?;

    tracing::info!(schema_version = events::SCHEMA_VERSION, "server starting");

    Ok(())
}
