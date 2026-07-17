//! Shared config-from-environment helpers — the fail-fast-at-boot read
//! discipline every service's `config.rs` follows, promoted here once the
//! third copy appeared (event-store, rule-engine, usage; the rule of three).
//!
//! Lives in `telemetry` because it is the one crate every service binary
//! already depends on and the one that established the "env access in one
//! spot" convention. Services still own *which* variables they read and what
//! they mean — only the read-and-error mechanics are shared.

use anyhow::{Context, Result};

/// Read a required env var, with the variable name in the error so a missing
/// value is self-explanatory in the boot log.
pub fn required(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing required env var {key}"))
}

/// Read an *optional* env var parsed into `T`, falling back to `default` when
/// unset. Only a present-but-unparseable value is an error — caught at boot,
/// not at first use.
pub fn parse_or<T>(key: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Ok(raw) => raw.parse().map_err(|err| {
            anyhow::anyhow!(
                "env var {key} is not a valid {}: {err}",
                std::any::type_name::<T>()
            )
        }),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env mutation is process-global; each test uses its own unique key so
    // they stay independent under the parallel test runner.

    #[test]
    fn required_names_the_missing_variable() {
        let err = required("TEST_ENV_HELPER_ABSENT").expect_err("must be missing");
        assert!(err.to_string().contains("TEST_ENV_HELPER_ABSENT"), "{err}");
    }

    #[test]
    fn parse_or_falls_back_when_unset_and_rejects_garbage() {
        assert_eq!(
            parse_or("TEST_ENV_HELPER_UNSET", 42_u32).expect("default"),
            42
        );

        std::env::set_var("TEST_ENV_HELPER_GARBAGE", "not-a-number");
        let err = parse_or("TEST_ENV_HELPER_GARBAGE", 42_u32).expect_err("must reject");
        assert!(err.to_string().contains("TEST_ENV_HELPER_GARBAGE"), "{err}");
        std::env::remove_var("TEST_ENV_HELPER_GARBAGE");
    }
}
