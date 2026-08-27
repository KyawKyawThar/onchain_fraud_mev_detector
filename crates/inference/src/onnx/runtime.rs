//! Bringing the ONNX Runtime library up, once per process.
//!
//! Split out of the engine because it is a different *lifetime* of concern:
//! the engine is per-model, this is per-process, and the two failure modes an
//! operator hits here (no library in the image; two models disagreeing about
//! which library) have nothing to do with any particular set of weights.
//!
//! Both of those exist because `ort` resolves its library through a
//! process-global `OnceLock` and is unhelpful at both ends of it — it
//! *panics* when the library is missing, and it *silently ignores* a second,
//! different path. See [`ensure_runtime`] and [`runtime_decision`].

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::OrtLoadKind;

/// Load the ONNX Runtime shared library, once per process.
///
/// Idempotent (`ort` keeps the handle in a `OnceLock`), so several engines in
/// one binary share it and only the first call does work. Calling this
/// explicitly — rather than letting `ort` resolve the library lazily on first
/// use — is what turns "no runtime in the image" into a typed boot error
/// instead of a panic at block time.
pub fn ensure_runtime(dylib_path: Option<&Path>) -> Result<(), OrtLoadKind> {
    let path = resolve_dylib_path(dylib_path);

    if !runtime_decision(ACTIVE_RUNTIME.get().map(PathBuf::as_path), &path)? {
        return Ok(());
    }

    ort::init_from(&path)
        .map_err(|source| OrtLoadKind::Runtime {
            path: path.clone(),
            message: source.to_string(),
        })?
        .with_name("onchain-detection-inference")
        // `false` only means another engine committed the environment first,
        // which is exactly what should happen for the second model in a binary.
        .commit();

    // Two threads can both pass the check above; the loser re-runs the same
    // comparison against whatever the winner actually installed.
    if ACTIVE_RUNTIME.set(path.clone()).is_err() {
        let active = ACTIVE_RUNTIME.get().expect("set by the winning thread");
        runtime_decision(Some(active), &path)?;
    }
    Ok(())
}

/// The library this process actually loaded. Mirrors `ort`'s own global
/// `OnceLock` so a *second* request can be compared against it — see
/// [`runtime_decision`].
static ACTIVE_RUNTIME: OnceLock<PathBuf> = OnceLock::new();

/// Where to load the runtime from: explicit config, then `ORT_DYLIB_PATH`,
/// then the platform's bare library name (resolved by the system loader).
fn resolve_dylib_path(dylib_path: Option<&Path>) -> PathBuf {
    dylib_path
        .map(Path::to_path_buf)
        .or_else(|| match std::env::var("ORT_DYLIB_PATH") {
            Ok(p) if !p.is_empty() => Some(PathBuf::from(p)),
            _ => None,
        })
        .unwrap_or_else(|| PathBuf::from(default_dylib_name()))
}

/// Given the runtime already loaded (if any) and the one being requested:
/// `Ok(true)` to load, `Ok(false)` if it is already loaded, `Err` on conflict.
///
/// This exists because of a real `ort` footgun. `ort::init_from` stores the
/// library handle in a process-global `OnceLock` and, on a second call with a
/// **different** path, quietly returns `Ok(false)` — the first library keeps
/// serving. Two models configured with different `dylib_path`s would then run
/// against a library neither of their configs names, with nothing said. That
/// is the same "config says A, reality is B" failure this crate refuses to
/// tolerate for *weights* (`expected_artifact`), so it refuses it here too.
///
/// The comparison is on the path as written. Two spellings of one file (a
/// symlink, a relative path) are reported as a conflict rather than resolved:
/// canonicalising is impossible for the bare-name case that relies on the
/// system loader's own search, and a false conflict costs one config edit
/// while a false *agreement* costs a silent mystery.
fn runtime_decision(active: Option<&Path>, requested: &Path) -> Result<bool, OrtLoadKind> {
    match active {
        None => Ok(true),
        Some(active) if active == requested => Ok(false),
        Some(active) => Err(OrtLoadKind::RuntimeConflict {
            requested: requested.to_path_buf(),
            active: active.to_path_buf(),
        }),
    }
}

/// The bare library name each platform's loader resolves against its own
/// search path — the same fallback `ort` itself uses when `ORT_DYLIB_PATH` is
/// unset.
const fn default_dylib_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "onnxruntime.dll"
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        "libonnxruntime.dylib"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "ios")))]
    {
        "libonnxruntime.so"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_model_asking_for_a_different_runtime_is_a_conflict_not_a_silent_swap() {
        // The `ort` footgun this guards: `init_from` returns Ok(false) for a
        // second, *different* path and keeps serving the first library, so
        // both models run against something neither config names.
        let err = runtime_decision(
            Some(Path::new("/opt/a/libonnxruntime.so")),
            Path::new("/opt/b/libonnxruntime.so"),
        )
        .unwrap_err();
        assert!(
            matches!(err, OrtLoadKind::RuntimeConflict { .. }),
            "{err:?}"
        );
        // The message names both, so an operator can see which config to fix.
        let message = err.to_string();
        assert!(message.contains("/opt/a/libonnxruntime.so"), "{message}");
        assert!(message.contains("/opt/b/libonnxruntime.so"), "{message}");
    }

    #[test]
    fn the_same_runtime_twice_is_a_no_op_and_the_first_load_proceeds() {
        let path = Path::new("/opt/a/libonnxruntime.so");
        assert!(
            runtime_decision(None, path).unwrap(),
            "nothing loaded yet: load it"
        );
        assert!(
            !runtime_decision(Some(path), path).unwrap(),
            "a second model with the same path must not reload"
        );
    }

    #[test]
    fn an_explicit_dylib_path_wins_over_the_environment() {
        let explicit = Path::new("/opt/explicit/libonnxruntime.so");
        assert_eq!(resolve_dylib_path(Some(explicit)), explicit);
    }

    #[test]
    fn the_default_dylib_name_is_the_platform_convention() {
        let name = default_dylib_name();
        assert!(name.starts_with("libonnxruntime") || name == "onnxruntime.dll");
    }
}
