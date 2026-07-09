//! Codegen for the `IntelligenceRead` gRPC service (§11) from
//! `proto/intelligence.proto`. Uses the vendored `protoc` binary
//! (`protoc-bin-vendored`) rather than requiring a system `protobuf-compiler`
//! package — the same self-contained-build stance the rest of the workspace
//! takes for rdkafka/rustls, so CI and the Docker build need nothing extra.

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("locate vendored protoc binary");

    // Point the prost `Config` (re-exported by `tonic_prost_build`) at the
    // vendored binary explicitly (`protoc_executable`) rather than the
    // `PROTOC` env var — setting env vars from a build script requires
    // `unsafe` on current Rust, which this workspace forbids outright
    // (`unsafe_code = "forbid"`).
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc);

    println!("cargo:rerun-if-changed=proto/intelligence.proto");
    tonic_prost_build::configure()
        .compile_with_config(config, &["proto/intelligence.proto"], &["proto"])
        .expect("compiling proto/intelligence.proto");
}
