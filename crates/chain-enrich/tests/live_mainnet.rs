//! The committed mainnet config against a real archive node (Epic E).
//!
//! A thin wrapper over [`chain_enrich::probe`], which is also what
//! `dataset probe-archive` and the nightly workflow run. Kept as a test so a
//! developer can check a config change without building the `dataset`
//! binary:
//!
//! ```text
//! DATASET_ARCHIVE_RPC_URL=https://… \
//!   cargo test -p chain-enrich --test live_mainnet -- --ignored --nocapture
//! ```
//!
//! On a rate-limited keyless endpoint, add `CHAIN_ENRICH_LIVE_CONCURRENCY=1`.
//! `#[ignore]`d because it needs the network and an archive node. It fails,
//! rather than skips, when the variable is unset, and it fails on an
//! inconclusive probe too: a check that learned nothing is not a pass.

use chain_enrich::{probe, AlloyArchiveRpc, EnrichConfig, ProbeOptions, Verdict};
use events::primitives::Chain;

#[tokio::test]
#[ignore = "needs the network and an archive node (DATASET_ARCHIVE_RPC_URL)"]
async fn the_committed_mainnet_config_enriches_real_archive_blocks() {
    let url = std::env::var("DATASET_ARCHIVE_RPC_URL")
        .expect("set DATASET_ARCHIVE_RPC_URL to an archive node to run this test")
        .parse()
        .expect("DATASET_ARCHIVE_RPC_URL is a URL");
    let mut config = EnrichConfig::builtin(Chain::ETHEREUM).expect("the committed config parses");
    if let Ok(n) = std::env::var("CHAIN_ENRICH_LIVE_CONCURRENCY") {
        config.concurrency = n
            .parse()
            .expect("CHAIN_ENRICH_LIVE_CONCURRENCY is a number");
    }

    let report = probe(
        AlloyArchiveRpc::new(url, AlloyArchiveRpc::DEFAULT_TIMEOUT),
        config,
        ProbeOptions::default(),
    )
    .await;
    println!("{report}");
    assert_eq!(report.verdict, Verdict::Pass, "{report}");
}
