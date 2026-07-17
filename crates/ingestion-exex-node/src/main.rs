//! reth ExEx node binary (§5, adapter #1) — the in-node deployment of the
//! ingestion pipeline.
//!
//! This is the *thin reth glue* around the reth-agnostic bridge in
//! [`ingestion::source::exex`]. It does three things:
//!
//! 1. registers an Execution Extension on a reth Ethereum node
//!    ([`install_exex`]);
//! 2. translates each reth `ExExNotification` (committed / reverted / reorged)
//!    into the crate's reth-free [`ExExNotice`] and forwards it to the bridge;
//! 3. relays the pipeline's **durable-progress watermark** back to reth as
//!    [`ExExEvent::FinishedHeight`] so the node can prune executed blocks it no
//!    longer needs to keep for us — the ack fires only *after* a block's events
//!    are published (see [`Pipeline::report_progress_to`]), so pruning can never
//!    outrun the at-least-once audit stream.
//!
//! Everything downstream of the notice — the [`ExExSource`], the reorg-aware
//! [`BlockTree`](ingestion::tree), the [`Pipeline`], and the Kafka emission — is
//! the *same code the RPC ingestion binary runs*, so the emitted
//! `RawBlockReceived` / `BlockAssembled` / `BlockCanonicalized` / `BlockReverted`
//! lifecycle is identical.
//!
//! `trace_available` is left `false` (`ExExSource::new`): the notice reduces each
//! block to a header-only [`ChainHead`], so there are no traces to promise yet.
//! Once an execution-outcome delivery seam exists, switch to
//! `ExExSource::new(cap).advertising_traces()` — the capability follows the
//! mechanism.
//!
//! ## Version-pinned, out-of-CI
//!
//! reth's ExEx types are not yet semver-stable, and reth's transitive
//! alloy/revm pins clash with this workspace's `alloy = "1"` pin — so this crate
//! is **excluded** from the workspace (its own Cargo.lock) and is not built by
//! `cargo build --workspace` / CI. The accessor names in [`block_to_head`] and
//! the notification match arms below track the reth release pinned in
//! `Cargo.toml`; bump them together. Cross-alloy-version values (block hashes)
//! are converted through their raw 32 bytes so the two alloy majors never have
//! to be the same Rust type.

use std::sync::Arc;
use std::time::Duration;

use eyre::Result;
use futures::TryStreamExt;
use tokio::sync::mpsc;

use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::FullNodeComponents;
use reth_node_ethereum::EthereumNode;

use alloy_primitives::B256;
use events::primitives::{BlockRef, Chain};
use ingestion::pipeline::Pipeline;
use ingestion::publisher::KafkaEventSink;
use ingestion::source::exex::{run_bridge, ExExNotice, ExExSource, ExecutedBlock};
use ingestion::source::ChainHead;
use tokio_util::sync::CancellationToken;

/// Config the in-node adapter reads from the environment. A subset of the RPC
/// binary's config — no endpoint list (the node *is* the source), so we read the
/// handful of vars directly rather than through `ingestion::config` (which
/// requires `ETH_RPC_URLS`).
struct ExExConfig {
    chain: Chain,
    finalization_depth: u64,
    finalize_interval: Duration,
    kafka_brokers: String,
    /// How many recent blocks the [`ExExSource`] retains for reorg back-fill.
    buffer_capacity: usize,
}

impl ExExConfig {
    fn from_env() -> Result<Self> {
        let u64_env = |k: &str, d: u64| -> Result<u64> {
            match std::env::var(k) {
                Ok(v) => Ok(v.parse()?),
                Err(_) => Ok(d),
            }
        };
        Ok(Self {
            chain: Chain(u64_env("CHAIN_ID", 1)?),
            finalization_depth: u64_env("FINALIZATION_DEPTH", 64)?,
            finalize_interval: Duration::from_millis(u64_env("FINALIZE_INTERVAL_MS", 12_000)?),
            kafka_brokers: std::env::var("KAFKA_BROKERS")
                .map_err(|_| eyre::eyre!("missing required env var KAFKA_BROKERS"))?,
            buffer_capacity: u64_env("EXEX_BUFFER_CAPACITY", 4_096)? as usize,
        })
    }
}

fn main() -> Result<()> {
    reth::cli::Cli::parse_args().run(|builder, _| async move {
        let cfg = ExExConfig::from_env()?;
        let handle = builder
            .node(EthereumNode::default())
            .install_exex("mev-ingestion", move |ctx| {
                let cfg = cfg;
                async move { Ok(mev_ingestion_exex(ctx, cfg)) }
            })
            .launch()
            .await?;
        handle.wait_for_node_exit().await
    })
}

/// The ExEx future reth drives. Stands up the ingestion pipeline once, then
/// loops: reth notification → [`ExExNotice`] → bridge; bridge finished-ack →
/// [`ExExEvent::FinishedHeight`] → reth.
async fn mev_ingestion_exex<Node: FullNodeComponents>(
    mut ctx: ExExContext<Node>,
    cfg: ExExConfig,
) -> Result<()> {
    let shutdown = CancellationToken::new();

    // The reth-agnostic seams, shared with the RPC ingestion binary. Header-only
    // today: `ExExSource::new` wires no execution sink, so `trace_available`
    // stays false and the `executed` facts built in `notification_to_notice` are
    // dropped. When the cross-process trace store lands, swap this for
    // `ExExSource::with_execution_sink(cfg.buffer_capacity, store)` — the same
    // notice data then flows to detection and the trace flag flips on its own.
    let source = Arc::new(ExExSource::new(cfg.buffer_capacity));
    let sink = Arc::new(KafkaEventSink::new(&cfg.kafka_brokers)?);

    // notices: this loop → bridge. heads: bridge → pipeline. progress: pipeline →
    // this loop → reth (the durable-progress watermark → FinishedHeight ack).
    let (notices_tx, notices_rx) = mpsc::channel::<ExExNotice>(1024);
    let (heads_tx, heads_rx) = mpsc::channel::<ChainHead>(1024);
    let (progress_tx, mut progress_rx) = mpsc::channel::<BlockRef>(1024);

    // Pipeline: heads → reorg-aware tree → chain events on Kafka (single writer),
    // reporting each published canonical tip on the progress watermark.
    let mut pipeline = Pipeline::new(
        cfg.chain,
        source.clone(),
        sink,
        cfg.finalization_depth,
        shutdown.clone(),
    );
    pipeline.report_progress_to(progress_tx);
    let pipeline_task = tokio::spawn(pipeline.run(heads_rx, cfg.finalize_interval));

    // Bridge: notices → records source + forwards committed heads (metered).
    let bridge_task = tokio::spawn(run_bridge(
        notices_rx,
        heads_tx,
        source,
        shutdown.clone(),
    ));

    // The reth-facing loop: own `ctx` here (single owner of `ctx.events`), select
    // between incoming notifications and the pipeline's durable-progress acks.
    loop {
        tokio::select! {
            biased;
            // Ack durably-published heights so reth can prune below them. Fired by
            // the pipeline only after the height's events are on Kafka.
            progress = progress_rx.recv() => match progress {
                Some(block) => {
                    ctx.events.send(ExExEvent::FinishedHeight(to_num_hash(block)))?;
                }
                None => break, // pipeline stopped
            },
            // Translate and forward each reth notification, attaching the node's
            // current finalized head (which the notification itself doesn't carry).
            notification = ctx.notifications.try_next() => match notification? {
                Some(notification) => {
                    let finalized = finalized_head(&ctx);
                    let notice = notification_to_notice(&notification, finalized);
                    if notices_tx.send(notice).await.is_err() {
                        break; // bridge gone
                    }
                }
                None => break, // node is shutting down: no more notifications
            },
        }
    }

    shutdown.cancel();
    let _ = pipeline_task.await;
    let _ = bridge_task.await;
    Ok(())
}

/// Reduce a reth `ExExNotification` to the reth-free [`ExExNotice`] the bridge
/// consumes. Committed → the new-canonical heads (plus their post-execution facts
/// as [`ExecutedBlock`]s); reverted → the old ones (kept for back-fill, not fed to
/// the tree — see [`ExExNotice::reverted`]); `finalized` → the node's finalized
/// head, passed in from [`finalized_head`] (the notification itself doesn't carry
/// the beacon `finalized` tag).
fn notification_to_notice(
    notification: &ExExNotification,
    finalized: Option<ChainHead>,
) -> ExExNotice {
    let committed_chain = notification.committed_chain();
    let committed = committed_chain
        .as_ref()
        .map(|chain| chain_to_heads(chain))
        .unwrap_or_default();
    // The in-node extra the RPC path can't supply: each committed block's tx set,
    // for the `ExecutedBlockSink`. Only worth building when a sink is wired (see
    // the source construction in `mev_ingestion_exex`); it is dropped otherwise.
    let executed = committed_chain
        .as_ref()
        .map(|chain| chain_to_executed(chain))
        .unwrap_or_default();
    let reverted = notification
        .reverted_chain()
        .map(|chain| chain_to_heads(&chain))
        .unwrap_or_default();
    ExExNotice {
        committed,
        reverted,
        finalized,
        executed,
    }
}

/// The node's current finalized head as a [`ChainHead`], or `None` if the node
/// hasn't finalized anything yet (pre-merge history / fresh sync). Only `number`
/// and `hash` matter downstream (`finalized_head` feeds `finalize`'s `block_ref`),
/// so the other fields are left zero. The provider accessor tracks the pinned reth
/// release.
fn finalized_head<Node: FullNodeComponents>(ctx: &ExExContext<Node>) -> Option<ChainHead> {
    let num_hash = ctx.provider().finalized_block_num_hash().ok().flatten()?;
    Some(ChainHead {
        number: num_hash.number,
        hash: to_b256(num_hash.hash),
        parent_hash: B256::ZERO,
        timestamp: 0,
        tx_count: 0,
    })
}

/// Map a reth `Chain` (a contiguous run of executed blocks, ascending) to the
/// ingestion [`ChainHead`]s, ordered ascending by number.
fn chain_to_heads(chain: &reth::providers::Chain) -> Vec<ChainHead> {
    let mut heads: Vec<ChainHead> = chain.blocks_iter().map(block_to_head).collect();
    heads.sort_by_key(|h| h.number);
    heads
}

/// Map a reth `Chain` to per-block post-execution facts for the
/// [`ExecutedBlockSink`]: each block's `(ref, tx hashes in order)`. Receipts and
/// traces (from `chain.execution_outcome()`) extend `ExecutedBlock` without
/// changing this shape; the accessor names track the pinned reth release.
fn chain_to_executed(chain: &reth::providers::Chain) -> Vec<ExecutedBlock> {
    let mut executed: Vec<ExecutedBlock> = chain
        .blocks_iter()
        .map(|block| ExecutedBlock {
            block: BlockRef::new(block.header().number, to_b256(block.hash())),
            txs: block
                .body()
                .transactions
                .iter()
                .map(|tx| to_b256(tx.hash()))
                .collect(),
        })
        .collect();
    executed.sort_by_key(|e| e.block.number);
    executed
}

/// One reth sealed block → a [`ChainHead`]. The accessor names track the pinned
/// reth release; hashes cross the alloy-version boundary via their raw 32 bytes.
fn block_to_head<B>(block: &B) -> ChainHead
where
    B: reth::providers::BlockWithSenders,
{
    let header = block.header();
    ChainHead {
        number: header.number,
        hash: to_b256(block.hash()),
        parent_hash: to_b256(header.parent_hash),
        timestamp: header.timestamp,
        // Transaction count from the executed body — the `tx_count` carried onto
        // `BlockAssembled`.
        tx_count: block.body().transactions.len() as u32,
    }
}

/// Convert a reth-side 32-byte hash into the workspace `alloy_primitives::B256`
/// via raw bytes, so the two alloy majors never need to be the same type.
fn to_b256(hash: impl AsRef<[u8]>) -> B256 {
    B256::from_slice(hash.as_ref())
}

/// The workspace [`BlockRef`] → reth's `BlockNumHash` for `FinishedHeight`, again
/// through raw hash bytes.
fn to_num_hash(block: BlockRef) -> reth::primitives::BlockNumHash {
    reth::primitives::BlockNumHash {
        number: block.number,
        hash: reth::primitives::B256::from_slice(block.hash.as_slice()),
    }
}
