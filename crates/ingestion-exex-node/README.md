# ingestion-exex-node — reth ExEx in-node ingestion (§5, adapter #1)

Source adapter **#1** of §5: the ingestion pipeline embedded *inside* a
[reth](https://github.com/paradigmxyz/reth) node as an Execution Extension
(ExEx), the most-preferred (in-node, post-execution) chain source. It reuses the
workspace `ingestion` crate wholesale — the reorg-aware `BlockTree`, the
`Pipeline`, and the reth-agnostic bridge in `ingestion::source::exex` — and adds
only the thin reth glue in [`src/main.rs`](src/main.rs).

## Why it's excluded from the workspace

This crate is **not** a `[workspace.members]` entry (see the root `Cargo.toml`
`exclude`). It has its own `Cargo.lock`, and the default
`cargo build --workspace --all-features` (what CI runs) never resolves or
compiles it. Two reasons:

1. **Dependency-pin clash.** reth's crates pin their own `alloy`/`revm`
   versions, which collide with this workspace's `alloy = "1"` pin — the same
   clash that makes `simulation` defer revm's `alloydb` backend. Isolating reth
   in a separate lockfile lets the two `alloy` majors coexist; the boundary
   conversions (block hashes) go through raw 32 bytes, never by type identity.
2. **Toolchain.** reth tends to require a newer/np toolchain than the pinned
   stable in `rust-toolchain.toml`. Keeping it out of the workspace means the
   rest of the repo keeps building on the pinned toolchain.

## The contract it preserves

The bridge translates each reth `ExExNotification` into the **same** ascending
`ChainHead` stream the RPC head-poller produces, and feeds it to the **same**
`Pipeline`. So the emitted lifecycle — `RawBlockReceived`, `BlockAssembled`,
`BlockCanonicalized`, `BlockReverted` — is byte-for-byte the RPC path's. There is
one reorg implementation in the service (`ingestion::tree::BlockTree`); the ExEx
does **not** add a second.

Reorgs work because we forward only the **committed** (new-canonical) segment and
let the tree re-derive the reverts from its `parent_hash` walk; reverted blocks
are buffered in `ExExSource` only so a back-fill can find them.

### Pruning acks trail durability

reth needs `ExExEvent::FinishedHeight(N)` to prune. That ack is the pipeline's
**progress watermark** (`Pipeline::report_progress_to`), which fires a canonical
tip only *after* its events are published — so reth never prunes a block whose
`BlockAssembled` hasn't durably shipped. The glue relays the watermark to
`FinishedHeight`; the bridge itself produces no acks.

### Traces / execution outcome are opt-in, not assumed

`trace_available` is **false** by default (`ExExSource::new`, no execution sink):
the pipeline still emits from header-only `ChainHead`s, so nothing is promised.
The in-node extra — each committed block's tx set (and later receipts/traces) — is
built in `notification_to_notice` and shipped through the `ExecutedBlockSink`
port. Wire it by constructing the source with
`ExExSource::with_execution_sink(cap, store)`; `traces_available()` then becomes
exactly `store.delivers_traces()`, so the flag follows the mechanism. The
cross-process store that persists these facts and the detection-side bundle
source that reads them are the remaining piece.

### Backpressure

The head channel is bounded; on a Kafka stall the bridge **blocks** rather than
drop a head (a lost `BlockAssembled` is unrecoverable), throttling reth's ExEx
loop. The `ingestion_exex_backpressure_total` counter makes a sustained stall
alertable.

## Building & running

Pin the four `reth-*` deps in [`Cargo.toml`](Cargo.toml) to the **same release
as the node you run** (the ExEx type API is not yet semver-stable), then, from
this directory:

```bash
cd crates/ingestion-exex-node
cargo run --release -- node \
  --chain mainnet \
  --datadir /var/lib/reth
```

Configuration (env, same names as the RPC ingestion binary where they overlap):

| var | default | meaning |
|-----|---------|---------|
| `KAFKA_BROKERS` | *(required)* | bootstrap brokers for chain-event emission |
| `CHAIN_ID` | `1` | chain id / partition key on every emitted event |
| `FINALIZATION_DEPTH` | `64` | in-memory tree memory backstop (§15) |
| `FINALIZE_INTERVAL_MS` | `12000` | finality tick interval |
| `EXEX_BUFFER_CAPACITY` | `4096` | recent blocks retained for reorg back-fill |

## Finality

`BlockFinalized` is driven from the node's finalized head: on each notification
the glue reads `ctx.provider().finalized_block_num_hash()` (`finalized_head`) and
attaches it to the notice, which flows through `ExExSource::finalized_head` into
`Pipeline::tick_finalize`. reth's `ExExNotification` doesn't itself carry the
beacon `finalized` tag, hence the provider read. Before the node has finalized
anything the tag is `None` and the tree's depth backstop still bounds memory,
exactly as when the RPC source's `finalized` fetch is unavailable.

## Remaining follow-up

The `ExecutedBlockSink` port is wired producer-side (`chain_to_executed` builds
each committed block's tx set), but no store implements it yet, so the glue
constructs `ExExSource::new` (header-only, `trace_available = false`) and the
executed facts are dropped. The remaining piece is the **cross-process trace
store** (an `ExecutedBlockSink` impl that persists the facts) plus the
**detection-side bundle source** that reads it to populate `BlockBundle::txs` /
enrichment. Once the store exists, swap to `ExExSource::with_execution_sink(...)`
— no pipeline change.
