# Mainnet replay windows

Every `*.json` / `*.json.gz` file here is one replay window (the `corpus` crate's format):
consecutive mainnet blocks, each stored as the full `DetectionCtx` a detector
saw, plus simulation's verdict on each finding the live roster raised on those
blocks. `cargo run -p backtest` replays every file here on every PR. These
windows are the only evidence the false-positive-rate claim accepts
(`crates/backtest/src/claim.rs`).

**The directory is empty until someone captures from an archive node.**
`dataset window` reads every block through `chain-enrich` and refuses any
block below `enriched` fidelity. An empty directory means the corpus has no
field evidence yet. Do not fill it with hand-built stand-ins.

## Capturing a window

```bash
export DATASET_ARCHIVE_RPC_URL=https://…          # an archive node; the URL is a secret
dataset window \
  --from 2026-10-01T00:00:00Z --to 2026-10-01T01:00:00Z \
  --name "eth mainnet 2026-10-01 00:00 UTC, 1h" \
  --out crates/backtest/corpus/mainnet/eth-2026-10-01T00.json.gz
```

Contexts come from the archive node (`--context-source archive`, the default
for `window`). At connect, the command checks the node's chain and every
configured price feed's `description()`. A pruned full node fails with "an
archive node is required". Venues and feeds live in
`crates/chain-enrich/config/ethereum-mainnet.json` (`--enrich-config` to
override). Write `.json.gz`: it is about ten times smaller.

The command:

- replays the range from the event store;
- joins each `DetectorTriggered` to its simulation outcome under
  `sim-outcome-v1`;
- keeps only trusted bindings;
- writes every canonical block in the range.

It fails rather than writing a window with a gap, a missing block, or a block
below `enriched` fidelity.

After adding a window:

1. Run `just backtest`. Expect the baseline to move: windows add blocks and
   verdicts.
2. Run `just backtest-update-baseline` and
   `cargo run -p backtest -- --update-model-cards`.
3. Run `just backtest-accept-snapshot`.
4. Review all four diffs together.

## Rules

- **Never edit a window by hand.** A window is evidence. If one is wrong,
  re-capture it.
- **Stay within the storage budget** (`corpus::Budget::COMMITTED`): 24 MiB per
  file, 512 MiB decoded, 256 MiB for the whole directory. Past the corpus
  budget, move windows to an object store and keep their digests in git. If
  the files are ever put in Git LFS, the CI checkout needs `lfs: true`; a
  pointer file is refused with a message saying so.
- **Windows must not overlap.** The loader refuses two files that cover the
  same block, because every alert on the overlap would be scored twice.
- **Spread windows out.** The claim needs at least three windows, and a
  block-bootstrap bound that treats a burst of alerts as one event. Several
  hours from different days and market regimes are worth more than one long
  window.
- **Unadjudicated is not wrong.** An alert the current roster raises with no
  simulation verdict is excluded from the rate and reported. Simulation only
  ever ran on what the live roster flagged, so these windows measure
  precision and cannot measure recall.
