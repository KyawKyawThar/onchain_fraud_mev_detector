# Runbook — load test the fast path (readiness Epic D)

**What this answers:** does §6's "preliminary alert in under one second" hold
when the pipeline is saturated, rather than when a block arrives every twelve
seconds and nothing is queued behind it?

**Why it needed a new tool.** The number was never measurable before. The only
latency series detection exported was `detector_detect_duration_seconds` — one
`detect` call, microseconds on a header-only block, and *unchanged* by a queue
building up in front of it. A dashboard built on it reads green exactly when the
claim is most likely to be false. `detection_fast_path_duration_seconds` was
added for this: `BlockAssembled.occurred_at` → the alert's publication, spanning
the broker hop and the scheduler's bounded work channel.

---

## Running it

The subject is a **running stack**, not an in-process fake. Locally:

```sh
just up                    # kafka, postgres, redis, clickhouse
just run-ingestion         # optional — the harness generates its own blocks
just run-detection-demo    # REQUIRED: see "the demo detector" below
just load-test-smoke       # ~1 min: proves the wiring
just load-test             # the real run: 30s warmup + 5 min + drain
just load-test-headroom    # the exit gate's bar: 1.5x projected peak
```

Against staging, point the same binary at it:

```sh
KAFKA_BROKERS=kafka.staging:9092 \
LOADTEST_DETECTION_METRICS_URL=http://detection-0:9100/metrics,http://detection-1:9100/metrics \
LOADTEST_API_BASE_URL=https://api.staging.example.com \
LOADTEST_API_TOKEN="$STAGING_TOKEN" \
cargo run -p loadtest --release -- \
  --profile crates/loadtest/profiles/mainnet-peak.json --headroom 1.5
```

**`LOADTEST_DETECTION_METRICS_URL` takes a comma-separated list, and in a real
deployment it must.** The SLO is stated over the whole deployment — `sum by (le)`
— and detection runs one instance per chain (§20) with several replicas each
under the HPA. Point the harness at one pod and it measures that pod and reports
it as the platform: one healthy replica will carry a struggling one to a pass.
The harness sums the replicas' histograms, which is exactly what the PromQL
does. List every pod that serves the chain under test.

## Reading the report: preconditions, then claims

The report has two gate sections and the order is the argument:

- **PRECONDITIONS** — did this run measure what it claims to have measured? The
  load arrived, the blocks that arrived came back out, the pipeline caught up,
  the API answered rather than 429'd.
- **CLAIMS** — the published budgets (§6's < 1s, the API p99).

**A claim verdict is only meaningful if every precondition held.** When one did
not, every claim is printed with `[UNSUPPORTED]` and the section carries a
warning. Those verdicts are not wrong — they are *about something else*, namely
a run that did not offer, deliver or drain the load it set out to. The exit code
already accounts for this (a failed precondition is at least inconclusive); the
marking exists because a green `fast_path_p99` line beside a failed precondition
is exactly what a skim-reader takes home.

## The exit code is the result

| code | meaning | what to do |
|------|---------|------------|
| `0` | every budget held at the offered load | record the report; it is the evidence for the Epic D exit gate |
| `1` | a budget was breached | read `queue_wait_p99` vs `processing_p99` in the report — they say *which* term grew |
| `2` | the run could not decide | **not a pass.** Fix the run and repeat; the check's text says what was missing |

Exit `2` is the code most likely to be mishandled. It fires when the generator
missed its target rate, when the pipeline never drained, when too few alerting
samples were collected, or when the histogram had no bucket boundary on the
budget. Every one of those produces a clean-looking p99 over a subset of the
work, so a CI job that treats `2` as success has re-created exactly the problem
this harness exists to solve.

## The demo detector is required, and why that is a real limitation

`demo-v0.1` is the only detector that fires on a header-only `BlockAssembled`
(the live source carries no transactions, §6), and it fires on **even block
numbers**. So the harness controls "peak alert volume" by choosing block-number
parity, and a detection build without `--features demo` produces **zero**
alerting samples — the run then reports inconclusive rather than passing on an
empty series.

This is a deliberate, visible coupling and it bounds what a green run proves:
the emit and publish path is exercised at volume, but no real detector's
analysis is. When a transaction-carrying source lands, the alerting fraction
should come from real evidence and this coupling should go.

## The API dimension needs the subject configured for it

Two things about a real stack will otherwise make the API numbers meaningless,
and both were found by running this harness rather than by reading the code:

**The screening rate limit will dominate the run.** `/v1/address/{address}/screen`
has a dedicated per-customer limit (§19, `SCREENING_RATE_LIMIT_PER_MINUTE`,
default **120/min**). The harness drives **one identity**, so a profile offering
60 screening qps presents 3600/min from a single customer and collects 429s —
which are cheap and fast, so the p99 looks superb while nothing was measured.
The `api_success_ratio` gate is what catches this (it breached on the first real
run here, at 0.324). Raise the limit on the subject for the duration of the test,
or accept that you are measuring the limiter:

```sh
SCREENING_RATE_LIMIT_PER_MINUTE=100000 ./target/release/server
```

This is not a reason to weaken the limit in production. It is the difference
between a load test of one customer's quota and a load test of the API.

**Proxied routes need their upstream.** `/v1/incidents` and `/v1/audit/incident/{id}`
proxy to event-store; with it down they answer 502 in microseconds — the same
"fast because it never worked" failure. Run event-store, or drop those routes
from the profile.

**The methods matter.** `/screen` is a POST (§11 — a screening decision is a
billable, audited event, not a cacheable read). A profile that names it without
`"method": "POST"` collects 405s. The method is part of the committed profile
for exactly this reason.

**`/screen` has its own two gates, and they read only its successes.**
`screen_p50` (§11's contractual < 100ms) and `screen_p99` (`slo.json`'s
`screen_p99_seconds`) apply to any profile whose mix drives
`/v1/address/{address}/screen`, and are judged over that route's **2xx responses
alone** — not the aggregate `api_p99`, which the cheapest route in the mix drags
toward itself, and not 429s or 502s, which answer in microseconds without being
decisions. A profile that does not screen reports no screening gate at all; one
that screens but gets no 2xx back reports them inconclusive.

Two consequences for the subject. **Degradation changes what you measure**
(`crates/server/src/degrade.rs`): with intelligence slow, an address that has a
last-known-good snapshot is answered at `SCREENING_FRESH_BUDGET_MS` as a flagged
`stale: true` 2xx, and counts — it is what the customer waited for. The driver
screens *distinct synthetic addresses* on purpose, so most have no snapshot and
ride the full `SCREENING_DEADLINE_MS`; a run that passes only because it re-screened
warm addresses has measured the fallback, not the service. To measure the fresh
path alone, run the subject with `SCREENING_STALE_MAX_AGE_SECS=0`. The share of stale decisions is reported as the `screen_stale_share` observation
whenever `LOADTEST_API_METRICS_URL` points at the API service's `/metrics`.

## Degraded mode: screening while intelligence is slow

`profiles/screening-degraded.json` measures readiness Epic D's graceful-degradation
claim instead of asserting it. `just load-test-degraded` runs it. Three things make
it a measurement rather than a staged demo:

- **The fault is on only for the measurement window.** Warmup runs against a
  healthy intelligence so the subject builds what production has when an incident
  starts: snapshots for the counterparties in play, a synced sanctions view, and
  latency history for the adaptive budget and hedging. Then `LatencyProxy` adds
  `fault.intelligence_latency_ms` (300ms) to every intelligence response. That is
  above the fresh budget ceiling and below the hard deadline, so the stale path
  and then the open breaker are what gets exercised.
- **Counterparties repeat.** `address_pool: 500` cycles a bounded set of
  addresses. With a fresh address per request no snapshot ever exists, and the run
  would measure fail-closed and nothing else; the profile refuses to load without
  a pool.
- **The verdict reads the service's own counters.** `screen_failed_closed`
  (budget `max_screen_failed_closed_share`, 1%) differences
  `screening_facts_served_total` / `screening_degraded_total` over the window, so a
  502 from an unrelated dependency is not mistaken for the degradation path. If
  *nothing* left the fresh path the gate is inconclusive, not green: the fault
  never reached the screening read.

Wiring the subject (the proxy lives in the harness process):

```sh
# the API service under test reaches intelligence through the proxy
INTELLIGENCE_GRPC_ADDR=http://127.0.0.1:50061 SCREENING_RATE_LIMIT_PER_MINUTE=100000 ./target/release/server

# the harness: proxy 50061 -> real intelligence on 50051, scraping the API's metrics
LOADTEST_API_BASE_URL=http://127.0.0.1:8080 LOADTEST_API_TOKEN=... \
LOADTEST_API_METRICS_URL=http://127.0.0.1:9112/metrics \
just load-test-degraded
```

Reading it: `screen_p50` during the fault is the breaker's number. Before it opens,
calls wait the fresh budget; once it opens, snapshots answer in about one Redis
read. A breach with a low `screen_stale_share` means the breaker never opened
(`SCREENING_BREAKER_FAILURE_THRESHOLD`, or slow calls not reaching the slow-call
threshold). A `screen_failed_closed` breach means snapshots were missing
(`screening_snapshot_lookups_total{result}` on the subject says whether they were
missing, too old, or unreadable).

## Reading a breach

The report splits the fast path into its terms:

- **`queue_wait_p99` large** — detection is the bottleneck. Blocks are sitting
  in the bounded work channel. Look at the rayon fan-out, the per-detector
  latencies, and whether the roster grew.
- **`processing_p99` large** — the work itself is slow: a detector, or the
  publish path (check `publish_resilient` retries and broker health).
- **both small, `fast_path_p99` large** — the time is outside this process:
  broker transit, consumer lag, or clock skew between the generator and
  detection. Check that both run against one clock; a cross-process wall-clock
  comparison inherits the skew between them.
- **`pipeline_drained` inconclusive** — detection never caught up. The p99
  above it describes only the blocks that kept up, and the honest reading is
  that the platform cannot sustain the offered rate at all.
- **`blocks_accounted_for` inconclusive** — blocks *reached the broker* and did
  not come back out of the fast path. This one is specifically about loss inside
  the pipeline: its denominator is what the generator actually delivered, not
  what the profile asked for, so a generator that fell short shows up on
  `chain_load_achieved` instead and never here. When this fires, the DLQ and the
  chain-id match are the right places to look.

## Changing the numbers

- **The load** lives in `crates/loadtest/profiles/*.json`, each carrying its own
  `rationale` — the report prints it, because a p99 without the load it was
  measured under is not a result.
- **The budgets** live in `crates/loadtest/slo.json`. There is deliberately
  **no `--update` flag**: unlike a backtest baseline, `fast_path_p99_seconds` is
  a published claim about the product, not a record of what the code currently
  does. A run that cannot meet it is a failing run, never a reason to write down
  a larger number.
- A latency budget must sit on a bucket boundary of
  `telemetry::metrics::LATENCY_BUCKETS_SECONDS`, or no histogram can decide it.
  That is validated when `slo.json` loads, so an unmeasurable budget fails at
  startup instead of turning every future run inconclusive.

## What a green run does not prove

The report prints these with every result; they are repeated here because they
are the boundary of the claim:

- Blocks are **header-only**. `txs_per_block` sets the declared chain tps and the
  event's size; it does not make the detectors do more work. This measures the
  pipeline at chain rate, not the per-transaction cost of a full bundle.
- The alerting share is synthetic (see above).
- The fast path excludes **ingestion's own** source→emit time. The block →
  delivered-notification budget is a different, larger claim, measured by
  `notification_alert_end_to_end_seconds`.
- The p99 is a **bucketed bound**: the verdict is "≥99% of samples at or below
  the budget", which the ladder decides exactly, and the printed figure is the
  containing bucket's upper bound — not an interpolated point estimate.
