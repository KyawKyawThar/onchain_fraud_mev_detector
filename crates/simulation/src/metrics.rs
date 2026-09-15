//! Simulation worker metrics (§19, Sprint 13 t4): confirmation rate + job
//! latency.
//!
//! Two call sites, both in [`crate::worker::Worker::process`] — the one seam
//! every job passes through, mirroring `detection::metrics`'s single-call-site
//! discipline. Queue depth (`sim.jobs`/`sim.jobs.dlq`) is already covered by
//! RabbitMQ's own `/metrics/per-object` scrape (see `deploy/prometheus.yml`) —
//! nothing to duplicate here. What the broker cannot know is how much of that
//! depth one replica absorbs, so the worker publishes it
//! ([`SIMULATION_WORKER_JOB_CAPACITY`]).

use std::time::Duration;

/// Gauge: jobs one worker replica holds at once — `SIMULATION_WORKERS` ×
/// `RABBITMQ_PREFETCH`, the backpressure bound the deployment declares (§6).
///
/// The autoscaler's unit. `simulation:sim_jobs_replicas_demanded` in
/// `deploy/prometheus-rules.yml` divides the queue's ready + unacked count by
/// it, so retuning either knob moves the scaling point with it; a literal in
/// the HPA would be a second copy of this policy, stale the moment either
/// knob changes.
pub const SIMULATION_WORKER_JOB_CAPACITY: &str = "simulation_worker_job_capacity";

/// Counter: every job that finished simulating, labeled `outcome`
/// (`confirmed`/`unconfirmed`). Confirmation rate is derived in PromQL as
/// `confirmed / (confirmed + unconfirmed)`, not stored — the same convention
/// as detection's hit-rate (a ratio from two monotonic counters survives
/// restarts and re-aggregates across replicas).
pub const SIMULATION_JOBS_TOTAL: &str = "simulation_jobs_total";
/// Histogram: one `Worker::process` call's wall-clock latency, regardless of
/// how it resolved (resolve failure, orphan-cancelled, simulate failure, or a
/// completed run) — a resolver hanging or revm running long are both latency
/// this dashboard should surface.
pub const SIMULATION_JOB_DURATION_SECONDS: &str = "simulation_job_duration_seconds";

/// Record one completed simulation's confirm/retract outcome. Only called for
/// jobs that actually ran revm to completion — a resolve/simulate failure or
/// an orphan-cancelled job isn't a confirmation-rate sample.
pub fn record_job_outcome(confirmed: bool) {
    let outcome = if confirmed {
        "confirmed"
    } else {
        "unconfirmed"
    };
    metrics::counter!(SIMULATION_JOBS_TOTAL, "outcome" => outcome).increment(1);
}

/// Record one `process()` call's total wall-clock duration.
pub fn record_job_duration(elapsed: Duration) {
    metrics::histogram!(SIMULATION_JOB_DURATION_SECONDS).record(elapsed.as_secs_f64());
}

/// Publish this replica's job capacity. Called once at boot, before any consumer
/// connects: a replica that holds jobs without reporting its capacity would count
/// toward the backlog and never toward the capacity absorbing it.
pub fn record_job_capacity(capacity: crate::config::JobCapacity) {
    metrics::gauge!(SIMULATION_WORKER_JOB_CAPACITY).set(capacity.jobs() as f64);
}

/// Counter: `SimulationJob` publishes the broker refused because `sim.jobs` is at
/// its length bound (`x-overflow: reject-publish`). The dispatcher leaves each
/// alert on Kafka and retries it, so nothing is lost. A sustained rate means the
/// backlog has moved into Kafka lag because the worker pool cannot grow further.
pub const SIMULATION_DISPATCH_REJECTED_TOTAL: &str = "simulation_dispatch_rejected_total";

/// Counter: jobs that ran past `SIMULATION_JOB_DEADLINE_SECS`, labeled `stage`
/// (`resolve`/`simulate`). A count that should be zero: each is work thrown away
/// and requeued.
pub const SIMULATION_JOBS_DEADLINE_EXCEEDED_TOTAL: &str = "simulation_jobs_deadline_exceeded_total";

/// Histogram: how far past its deadline a simulation was when it stopped. The
/// deadline is checked between transactions, so this is one transaction's worst
/// case. It is the measured side of `worker::DEADLINE_OVERSHOOT_ALLOWANCE`, the
/// term the pod's grace-period budget assumes.
pub const SIMULATION_DEADLINE_OVERSHOOT_SECONDS: telemetry::metrics::DurationMetric =
    telemetry::metrics::DurationMetric::latency("simulation_job_deadline_overshoot_seconds");

/// The dispatcher found `sim.jobs` at its bound.
pub fn record_dispatch_rejected() {
    metrics::counter!(SIMULATION_DISPATCH_REJECTED_TOTAL).increment(1);
}

/// A job ran past its deadline at `stage`, by `overshoot` (zero for `resolve`,
/// which is cancelled exactly at the deadline).
pub fn record_deadline_exceeded(stage: &'static str, overshoot: Duration) {
    metrics::counter!(SIMULATION_JOBS_DEADLINE_EXCEEDED_TOTAL, "stage" => stage).increment(1);
    if stage == "simulate" {
        telemetry::metrics::record_duration(
            SIMULATION_DEADLINE_OVERSHOOT_SECONDS,
            overshoot.as_secs_f64(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::CompositeKey;

    type Series = Vec<(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )>;

    fn captured(f: impl FnOnce()) -> Series {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, f);
        snapshotter.snapshot().into_vec()
    }

    fn counter(series: &Series, name: &str, label_value: &str) -> Option<u64> {
        series.iter().find_map(|(ck, _, _, v)| {
            if ck.key().name() != name {
                return None;
            }
            let matches = ck.key().labels().any(|l| l.value() == label_value);
            if !matches {
                return None;
            }
            match v {
                DebugValue::Counter(n) => Some(*n),
                _ => None,
            }
        })
    }

    #[test]
    fn a_confirmed_job_increments_the_confirmed_series_only() {
        let series = captured(|| record_job_outcome(true));
        assert_eq!(
            counter(&series, SIMULATION_JOBS_TOTAL, "confirmed"),
            Some(1)
        );
        assert_eq!(counter(&series, SIMULATION_JOBS_TOTAL, "unconfirmed"), None);
    }

    #[test]
    fn an_unconfirmed_job_increments_the_unconfirmed_series_only() {
        let series = captured(|| record_job_outcome(false));
        assert_eq!(counter(&series, SIMULATION_JOBS_TOTAL, "confirmed"), None);
        assert_eq!(
            counter(&series, SIMULATION_JOBS_TOTAL, "unconfirmed"),
            Some(1)
        );
    }

    #[test]
    fn job_capacity_is_workers_times_prefetch() {
        let series =
            captured(|| record_job_capacity(crate::config::JobCapacity::try_new(4, 16).unwrap()));
        match series
            .iter()
            .find(|(ck, ..)| ck.key().name() == SIMULATION_WORKER_JOB_CAPACITY)
        {
            Some((_, _, _, DebugValue::Gauge(v))) => assert_eq!(v.into_inner(), 64.0),
            other => panic!("expected a gauge, got {other:?}"),
        }
    }

    #[test]
    fn a_deadline_overrun_is_counted_by_stage() {
        let series = captured(|| {
            record_deadline_exceeded("simulate", Duration::from_millis(7));
            record_deadline_exceeded("resolve", Duration::ZERO);
        });
        assert_eq!(
            counter(&series, SIMULATION_JOBS_DEADLINE_EXCEEDED_TOTAL, "simulate"),
            Some(1)
        );
        assert_eq!(
            counter(&series, SIMULATION_JOBS_DEADLINE_EXCEEDED_TOTAL, "resolve"),
            Some(1)
        );
    }

    #[test]
    fn job_duration_records_one_sample() {
        let series = captured(|| record_job_duration(Duration::from_millis(42)));
        match series
            .iter()
            .find(|(ck, ..)| ck.key().name() == SIMULATION_JOB_DURATION_SECONDS)
        {
            Some((_, _, _, DebugValue::Histogram(samples))) => assert_eq!(samples.len(), 1),
            other => panic!("expected a histogram, got {other:?}"),
        }
    }
}
