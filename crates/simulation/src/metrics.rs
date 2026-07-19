//! Simulation worker metrics (§19, Sprint 13 t4): confirmation rate + job
//! latency.
//!
//! Two call sites, both in [`crate::worker::Worker::process`] — the one seam
//! every job passes through, mirroring `detection::metrics`'s single-call-site
//! discipline. Queue depth (`sim.jobs`/`sim.jobs.dlq`) is already covered by
//! RabbitMQ's own `/metrics/per-object` scrape (see `deploy/prometheus.yml`) —
//! nothing to duplicate here.

use std::time::Duration;

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
