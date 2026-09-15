//! The simulation worker's termination grace period, derived rather than guessed.
//!
//! A job in flight at SIGTERM runs to its settle: `Worker::run` observes
//! shutdown only between jobs. So the worst case the pod must outlive is
//!
//! ```text
//!   job deadline                    resolve + simulate stop here …
//! + DEADLINE_OVERSHOOT_ALLOWANCE    … or one transaction later (checked between txs)
//! + MAX_RESULT_EVENTS × SEND_TIMEOUT  each result's first attempt still runs during a
//!                                    drain; publishing stops at the first failure
//! ```
//!
//! Usage facts are not in the budget, because the worker does not meter during a
//! drain. If the manifest's grace period is shorter than this, Kubernetes
//! SIGKILLs a worker whose job was about to settle, and the job redelivers into
//! a second full run: exactly the waste the drain exists to avoid. Scale-down makes
//! that routine rather than rare.

use std::path::Path;
use std::time::Duration;

use simulation::worker::{DEADLINE_OVERSHOOT_ALLOWANCE, DEFAULT_JOB_DEADLINE, MAX_RESULT_EVENTS};
use yaml_rust2::YamlLoader;

#[test]
fn the_worker_grace_period_covers_a_job_in_flight_at_sigterm() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/k8s/base/services/simulation.yaml");
    let raw = std::fs::read_to_string(&manifest_path).expect("reading the simulation manifest");
    let docs = YamlLoader::load_from_str(&raw).expect("parsing the simulation manifest");

    let worker = docs
        .iter()
        .find(|d| {
            d["kind"].as_str() == Some("Deployment")
                && d["metadata"]["name"].as_str() == Some("simulation-worker")
        })
        .expect("a simulation-worker Deployment");
    let pod = &worker["spec"]["template"]["spec"];

    let grace = pod["terminationGracePeriodSeconds"]
        .as_i64()
        .map(|s| Duration::from_secs(u64::try_from(s).expect("non-negative")))
        .expect("simulation-worker must set terminationGracePeriodSeconds; the default 30s cannot cover a job");

    let container = pod["containers"]
        .as_vec()
        .and_then(|cs| cs.iter().find(|c| c["name"].as_str() == Some("worker")))
        .expect("a `worker` container");
    let deadline = container["env"]
        .as_vec()
        .into_iter()
        .flatten()
        .find(|e| e["name"].as_str() == Some("SIMULATION_JOB_DEADLINE_SECS"))
        .map(|e| {
            let secs = e["value"].as_str().expect("the env value is a string");
            Duration::from_secs(
                secs.parse()
                    .expect("SIMULATION_JOB_DEADLINE_SECS is whole seconds"),
            )
        })
        .unwrap_or(DEFAULT_JOB_DEADLINE);

    let publishes = event_bus::SEND_TIMEOUT * u32::try_from(MAX_RESULT_EVENTS).unwrap();
    let budget = deadline + DEADLINE_OVERSHOOT_ALLOWANCE + publishes;

    assert!(
        grace >= budget,
        "simulation-worker's terminationGracePeriodSeconds is {grace:?}, but a job in flight at \
         SIGTERM may need {budget:?} to settle: deadline {deadline:?} + overshoot allowance \
         {DEADLINE_OVERSHOOT_ALLOWANCE:?} + {MAX_RESULT_EVENTS} result publishes x send timeout \
         {:?}. Raise the grace period or lower SIMULATION_JOB_DEADLINE_SECS.",
        event_bus::SEND_TIMEOUT,
    );
}
