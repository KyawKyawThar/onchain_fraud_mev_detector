//! Live-broker integration tests for the worker pool's per-job ack/redelivery/
//! dead-letter semantics (§7), against a *real* RabbitMQ via testcontainers. Marked
//! `#[ignore]` so the default `cargo test` stays hermetic; `just test-integration`
//! (nextest `--run-ignored all`) runs them.
//!
//! These prove what the in-memory `worker.rs` unit tests can't — that the broker
//! actually honours the disposition the worker chose: that an **acked** job leaves
//! the queue, that a job whose worker **dies mid-run** (the source is dropped before
//! ack) is **redelivered**, and that a **poison** job is **dead-lettered** onto
//! `sim.jobs.dlq` instead of looping. This is the Sprint 5 t3 deliverable.

use std::sync::Arc;
use std::time::Duration;

use lapin::options::BasicGetOptions;
use lapin::{Channel, Connection, ConnectionProperties};

use events::primitives::{AlertId, AlertKind, Chain, Confidence, DetectorRef};

use simulation::command::{job_for_alert, Priority, SimulationJob};
use simulation::config::RabbitConfig;
use simulation::consumer::{JobSource, RabbitJobSource};
use simulation::queue::{JobSink, RabbitJobSink};
use simulation::reorg::NeverOrphaned;
use simulation::resolver::{JobResolver, UnresolvedJobResolver};
use simulation::simulator::{MinProfit, RevmSimulator, Simulator};
use simulation::test_util::{test_pool, EmptyScenarioResolver, RecordingEventSink};
use simulation::topology::declare_sim_topology;
use simulation::worker::{Disposition, Worker};

use tokio_util::sync::CancellationToken;

use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::rabbitmq::RabbitMq;

// ── Test harness ─────────────────────────────────────────────────

async fn start_rabbit() -> (ContainerAsync<RabbitMq>, String) {
    let node = RabbitMq::default()
        .start()
        .await
        .expect("starting RabbitMQ container");
    let url = format!(
        "amqp://{}:{}",
        node.get_host().await.expect("container host"),
        node.get_host_port_ipv4(5672)
            .await
            .expect("container amqp port"),
    );
    (node, url)
}

async fn open_channel(url: &str) -> (Connection, Channel) {
    let connection = Connection::connect(url, ConnectionProperties::default())
        .await
        .expect("connecting to RabbitMQ");
    let channel = connection
        .create_channel()
        .await
        .expect("opening a channel");
    (connection, channel)
}

fn test_config(url: &str) -> RabbitConfig {
    RabbitConfig {
        url: url.to_owned(),
        queue: "sim.jobs".into(),
        dlx: "sim.jobs.dlx".into(),
        dead_letter_queue: "sim.jobs.dlq".into(),
        // Low limit so the redelivery-loop backstop is cheap to reason about.
        delivery_limit: 3,
    }
}

fn a_job() -> SimulationJob {
    let alert = events::detection::PreliminaryAlertCreated {
        alert_id: AlertId::new(),
        detector: DetectorRef {
            id: "sandwich".into(),
            version: "1.2.0".into(),
            config_hash: "deadbeef".into(),
        },
        addresses: vec![],
        kind: AlertKind::Sandwich,
        confidence: Confidence::new(0.7),
        provisional: true,
    };
    job_for_alert(Chain::ETHEREUM, &alert).0
}

/// How many messages are ready on a queue right now (drains them in the process).
async fn drain_count(channel: &Channel, queue: &str) -> usize {
    let mut count = 0;
    while channel
        .basic_get(queue, BasicGetOptions { no_ack: true })
        .await
        .expect("basic_get")
        .is_some()
    {
        count += 1;
    }
    count
}

// ── Worker collaborators (queue mechanics under test, not revm) ───
//
// The doubles (`EmptyScenarioResolver`, `RecordingEventSink`, `test_pool`) live in
// `simulation::test_util` so the in-crate unit tests and this integration crate share
// one set. We're exercising the *queue* path (ack/redelivery/DLX) with the real revm
// engine over an empty bundle, not the EVM itself.

fn worker(
    resolver: Arc<dyn JobResolver>,
    simulator: Arc<dyn Simulator>,
    events: Arc<RecordingEventSink>,
) -> Worker {
    Worker::new(
        resolver,
        Arc::new(NeverOrphaned),
        simulator,
        test_pool(),
        events,
        CancellationToken::new(),
    )
}

// ── Tests ────────────────────────────────────────────────────────

/// The happy path: a worker pulls the job off `sim.jobs`, runs the (real) engine,
/// publishes the result, and **acks** — so the queue is empty afterward.
#[tokio::test]
#[ignore = "requires Docker; run via `just test-integration`"]
async fn a_worker_runs_a_job_and_acks_it_off_the_queue() {
    let (_node, url) = start_rabbit().await;
    let cfg = test_config(&url);
    declare_sim_topology(&url, &cfg)
        .await
        .expect("declare topology");

    // Queue one job through the production publish sink.
    let sink = RabbitJobSink::connect(&url, cfg.queue.clone())
        .await
        .expect("connect sink");
    let job = a_job();
    sink.publish(&job).await.expect("publish job");

    // Drain it with the worker seam: recv → process → settle (ack).
    let events = Arc::new(RecordingEventSink::default());
    let w = worker(
        Arc::new(EmptyScenarioResolver),
        Arc::new(RevmSimulator::new(MinProfit::try_new(1.0).unwrap())),
        events.clone(),
    );
    let mut source = RabbitJobSource::connect(&url, &cfg.queue, 8)
        .await
        .expect("connect source");
    let delivery = source.recv().await.expect("a job is delivered");
    assert_eq!(delivery.job.alert_id, job.alert_id);

    let disposition = w.process(&delivery.job).await;
    assert_eq!(
        disposition,
        Disposition::Ack,
        "an empty-bundle job is acked"
    );
    delivery.settle(Disposition::Ack).await.expect("ack");

    // The result (SimulationCompleted; not confirmed at a 1 ETH bar) was published
    // — filtering out the `SimulationRun` usage fact (§13) that rides the same
    // sink alongside it (see `RecordingSink::non_usage_events`).
    assert_eq!(events.non_usage_events().len(), 1);

    // Drop the consumer so its prefetch can't hold the (already-acked) message, then
    // confirm the queue is empty.
    drop(source);
    let (_conn, channel) = open_channel(&url).await;
    assert_eq!(
        drain_count(&channel, &cfg.queue).await,
        0,
        "an acked job leaves the queue"
    );
}

/// A worker that dies mid-run — the source is dropped before the job is acked —
/// leaves the job unacked, so the broker **redelivers** it to the next consumer.
#[tokio::test]
#[ignore = "requires Docker; run via `just test-integration`"]
async fn an_unacked_job_is_redelivered_after_the_worker_dies() {
    let (_node, url) = start_rabbit().await;
    let cfg = test_config(&url);
    declare_sim_topology(&url, &cfg)
        .await
        .expect("declare topology");

    let sink = RabbitJobSink::connect(&url, cfg.queue.clone())
        .await
        .expect("connect sink");
    let job = a_job();
    sink.publish(&job).await.expect("publish job");

    // First consumer takes the job, then "crashes" — we drop it without acking.
    {
        let mut dying = RabbitJobSource::connect(&url, &cfg.queue, 8)
            .await
            .expect("connect first source");
        let delivery = dying.recv().await.expect("first delivery");
        assert_eq!(delivery.job.alert_id, job.alert_id);
        assert!(!delivery.redelivered, "first delivery is not a redelivery");
        // Drop `delivery` (no ack) and the source/connection → the broker requeues.
        drop(delivery);
        drop(dying);
    }

    // A fresh consumer must see the same job again, flagged as redelivered.
    let mut survivor = RabbitJobSource::connect(&url, &cfg.queue, 8)
        .await
        .expect("connect second source");
    let again = tokio::time::timeout(Duration::from_secs(10), survivor.recv())
        .await
        .expect("redelivery arrives within timeout")
        .expect("a redelivered job");
    assert_eq!(again.job.alert_id, job.alert_id, "same job redelivered");
    assert!(again.redelivered, "the broker flags it as a redelivery");
    again
        .settle(Disposition::Ack)
        .await
        .expect("ack the redelivery");
}

/// A poison job — one the resolver can't turn into a scenario (the deferred-stub
/// resolver) — is **dead-lettered** to `sim.jobs.dlq` rather than requeued forever.
#[tokio::test]
#[ignore = "requires Docker; run via `just test-integration`"]
async fn a_poison_job_is_dead_lettered_not_looped() {
    let (_node, url) = start_rabbit().await;
    let cfg = test_config(&url);
    declare_sim_topology(&url, &cfg)
        .await
        .expect("declare topology");

    let sink = RabbitJobSink::connect(&url, cfg.queue.clone())
        .await
        .expect("connect sink");
    let job = a_job();
    sink.publish(&job).await.expect("publish job");

    // The stub resolver makes every job poison → the worker dead-letters it.
    let events = Arc::new(RecordingEventSink::default());
    let w = worker(
        Arc::new(UnresolvedJobResolver),
        Arc::new(RevmSimulator::new(MinProfit::try_new(1.0).unwrap())),
        events.clone(),
    );
    let mut source = RabbitJobSource::connect(&url, &cfg.queue, 8)
        .await
        .expect("connect source");
    let delivery = source.recv().await.expect("a job is delivered");
    let disposition = w.process(&delivery.job).await;
    assert_eq!(
        disposition,
        Disposition::DeadLetter,
        "an unresolvable job is poison"
    );
    delivery
        .settle(Disposition::DeadLetter)
        .await
        .expect("dead-letter");
    drop(source);

    // No result was published for a job that never simulated.
    assert!(events.events().is_empty());

    // The job is now quarantined on the dead-letter queue.
    let (_conn, channel) = open_channel(&url).await;
    let dead = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(msg) = channel
                .basic_get(&cfg.dead_letter_queue, BasicGetOptions { no_ack: true })
                .await
                .expect("basic_get on dlq")
            {
                break msg;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the poison job reaches the DLQ");

    let decoded: SimulationJob =
        serde_json::from_slice(&dead.delivery.data).expect("decode the dead-lettered job");
    assert_eq!(
        decoded.alert_id, job.alert_id,
        "the same job is quarantined"
    );

    // And the work queue is empty — it didn't loop.
    assert_eq!(
        drain_count(&channel, &cfg.queue).await,
        0,
        "the poison job left the work queue (no loop)"
    );
}

/// Sanity guard mirroring the topology suite: the `Priority` set on a published job
/// survives onto the consumed delivery (the worker can read it). Kept here so the
/// worker-side consume path is covered, not just the publish path.
#[tokio::test]
#[ignore = "requires Docker; run via `just test-integration`"]
async fn consumed_job_preserves_its_priority() {
    let (_node, url) = start_rabbit().await;
    let cfg = test_config(&url);
    declare_sim_topology(&url, &cfg)
        .await
        .expect("declare topology");

    let sink = RabbitJobSink::connect(&url, cfg.queue.clone())
        .await
        .expect("connect sink");
    let mut job = a_job();
    job.priority = Priority::new(7);
    sink.publish(&job).await.expect("publish job");

    let mut source = RabbitJobSource::connect(&url, &cfg.queue, 8)
        .await
        .expect("connect source");
    let delivery = source.recv().await.expect("a job is delivered");
    assert_eq!(delivery.job.priority, Priority::new(7));
    delivery.settle(Disposition::Ack).await.expect("ack");
}
