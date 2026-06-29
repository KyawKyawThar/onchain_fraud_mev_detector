//! Live-broker integration tests for the `sim.jobs` topology (§7, §20), against a
//! *real* RabbitMQ spun up via testcontainers. Marked `#[ignore]` so the default
//! `cargo test` stays hermetic; `just test-integration` (nextest `--run-ignored
//! all`) runs them. They prove the things the pure arg-builder unit tests in
//! `topology.rs` can't: that the broker actually *accepts* our declaration, that
//! re-declaring is idempotent, that a published job round-trips through the declared
//! queue, and — the crux of the quorum-vs-classic decision — that the broker
//! *rejects* a quorum queue carrying `x-max-priority`.

use lapin::options::{BasicGetOptions, QueueDeclareOptions};
use lapin::types::{AMQPValue, FieldTable};
use lapin::{Channel, Connection, ConnectionProperties};

use events::primitives::{AlertId, AlertKind, Chain, Confidence, DetectorRef};
use simulation::command::{Priority, SimulationJob};
use simulation::config::RabbitConfig;
use simulation::queue::{JobSink, RabbitJobSink};
use simulation::topology::declare_sim_topology;

use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::rabbitmq::RabbitMq;

/// Start a RabbitMQ container and return it (kept alive by the caller) plus its
/// host AMQP URL. The container stops when the returned handle is dropped.
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
        delivery_limit: 5,
    }
}

fn a_job(priority: u8) -> SimulationJob {
    SimulationJob {
        alert_id: AlertId::new(),
        chain: Chain::ETHEREUM,
        kind: AlertKind::Sandwich,
        detector: DetectorRef {
            id: "sandwich".into(),
            version: "1.2.0".into(),
            config_hash: "deadbeef".into(),
        },
        addresses: vec![],
        confidence: Confidence::new(0.7),
        priority: Priority::new(priority),
    }
}

/// The happy path: declaring is accepted by a real broker, is idempotent, and a job
/// published through `RabbitJobSink` lands on the declared `sim.jobs` queue and
/// decodes back to exactly what was sent, with its AMQP priority property intact.
#[tokio::test]
#[ignore = "requires Docker; run via `just test-integration`"]
async fn declares_quorum_topology_idempotently_and_routes_a_published_job() {
    let (_node, url) = start_rabbit().await;
    let cfg = test_config(&url);

    // Accepted by the broker...
    declare_sim_topology(&url, &cfg)
        .await
        .expect("first topology declaration");
    // ...and idempotent: the identical re-declare is a no-op, not a conflict.
    declare_sim_topology(&url, &cfg)
        .await
        .expect("re-declaring identical topology is idempotent");

    // Publish a job through the production sink (which never declares — it relies on
    // the declaration above).
    let sink = RabbitJobSink::connect(&url, cfg.queue.clone())
        .await
        .expect("connecting the job sink");
    let job = a_job(7);
    sink.publish(&job).await.expect("publishing a job");

    // Pull it straight back off the declared queue and check it survived the trip.
    let (_conn, channel) = open_channel(&url).await;
    let got = channel
        .basic_get(
            &cfg.queue,
            BasicGetOptions { no_ack: true },
        )
        .await
        .expect("basic_get")
        .expect("a message is waiting on sim.jobs");

    let decoded: SimulationJob =
        serde_json::from_slice(&got.delivery.data).expect("decoding the job body");
    assert_eq!(decoded, job, "the body round-trips through the real queue");
    assert_eq!(
        got.delivery.properties.priority(),
        &Some(7),
        "the 0..=9 priority property rides along (the quorum queue collapses it to \
         high/normal at routing time, but the property itself is preserved)"
    );
}

/// The decision guard: a quorum queue carrying `x-max-priority` is *rejected* by the
/// broker. This is exactly why `sim_jobs_arguments` omits it — and a regression that
/// "just adds priority back" the classic way would fail here, on a real broker,
/// rather than silently in production.
#[tokio::test]
#[ignore = "requires Docker; run via `just test-integration`"]
async fn quorum_queue_rejects_x_max_priority() {
    let (_node, url) = start_rabbit().await;
    let (_conn, channel) = open_channel(&url).await;

    let mut args = FieldTable::default();
    args.insert("x-queue-type".into(), AMQPValue::LongString("quorum".into()));
    args.insert("x-max-priority".into(), AMQPValue::LongInt(9));

    let result = channel
        .queue_declare(
            "sim.jobs.priority.reject",
            QueueDeclareOptions {
                durable: true,
                ..Default::default()
            },
            args,
        )
        .await;

    assert!(
        result.is_err(),
        "RabbitMQ must reject x-max-priority on a quorum queue — this is the \
         constraint that forced the quorum/2-level-priority design (§7)"
    );
}
