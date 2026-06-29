//! The RabbitMQ `sim.jobs` topology (§7, §20) — declared once at boot, before the
//! dispatcher's [`RabbitJobSink`](crate::queue::RabbitJobSink) publishes a single
//! command, so the queue the sink publishes into is guaranteed to exist with the
//! right arguments (the sink itself deliberately never declares — see
//! [`crate::queue`]).
//!
//! The shape (§7 "Job dispatch", §20 deployment line):
//!
//! ```text
//!   sim.jobs                         quorum, durable
//!   ├─ x-queue-type: quorum          replicated across nodes for HA (§20)
//!   ├─ x-dead-letter-exchange: sim.jobs.dlx
//!   └─ x-delivery-limit: N           fail N times → DLX (§7)
//!        │  (after N failed redeliveries)
//!        ▼
//!   sim.jobs.dlx  (fanout) ──► sim.jobs.dlq   quorum, durable — the quarantine
//! ```
//!
//! **Priority on a quorum queue (the one place the spec couldn't be taken
//! literally).** §7 calls for "priority 0–9". A *classic* queue gets that via
//! `x-max-priority`, but classic queues aren't replicated (mirrored queues were
//! removed in RabbitMQ 4), which would forfeit §20's HA requirement; and a quorum
//! queue **rejects `x-max-priority`** outright. So the work queue is quorum (HA +
//! the native `x-delivery-limit` DLX path §7 needs), and priority is the quorum
//! queue's built-in **two-level** scheme: a message published with `priority > 4`
//! is treated as high, `≤ 4` as normal. The producer still stamps the full `0..=9`
//! ([`Priority`](crate::command::Priority) / [`queue`](crate::queue) `with_priority`)
//! — the queue simply collapses it to high/normal, so a high-confidence/enterprise
//! alert still jumps the free-tier backlog, just without ten distinct bands.
//! Declaring `x-max-priority` here is therefore deliberately omitted (it would fail
//! the declaration).
//!
//! Declaration is idempotent: re-running with identical arguments is a no-op;
//! re-running with *different* arguments fails the channel (precondition) — which is
//! the fail-fast we want, surfacing a topology drift at boot rather than silently.

use anyhow::{Context, Result};
use lapin::options::{ExchangeDeclareOptions, QueueBindOptions, QueueDeclareOptions};
use lapin::types::{AMQPValue, FieldTable};
use lapin::{Channel, ExchangeKind};

use crate::config::RabbitConfig;
use crate::queue::amqp_connect;

/// `x-queue-type` value selecting a quorum queue — replicated across nodes for HA
/// (§20). Both the work queue and its dead-letter queue use it so neither loses
/// messages to a single node failing.
const QUORUM: &str = "quorum";

/// Declare the full `sim.jobs` topology on a throwaway connection, then drop it (the
/// declarations are durable and persist on the broker). Call once at boot, before
/// connecting the publish sink.
pub async fn declare_sim_topology(url: &str, cfg: &RabbitConfig) -> Result<()> {
    let connection = amqp_connect(url).await?;
    let channel = connection
        .create_channel()
        .await
        .context("opening a RabbitMQ channel for topology declaration")?;
    declare_on_channel(&channel, cfg).await
    // `connection` drops here, closing the channel — the durable topology remains.
}

/// The declaration itself, factored off the connection so it reads top-to-bottom:
/// DLX exchange → dead-letter queue → bind → work queue. The work queue points its
/// `x-dead-letter-exchange` at the DLX, so this order means the DLX target already
/// exists when the work queue starts referencing it.
async fn declare_on_channel(channel: &Channel, cfg: &RabbitConfig) -> Result<()> {
    // 1. The dead-letter exchange. Fanout: a dead-lettered job carries its original
    //    routing key, but we want every dead letter to land in the one quarantine
    //    queue regardless, so the exchange ignores the key.
    channel
        .exchange_declare(
            &cfg.dlx,
            ExchangeKind::Fanout,
            ExchangeDeclareOptions {
                durable: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .with_context(|| format!("declaring dead-letter exchange {}", cfg.dlx))?;

    // 2. The quarantine queue, and bind it behind the DLX so dead letters are kept
    //    (an unbound DLX would silently drop them).
    channel
        .queue_declare(
            &cfg.dead_letter_queue,
            QueueDeclareOptions {
                durable: true,
                ..Default::default()
            },
            quorum_only_arguments(),
        )
        .await
        .with_context(|| format!("declaring dead-letter queue {}", cfg.dead_letter_queue))?;
    channel
        .queue_bind(
            &cfg.dead_letter_queue,
            &cfg.dlx,
            "", // fanout ignores the routing key
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .with_context(|| {
            format!(
                "binding dead-letter queue {} to exchange {}",
                cfg.dead_letter_queue, cfg.dlx
            )
        })?;

    // 3. The work queue itself.
    channel
        .queue_declare(
            &cfg.queue,
            QueueDeclareOptions {
                durable: true,
                ..Default::default()
            },
            sim_jobs_arguments(cfg),
        )
        .await
        .with_context(|| format!("declaring work queue {}", cfg.queue))?;

    tracing::info!(
        queue = %cfg.queue,
        dlx = %cfg.dlx,
        dead_letter_queue = %cfg.dead_letter_queue,
        delivery_limit = cfg.delivery_limit,
        "RabbitMQ sim.jobs topology declared (quorum, durable, DLX)"
    );
    Ok(())
}

/// Arguments for the `sim.jobs` work queue: a durable quorum queue that dead-letters
/// to [`cfg.dlx`](RabbitConfig::dlx) after [`cfg.delivery_limit`](RabbitConfig::delivery_limit)
/// failed deliveries. Deliberately **no** `x-max-priority` — quorum queues reject it
/// (see the module docs); priority rides the quorum queue's built-in high/normal
/// split on the published message's `priority` property instead.
pub(crate) fn sim_jobs_arguments(cfg: &RabbitConfig) -> FieldTable {
    let mut args = FieldTable::default();
    args.insert("x-queue-type".into(), AMQPValue::LongString(QUORUM.into()));
    args.insert(
        "x-dead-letter-exchange".into(),
        AMQPValue::LongString(cfg.dlx.as_str().into()),
    );
    args.insert(
        "x-delivery-limit".into(),
        AMQPValue::LongLongInt(cfg.delivery_limit),
    );
    args
}

/// Arguments for the dead-letter queue: just "make it a quorum queue" so the
/// quarantine is as durable/HA as the work queue. It carries no DLX of its own —
/// dead letters terminate here for inspection, they don't dead-letter again.
fn quorum_only_arguments() -> FieldTable {
    let mut args = FieldTable::default();
    args.insert("x-queue-type".into(), AMQPValue::LongString(QUORUM.into()));
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RabbitConfig {
        RabbitConfig {
            url: "amqp://localhost:5672/".into(),
            queue: "sim.jobs".into(),
            dlx: "sim.jobs.dlx".into(),
            dead_letter_queue: "sim.jobs.dlq".into(),
            delivery_limit: 5,
        }
    }

    #[test]
    fn work_queue_is_quorum_with_dlx_and_delivery_limit() {
        let args = sim_jobs_arguments(&cfg());
        assert_eq!(
            args.inner().get("x-queue-type"),
            Some(&AMQPValue::LongString(QUORUM.into()))
        );
        assert_eq!(
            args.inner().get("x-dead-letter-exchange"),
            Some(&AMQPValue::LongString("sim.jobs.dlx".into()))
        );
        assert_eq!(
            args.inner().get("x-delivery-limit"),
            Some(&AMQPValue::LongLongInt(5))
        );
    }

    /// The crux of the quorum-vs-classic decision: `x-max-priority` must NOT be set,
    /// because a quorum queue rejects it and the declaration would fail. Priority is
    /// the quorum queue's high/normal split on the message property, not a queue arg.
    #[test]
    fn work_queue_omits_x_max_priority_rejected_on_quorum() {
        let args = sim_jobs_arguments(&cfg());
        assert!(!args.contains_key("x-max-priority"));
    }

    #[test]
    fn delivery_limit_is_configurable() {
        let args = sim_jobs_arguments(&RabbitConfig {
            delivery_limit: 20,
            ..cfg()
        });
        assert_eq!(
            args.inner().get("x-delivery-limit"),
            Some(&AMQPValue::LongLongInt(20))
        );
    }

    #[test]
    fn dead_letter_queue_is_quorum_and_terminal() {
        let args = quorum_only_arguments();
        assert_eq!(
            args.inner().get("x-queue-type"),
            Some(&AMQPValue::LongString(QUORUM.into()))
        );
        // No DLX of its own — dead letters terminate here, no re-dead-lettering loop.
        assert!(!args.contains_key("x-dead-letter-exchange"));
    }
}
