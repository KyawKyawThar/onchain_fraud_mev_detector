//! The publish seam the ingestion [`crate::pipeline`] writes against.
//!
//! The seam itself — the [`EventSink`] trait, the [`KafkaEventSink`] production
//! impl, the transport-agnostic [`PublishError`], and the at-least-once
//! [`publish_resilient`] retry policy — now lives in the shared [`event_bus`]
//! crate, because detection is the system's *second* producer and needs the
//! identical contract (one Kafka producer config, one retry discipline). This
//! module re-exports it so the established `crate::publisher::*` paths keep
//! resolving.

pub use event_bus::{publish_resilient, EventSink, KafkaEventSink, PublishError, PUBLISH_BACKOFF};
