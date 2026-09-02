//! The schema registry (§17) — the committed, machine-readable description of
//! every [`DomainEvent`](crate::DomainEvent), and the rules that decide whether
//! a change to one is safe to deploy.
//!
//! `tests/wire_format.rs` locks the *bytes* of today's shape. That is a lock,
//! not a compatibility rule: it says "this changed", never "this change is
//! safe". Safety is the operational requirement — a producer and a consumer are
//! deployed minutes or days apart, and an event written a year ago is still in
//! the event store waiting to be replayed (§4, §18).
//!
//! ## The pieces
//!
//! - [`Registry`] — the schema of one `SCHEMA_VERSION`: every event's fields,
//!   topic and partition key, plus the envelope's own fields. Built from the
//!   canonical [`fixtures`] by [`generate`], **probed out of this crate's real
//!   `Deserialize` impls** (see [`probe`]), never from a second derive.
//! - [`compare`] — the classifier: two registries in, a list of [`Change`]s out,
//!   each carrying the [`Verdict`] that says whether it breaks archived events,
//!   deployed readers, or nothing.
//! - [`committed`] — the registry as committed under `schema/v<N>/`, compiled
//!   into the crate, so a *consumer* can assert at test time that the fields it
//!   reads still exist ([`assert_reads`]).
//!
//! Everything here is pure: values in, values out, no I/O. The file handling and
//! the assertions live in the shell (`tests/schema_registry.rs`), which is what
//! lets the same engine serve the gate, a consumer's own test, and any tool that
//! wants to publish the schema elsewhere.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod fixtures;
mod probe;

use probe::{Probe, Seg};

/// The committed registry for the current [`SCHEMA_VERSION`](crate::SCHEMA_VERSION),
/// compiled in so it is readable without a filesystem.
///
/// The path is deliberately literal: a `SCHEMA_VERSION` bump has to come here
/// and change it, and [`committed`] asserts the two agree.
const COMMITTED: &str = include_str!("../../schema/v1/registry.json");

/// The version of the *registry file format* — this module's own output shape,
/// which is a different thing from the event schema it describes.
///
/// Without it, a change to how a schema is written down (splitting a `string`
/// into `string`/`validated_string`/`enum`, say) reads as a change to every
/// event that has a string in it, and the gate's report becomes noise at exactly
/// the moment someone needs to trust it. A mismatch here means "regenerate",
/// never "your schema broke".
pub const REGISTRY_FORMAT: u16 = 1;

// ── What a schema is ─────────────────────────────────────────────

/// The observed type of one field.
///
/// The three string forms are separate variants rather than a `String` plus
/// flags, so `enum + validated` — a state with no meaning — cannot be written
/// down (§4). They form a widening lattice: [`FieldType::Enum`] ⊂
/// [`FieldType::ValidatedString`] ⊂ [`FieldType::String`], and every
/// compatibility rule about strings falls out of which direction a change moves
/// along it (see [`FieldType::openness`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FieldType {
    Integer,
    Float,
    Boolean,
    Object,
    Array,
    /// Free-form JSON (a `serde_json::Value`): it accepts anything, so its
    /// interior is payload rather than schema and the walk stops there.
    Any,
    /// Only reachable if a fixture leaves a field unset, which the gate rejects
    /// — an unset field has no observable type.
    Null,
    /// Any string decodes.
    String,
    /// A string the codec validates: an address, a hash, a timestamp.
    ValidatedString,
    /// A closed set of accepted values, read out of serde's own error.
    Enum {
        values: Vec<String>,
    },
}

impl FieldType {
    /// Where a string type sits on the widening lattice; `None` for everything
    /// that is not a string. Higher accepts strictly more.
    fn openness(&self) -> Option<u8> {
        match self {
            FieldType::String => Some(2),
            FieldType::ValidatedString => Some(1),
            FieldType::Enum { .. } => Some(0),
            _ => None,
        }
    }

    /// The name used in a change report.
    fn label(&self) -> &'static str {
        match self {
            FieldType::Integer => "integer",
            FieldType::Float => "float",
            FieldType::Boolean => "boolean",
            FieldType::Object => "object",
            FieldType::Array => "array",
            FieldType::Any => "free-form json",
            FieldType::Null => "null",
            FieldType::String => "string",
            FieldType::ValidatedString => "validated string",
            FieldType::Enum { .. } => "enum",
        }
    }
}

/// The structural schema of one field, as observed from the real codec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSchema {
    /// Dotted path within the payload; `[]` denotes an array element
    /// (`legs[].chain`).
    pub path: String,
    #[serde(flatten)]
    pub ty: FieldType,
    /// Whether a document *without* this field fails to decode — derived by
    /// deleting it, so `Option<T>` and `#[serde(default)]` both read as
    /// optional, which is the property backwards compatibility turns on.
    /// Absent for an array element, which is a position rather than a field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// Everything that is contractual about one event type.
///
/// Not just the fields: `topic` is where a consumer subscribes, and
/// `partition_key` is the *ordering* guarantee it inherits (§20). Changing
/// either leaves every field identical while silently breaking a consumer that
/// depends on two events co-partitioning — which is why they are in the
/// registry and classified like any other change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSchema {
    pub topic: String,
    /// The [`PartitionKey`](crate::PartitionKey) discriminant this event's
    /// canonical fixture partitions under (`chain`, `customer`, `incident`, …).
    pub partition_key: String,
    pub fields: Vec<FieldSchema>,
}

/// The schema of one `SCHEMA_VERSION`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    /// [`REGISTRY_FORMAT`] — how this file is written, not what it describes.
    #[serde(default)]
    pub registry_format: u16,
    pub schema_version: u16,
    /// The transport/storage wrapper's own fields — the event-store columns.
    /// The walk stops at `payload`, which every event's entry covers.
    pub envelope: Vec<FieldSchema>,
    pub events: BTreeMap<String, EventSchema>,
}

impl Registry {
    /// The schema of `path` within `event_type`, if the registry has one.
    pub fn field(&self, event_type: &str, path: &str) -> Option<&FieldSchema> {
        self.events
            .get(event_type)?
            .fields
            .iter()
            .find(|f| f.path == path)
    }
}

// ── Generating it ────────────────────────────────────────────────

fn decode_event(doc: &Value) -> Result<(), String> {
    serde_json::from_value::<crate::DomainEvent>(doc.clone())
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn decode_envelope(doc: &Value) -> Result<(), String> {
    serde_json::from_value::<crate::EventEnvelope>(doc.clone())
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Describe every field of `doc` below `base`, by probing `decode`.
///
/// `stop_at` names rendered paths whose interior is covered elsewhere (the
/// envelope's `payload`). Fields come back sorted by path, so the description is
/// a function of the shape and not of struct declaration order.
pub fn describe(
    doc: Value,
    decode: &dyn Fn(&Value) -> Result<(), String>,
    base: &[&str],
    stop_at: &[&str],
) -> Vec<FieldSchema> {
    let probe = Probe::new(doc, decode);
    let mut path: Vec<Seg> = base.iter().map(|k| Seg::Key((*k).to_owned())).collect();
    let mut out = Vec::new();
    probe::walk(&probe, &mut path, base.len(), stop_at, &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// The schema of the code as it stands right now.
///
/// # Panics
///
/// If [`fixtures::sample_events`] does not cover every `DomainEvent` variant —
/// the same exhaustiveness the wire-format goldens require.
pub fn generate() -> Registry {
    use strum::VariantNames;

    let events = fixtures::sample_events()
        .into_iter()
        .map(|event| {
            let name = event.event_type().to_owned();
            let envelope = fixtures::envelope_for(event);
            let doc = serde_json::to_value(&envelope.payload).expect("serialize fixture");
            let schema = EventSchema {
                topic: envelope.topic(),
                // The fixtures are fully populated, so a data-dependent key
                // (`UsageRecorded` is customer-keyed only when it names one)
                // is observed in its business form — the form that carries the
                // ordering guarantee worth locking.
                partition_key: envelope.partition_key().kind().to_owned(),
                fields: describe(doc, &decode_event, &["payload"], &[]),
            };
            (name, schema)
        })
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        events.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        crate::DomainEvent::VARIANTS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        "events::schema::fixtures must produce exactly one of every variant",
    );

    let envelope_doc =
        serde_json::to_value(fixtures::sample_envelope()).expect("serialize envelope");
    Registry {
        registry_format: REGISTRY_FORMAT,
        schema_version: crate::SCHEMA_VERSION,
        envelope: describe(envelope_doc, &decode_envelope, &[], &["payload"]),
        events,
    }
}

/// The registry as committed under `schema/v<SCHEMA_VERSION>/`, or why it
/// cannot be read as one.
///
/// The error is not a failure of the *schema* — it means the committed file is
/// stale relative to this build's tooling (a new [`REGISTRY_FORMAT`]) or its
/// version (a `SCHEMA_VERSION` bump that has not repointed [`COMMITTED`]). The
/// fix in both cases is to regenerate, which is why blessing treats it as a
/// bootstrap rather than as something to compare against.
pub fn try_committed() -> Result<Registry, String> {
    let registry: Registry = serde_json::from_str(COMMITTED)
        .map_err(|e| format!("the committed registry is unreadable: {e}"))?;
    if registry.registry_format != REGISTRY_FORMAT {
        return Err(format!(
            "the committed registry is in format {} but this build writes {REGISTRY_FORMAT} \
             — regenerate it with `just schema-bless`",
            registry.registry_format,
        ));
    }
    if registry.schema_version != crate::SCHEMA_VERSION {
        return Err(format!(
            "the compiled-in registry is v{} but this build is v{} — point \
             events::schema::COMMITTED at the new version's directory",
            registry.schema_version,
            crate::SCHEMA_VERSION,
        ));
    }
    Ok(registry)
}

/// The committed registry.
///
/// # Panics
///
/// If it cannot be read as one — see [`try_committed`].
pub fn committed() -> Registry {
    try_committed().unwrap_or_else(|e| panic!("{e}"))
}

// ── Classifying a change ─────────────────────────────────────────

/// What a single difference between two registries means for two services
/// deploying independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Old readers and old data both survive: a new event type, a defaulted
    /// field, a loosened constraint.
    Compatible,
    /// Old *data* survives, old *readers* do not — a new value in a closed enum
    /// is rejected by a consumer that has never heard of it. Legal, but
    /// consumers deploy before the producer that emits it.
    ConsumersFirst,
    /// Something already written, or already deployed, can no longer be read.
    Breaking,
}

#[derive(Debug, Clone)]
pub struct Change {
    pub verdict: Verdict,
    pub detail: String,
}

impl Change {
    fn new(verdict: Verdict, detail: String) -> Self {
        Self { verdict, detail }
    }
}

/// Classify every difference between the committed schema and a new one.
///
/// Pure and total: no I/O, no panics, and an empty result exactly when the two
/// describe the same contract.
pub fn compare(old: &Registry, new: &Registry) -> Vec<Change> {
    let mut changes = Vec::new();
    compare_fields("envelope", &old.envelope, &new.envelope, &mut changes);

    for name in old.events.keys() {
        if !new.events.contains_key(name) {
            changes.push(Change::new(
                Verdict::Breaking,
                format!(
                    "{name}: event type removed — its topic still has history and \
                     nothing may drop out of replay (§18)"
                ),
            ));
        }
    }

    for (name, now) in &new.events {
        let Some(was) = old.events.get(name) else {
            changes.push(Change::new(
                Verdict::Compatible,
                format!("{name}: new event type ({} fields)", now.fields.len()),
            ));
            continue;
        };

        if was.topic != now.topic {
            changes.push(Change::new(
                Verdict::Breaking,
                format!(
                    "{name}: topic moved {} → {} — every consumer is subscribed to \
                     the old one and would simply stop receiving it",
                    was.topic, now.topic
                ),
            ));
        }
        if was.partition_key != now.partition_key {
            changes.push(Change::new(
                Verdict::Breaking,
                format!(
                    "{name}: partition key changed {} → {} — the ordering and \
                     co-partitioning guarantee consumers were built on is not the \
                     one they now get (§20)",
                    was.partition_key, now.partition_key
                ),
            ));
        }
        compare_fields(name, &was.fields, &now.fields, &mut changes);
    }

    changes
}

fn compare_fields(scope: &str, old: &[FieldSchema], new: &[FieldSchema], out: &mut Vec<Change>) {
    let before: BTreeMap<&str, &FieldSchema> = old.iter().map(|f| (f.path.as_str(), f)).collect();
    let after: BTreeMap<&str, &FieldSchema> = new.iter().map(|f| (f.path.as_str(), f)).collect();

    for (path, was) in &before {
        if !after.contains_key(path) {
            out.push(Change::new(
                Verdict::Breaking,
                format!(
                    "{scope}.{path}: removed (was {}) — every archived event still \
                     carries it and every deployed reader still expects it",
                    was.ty.label()
                ),
            ));
        }
    }

    for (path, now) in &after {
        let Some(was) = before.get(path) else {
            out.push(if now.required == Some(true) {
                Change::new(
                    Verdict::Breaking,
                    format!(
                        "{scope}.{path}: added as a REQUIRED {} — no archived event \
                         has it, so history stops decoding. Give it \
                         `#[serde(default …)]` and it becomes compatible",
                        now.ty.label()
                    ),
                )
            } else {
                Change::new(
                    Verdict::Compatible,
                    format!(
                        "{scope}.{path}: added, optional on read ({})",
                        now.ty.label()
                    ),
                )
            });
            continue;
        };

        compare_type(scope, path, &was.ty, &now.ty, out);

        match (was.required, now.required) {
            (Some(false), Some(true)) => out.push(Change::new(
                Verdict::Breaking,
                format!(
                    "{scope}.{path}: optional → required — events written without it \
                     no longer decode"
                ),
            )),
            (Some(true), Some(false)) => out.push(Change::new(
                Verdict::Compatible,
                format!("{scope}.{path}: required → optional"),
            )),
            (a, b) if a != b => out.push(Change::new(
                Verdict::Breaking,
                format!(
                    "{scope}.{path}: changed between a field and an array element \
                     ({a:?} → {b:?})"
                ),
            )),
            _ => {}
        }
    }
}

fn compare_type(scope: &str, path: &str, was: &FieldType, now: &FieldType, out: &mut Vec<Change>) {
    if was == now {
        return;
    }

    if let (FieldType::Enum { values: before }, FieldType::Enum { values: after }) = (was, now) {
        let (before, after): (BTreeSet<_>, BTreeSet<_>) =
            (before.iter().collect(), after.iter().collect());
        let removed: Vec<_> = before.difference(&after).collect();
        let added: Vec<_> = after.difference(&before).collect();
        if !removed.is_empty() {
            out.push(Change::new(
                Verdict::Breaking,
                format!(
                    "{scope}.{path}: enum value(s) {removed:?} removed — archived \
                     events carrying them no longer decode"
                ),
            ));
        }
        if !added.is_empty() {
            out.push(Change::new(
                Verdict::ConsumersFirst,
                format!(
                    "{scope}.{path}: enum value(s) {added:?} added — a consumer built \
                     before this rejects them as an unknown variant, so every \
                     consumer deploys before the producer that emits one"
                ),
            ));
        }
        return;
    }

    // Both string-shaped: the lattice decides. Widening accepts everything the
    // old form did; narrowing may reject values already on disk.
    if let (Some(before), Some(after)) = (was.openness(), now.openness()) {
        out.push(if after > before {
            Change::new(
                Verdict::Compatible,
                format!(
                    "{scope}.{path}: {} → {} (strictly wider)",
                    was.label(),
                    now.label()
                ),
            )
        } else {
            Change::new(
                Verdict::Breaking,
                format!(
                    "{scope}.{path}: {} → {} — values already on disk may no longer \
                     parse",
                    was.label(),
                    now.label()
                ),
            )
        });
        return;
    }

    out.push(Change::new(
        Verdict::Breaking,
        format!("{scope}.{path}: retyped {} → {}", was.label(), now.label()),
    ));
}

/// A human-readable report of `changes`, grouped worst-first. Empty when there
/// is nothing to say.
pub fn report(changes: &[Change]) -> String {
    let mut out = String::new();
    for verdict in [
        Verdict::Breaking,
        Verdict::ConsumersFirst,
        Verdict::Compatible,
    ] {
        let group: Vec<&Change> = changes.iter().filter(|c| c.verdict == verdict).collect();
        if group.is_empty() {
            continue;
        }
        let heading = match verdict {
            Verdict::Breaking => "BREAKING — archived events or deployed readers stop working",
            Verdict::ConsumersFirst => "CONSUMERS FIRST — safe only in that rollout order",
            Verdict::Compatible => "compatible",
        };
        let _ = writeln!(out, "\n  {heading}:");
        for change in group {
            let _ = writeln!(out, "    · {}", change.detail);
        }
    }
    out
}

// ── What a consumer depends on ───────────────────────────────────

/// Assert that every `(event_type, field path)` this consumer reads still exists
/// in the committed schema.
///
/// The registry gate in `events` can prove that a field was removed; it cannot
/// know *who* was reading it, because the dependency points the other way. So
/// the declaration lives with the consumer — the same shape as
/// [`topics_for`](crate::topics_for), which makes a consumer state the events it
/// reads and validates the list against the schema — and this turns a removed
/// field from "someone's silent `None` in production" into that crate's own
/// red test, naming itself.
///
/// ```no_run
/// # const READS: &[(&str, &str)] = &[("UsageRecorded", "quantity")];
/// #[test]
/// fn declared_reads_still_exist() {
///     events::schema::assert_reads("usage", READS);
/// }
/// ```
///
/// # Panics
///
/// Listing every declared path the committed schema no longer has.
pub fn assert_reads(consumer: &str, reads: &[(&str, &str)]) {
    let registry = committed();
    let missing: Vec<String> = reads
        .iter()
        .filter(|(event_type, path)| registry.field(event_type, path).is_none())
        .map(|(event_type, path)| format!("{event_type}.{path}"))
        .collect();

    assert!(
        missing.is_empty(),
        "`{consumer}` reads {} field(s) the committed v{} schema no longer has: {}\n  \
         Either the read is stale and should go, or the field was removed out from \
         under this consumer — which is exactly the deploy-order break the registry \
         exists to surface (crates/events/SCHEMA.md).",
        missing.len(),
        crate::SCHEMA_VERSION,
        missing.join(", "),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(path: &str, ty: FieldType, required: Option<bool>) -> FieldSchema {
        FieldSchema {
            path: path.to_owned(),
            ty,
            required,
        }
    }

    fn registry(fields: Vec<FieldSchema>) -> Registry {
        Registry {
            registry_format: REGISTRY_FORMAT,
            schema_version: crate::SCHEMA_VERSION,
            envelope: Vec::new(),
            events: BTreeMap::from([(
                "Ev".to_owned(),
                EventSchema {
                    topic: "mev.events.Ev".to_owned(),
                    partition_key: "chain".to_owned(),
                    fields,
                },
            )]),
        }
    }

    fn verdicts(old: &Registry, new: &Registry) -> Vec<Verdict> {
        compare(old, new).iter().map(|c| c.verdict).collect()
    }

    #[test]
    fn an_unchanged_schema_has_nothing_to_report() {
        let r = registry(vec![field("a", FieldType::Integer, Some(true))]);
        assert!(compare(&r, &r).is_empty());
        assert!(report(&compare(&r, &r)).is_empty());
    }

    #[test]
    fn removing_a_field_is_breaking_and_adding_a_defaulted_one_is_not() {
        let with = registry(vec![
            field("a", FieldType::Integer, Some(true)),
            field("b", FieldType::String, Some(false)),
        ]);
        let without = registry(vec![field("a", FieldType::Integer, Some(true))]);

        assert_eq!(verdicts(&with, &without), vec![Verdict::Breaking]);
        assert_eq!(verdicts(&without, &with), vec![Verdict::Compatible]);
    }

    #[test]
    fn a_new_required_field_breaks_history() {
        let before = registry(vec![field("a", FieldType::Integer, Some(true))]);
        let after = registry(vec![
            field("a", FieldType::Integer, Some(true)),
            field("b", FieldType::String, Some(true)),
        ]);
        assert_eq!(verdicts(&before, &after), vec![Verdict::Breaking]);
    }

    #[test]
    fn a_retype_is_breaking_in_both_directions() {
        let int = registry(vec![field("a", FieldType::Integer, Some(true))]);
        let float = registry(vec![field("a", FieldType::Float, Some(true))]);
        assert_eq!(verdicts(&int, &float), vec![Verdict::Breaking]);
        assert_eq!(verdicts(&float, &int), vec![Verdict::Breaking]);
    }

    #[test]
    fn the_string_lattice_widens_safely_and_narrows_dangerously() {
        let closed = |values: &[&str]| {
            registry(vec![field(
                "a",
                FieldType::Enum {
                    values: values.iter().map(|v| (*v).to_owned()).collect(),
                },
                Some(true),
            )])
        };
        let validated = registry(vec![field("a", FieldType::ValidatedString, Some(true))]);
        let free = registry(vec![field("a", FieldType::String, Some(true))]);

        assert_eq!(verdicts(&closed(&["x"]), &free), vec![Verdict::Compatible]);
        assert_eq!(
            verdicts(&validated, &free),
            vec![Verdict::Compatible],
            "dropping validation accepts everything it used to",
        );
        assert_eq!(verdicts(&free, &validated), vec![Verdict::Breaking]);
        assert_eq!(verdicts(&free, &closed(&["x"])), vec![Verdict::Breaking]);

        // A new value is legal but rollout-ordered; a removed one is not legal.
        assert_eq!(
            verdicts(&closed(&["x"]), &closed(&["x", "y"])),
            vec![Verdict::ConsumersFirst],
        );
        assert_eq!(
            verdicts(&closed(&["x", "y"]), &closed(&["x"])),
            vec![Verdict::Breaking],
        );
    }

    #[test]
    fn the_transport_contract_is_part_of_the_schema() {
        let base = registry(vec![field("a", FieldType::Integer, Some(true))]);

        let mut rekeyed = base.clone();
        rekeyed.events.get_mut("Ev").expect("Ev").partition_key = "customer".to_owned();
        assert_eq!(
            verdicts(&base, &rekeyed),
            vec![Verdict::Breaking],
            "re-keying changes the ordering guarantee without touching a field",
        );

        let mut moved = base.clone();
        moved.events.get_mut("Ev").expect("Ev").topic = "mev.events.Other".to_owned();
        assert_eq!(verdicts(&base, &moved), vec![Verdict::Breaking]);
    }

    #[test]
    fn a_new_event_type_is_compatible_and_a_removed_one_is_not() {
        let base = registry(vec![field("a", FieldType::Integer, Some(true))]);
        let mut extended = base.clone();
        extended.events.insert(
            "New".to_owned(),
            EventSchema {
                topic: "mev.events.New".to_owned(),
                partition_key: "chain".to_owned(),
                fields: Vec::new(),
            },
        );

        assert_eq!(verdicts(&base, &extended), vec![Verdict::Compatible]);
        assert_eq!(verdicts(&extended, &base), vec![Verdict::Breaking]);
    }

    #[test]
    fn the_committed_registry_is_this_builds_version() {
        // Also proves the compiled-in JSON parses into the current shape: a
        // registry-format change that forgot to re-bless fails here.
        assert_eq!(committed().schema_version, crate::SCHEMA_VERSION);
    }
}
