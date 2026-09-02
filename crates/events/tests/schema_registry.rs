//! The compatibility gate (§17) — the I/O shell around [`events::schema`].
//!
//! The engine is a library: describing a type from its own codec, and
//! classifying the difference between two descriptions, are pure functions any
//! crate can call. This file is the part that cannot be: reading what is
//! committed, walking the archive, failing the build, and rewriting the
//! committed schema when a change is deliberate.
//!
//! ## What is committed
//!
//! ```text
//! schema/v<N>/registry.json    the schema of every event at SCHEMA_VERSION N
//! schema/corpus/<Event>/*.json every distinct shape ever emitted, append-only
//! ```
//!
//! The two have different lifetimes on purpose. `registry.json` is the *current*
//! belief at version N and is rewritten whenever a compatible change lands (a
//! new event, a defaulted field). The corpus is an **archive**: a shape is added
//! the first time it is seen and never rewritten or removed, because the bytes
//! it describes are sitting in the event store forever (§4, §18). A registry
//! that could be rewritten *and* served as the archive would quietly lose the
//! pre-change shape on the very blessing that introduced the change — which is
//! the failure this split exists to prevent.
//!
//! ## The gate
//!
//! - [`registry_matches_the_committed_schema`] — regenerate and diff. **Any**
//!   difference fails the build, classified: *compatible* (re-bless),
//!   *consumers first* (a new closed-enum value: consumers deploy before the
//!   producer), *breaking* (a removed/retyped/newly-required field, a moved
//!   topic, a re-keyed partition, a removed event type), which blessing refuses.
//! - [`every_archived_shape_still_decodes`] — replay the whole corpus through
//!   today's reader. After a `SCHEMA_VERSION` bump this is the test that stays
//!   red until the [`events::upcast`] step for the old shape exists.
//! - [`todays_shapes_are_in_the_archive`] — the corpus is not allowed to lag the
//!   code, or the replay above would be checking shapes nobody emits.
//! - [`readers_ignore_fields_from_a_newer_producer`] — the forward half.
//!
//! ## Changing the schema on purpose
//!
//! ```sh
//! just schema-bless
//! ```
//!
//! It rewrites the current version's registry, *appends* any new shape to the
//! archive, and refuses outright if the change is breaking — the version bump is
//! the only way through, and that is the point.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use events::schema::{self, fixtures, Registry, Verdict};
use events::{DomainEvent, EventEnvelope, SCHEMA_VERSION};
use serde::Serialize;
use serde_json::{json, Value};

// ── Where the committed schema lives ─────────────────────────────

fn schema_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("schema")
}

fn version_dir(version: u16) -> PathBuf {
    schema_dir().join(format!("v{version}"))
}

fn corpus_dir() -> PathBuf {
    schema_dir().join("corpus")
}

/// Every archived shape, as `(source file, envelope document)`.
fn corpus() -> Vec<(PathBuf, Value)> {
    let mut shapes = Vec::new();
    let dir = corpus_dir();
    let events = fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!(
            "no corpus at {} ({e}) — run `just schema-bless`",
            dir.display()
        )
    });

    for event in events {
        let event = event.expect("read corpus entry").path();
        if !event.is_dir() {
            continue;
        }
        for shape in fs::read_dir(&event).expect("read event corpus") {
            let path = shape.expect("read shape").path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let bytes = fs::read(&path).expect("read shape");
            let value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()));
            shapes.push((path, value));
        }
    }
    shapes.sort_by(|(a, _), (b, _)| a.cmp(b));
    shapes
}

/// The canonical bytes of one archived shape — pretty-printed with sorted keys,
/// so "have we seen this shape before?" is a byte comparison.
fn canonical(value: &Value) -> String {
    let mut json = serde_json::to_string_pretty(value).expect("serialize");
    json.push('\n');
    json
}

/// Today's fixtures, wrapped in the fixed envelope metadata: event type → doc.
fn todays_shapes() -> BTreeMap<String, Value> {
    fixtures::sample_events()
        .into_iter()
        .map(|event| {
            let name = event.event_type().to_owned();
            let value = serde_json::to_value(fixtures::envelope_for(event)).expect("serialize");
            (name, value)
        })
        .collect()
}

// ── The gate ─────────────────────────────────────────────────────

#[test]
fn registry_matches_the_committed_schema() {
    let committed = schema::committed();
    let generated = schema::generate();
    let changes = schema::compare(&committed, &generated);

    if changes.is_empty() {
        assert_eq!(
            committed, generated,
            "the schemas classify as identical but do not serialize identically — \
             re-bless with `just schema-bless`",
        );
        return;
    }

    let breaking = changes.iter().any(|c| c.verdict == Verdict::Breaking);
    assert!(
        !breaking,
        "the event schema changed incompatibly at SCHEMA_VERSION {SCHEMA_VERSION}:\n{}\n\
         \n  A producer and a consumer can no longer deploy independently, and \
         events already in the store stop decoding.\n  If the change is wanted: \
         bump events::SCHEMA_VERSION, point events::schema::COMMITTED at the new \
         directory, add the v{SCHEMA_VERSION} → v{} step in events::upcast, then \
         `just schema-bless`.\n  If it is not: put the field back.",
        schema::report(&changes),
        SCHEMA_VERSION + 1,
    );

    panic!(
        "the event schema changed compatibly at SCHEMA_VERSION {SCHEMA_VERSION}:\n{}\n\
         \n  Nothing here breaks a reader of archived events. Re-commit the schema \
         so the next change is measured against this one: `just schema-bless`.",
        schema::report(&changes),
    );
}

/// The backward half, over the whole archive: every shape ever emitted must
/// decode under *today's* reader — through [`events::upcast`] where it is old.
#[test]
fn every_archived_shape_still_decodes() {
    let shapes = corpus();
    assert!(!shapes.is_empty(), "the archive is empty");

    for (path, value) in shapes {
        let expected = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            .expect("corpus layout is corpus/<EventType>/<n>.json")
            .to_owned();
        let version = value
            .get("schema_version")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("{} has no schema_version", path.display()));

        let bytes = serde_json::to_vec(&value).expect("re-serialize archived shape");
        let decoded = EventEnvelope::from_json_slice(&bytes).unwrap_or_else(|e| {
            panic!(
                "{} no longer decodes: {e}\n  This is a real shape that was written \
                 to the event store under schema version {version}. Reading it is not \
                 optional — add the migration step in events::upcast rather than \
                 changing the archive.",
                path.display(),
            )
        });

        assert_eq!(
            decoded.event_type(),
            expected,
            "{} is filed under the wrong event type",
            path.display(),
        );
        assert_eq!(
            decoded.schema_version,
            SCHEMA_VERSION,
            "{} decoded but was not brought up to the current version",
            path.display(),
        );
    }
}

/// The archive must contain what the code emits *today*, or the replay above is
/// only proving that yesterday's shapes still work.
#[test]
fn todays_shapes_are_in_the_archive() {
    let archived: BTreeSet<String> = corpus().iter().map(|(_, value)| canonical(value)).collect();

    let missing: Vec<String> = todays_shapes()
        .into_iter()
        .filter(|(_, value)| !archived.contains(&canonical(value)))
        .map(|(name, _)| name)
        .collect();

    assert!(
        missing.is_empty(),
        "the archive does not contain the current shape of: {}\n  Run \
         `just schema-bless` — it appends new shapes and never rewrites old ones.",
        missing.join(", "),
    );
}

/// Every event type has at least one archived shape, so a new event cannot be
/// added without its first shape being recorded.
#[test]
fn every_event_type_is_archived() {
    use strum::VariantNames;

    let archived: BTreeSet<String> = corpus()
        .iter()
        .filter_map(|(path, _)| {
            path.parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .map(str::to_owned)
        })
        .collect();

    let variants: BTreeSet<String> = DomainEvent::VARIANTS
        .iter()
        .map(|v| (*v).to_owned())
        .collect();
    assert_eq!(
        variants.difference(&archived).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "these event types have no archived shape — run `just schema-bless`",
    );
    assert_eq!(
        archived.difference(&variants).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "the archive holds event types the schema no longer has; a retired event's \
         history is still replayed, so the variant must stay (§18)",
    );
}

/// The complete registry history is committed: a deleted version directory would
/// silently narrow what the gate measures.
#[test]
fn every_schema_version_is_committed() {
    for version in 1..=SCHEMA_VERSION {
        let path = version_dir(version).join("registry.json");
        assert!(
            path.exists(),
            "{} is missing — every schema version keeps its directory forever",
            path.display(),
        );
    }
    let unexpected = version_dir(SCHEMA_VERSION + 1);
    assert!(
        !unexpected.exists(),
        "{} exists but SCHEMA_VERSION is still {SCHEMA_VERSION} — the constant and \
         the registry must be bumped together",
        unexpected.display(),
    );
}

/// The forward half: a consumer built against this version must tolerate an
/// event a *newer* producer wrote — one carrying fields it has never heard of.
/// Without this, adding a field would require every consumer to be redeployed
/// first, which is the independent-deploy property the registry exists to
/// protect.
#[test]
fn readers_ignore_fields_from_a_newer_producer() {
    fn inject(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (_, v) in map.iter_mut() {
                    inject(v);
                }
                map.insert(
                    "__field_from_a_newer_producer__".to_owned(),
                    json!({"a": [1]}),
                );
            }
            Value::Array(items) => items.iter_mut().for_each(inject),
            _ => {}
        }
    }

    for (event_type, mut doc) in todays_shapes() {
        // The adjacently-tagged wrapper (`{"type":…,"payload":…}`) is serde's own
        // frame, not a struct anyone adds fields to; inject into the envelope and
        // into the event's own payload object.
        inject(
            doc.get_mut("payload")
                .and_then(|p| p.get_mut("payload"))
                .expect("adjacently-tagged payload"),
        );
        let Value::Object(map) = &mut doc else {
            unreachable!("an envelope is an object")
        };
        map.insert(
            "__field_from_a_newer_producer__".to_owned(),
            json!("v-next"),
        );

        let bytes = serde_json::to_vec(&doc).expect("serialize");
        EventEnvelope::from_json_slice(&bytes).unwrap_or_else(|e| {
            panic!(
                "{event_type} stops decoding once a newer producer adds a field: {e}\n  \
                 Readers must ignore what they don't know (no `deny_unknown_fields` \
                 anywhere on the event schema) or no producer can ever ship before \
                 its consumers.",
            )
        });
    }
}

/// The registry is only as good as the fixtures it is probed from: a `null` or
/// an empty collection describes no shape, so a retype underneath one would pass
/// the gate unnoticed.
#[test]
fn fixtures_describe_every_field() {
    fn check(path: &str, value: &Value) {
        match value {
            Value::Null => panic!(
                "{path} is null in the fixtures — an unset field has no observable \
                 type, so the compatibility gate goes blind there. Make it `Some(…)` \
                 in events::schema::fixtures and re-bless.",
            ),
            Value::Array(items) => {
                assert!(
                    !items.is_empty(),
                    "{path} is an empty array in the fixtures — populate it in \
                     events::schema::fixtures and re-bless",
                );
                for (i, item) in items.iter().enumerate() {
                    check(&format!("{path}[{i}]"), item);
                }
            }
            Value::Object(map) => {
                for (key, v) in map {
                    check(&format!("{path}.{key}"), v);
                }
            }
            _ => {}
        }
    }

    for (event_type, doc) in todays_shapes() {
        check(&event_type, &doc);
    }
}

// ── The probes, pinned against the real schema ───────────────────
// The library's own unit tests cover the classifier and the error-message parse.
// These pin the *generated* description of real events, which is where a probe
// silently changing its mind would show up first.

#[test]
fn probes_read_optionality_off_the_real_codec() {
    let registry = schema::generate();
    let field = |path: &str| {
        registry
            .field("PreliminaryAlertCreated", path)
            .unwrap_or_else(|| panic!("no {path} in the generated schema"))
    };

    // `#[serde(default …)]`, added by the §15 scoring pass — the property the
    // legacy-decode tests in wire_format.rs exercise by hand.
    assert_eq!(
        field("severity").required,
        Some(false),
        "severity is defaulted on read"
    );
    assert_eq!(field("impact_usd").required, Some(false));
    // No default: an alert without an id is not an alert.
    assert_eq!(field("alert_id").required, Some(true));
    // An element of `addresses` is a position in a list, not an omittable field.
    assert_eq!(field("addresses[]").required, None);
}

#[test]
fn probes_recover_the_variants_of_a_closed_enum() {
    let registry = schema::generate();
    let kind = registry
        .field("PreliminaryAlertCreated", "kind")
        .expect("kind");

    let schema::FieldType::Enum { values } = &kind.ty else {
        panic!("AlertKind is a closed enum, got {:?}", kind.ty);
    };
    assert!(
        values.contains(&"sandwich".to_owned()) && values.contains(&"anomaly".to_owned()),
        "expected the AlertKind wire values, got {values:?}",
    );
}

#[test]
fn probes_separate_free_form_json_from_typed_fields() {
    let registry = schema::generate();
    let triggered = &registry.events["DetectorTriggered"];

    // Detector evidence is a `serde_json::Value`: its interior is payload, not
    // schema, and the walk must not descend into it and pin a shape.
    assert_eq!(
        registry
            .field("DetectorTriggered", "evidence")
            .map(|f| &f.ty),
        Some(&schema::FieldType::Any),
    );
    assert!(
        !triggered
            .fields
            .iter()
            .any(|f| f.path.starts_with("evidence.")),
        "the walk descended into free-form JSON",
    );
    // …while a validated string next to it is neither `any` nor free-form.
    assert_eq!(
        registry.field("DetectorTriggered", "txs[]").map(|f| &f.ty),
        Some(&schema::FieldType::ValidatedString),
        "a 32-byte hash rejects arbitrary strings",
    );
}

#[test]
fn the_transport_contract_is_generated_from_the_real_envelope() {
    let registry = schema::generate();

    let block = &registry.events["BlockFinalized"];
    assert_eq!(block.topic, "mev.events.BlockFinalized");
    assert_eq!(block.partition_key, "chain", "the §20 default");

    // §13: metering is customer-keyed, not chain-keyed. If that ever changes
    // silently, every consumer's ordering guarantee changes with it.
    assert_eq!(registry.events["UsageRecorded"].partition_key, "customer");
    // §7: the simulation lifecycle co-partitions on its business key.
    assert_eq!(registry.events["IncidentCreated"].partition_key, "alert");
    assert_eq!(
        registry.events["IncidentFinalized"].partition_key,
        "incident"
    );
}

// ── Re-committing the schema ─────────────────────────────────────

/// Rewrite the current version's registry and append any new shape to the
/// archive.
///
/// ```sh
/// just schema-bless
/// ```
///
/// Refuses a breaking change outright: at that point the answer is a
/// `SCHEMA_VERSION` bump (which makes this write a fresh directory and leave the
/// old one frozen), never an overwrite of what consumers and the event store
/// already believe. The archive is append-only in either case — a shape that has
/// ever been emitted is never rewritten or deleted.
#[test]
#[ignore = "manual: rewrites the committed schema"]
fn bless() {
    let generated = schema::generate();
    let dir = version_dir(SCHEMA_VERSION);

    match schema::try_committed() {
        // Nothing readable to compare against: the first bless of a version, or
        // a change to the registry *file format* itself. Regenerating is the
        // fix, not a decision about compatibility.
        Err(why) if dir.join("registry.json").exists() => {
            println!("regenerating v{SCHEMA_VERSION} from scratch — {why}");
        }
        Err(_) => {}
        Ok(committed) => {
            let changes = schema::compare(&committed, &generated);
            assert!(
                !changes.iter().any(|c| c.verdict == Verdict::Breaking),
                "refusing to overwrite the committed v{SCHEMA_VERSION} schema with an \
             incompatible one:\n{}\n\n  Bump events::SCHEMA_VERSION, point \
             events::schema::COMMITTED at the new directory and add the migration \
             step (SCHEMA.md); this will then write v{} and leave v{SCHEMA_VERSION} \
             as the archive it is.",
                schema::report(&changes),
                SCHEMA_VERSION + 1,
            );
        }
    }

    fs::create_dir_all(&dir).expect("create the version directory");
    write_json(&dir.join("registry.json"), &generated);

    let mut added = 0;
    for (event_type, value) in todays_shapes() {
        added += usize::from(archive(&event_type, &value));
    }
    println!("wrote {} ({added} new shape(s) archived)", dir.display(),);
}

/// Add `value` to the archive if this exact shape has never been seen. Returns
/// whether it was new. Existing files are never touched: they describe bytes
/// that are already on disk somewhere.
fn archive(event_type: &str, value: &Value) -> bool {
    let dir = corpus_dir().join(event_type);
    fs::create_dir_all(&dir).expect("create the event's corpus directory");
    let bytes = canonical(value);

    let mut next = 1;
    for entry in fs::read_dir(&dir).expect("read the event's corpus") {
        let path = entry.expect("read shape").path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        if fs::read_to_string(&path).expect("read shape") == bytes {
            return false;
        }
        next += 1;
    }

    fs::write(dir.join(format!("{next:03}.json")), bytes).expect("write shape");
    true
}

fn write_json<T: Serialize>(path: &Path, value: &T) {
    let mut json = serde_json::to_string_pretty(value).expect("serialize");
    json.push('\n');
    fs::write(path, json).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// Sanity: the registry the engine generates is the one that gets written, and
/// it round-trips through the committed file format.
#[test]
fn the_registry_round_trips_through_its_file_format() {
    let generated = schema::generate();
    let json = serde_json::to_string_pretty(&generated).expect("serialize");
    let parsed: Registry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, generated);
}
