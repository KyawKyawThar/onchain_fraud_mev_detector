//! Reading a type's schema off its own codec.
//!
//! Every property in a [`FieldSchema`](super::FieldSchema) is *observed* — a
//! real document that decodes today is mutated, handed back to the real
//! `Deserialize` impl, and the outcome is the answer. Is a field optional?
//! Delete it and see. Is it a closed enum? Feed it an unknown string and read
//! the accepted set out of serde's own error. Is it free-form JSON? Hand it
//! three mutually incompatible values and see if all three are taken.
//!
//! The alternative — deriving a second description with `schemars`/`utoipa` —
//! produces a *claim* about the wire format that is free to disagree with the
//! codec that actually writes it. Probing cannot: there is only one impl, and
//! it is the one being asked.
//!
//! ## The one shape this cannot describe
//!
//! A map with dynamic keys (`HashMap<String, T>`) is indistinguishable from a
//! struct through serde alone — both take an object, both ignore unknown keys —
//! so its *data* keys would be recorded as schema and every new key would read
//! as an added field. `DomainEvent` therefore does not contain one (§17): free
//! form goes in a `serde_json::Value`, which the opacity probe recognises and
//! stops at, and anything with meaningful keys is a `Vec` of pairs.

use serde_json::{json, Value};

use super::{FieldSchema, FieldType};

/// A string no enum variant and no validated format will ever accept.
const UNKNOWN: &str = "__schema_registry_probe__";

/// One step of a path into a document: an object key, or "the first element of
/// this array" (one element is enough — a homogeneous collection's shape is its
/// element's shape).
#[derive(Debug, Clone)]
pub(super) enum Seg {
    Key(String),
    Elem,
}

/// `legs[].chain` — the form used as a [`FieldSchema::path`].
pub(super) fn render(path: &[Seg]) -> String {
    let mut out = String::new();
    for seg in path {
        match seg {
            Seg::Key(k) if out.is_empty() => out.push_str(k),
            Seg::Key(k) => {
                out.push('.');
                out.push_str(k);
            }
            Seg::Elem => out.push_str("[]"),
        }
    }
    out
}

fn node<'v>(root: &'v Value, path: &[Seg]) -> Option<&'v Value> {
    let mut cur = root;
    for seg in path {
        cur = match seg {
            Seg::Key(k) => cur.as_object()?.get(k)?,
            Seg::Elem => cur.as_array()?.first()?,
        };
    }
    Some(cur)
}

fn node_mut<'v>(root: &'v mut Value, path: &[Seg]) -> Option<&'v mut Value> {
    let mut cur = root;
    for seg in path {
        cur = match seg {
            Seg::Key(k) => cur.as_object_mut()?.get_mut(k)?,
            Seg::Elem => cur.as_array_mut()?.get_mut(0)?,
        };
    }
    Some(cur)
}

/// A document that decodes today, plus the decoder that decodes it. Every
/// question is asked by mutating the document and handing it back.
pub(super) struct Probe<'a> {
    doc: Value,
    decode: &'a dyn Fn(&Value) -> Result<(), String>,
}

impl<'a> Probe<'a> {
    pub(super) fn new(doc: Value, decode: &'a dyn Fn(&Value) -> Result<(), String>) -> Self {
        Self { doc, decode }
    }

    /// Decode the document with the field at `path` deleted.
    fn without(&self, path: &[Seg]) -> Result<(), String> {
        let (last, parent) = path.split_last().expect("never called on the root");
        let Seg::Key(key) = last else {
            return Ok(()); // array elements aren't fields; nothing to delete
        };
        let mut doc = self.doc.clone();
        node_mut(&mut doc, parent)
            .and_then(Value::as_object_mut)
            .expect("parent object")
            .remove(key);
        (self.decode)(&doc)
    }

    /// Decode the document with the field at `path` replaced by `value`.
    fn with(&self, path: &[Seg], value: Value) -> Result<(), String> {
        let mut doc = self.doc.clone();
        *node_mut(&mut doc, path).expect("path exists in the document") = value;
        (self.decode)(&doc)
    }
}

/// The variants serde listed in an `unknown variant` error — the only place the
/// *complete* accepted set of a closed enum is observable without a second
/// derive on every type.
///
/// Returns `None` for any other error: a validated format (an address, a hash,
/// a timestamp) also rejects [`UNKNOWN`], but it fails differently. If serde
/// ever rewords this message the set comes back empty and the field reads as a
/// validated string, which the compatibility gate reports as a change rather
/// than passing silently — see the canary test below.
fn accepted_variants(err: &str) -> Option<Vec<String>> {
    let (_, rest) = err.split_once("unknown variant")?;
    let (_, expected) = rest.split_once("expected")?;
    // serde renders the set as `a`, `b`, `c` (or a single `a`); the quoted
    // tokens are the odd-indexed pieces of a backtick split.
    let variants: Vec<String> = expected
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect();
    (!variants.is_empty()).then_some(variants)
}

/// Walk `probe`'s document below `path`, emitting one [`FieldSchema`] per node.
///
/// `base` is how many leading segments belong to the container (the `payload`
/// wrapper) and are stripped from the rendered path; `stop_at` names rendered
/// paths whose interior another entry already covers.
pub(super) fn walk(
    probe: &Probe,
    path: &mut Vec<Seg>,
    base: usize,
    stop_at: &[&str],
    out: &mut Vec<FieldSchema>,
) {
    let value = node(&probe.doc, path)
        .expect("walking a path we just took")
        .clone();
    let rendered = render(&path[base..]);

    if !rendered.is_empty() {
        let ty = describe_node(probe, path, &value);
        let opaque = ty == FieldType::Any;
        out.push(FieldSchema {
            path: rendered.clone(),
            // An array element is a position, not a field — nothing to omit.
            required: (!matches!(path.last(), Some(Seg::Elem)))
                .then(|| probe.without(path).is_err()),
            ty,
        });

        if opaque || stop_at.contains(&rendered.as_str()) {
            return;
        }
    }

    match value {
        Value::Object(fields) => {
            for key in fields.keys() {
                path.push(Seg::Key(key.clone()));
                walk(probe, path, base, stop_at, out);
                path.pop();
            }
        }
        Value::Array(items) => {
            assert!(
                !items.is_empty(),
                "the fixture for {rendered} is an empty array — a collection with \
                 no element describes no shape; populate it in events::schema::fixtures",
            );
            path.push(Seg::Elem);
            walk(probe, path, base, stop_at, out);
            path.pop();
        }
        _ => {}
    }
}

fn describe_node(probe: &Probe, path: &[Seg], value: &Value) -> FieldType {
    // Free-form JSON accepts anything; three mutually incompatible values
    // separate it from every typed field (a bool field takes the bool, a string
    // field takes the string, neither takes all three).
    let opaque = [json!(true), json!(UNKNOWN), json!([1, "two"])]
        .into_iter()
        .all(|v| probe.with(path, v).is_ok());
    if opaque {
        return FieldType::Any;
    }

    match value {
        Value::Null => FieldType::Null,
        Value::Bool(_) => FieldType::Boolean,
        Value::Number(n) if n.is_f64() => FieldType::Float,
        Value::Number(_) => FieldType::Integer,
        Value::Array(_) => FieldType::Array,
        Value::Object(_) => FieldType::Object,
        Value::String(_) => match probe.with(path, json!(UNKNOWN)) {
            Ok(()) => FieldType::String,
            Err(err) => match accepted_variants(&err) {
                Some(values) => FieldType::Enum { values },
                None => FieldType::ValidatedString,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    /// A canary for the one piece of this file that depends on the *wording* of
    /// somebody else's error message. It is pinned against a local enum rather
    /// than a domain type, so a serde upgrade that rewords `unknown variant`
    /// reads as "serde's error format changed" here, instead of showing up as
    /// "`AlertKind` stopped being an enum" in the compatibility report.
    #[test]
    fn the_unknown_variant_parse_tracks_serde() {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Canary {
            First,
            SecondOne,
        }

        let err = serde_json::from_value::<Canary>(json!(UNKNOWN))
            .expect_err("an unknown variant must not decode")
            .to_string();

        assert_eq!(
            accepted_variants(&err).as_deref(),
            Some(["first".to_owned(), "second_one".to_owned()].as_slice()),
            "serde's `unknown variant` message no longer parses: {err}",
        );
    }

    #[test]
    fn a_single_variant_enum_still_parses() {
        #[derive(Debug, Deserialize)]
        enum Only {
            Alone,
        }

        let err = serde_json::from_value::<Only>(json!(UNKNOWN))
            .expect_err("unknown variant")
            .to_string();
        assert_eq!(
            accepted_variants(&err).as_deref(),
            Some(["Alone".to_owned()].as_slice())
        );
    }

    #[test]
    fn a_validated_string_is_not_mistaken_for_an_enum() {
        // An address rejects the probe string, but not with `unknown variant`.
        let err = serde_json::from_value::<alloy_primitives::Address>(json!(UNKNOWN))
            .expect_err("not an address")
            .to_string();
        assert_eq!(accepted_variants(&err), None, "misread as an enum: {err}");
    }

    #[test]
    fn paths_render_through_arrays() {
        let path = vec![
            Seg::Key("legs".to_owned()),
            Seg::Elem,
            Seg::Key("block".to_owned()),
            Seg::Key("hash".to_owned()),
        ];
        assert_eq!(render(&path), "legs[].block.hash");
    }
}
