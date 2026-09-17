//! Measurements keyed on the build they were taken from (§18, Epic E).
//!
//! A precision number is a fact about one detector **build**: an
//! `(id, version, config_hash)` triple. Lower a threshold and the number
//! describes a detector that no longer runs. So everything this workspace
//! persists about a detector's measured quality (the backtest's regression
//! baseline, the model cards' performance store) is a [`BuildKeyed`] store,
//! and every reader asks one question through [`BuildKeyed::lookup`]:
//!
//! | [`Lookup`] | meaning | baseline gate | model card |
//! |---|---|---|---|
//! | `Current` | measured on exactly the running build | compare for a regression | show it |
//! | `Stale` | measured on another build of this id | `REBUILT` | stays unmeasured, counted |
//! | `Missing` | never measured | not gated | stays unmeasured |
//!
//! "Stale" is a variant, not a `bool` beside the value, so a caller cannot
//! read the numbers without first deciding what a stale entry means to it.
//!
//! [`Build`] is the one typed identity. The wire [`DetectorRef`] (plain
//! strings) is converted at the edge ([`Build::from_ref`] / [`Build::to_ref`])
//! and never compared field by field.

use std::collections::BTreeMap;

use events::primitives::DetectorRef;
use serde::{Deserialize, Serialize};

use crate::model::{ConfigHash, ConfigHashParseError};
use detector_api::{SemVer, SemVerParseError};

/// A detector build: the `(id, version, config_hash)` triple, typed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Build {
    pub id: String,
    pub version: SemVer,
    pub config_hash: ConfigHash,
}

/// A wire [`DetectorRef`] that does not name a valid build.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildParseError {
    #[error("detector {id}: {source}")]
    Version {
        id: String,
        #[source]
        source: SemVerParseError,
    },
    #[error("detector {id}: {source}")]
    ConfigHash {
        id: String,
        #[source]
        source: ConfigHashParseError,
    },
}

impl Build {
    pub fn new(id: impl Into<String>, version: SemVer, config_hash: ConfigHash) -> Self {
        Self {
            id: id.into(),
            version,
            config_hash,
        }
    }

    /// Parse a wire triple. Every triple this workspace emits parses; the
    /// error exists for triples read back from outside the process.
    pub fn from_ref(r: &DetectorRef) -> Result<Self, BuildParseError> {
        Ok(Self {
            id: r.id.clone(),
            version: r
                .version
                .parse()
                .map_err(|source| BuildParseError::Version {
                    id: r.id.clone(),
                    source,
                })?,
            config_hash: r
                .config_hash
                .parse()
                .map_err(|source| BuildParseError::ConfigHash {
                    id: r.id.clone(),
                    source,
                })?,
        })
    }

    /// The wire form stamped onto every `DetectorTriggered`.
    pub fn to_ref(&self) -> DetectorRef {
        DetectorRef {
            id: self.id.clone(),
            version: self.version.to_string(),
            config_hash: self.config_hash.to_hex(),
        }
    }
}

/// `v1.2.0 cfg 410e44c54bb0` — the id is left to the caller's column, and the
/// hash is cut to 12 hex digits: enough to tell two builds apart by eye, while
/// the committed files keep all 64.
impl std::fmt::Display for Build {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = self.config_hash.to_hex();
        write!(f, "v{} cfg {}", self.version, &hex[..12])
    }
}

/// One measurement and the build it describes. The id is the key of the
/// [`BuildKeyed`] map that holds it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measured<T> {
    /// Rendered `"1.2.0"`, as in [`DetectorRef::version`].
    #[serde(with = "semver_text")]
    pub version: SemVer,
    pub config_hash: ConfigHash,
    pub metrics: T,
}

impl<T> Measured<T> {
    /// The build this entry was measured on, for the detector `id`.
    pub fn build(&self, id: &str) -> Build {
        Build::new(id, self.version, self.config_hash.clone())
    }

    fn describes(&self, running: &Build) -> bool {
        self.version == running.version && self.config_hash == running.config_hash
    }
}

/// What a store knows about the running build of one detector.
#[derive(Debug, Clone, PartialEq)]
pub enum Lookup<'a, T> {
    /// Measured on exactly this build.
    Current(&'a T),
    /// Measured on a different build of the same detector.
    Stale { measured: Build },
    /// Never measured.
    Missing,
}

/// A stored measurement that no longer describes the build that runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleMeasurement {
    pub running: Build,
    pub measured: Build,
}

/// Measurements keyed by detector id, each naming its build.
///
/// A `BTreeMap` underneath so a committed file diffs one detector at a time.
/// Serialized as `{ "<id>": { "version", "config_hash", "metrics": {…} } }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: Deserialize<'de>"))]
pub struct BuildKeyed<T>(BTreeMap<String, Measured<T>>);

impl<T> Default for BuildKeyed<T> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<T> BuildKeyed<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Record `metrics` as measured on `build`, replacing any earlier entry
    /// for that id.
    pub fn insert(&mut self, build: &Build, metrics: T) {
        self.0.insert(
            build.id.clone(),
            Measured {
                version: build.version,
                config_hash: build.config_hash.clone(),
                metrics,
            },
        );
    }

    /// The raw entry for `id`, whatever build it names — for tooling that
    /// prints or rewrites the file. Readers that act on a measurement use
    /// [`lookup`](Self::lookup).
    pub fn get(&self, id: &str) -> Option<&Measured<T>> {
        self.0.get(id)
    }

    /// Every entry, in id order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Measured<T>)> {
        self.0.iter().map(|(id, m)| (id.as_str(), m))
    }

    /// What this store knows about `running` (see the module docs).
    pub fn lookup(&self, running: &Build) -> Lookup<'_, T> {
        match self.0.get(&running.id) {
            Some(m) if m.describes(running) => Lookup::Current(&m.metrics),
            Some(m) => Lookup::Stale {
                measured: m.build(&running.id),
            },
            None => Lookup::Missing,
        }
    }

    /// Every entry that names a different build from the one running, among
    /// `running`. An entry for a detector not in `running` is not stale; it
    /// is simply not linked by this binary.
    pub fn stale_against<'b>(
        &self,
        running: impl IntoIterator<Item = &'b Build>,
    ) -> Vec<StaleMeasurement> {
        running
            .into_iter()
            .filter_map(|build| match self.lookup(build) {
                Lookup::Stale { measured } => Some(StaleMeasurement {
                    running: build.clone(),
                    measured,
                }),
                Lookup::Current(_) | Lookup::Missing => None,
            })
            .collect()
    }
}

impl<T> FromIterator<(Build, T)> for BuildKeyed<T> {
    fn from_iter<I: IntoIterator<Item = (Build, T)>>(iter: I) -> Self {
        let mut store = Self::new();
        for (build, metrics) in iter {
            store.insert(&build, metrics);
        }
        store
    }
}

/// `SemVer` as its dotted wire text. The derived serde would write an object.
pub(crate) mod semver_text {
    use detector_api::SemVer;
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(version: &SemVer, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(version)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SemVer, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

/// Canonical JSON bytes of `value`: object keys sorted at every depth, no
/// whitespace, scalars as `serde_json` writes them.
///
/// Sorted explicitly rather than by relying on `serde_json::Value`'s map
/// order: that order is a cargo feature (`preserve_order`) which any crate in
/// the build graph can switch on, and feature unification would then change
/// every config hash with no compile error. The golden hashes in
/// `boot::tests` pin the output.
pub fn canonical_json(value: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &serde_json::Value, out: &mut Vec<u8>) {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            out.push(b'{');
            for (i, (key, value)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key).expect("writing to a Vec cannot fail");
                out.push(b':');
                write_canonical(value, out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        scalar => serde_json::to_writer(&mut *out, scalar).expect("writing to a Vec cannot fail"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn build(id: &str, version: SemVer, cfg: &str) -> Build {
        Build::new(id, version, ConfigHash::of_bytes(cfg.as_bytes()))
    }

    #[test]
    fn lookup_distinguishes_current_stale_and_missing() {
        let running = build("sandwich", SemVer::new(1, 2, 0), "a");
        let store: BuildKeyed<u32> = [(running.clone(), 7)].into_iter().collect();

        assert_eq!(store.lookup(&running), Lookup::Current(&7));

        let reconfigured = build("sandwich", SemVer::new(1, 2, 0), "b");
        assert_eq!(
            store.lookup(&reconfigured),
            Lookup::Stale {
                measured: running.clone()
            }
        );
        let bumped = build("sandwich", SemVer::new(1, 3, 0), "a");
        assert!(matches!(store.lookup(&bumped), Lookup::Stale { .. }));

        assert_eq!(
            store.lookup(&build("arb", SemVer::new(1, 0, 0), "a")),
            Lookup::Missing
        );
    }

    #[test]
    fn stale_against_names_both_builds_and_ignores_unlinked_entries() {
        let measured = build("sandwich", SemVer::new(1, 2, 0), "a");
        let retired = build("retired", SemVer::new(1, 0, 0), "a");
        let store: BuildKeyed<u32> = [(measured.clone(), 1), (retired, 1)].into_iter().collect();

        let running = [
            build("sandwich", SemVer::new(1, 2, 0), "b"),
            build("arb", SemVer::new(1, 0, 0), "a"),
        ];
        assert_eq!(
            store.stale_against(&running),
            vec![StaleMeasurement {
                running: running[0].clone(),
                measured,
            }]
        );
    }

    #[test]
    fn the_wire_shape_is_versioned_text_plus_nested_metrics() {
        let b = build("sandwich", SemVer::new(1, 2, 0), "a");
        let store: BuildKeyed<u32> = [(b.clone(), 7)].into_iter().collect();
        let json = serde_json::to_value(&store).unwrap();
        assert_eq!(
            json,
            json!({ "sandwich": {
                "version": "1.2.0",
                "config_hash": b.config_hash.to_hex(),
                "metrics": 7,
            }})
        );
        let back: BuildKeyed<u32> = serde_json::from_value(json).unwrap();
        assert_eq!(back, store);
    }

    #[test]
    fn an_entry_without_its_build_or_with_extra_fields_is_refused() {
        let legacy = json!({ "sandwich": { "metrics": 7 } });
        assert!(serde_json::from_value::<BuildKeyed<u32>>(legacy).is_err());

        let b = build("sandwich", SemVer::new(1, 2, 0), "a");
        let extra = json!({ "sandwich": {
            "version": "1.2.0", "config_hash": b.config_hash.to_hex(),
            "metrics": 7, "note": "hand edit",
        }});
        assert!(serde_json::from_value::<BuildKeyed<u32>>(extra).is_err());
    }

    #[test]
    fn a_build_round_trips_through_its_wire_ref() {
        let b = build("sandwich", SemVer::new(1, 2, 0), "a");
        assert_eq!(Build::from_ref(&b.to_ref()).unwrap(), b);

        let mut bad = b.to_ref();
        bad.config_hash = "cfg-abc".into();
        assert!(matches!(
            Build::from_ref(&bad),
            Err(BuildParseError::ConfigHash { .. })
        ));
        let mut bad = b.to_ref();
        bad.version = "1.2".into();
        assert!(matches!(
            Build::from_ref(&bad),
            Err(BuildParseError::Version { .. })
        ));
    }

    #[test]
    fn display_is_version_and_a_short_hash() {
        let b = build("sandwich", SemVer::new(1, 2, 0), "a");
        let shown = b.to_string();
        assert_eq!(
            shown,
            format!("v1.2.0 cfg {}", &b.config_hash.to_hex()[..12])
        );
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_depth() {
        let a: serde_json::Value =
            serde_json::from_str(r#"{"b":{"y":1,"x":[{"q":1,"p":2}]},"a":1.5}"#).unwrap();
        assert_eq!(
            String::from_utf8(canonical_json(&a)).unwrap(),
            r#"{"a":1.5,"b":{"x":[{"p":2,"q":1}],"y":1}}"#
        );
    }

    #[test]
    fn canonical_json_agrees_with_serde_json_on_sorted_input() {
        // The encoding the committed hashes were first taken with.
        let v = json!({ "min_profit_usd": 10.0, "window_blocks": 100, "s": "x\"y", "n": null });
        assert_eq!(canonical_json(&v), serde_json::to_vec(&v).unwrap());
    }
}
