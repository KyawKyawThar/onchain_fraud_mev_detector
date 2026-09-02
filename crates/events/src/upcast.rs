//! Reading events written under an older schema version (§17).
//!
//! The event store is immutable and retained forever (§4, §18): every event ever
//! written under `v1` stays on disk as `v1`, byte-for-byte. So the moment
//! [`SCHEMA_VERSION`](crate::SCHEMA_VERSION) makes an incompatible move, a
//! current build replaying history is handed bytes that no longer match its
//! [`DomainEvent`](crate::DomainEvent).
//!
//! The answer is an **upcasting chain on read**: a pure `vN → vN+1` transform
//! per event type, run in sequence at the one seam that already inspects the
//! version, so the rest of the codebase only ever sees the current shape. There
//! are no steps at `v1` — there is nothing older to migrate — but the *mechanism*
//! is here and tested, because the alternative is discovering at the first bump
//! that every reader needs changing.
//!
//! ## The rules that keep it working
//!
//! - **Steps are pure and total.** A `vN → vN+1` step is a plain JSON transform:
//!   no I/O, no clock, no failure. It is unit-testable against the archived
//!   corpus (`schema/corpus/`), which is exactly the set of shapes it must
//!   handle.
//! - **A shipped step is never edited.** Old data on disk is forever; a step that
//!   produced the wrong output for some historical event cannot be "fixed" in
//!   place without re-reading all of history. Add another step instead.
//! - **Upcast on read; never rewrite what is stored.** The stored bytes are the
//!   audit record (§4). A log you rewrote to make it decode is not one.
//! - **An incompatible change must actually stop the old shape decoding.**
//!   [`decode`] only reaches for the chain when a direct decode *fails*, so the
//!   hot path pays nothing. That makes one change shape unsafe: renaming a field
//!   to one that is `#[serde(default)]`ed, where the old bytes still decode —
//!   into the default, silently. Don't; the registry gate classifies that as
//!   breaking for exactly this reason.

use serde_json::Value;

use crate::{EventEnvelope, EventError, SCHEMA_VERSION};

/// One `from → from + 1` migration of a single event's envelope JSON.
///
/// `event_type` is `None` for a change to the envelope itself, which applies to
/// every event of that version.
pub struct Upcaster {
    pub from: u16,
    pub event_type: Option<&'static str>,
    pub apply: fn(&mut Value),
}

/// Every migration this build knows, in no particular order — [`upcast`] selects
/// and sequences them by version.
///
/// Empty at `v1`: there is exactly one shape, so there is nothing to migrate.
pub static STEPS: &[Upcaster] = &[];

/// The `type` tag of an adjacently-tagged envelope payload, if it has one.
fn event_type_of(envelope: &Value) -> Option<&str> {
    envelope.get("payload")?.get("type")?.as_str()
}

/// The `schema_version` an envelope document declares.
fn version_of(envelope: &Value) -> Option<u16> {
    envelope.get("schema_version")?.as_u64()?.try_into().ok()
}

/// Migrate `envelope` from the version it declares up to [`SCHEMA_VERSION`].
///
/// Pure: the only failure is being handed a version this build cannot reach.
pub fn upcast(steps: &[Upcaster], envelope: &mut Value) -> Result<(), EventError> {
    upcast_to(steps, envelope, SCHEMA_VERSION)
}

/// Migrate `envelope` from the version it declares up to `to`, running every
/// applicable step of every intervening version in order.
///
/// Both endpoints are explicit so the sequencing is testable at any distance —
/// at `SCHEMA_VERSION` 1 there is no real two-step migration to exercise, and a
/// chain nobody has ever run more than one link of is a chain nobody knows works.
pub fn upcast_to(steps: &[Upcaster], envelope: &mut Value, to: u16) -> Result<(), EventError> {
    let Some(mut version) = version_of(envelope) else {
        return Err(EventError::MissingSchemaVersion);
    };
    if version > to {
        return Err(EventError::UnsupportedSchemaVersion {
            found: version,
            supported: to,
        });
    }

    while version < to {
        let event_type = event_type_of(envelope).map(str::to_owned);
        for step in steps
            .iter()
            .filter(|s| s.from == version && s.event_type.is_none_or_matches(event_type.as_deref()))
        {
            (step.apply)(envelope);
        }
        version += 1;
        if let Some(object) = envelope.as_object_mut() {
            object.insert("schema_version".to_owned(), Value::from(version));
        }
    }
    Ok(())
}

/// Small helper so the filter above reads as one thought.
trait MatchesEventType {
    fn is_none_or_matches(&self, event_type: Option<&str>) -> bool;
}

impl MatchesEventType for Option<&'static str> {
    fn is_none_or_matches(&self, event_type: Option<&str>) -> bool {
        match self {
            None => true,
            Some(wanted) => event_type == Some(*wanted),
        }
    }
}

/// Decode an envelope, migrating it forward first if it was written under an
/// older schema version.
///
/// The current shape is the overwhelmingly common case, so it is the fast path:
/// one direct deserialize, no intermediate tree, byte-identical in cost to not
/// having an upcasting chain at all. Only when that fails does this parse
/// loosely, run the chain, and retry — and if the document was simply malformed,
/// the *original* error is what comes back, not a confusing one from the retry.
pub fn decode(steps: &[Upcaster], bytes: &[u8]) -> Result<EventEnvelope, EventError> {
    let direct = match serde_json::from_slice::<EventEnvelope>(bytes) {
        Ok(envelope) => {
            envelope.ensure_supported()?;
            return Ok(envelope);
        }
        Err(direct) => direct,
    };

    // It may be an older shape. Anything that is not — malformed JSON, a
    // genuinely broken document — falls back to the original error.
    let Ok(mut value) = serde_json::from_slice::<Value>(bytes) else {
        return Err(EventError::Serde(direct));
    };
    let Some(found) = version_of(&value) else {
        return Err(EventError::Serde(direct));
    };
    if found >= SCHEMA_VERSION {
        // Not a historical shape: either too new (a precise error is better
        // than serde's) or simply undecodable at this version.
        return Err(if found > SCHEMA_VERSION {
            EventError::UnsupportedSchemaVersion {
                found,
                supported: SCHEMA_VERSION,
            }
        } else {
            EventError::Serde(direct)
        });
    }

    upcast(steps, &mut value)?;
    serde_json::from_value::<EventEnvelope>(value).map_err(|source| {
        EventError::UnreadableHistoricalEvent {
            found,
            supported: SCHEMA_VERSION,
            source,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::BlockFinalized;
    use crate::primitives::{BlockRef, Chain};
    use crate::DomainEvent;
    use alloy_primitives::B256;
    use serde_json::json;

    fn envelope_json(schema_version: u16, payload: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "event_id": "00000000-0000-0000-0000-000000000e2e",
            "schema_version": schema_version,
            "chain": 1,
            "occurred_at": "2023-11-14T22:13:20Z",
            "payload": payload,
        }))
        .expect("serialize")
    }

    fn current_block_finalized() -> Value {
        json!({
            "type": "BlockFinalized",
            "payload": {"block": {"number": 19_800_000, "hash": format!("0x{}", "11".repeat(32))}},
        })
    }

    /// The `v0` shape used by the fake chain below: `block` was two loose
    /// fields before it was a `BlockRef`. Nothing like this exists on disk —
    /// it is here to exercise the mechanism while `STEPS` is legitimately empty.
    fn v0_block_finalized() -> Value {
        json!({
            "type": "BlockFinalized",
            "payload": {"number": 19_800_000, "hash": format!("0x{}", "11".repeat(32))},
        })
    }

    fn fold_block_fields(envelope: &mut Value) {
        let payload = envelope["payload"]["payload"]
            .as_object_mut()
            .expect("payload object");
        let number = payload.remove("number").expect("number");
        let hash = payload.remove("hash").expect("hash");
        payload.insert("block".to_owned(), json!({"number": number, "hash": hash}));
    }

    fn fake_steps() -> Vec<Upcaster> {
        vec![Upcaster {
            from: 0,
            event_type: Some("BlockFinalized"),
            apply: fold_block_fields,
        }]
    }

    #[test]
    fn a_current_event_never_touches_the_chain() {
        // A step that would corrupt the document proves the fast path skipped it.
        let steps = vec![Upcaster {
            from: SCHEMA_VERSION,
            event_type: None,
            apply: |envelope| {
                envelope["chain"] = json!("wrecked");
            },
        }];
        let bytes = envelope_json(SCHEMA_VERSION, current_block_finalized());

        let envelope = decode(&steps, &bytes).expect("decodes directly");
        assert_eq!(envelope.chain, Chain::ETHEREUM);
        assert_eq!(
            envelope.payload,
            DomainEvent::BlockFinalized(BlockFinalized {
                block: BlockRef::new(19_800_000, B256::repeat_byte(0x11)),
            }),
        );
    }

    #[test]
    fn an_older_shape_is_migrated_forward_and_restamped() {
        let bytes = envelope_json(0, v0_block_finalized());

        let envelope = decode(&fake_steps(), &bytes).expect("a v0 event must still decode");

        assert_eq!(
            envelope.payload,
            DomainEvent::BlockFinalized(BlockFinalized {
                block: BlockRef::new(19_800_000, B256::repeat_byte(0x11)),
            }),
        );
        assert_eq!(
            envelope.schema_version, SCHEMA_VERSION,
            "an upcast event carries the version it was migrated to",
        );
    }

    #[test]
    fn an_older_shape_with_no_step_says_so() {
        let bytes = envelope_json(0, v0_block_finalized());

        let err = decode(&[], &bytes).expect_err("no upcaster for v0");

        assert!(
            matches!(err, EventError::UnreadableHistoricalEvent { found: 0, .. }),
            "expected a historical-event error, got {err:?}",
        );
    }

    #[test]
    fn a_step_for_another_event_type_is_not_applied() {
        let steps = vec![Upcaster {
            from: 0,
            event_type: Some("BlockAssembled"),
            apply: fold_block_fields,
        }];
        let bytes = envelope_json(0, v0_block_finalized());

        assert!(matches!(
            decode(&steps, &bytes),
            Err(EventError::UnreadableHistoricalEvent { .. }),
        ));
    }

    #[test]
    fn malformed_bytes_report_the_original_error() {
        let err = decode(&fake_steps(), b"{not json").expect_err("malformed");
        assert!(matches!(err, EventError::Serde(_)), "got {err:?}");
    }

    #[test]
    fn a_newer_version_is_rejected_precisely() {
        // Structurally fine, but written by a build that knows more than this one.
        let bytes = envelope_json(SCHEMA_VERSION + 1, current_block_finalized());
        assert!(matches!(
            decode(&fake_steps(), &bytes),
            Err(EventError::UnsupportedSchemaVersion { .. }),
        ));

        // Same, for a shape this build cannot even parse.
        let bytes = envelope_json(SCHEMA_VERSION + 1, v0_block_finalized());
        assert!(matches!(
            decode(&fake_steps(), &bytes),
            Err(EventError::UnsupportedSchemaVersion { .. }),
        ));
    }

    #[test]
    fn upcasting_runs_every_intervening_version_in_order() {
        fn note(envelope: &mut Value, step: u64) {
            let run = envelope
                .as_object_mut()
                .expect("envelope object")
                .entry("__steps_run")
                .or_insert_with(|| json!([]));
            run.as_array_mut().expect("array").push(json!(step));
        }

        let steps = [
            Upcaster {
                from: 0,
                event_type: None,
                apply: |e| note(e, 0),
            },
            Upcaster {
                from: 1,
                event_type: None,
                apply: |e| note(e, 1),
            },
            Upcaster {
                from: 2,
                event_type: None,
                apply: |e| note(e, 2),
            },
        ];
        let mut value: Value =
            serde_json::from_slice(&envelope_json(0, current_block_finalized())).expect("parse");

        upcast_to(&steps, &mut value, 3).expect("upcast");

        assert_eq!(
            value["__steps_run"],
            json!([0, 1, 2]),
            "each intervening version's step runs exactly once, in order",
        );
        assert_eq!(
            version_of(&value),
            Some(3),
            "the document is restamped with the version it was migrated to",
        );
    }

    #[test]
    fn an_event_from_the_future_is_never_migrated_downwards() {
        let mut value: Value =
            serde_json::from_slice(&envelope_json(9, current_block_finalized())).expect("parse");

        let err = upcast_to(&[], &mut value, 3).expect_err("9 is beyond 3");

        assert!(
            matches!(
                err,
                EventError::UnsupportedSchemaVersion {
                    found: 9,
                    supported: 3
                }
            ),
            "got {err:?}",
        );
        assert_eq!(version_of(&value), Some(9), "and nothing was rewritten");
    }
}
