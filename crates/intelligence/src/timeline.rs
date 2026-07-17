//! Entity timeline (§8.4, §11): the milestone projection behind
//! `GET /v1/entity/{id}/timeline` — a small, curated, *narrative* history of an
//! entity ("first seen → reclassified to MEV Bot → attributed to a sandwich
//! incident"), distinct from the incident-level forensic
//! `GET /v1/audit/incident/{id}`.
//!
//! Where the audit trail is the full event sequence behind one alert, the
//! timeline is the handful of moments that changed what we know about an
//! *entity*. It is assembled from the facts intelligence already owns, through
//! the existing store seams — no second source of truth:
//!
//! - **first seen** — the entity's own `created_at` ([`crate::store::EntityStore`]).
//! - **classification** — every active label on every member address, with its
//!   kind/value/provenance ([`crate::store::LabelStore`]). A member gaining a
//!   `MevBot`/`Scammer`/`CexWallet` label *is* the "reclassified" narrative,
//!   and a newly-labelled member surfaces the "new linked wallet" it rode in
//!   on.
//! - **notable incidents** — every incident attributed to the entity, with the
//!   attribution's confidence and its `incident_id` for the audit-trail hop
//!   ([`crate::store::AttributionStore`]).
//!
//! The selection/ordering is a **pure function** ([`project_timeline`]) over
//! plain values, so the interesting logic is unit-tested without any store; the
//! async [`entity_timeline`] shell only gathers the inputs and hands them over.
//!
//! Scope note (native-stores projection): per-*link* timestamps and per-*chain*
//! first-activity aren't exposed by the current store seams, so the literal
//! "new linked wallet" / "chain expansion" milestone times aren't reconstructed
//! here — the label milestones stand in for the linked-wallet narrative. When
//! those become queryable (a link-log read, an adjacency by-chain first-seen),
//! they slot in as two more [`MilestoneKind`]s behind the same pure projection.

use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, EntityId, IncidentId};

use crate::model::LabelRecord;
use crate::store::{StoreError, StoreSeams};

/// What kind of moment a [`Milestone`] marks. Carries a derive-driven wire
/// string (the same `strum(serialize_all)` discipline as the storage enums in
/// [`crate::model`]) so the gRPC/HTTP form can't drift from the variant.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr, strum::EnumString, strum::EnumIter,
)]
#[strum(serialize_all = "snake_case")]
pub enum MilestoneKind {
    /// The entity was first observed (its `created_at`).
    FirstSeen,
    /// A label was placed on one of the entity's member addresses.
    Labeled,
    /// An incident was attributed to the entity.
    Incident,
}

/// One curated moment in an entity's history. The `summary` is the human,
/// narrative line; the structured fields carry the same facts for a UI that
/// wants to render its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Milestone {
    pub kind: MilestoneKind,
    pub occurred_at: DateTime<Utc>,
    /// The member address this milestone concerns, if any (a `Labeled`
    /// milestone always has one; `FirstSeen` is entity-level).
    pub address: Option<AccountAddress>,
    /// A one-line narrative rendering of the milestone.
    pub summary: String,
    /// A stable reference for the audit-trail hop: the `incident_id` for an
    /// `Incident`, the `label_id` for a `Labeled` milestone.
    pub reference: Option<String>,
}

/// One member's active labels — the shape [`project_timeline`] consumes, so the
/// async shell hands over exactly what the pure function needs.
pub struct MemberLabels {
    pub address: AccountAddress,
    pub labels: Vec<LabelRecord>,
}

/// One attributed incident — the projection input distilled from an
/// [`crate::model::AttributionRecord`].
pub struct IncidentLink {
    pub incident_id: IncidentId,
    pub confidence: f64,
    pub attributed_at: DateTime<Utc>,
}

/// Build the ordered milestone list from an entity's facts. Pure and total: the
/// same inputs always yield the same timeline, oldest first, with a stable
/// tiebreak (kind, then address, then reference) so two milestones at the same
/// instant never reorder between runs.
pub fn project_timeline(
    created_at: DateTime<Utc>,
    members: &[MemberLabels],
    incidents: &[IncidentLink],
) -> Vec<Milestone> {
    let mut milestones = Vec::new();

    milestones.push(Milestone {
        kind: MilestoneKind::FirstSeen,
        occurred_at: created_at,
        address: None,
        summary: "entity first seen".to_owned(),
        reference: None,
    });

    for member in members {
        for label in &member.labels {
            milestones.push(Milestone {
                kind: MilestoneKind::Labeled,
                occurred_at: label.created_at,
                address: Some(member.address),
                summary: label_summary(label),
                reference: Some(label.label_id.to_string()),
            });
        }
    }

    for incident in incidents {
        milestones.push(Milestone {
            kind: MilestoneKind::Incident,
            occurred_at: incident.attributed_at,
            address: None,
            summary: format!(
                "attributed to incident {} (confidence {:.2})",
                incident.incident_id, incident.confidence
            ),
            reference: Some(incident.incident_id.to_string()),
        });
    }

    milestones.sort_by(|a, b| {
        a.occurred_at
            .cmp(&b.occurred_at)
            .then_with(|| kind_rank(a.kind).cmp(&kind_rank(b.kind)))
            .then_with(|| a.address.cmp(&b.address))
            .then_with(|| a.reference.cmp(&b.reference))
    });
    milestones
}

/// A stable ordering among milestones that share an instant: the entity's birth
/// before anything about it, labels before the incidents they may explain.
fn kind_rank(kind: MilestoneKind) -> u8 {
    match kind {
        MilestoneKind::FirstSeen => 0,
        MilestoneKind::Labeled => 1,
        MilestoneKind::Incident => 2,
    }
}

/// Render a label as a narrative line: `labeled mev_bot "jaredfromsubway.eth"
/// via external_feed` (the value is omitted when empty).
fn label_summary(label: &LabelRecord) -> String {
    let kind: &str = label.kind.into();
    let source: &str = label.source.into();
    if label.value.is_empty() {
        format!("labeled {kind} via {source}")
    } else {
        format!("labeled {kind} {:?} via {source}", label.value)
    }
}

/// Gather an entity's facts through the store seams and project its timeline.
/// Returns `Ok(None)` when the entity is unknown (a 404 at the edge).
///
/// Labels are read as of *now* — the currently-valid classification of each
/// member (revoked/expired labels are excluded by the seam), which is the
/// classification story a caller wants today.
#[tracing::instrument(skip_all, fields(%entity_id))]
pub async fn entity_timeline(
    stores: &StoreSeams,
    entity_id: EntityId,
) -> Result<Option<Vec<Milestone>>, StoreError> {
    let Some(entity) = stores.entities.entity(entity_id).await? else {
        return Ok(None);
    };

    // One batched read for the whole membership instead of a query per member
    // (§8.4 timelines are read on demand — an entity with a wide cluster
    // shouldn't fan out into N Postgres round-trips).
    let now = Utc::now();
    let mut by_address = stores
        .labels
        .labels_for_many(&entity.addresses, now)
        .await?;
    // Preserve the entity's (sorted) member order for a stable projection.
    let members: Vec<MemberLabels> = entity
        .addresses
        .iter()
        .map(|address| MemberLabels {
            address: *address,
            labels: by_address.remove(address).unwrap_or_default(),
        })
        .collect();

    let incidents: Vec<IncidentLink> = stores
        .attributions
        .attributions_for_entity(entity_id)
        .await?
        .into_iter()
        .map(|a| IncidentLink {
            incident_id: a.incident_id,
            confidence: a.confidence.get(),
            attributed_at: a.attributed_at,
        })
        .collect();

    Ok(Some(project_timeline(entity.created_at, &members, &incidents)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LabelKind, LabelRecord, LabelSource};
    use crate::store::{AttributionStore, EntityStore, LabelStore};
    use crate::test_util::{store_seams, InMemoryIntelligenceStore};
    use alloy_primitives::Address;
    use events::primitives::Confidence;
    use std::str::FromStr;
    use std::sync::Arc;
    use strum::IntoEnumIterator;

    fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn label(address: AccountAddress, kind: LabelKind, value: &str, at: DateTime<Utc>) -> LabelRecord {
        LabelRecord::new(address, kind, value, LabelSource::ExternalFeed, "feed", at)
    }

    #[test]
    fn every_milestone_kind_round_trips_its_wire_string() {
        for kind in MilestoneKind::iter() {
            let wire: &str = kind.into();
            assert_eq!(MilestoneKind::from_str(wire), Ok(kind));
        }
        assert_eq!(<&str>::from(MilestoneKind::FirstSeen), "first_seen");
    }

    #[test]
    fn projection_is_first_seen_then_chronological_with_stable_tiebreak() {
        let members = vec![MemberLabels {
            address: addr(1),
            labels: vec![
                label(addr(1), LabelKind::MevBot, "jared", at(300)),
                label(addr(1), LabelKind::KnownScammer, "", at(100)),
            ],
        }];
        let incidents = vec![IncidentLink {
            incident_id: IncidentId(uuid::Uuid::from_u128(9)),
            confidence: 0.9,
            attributed_at: at(200),
        }];

        let timeline = project_timeline(at(50), &members, &incidents);

        let kinds: Vec<MilestoneKind> = timeline.iter().map(|m| m.kind).collect();
        assert_eq!(
            kinds,
            vec![
                MilestoneKind::FirstSeen, // t=50
                MilestoneKind::Labeled,   // t=100 (scammer)
                MilestoneKind::Incident,  // t=200
                MilestoneKind::Labeled,   // t=300 (mev_bot)
            ]
        );
        assert_eq!(timeline[0].summary, "entity first seen");
        assert_eq!(timeline[1].summary, "labeled known_scammer via external_feed");
        assert_eq!(timeline[3].summary, "labeled mev_bot \"jared\" via external_feed");
        assert_eq!(
            timeline[2].reference.as_deref(),
            Some("00000000-0000-0000-0000-000000000009")
        );
    }

    #[test]
    fn co_timed_milestones_order_deterministically_by_kind() {
        // A label and an incident at the very same instant: label before
        // incident (the label may explain the attribution).
        let members = vec![MemberLabels {
            address: addr(1),
            labels: vec![label(addr(1), LabelKind::MevBot, "x", at(100))],
        }];
        let incidents = vec![IncidentLink {
            incident_id: IncidentId(uuid::Uuid::from_u128(1)),
            confidence: 0.5,
            attributed_at: at(100),
        }];
        let timeline = project_timeline(at(100), &members, &incidents);
        let kinds: Vec<MilestoneKind> = timeline.iter().map(|m| m.kind).collect();
        assert_eq!(
            kinds,
            vec![
                MilestoneKind::FirstSeen,
                MilestoneKind::Labeled,
                MilestoneKind::Incident
            ]
        );
    }

    #[tokio::test]
    async fn unknown_entity_is_none() {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let seams = store_seams(&store);
        assert!(entity_timeline(&seams, EntityId::new())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn shell_gathers_entity_labels_and_incidents() {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let seams = store_seams(&store);

        let id = EntityId::new();
        store.create_entity(id, &addr(1), "seed", at(10)).await.unwrap();
        store.link_address(id, &addr(2), "link", at(20)).await.unwrap();
        store
            .add_label(&label(addr(2), LabelKind::MevBot, "bot", at(30)))
            .await
            .unwrap();
        store
            .record_attribution(&crate::model::AttributionRecord {
                incident_id: IncidentId(uuid::Uuid::from_u128(7)),
                entity_id: id,
                confidence: Confidence::new(0.8),
                evidence: "sim".into(),
                attributed_at: at(40),
            })
            .await
            .unwrap();

        let timeline = entity_timeline(&seams, id).await.unwrap().unwrap();
        let kinds: Vec<MilestoneKind> = timeline.iter().map(|m| m.kind).collect();
        assert_eq!(
            kinds,
            vec![
                MilestoneKind::FirstSeen,
                MilestoneKind::Labeled,
                MilestoneKind::Incident
            ]
        );
        // The label milestone names the member it was placed on.
        assert_eq!(timeline[1].address, Some(addr(2)));
        assert_eq!(timeline[2].address, None);
    }

    #[tokio::test]
    async fn revoked_labels_are_excluded_from_the_classification_story() {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let seams = store_seams(&store);

        let id = EntityId::new();
        store.create_entity(id, &addr(1), "seed", at(10)).await.unwrap();
        let l = label(addr(1), LabelKind::MevBot, "bot", at(30));
        store.add_label(&l).await.unwrap();
        store.revoke_label(l.label_id, "wrong", at(40)).await.unwrap();

        let timeline = entity_timeline(&seams, id).await.unwrap().unwrap();
        assert_eq!(
            timeline.iter().filter(|m| m.kind == MilestoneKind::Labeled).count(),
            0,
            "a revoked label is no longer part of the current classification"
        );
    }
}
