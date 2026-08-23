//! The association flywheel (§8.1/§8.6) — shared by every consumer that
//! resolves an entity and needs its cluster-mates checked for a directly-known
//! bad-actor label. Extracted out of `attribution.rs` (Sprint 7 t4) when
//! Sprint 17 t4's [`crate::cross_chain_attribution`] needed the exact same
//! pass off a cross-chain finding's `entity_hint` instead of an incident's
//! addresses — the walk itself doesn't care which event triggered clustering,
//! only that an entity was just resolved.

use chrono::{DateTime, Utc};
use event_bus::Transience;
use events::primitives::EntityId;

use crate::cache::{CacheError, HotCache};
use crate::model::{LabelKind, LabelRecord, LabelSource};
use crate::seed::seeded_label_id;
use crate::store::{StoreError, StoreSeams};

/// Label kinds that mark an address as a *directly known* bad actor — the
/// association flywheel's trigger (§8.1/§8.6). `SanctionedEntity` is included
/// alongside `KnownScammer` because a sanctions hit is exactly as strong a
/// direct signal.
pub const BAD_ACTOR_KINDS: &[LabelKind] = &[LabelKind::KnownScammer, LabelKind::SanctionedEntity];

/// Label kinds that already mark an address as flagged, directly or by prior
/// association — skipped when deciding whether a member needs a *fresh*
/// derived label, so an already-flagged member is never relabeled.
pub const FLAGGED_KINDS: &[LabelKind] = &[
    LabelKind::KnownScammer,
    LabelKind::SanctionedEntity,
    LabelKind::ScammerAssociate,
];

/// The `source_detail` every association-flywheel label carries. Distinct from
/// any feed's `source_detail` (§8.1) so [`seeded_label_id`]'s deterministic id
/// can never collide with a seeded feed label for the same address/kind/value.
pub const ASSOCIATION_SOURCE_DETAIL: &str = "entity_clustering_v1";

/// A failure walking or writing labels for one entity's membership. Wraps the
/// two seam errors this pass touches — no [`crate::cluster::ClusterError`]
/// here, since clustering itself (resolving `entity_id` in the first place) is
/// always the caller's job; this runs strictly *after* an entity exists.
#[derive(Debug, thiserror::Error)]
pub enum AssociationError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Cache(#[from] CacheError),
}

impl Transience for AssociationError {
    /// Whether retrying the same pass could plausibly succeed.
    fn is_transient(&self) -> bool {
        match self {
            AssociationError::Store(err) => err.is_transient(),
            AssociationError::Cache(err) => err.is_transient(),
        }
    }
}

/// The association flywheel (§8.1/§8.6): if any member of `entity_id`
/// already carries a directly-known bad-actor label ([`BAD_ACTOR_KINDS`]),
/// every other member lacking one of [`FLAGGED_KINDS`] gets a derived
/// `ScammerAssociate` label — `EntityDerived` provenance, the §8.1 reduced
/// confidence band. The deterministic label id ([`seeded_label_id`]) makes a
/// re-run an idempotent no-op: only labels newly stored *this* call are
/// returned, so a redelivered/duplicate pass returns an empty `Vec`.
///
/// Store-and-cache-only: the hot cache is evicted for every member a label
/// newly lands on, but publishing `LabelAdded` for each returned record is the
/// caller's job (a `chain`/event-sink concern this function deliberately
/// doesn't own, so it stays usable from any consumer's seams).
pub async fn label_associates(
    stores: &StoreSeams,
    cache: &dyn HotCache,
    entity_id: EntityId,
    at: DateTime<Utc>,
) -> Result<Vec<LabelRecord>, AssociationError> {
    let Some(entity) = stores.entities.entity(entity_id).await? else {
        return Ok(Vec::new());
    };
    if entity.addresses.len() < 2 {
        return Ok(Vec::new());
    }

    let mut flagged_by: Option<events::primitives::AccountAddress> = None;
    for member in &entity.addresses {
        let member_labels = stores.labels.labels_for(member, at).await?;
        if member_labels
            .iter()
            .any(|label| BAD_ACTOR_KINDS.contains(&label.kind))
        {
            flagged_by = Some(*member);
            break;
        }
    }
    let Some(flagged_by) = flagged_by else {
        return Ok(Vec::new());
    };

    let mut newly_stored = Vec::new();
    for member in &entity.addresses {
        if *member == flagged_by {
            continue;
        }
        let existing = stores.labels.labels_for(member, at).await?;
        if existing
            .iter()
            .any(|label| FLAGGED_KINDS.contains(&label.kind))
        {
            continue;
        }

        let value = format!("clustered with {flagged_by:#x}");
        let derived = LabelRecord {
            label_id: seeded_label_id(
                ASSOCIATION_SOURCE_DETAIL,
                member,
                LabelKind::ScammerAssociate,
                &value,
            ),
            address: *member,
            kind: LabelKind::ScammerAssociate,
            value,
            confidence: LabelSource::EntityDerived.default_confidence(),
            source: LabelSource::EntityDerived,
            source_detail: ASSOCIATION_SOURCE_DETAIL.to_owned(),
            created_at: at,
            valid_until: None,
        };

        if stores.labels.add_label(&derived).await? {
            cache.evict(member).await?;
            newly_stored.push(derived);
        }
    }
    Ok(newly_stored)
}
