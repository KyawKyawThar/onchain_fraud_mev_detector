//! The §20.3 **clustering signal** (Sprint 19 t3): high behavioral similarity
//! to a directly-known actor, entered into entity clustering as a
//! reduced-confidence heuristic — a *candidate link* surfaced for the flywheel
//! (§8.5), never an automatic `EntityMerged`.
//!
//! This is [`crate::similarity`]'s answer turned into a claim, and the whole
//! module is about how narrow that claim is allowed to be.
//!
//! # Why this is not a merge, and why the table is separate
//!
//! `entity_addresses` has a primary key on `address`: an address belongs to at
//! most one entity, and that invariant is what attribution (§8), risk scoring
//! (§8.3) and the rule engine (§9) are all allowed to assume. Everything that
//! writes it does so off §8.2's on-chain evidence — common funder, common
//! deployer, same code hash, shared profit receiver — facts the chain itself
//! recorded.
//!
//! A behavioral match is not that kind of fact. It says two addresses *look*
//! alike under one versioned feature space, against one population baseline,
//! at one moment. It can be right about a freshly funded bot with no graph
//! edges at all — that is exactly the recall §20.3 exists to widen — and it can
//! equally be two unrelated arbitrage bots running the same off-the-shelf
//! strategy. Merging on it would let a learned score silently rewrite the
//! graph's correctness story, and the failure would be invisible: a wrong merge
//! produces a plausible entity, not an error. So the proposal gets its own
//! table, its own event, and an operator decision — and the merge path is left
//! exactly as it was.
//!
//! # The anchor must be *directly* known
//!
//! A pair is only worth proposing when one side ([`Proposal::anchor`])
//! carries an [`ANCHOR_LABEL_KINDS`] label that some **direct** source put
//! there — manual curation, a public feed, or an on-chain heuristic. Labels
//! whose source is [`LabelSource::EntityDerived`] are refused as anchors, and
//! that refusal is the module's most important rule.
//!
//! Without it, taint spreads transitively and without bound: A is a known
//! scammer, B behaves like A and earns a derived `ScammerAssociate`, C behaves
//! like *B* and earns one off B's derived label, and after a few hops the
//! system is confidently accusing addresses on the strength of its own
//! guesses. §8.3 already names taint-by-association as legally contested and
//! reduced-confidence; second-order taint is that problem squared, and there
//! is no confidence discount small enough to make it honest. One hop from a
//! directly-known actor, or nothing.
//!
//! # Confidence is capped below the graph, and scaled by the score
//!
//! [`SignalPolicy::confidence_ceiling`] defaults to just under
//! [`LabelSource::EntityDerived`]'s 0.5 band, and the proposal's confidence is
//! that ceiling *scaled by the similarity that produced it* — so a link can
//! never claim as much as a graph-evidence cluster, and a 0.86 match never
//! reads like a 0.99 one. A neighbour whose vector was truncated (§8.2's hub
//! rule) is discounted again: a hub matching a hub is a weaker claim, and the
//! stored fidelity flag is what says so.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use events::primitives::{
    AccountAddress, Confidence, EntityId, LabelId, LabelKind, LinkCandidateId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::association::{ASSOCIATION_SOURCE_DETAIL, BAD_ACTOR_KINDS};
use crate::model::{address_key, LabelRecord, LabelSource};
use crate::seed::seeded_label_id;
use crate::similarity::{SimilarAddress, Similarity, SimilaritySearch};
use crate::store::StoreError;

/// The `source_detail` every artifact of this pass carries — the proposal
/// rows and the derived labels alike. Distinct from
/// [`ASSOCIATION_SOURCE_DETAIL`] (`entity_clustering_v1`) on purpose: a label
/// minted because two addresses *behave* alike is a materially weaker claim
/// than one minted because they share a funder, and an auditor reading a
/// `ScammerAssociate` row must be able to tell which of the two it is without
/// leaving the row. It also keeps [`seeded_label_id`]'s deterministic ids in
/// separate namespaces, so the two passes can never collide on one id.
pub const LINK_SOURCE_DETAIL: &str = "behavior_similarity_v1";

/// Label kinds strong enough to make their bearer an **anchor**: a
/// directly-known actor whose behavioral twin is worth surfacing.
///
/// `MevBot` sits beside the two bad-actor kinds here even though it is not an
/// accusation, because it is the §20.3 deliverable's own example — a new MEV
/// bot funded fresh, with no graph edges yet, recognised as a candidate member
/// of a known cluster by behavior alone. It is *not* in [`BAD_ACTOR_KINDS`],
/// so it proposes a link without ever minting a `ScammerAssociate` label:
/// looking like a bot is not looking like a scammer, and the two must not fold
/// into one another.
pub const ANCHOR_LABEL_KINDS: &[LabelKind] = &[
    LabelKind::KnownScammer,
    LabelKind::SanctionedEntity,
    LabelKind::MevBot,
];

/// Proposals counted by outcome: `new` (a link the store had never seen),
/// `re_announce` (stored but never announced — the crash window, see
/// [`ProposalOutcome`]), `refreshed` (an open proposal seen again — the
/// strongest triage signal there is), `decided` (rediscovered after an operator
/// already ruled on it, which changes nothing).
pub const PROPOSALS_TOTAL: &str = "intelligence_link_candidates_total";

/// Neighbours examined but not proposed, labelled by [`Suppressed`] — the
/// denominator that says whether the threshold is set anywhere near right.
pub const SUPPRESSED_TOTAL: &str = "intelligence_link_signal_suppressed_total";

/// Where one proposal stands. Only an operator moves it off
/// [`LinkStatus::Proposed`] — nothing in the pipeline does, which is the
/// "never an automatic `EntityMerged`" rule expressed as a state machine.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    strum::IntoStaticStr,
    strum::EnumString,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum LinkStatus {
    /// Open: proposed by the signal, awaiting a human.
    Proposed,
    /// An operator agreed the two addresses share a controller. Note this
    /// still does not *perform* a merge — it records that the evidence for one
    /// now exists.
    Confirmed,
    /// An operator ruled the resemblance coincidental. Kept, not deleted: a
    /// rejected pair that keeps being re-proposed is how a bad threshold or a
    /// degenerate feature makes itself visible.
    Rejected,
}

/// One feature's signed share of the similarity behind a proposal — the
/// stored/wire form of [`crate::similarity::SimilarityFactor`], trimmed to the
/// four numbers a reader actually needs (the z-forms are a re-derivable
/// intermediate, and storing them would pin the baseline into the row).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LinkFactor {
    pub feature: String,
    pub subject_value: f32,
    pub candidate_value: f32,
    pub contribution: f32,
}

/// A proposed behavioral link between two addresses — **what the kernel
/// emits**, before any store has seen it.
///
/// Deliberately carries no `status` and no decision fields. Those describe
/// what happened to a proposal *after* it was stored, and a type that could
/// express them here would let a caller hand [`LinkCandidateStore::propose_link`]
/// a "confirmed" proposal — which the SQL would silently store as `proposed`
/// anyway. Illegal states are better unrepresentable than silently ignored;
/// [`StoredLink`] is the shape that has been through the store.
///
/// The pair is held **unordered** (`address_a < address_b` as lowercase hex)
/// and the id is derived from that canonical form, so the same link
/// rediscovered from the other end — which happens the moment the anchor's own
/// vector is recomputed — is the same row rather than a mirror image of it.
/// [`Self::anchor`] carries the direction that actually matters: which side
/// was the known actor.
#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub candidate_id: LinkCandidateId,
    pub address_a: AccountAddress,
    pub address_b: AccountAddress,
    pub anchor: AccountAddress,
    /// The anchor's [`ANCHOR_LABEL_KINDS`] label kinds at proposal time,
    /// frozen: a later revocation must not silently rewrite *why* the proposal
    /// exists.
    pub anchor_labels: Vec<LabelKind>,
    pub entity_a: Option<EntityId>,
    pub entity_b: Option<EntityId>,
    pub similarity: Similarity,
    pub confidence: Confidence,
    pub embedding_version: String,
    pub schema_hash: String,
    pub factors: Vec<LinkFactor>,
    pub proposed_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// An operator's ruling on a proposal. One struct rather than three
/// independently-nullable columns: `decided_at`, `decided_by` and the note are
/// only ever all-set or all-unset, and `Option<Decision>` is the type that
/// says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub by: String,
    pub note: Option<String>,
    pub at: DateTime<Utc>,
}

/// A proposal as it stands in the store: the claim, plus everything that has
/// happened to it since. The **read** model — what listings, the gRPC surface
/// and the operator CLI see.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredLink {
    pub proposal: Proposal,
    pub status: LinkStatus,
    /// Set exactly when `status` is not [`LinkStatus::Proposed`].
    pub decision: Option<Decision>,
    /// When `EntityLinkProposed` was published for this row, or `None` when it
    /// is still owed one — see [`ProposalOutcome::ReAnnounce`].
    pub announced_at: Option<DateTime<Utc>>,
}

impl std::ops::Deref for StoredLink {
    type Target = Proposal;

    /// Read-through to the claim, so a listing can say `link.similarity`
    /// rather than `link.proposal.similarity` at every call site. Deliberately
    /// **not** `DerefMut`: the claim is immutable once stored (only `status`,
    /// `decision` and the refreshed scores move, and those go through the
    /// store).
    fn deref(&self) -> &Proposal {
        &self.proposal
    }
}

impl Proposal {
    /// The other side of the link from `address` — `None` if `address` is
    /// neither endpoint.
    pub fn counterpart(&self, address: &AccountAddress) -> Option<AccountAddress> {
        if *address == self.address_a {
            Some(self.address_b)
        } else if *address == self.address_b {
            Some(self.address_a)
        } else {
            None
        }
    }

    /// Whether the anchor's labels include a directly-known *bad actor* kind —
    /// the condition under which this link is also worth a §8.1
    /// `ScammerAssociate` label on the other address. A `MevBot`-only anchor
    /// proposes a link and mints nothing.
    pub fn implies_bad_actor(&self) -> bool {
        self.anchor_labels
            .iter()
            .any(|kind| BAD_ACTOR_KINDS.contains(kind))
    }

    /// The reduced-confidence §8.1 label this link justifies on the
    /// *non-anchor* side, if any (see [`Self::implies_bad_actor`]).
    ///
    /// A *derivation* of the claim, not a policy decision — whether the label
    /// is actually minted is [`plan`]'s call, and it is the one place the
    /// "one label per subject per pass" rule lives.
    ///
    /// Deterministic id, keyed on the claim rather than the moment, so a
    /// re-proposal of the same link is an idempotent no-op at the label store —
    /// which is also what stops the label→embedding→signal→label cycle from
    /// running forever (see [`crate::link_signal`]).
    pub fn derived_label(&self) -> Option<LabelRecord> {
        if !self.implies_bad_actor() {
            return None;
        }
        let subject = self.counterpart(&self.anchor)?;
        let value = format!(
            "behaves like {:#x} (cosine {}, {})",
            self.anchor, self.similarity, self.embedding_version
        );
        Some(LabelRecord {
            label_id: seeded_label_id(
                LINK_SOURCE_DETAIL,
                &subject,
                LabelKind::ScammerAssociate,
                &value,
            ),
            address: subject,
            kind: LabelKind::ScammerAssociate,
            value,
            // Not `LabelSource::EntityDerived::default_confidence()`: this
            // claim is weaker than the clustering one that band describes, and
            // the proposal already computed how much weaker.
            confidence: self.confidence,
            source: LabelSource::EntityDerived,
            source_detail: LINK_SOURCE_DETAIL.to_owned(),
            created_at: self.proposed_at,
            valid_until: None,
        })
    }
}

/// Deterministic identity for a candidate link: SHA-256 over the *unordered*
/// address pair, the feature space, and the proposer's `source_detail`
/// (length-prefixed so field boundaries can't be forged), folded into a
/// well-formed UUIDv8 — the [`seeded_label_id`] recipe applied to a pair.
///
/// What is *not* in the preimage is the point: not the similarity, not the
/// anchor side, not the time. A link re-scored slightly differently on the
/// next sweep, or rediscovered from the other end, is the *same* proposal —
/// otherwise an operator's triage queue would refill with duplicates of
/// everything they already dismissed.
///
/// **The recipe is a persistence contract.** Changing it re-mints every stored
/// id and re-opens every decided proposal; the golden test below pins the
/// bytes so a well-meaning refactor fails CI instead.
pub fn link_candidate_id(
    a: &AccountAddress,
    b: &AccountAddress,
    embedding_version: &str,
) -> LinkCandidateId {
    let (low, high) = canonical_pair(a, b);
    let mut hasher = Sha256::new();
    hasher.update(b"mevwatch.link-candidate.v1");
    for field in [
        LINK_SOURCE_DETAIL,
        low.as_str(),
        high.as_str(),
        embedding_version,
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    LinkCandidateId(uuid::Uuid::from_bytes(bytes))
}

/// The pair's canonical (lexicographic, lowercase-hex) ordering — the one
/// place the ordering rule lives, shared by the id recipe and the row layout
/// so the `address_a < address_b` check constraint can never disagree with the
/// id.
pub fn canonical_pair(a: &AccountAddress, b: &AccountAddress) -> (String, String) {
    let (ka, kb) = (address_key(a), address_key(b));
    if ka <= kb {
        (ka, kb)
    } else {
        (kb, ka)
    }
}

/// Why an examined neighbour did not become a proposal. A closed vocabulary
/// because it is a metric label — and because each one has a different fix:
/// [`BelowThreshold`](Self::BelowThreshold) is a knob, `NoAnchor` is the
/// normal case, `AlreadyClustered` means the graph already knows, and `Capped`
/// means the per-subject bound bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Suppressed {
    /// Scored below [`SignalPolicy::min_similarity`]. The overwhelming
    /// majority; counted anyway, because the ratio to `no_anchor` is what says
    /// whether the threshold is doing any work.
    BelowThreshold,
    /// No [`ANCHOR_LABEL_KINDS`] label from a direct source. The ordinary
    /// outcome for a neighbour nobody has identified.
    NoAnchor,
    /// The only labels of an anchor kind were themselves derived — the
    /// second-order-taint refusal in the module docs. Counted separately from
    /// `no_anchor` precisely because it is the interesting one: a sustained
    /// rate means the derived labels are pooling into a cluster of their own.
    DerivedAnchorOnly,
    /// Both addresses already belong to the same entity, so there is no link
    /// to propose — the graph got there first.
    AlreadyClustered,
    /// Beyond [`SignalPolicy::max_per_subject`]. The proposals are taken
    /// strongest-first, so this is the tail.
    Capped,
}

/// The bounds and thresholds one proposal pass respects.
#[derive(Debug, Clone, Copy)]
pub struct SignalPolicy {
    /// The standardized-cosine floor a neighbour must clear. Deliberately
    /// high: the cost of a missed link is a proposal nobody sees, and the cost
    /// of a loose one is an investigator's queue full of arbitrage bots that
    /// merely share a strategy.
    ///
    /// A [`Similarity`], not a bare `f32`: it is compared against scores that
    /// are `Similarity`, and negative values are *meaningful* in this space —
    /// code that assumed `[0, 1]` would be silently wrong, which is exactly
    /// what the newtype was introduced for one task ago.
    pub min_similarity: Similarity,
    /// How many proposals one subject may generate per pass. A bound, not a
    /// ranking preference: without it, one address in a dense behavioral
    /// neighbourhood (every sandwich bot resembles every other) writes its
    /// whole neighbourhood into the triage queue.
    pub max_per_subject: usize,
    /// The confidence a *perfect* match would be worth. Under
    /// [`LabelSource::EntityDerived`]'s 0.5 band by construction — see the
    /// module docs. A [`Confidence`] rather than an `f64` so the ceiling and
    /// the values it produces are the same type, and an out-of-range ceiling
    /// cannot be configured at all.
    pub confidence_ceiling: Confidence,
    /// Multiplier applied when the neighbour's vector describes a recent
    /// window rather than its whole history (§8.2's hub rule). A plain ratio,
    /// deliberately not a `Confidence`: it scales one, it is not one.
    pub truncated_discount: f64,
}

impl Default for SignalPolicy {
    fn default() -> Self {
        Self {
            min_similarity: Similarity::new(0.85),
            max_per_subject: 3,
            // Strictly below EntityDerived's 0.5: a behavioral match may never
            // claim as much as a shared-funder cluster, even at cosine 1.0.
            confidence_ceiling: Confidence::new(0.45),
            truncated_discount: 0.9,
        }
    }
}

impl SignalPolicy {
    /// The §8.1 reduced confidence one match is worth: the ceiling scaled by
    /// the similarity that produced it, discounted again for a truncated
    /// (hub-window) neighbour.
    ///
    /// Multiplicative rather than banded so the number moves continuously with
    /// the evidence — a 0.86 match and a 0.99 match are different claims, and
    /// bucketing them into one band would throw away the only quantitative
    /// thing this signal knows.
    pub fn confidence_for(&self, similarity: Similarity, truncated: bool) -> Confidence {
        let scaled = self.confidence_ceiling.get() * f64::from(similarity.get().max(0.0));
        let discounted = if truncated {
            scaled * self.truncated_discount
        } else {
            scaled
        };
        Confidence::new(discounted)
    }
}

/// Everything the pure proposer needs. A struct rather than six positional
/// arguments — three of them are maps keyed by the same address type.
pub struct ProposalInputs<'a> {
    /// The completed search this pass is turning into claims.
    pub search: &'a SimilaritySearch,
    /// The subject's entity, if the graph already placed it.
    pub subject_entity: Option<EntityId>,
    /// Active labels per neighbour address, from one batched read.
    pub neighbor_labels: &'a HashMap<AccountAddress, Vec<LabelRecord>>,
    /// Current entity membership per neighbour, from one batched read —
    /// absent means unclustered.
    ///
    /// Deliberately *not* [`SimilarAddress::entity_id`], which is the
    /// neighbour's entity as of the moment its **vector** was computed. A
    /// stored vector can be weeks old, and membership moves on every merge;
    /// proposing a link to an address the graph placed with the subject
    /// yesterday would be a proposal that is simply wrong, and the store is
    /// the only authority on that. The stale value stays on the search result
    /// because it is what the *search* saw — this is the pass that corrects
    /// it.
    pub neighbor_entities: &'a HashMap<AccountAddress, EntityId>,
    pub policy: SignalPolicy,
    pub at: DateTime<Utc>,
}

/// What one [`propose`] pass produced.
#[derive(Debug, Clone, PartialEq)]
pub struct Proposals {
    /// Strongest first, at most [`SignalPolicy::max_per_subject`].
    pub candidates: Vec<Proposal>,
    /// Every examined neighbour that did not become one, with why — counted by
    /// the caller, and the reason a threshold change can be argued from data
    /// rather than taste.
    pub suppressed: Vec<(AccountAddress, Suppressed)>,
}

/// Turn one similarity search into candidate links — the pure decision, with
/// no store, clock or event sink in sight.
///
/// `search.results` arrive strongest-first from [`crate::similarity::rank`],
/// and that order is preserved, so the per-subject cap keeps the strongest
/// proposals rather than the first ones the map iteration happened to yield.
pub fn propose(inputs: ProposalInputs<'_>) -> Proposals {
    let ProposalInputs {
        search,
        subject_entity,
        neighbor_labels,
        neighbor_entities,
        policy,
        at,
    } = inputs;

    let mut candidates = Vec::new();
    let mut suppressed = Vec::new();

    for result in &search.results {
        if result.similarity.get() < policy.min_similarity.get() {
            // The results are ordered, so everything after this one is weaker
            // too — but they are still counted individually, because the
            // *shape* of the suppression histogram is what the threshold is
            // tuned against.
            suppressed.push((result.address, Suppressed::BelowThreshold));
            continue;
        }
        // An address the graph already placed with the subject needs no
        // proposal — checked before the (more expensive to reason about) label
        // rules, and before the cap, so a clustered neighbour never consumes
        // one of the subject's proposal slots.
        let neighbor_entity = neighbor_entities.get(&result.address).copied();
        if subject_entity.is_some() && subject_entity == neighbor_entity {
            suppressed.push((result.address, Suppressed::AlreadyClustered));
            continue;
        }

        let labels = neighbor_labels
            .get(&result.address)
            .map(Vec::as_slice)
            .unwrap_or_default();
        match anchor_kinds(labels) {
            AnchorVerdict::Anchored(kinds) => {
                if candidates.len() >= policy.max_per_subject {
                    suppressed.push((result.address, Suppressed::Capped));
                    continue;
                }
                candidates.push(build(BuildArgs {
                    search,
                    subject_entity,
                    result,
                    neighbor_entity,
                    anchor_labels: kinds,
                    policy,
                    at,
                }));
            }
            AnchorVerdict::DerivedOnly => {
                suppressed.push((result.address, Suppressed::DerivedAnchorOnly));
            }
            AnchorVerdict::None => {
                suppressed.push((result.address, Suppressed::NoAnchor));
            }
        }
    }

    Proposals {
        candidates,
        suppressed,
    }
}

/// Whether a neighbour's labels make it an anchor — and, when they don't,
/// whether the *only* thing standing in the way was that every anchor-kind
/// label it holds is itself derived. That distinction is worth a variant
/// rather than a bool because it is the module's central refusal, and it must
/// be visible in a metric rather than inferred from an absence.
enum AnchorVerdict {
    Anchored(Vec<LabelKind>),
    DerivedOnly,
    None,
}

fn anchor_kinds(labels: &[LabelRecord]) -> AnchorVerdict {
    let mut direct = Vec::new();
    let mut saw_derived = false;
    for label in labels {
        if !ANCHOR_LABEL_KINDS.contains(&label.kind) {
            continue;
        }
        if label.source == LabelSource::EntityDerived {
            saw_derived = true;
            continue;
        }
        if !direct.contains(&label.kind) {
            direct.push(label.kind);
        }
    }
    if !direct.is_empty() {
        AnchorVerdict::Anchored(direct)
    } else if saw_derived {
        AnchorVerdict::DerivedOnly
    } else {
        AnchorVerdict::None
    }
}

/// One [`build`] call's inputs — a struct because `subject_entity` and
/// `neighbor_entity` are adjacent `Option<EntityId>`s whose swap still
/// compiles and silently mislabels which side the graph had already placed.
struct BuildArgs<'a> {
    search: &'a SimilaritySearch,
    subject_entity: Option<EntityId>,
    result: &'a SimilarAddress,
    neighbor_entity: Option<EntityId>,
    anchor_labels: Vec<LabelKind>,
    policy: SignalPolicy,
    at: DateTime<Utc>,
}

fn build(args: BuildArgs<'_>) -> Proposal {
    let BuildArgs {
        search,
        subject_entity,
        result,
        neighbor_entity,
        anchor_labels,
        policy,
        at,
    } = args;
    let subject = search.subject;
    let anchor = result.address;
    // Canonical ordering by the same rule the id and the row use, so the three
    // can never disagree about which address is `a`.
    let (low, _) = canonical_pair(&subject, &anchor);
    let subject_is_low = address_key(&subject) == low;
    let (address_a, address_b, entity_a, entity_b) = if subject_is_low {
        (subject, anchor, subject_entity, neighbor_entity)
    } else {
        (anchor, subject, neighbor_entity, subject_entity)
    };

    Proposal {
        candidate_id: link_candidate_id(&subject, &anchor, &search.embedding_version),
        address_a,
        address_b,
        anchor,
        anchor_labels,
        entity_a,
        entity_b,
        similarity: result.similarity,
        confidence: policy.confidence_for(result.similarity, result.observations_truncated),
        embedding_version: search.embedding_version.clone(),
        schema_hash: search.schema_hash.clone(),
        factors: result
            .factors
            .iter()
            .map(|factor| LinkFactor {
                feature: factor.feature.to_owned(),
                subject_value: factor.subject_value,
                candidate_value: factor.candidate_value,
                contribution: factor.contribution,
            })
            .collect(),
        proposed_at: at,
        last_seen_at: at,
    }
}

/// What storing one proposal did — the idempotency contract, and the reason
/// the pipeline neither loops forever nor loses an announcement.
///
/// # Why this is four variants and not three
///
/// The obvious design is "announce iff the row was newly inserted", and it is
/// wrong in a way that only shows up under a crash. The row and its
/// `EntityLinkProposed` are writes to two different systems: Postgres commits,
/// then Kafka publishes. Lose the process in between — a pod eviction, a
/// rolling update, a shutdown that stops the publish retry — and the consumer
/// offset was never committed, so the event redelivers, the row now *exists*,
/// and an insert-only rule would classify it as `Refreshed` and stay silent.
/// The announcement would be lost permanently and silently.
///
/// So the question the store answers is not "did I insert this?" but **"does
/// this row still owe an announcement?"** — `announced_at IS NULL`, a column
/// this code owns, rather than an inference from the insert. That makes
/// delivery at-least-once (a crash between publish and the stamp re-announces)
/// which every downstream write off this event already tolerates: the label id
/// is seeded from the claim, so a duplicate mints nothing.
///
/// This is [`rule_outbox`](../../rule-engine/src/outbox.rs)'s trade in the
/// cheaper shape the workload allows: one table, no second row to drain,
/// because the proposal row *is* the durable record the announcement belongs
/// to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum ProposalOutcome {
    /// The store had never seen this link. Announce it.
    New,
    /// The row already existed and is **still unannounced** — the crash
    /// window above. Announce it now. Counted separately from `new` precisely
    /// because a non-zero rate is the visible evidence that the crash window
    /// is real and being covered.
    ReAnnounce,
    /// An open proposal was seen again and has already been announced: its
    /// similarity, confidence and `last_seen_at` are refreshed, and nothing is
    /// published. A link that keeps being re-proposed is stronger evidence
    /// than one seen once, and that is what the refreshed timestamp is for.
    Refreshed,
    /// An operator already decided this link. Left completely alone —
    /// re-proposing must never reopen a rejection, or the queue becomes
    /// unclearable.
    Decided,
}

impl ProposalOutcome {
    /// Whether this row still owes an `EntityLinkProposed`.
    pub fn needs_announcement(self) -> bool {
        matches!(self, ProposalOutcome::New | ProposalOutcome::ReAnnounce)
    }
}

/// One durable side effect an announcement pass must perform.
///
/// The pass's *decisions* are [`plan`]'s pure output; performing them is the
/// driver's job. Splitting them is what makes the rule that actually matters —
/// **at most one derived label per subject per pass**, however many proposals
/// that subject produced — an `assert_eq!` on a `Vec` rather than an assertion
/// about a recording event sink three layers down.
#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    /// Publish `EntityLinkProposed` and stamp `announced_at`. The stamp is
    /// part of applying the effect, never a separate one: a stamp without a
    /// publish is exactly the silent loss [`ProposalOutcome`] exists to
    /// prevent, and the two must not be independently schedulable.
    Announce(Proposal),
    /// Mint the §8.1 reduced-confidence label a proposal justifies. Applying
    /// it is `add_label` → *if newly stored* evict the hot cache and publish
    /// `LabelAdded`; the idempotent no-op on a redelivery is what keeps the
    /// label→embedding→signal→label cycle a fixpoint.
    MintLabel(LabelRecord),
}

/// Plan the announcements for the proposals a store said still owe one — the
/// pure half of the write path.
///
/// `subject_flagged` is whether the subject *already* carries a
/// [`FLAGGED_KINDS`](crate::association::FLAGGED_KINDS) label, directly or by
/// either flywheel. It is threaded through the fold rather than re-read per
/// proposal because it changes the moment this pass mints one: a subject
/// matching three known scammers must earn **one** label, not three — and
/// without the fold the first run would mint three where a re-run mints none,
/// i.e. the pass would not agree with itself.
///
/// Every `Announce` precedes its `MintLabel`, because the label is a
/// *consequence* of the proposal and an audit trail that records the
/// consequence first reads as a claim with no origin.
pub fn plan(owed: &[Proposal], subject_flagged: bool) -> Vec<Effect> {
    let mut effects = Vec::with_capacity(owed.len());
    let mut flagged = subject_flagged;
    for proposal in owed {
        effects.push(Effect::Announce(proposal.clone()));
        if flagged {
            continue;
        }
        // `None` when the anchor is an identified `MevBot` and nothing worse:
        // the link is still worth proposing, but looking like a bot is not
        // looking like a scammer and must not be recorded as one.
        if let Some(label) = proposal.derived_label() {
            effects.push(Effect::MintLabel(label));
            flagged = true;
        }
    }
    effects
}

/// The candidate-link store seam (§20.3). Object-safe; production is
/// `PgIntelligenceStore` (see [`crate::store`]), tests use the in-memory
/// double in [`crate::test_util`].
#[async_trait::async_trait]
pub trait LinkCandidateStore: Send + Sync {
    /// Record a proposal, keyed by its deterministic
    /// [`Proposal::candidate_id`]. See [`ProposalOutcome`] for the four ways
    /// this lands and why "still owes an announcement" is a stored column
    /// rather than an inference from the insert.
    ///
    /// Takes a [`Proposal`], never a [`StoredLink`]: a caller must not be able
    /// to express a status here, because this call does not set one.
    async fn propose_link(&self, proposal: &Proposal) -> Result<ProposalOutcome, StoreError>;

    /// Stamp `announced_at`, closing the crash window for one row. Called
    /// **after** the publish succeeds, never before — the whole point is that
    /// the stamp is evidence the event actually went out.
    async fn mark_announced(
        &self,
        id: LinkCandidateId,
        at: DateTime<Utc>,
    ) -> Result<(), StoreError>;

    /// Proposals stored but never announced, oldest first — the crash-recovery
    /// sweep.
    ///
    /// Redelivery covers the common case (the consumer offset was never
    /// committed, so the event comes back), but not every one: a proposal
    /// whose topic has since been compacted past, or whose consumer group was
    /// reset forward, would otherwise owe an announcement no redelivery will
    /// ever trigger. This is the backstop that makes at-least-once true
    /// independently of broker retention, and its normal result is empty.
    async fn unannounced_links(&self, limit: usize) -> Result<Vec<Proposal>, StoreError>;

    /// Every candidate link touching `address`, strongest first. Includes
    /// decided ones — an investigator looking at an address wants to see that
    /// a link was proposed *and rejected* just as much as an open one.
    async fn links_for_address(
        &self,
        address: &AccountAddress,
        limit: usize,
    ) -> Result<Vec<StoredLink>, StoreError>;

    /// One proposal by id, whatever its status.
    async fn link(&self, id: LinkCandidateId) -> Result<Option<StoredLink>, StoreError>;

    /// Record an operator's decision. Returns the row as it stood *before*
    /// the decision — `None` if the id is unknown. Deciding an
    /// already-decided proposal overwrites the earlier decision (an operator
    /// correcting themselves), which is why the previous state is returned
    /// rather than the write being refused.
    async fn decide_link(
        &self,
        id: LinkCandidateId,
        status: LinkStatus,
        decision: &Decision,
    ) -> Result<Option<StoredLink>, StoreError>;

    /// The open triage queue, strongest first — what a reviewer works through.
    async fn open_links(&self, limit: usize) -> Result<Vec<StoredLink>, StoreError>;
}

/// The derived-label id the association flywheel would mint for the same
/// address/kind/value — exposed so a test can prove the two passes' seeded ids
/// live in different namespaces rather than trusting the constants to differ.
#[doc(hidden)]
pub fn association_id_for(address: &AccountAddress, kind: LabelKind, value: &str) -> LabelId {
    seeded_label_id(ASSOCIATION_SOURCE_DETAIL, address, kind, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::similarity::SimilarityFactor;

    fn addr(byte: u8) -> AccountAddress {
        AccountAddress::repeat_byte(byte)
    }

    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp")
    }

    fn label(address: AccountAddress, kind: LabelKind, source: LabelSource) -> LabelRecord {
        LabelRecord::new(address, kind, "v", source, "test", at())
    }

    fn neighbor(address: AccountAddress, similarity: f32) -> SimilarAddress {
        SimilarAddress {
            address,
            entity_id: None,
            similarity: Similarity::new(f64::from(similarity)),
            observations_truncated: false,
            computed_at: at(),
            factors: vec![SimilarityFactor {
                feature: "edge_count_log",
                subject_value: 1.0,
                candidate_value: 1.1,
                subject_z: 0.5,
                candidate_z: 0.6,
                contribution: 0.3,
            }],
        }
    }

    fn search(subject: AccountAddress, results: Vec<SimilarAddress>) -> SimilaritySearch {
        SimilaritySearch {
            subject,
            embedding_version: "behavior-v1".into(),
            schema_hash: "abc123".into(),
            subject_computed_at: at(),
            results,
            candidates_considered: 10,
            candidates_skipped: 0,
            approximate: false,
        }
    }

    fn run(
        subject: AccountAddress,
        subject_entity: Option<EntityId>,
        results: Vec<SimilarAddress>,
        labels: Vec<(AccountAddress, Vec<LabelRecord>)>,
    ) -> Proposals {
        // The default: membership comes from the search results, which is what
        // every case that doesn't specifically exercise staleness means.
        let entities = results
            .iter()
            .filter_map(|r| r.entity_id.map(|id| (r.address, id)))
            .collect();
        run_with_entities(subject, subject_entity, results, labels, entities)
    }

    fn run_with_entities(
        subject: AccountAddress,
        subject_entity: Option<EntityId>,
        results: Vec<SimilarAddress>,
        labels: Vec<(AccountAddress, Vec<LabelRecord>)>,
        neighbor_entities: HashMap<AccountAddress, EntityId>,
    ) -> Proposals {
        let search = search(subject, results);
        let labels: HashMap<_, _> = labels.into_iter().collect();
        propose(ProposalInputs {
            search: &search,
            subject_entity,
            neighbor_labels: &labels,
            neighbor_entities: &neighbor_entities,
            policy: SignalPolicy::default(),
            at: at(),
        })
    }

    #[test]
    fn a_strong_match_to_a_directly_labeled_actor_is_proposed() {
        let out = run(
            addr(1),
            None,
            vec![neighbor(addr(2), 0.95)],
            vec![(
                addr(2),
                vec![label(
                    addr(2),
                    LabelKind::KnownScammer,
                    LabelSource::ExternalFeed,
                )],
            )],
        );
        assert_eq!(out.candidates.len(), 1);
        let candidate = &out.candidates[0];
        assert_eq!(candidate.anchor, addr(2));
        assert_eq!(candidate.anchor_labels, vec![LabelKind::KnownScammer]);
        // Canonical ordering: 0x01… sorts before 0x02….
        assert_eq!(candidate.address_a, addr(1));
        assert_eq!(candidate.address_b, addr(2));
    }

    /// The module's central rule: a derived label may not anchor a new
    /// proposal, or taint spreads transitively without bound.
    #[test]
    fn a_derived_anchor_label_never_proposes_a_second_hop() {
        let out = run(
            addr(1),
            None,
            vec![neighbor(addr(2), 0.99)],
            vec![(
                addr(2),
                vec![label(
                    addr(2),
                    LabelKind::ScammerAssociate,
                    LabelSource::EntityDerived,
                )],
            )],
        );
        assert!(out.candidates.is_empty(), "no proposal off a derived label");
        // `ScammerAssociate` is not an anchor kind at all, so this reads as a
        // plain miss rather than the derived-only refusal.
        assert_eq!(out.suppressed, vec![(addr(2), Suppressed::NoAnchor)]);

        // …and the refusal that *is* about provenance: an anchor *kind*, but
        // derived rather than directly known.
        let out = run(
            addr(1),
            None,
            vec![neighbor(addr(2), 0.99)],
            vec![(
                addr(2),
                vec![label(
                    addr(2),
                    LabelKind::KnownScammer,
                    LabelSource::EntityDerived,
                )],
            )],
        );
        assert!(out.candidates.is_empty());
        assert_eq!(
            out.suppressed,
            vec![(addr(2), Suppressed::DerivedAnchorOnly)]
        );
    }

    #[test]
    fn a_weak_match_or_an_unlabeled_neighbour_is_suppressed_with_its_reason() {
        let out = run(
            addr(1),
            None,
            vec![neighbor(addr(2), 0.5), neighbor(addr(3), 0.99)],
            vec![(
                addr(2),
                vec![label(addr(2), LabelKind::KnownScammer, LabelSource::Manual)],
            )],
        );
        assert!(out.candidates.is_empty());
        assert_eq!(
            out.suppressed,
            vec![
                (addr(2), Suppressed::BelowThreshold),
                (addr(3), Suppressed::NoAnchor),
            ]
        );
    }

    #[test]
    fn a_neighbour_already_in_the_subjects_entity_is_not_re_proposed() {
        let entity = EntityId::new();
        let mut hit = neighbor(addr(2), 0.99);
        hit.entity_id = Some(entity);
        let out = run(
            addr(1),
            Some(entity),
            vec![hit],
            vec![(
                addr(2),
                vec![label(addr(2), LabelKind::KnownScammer, LabelSource::Manual)],
            )],
        );
        assert!(out.candidates.is_empty());
        assert_eq!(
            out.suppressed,
            vec![(addr(2), Suppressed::AlreadyClustered)]
        );
    }

    /// A neighbour in a *different* entity is the merge-candidate shape — the
    /// one this module most carefully refuses to act on itself.
    #[test]
    fn a_neighbour_in_another_entity_is_proposed_not_merged() {
        let mut hit = neighbor(addr(2), 0.97);
        hit.entity_id = Some(EntityId::new());
        let out = run(
            addr(1),
            Some(EntityId::new()),
            vec![hit],
            vec![(
                addr(2),
                vec![label(addr(2), LabelKind::KnownScammer, LabelSource::Manual)],
            )],
        );
        assert_eq!(out.candidates.len(), 1);
        let candidate = &out.candidates[0];
        assert!(candidate.entity_a.is_some() && candidate.entity_b.is_some());
        assert_ne!(
            candidate.entity_a, candidate.entity_b,
            "two different entities is the merge-candidate shape — and a `Proposal` \
             has no status field to express a merge with, by construction"
        );
    }

    #[test]
    fn the_per_subject_cap_keeps_the_strongest_and_counts_the_tail() {
        let scammer = |a: AccountAddress| {
            (
                a,
                vec![label(a, LabelKind::KnownScammer, LabelSource::Manual)],
            )
        };
        let out = run(
            addr(1),
            None,
            vec![
                neighbor(addr(2), 0.99),
                neighbor(addr(3), 0.98),
                neighbor(addr(4), 0.97),
                neighbor(addr(5), 0.96),
            ],
            vec![
                scammer(addr(2)),
                scammer(addr(3)),
                scammer(addr(4)),
                scammer(addr(5)),
            ],
        );
        assert_eq!(
            out.candidates.len(),
            SignalPolicy::default().max_per_subject
        );
        let kept: Vec<_> = out.candidates.iter().map(|c| c.anchor).collect();
        assert_eq!(kept, vec![addr(2), addr(3), addr(4)]);
        assert_eq!(out.suppressed, vec![(addr(5), Suppressed::Capped)]);
    }

    /// §8.1's confidence ladder, enforced numerically: a behavioral match is
    /// worth less than an entity-derived label, which is worth less than a
    /// heuristic one.
    #[test]
    fn confidence_stays_below_the_entity_derived_band() {
        let policy = SignalPolicy::default();
        let perfect = policy.confidence_for(Similarity::IDENTICAL, false);
        assert!(
            perfect.get() < LabelSource::EntityDerived.default_confidence().get(),
            "even a perfect behavioral match must claim less than a graph cluster"
        );
        assert!(
            policy.confidence_for(Similarity::new(0.86), false).get() < perfect.get(),
            "confidence scales with the score"
        );
        assert!(
            policy.confidence_for(Similarity::new(0.95), true).get()
                < policy.confidence_for(Similarity::new(0.95), false).get(),
            "a truncated (hub-window) vector is a weaker claim"
        );
        // A negative similarity can't be proposed (it's below every sane
        // threshold), but the arithmetic must not produce a negative
        // confidence if one ever reached here.
        assert_eq!(
            policy.confidence_for(Similarity::new(-0.5), false),
            Confidence::new(0.0)
        );
    }

    #[test]
    fn the_id_is_the_same_from_either_end_and_differs_by_version() {
        let forward = link_candidate_id(&addr(1), &addr(2), "behavior-v1");
        let reverse = link_candidate_id(&addr(2), &addr(1), "behavior-v1");
        assert_eq!(
            forward, reverse,
            "a link rediscovered from the other end is the same proposal"
        );
        assert_ne!(
            forward,
            link_candidate_id(&addr(1), &addr(2), "behavior-v2"),
            "a different feature space is a different claim"
        );
        assert_ne!(
            forward,
            link_candidate_id(&addr(1), &addr(3), "behavior-v1")
        );
    }

    /// The preimage is a persistence contract (see [`link_candidate_id`]):
    /// changing it silently re-opens every decided proposal.
    #[test]
    fn the_id_recipe_is_pinned() {
        assert_eq!(
            link_candidate_id(&addr(1), &addr(2), "behavior-v1").to_string(),
            "8a47643f-8557-8d1a-a21d-6b06a8e0a19b"
        );
    }

    #[test]
    fn a_bad_actor_anchor_mints_a_reduced_confidence_label_and_a_bot_anchor_does_not() {
        let scam = run(
            addr(1),
            None,
            vec![neighbor(addr(2), 0.95)],
            vec![(
                addr(2),
                vec![label(addr(2), LabelKind::KnownScammer, LabelSource::Manual)],
            )],
        );
        let derived = scam.candidates[0]
            .derived_label()
            .expect("a known-scammer anchor implies a ScammerAssociate");
        assert_eq!(
            plan(&scam.candidates, false),
            vec![
                Effect::Announce(scam.candidates[0].clone()),
                Effect::MintLabel(derived.clone()),
            ],
            "the announcement precedes the consequence it justifies"
        );
        assert_eq!(
            derived.address,
            addr(1),
            "the label lands on the *other* side"
        );
        assert_eq!(derived.kind, LabelKind::ScammerAssociate);
        assert_eq!(derived.source, LabelSource::EntityDerived);
        assert_eq!(derived.source_detail, LINK_SOURCE_DETAIL);
        assert_eq!(derived.confidence, scam.candidates[0].confidence);
        assert!(
            derived.confidence.get() < LabelSource::EntityDerived.default_confidence().get(),
            "the label carries the proposal's reduced band, not the source default"
        );

        let bot = run(
            addr(1),
            None,
            vec![neighbor(addr(2), 0.95)],
            vec![(
                addr(2),
                vec![label(addr(2), LabelKind::MevBot, LabelSource::ExternalFeed)],
            )],
        );
        assert_eq!(
            bot.candidates.len(),
            1,
            "a bot anchor still proposes a link"
        );
        assert!(
            bot.candidates[0].derived_label().is_none(),
            "looking like a bot is not looking like a scammer"
        );
    }

    /// The two flywheel passes mint ids in separate namespaces, so a
    /// behavioral `ScammerAssociate` and a clustering one for the same address
    /// coexist as the distinct claims they are (§8.1: conflicting labels are
    /// stored, not overwritten).
    #[test]
    fn behavioral_and_clustering_labels_never_collide_on_one_id() {
        let value = "same text";
        assert_ne!(
            seeded_label_id(
                LINK_SOURCE_DETAIL,
                &addr(1),
                LabelKind::ScammerAssociate,
                value
            ),
            association_id_for(&addr(1), LabelKind::ScammerAssociate, value)
        );
    }

    /// The rule the effects layer exists to make assertable: however many
    /// proposals one pass produces, the subject earns **one** label. Before
    /// this was a plan, the only way to check it was to run the whole consumer
    /// against a recording sink and count published events.
    #[test]
    fn three_scammer_anchors_mint_exactly_one_label() {
        let scammer = |a: AccountAddress| {
            (
                a,
                vec![label(a, LabelKind::KnownScammer, LabelSource::Manual)],
            )
        };
        let out = run(
            addr(1),
            None,
            vec![
                neighbor(addr(2), 0.99),
                neighbor(addr(3), 0.98),
                neighbor(addr(4), 0.97),
            ],
            vec![scammer(addr(2)), scammer(addr(3)), scammer(addr(4))],
        );
        assert_eq!(out.candidates.len(), 3);

        let effects = plan(&out.candidates, false);
        let announced = effects
            .iter()
            .filter(|e| matches!(e, Effect::Announce(_)))
            .count();
        let minted = effects
            .iter()
            .filter(|e| matches!(e, Effect::MintLabel(_)))
            .count();
        assert_eq!(announced, 3, "every proposal is announced");
        assert_eq!(
            minted, 1,
            "one label, not one per proposal — piling three ScammerAssociates on \
             one address adds noise and no information"
        );
        // …and the label names the *first* (strongest) anchor, since the
        // proposals arrive strongest-first.
        let Effect::MintLabel(minted) = effects
            .iter()
            .find(|e| matches!(e, Effect::MintLabel(_)))
            .expect("one label")
        else {
            unreachable!()
        };
        assert!(minted.value.contains(&format!("{:#x}", addr(2))));
    }

    /// The pass agrees with itself across runs: an already-flagged subject
    /// (which is what the *previous* run left behind) mints nothing, so a
    /// re-run is announcements only.
    #[test]
    fn an_already_flagged_subject_earns_announcements_and_no_further_label() {
        let out = run(
            addr(1),
            None,
            vec![neighbor(addr(2), 0.95)],
            vec![(
                addr(2),
                vec![label(addr(2), LabelKind::KnownScammer, LabelSource::Manual)],
            )],
        );
        assert_eq!(
            plan(&out.candidates, true),
            vec![Effect::Announce(out.candidates[0].clone())],
            "the proposal is still announced; only the label is suppressed"
        );
    }

    /// A `MevBot` anchor is worth a link and never a label, at the plan level
    /// too — the distinction has to survive the layer that performs writes.
    #[test]
    fn a_bot_anchor_plans_an_announcement_and_nothing_else() {
        let out = run(
            addr(1),
            None,
            vec![neighbor(addr(2), 0.95)],
            vec![(
                addr(2),
                vec![label(addr(2), LabelKind::MevBot, LabelSource::ExternalFeed)],
            )],
        );
        assert_eq!(
            plan(&out.candidates, false),
            vec![Effect::Announce(out.candidates[0].clone())]
        );
    }

    #[test]
    fn an_outcome_owes_an_announcement_only_when_it_has_not_been_made() {
        assert!(ProposalOutcome::New.needs_announcement());
        // The crash window: the row exists, the event never went out.
        assert!(ProposalOutcome::ReAnnounce.needs_announcement());
        assert!(!ProposalOutcome::Refreshed.needs_announcement());
        assert!(!ProposalOutcome::Decided.needs_announcement());
    }

    #[test]
    fn counterpart_names_the_other_side_and_nothing_else() {
        let out = run(
            addr(1),
            None,
            vec![neighbor(addr(2), 0.95)],
            vec![(
                addr(2),
                vec![label(addr(2), LabelKind::KnownScammer, LabelSource::Manual)],
            )],
        );
        let candidate = &out.candidates[0];
        assert_eq!(candidate.counterpart(&addr(1)), Some(addr(2)));
        assert_eq!(candidate.counterpart(&addr(2)), Some(addr(1)));
        assert_eq!(candidate.counterpart(&addr(9)), None);
    }
}
