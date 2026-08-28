//! **Behavior schema v1 — FROZEN.** Shipped 2026-08-28; do not edit anything
//! observable here (names, order, kinds, formulas). New or changed semantics
//! are a new version module (`v2`) registered alongside this one in
//! [`super::EMBEDDERS`] — that roster exists precisely so the two can run side
//! by side through a rollout.
//!
//! The [`BehaviorFeature`] enum *is* the schema: variant declaration order is
//! vector order, variant names (strum `snake_case`) are the wire names, and
//! [`Embedder::embed`] computes values through one exhaustive `match` — so a
//! missing, duplicated or reordered feature is a compile error, and the name
//! list, the value list and the [`FeatureKind`] metadata cannot drift apart.
//!
//! The schema **hash covers the layout, not the arithmetic** — names, order
//! and kinds, which is what makes two vectors structurally comparable. A
//! changed *formula* under an unchanged layout is invisible to it, and is
//! caught by this module's unit tests plus the rule stated above: a changed
//! formula is a new version module. Do not rely on the hash to notice one.
//!
//! Four families, matching §20.3: activity cadence, counterparty-type
//! distribution, value-flow shape, incident history. This mirrors
//! `ml-features`' v1 discipline deliberately, but does **not** reuse that
//! crate: `ml-features` is attribution-blind by construction (§20.1) and
//! per-block, while this schema is per-address and reads labels and incident
//! history on purpose. Two schemas with opposite constraints that happen to
//! share a technique.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, EntityId};
use strum::{EnumIter, IntoEnumIterator, IntoStaticStr};

use super::{
    days_between, log_magnitude, ratio, store_value, BehaviorEmbedder, BehaviorInputs,
    BehaviorSchema, BehaviorVector, FeatureDef, FeatureKind,
};
use crate::model::{AddressEdge, EdgeKind, LabelKind};

/// The version stamped on every vector this module computes.
pub const VERSION: &str = "behavior-v1";

/// Trailing window that [`BehaviorFeature::RecentWindowShare`] measures — "how
/// much of this address's recorded behavior is *current*", the cheapest signal
/// separating a live bot from a dormant one with the same lifetime shape.
const RECENT_WINDOW_DAYS: f64 = 30.0;

/// Half-life for the incident-history intensity, matching [`crate::risk`]'s
/// attribution half-life: "old incidents contribute less" (§8.3) is one rule,
/// and two subsystems disagreeing about it would make a risk score and a
/// behavior vector tell different stories about the same address.
const INCIDENT_HALF_LIFE_DAYS: f64 = 180.0;

/// v1's feature layout, in vector order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum BehaviorFeature {
    // ── activity cadence ────────────────────────────────────────────
    /// How much this address has been observed doing at all.
    ObservationCountLog,
    /// Days between its first and last observation.
    LifespanDaysLog,
    /// Distinct UTC days on which it was observed.
    ActiveDaysLog,
    /// Days since its most recent observation — dormancy.
    RecencyDaysLog,
    /// `active_days / (lifespan_days + 1)`: continuous operation (a bot near
    /// `1.0`) vs. a handful of days spread over a year (near `0.0`).
    ActivityDensity,
    /// Share of observations falling on its single busiest day — burstiness.
    BusiestDayShare,
    /// Share of observations inside the trailing [`RECENT_WINDOW_DAYS`].
    RecentWindowShare,
    /// Mean gap between consecutive observations, in days.
    MeanGapDaysLog,

    // ── counterparty-type distribution ──────────────────────────────
    /// Distinct counterparties.
    CounterpartyCountLog,
    /// Share of counterparties carrying any label at all — how *known* the
    /// company this address keeps is.
    LabeledCounterpartyFraction,
    /// Share whose strongest label is venue infrastructure (CEX, bridge).
    VenueCounterpartyFraction,
    /// Share that are MEV actors (searcher bots, block builders).
    MevCounterpartyFraction,
    /// Share that are illicit (scammer, sanctioned, associate, mixer user).
    IllicitCounterpartyFraction,
    /// Share that are protocol contracts or deployers.
    ProtocolCounterpartyFraction,
    /// Normalized Shannon entropy over the five counterparty buckets
    /// (including unlabeled): `0.0` = one kind of counterparty only,
    /// `1.0` = evenly spread. Separates a single-purpose bot from a wallet
    /// touching everything, which the individual shares alone do not.
    CounterpartyTypeEntropy,
    /// The observation history hit its read cap — this address is a hub, and
    /// every cadence feature above describes a recent window rather than its
    /// whole life (§8.2). Carried *inside* the vector so a similarity search
    /// can't compare a hub's window against a normal address's lifetime
    /// without the difference being one of the compared dimensions.
    IsHub,

    // ── value-flow shape ────────────────────────────────────────────
    /// Share of observations where this address is the *source* — the
    /// direction balance, sender vs. receiver.
    OutboundObservationFraction,
    /// Share of observations that are this address funding another.
    FundedOutFraction,
    /// Share that are another address funding this one.
    FundedInFraction,
    /// Share that are contract deployments (either direction).
    DeployedFraction,
    /// Share that are MEV profit-receiver relations.
    ProfitReceiverFraction,
    /// Share that are plain interactions.
    InteractedFraction,
    /// Share that are shared-bytecode relations — the cloned-contract shape.
    SameCodeHashFraction,
    /// Herfindahl index over per-counterparty observation counts: `1.0` = all
    /// flow through one counterparty, → `0.0` = spread evenly over many.
    CounterpartyConcentration,
    /// Share of observations with a counterparty this address met more than
    /// once — a repeat relationship vs. one-shot fan-out.
    RepeatCounterpartyFraction,
    /// Whether any *monetary* magnitude backs the flow features above.
    /// Always `0.0` in v1: the adjacency store records relations, not amounts
    /// (see [`super`]'s module docs). Encoded, never imputed.
    ValueMagnitudeKnown,

    // ── incident history ────────────────────────────────────────────
    /// Confirmed incidents attributed to this address's entity.
    AttributedIncidentCountLog,
    /// Those incidents summed with a [`INCIDENT_HALF_LIFE_DAYS`] decay — a
    /// long-quiet history and a live one are different behaviors, which the
    /// raw count alone cannot distinguish.
    IncidentRecencyWeight,
    /// Size of the entity this address belongs to.
    EntitySizeLog,
    /// A sanctions-list match (§8.5).
    IsSanctioned,
    /// The address's own active labels.
    OwnLabelCountLog,
    /// It carries an illicit label of its own.
    HasIllicitLabel,
    /// It carries an MEV-actor label of its own.
    HasMevLabel,
}

impl BehaviorFeature {
    /// The scaling convention — exhaustive, so a new variant cannot ship
    /// unclassified.
    pub fn kind(self) -> FeatureKind {
        use BehaviorFeature as F;
        match self {
            F::ActivityDensity
            | F::BusiestDayShare
            | F::RecentWindowShare
            | F::LabeledCounterpartyFraction
            | F::VenueCounterpartyFraction
            | F::MevCounterpartyFraction
            | F::IllicitCounterpartyFraction
            | F::ProtocolCounterpartyFraction
            | F::CounterpartyTypeEntropy
            | F::OutboundObservationFraction
            | F::FundedOutFraction
            | F::FundedInFraction
            | F::DeployedFraction
            | F::ProfitReceiverFraction
            | F::InteractedFraction
            | F::SameCodeHashFraction
            | F::CounterpartyConcentration
            | F::RepeatCounterpartyFraction => FeatureKind::Fraction,
            F::IsHub
            | F::ValueMagnitudeKnown
            | F::IsSanctioned
            | F::HasIllicitLabel
            | F::HasMevLabel => FeatureKind::Indicator,
            F::ObservationCountLog
            | F::LifespanDaysLog
            | F::ActiveDaysLog
            | F::RecencyDaysLog
            | F::MeanGapDaysLog
            | F::CounterpartyCountLog
            | F::AttributedIncidentCountLog
            | F::EntitySizeLog
            | F::OwnLabelCountLog => FeatureKind::LogMagnitude,
            F::IncidentRecencyWeight => FeatureKind::Ratio,
        }
    }

    /// The feature's stable wire name (the strum `snake_case` form).
    pub fn name(self) -> &'static str {
        self.into()
    }

    /// This feature's index in a v1 vector — the typed accessor a caller that
    /// knows it is reading v1 uses, instead of
    /// [`BehaviorVector::get`](super::BehaviorVector::get)'s name lookup.
    pub fn index(self) -> usize {
        BehaviorFeature::iter()
            .position(|f| f == self)
            .expect("BehaviorFeature::iter yields every variant")
    }
}

/// v1's frozen schema, built once from the enum.
pub static SCHEMA: LazyLock<BehaviorSchema> = LazyLock::new(|| {
    BehaviorSchema::new(
        VERSION,
        BehaviorFeature::iter()
            .map(|feature| FeatureDef {
                name: feature.name(),
                kind: feature.kind(),
            })
            .collect(),
    )
});

/// The v1 embedder — a unit struct so the roster can hold it in a `static`.
#[derive(Debug, Clone, Copy)]
pub struct Embedder;

impl BehaviorEmbedder for Embedder {
    fn schema(&self) -> &'static BehaviorSchema {
        &SCHEMA
    }

    fn embed(
        &self,
        address: AccountAddress,
        entity_id: Option<EntityId>,
        inputs: &BehaviorInputs,
        as_of: DateTime<Utc>,
    ) -> BehaviorVector {
        embed(address, entity_id, inputs, as_of)
    }
}

/// Which behavioral bucket a counterparty's labels put it in. Coarser than
/// [`LabelKind`] on purpose: the distribution over ten label kinds is mostly
/// zeros for any real address, and the *behavioral* question is which kind of
/// company an address keeps, not which exact tag its counterparty carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CounterpartyClass {
    /// Illicit — dominates: one scammer counterparty is the fact worth
    /// keeping, even among a hundred protocol contracts.
    Illicit,
    Mev,
    Venue,
    Protocol,
    Unlabeled,
}

impl CounterpartyClass {
    /// The single class for a counterparty carrying `kinds`, strongest-wins in
    /// [`CounterpartyClass`]'s own declaration order — so an address that is
    /// both a CEX wallet and a known scammer counts once, as a scammer.
    fn strongest(kinds: &[LabelKind]) -> Self {
        kinds
            .iter()
            .map(|kind| match kind {
                LabelKind::KnownScammer
                | LabelKind::SanctionedEntity
                | LabelKind::ScammerAssociate
                | LabelKind::MixerUser => CounterpartyClass::Illicit,
                LabelKind::MevBot | LabelKind::BuilderAddress => CounterpartyClass::Mev,
                LabelKind::CexWallet | LabelKind::Bridge => CounterpartyClass::Venue,
                LabelKind::Protocol | LabelKind::Deployer => CounterpartyClass::Protocol,
            })
            .min()
            .unwrap_or(CounterpartyClass::Unlabeled)
    }
}

/// The cadence facts one pass over the history yields — computed together
/// because they share the same scan and the same "empty history" answer.
struct Cadence {
    lifespan_days: f64,
    active_days: u64,
    recency_days: f64,
    busiest_day_share: f64,
    recent_window_share: f64,
    mean_gap_days: f64,
}

/// Cadence over `edges`, `as_of` a given instant. `edges` need not be sorted —
/// the caller's ordering is a store concern, and a kernel that silently
/// depended on it would be wrong the first time a double returned them
/// oldest-first.
/// Truncate an instant to the start of its UTC day.
///
/// **The clock enters a behavior vector at day resolution, deliberately.**
/// Three features are functions of `as_of` rather than of the observations
/// alone (recency, the trailing-window share, and the incident decay). With a
/// continuous clock every one of them moves on *every* recomputation, so a
/// dormant address — the case the schedule exists to notice — would produce a
/// different vector every hour forever, and the change detection in
/// [`crate::embedding_job`] would never once skip a write.
///
/// Quantizing is also the better statistic: sub-day precision in "days since
/// last seen" is spurious, and a similarity search that ranked on it would be
/// ranking on when the sweep happened to run.
fn as_of_day(as_of: DateTime<Utc>) -> DateTime<Utc> {
    as_of
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .map(|naive| naive.and_utc())
        .unwrap_or(as_of)
}

fn cadence(edges: &[AddressEdge], as_of: DateTime<Utc>) -> Cadence {
    if edges.is_empty() {
        return Cadence {
            lifespan_days: 0.0,
            active_days: 0,
            recency_days: 0.0,
            busiest_day_share: 0.0,
            recent_window_share: 0.0,
            mean_gap_days: 0.0,
        };
    }

    let mut timestamps: Vec<DateTime<Utc>> = edges.iter().map(|e| e.observed_at).collect();
    timestamps.sort_unstable();
    let first = timestamps[0];
    let last = timestamps[timestamps.len() - 1];

    // Keyed by the UTC calendar date itself — "distinct days active" is a
    // calendar question, not a `timestamp / 86400` one, and bucketing by
    // epoch-day arithmetic would silently answer a different question for any
    // future non-UTC reading.
    let mut per_day: BTreeMap<chrono::NaiveDate, u64> = BTreeMap::new();
    for at in &timestamps {
        *per_day.entry(at.date_naive()).or_default() += 1;
    }
    let busiest = per_day.values().copied().max().unwrap_or(0);

    // Both clock-dependent quantities read the *day*, not the instant — see
    // `as_of_day`.
    let today = as_of_day(as_of);
    let window_start = today - chrono::Duration::seconds((RECENT_WINDOW_DAYS * 86_400.0) as i64);
    let recent = timestamps.iter().filter(|at| **at >= window_start).count();

    let lifespan_days = days_between(first, last);
    // Mean *gap*, not mean spacing: n observations have n-1 gaps, and a single
    // observation has none (0.0, not a division by zero).
    let mean_gap_days = ratio(lifespan_days, (timestamps.len().saturating_sub(1)) as f64);

    Cadence {
        lifespan_days,
        active_days: per_day.len() as u64,
        recency_days: days_between(last, today),
        busiest_day_share: ratio(busiest as f64, timestamps.len() as f64),
        recent_window_share: ratio(recent as f64, timestamps.len() as f64),
        mean_gap_days,
    }
}

/// The counterparty-side facts: per-counterparty observation counts and the
/// class census, from one pass over the history joined to the label map.
struct Counterparties {
    /// Observations per distinct counterparty.
    counts: BTreeMap<AccountAddress, u64>,
    /// Distinct counterparties per behavioral class.
    census: BTreeMap<CounterpartyClass, u64>,
}

fn counterparties(
    edges: &[AddressEdge],
    labels: &BTreeMap<AccountAddress, Vec<LabelKind>>,
) -> Counterparties {
    let mut counts: BTreeMap<AccountAddress, u64> = BTreeMap::new();
    for edge in edges {
        *counts.entry(edge.counterparty).or_default() += 1;
    }
    let mut census: BTreeMap<CounterpartyClass, u64> = BTreeMap::new();
    for counterparty in counts.keys() {
        let class = labels
            .get(counterparty)
            .map(|kinds| CounterpartyClass::strongest(kinds))
            .unwrap_or(CounterpartyClass::Unlabeled);
        *census.entry(class).or_default() += 1;
    }
    Counterparties { counts, census }
}

/// Normalized Shannon entropy of a census over `buckets` classes, in `[0, 1]`.
/// A single populated class is `0.0`; an even spread over all of them is
/// `1.0`. Normalizing by `log(buckets)` is what makes the number comparable
/// across addresses instead of scaling with how many classes happen to appear.
fn normalized_entropy(census: &BTreeMap<CounterpartyClass, u64>, buckets: usize) -> f64 {
    let total: u64 = census.values().sum();
    if total == 0 || buckets < 2 {
        return 0.0;
    }
    let entropy: f64 = census
        .values()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / total as f64;
            -p * libm::log(p)
        })
        .sum();
    (entropy / libm::log(buckets as f64)).clamp(0.0, 1.0)
}

/// Share of observations whose kind and direction match `predicate`.
fn edge_share(edges: &[AddressEdge], predicate: impl Fn(&AddressEdge) -> bool) -> f64 {
    ratio(
        edges.iter().filter(|e| predicate(e)).count() as f64,
        edges.len() as f64,
    )
}

/// Compute one address's v1 behavior vector from already-fetched
/// [`BehaviorInputs`], `as_of` a given instant.
///
/// Every feature is bounded or log-scaled by its [`FeatureKind`], and an
/// address with no recorded behavior yields an all-zero vector rather than a
/// vector of plausible-looking defaults: "nothing observed" must be
/// distinguishable from "observed, and unremarkable".
pub fn embed(
    address: AccountAddress,
    entity_id: Option<EntityId>,
    inputs: &BehaviorInputs,
    as_of: DateTime<Utc>,
) -> BehaviorVector {
    let edges = &inputs.history.edges;
    let observations = edges.len() as f64;

    let cadence = cadence(edges, as_of);
    let parties = counterparties(edges, &inputs.counterparty_labels);
    let counterparty_count = parties.counts.len() as f64;

    let class_share = |class: CounterpartyClass| {
        ratio(
            parties.census.get(&class).copied().unwrap_or(0) as f64,
            counterparty_count,
        )
    };

    // Herfindahl over per-counterparty observation shares. Defined as 0.0 for
    // an empty history (no concentration to speak of) rather than 1.0, which
    // would make a silent address look maximally focused.
    let concentration: f64 = parties
        .counts
        .values()
        .map(|count| {
            let share = ratio(*count as f64, observations);
            share * share
        })
        .sum();

    // Counted, not derived as `1 - unlabeled_share`: with no counterparties at
    // all that subtraction reports "100% labeled" off a 0/0, which is exactly
    // the fabricated default this schema exists to avoid.
    let labeled_counterparties = counterparty_count
        - parties
            .census
            .get(&CounterpartyClass::Unlabeled)
            .copied()
            .unwrap_or(0) as f64;

    let repeat_observations: u64 = parties.counts.values().filter(|c| **c > 1).sum();

    let own_kinds: Vec<LabelKind> = inputs.labels.iter().map(|label| label.kind).collect();
    let own_class = CounterpartyClass::strongest(&own_kinds);

    // Quantized like the cadence clock: a decay evaluated at the instant would
    // move on every recomputation and make every attributed address look
    // "changed" forever (see `as_of_day`).
    let today = as_of_day(as_of);
    let incident_weight: f64 = inputs
        .attributions
        .iter()
        .map(|attribution| {
            let age = days_between(attribution.attributed_at, today);
            0.5_f64.powf(age / INCIDENT_HALF_LIFE_DAYS)
        })
        .sum();

    let entity_size = inputs
        .entity
        .as_ref()
        .map(|entity| entity.addresses.len())
        .unwrap_or(0) as f64;

    use BehaviorFeature as F;
    let values: Vec<f32> = BehaviorFeature::iter()
        .map(|feature| {
            let value: f64 = match feature {
                // — activity cadence —
                F::ObservationCountLog => log_magnitude(observations),
                F::LifespanDaysLog => log_magnitude(cadence.lifespan_days),
                F::ActiveDaysLog => log_magnitude(cadence.active_days as f64),
                F::RecencyDaysLog => log_magnitude(cadence.recency_days),
                F::ActivityDensity => {
                    ratio(cadence.active_days as f64, cadence.lifespan_days + 1.0).clamp(0.0, 1.0)
                }
                F::BusiestDayShare => cadence.busiest_day_share,
                F::RecentWindowShare => cadence.recent_window_share,
                F::MeanGapDaysLog => log_magnitude(cadence.mean_gap_days),

                // — counterparty-type distribution —
                F::CounterpartyCountLog => log_magnitude(counterparty_count),
                F::LabeledCounterpartyFraction => ratio(labeled_counterparties, counterparty_count),
                F::VenueCounterpartyFraction => class_share(CounterpartyClass::Venue),
                F::MevCounterpartyFraction => class_share(CounterpartyClass::Mev),
                F::IllicitCounterpartyFraction => class_share(CounterpartyClass::Illicit),
                F::ProtocolCounterpartyFraction => class_share(CounterpartyClass::Protocol),
                F::CounterpartyTypeEntropy => normalized_entropy(&parties.census, 5),
                F::IsHub => f64::from(u8::from(inputs.history.truncated)),

                // — value-flow shape —
                F::OutboundObservationFraction => edge_share(edges, |e| e.outbound),
                F::FundedOutFraction => {
                    edge_share(edges, |e| e.kind == EdgeKind::Funded && e.outbound)
                }
                F::FundedInFraction => {
                    edge_share(edges, |e| e.kind == EdgeKind::Funded && !e.outbound)
                }
                F::DeployedFraction => edge_share(edges, |e| e.kind == EdgeKind::Deployed),
                F::ProfitReceiverFraction => {
                    edge_share(edges, |e| e.kind == EdgeKind::ProfitReceiver)
                }
                F::InteractedFraction => edge_share(edges, |e| e.kind == EdgeKind::Interacted),
                F::SameCodeHashFraction => edge_share(edges, |e| e.kind == EdgeKind::SameCodeHash),
                F::CounterpartyConcentration => concentration.clamp(0.0, 1.0),
                F::RepeatCounterpartyFraction => ratio(repeat_observations as f64, observations),
                // Encoded, never imputed — see the module docs.
                F::ValueMagnitudeKnown => 0.0,

                // — incident history —
                F::AttributedIncidentCountLog => log_magnitude(inputs.attributions.len() as f64),
                F::IncidentRecencyWeight => incident_weight,
                F::EntitySizeLog => log_magnitude(entity_size),
                F::IsSanctioned => f64::from(u8::from(!inputs.sanctions.is_empty())),
                F::OwnLabelCountLog => log_magnitude(inputs.labels.len() as f64),
                F::HasIllicitLabel => f64::from(u8::from(own_class == CounterpartyClass::Illicit)),
                F::HasMevLabel => f64::from(u8::from(own_class == CounterpartyClass::Mev)),
            };
            store_value(value)
        })
        .collect();

    BehaviorVector {
        address,
        entity_id,
        schema: &SCHEMA,
        values,
        observations_truncated: inputs.history.truncated,
        computed_at: as_of,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedding::MAX_VISIBLE_FACTORS;
    use crate::model::{
        AttributionRecord, EdgeHistory, EntityRecord, EntityStatus, LabelRecord, LabelSource,
        SanctionEntry,
    };
    use alloy_primitives::Address;
    use events::primitives::{Confidence, IncidentId, LabelId};
    use proptest::prelude::*;

    const DAY: i64 = 86_400;

    /// Typed feature read — the v1-internal accessor, so these tests break on a
    /// reordered schema instead of silently asserting about the wrong column.
    fn get(vector: &BehaviorVector, feature: BehaviorFeature) -> f32 {
        vector.values[feature.index()]
    }

    fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn edge(counterparty: u8, kind: EdgeKind, outbound: bool, at_secs: i64) -> AddressEdge {
        AddressEdge {
            counterparty: addr(counterparty),
            kind,
            outbound,
            block_number: at_secs as u64,
            observed_at: at(at_secs),
        }
    }

    fn history(edges: Vec<AddressEdge>) -> EdgeHistory {
        EdgeHistory {
            edges,
            truncated: false,
        }
    }

    fn label(kind: LabelKind) -> LabelRecord {
        LabelRecord {
            label_id: LabelId::new(),
            address: addr(0x01),
            kind,
            value: "test".into(),
            confidence: LabelSource::Manual.default_confidence(),
            source: LabelSource::Manual,
            source_detail: "unit-test".into(),
            created_at: at(0),
            valid_until: None,
        }
    }

    fn attribution(attributed_at: DateTime<Utc>) -> AttributionRecord {
        AttributionRecord {
            incident_id: IncidentId::new(),
            entity_id: EntityId::new(),
            confidence: Confidence::new(1.0),
            evidence: "unit-test".into(),
            attributed_at,
        }
    }

    fn entity(members: usize) -> EntityRecord {
        EntityRecord {
            entity_id: EntityId::new(),
            version: 1,
            status: EntityStatus::Active,
            absorbed_into: None,
            addresses: (0..members as u8).map(addr).collect(),
            created_at: at(0),
        }
    }

    // ── The frozen schema ────────────────────────────────────────────

    /// The schema is FROZEN: this hash is the contract. A failure here means a
    /// feature was added, removed, reordered, or reclassified — all of which
    /// make old vectors incomparable to new ones. The fix is a **new version
    /// module** registered alongside this one, not a new golden, unless
    /// [`VERSION`] moved in the same change (the same stance as the
    /// event-schema wire-format lock).
    #[test]
    fn schema_hash_is_pinned() {
        assert_eq!(
            SCHEMA.content_hash(),
            "05b2972272f5f5fdcd82f16cfeeade590bdc8deca4d53a570fe9063c432b0341",
            "the v1 behavior schema changed — see this test's doc comment"
        );
    }

    #[test]
    fn dimension_and_names_are_derived_from_the_schema_enum() {
        let vector = embed(addr(1), None, &BehaviorInputs::default(), at(0));
        assert_eq!(vector.values.len(), SCHEMA.dimension());
        assert_eq!(BehaviorFeature::iter().count(), SCHEMA.dimension());
        for feature in BehaviorFeature::iter() {
            assert_eq!(
                SCHEMA.index_of(feature.name()),
                Some(feature.index()),
                "{} is not at its own index",
                feature.name()
            );
        }
    }

    // ── The empty case ───────────────────────────────────────────────

    /// "Nothing observed" must be distinguishable from "observed, and
    /// unremarkable" — so an address with no facts at all is exactly zero, not
    /// a vector of plausible-looking defaults.
    #[test]
    fn no_behavior_is_an_all_zero_vector() {
        let vector = embed(addr(1), None, &BehaviorInputs::default(), at(1_000));
        assert!(
            vector.values.iter().all(|v| *v == 0.0),
            "{:?}",
            vector.values
        );
        // Positive zero specifically: `-0.0` compares equal but stores as
        // different bits, and `content_digest` hashes the bits.
        assert!(
            vector.values.iter().all(|v| v.is_sign_positive()),
            "a negative zero leaked into the vector: {:?}",
            vector.values
        );
        assert!(vector.top_factors(8).is_empty());
        assert_eq!(vector.embedding_version(), VERSION);
        assert!(!vector.observations_truncated);
    }

    // ── Activity cadence ─────────────────────────────────────────────

    #[test]
    fn a_daily_bot_and_a_one_day_burst_differ_in_cadence() {
        // Same observation count, opposite cadence: one edge a day for ten
        // days vs. ten edges in one day.
        let daily = history(
            (0..10)
                .map(|d| edge(0xAA, EdgeKind::Interacted, true, d * DAY))
                .collect(),
        );
        let burst = history(
            (0..10)
                .map(|i| edge(0xAA, EdgeKind::Interacted, true, i * 60))
                .collect(),
        );
        let as_of = at(10 * DAY);

        let daily = embed(
            addr(1),
            None,
            &BehaviorInputs {
                history: daily,
                ..Default::default()
            },
            as_of,
        );
        let burst = embed(
            addr(1),
            None,
            &BehaviorInputs {
                history: burst,
                ..Default::default()
            },
            as_of,
        );

        assert_eq!(
            get(&daily, BehaviorFeature::ObservationCountLog),
            get(&burst, BehaviorFeature::ObservationCountLog),
            "the count family must not be what separates them"
        );
        assert!(
            get(&daily, BehaviorFeature::ActiveDaysLog)
                > get(&burst, BehaviorFeature::ActiveDaysLog)
        );
        assert!(
            get(&daily, BehaviorFeature::BusiestDayShare)
                < get(&burst, BehaviorFeature::BusiestDayShare)
        );
        assert_eq!(get(&burst, BehaviorFeature::BusiestDayShare), 1.0);
    }

    #[test]
    fn dormancy_shows_up_as_recency_and_recent_window_share() {
        let edges = history(vec![edge(0xAA, EdgeKind::Interacted, true, 0)]);
        let fresh = embed(
            addr(1),
            None,
            &BehaviorInputs {
                history: edges.clone(),
                ..Default::default()
            },
            at(0),
        );
        let dormant = embed(
            addr(1),
            None,
            &BehaviorInputs {
                history: edges,
                ..Default::default()
            },
            at(400 * DAY),
        );

        assert_eq!(get(&fresh, BehaviorFeature::RecencyDaysLog), 0.0);
        assert!(get(&dormant, BehaviorFeature::RecencyDaysLog) > 2.0);
        assert_eq!(get(&fresh, BehaviorFeature::RecentWindowShare), 1.0);
        assert_eq!(get(&dormant, BehaviorFeature::RecentWindowShare), 0.0);
    }

    /// A single observation has no *gaps* — zero, not a division by zero and
    /// not a fabricated interval.
    #[test]
    fn a_single_observation_has_no_mean_gap() {
        let vector = embed(
            addr(1),
            None,
            &BehaviorInputs {
                history: history(vec![edge(0xAA, EdgeKind::Funded, false, 0)]),
                ..Default::default()
            },
            at(DAY),
        );
        assert_eq!(get(&vector, BehaviorFeature::MeanGapDaysLog), 0.0);
        assert_eq!(get(&vector, BehaviorFeature::LifespanDaysLog), 0.0);
    }

    // ── Counterparty-type distribution ───────────────────────────────

    #[test]
    fn counterparty_classes_are_strongest_wins() {
        // A counterparty that is both a CEX wallet and a known scammer counts
        // once, as illicit — the strongest claim, not the first read.
        assert_eq!(
            CounterpartyClass::strongest(&[LabelKind::CexWallet, LabelKind::KnownScammer]),
            CounterpartyClass::Illicit
        );
        assert_eq!(
            CounterpartyClass::strongest(&[LabelKind::Protocol, LabelKind::MevBot]),
            CounterpartyClass::Mev
        );
        assert_eq!(
            CounterpartyClass::strongest(&[]),
            CounterpartyClass::Unlabeled
        );
    }

    #[test]
    fn counterparty_distribution_is_over_distinct_counterparties() {
        // Three observations, two counterparties, one of them labeled: the
        // labeled *share* is 1/2 (per counterparty), not 2/3 (per edge) — a
        // chatty counterparty must not dominate the distribution.
        let inputs = BehaviorInputs {
            history: history(vec![
                edge(0xAA, EdgeKind::Interacted, true, 0),
                edge(0xAA, EdgeKind::Interacted, true, 60),
                edge(0xBB, EdgeKind::Interacted, true, 120),
            ]),
            counterparty_labels: BTreeMap::from([(addr(0xAA), vec![LabelKind::CexWallet])]),
            ..Default::default()
        };
        let vector = embed(addr(1), None, &inputs, at(DAY));
        assert_eq!(
            get(&vector, BehaviorFeature::LabeledCounterpartyFraction),
            0.5
        );
        assert_eq!(
            get(&vector, BehaviorFeature::VenueCounterpartyFraction),
            0.5
        );
        assert_eq!(
            get(&vector, BehaviorFeature::IllicitCounterpartyFraction),
            0.0
        );
    }

    #[test]
    fn one_kind_of_counterparty_is_zero_entropy() {
        let inputs = BehaviorInputs {
            history: history(vec![
                edge(0xAA, EdgeKind::Interacted, true, 0),
                edge(0xBB, EdgeKind::Interacted, true, 60),
            ]),
            counterparty_labels: BTreeMap::from([
                (addr(0xAA), vec![LabelKind::MevBot]),
                (addr(0xBB), vec![LabelKind::BuilderAddress]),
            ]),
            ..Default::default()
        };
        let vector = embed(addr(1), None, &inputs, at(DAY));
        assert_eq!(get(&vector, BehaviorFeature::MevCounterpartyFraction), 1.0);
        assert_eq!(get(&vector, BehaviorFeature::CounterpartyTypeEntropy), 0.0);
    }

    /// The hub flag is a *dimension of the vector*, not metadata beside it —
    /// otherwise a similarity search would compare a hub's recent window
    /// against a normal address's whole life with nothing marking the
    /// difference.
    #[test]
    fn truncation_is_carried_inside_the_vector() {
        let inputs = BehaviorInputs {
            history: EdgeHistory {
                edges: vec![edge(0xAA, EdgeKind::Interacted, true, 0)],
                truncated: true,
            },
            ..Default::default()
        };
        let vector = embed(addr(1), None, &inputs, at(DAY));
        assert_eq!(get(&vector, BehaviorFeature::IsHub), 1.0);
        assert!(vector.observations_truncated);
    }

    // ── Value-flow shape ─────────────────────────────────────────────

    #[test]
    fn flow_direction_and_kind_shares_split_the_history() {
        let inputs = BehaviorInputs {
            history: history(vec![
                edge(0xAA, EdgeKind::Funded, true, 0),
                edge(0xBB, EdgeKind::Funded, false, 60),
                edge(0xCC, EdgeKind::Deployed, true, 120),
                edge(0xDD, EdgeKind::Interacted, false, 180),
            ]),
            ..Default::default()
        };
        let vector = embed(addr(1), None, &inputs, at(DAY));
        assert_eq!(
            get(&vector, BehaviorFeature::OutboundObservationFraction),
            0.5
        );
        assert_eq!(get(&vector, BehaviorFeature::FundedOutFraction), 0.25);
        assert_eq!(get(&vector, BehaviorFeature::FundedInFraction), 0.25);
        assert_eq!(get(&vector, BehaviorFeature::DeployedFraction), 0.25);
        assert_eq!(get(&vector, BehaviorFeature::InteractedFraction), 0.25);
        assert_eq!(get(&vector, BehaviorFeature::ProfitReceiverFraction), 0.0);
    }

    #[test]
    fn concentration_separates_one_counterparty_from_many() {
        let focused = BehaviorInputs {
            history: history(
                (0..4)
                    .map(|i| edge(0xAA, EdgeKind::Interacted, true, i * 60))
                    .collect(),
            ),
            ..Default::default()
        };
        let spread = BehaviorInputs {
            history: history(
                (0..4)
                    .map(|i| edge(0xA0 + i as u8, EdgeKind::Interacted, true, i * 60))
                    .collect(),
            ),
            ..Default::default()
        };
        let focused = embed(addr(1), None, &focused, at(DAY));
        let spread = embed(addr(1), None, &spread, at(DAY));

        assert_eq!(
            get(&focused, BehaviorFeature::CounterpartyConcentration),
            1.0
        );
        assert_eq!(
            get(&focused, BehaviorFeature::RepeatCounterpartyFraction),
            1.0
        );
        assert_eq!(
            get(&spread, BehaviorFeature::CounterpartyConcentration),
            0.25
        );
        assert_eq!(
            get(&spread, BehaviorFeature::RepeatCounterpartyFraction),
            0.0
        );
    }

    /// The adjacency store records relations, never amounts — so this reports
    /// "unknown", and a reader can tell that apart from "zero volume".
    #[test]
    fn value_magnitude_is_reported_as_unknown_not_zero_volume() {
        let inputs = BehaviorInputs {
            history: history(vec![edge(0xAA, EdgeKind::Funded, true, 0)]),
            ..Default::default()
        };
        let vector = embed(addr(1), None, &inputs, at(DAY));
        assert_eq!(get(&vector, BehaviorFeature::ValueMagnitudeKnown), 0.0);
    }

    // ── Incident history ─────────────────────────────────────────────

    #[test]
    fn incident_history_decays_but_the_count_does_not() {
        let inputs = BehaviorInputs {
            attributions: vec![attribution(at(0)), attribution(at(0))],
            ..Default::default()
        };
        let fresh = embed(addr(1), None, &inputs, at(0));
        let old = embed(addr(1), None, &inputs, at(360 * DAY)); // two half-lives

        assert_eq!(
            get(&fresh, BehaviorFeature::AttributedIncidentCountLog),
            get(&old, BehaviorFeature::AttributedIncidentCountLog)
        );
        assert_eq!(get(&fresh, BehaviorFeature::IncidentRecencyWeight), 2.0);
        assert!(get(&old, BehaviorFeature::IncidentRecencyWeight) < 0.6);
        assert!(get(&old, BehaviorFeature::IncidentRecencyWeight) > 0.0);
    }

    #[test]
    fn own_identity_features_read_the_address_own_labels() {
        let inputs = BehaviorInputs {
            labels: vec![label(LabelKind::MevBot)],
            sanctions: vec![SanctionEntry {
                address: addr(1),
                list_name: "ofac_sdn".into(),
                entry: "Evil Corp".into(),
                listed_at: None,
            }],
            entity: Some(entity(4)),
            ..Default::default()
        };
        let vector = embed(addr(1), None, &inputs, at(DAY));
        assert_eq!(get(&vector, BehaviorFeature::IsSanctioned), 1.0);
        assert_eq!(get(&vector, BehaviorFeature::HasMevLabel), 1.0);
        assert_eq!(get(&vector, BehaviorFeature::HasIllicitLabel), 0.0);
        assert!(get(&vector, BehaviorFeature::EntitySizeLog) > 0.0);
    }

    // ── The clock enters at day resolution ───────────────────────────

    /// The property that makes change detection pay for its keep.
    ///
    /// Three features are functions of `as_of` rather than of the observations
    /// alone. With a continuous clock, a dormant address — precisely the case
    /// the *schedule* exists to notice — would produce a different vector on
    /// every single recomputation, so nothing could ever be skipped and the
    /// store would grow as address-space x sweep-interval forever.
    #[test]
    fn a_dormant_address_is_stable_within_a_day_and_moves_across_one() {
        let inputs = BehaviorInputs {
            history: history(vec![edge(0xAA, EdgeKind::Interacted, true, 0)]),
            attributions: vec![attribution(at(0))],
            ..Default::default()
        };
        // Same UTC day, hours apart.
        let morning = embed(addr(1), None, &inputs, at(100 * DAY + 3_600));
        let evening = embed(addr(1), None, &inputs, at(100 * DAY + 20 * 3_600));
        assert_eq!(morning.values, evening.values);
        assert_eq!(morning.content_digest(), evening.content_digest());

        // The next day, it genuinely is older.
        let tomorrow = embed(addr(1), None, &inputs, at(101 * DAY + 3_600));
        assert_ne!(morning.values, tomorrow.values);
        assert!(
            get(&tomorrow, BehaviorFeature::RecencyDaysLog)
                > get(&morning, BehaviorFeature::RecencyDaysLog)
        );
        assert!(
            get(&tomorrow, BehaviorFeature::IncidentRecencyWeight)
                < get(&morning, BehaviorFeature::IncidentRecencyWeight)
        );
    }

    /// The trailing-window boundary is quantized too, so an observation does
    /// not drift in and out of the window between two ticks of the same day.
    #[test]
    fn the_recent_window_boundary_is_quantized_to_the_day() {
        let inputs = BehaviorInputs {
            history: history(vec![
                edge(0xAA, EdgeKind::Interacted, true, 0),
                edge(0xBB, EdgeKind::Interacted, true, 40 * DAY),
            ]),
            ..Default::default()
        };
        let early = embed(addr(1), None, &inputs, at(50 * DAY + 60));
        let late = embed(addr(1), None, &inputs, at(50 * DAY + 23 * 3_600));
        assert_eq!(
            get(&early, BehaviorFeature::RecentWindowShare),
            get(&late, BehaviorFeature::RecentWindowShare)
        );
    }

    // ── Determinism (§18) ────────────────────────────────────────────

    /// The kernel must not depend on the order the store happened to return
    /// observations in — a double returning them oldest-first and ClickHouse
    /// returning them newest-first must produce the same bits.
    #[test]
    fn the_vector_does_not_depend_on_history_order() {
        let edges = vec![
            edge(0xAA, EdgeKind::Funded, true, 3 * DAY),
            edge(0xBB, EdgeKind::Interacted, false, DAY),
            edge(0xAA, EdgeKind::ProfitReceiver, false, 2 * DAY),
        ];
        let mut reversed = edges.clone();
        reversed.reverse();

        let forward = embed(
            addr(1),
            None,
            &BehaviorInputs {
                history: history(edges),
                ..Default::default()
            },
            at(4 * DAY),
        );
        let backward = embed(
            addr(1),
            None,
            &BehaviorInputs {
                history: history(reversed),
                ..Default::default()
            },
            at(4 * DAY),
        );
        assert_eq!(forward.values, backward.values);
        assert_eq!(forward.content_digest(), backward.content_digest());
    }

    // ── Explainability ───────────────────────────────────────────────

    #[test]
    fn top_factors_are_share_ordered_bounded_and_reconcile() {
        let inputs = BehaviorInputs {
            history: history(
                (0..20)
                    .map(|i| edge(0xA0 + (i % 3) as u8, EdgeKind::Interacted, true, i * DAY))
                    .collect(),
            ),
            attributions: vec![attribution(at(0)); 3],
            entity: Some(entity(6)),
            ..Default::default()
        };
        let vector = embed(addr(1), None, &inputs, at(20 * DAY));
        let factors = vector.top_factors(MAX_VISIBLE_FACTORS);

        assert!(factors.len() <= MAX_VISIBLE_FACTORS);
        assert!(!factors.is_empty());
        for pair in factors.windows(2) {
            assert!(
                pair[0].share >= pair[1].share,
                "factors must be share-ordered"
            );
        }
        // Every reported factor is a real dimension of the vector, at its
        // actual value — the explanation is a view, never a second number.
        for factor in &factors {
            assert_eq!(vector.get(&factor.feature), Some(factor.value));
        }
        // Shares are a partition of the squared magnitude, so the visible ones
        // can never exceed the whole.
        let visible: f32 = factors.iter().map(|f| f.share).sum();
        assert!(visible <= 1.0001, "visible share {visible} exceeds 1.0");
    }

    #[test]
    fn zero_valued_features_are_never_reported_as_factors() {
        let inputs = BehaviorInputs {
            history: history(vec![edge(0xAA, EdgeKind::Funded, true, 0)]),
            ..Default::default()
        };
        let vector = embed(addr(1), None, &inputs, at(0));
        for factor in vector.top_factors(MAX_VISIBLE_FACTORS) {
            assert_ne!(factor.value, 0.0, "{} is zero", factor.feature);
        }
    }

    #[test]
    fn the_event_carries_the_whole_vector_and_a_bounded_explanation() {
        let inputs = BehaviorInputs {
            history: history(vec![edge(0xAA, EdgeKind::Funded, true, 0)]),
            ..Default::default()
        };
        let vector = embed(addr(1), Some(EntityId::new()), &inputs, at(0));
        let event = vector.to_event();

        assert_eq!(event.vector, vector.values);
        assert_eq!(event.embedding_version, VERSION);
        assert_eq!(event.schema_hash, SCHEMA.content_hash());
        assert!(event.top_factors.len() <= MAX_VISIBLE_FACTORS);
        assert!(!event.observations_truncated);
    }

    // ── Properties ───────────────────────────────────────────────────

    prop_compose! {
        fn arb_edge()(
            counterparty in 0u8..8,
            kind_index in 0usize..5,
            outbound in any::<bool>(),
            day in 0i64..400,
        ) -> AddressEdge {
            let kind = [
                EdgeKind::Funded,
                EdgeKind::Deployed,
                EdgeKind::ProfitReceiver,
                EdgeKind::SameCodeHash,
                EdgeKind::Interacted,
            ][kind_index];
            edge(counterparty, kind, outbound, day * DAY)
        }
    }

    proptest! {
        /// Every feature obeys the scaling convention its [`FeatureKind`]
        /// declares, for *any* history — the invariant a similarity search
        /// depends on and that no individual formula's unit test can prove.
        /// A `NaN` or an out-of-range fraction here would poison every
        /// distance computed against this vector.
        #[test]
        fn every_feature_stays_inside_its_declared_kind(
            edges in prop::collection::vec(arb_edge(), 0..40),
            truncated in any::<bool>(),
            attributions in 0usize..5,
            entity_size in 0usize..8,
            as_of_day in 0i64..500,
        ) {
            let inputs = BehaviorInputs {
                history: EdgeHistory { edges, truncated },
                attributions: vec![attribution(at(0)); attributions],
                entity: (entity_size > 0).then(|| entity(entity_size)),
                ..Default::default()
            };
            let vector = embed(addr(1), None, &inputs, at(as_of_day * DAY));

            for (feature, value) in BehaviorFeature::iter().zip(vector.values.iter().copied()) {
                prop_assert!(value.is_finite(), "{} is not finite: {value}", feature.name());
                match feature.kind() {
                    FeatureKind::Fraction => prop_assert!(
                        (0.0..=1.0).contains(&value),
                        "{} = {value} is outside [0, 1]", feature.name()
                    ),
                    FeatureKind::Indicator => prop_assert!(
                        value == 0.0 || value == 1.0,
                        "{} = {value} is not an indicator", feature.name()
                    ),
                    FeatureKind::LogMagnitude | FeatureKind::Ratio => prop_assert!(
                        value >= 0.0,
                        "{} = {value} is negative", feature.name()
                    ),
                }
            }
        }

        /// The same inputs always yield the same bits — replay determinism
        /// (§18) at the level the store keys on and `content_digest` hashes.
        #[test]
        fn embedding_is_bit_identical_across_runs(
            edges in prop::collection::vec(arb_edge(), 0..20),
            as_of_day in 0i64..500,
        ) {
            let inputs = BehaviorInputs {
                history: history(edges),
                ..Default::default()
            };
            let as_of = at(as_of_day * DAY);
            let first = embed(addr(1), None, &inputs, as_of);
            let second = embed(addr(1), None, &inputs, as_of);
            prop_assert_eq!(&first.values, &second.values);
            prop_assert_eq!(first.content_digest(), second.content_digest());
        }
    }
}
