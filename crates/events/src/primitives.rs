//! Shared value types used across event families: chain identifiers, block
//! references, strongly-typed entity ids, and small enums. Keeping these in one
//! place stops each family from inventing its own `block_hash: String`.

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Which chain an event pertains to. Kafka topics are partitioned by chain
/// (§20), and the event store partitions by `(chain, event_type, date)` (§4),
/// so this is the primary routing key carried on the [`crate::EventEnvelope`].
///
/// Modelled as a chain id so adding an L2 (Phase 10) needs no new variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(value_type = u64))]
#[serde(transparent)]
pub struct Chain(pub u64);

impl Chain {
    pub const ETHEREUM: Chain = Chain(1);
    /// Base (OP-stack L2, chain id 8453) — the first L2 through the pipeline
    /// (Phase 10, Sprint 13 t2).
    pub const BASE: Chain = Chain(8453);

    pub fn id(self) -> u64 {
        self.0
    }

    /// Human-readable name for the chains this deployment knows, for logs and
    /// metrics labels. `None` for an id we carry but don't recognize — callers
    /// fall back to [`Display`](std::fmt::Display) (`chain-<id>`), which is
    /// also the Kafka partition-key string and must never change.
    pub fn name(self) -> Option<&'static str> {
        match self {
            Chain::ETHEREUM => Some("ethereum"),
            Chain::BASE => Some("base"),
            _ => None,
        }
    }

    /// The chain's metrics-label value (§19): the human name for chains we
    /// know (`ethereum`, `base`), the partition-key form (`chain-<id>`) for
    /// ones we don't — so per-chain instances' series aggregate and filter by
    /// a stable, readable `chain` label.
    pub fn metrics_label(self) -> String {
        match self.name() {
            Some(name) => name.to_owned(),
            None => self.to_string(),
        }
    }

    /// Default finalization depth (blocks below the tip treated as final, §15)
    /// for chains we know; `None` means the deployment must configure a depth
    /// explicitly. The depth is the in-memory block-tree bound and reorg prune
    /// backstop — the authoritative finality signal is still the source's
    /// `finalized` tag (Sprint 1).
    ///
    /// * Ethereum: 64 — two epochs (2 × 32 slots), the standard finality lag.
    /// * Base: 1024 — an OP-stack L2's `finalized` tag trails the unsafe head
    ///   by batch-posting lag plus L1 finality (~20–35 min); at 2 s blocks
    ///   that's up to ~1050 blocks, so 1024 (~34 min) bounds the tree while
    ///   the tag drives actual finality.
    pub fn default_finalization_depth(self) -> Option<u64> {
        match self {
            Chain::ETHEREUM => Some(64),
            Chain::BASE => Some(1024),
            _ => None,
        }
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "chain-{}", self.0)
    }
}

/// A block identified by height and hash. Both are needed: height orders the
/// chain, hash disambiguates competing blocks at the same height during a reorg
/// (§5, §15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BlockRef {
    pub number: u64,
    /// 32-byte block hash, hex-encoded (`0x…`) on the wire.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub hash: B256,
}

impl BlockRef {
    pub fn new(number: u64, hash: B256) -> Self {
        Self { number, hash }
    }
}

/// What a detector/incident is about. Attribution-blind on the fast path (§6) —
/// this names the *behaviour*, never the actor.
///
/// `strum::IntoStaticStr` with `serialize_all = "snake_case"` mirrors the serde wire
/// form, so a consumer that needs the variant as a `&'static str` (e.g. a persistence
/// projection stamping it into a column) gets it derive-driven — guaranteed to stay in
/// sync with the variants, no hand-rolled match to drift (§2, same pattern as `EventFamily`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::IntoStaticStr, strum::EnumIter,
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum AlertKind {
    Sandwich,
    Arbitrage,
    Liquidation,
    Flashloan,
    Rugpull,
    WashTrading,
    AddressPoisoning,
}

/// What a label claims about an address (§8.1) — the platform's shared label
/// vocabulary. A closed enum — a new kind is a compile error at every `match` —
/// with the snake_case wire/storage string derive-driven (same pairing as
/// [`AlertKind`]).
///
/// Lives here (not in the intelligence service that mints labels) because it is
/// cross-service vocabulary: the rule engine's §9 conditions (`EntityLabel`,
/// `InteractedWith`) name label kinds in customer-defined rules, and validating
/// those against the closed set must use the *same* enum intelligence stores —
/// two copies would drift. The label *provenance* enum (`LabelSource`) stays in
/// `intelligence::model`: which class a claim came from is that service's
/// internal concern.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    // Ord so label kinds can key ordered collections (e.g. the rule engine's
    // enrichment sets) with deterministic iteration.
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::EnumIter,
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum LabelKind {
    CexWallet,
    MevBot,
    KnownScammer,
    Bridge,
    Protocol,
    Deployer,
    MixerUser,
    SanctionedEntity,
    /// Derived by association: clusters with a known scammer (§8.1), at reduced
    /// confidence.
    ScammerAssociate,
    BuilderAddress,
}

/// A lending protocol the predictive pipeline's position tracker knows how to
/// decode (§16.1) — `Aave`/`Compound` position events fold into a per-
/// `(protocol, account)` book, and the Sprint 16 task 2 cascade engine names
/// this on the wire in `LiquidationRiskPredicted`. Lives here (not in
/// `predictive`, which depends on `events`) for the same reason `LabelKind`
/// does: it's the one definition a wire event and its producer both use,
/// rather than two copies that could drift.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    strum::IntoStaticStr,
    strum::EnumIter,
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum LendingProtocol {
    Aave,
    Compound,
}

/// Coarse incident severity, set when simulation confirms an incident (§7). Carries the
/// same derive-driven `&'static str` mapping as [`AlertKind`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::IntoStaticStr, strum::EnumIter,
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// The operator-facing next step a [`Severity`] band recommends for a
/// provisional alert (§6) — a closed set so a consumer can render/route on it
/// without inventing its own bucketing. Derived purely from `severity`
/// (`detection::emit::suggested_action`); it carries no attribution opinion,
/// only "how urgently should a human look at this."
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::IntoStaticStr, strum::EnumIter,
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SuggestedAction {
    /// Low severity — log it, no operator action expected.
    Monitor,
    /// Medium severity — worth a human look, not urgent.
    Investigate,
    /// High severity — an operator should act on this alert.
    Escalate,
    /// Critical severity — page/act now.
    EscalateImmediately,
}

// ── Strongly-typed ids ───────────────────────────────────────────
// Newtypes over UUID so an `AlertId` can never be passed where an
// `IncidentId` is expected. `#[serde(transparent)]` keeps the wire form a
// plain UUID string.

macro_rules! id_newtype {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        #[cfg_attr(feature = "openapi", schema(value_type = String, format = Uuid))]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Mint a fresh random id.
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

id_newtype!(
    /// Preliminary alert id, minted by the detection service (§6).
    AlertId
);
id_newtype!(
    /// Predictive-pipeline forecast id, minted by the predictive service (§16).
    /// Distinct from [`AlertId`] — a prediction is a forecast, never
    /// sim-confirmed, so it never becomes an incident.
    PredictionId
);
id_newtype!(
    /// Confirmed incident id, minted by the simulation service (§7).
    IncidentId
);
id_newtype!(
    /// Intelligence entity (wallet cluster) id (§8.2).
    EntityId
);
id_newtype!(
    /// Wallet label id (§8.1).
    LabelId
);
id_newtype!(
    /// Customer-configurable rule id (§9).
    RuleId
);
id_newtype!(
    /// Billing customer id (§13).
    CustomerId
);

/// A detector's identity: `(id, version, config_hash)`. Every
/// [`crate::detection::DetectorTriggered`] must carry the exact triple so an
/// alert is reproducible against a specific model build (§6, §22).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DetectorRef {
    pub id: String,
    pub version: String,
    /// Hash of the detector config that produced this result — pins the exact
    /// behaviour for replay/backtesting (§18).
    pub config_hash: String,
}

/// Confidence value `value` is outside the valid `[0.0, 1.0]` range.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
#[error("confidence {value} is outside the range [0.0, 1.0]")]
pub struct ConfidenceOutOfRange {
    pub value: f64,
}

/// A confidence/probability in `[0.0, 1.0]`. A plain `f64` would silently admit
/// nonsense like `1.7`.
///
/// Two constructors, by intent: [`Confidence::new`] clamps and is for
/// known-good literals (e.g. a detector's hard-coded threshold);
/// [`Confidence::try_new`] validates and is for values from outside the process
/// (deserialized input, model output) where an out-of-range value is a bug you
/// want surfaced, not silently masked.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(value_type = f64))]
#[serde(transparent)]
pub struct Confidence(f64);

impl Confidence {
    /// Full certainty — `1.0`. A measured fact rather than an estimate: the slow
    /// path (§7) restamps its confirmed figures at this confidence, since the
    /// value is *known* to have moved and nothing should be discounted.
    pub const CERTAIN: Self = Self(1.0);

    /// Clamp `value` into `[0.0, 1.0]`. Use for trusted, in-code values.
    pub fn new(value: f64) -> Self {
        Self(value.clamp(0.0, 1.0))
    }

    /// Validate `value` is in `[0.0, 1.0]`, erroring otherwise. Use for
    /// untrusted input where clamping would hide a defect.
    pub fn try_new(value: f64) -> Result<Self, ConfidenceOutOfRange> {
        if (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ConfidenceOutOfRange { value })
        }
    }

    pub fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for Confidence {
    type Error = ConfidenceOutOfRange;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

/// A `UsdAmount` was constructed from a value that isn't a finite, non-negative
/// number.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
#[error("usd amount {value} is not a finite, non-negative number")]
pub struct InvalidUsdAmount {
    pub value: f64,
}

/// A non-negative USD quantity in *whole dollars* — a coarse, lossy estimate
/// fit for banding/thresholding, never exact accounting (see
/// `detector_api::TokenMeta::to_whole`).
///
/// A validated newtype rather than a bare `f64`, the same discipline as
/// [`Confidence`] and `detector_api::UsdPrice`: a plain float silently admits a
/// negative (nonsense for a magnitude) or a `NaN` (which poisons every `>`
/// comparison a severity gate makes). Distinct from `UsdPrice` — that is a
/// *price per token*; this is a *total value*. Two constructors, by intent:
/// [`UsdAmount::new`] sanitizes and is for trusted in-code values already known
/// finite and non-negative (a summed enrichment figure); [`UsdAmount::try_new`]
/// validates and is for values crossing the process edge (deserialized input),
/// where a bad value is a defect to surface, not mask.
///
/// This is *impact scale* only — how much value moved — and carries no opinion
/// on *who* moved it; attribution stays off this path (§6/§8).
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(value_type = f64))]
pub struct UsdAmount(f64);

impl UsdAmount {
    /// Sanitize a trusted, in-code `value` into a non-negative, finite amount:
    /// a `NaN` or negative collapses to `0.0`. Use for figures the process
    /// itself produced and already knows are well-formed (a summed USD total);
    /// the clamp is a defensive no-op there, and a belt-and-braces guard against
    /// a stray non-finite reaching a threshold comparison. Mirrors
    /// [`Confidence::new`].
    pub fn new(value: f64) -> Self {
        // `NaN.max(0.0) == 0.0` in Rust, so this rejects NaN too.
        Self(if value.is_finite() {
            value.max(0.0)
        } else {
            0.0
        })
    }

    /// Validate `value` is finite and `>= 0.0`, erroring otherwise. Use for
    /// values from outside the process (deserialized input, a feed) where
    /// clamping would hide a defect. Mirrors `UsdPrice::try_new`.
    pub fn try_new(value: f64) -> Result<Self, InvalidUsdAmount> {
        if value.is_finite() && value >= 0.0 {
            Ok(Self(value))
        } else {
            Err(InvalidUsdAmount { value })
        }
    }

    pub fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for UsdAmount {
    type Error = InvalidUsdAmount;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

// Serde routes through `try_new` on the way *in*, so a `UsdAmount` deserialized
// from an event on the wire is validated at the edge — a NaN or negative can't
// slip in and silently poison a severity `>` comparison later. The wire form is
// a bare JSON number (identical bytes to an `f64`), so this is a
// backwards-compatible representation of the previously-raw field. Mirrors
// `UsdPrice`'s validated (de)serialize.
impl Serialize for UsdAmount {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_f64(self.0)
    }
}

impl<'de> Deserialize<'de> for UsdAmount {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let value = f64::deserialize(deserializer)?;
        Self::try_new(value).map_err(D::Error::custom)
    }
}

/// Convenience alias for an on-chain account address.
pub type AccountAddress = Address;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_chains_have_names_and_finality_defaults() {
        assert_eq!(Chain::ETHEREUM.name(), Some("ethereum"));
        assert_eq!(Chain::BASE.name(), Some("base"));
        assert_eq!(Chain::ETHEREUM.default_finalization_depth(), Some(64));
        assert_eq!(Chain::BASE.default_finalization_depth(), Some(1024));
    }

    #[test]
    fn unknown_chains_require_explicit_config() {
        let unknown = Chain(424242);
        assert_eq!(unknown.name(), None);
        assert_eq!(unknown.default_finalization_depth(), None);
        // The partition-key string still works for any id.
        assert_eq!(unknown.to_string(), "chain-424242");
    }

    #[test]
    fn base_display_is_the_partition_key_form() {
        // Display is the Kafka partition-key string (§20) — locked.
        assert_eq!(Chain::BASE.to_string(), "chain-8453");
    }

    #[test]
    fn metrics_label_is_the_name_with_a_partition_key_fallback() {
        assert_eq!(Chain::ETHEREUM.metrics_label(), "ethereum");
        assert_eq!(Chain::BASE.metrics_label(), "base");
        assert_eq!(Chain(424242).metrics_label(), "chain-424242");
    }

    #[test]
    fn usd_amount_new_sanitizes_negative_and_non_finite_to_zero() {
        assert_eq!(UsdAmount::new(1234.5).get(), 1234.5);
        assert_eq!(UsdAmount::new(0.0).get(), 0.0);
        assert_eq!(
            UsdAmount::new(-1.0).get(),
            0.0,
            "a magnitude can't be negative"
        );
        assert_eq!(
            UsdAmount::new(f64::NAN).get(),
            0.0,
            "NaN must never reach a gate"
        );
        assert_eq!(UsdAmount::new(f64::INFINITY).get(), 0.0);
    }

    #[test]
    fn usd_amount_try_new_rejects_ill_formed_values() {
        assert_eq!(UsdAmount::try_new(0.0).unwrap().get(), 0.0);
        assert_eq!(UsdAmount::try_new(9_999.99).unwrap().get(), 9_999.99);
        assert!(
            UsdAmount::try_new(-0.01).is_err(),
            "negative is a defect at the edge"
        );
        assert!(UsdAmount::try_new(f64::NAN).is_err());
        assert!(UsdAmount::try_new(f64::INFINITY).is_err());
    }

    #[test]
    fn usd_amount_wire_form_is_a_bare_number_that_validates_on_read() {
        // Serializes as a plain JSON number (same bytes as the previously-raw
        // f64 field), so the change is wire-compatible.
        let amount = UsdAmount::new(150_000.0);
        assert_eq!(serde_json::to_string(&amount).unwrap(), "150000.0");
        assert_eq!(
            serde_json::from_str::<UsdAmount>("150000.0").unwrap(),
            amount
        );
        // A negative/NaN on the wire is rejected at the deserialize edge.
        assert!(serde_json::from_str::<UsdAmount>("-5.0").is_err());
    }
}
