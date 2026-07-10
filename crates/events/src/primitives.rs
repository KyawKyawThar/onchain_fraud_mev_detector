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

    pub fn id(self) -> u64 {
        self.0
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

/// Convenience alias for an on-chain account address.
pub type AccountAddress = Address;
