//! Behavioral similarity search (§20.3, §8.3): the read behind
//! `GET /v1/address/{addr}/similar` — "which addresses behave like this one",
//! each answer carrying the behavioral factors that drove it.
//!
//! This is to [`crate::embedding`] what [`crate::graph`] is to
//! [`crate::adjacency`]: the query layer over a store seam, with the decision
//! itself ([`rank`]) kept pure so it is `assert_eq!`-testable with plain
//! structs.
//!
//! # The metric is standardized, and that is not negotiable
//!
//! Two stored vectors are never compared in their raw units. The v1 feature
//! families have deliberately different natural ranges, so a raw distance is
//! dominated by the log-magnitude family and "behaviorally similar" quietly
//! degrades into "similar transaction count" — see
//! [`baseline`](crate::embedding::baseline) for why that is the wrong answer
//! rather than a slightly worse one. Every score this module returns is a
//! cosine similarity between **baseline-standardized** vectors, and a search
//! whose baseline is missing, thin or schema-mismatched is *refused* rather
//! than served in the wrong units.
//!
//! # Two stages, and only one of them is approximate
//!
//! ClickHouse's `vector_similarity` index can only accelerate the distance
//! function baked into it, and standardization is an affine shift no such
//! index expresses. So the search is the standard ANN shape:
//!
//! 1. **Candidate generation** — `ORDER BY cosineDistance(vector, q) LIMIT n`
//!    in ClickHouse, over *raw* vectors, index-accelerated (migration 0007).
//!    Over-fetched by [`SimilarityLimits::candidate_multiplier`].
//! 2. **Exact re-rank** — [`rank`] standardizes every candidate against the
//!    population baseline and scores it in that space. This stage decides the
//!    order, the score, and the explanation.
//!
//! Stage 1 is the approximation, and it is a *recall* approximation only: a
//! neighbour it fails to shortlist is missing from the answer, but nothing it
//! does can make a returned score or explanation wrong. That is why the result
//! is stamped [`SimilaritySearch::approximate`] and reports
//! [`SimilaritySearch::candidates_considered`] — the fidelity is marked, not
//! assumed, the same stance `observations_truncated` takes one layer down.
//! Raising `candidate_multiplier` trades latency for recall; the ceiling
//! ([`SimilarityLimits::max_candidates`]) is what stops a caller turning one
//! request into a whole-table scan.
//!
//! # The explanation adds up
//!
//! Cosine similarity over standardized vectors decomposes *exactly* into one
//! signed term per feature:
//!
//! ```text
//! similarity = sum_i (z_subject[i] * z_candidate[i]) / (|z_subject| * |z_candidate|)
//! ```
//!
//! so [`SimilarityFactor::contribution`] is not an attribution heuristic — the
//! contributions sum to the score, and this is checked
//! (pinned by the `contributions_sum_to_the_similarity` test).
//! A positive term means both addresses sit on the *same* side of the
//! population median on that feature; a negative one means they sit on
//! opposite sides and that feature is pushing them apart. Both are surfaced,
//! ranked by magnitude, because "these two look alike except on X" is the
//! sentence an investigator actually needs.
//!
//! # Two addresses with no signal are not similar
//!
//! An address whose standardized vector is the zero vector is exactly average
//! on every feature. Cosine against it is `0/0`. The honest answer is that
//! there is nothing to match on, so a subject like that is a typed refusal
//! ([`SimilarityError::NoSignal`]) and a *candidate* like that is skipped —
//! never a NaN score, and never an arbitrary ranking of the whole population.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, Chain, EntityId};
use serde::{Deserialize, Serialize};

use crate::embedding::baseline::{BaselineError, BehaviorBaseline};
use crate::embedding::{BehaviorSchema, MAX_VISIBLE_FACTORS};
use crate::embedding_store::{
    CachedNeighbor, CachedNeighbors, EmbeddingStore, EmbeddingStoreError, StoredEmbedding,
};

/// The vector arity migration 0007's HNSW index is declared with.
///
/// Kept here rather than in the SQL alone because a `vector_similarity` index
/// **rejects** any insert whose array length differs from it, which would take
/// down the embedding job's writes the first time a differently-shaped version
/// shipped. The `every_shipped_version_fits_the_vector_index` test turns that
/// production failure into a failing build with the fix in the message.
pub const INDEXED_DIMENSION: usize = 33;

/// Materialized-ranking lookups, labelled `outcome`: `hit`, `miss` (nothing
/// stored), `stale_baseline` (stored under a baseline that is no longer
/// current — the invalidation working), or `expired` (past `max_age`).
///
/// `stale_baseline` spiking once after a baseline re-derivation is correct and
/// expected; a *sustained* rate means baselines are being rewritten faster than
/// the working set refills, and the cache is costing more than it saves.
pub const NEIGHBOR_CACHE_TOTAL: &str = "intelligence_similarity_neighbor_cache_total";

/// A standardized vector shorter than this in Euclidean norm is treated as
/// having no signal: the address is at the population median on essentially
/// every feature, and the direction of what is left is numerical noise.
const MIN_SIGNAL_NORM: f64 = 1e-6;

/// Bounds one similarity search respects. `max_results`/`max_candidates` are
/// operator-tunable (wired from config in `main`); the rest are per-request.
#[derive(Debug, Clone, Copy)]
pub struct SimilarityLimits {
    /// Hard ceiling on returned neighbours — a caller asking for more is
    /// served at the ceiling, not rejected (the [`crate::leaderboard::Limit`]
    /// stance).
    pub max_results: usize,
    /// What a caller who names no limit gets.
    pub default_results: usize,
    /// How many candidates to shortlist per requested result. The whole
    /// recall budget of the approximate stage: stage 1 ranks in raw space and
    /// stage 2 re-ranks in standardized space, so a neighbour must survive a
    /// metric it is not scored by to be seen at all.
    pub candidate_multiplier: usize,
    /// Absolute ceiling on the shortlist, so `limit * multiplier` cannot turn
    /// one request into a whole-table read.
    pub max_candidates: usize,
    /// How long a materialized ranking may be served before it is recomputed.
    ///
    /// Separate from baseline invalidation, which is exact: this bounds
    /// staleness against *vector* drift, which has no fingerprint because the
    /// neighbours' own vectors move independently of the subject's. `None`
    /// disables the materialized read model entirely — every search runs live.
    pub cache_max_age: Option<Duration>,
}

impl Default for SimilarityLimits {
    fn default() -> Self {
        Self {
            max_results: 100,
            default_results: 20,
            // 20x: generous, because the two stages rank by different metrics
            // and the cost of a shortlist ClickHouse already has in memory is
            // far below the cost of a neighbour never surfacing.
            candidate_multiplier: 20,
            max_candidates: 2_000,
            // An hour: the embedding sweep's own default cadence, so a cached
            // ranking is never staler than the vectors it ranks. Raising this
            // past the sweep interval buys throughput with answers that
            // disagree with the data they claim to summarize.
            cache_max_age: Some(Duration::from_secs(3_600)),
        }
    }
}

impl SimilarityLimits {
    /// Resolve a caller's requested result count (`0`/absent = the default)
    /// against these bounds.
    pub fn results_for(&self, requested: u32) -> usize {
        match requested as usize {
            0 => self.default_results,
            n => n.min(self.max_results),
        }
    }

    /// How many candidates to shortlist for `results` returned neighbours.
    ///
    /// Never below `results` + 1: the subject's own row is excluded in SQL,
    /// but an incomparable or signal-free candidate is dropped during the
    /// re-rank, so the shortlist must have slack even at a multiplier of 1.
    pub fn candidates_for(&self, results: usize) -> usize {
        results
            .saturating_mul(self.candidate_multiplier.max(1))
            .clamp(results.saturating_add(1), self.max_candidates.max(1))
    }
}

/// A cosine similarity in `[-1, 1]` between two baseline-standardized behavior
/// vectors.
///
/// A newtype rather than a bare `f32` for the same reason
/// [`Confidence`](events::primitives::Confidence) is one: the range carries
/// meaning that a float does not. `1.0` is "behaviourally identical", `0.0` is
/// "unrelated", and **negative values are meaningful** — an address that is
/// systematically the *opposite* of the subject on the features that
/// distinguish it. Code that assumed `[0, 1]` (a progress bar, a `1.0 - score`
/// distance) would be silently wrong on real output, which is exactly the
/// mistake a named type prevents.
///
/// Construction clamps rather than validates: the value is produced in-process
/// by [`rank`], and floating-point summation over 33 terms can land a hair
/// outside the range the metric is defined on. That is a rounding artifact,
/// not a defect worth failing a request over — unlike a value arriving from
/// outside the process, which has no constructor here at all.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Similarity(f32);

impl Similarity {
    /// Behaviourally identical under the current baseline.
    pub const IDENTICAL: Self = Self(1.0);
    /// No relationship in the standardized space.
    pub const UNRELATED: Self = Self(0.0);

    /// Clamp into `[-1, 1]`. For values computed in-process by [`rank`].
    pub fn new(value: f64) -> Self {
        Self(value.clamp(-1.0, 1.0) as f32)
    }

    /// The raw score, for wire encoding and comparison.
    pub fn get(self) -> f32 {
        self.0
    }
}

impl std::fmt::Display for Similarity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.4}", self.0)
    }
}

/// One feature's exact, signed contribution to a similarity score.
///
/// The values are reported in **raw, interpretable units** (a
/// `busiest_day_share` of `0.8` reads as `0.8`) alongside the standardized
/// `_z` forms the score is actually computed from — the raw number is what a
/// human reads, the z is what explains why it mattered.
#[derive(Debug, Clone, PartialEq)]
pub struct SimilarityFactor {
    pub feature: &'static str,
    /// The subject's raw value for this feature.
    pub subject_value: f32,
    /// The neighbour's raw value.
    pub candidate_value: f32,
    /// The subject's value in robust z-units against the population.
    pub subject_z: f32,
    /// The neighbour's value in robust z-units.
    pub candidate_z: f32,
    /// This feature's signed share of the similarity score. Positive: both sit
    /// on the same side of the population median, pulling them together.
    /// Negative: opposite sides, pushing them apart. Sums, over all features,
    /// to exactly [`SimilarAddress::similarity`].
    pub contribution: f32,
}

/// One ranked neighbour.
#[derive(Debug, Clone, PartialEq)]
pub struct SimilarAddress {
    pub address: AccountAddress,
    /// The neighbour's resolved entity at *its* compute time, if any. A hit
    /// whose entity is already known is the §20.3 clustering signal's input —
    /// a reduced-confidence heuristic, never a merge (§8.2).
    pub entity_id: Option<EntityId>,
    /// Cosine similarity in standardized space.
    pub similarity: Similarity,
    /// This neighbour's vector describes a recent window rather than its whole
    /// history (§8.2's hub rule) — a fidelity flag carried through from the
    /// stored row, because a hub matching a hub is a weaker claim.
    pub observations_truncated: bool,
    /// When the neighbour's vector was computed — how stale this match is.
    pub computed_at: DateTime<Utc>,
    /// The largest-magnitude contributions, most significant first.
    pub factors: Vec<SimilarityFactor>,
}

/// A completed search: the ranking plus what it cost and what it skipped.
#[derive(Debug, Clone, PartialEq)]
pub struct SimilaritySearch {
    pub subject: AccountAddress,
    pub embedding_version: String,
    pub schema_hash: String,
    /// When the subject's own vector was computed.
    pub subject_computed_at: DateTime<Utc>,
    pub results: Vec<SimilarAddress>,
    /// How many rows the shortlist stage returned — the denominator behind
    /// `approximate`.
    pub candidates_considered: usize,
    /// Candidates dropped during the re-rank: a superseded row for an address
    /// already seen, a vector stamped with a different schema, or one with no
    /// signal to compare against.
    pub candidates_skipped: usize,
    /// The shortlist was capped, so a better neighbour may exist outside it.
    /// `false` only when the shortlist came back short of the cap, which means
    /// the candidate stage saw the whole comparable population and the ranking
    /// is exact.
    pub approximate: bool,
}

impl SimilaritySearch {
    /// Rebuild a search result from a materialized ranking.
    ///
    /// `candidates_considered`/`candidates_skipped` come back as `0`: they
    /// describe work *this* request did, and a cache hit did none. Reporting
    /// the original run's numbers would misattribute cost. `approximate` is
    /// carried through, because it describes the **ranking**, not the request
    /// — a cached answer is exactly as approximate as the search that produced
    /// it, and silently reporting `false` would upgrade its claimed fidelity.
    fn from_cache(
        schema: &BehaviorSchema,
        subject: &StoredEmbedding,
        entry: CachedNeighbors,
        limit: usize,
    ) -> Self {
        Self {
            subject: subject.address,
            embedding_version: subject.embedding_version.clone(),
            schema_hash: subject.schema_hash.clone(),
            subject_computed_at: subject.computed_at,
            results: entry
                .neighbors
                .into_iter()
                .take(limit)
                .map(|n| SimilarAddress {
                    address: n.address,
                    entity_id: n.entity_id,
                    similarity: Similarity::new(f64::from(n.similarity)),
                    // Not stored: a cached ranking keeps the neighbour list and
                    // its explanation, not each neighbour's own fidelity flag.
                    observations_truncated: false,
                    computed_at: entry.computed_at,
                    factors: n
                        .factors
                        .into_iter()
                        // A stored factor name is *resolved against the schema*
                        // rather than turned into a `&'static str` by leaking
                        // it. Leaking would be an unbounded allocation driven
                        // by stored data on a path that runs per cache hit —
                        // a corrupt or forward-versioned row would grow the
                        // process without limit. A name the schema does not
                        // know is dropped: it cannot be explained under this
                        // version anyway.
                        .filter_map(|f| {
                            let feature = schema
                                .features()
                                .iter()
                                .find(|def| def.name == f.feature)?
                                .name;
                            Some(SimilarityFactor {
                                feature,
                                subject_value: 0.0,
                                candidate_value: f.value,
                                subject_z: 0.0,
                                candidate_z: 0.0,
                                contribution: f.share,
                            })
                        })
                        .collect(),
                })
                .collect(),
            candidates_considered: 0,
            candidates_skipped: 0,
            approximate: entry.approximate,
        }
    }

    /// The materializable form of this search.
    fn to_cache_entry(&self, baseline_fingerprint: &str, now: DateTime<Utc>) -> CachedNeighbors {
        CachedNeighbors {
            address: self.subject,
            embedding_version: self.embedding_version.clone(),
            baseline_fingerprint: baseline_fingerprint.to_owned(),
            neighbors: self
                .results
                .iter()
                .map(|hit| CachedNeighbor {
                    address: hit.address,
                    entity_id: hit.entity_id,
                    similarity: hit.similarity.get(),
                    factors: hit
                        .factors
                        .iter()
                        .map(|f| events::intelligence::BehaviorFactor {
                            feature: f.feature.to_owned(),
                            value: f.candidate_value,
                            share: f.contribution,
                        })
                        .collect(),
                })
                .collect(),
            approximate: self.approximate,
            computed_at: now,
        }
    }
}

/// Why a similarity search could not be served. Distinguished by *class*
/// because the classes have different fixes: a store fault is a retry, a
/// missing baseline is "wait for the baseline job", and a signal-free subject
/// is a permanent property of that address.
#[derive(Debug, thiserror::Error)]
pub enum SimilarityError {
    #[error(transparent)]
    Store(#[from] EmbeddingStoreError),

    /// No population baseline has been computed for this
    /// `(chain, embedding_version)` yet. Not an error in the vectors — the
    /// `embedding-baseline` run mode has simply not produced one, and ranking
    /// without it would rank in unstandardized units.
    #[error("no population baseline for {embedding_version} on chain {chain}")]
    NoBaseline {
        chain: u64,
        embedding_version: String,
    },

    /// A baseline exists but cannot standardize these vectors — a schema
    /// mismatch, or too thin a sample to mean anything.
    #[error("the population baseline cannot be applied: {0}")]
    Baseline(#[from] BaselineError),

    /// The subject is at the population median on essentially every feature.
    /// There is no behavioral direction to search along, so any ranking would
    /// be noise ordering.
    #[error("{address} has no distinguishing behavior to match on")]
    NoSignal { address: String },
}

/// The two ways a similarity search cannot run that are **states of the data**
/// rather than failures — reported as an explained empty result, not an error
/// status.
///
/// The distinction matters at the edge: an investigator's panel wants to read
/// "this address is unremarkable on every feature" or "the population baseline
/// has not been computed yet", both of which are answers. A 500 is neither,
/// and an unexplained empty list is worse than both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Unavailable {
    /// No population baseline exists for this `(chain, version)` yet. Resolves
    /// once the `embedding-baseline` run mode produces one; visible to ops as
    /// a labelled counter in the meantime.
    NoBaseline,
    /// The subject sits at the population median on essentially every feature.
    /// A property of the address, not of the system — it will not resolve on
    /// its own.
    NoSignal,
}

impl SimilarityError {
    /// The reportable state behind this error, if it is one of the two that
    /// are states rather than faults. `None` for a store fault or an
    /// unusable baseline, which are real failures and get a status.
    pub fn unavailable(&self) -> Option<Unavailable> {
        match self {
            SimilarityError::NoBaseline { .. } => Some(Unavailable::NoBaseline),
            SimilarityError::NoSignal { .. } => Some(Unavailable::NoSignal),
            SimilarityError::Store(_) | SimilarityError::Baseline(_) => None,
        }
    }
}

impl event_bus::Transience for SimilarityError {
    /// Only a store fault is worth retrying. A missing baseline *will* resolve
    /// on its own, but not on a request-retry timescale, so it is reported as
    /// a state rather than a blip.
    fn is_transient(&self) -> bool {
        match self {
            SimilarityError::Store(err) => err.is_transient(),
            _ => false,
        }
    }
}

/// Everything one [`similar_addresses`] call needs.
///
/// A struct rather than eight positional arguments: three of them are
/// `&`-references to different types and two are plain scalars, so a
/// mis-ordered call site is a compile error only by luck.
pub struct SearchRequest<'a> {
    pub store: &'a dyn EmbeddingStore,
    pub chain: Chain,
    pub address: &'a AccountAddress,
    pub schema: &'a BehaviorSchema,
    /// The current population baseline, from the process-wide snapshot.
    /// `None` is "never loaded, or too stale to rank against" — both report
    /// as [`Unavailable::NoBaseline`].
    pub baseline: Option<std::sync::Arc<BehaviorBaseline>>,
    pub limits: SimilarityLimits,
    /// `0` means the server default; clamped to the ceiling.
    pub requested_results: u32,
    /// Explicit rather than an ambient clock, so both staleness rules — the
    /// baseline's and the cache's — are testable without sleeping, and are
    /// judged against the *same* instant. The `as_of` discipline the embedding
    /// kernel follows.
    pub now: DateTime<Utc>,
}

/// Run a similarity search for one address.
///
/// `Ok(None)` means the address has never been embedded under this version —
/// a clean miss the edge maps to a 404, distinct from every failure above.
pub async fn similar_addresses(
    request: SearchRequest<'_>,
) -> Result<Option<SimilaritySearch>, SimilarityError> {
    let SearchRequest {
        store,
        chain,
        address,
        schema,
        baseline,
        limits,
        requested_results,
        now,
    } = request;
    let version = schema.version();

    let Some(subject) = store.latest(chain, address, version).await? else {
        return Ok(None);
    };

    // The baseline comes from the process-wide snapshot, not a per-request
    // read: it is keyed by (chain, version) rather than by address, so every
    // search on this chain wants the identical ~264 bytes and fetching them
    // per request buys a round trip and a failure mode for nothing. The
    // snapshot also owns the staleness rule — `None` here is either "never
    // loaded" or "too old to rank against", and both are the same answer to
    // the caller. See `crate::baseline_cache`.
    //
    // Checked *before* the much more expensive shortlist: a search that cannot
    // be standardized must not first pay for candidates it will refuse to rank.
    let Some(baseline) = baseline else {
        return Err(SimilarityError::NoBaseline {
            chain: chain.id(),
            embedding_version: version.to_owned(),
        });
    };

    // A raw all-zero subject makes `cosineDistance` return NaN for *every*
    // row, which ClickHouse will happily sort into an arbitrary order. Caught
    // here rather than trusting the store, because a NaN ordering looks like a
    // result. (The standardized zero-vector case is caught in `rank`; this is
    // the raw-space one, and they are not the same address set.)
    if subject.values.iter().all(|v| *v == 0.0) {
        return Err(SimilarityError::NoSignal {
            address: crate::model::address_key(address),
        });
    }

    let results = limits.results_for(requested_results);
    let fingerprint = baseline.fingerprint();

    // ── Materialized read model (§20.3) ──────────────────────────────────
    // Serve a stored ranking only if it was produced under *this* baseline and
    // is inside the freshness bound. Two different staleness rules on purpose:
    // the baseline check is exact (a fingerprint equality), because a
    // re-derived baseline is defined to change rankings; the age check is a
    // bound, because the neighbours' own vectors drift with no fingerprint of
    // their own.
    if let Some(max_age) = limits.cache_max_age {
        match store.cached_neighbors(chain, address, version).await {
            Ok(Some(entry)) => match entry.validity(&fingerprint, now, max_age) {
                CacheVerdict::Fresh => {
                    metrics::counter!(NEIGHBOR_CACHE_TOTAL, "outcome" => "hit").increment(1);
                    return Ok(Some(SimilaritySearch::from_cache(
                        schema, &subject, entry, results,
                    )));
                }
                verdict => {
                    metrics::counter!(NEIGHBOR_CACHE_TOTAL, "outcome" => verdict.label())
                        .increment(1);
                }
            },
            Ok(None) => {
                metrics::counter!(NEIGHBOR_CACHE_TOTAL, "outcome" => "miss").increment(1);
            }
            // A cache that cannot be read is a cache miss, never a failed
            // search: the live path below is the source of truth and is
            // always available.
            Err(err) => {
                metrics::counter!(NEIGHBOR_CACHE_TOTAL, "outcome" => "error").increment(1);
                tracing::warn!(error = %err, "neighbour cache read failed; falling through to the live search");
            }
        }
    }

    let want_candidates = limits.candidates_for(results);
    let candidates = store
        .nearest_candidates(chain, version, &subject.values, address, want_candidates)
        .await?;

    let search = rank(RankRequest {
        schema,
        baseline: baseline.as_ref(),
        subject: &subject,
        candidates: &candidates,
        limit: results,
        shortlist_cap: want_candidates,
    })?;

    // Materialize what we just computed. A write failure is logged and
    // swallowed: the caller already has a correct answer, and failing a served
    // search because a *cache* could not be updated would be strictly worse
    // than being slow next time.
    if let (Some(_), Some(found)) = (limits.cache_max_age, search.as_ref()) {
        let entry = found.to_cache_entry(&fingerprint, now);
        if let Err(err) = store.put_neighbors(chain, &entry).await {
            tracing::warn!(error = %err, "failed to materialize a neighbour ranking");
        }
    }

    Ok(search)
}

/// Why a materialized ranking was or was not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheVerdict {
    /// Produced under the current baseline and inside the freshness bound.
    Fresh,
    /// Produced under a baseline that is no longer current. Not an error —
    /// this is the invalidation doing its job.
    StaleBaseline,
    /// Current baseline, but older than the freshness bound.
    Expired,
}

impl CacheVerdict {
    /// The metric label. A closed vocabulary so the `outcome` cardinality is
    /// fixed.
    pub fn label(self) -> &'static str {
        match self {
            CacheVerdict::Fresh => "hit",
            CacheVerdict::StaleBaseline => "stale_baseline",
            CacheVerdict::Expired => "expired",
        }
    }
}

impl CachedNeighbors {
    /// Whether this entry may be served, given the current baseline and clock.
    ///
    /// The baseline test comes **first and is exact**: an entry ranked under a
    /// superseded baseline is wrong in a way no freshness bound would catch,
    /// because it can be arbitrarily recent and still describe the wrong
    /// ordering.
    pub fn validity(
        &self,
        current_fingerprint: &str,
        now: DateTime<Utc>,
        max_age: Duration,
    ) -> CacheVerdict {
        if self.baseline_fingerprint != current_fingerprint {
            return CacheVerdict::StaleBaseline;
        }
        let age = now.signed_duration_since(self.computed_at).num_seconds();
        if age > max_age.as_secs() as i64 {
            return CacheVerdict::Expired;
        }
        CacheVerdict::Fresh
    }
}

/// Everything one [`rank`] call needs.
///
pub struct RankRequest<'a> {
    pub schema: &'a BehaviorSchema,
    pub baseline: &'a BehaviorBaseline,
    pub subject: &'a StoredEmbedding,
    pub candidates: &'a [StoredEmbedding],
    /// How many neighbours to return.
    pub limit: usize,
    /// The cap the shortlist was fetched under — used **only** to decide
    /// [`SimilaritySearch::approximate`]: a shortlist that came back short of
    /// its own cap saw the whole comparable population, so the ranking is
    /// exact.
    pub shortlist_cap: usize,
}

/// Score and order `candidates` against `subject` in standardized space — the
/// pure decision, with no store in sight.
///
/// Takes a struct rather than six positional arguments because `limit` and
/// `shortlist_cap` are adjacent `usize`s with entirely different meanings:
/// swapping them still compiles and silently mis-reports whether the answer
/// was approximate. Naming them at the call site is the cheapest possible
/// guard against that.
pub fn rank(request: RankRequest<'_>) -> Result<Option<SimilaritySearch>, SimilarityError> {
    let RankRequest {
        schema,
        baseline,
        subject,
        candidates,
        limit,
        shortlist_cap,
    } = request;
    let subject_z = baseline.standardize(schema, &subject.values)?;
    let subject_norm = norm(&subject_z);
    if subject_norm <= MIN_SIGNAL_NORM {
        return Err(SimilarityError::NoSignal {
            address: crate::model::address_key(&subject.address),
        });
    }

    // Latest-per-address, kept explicitly: the shortlist runs against the raw
    // table so a `ReplacingMergeTree` that has not merged yet can hand back a
    // superseded row beside its replacement. Keeping the newer of the two is
    // the same latest-wins rule the single-address read applies, just done
    // here because the shortlist cannot afford the `LIMIT 1 BY` that would
    // cost it the index.
    let mut best: HashMap<AccountAddress, &StoredEmbedding> =
        HashMap::with_capacity(candidates.len());
    let mut skipped = 0usize;
    for candidate in candidates {
        if candidate.address == subject.address {
            skipped += 1;
            continue;
        }
        match best.get(&candidate.address) {
            Some(seen) if seen.computed_at >= candidate.computed_at => {
                skipped += 1;
            }
            Some(_) => {
                best.insert(candidate.address, candidate);
                skipped += 1;
            }
            None => {
                best.insert(candidate.address, candidate);
            }
        }
    }

    let mut scored: Vec<SimilarAddress> = Vec::with_capacity(best.len());
    for candidate in best.into_values() {
        // A vector stamped with a different schema is not comparable, and the
        // baseline would refuse it anyway — counted, never silently dropped.
        if !candidate.matches(schema.version(), schema.content_hash()) {
            skipped += 1;
            continue;
        }
        let candidate_z = baseline.standardize(schema, &candidate.values)?;
        let candidate_norm = norm(&candidate_z);
        if candidate_norm <= MIN_SIGNAL_NORM {
            skipped += 1;
            continue;
        }

        let scale = subject_norm * candidate_norm;
        let mut factors: Vec<SimilarityFactor> = Vec::with_capacity(schema.dimension());
        let mut similarity = 0.0f64;
        for (index, feature) in schema.features().iter().enumerate() {
            let sz = f64::from(subject_z[index]);
            let cz = f64::from(candidate_z[index]);
            let contribution = sz * cz / scale;
            similarity += contribution;
            if contribution != 0.0 {
                factors.push(SimilarityFactor {
                    feature: feature.name,
                    subject_value: subject.values[index],
                    candidate_value: candidate.values[index],
                    subject_z: subject_z[index],
                    candidate_z: candidate_z[index],
                    contribution: contribution as f32,
                });
            }
        }
        // Largest effect first — a sharp *disagreement* explains a match as
        // much as an agreement does. Ties broken by feature name so the
        // explanation never depends on iteration accidents.
        factors.sort_by(|a, b| {
            b.contribution
                .abs()
                .partial_cmp(&a.contribution.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.feature.cmp(b.feature))
        });
        factors.truncate(MAX_VISIBLE_FACTORS);

        scored.push(SimilarAddress {
            address: candidate.address,
            entity_id: candidate.entity_id,
            // `Similarity::new` clamps: floating-point summation over 33
            // terms can drift a hair outside the range the metric is defined
            // on, and a caller reading "1.0000001" would be right to distrust
            // the whole number.
            similarity: Similarity::new(similarity),
            observations_truncated: candidate.observations_truncated,
            computed_at: candidate.computed_at,
            factors,
        });
    }

    // Most similar first; ties broken by address so the same store state
    // always yields byte-identical output (the `graph` module's rule).
    scored.sort_by(|a, b| {
        b.similarity
            .get()
            .partial_cmp(&a.similarity.get())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.address.cmp(&b.address))
    });
    scored.truncate(limit);

    Ok(Some(SimilaritySearch {
        subject: subject.address,
        embedding_version: subject.embedding_version.clone(),
        schema_hash: subject.schema_hash.clone(),
        subject_computed_at: subject.computed_at,
        results: scored,
        candidates_considered: candidates.len(),
        candidates_skipped: skipped,
        approximate: candidates.len() >= shortlist_cap,
    }))
}

/// Euclidean norm in `f64` — the vectors are `f32`, but the norm feeds a
/// division, and accumulating 33 squares in `f32` loses precision the score
/// then inherits.
fn norm(values: &[f32]) -> f64 {
    values
        .iter()
        .map(|v| f64::from(*v) * f64::from(*v))
        .sum::<f64>()
        .sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedding::{v1, FeatureDef, FeatureKind};
    use alloy_primitives::Address;
    use events::intelligence::BehaviorFactor;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    /// A three-feature stand-in so every score below is checkable by hand.
    fn schema() -> BehaviorSchema {
        BehaviorSchema::new(
            "test-sim-v1",
            vec![
                FeatureDef {
                    name: "alpha",
                    kind: FeatureKind::Ratio,
                },
                FeatureDef {
                    name: "beta",
                    kind: FeatureKind::Ratio,
                },
                FeatureDef {
                    name: "gamma",
                    kind: FeatureKind::Ratio,
                },
            ],
        )
    }

    /// A baseline centred on zero with unit spread, so raw values *are* their
    /// own z-scores and the arithmetic stays legible.
    fn unit_baseline(schema: &BehaviorSchema) -> BehaviorBaseline {
        BehaviorBaseline {
            embedding_version: schema.version().to_owned(),
            schema_hash: schema.content_hash().to_owned(),
            centre: vec![0.0; schema.dimension()],
            spread: vec![1.0; schema.dimension()],
            sample_count: crate::embedding::baseline::MIN_SAMPLES,
            computed_at: at(0),
        }
    }

    fn stored(schema: &BehaviorSchema, byte: u8, values: &[f32]) -> StoredEmbedding {
        StoredEmbedding {
            address: Address::repeat_byte(byte),
            entity_id: None,
            embedding_version: schema.version().to_owned(),
            schema_hash: schema.content_hash().to_owned(),
            values: values.to_vec(),
            top_factors: Vec::<BehaviorFactor>::new(),
            observations_truncated: false,
            computed_at: at(1_000),
        }
    }

    fn search(
        schema: &BehaviorSchema,
        subject: &StoredEmbedding,
        candidates: &[StoredEmbedding],
    ) -> SimilaritySearch {
        rank(RankRequest {
            schema,
            baseline: &unit_baseline(schema),
            subject,
            candidates,
            limit: 10,
            shortlist_cap: usize::MAX,
        })
        .expect("a comparable search")
        .expect("a subject with signal")
    }

    /// The migration's HNSW index rejects any insert whose array length
    /// differs from the dimension declared in its DDL, which would stop the
    /// embedding job's writes dead. Every version this build ships must fit.
    #[test]
    fn every_shipped_version_fits_the_vector_index() {
        for embedder in crate::embedding::embedders() {
            assert_eq!(
                embedder.schema().dimension(),
                INDEXED_DIMENSION,
                "embedding version {} has {} features, but migration 0007's \
                 vector_similarity index is declared over {INDEXED_DIMENSION}. \
                 ClickHouse rejects an insert of a differently-sized array into \
                 an indexed column, so shipping this version needs a migration \
                 that DROPs idx_embedding_vector first.",
                embedder.version(),
                embedder.schema().dimension(),
            );
        }
    }

    /// The property the whole explanation rests on: the per-feature
    /// contributions are the score's exact decomposition, not an attribution
    /// heuristic laid beside it.
    #[test]
    fn contributions_sum_to_the_similarity() {
        let schema = schema();
        let subject = stored(&schema, 0x11, &[3.0, -1.0, 2.0]);
        let neighbour = stored(&schema, 0x22, &[2.0, 1.0, 4.0]);

        let found = search(&schema, &subject, &[neighbour]);
        let hit = &found.results[0];
        let total: f32 = hit.factors.iter().map(|f| f.contribution).sum();

        assert!(
            (total - hit.similarity.get()).abs() < 1e-5,
            "contributions {total} must sum to the similarity {}",
            hit.similarity
        );
    }

    /// Identical behavior is a similarity of 1; opposite behavior is -1. The
    /// sign is load-bearing — it is what makes a *disagreeing* factor readable
    /// as a disagreement.
    #[test]
    fn identical_vectors_score_one_and_opposed_ones_minus_one() {
        let schema = schema();
        let subject = stored(&schema, 0x11, &[1.0, 2.0, -3.0]);
        let twin = stored(&schema, 0x22, &[1.0, 2.0, -3.0]);
        let mirror = stored(&schema, 0x33, &[-1.0, -2.0, 3.0]);

        let found = search(&schema, &subject, &[twin, mirror]);
        assert_eq!(found.results.len(), 2);
        assert!((found.results[0].similarity.get() - 1.0).abs() < 1e-6);
        assert!((found.results[1].similarity.get() + 1.0).abs() < 1e-6);
        assert_eq!(found.results[0].address, Address::repeat_byte(0x22));
    }

    /// Scale is not behavior: an address doing the same things twice as much
    /// is behaviorally identical under a cosine, which is precisely why the
    /// metric is a cosine and not a distance.
    #[test]
    fn a_scaled_copy_is_the_same_behavior() {
        let schema = schema();
        let subject = stored(&schema, 0x11, &[1.0, 2.0, 3.0]);
        let bigger = stored(&schema, 0x22, &[10.0, 20.0, 30.0]);

        let found = search(&schema, &subject, &[bigger]);
        assert!((found.results[0].similarity.get() - 1.0).abs() < 1e-6);
    }

    /// Standardization is the whole point of the baseline: without it the
    /// feature with the widest natural range decides every ranking. Here
    /// `gamma` has a hundred-fold larger spread, and the neighbour that agrees
    /// on the two *informative* features must win despite disagreeing on it.
    #[test]
    fn the_baseline_decides_the_ranking_not_the_raw_units() {
        let schema = schema();
        let mut baseline = unit_baseline(&schema);
        baseline.spread = vec![1.0, 1.0, 100.0];

        let subject = stored(&schema, 0x11, &[2.0, 2.0, 100.0]);
        let agrees_on_signal = stored(&schema, 0x22, &[2.0, 2.0, -100.0]);
        let agrees_on_noise = stored(&schema, 0x33, &[-2.0, -2.0, 100.0]);

        let found = rank(RankRequest {
            schema: &schema,
            baseline: &baseline,
            subject: &subject,
            candidates: &[agrees_on_signal, agrees_on_noise],
            limit: 10,
            shortlist_cap: usize::MAX,
        })
        .expect("comparable")
        .expect("has signal");

        assert_eq!(found.results[0].address, Address::repeat_byte(0x22));
        assert!(found.results[0].similarity.get() > 0.0);
        assert!(found.results[1].similarity.get() < 0.0);
    }

    /// The factor list is ordered by *effect*, so the feature that pushed two
    /// addresses apart outranks a feature they merely both sit near the median
    /// on. A zero-contribution feature carries no explanation and is absent
    /// rather than padding the list.
    #[test]
    fn factors_are_ranked_by_effect_and_zero_terms_are_omitted() {
        let schema = schema();
        let subject = stored(&schema, 0x11, &[5.0, 0.0, 1.0]);
        let neighbour = stored(&schema, 0x22, &[-5.0, 3.0, 1.0]);

        let found = search(&schema, &subject, &[neighbour]);
        let factors = &found.results[0].factors;

        assert_eq!(factors[0].feature, "alpha", "the largest effect leads");
        assert!(factors[0].contribution < 0.0, "and it is a disagreement");
        assert!(
            !factors.iter().any(|f| f.feature == "beta"),
            "a feature the subject is exactly average on contributes nothing"
        );
        // Raw units survive to the explanation; the z-forms are what scored.
        assert_eq!(factors[0].subject_value, 5.0);
        assert_eq!(factors[0].candidate_value, -5.0);
    }

    /// An address at the population median on every feature has no direction
    /// to search along. Refused as a typed state, never served as a NaN score
    /// or an arbitrary ordering of the whole population.
    #[test]
    fn a_subject_with_no_signal_is_refused_rather_than_ranked() {
        let schema = schema();
        let subject = stored(&schema, 0x11, &[0.0, 0.0, 0.0]);
        let neighbour = stored(&schema, 0x22, &[1.0, 1.0, 1.0]);

        let err = rank(RankRequest {
            schema: &schema,
            baseline: &unit_baseline(&schema),
            subject: &subject,
            candidates: &[neighbour],
            limit: 10,
            shortlist_cap: usize::MAX,
        })
        .expect_err("a signal-free subject is refused");
        assert!(matches!(err, SimilarityError::NoSignal { .. }));
    }

    /// The same case on the *candidate* side is a skip, not a refusal: one
    /// featureless address must not sink the whole search.
    #[test]
    fn a_candidate_with_no_signal_is_skipped_and_counted() {
        let schema = schema();
        let subject = stored(&schema, 0x11, &[1.0, 1.0, 1.0]);
        let blank = stored(&schema, 0x22, &[0.0, 0.0, 0.0]);
        let real = stored(&schema, 0x33, &[1.0, 1.0, 0.5]);

        let found = search(&schema, &subject, &[blank, real]);
        assert_eq!(found.results.len(), 1);
        assert_eq!(found.results[0].address, Address::repeat_byte(0x33));
        assert_eq!(found.candidates_skipped, 1);
    }

    /// A vector from another schema version is not comparable at all, and the
    /// count is how an operator sees a half-finished rollout rather than
    /// wondering why the result set is thin.
    #[test]
    fn an_incomparable_version_is_skipped_and_counted() {
        let schema = schema();
        let subject = stored(&schema, 0x11, &[1.0, 1.0, 1.0]);
        let mut other_version = stored(&schema, 0x22, &[1.0, 1.0, 1.0]);
        other_version.embedding_version = "test-sim-v2".into();

        let found = search(&schema, &subject, &[other_version]);
        assert!(found.results.is_empty());
        assert_eq!(found.candidates_skipped, 1);
    }

    /// The shortlist runs against the raw table, so an unmerged
    /// `ReplacingMergeTree` can hand back a superseded row beside its
    /// replacement. Latest wins, and the loser is counted, not scored twice.
    #[test]
    fn a_superseded_candidate_row_collapses_to_the_latest() {
        let schema = schema();
        let subject = stored(&schema, 0x11, &[1.0, 1.0, 1.0]);
        let mut stale = stored(&schema, 0x22, &[-1.0, -1.0, -1.0]);
        stale.computed_at = at(500);
        let fresh = stored(&schema, 0x22, &[1.0, 1.0, 1.0]);

        // Both orderings, so "latest" can't be "whichever arrived last".
        for candidates in [
            vec![stale.clone(), fresh.clone()],
            vec![fresh.clone(), stale.clone()],
        ] {
            let found = search(&schema, &subject, &candidates);
            assert_eq!(found.results.len(), 1);
            assert!((found.results[0].similarity.get() - 1.0).abs() < 1e-6);
            assert_eq!(found.candidates_skipped, 1);
        }
    }

    /// The subject's own row is excluded — an address is not its own
    /// behavioral neighbour, and a similarity of 1.0 to itself would displace
    /// a real answer.
    #[test]
    fn the_subject_never_matches_itself() {
        let schema = schema();
        let subject = stored(&schema, 0x11, &[1.0, 2.0, 3.0]);
        let found = search(&schema, &subject, std::slice::from_ref(&subject));
        assert!(found.results.is_empty());
    }

    /// A shortlist that came back short of its cap saw the whole comparable
    /// population, so the ranking is exact and says so. One that filled the
    /// cap may have left a better neighbour outside it.
    #[test]
    fn approximation_is_reported_from_whether_the_shortlist_filled_its_cap() {
        let schema = schema();
        let subject = stored(&schema, 0x11, &[1.0, 2.0, 3.0]);
        let neighbours = vec![
            stored(&schema, 0x22, &[1.0, 2.0, 3.0]),
            stored(&schema, 0x33, &[3.0, 2.0, 1.0]),
        ];

        // Bound outside the closure: the closure cannot return a struct
        // borrowing a temporary it created.
        let baseline = unit_baseline(&schema);
        let base = |shortlist_cap| RankRequest {
            schema: &schema,
            baseline: &baseline,
            subject: &subject,
            candidates: &neighbours,
            limit: 10,
            shortlist_cap,
        };

        let exact = rank(base(50)).unwrap().unwrap();
        assert!(!exact.approximate);

        let capped = rank(base(2)).unwrap().unwrap();
        assert!(capped.approximate);
    }

    /// A mismatched baseline is a refused comparison, never a plausible
    /// ranking in the wrong units — the contract `baseline::standardize`
    /// declares, checked at the layer that would otherwise hide it.
    #[test]
    fn a_mismatched_baseline_refuses_the_whole_search() {
        let schema = schema();
        let mut baseline = unit_baseline(&schema);
        baseline.schema_hash = "a-different-schema".into();
        let subject = stored(&schema, 0x11, &[1.0, 2.0, 3.0]);

        assert!(matches!(
            rank(RankRequest {
                schema: &schema,
                baseline: &baseline,
                subject: &subject,
                candidates: &[],
                limit: 10,
                shortlist_cap: usize::MAX,
            }),
            Err(SimilarityError::Baseline(
                BaselineError::SchemaMismatch { .. }
            ))
        ));
    }

    /// The split that decides whether the edge answers with an explained
    /// empty result or an error status. A missing baseline and a featureless
    /// address are answers; a store fault and an unusable baseline are not.
    #[test]
    fn only_data_states_are_reportable_as_unavailable() {
        assert_eq!(
            SimilarityError::NoBaseline {
                chain: 1,
                embedding_version: "behavior-v1".into(),
            }
            .unavailable(),
            Some(Unavailable::NoBaseline)
        );
        assert_eq!(
            SimilarityError::NoSignal {
                address: "0x0".into(),
            }
            .unavailable(),
            Some(Unavailable::NoSignal)
        );
        assert!(SimilarityError::Baseline(BaselineError::TooFewSamples {
            samples: 3,
            minimum: 100,
        })
        .unavailable()
        .is_none());
        assert!(SimilarityError::Store(EmbeddingStoreError::Malformed {
            what: "corrupt".into(),
        })
        .unavailable()
        .is_none());

        assert_eq!(<&'static str>::from(Unavailable::NoBaseline), "no_baseline");
        assert_eq!(<&'static str>::from(Unavailable::NoSignal), "no_signal");
    }

    // ── the materialized read model ─────────────────────────────────────

    /// The property the whole cache rests on: a ranking produced under a
    /// superseded baseline is **not** served, however recent it is. Without
    /// this, §20.3's "a re-derived baseline changes rankings" contract is
    /// quietly repealed by the cache.
    #[test]
    fn a_ranking_from_a_superseded_baseline_is_refused_however_fresh() {
        let entry = CachedNeighbors {
            address: Address::repeat_byte(0x11),
            embedding_version: "behavior-v1".into(),
            baseline_fingerprint: "old-baseline".into(),
            neighbors: Vec::new(),
            approximate: false,
            computed_at: at(1_000),
        };

        assert_eq!(
            entry.validity("new-baseline", at(1_000), Duration::from_secs(3_600)),
            CacheVerdict::StaleBaseline,
            "zero seconds old and still unusable — the baseline moved"
        );
        assert_eq!(
            entry.validity("old-baseline", at(1_000), Duration::from_secs(3_600)),
            CacheVerdict::Fresh
        );
    }

    /// The second, independent rule: the neighbours' own vectors drift with no
    /// fingerprint of their own, so age bounds what the baseline check cannot.
    #[test]
    fn a_matching_baseline_still_expires_with_age() {
        let entry = CachedNeighbors {
            address: Address::repeat_byte(0x11),
            embedding_version: "behavior-v1".into(),
            baseline_fingerprint: "b".into(),
            neighbors: Vec::new(),
            approximate: false,
            computed_at: at(0),
        };
        let hour = Duration::from_secs(3_600);

        assert_eq!(entry.validity("b", at(3_600), hour), CacheVerdict::Fresh);
        assert_eq!(entry.validity("b", at(3_601), hour), CacheVerdict::Expired);
    }

    /// Each verdict has a distinct, closed metric label — `outcome`
    /// cardinality must not grow with traffic.
    #[test]
    fn cache_verdict_labels_are_a_closed_distinct_set() {
        let labels = [
            CacheVerdict::Fresh.label(),
            CacheVerdict::StaleBaseline.label(),
            CacheVerdict::Expired.label(),
        ];
        let unique: std::collections::BTreeSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len());
    }

    /// A cache hit reports the work *this* request did — none — while
    /// carrying through the fidelity of the ranking it replays. Reporting the
    /// original run's candidate counts would misattribute cost; silently
    /// reporting `approximate: false` would upgrade the claim.
    #[test]
    fn a_cached_answer_reports_no_work_but_keeps_its_fidelity() {
        let schema = &*v1::SCHEMA;
        let subject = stored(schema, 0x11, &vec![1.0; schema.dimension()]);
        let entry = CachedNeighbors {
            address: subject.address,
            embedding_version: schema.version().to_owned(),
            baseline_fingerprint: "b".into(),
            neighbors: vec![CachedNeighbor {
                address: Address::repeat_byte(0x22),
                entity_id: None,
                similarity: 0.75,
                factors: vec![BehaviorFactor {
                    feature: schema.features()[0].name.to_owned(),
                    value: 1.0,
                    share: 0.75,
                }],
            }],
            approximate: true,
            computed_at: at(5_000),
        };

        let search = SimilaritySearch::from_cache(schema, &subject, entry, 10);
        assert_eq!(search.candidates_considered, 0);
        assert_eq!(search.candidates_skipped, 0);
        assert!(search.approximate, "fidelity survives the round trip");
        assert_eq!(search.results.len(), 1);
        assert_eq!(search.results[0].similarity.get(), 0.75);
        assert_eq!(
            search.results[0].factors[0].feature,
            schema.features()[0].name
        );
    }

    /// A stored factor naming a feature this schema does not have is dropped,
    /// never turned into a leaked `&'static str`. That path runs on every
    /// cache hit, so growing an allocation from stored data would be an
    /// unbounded leak driven by the contents of a table.
    #[test]
    fn an_unknown_stored_factor_is_dropped_rather_than_leaked() {
        let schema = &*v1::SCHEMA;
        let subject = stored(schema, 0x11, &vec![1.0; schema.dimension()]);
        let entry = CachedNeighbors {
            address: subject.address,
            embedding_version: schema.version().to_owned(),
            baseline_fingerprint: "b".into(),
            neighbors: vec![CachedNeighbor {
                address: Address::repeat_byte(0x22),
                entity_id: None,
                similarity: 0.5,
                factors: vec![
                    BehaviorFactor {
                        feature: "a_feature_from_some_future_version".into(),
                        value: 1.0,
                        share: 0.5,
                    },
                    BehaviorFactor {
                        feature: schema.features()[1].name.to_owned(),
                        value: 2.0,
                        share: 0.5,
                    },
                ],
            }],
            approximate: false,
            computed_at: at(5_000),
        };

        let search = SimilaritySearch::from_cache(schema, &subject, entry, 10);
        let factors = &search.results[0].factors;
        assert_eq!(factors.len(), 1, "the unknown feature is dropped");
        assert_eq!(factors[0].feature, schema.features()[1].name);
    }

    /// Round trip: what a live search materializes is what a later hit
    /// replays.
    #[test]
    fn a_search_round_trips_through_its_cache_entry() {
        let schema = schema();
        let subject = stored(&schema, 0x11, &[3.0, -1.0, 2.0]);
        let neighbour = stored(&schema, 0x22, &[2.0, 1.0, 4.0]);
        let live = search(&schema, &subject, &[neighbour]);

        let entry = live.to_cache_entry("fp", at(9_000));
        assert_eq!(entry.baseline_fingerprint, "fp");
        assert_eq!(entry.neighbors.len(), live.results.len());
        assert_eq!(entry.approximate, live.approximate);

        let replayed = SimilaritySearch::from_cache(&schema, &subject, entry, 10);
        assert_eq!(replayed.results.len(), live.results.len());
        assert_eq!(replayed.results[0].address, live.results[0].address);
        assert!(
            (replayed.results[0].similarity.get() - live.results[0].similarity.get()).abs() < 1e-6
        );
    }

    #[test]
    fn requested_limits_clamp_rather_than_reject() {
        let limits = SimilarityLimits::default();
        assert_eq!(limits.results_for(0), limits.default_results);
        assert_eq!(limits.results_for(5), 5);
        assert_eq!(limits.results_for(10_000), limits.max_results);
    }

    /// The shortlist always has slack for the rows the re-rank will drop, even
    /// with the multiplier turned all the way down.
    #[test]
    fn the_shortlist_always_exceeds_the_result_count() {
        let limits = SimilarityLimits {
            candidate_multiplier: 1,
            ..SimilarityLimits::default()
        };
        assert!(limits.candidates_for(20) > 20);
        assert_eq!(
            SimilarityLimits::default().candidates_for(1_000),
            SimilarityLimits::default().max_candidates
        );
    }

    /// The real v1 schema, end to end: two addresses embedded from the same
    /// kernel rank against a baseline derived from their own population.
    #[test]
    fn ranks_real_v1_vectors() {
        use crate::embedding::{baseline, default_embedder, BehaviorInputs};

        let schema = &*v1::SCHEMA;
        let embedder = default_embedder();
        let subject_vector = embedder.embed(
            Address::repeat_byte(0x11),
            None,
            &BehaviorInputs::default(),
            at(1_000),
        );
        assert_eq!(subject_vector.values.len(), INDEXED_DIMENSION);

        // A population that actually varies, so the baseline has spread.
        let sample: Vec<Vec<f32>> = (0..5)
            .map(|i| {
                let mut row = vec![0.0f32; schema.dimension()];
                row[0] = i as f32;
                row
            })
            .collect();
        let mut population = baseline::compute(schema, &sample, at(0)).unwrap();
        population.sample_count = baseline::MIN_SAMPLES;

        let mut subject = stored(schema, 0x11, &subject_vector.values);
        subject.values[0] = 4.0;
        let mut neighbour = stored(schema, 0x22, &subject_vector.values);
        neighbour.values[0] = 3.0;

        let found = rank(RankRequest {
            schema,
            baseline: &population,
            subject: &subject,
            candidates: &[neighbour],
            limit: 10,
            shortlist_cap: usize::MAX,
        })
        .expect("comparable")
        .expect("has signal");
        assert_eq!(found.results.len(), 1);
        assert!(found.results[0].similarity.get() > 0.0);
        assert_eq!(found.embedding_version, v1::VERSION);
    }
}
