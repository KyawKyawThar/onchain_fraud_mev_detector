//! The pure core of sanctions-list versioning (§8.5, readiness Epic E): what a
//! list *is* ([`ListContent`]), how two versions differ ([`diff`]), whether a
//! fetched version may replace the current one ([`SnapshotPolicy`]), and what
//! a promotion announces ([`announcements`]). No I/O; the store and the sync
//! ([`crate::sanctions_sync`]) are the shell around it.
//!
//! # A list is a versioned snapshot, not a stream of upserts
//!
//! A fetched list is *staged* as a content-addressed snapshot, checked, and
//! only then *promoted*: one transaction makes the live `sanctions` rows for
//! that list equal the snapshot, logs the promotion, and queues its
//! announcements. Three things follow that an upsert-only import cannot give:
//!
//! - **The dangerous direction is guarded.** Designations hard-block
//!   withdrawals, so a bad *growth* (a wrong file, a concatenated mirror) is
//!   the irreversible failure, not a shrink. The growth bound
//!   ([`Finding::Grew`]) and the sentinel addresses
//!   ([`Finding::MissingSentinels`]) guard it; nothing reaches the live table
//!   unchecked.
//! - **Delisting is modelled.** Promotion removes what the list no longer
//!   carries, bounded by the shrink check ([`Finding::Shrunk`]), and announces
//!   it.
//! - **Provenance is point-in-time.** Snapshots and promotions are
//!   append-only, so "which version of this list were we screening with at
//!   time T, and did it contain X" has an answer, which a screening decision
//!   records by digest.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use chrono::{DateTime, Utc};
use events::intelligence::{SanctionHit, SanctionsListUpdated};
use events::primitives::{AccountAddress, Chain};
use events::DomainEvent;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::model::{address_key, SanctionsList};

/// Addresses per [`SanctionsListUpdated`] chunk. ~45 KiB of JSON, comfortably
/// under the broker's 1 MiB default however long the entries are, and small
/// enough that a redelivered chunk is cheap to reprocess.
pub const CHUNK_ADDRESSES: usize = 1_000;

/// The chain stamped on sanctions announcements. A list names EVM addresses,
/// valid on every chain, and has no chain of its own; one fixed chain keeps a
/// list's promotions ordered on one partition (the envelope's default key).
pub const ANNOUNCEMENT_CHAIN: Chain = Chain::ETHEREUM;

/// `promoted_by` for a promotion the scheduled sync made.
pub const SCHEDULED: &str = "scheduled";
/// `promoted_by` for a promotion that re-installed the current version because
/// the live rows had drifted from it.
pub const RECONCILE: &str = "reconcile";

// ── Content ──────────────────────────────────────────────────────

/// One designation: an address on a list, with the list's own entry text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Designation {
    pub address: AccountAddress,
    pub entry: String,
}

/// A list version: its distinct designations and their content digest.
///
/// Built only through [`ListContent::new`], so the digest always matches the
/// designations it is carried with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListContent {
    designations: BTreeMap<AccountAddress, String>,
    digest: String,
}

impl ListContent {
    /// Collapse designations by address (the last entry for an address wins —
    /// a feed may repeat a line) and digest the result.
    pub fn new(designations: impl IntoIterator<Item = Designation>) -> Self {
        let designations: BTreeMap<AccountAddress, String> = designations
            .into_iter()
            .map(|d| (d.address, d.entry))
            .collect();
        let digest = digest_of(&designations);
        Self {
            designations,
            digest,
        }
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn entries(&self) -> u64 {
        self.designations.len() as u64
    }

    pub fn contains(&self, address: &AccountAddress) -> bool {
        self.designations.contains_key(address)
    }

    pub fn entry(&self, address: &AccountAddress) -> Option<&str> {
        self.designations.get(address).map(String::as_str)
    }

    /// In address order.
    pub fn iter(&self) -> impl Iterator<Item = (&AccountAddress, &str)> {
        self.designations.iter().map(|(a, e)| (a, e.as_str()))
    }
}

/// SHA-256 over the address-ordered `(address, entry)` pairs, length-prefixed
/// so field boundaries cannot be forged.
///
/// Over the designations, not the file: a reordered file or an edited comment
/// is not a new version, and two mirrors of one list digest identically.
///
/// **A persistence contract**, like `seeded_label_id`: stored digests are
/// compared against freshly computed ones, so changing the recipe makes every
/// list look changed on its next sync. The golden test pins the bytes.
fn digest_of(designations: &BTreeMap<AccountAddress, String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mevwatch.sanctions-list-content.v1");
    for (address, entry) in designations {
        let address = address_key(address);
        for field in [address.as_str(), entry.as_str()] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
    }
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use fmt::Write;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

// ── Diff ─────────────────────────────────────────────────────────

/// How the live rows must change to equal a new version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diff {
    /// Newly designated.
    pub added: Vec<Designation>,
    /// Still designated, with a different entry text.
    pub changed: Vec<Designation>,
    /// No longer designated.
    pub removed: Vec<AccountAddress>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.changed.is_empty() && self.removed.is_empty()
    }
}

/// What turns `live` into `next`. Every vector comes out in address order, so
/// a diff (and the announcements built from it) is deterministic.
pub fn diff(live: &ListContent, next: &ListContent) -> Diff {
    let mut out = Diff::default();
    for (address, entry) in next.iter() {
        match live.entry(address) {
            None => out.added.push(Designation {
                address: *address,
                entry: entry.to_owned(),
            }),
            Some(current) if current != entry => out.changed.push(Designation {
                address: *address,
                entry: entry.to_owned(),
            }),
            Some(_) => {}
        }
    }
    out.removed = live
        .iter()
        .filter(|(address, _)| !next.contains(address))
        .map(|(address, _)| *address)
        .collect();
    out
}

// ── Checks ───────────────────────────────────────────────────────

/// Why a staged version was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// No designations at all. Never overridable: no real sanctions list is
    /// empty, and promoting one would delist everything.
    Empty,
    Shrunk {
        previous: u64,
        entries: u64,
        max_percent: u8,
    },
    Grew {
        previous: u64,
        entries: u64,
        max_percent: u32,
        floor: u64,
    },
    /// Addresses the operator declared must always be on this list are
    /// missing — the likeliest sign of a wrong file behind a right URL.
    MissingSentinels { missing: Vec<AccountAddress> },
}

impl Finding {
    /// Whether an operator may promote past it after checking upstream.
    pub fn overridable(&self) -> bool {
        !matches!(self, Finding::Empty)
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::Empty => write!(f, "the list has no addresses"),
            Finding::Shrunk {
                previous,
                entries,
                max_percent,
            } => write!(
                f,
                "the list shrank from {previous} to {entries} addresses, more than the \
                 {max_percent}% shrink allowed"
            ),
            Finding::Grew {
                previous,
                entries,
                max_percent,
                floor,
            } => write!(
                f,
                "the list grew from {previous} to {entries} addresses, more than the \
                 {max_percent}% (or {floor} addresses) growth allowed"
            ),
            Finding::MissingSentinels { missing } => {
                let shown: Vec<String> = missing.iter().take(5).map(address_key).collect();
                write!(
                    f,
                    "{} sentinel address(es) missing: {}",
                    missing.len(),
                    shown.join(", ")
                )
            }
        }
    }
}

/// Render findings as one line — the ledger's failure reason.
pub fn describe(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// The checks a staged version must pass before it may replace the current
/// one. A value, not a trait object per check: the set is closed, every check
/// is a few lines, and the whole policy is visible in one constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPolicy {
    max_shrink_percent: u8,
    max_growth_percent: u32,
    growth_floor: u64,
    sentinels: HashMap<SanctionsList, Vec<AccountAddress>>,
}

impl SnapshotPolicy {
    /// `max_shrink_percent` ≤ 100 (100 allows any shrink short of empty).
    /// Growth is refused past `max_growth_percent` **and** `growth_floor`
    /// addresses, so a small list is not refused for adding a handful.
    pub fn new(
        max_shrink_percent: u8,
        max_growth_percent: u32,
        growth_floor: u64,
        sentinels: HashMap<SanctionsList, Vec<AccountAddress>>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            max_shrink_percent <= 100,
            "max shrink must be 0..=100 percent, got {max_shrink_percent}"
        );
        Ok(Self {
            max_shrink_percent,
            max_growth_percent,
            growth_floor,
            sentinels,
        })
    }

    /// Every check `next` fails against the current version's `previous`
    /// entry count (`None` for a list's first version).
    pub fn evaluate(
        &self,
        list: SanctionsList,
        previous: Option<u64>,
        next: &ListContent,
    ) -> Vec<Finding> {
        let entries = next.entries();
        if entries == 0 {
            return vec![Finding::Empty];
        }
        let mut findings = Vec::new();
        if let Some(previous) = previous {
            // entries / previous < (100 - max) / 100, in integers.
            let floor = u128::from(previous) * u128::from(100 - self.max_shrink_percent);
            if u128::from(entries) * 100 < floor {
                findings.push(Finding::Shrunk {
                    previous,
                    entries,
                    max_percent: self.max_shrink_percent,
                });
            }
            let allowed = (u128::from(previous) * u128::from(self.max_growth_percent) / 100)
                .max(u128::from(self.growth_floor));
            if u128::from(entries) > u128::from(previous) + allowed {
                findings.push(Finding::Grew {
                    previous,
                    entries,
                    max_percent: self.max_growth_percent,
                    floor: self.growth_floor,
                });
            }
        }
        if let Some(sentinels) = self.sentinels.get(&list) {
            let missing: Vec<AccountAddress> = sentinels
                .iter()
                .filter(|address| !next.contains(address))
                .copied()
                .collect();
            if !missing.is_empty() {
                findings.push(Finding::MissingSentinels { missing });
            }
        }
        findings
    }
}

/// Parse `INTEL_SANCTIONS_SENTINELS`: `list:0xaddr,0xaddr;list:0xaddr`.
pub fn parse_sentinels(raw: &str) -> anyhow::Result<HashMap<SanctionsList, Vec<AccountAddress>>> {
    let mut out: HashMap<SanctionsList, Vec<AccountAddress>> = HashMap::new();
    for group in raw.split(';').map(str::trim).filter(|g| !g.is_empty()) {
        let (list, addresses) = group.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("INTEL_SANCTIONS_SENTINELS: {group:?} is not `list:0xaddr,…`")
        })?;
        let list: SanctionsList = list.trim().parse().map_err(|_| {
            anyhow::anyhow!("INTEL_SANCTIONS_SENTINELS: {list:?} is not a sanctions list")
        })?;
        for address in addresses
            .split(',')
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            let parsed: AccountAddress = address.parse().map_err(|_| {
                anyhow::anyhow!("INTEL_SANCTIONS_SENTINELS: {address:?} is not an address")
            })?;
            out.entry(list).or_default().push(parsed);
        }
    }
    Ok(out)
}

// ── Announcements ────────────────────────────────────────────────

/// The facts of one promotion that every announcement repeats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionFacts {
    pub promotion_id: Uuid,
    pub list: SanctionsList,
    pub digest: String,
    pub previous_digest: Option<String>,
    pub entries: u64,
    pub promoted_by: String,
    pub promoted_at: DateTime<Utc>,
}

/// One event a promotion queues, with the outbox idempotency key that makes a
/// retried transaction a no-op.
#[derive(Debug, Clone, PartialEq)]
pub struct Announcement {
    pub key: String,
    pub event: DomainEvent,
}

/// Everything a promotion announces:
///
/// - [`SanctionsListUpdated`], chunked to [`CHUNK_ADDRESSES`] (at least one
///   chunk, so even an entry-text-only change is on the record);
/// - a [`SanctionHit`] for every newly designated address that is already
///   `known` — §8.5's "a match against a new *or existing* label". Without
///   this, an address we have watched for months would raise nothing when it
///   is designated until it next appeared in an incident.
pub fn announcements(
    facts: &PromotionFacts,
    diff: &Diff,
    known: &HashSet<AccountAddress>,
) -> Vec<Announcement> {
    let total = diff.added.len() + diff.removed.len();
    let chunks = total.div_ceil(CHUNK_ADDRESSES).max(1);
    let mut out = Vec::with_capacity(chunks + known.len());

    let tagged = diff
        .added
        .iter()
        .map(|d| (true, d.address))
        .chain(diff.removed.iter().map(|a| (false, *a)))
        .collect::<Vec<_>>();
    for chunk in 0..chunks {
        let slice = tagged
            .iter()
            .skip(chunk * CHUNK_ADDRESSES)
            .take(CHUNK_ADDRESSES);
        let (added, removed): (Vec<_>, Vec<_>) = slice.partition(|(is_added, _)| *is_added);
        out.push(Announcement {
            key: format!("sanctions/{}/list/{chunk}", facts.promotion_id),
            event: DomainEvent::SanctionsListUpdated(SanctionsListUpdated {
                promotion_id: facts.promotion_id,
                list: facts.list.as_str().to_owned(),
                digest: facts.digest.clone(),
                previous_digest: facts.previous_digest.clone(),
                entries: facts.entries,
                added_total: diff.added.len() as u64,
                removed_total: diff.removed.len() as u64,
                added: added.into_iter().map(|(_, a)| a).collect(),
                removed: removed.into_iter().map(|(_, a)| a).collect(),
                chunk: chunk as u32,
                chunks: chunks as u32,
                promoted_by: facts.promoted_by.clone(),
                promoted_at: facts.promoted_at,
            }),
        });
    }

    for designation in diff.added.iter().filter(|d| known.contains(&d.address)) {
        out.push(Announcement {
            key: format!(
                "sanctions/{}/hit/{}",
                facts.promotion_id,
                address_key(&designation.address)
            ),
            event: DomainEvent::SanctionHit(SanctionHit {
                address: designation.address,
                list: facts.list.as_str().to_owned(),
                entry: designation.entry.clone(),
            }),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;

    fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    fn content(rows: &[(u8, &str)]) -> ListContent {
        ListContent::new(rows.iter().map(|(b, e)| Designation {
            address: addr(*b),
            entry: (*e).to_owned(),
        }))
    }

    fn policy(sentinels: &[(SanctionsList, u8)]) -> SnapshotPolicy {
        let mut map: HashMap<SanctionsList, Vec<AccountAddress>> = HashMap::new();
        for (list, byte) in sentinels {
            map.entry(*list).or_default().push(addr(*byte));
        }
        SnapshotPolicy::new(20, 100, 5, map).unwrap()
    }

    // ── Content ─────────────────────────────────────────────────

    #[test]
    fn content_is_order_and_duplicate_insensitive() {
        let a = content(&[(1, "x"), (2, "y")]);
        let b = content(&[(2, "y"), (1, "x"), (1, "x")]);
        assert_eq!(a, b);
        assert_eq!(a.entries(), 2);
        assert_eq!(a.digest().len(), 64);
    }

    #[test]
    fn entry_text_is_part_of_the_content() {
        assert_ne!(
            content(&[(1, "x")]).digest(),
            content(&[(1, "renamed")]).digest()
        );
    }

    /// **Golden pin of the digest recipe.** Stored digests are compared with
    /// fresh ones; changing the recipe flips every list to "changed" on its
    /// next sync and re-promotes it. Do not update without a migration story.
    #[test]
    fn digest_recipe_is_pinned() {
        assert_eq!(
            content(&[(0x11, "OFAC SDN digital-currency address")]).digest(),
            "d866ffd061554ef38f417e381b4a56569d8ba17668df55e8978484e4d5ef35da",
            "the sanctions content digest recipe changed — see digest_of's docs"
        );
    }

    // ── Diff ────────────────────────────────────────────────────

    #[test]
    fn diff_splits_added_changed_and_removed() {
        let live = content(&[(1, "a"), (2, "b"), (3, "c")]);
        let next = content(&[(2, "b"), (3, "c2"), (4, "d")]);
        let d = diff(&live, &next);
        assert_eq!(
            d.added,
            vec![Designation {
                address: addr(4),
                entry: "d".into()
            }]
        );
        assert_eq!(
            d.changed,
            vec![Designation {
                address: addr(3),
                entry: "c2".into()
            }]
        );
        assert_eq!(d.removed, vec![addr(1)]);
        assert!(diff(&next, &next).is_empty());
    }

    // ── Checks ──────────────────────────────────────────────────

    #[test]
    fn empty_is_refused_and_never_overridable() {
        let found = policy(&[]).evaluate(SanctionsList::OfacSdn, None, &content(&[]));
        assert_eq!(found, vec![Finding::Empty]);
        assert!(!found[0].overridable());
    }

    #[test]
    fn a_first_version_skips_the_size_checks() {
        let big = ListContent::new((0..=255u8).map(|b| Designation {
            address: addr(b),
            entry: "e".into(),
        }));
        assert!(policy(&[])
            .evaluate(SanctionsList::OfacSdn, None, &big)
            .is_empty());
    }

    #[test]
    fn shrink_boundary_is_inclusive_of_the_allowed_share() {
        let p = SnapshotPolicy::new(20, 100, 0, HashMap::new()).unwrap();
        let of = |n: u8| {
            ListContent::new((0..n).map(|b| Designation {
                address: addr(b),
                entry: "e".into(),
            }))
        };
        assert!(p
            .evaluate(SanctionsList::OfacSdn, Some(100), &of(80))
            .is_empty());
        let found = p.evaluate(SanctionsList::OfacSdn, Some(100), &of(79));
        assert!(matches!(found[..], [Finding::Shrunk { .. }]));
        assert!(found[0].overridable());
    }

    /// Growth is the irreversible direction: refused past the percentage *and*
    /// the absolute floor, so a small list may still gain a handful.
    #[test]
    fn growth_is_refused_past_both_the_percentage_and_the_floor() {
        let p = SnapshotPolicy::new(100, 100, 5, HashMap::new()).unwrap();
        let of = |n: u8| {
            ListContent::new((0..n).map(|b| Designation {
                address: addr(b),
                entry: "e".into(),
            }))
        };
        // previous 2: allowed growth is max(2, 5) = 5 → up to 7.
        assert!(p
            .evaluate(SanctionsList::OfacSdn, Some(2), &of(7))
            .is_empty());
        assert!(matches!(
            p.evaluate(SanctionsList::OfacSdn, Some(2), &of(8))[..],
            [Finding::Grew { .. }]
        ));
        // previous 100: allowed growth is 100 → up to 200.
        assert!(p
            .evaluate(SanctionsList::OfacSdn, Some(100), &of(200))
            .is_empty());
        assert!(matches!(
            p.evaluate(SanctionsList::OfacSdn, Some(100), &of(201))[..],
            [Finding::Grew { .. }]
        ));
    }

    #[test]
    fn sentinels_apply_per_list() {
        let p = policy(&[(SanctionsList::OfacSdn, 9)]);
        let without = content(&[(1, "e")]);
        let found = p.evaluate(SanctionsList::OfacSdn, None, &without);
        assert_eq!(
            found,
            vec![Finding::MissingSentinels {
                missing: vec![addr(9)]
            }]
        );
        assert!(p
            .evaluate(SanctionsList::EuConsolidated, None, &without)
            .is_empty());
        assert!(p
            .evaluate(SanctionsList::OfacSdn, None, &content(&[(9, "e")]))
            .is_empty());
    }

    #[test]
    fn sentinels_parse_and_reject_garbage() {
        let parsed = parse_sentinels(
            " ofac_sdn:0x1111111111111111111111111111111111111111,\
             0x2222222222222222222222222222222222222222 ; eu_consolidated:\
             0x3333333333333333333333333333333333333333",
        )
        .unwrap();
        assert_eq!(parsed[&SanctionsList::OfacSdn].len(), 2);
        assert_eq!(parsed[&SanctionsList::EuConsolidated], vec![addr(0x33)]);
        assert!(parse_sentinels("").unwrap().is_empty());
        assert!(parse_sentinels("ofac:0x11").is_err());
        assert!(parse_sentinels("ofac_sdn:nope").is_err());
        assert!(parse_sentinels("ofac_sdn").is_err());
    }

    // ── Announcements ───────────────────────────────────────────

    fn facts() -> PromotionFacts {
        PromotionFacts {
            promotion_id: Uuid::from_u128(7),
            list: SanctionsList::OfacSdn,
            digest: "d2".into(),
            previous_digest: Some("d1".into()),
            entries: 3,
            promoted_by: SCHEDULED.into(),
            promoted_at: DateTime::<Utc>::from_timestamp(100, 0).unwrap(),
        }
    }

    #[test]
    fn a_small_promotion_is_one_chunk_plus_hits_for_known_addresses() {
        let d = diff(&content(&[(1, "a")]), &content(&[(2, "b"), (3, "c")]));
        let known = HashSet::from([addr(3)]);
        let out = announcements(&facts(), &d, &known);
        assert_eq!(out.len(), 2);
        let DomainEvent::SanctionsListUpdated(update) = &out[0].event else {
            panic!("first is the list update");
        };
        assert_eq!(update.added, vec![addr(2), addr(3)]);
        assert_eq!(update.removed, vec![addr(1)]);
        assert_eq!((update.chunk, update.chunks), (0, 1));
        assert_eq!((update.added_total, update.removed_total), (2, 1));
        let DomainEvent::SanctionHit(hit) = &out[1].event else {
            panic!("second is the hit");
        };
        assert_eq!(hit.address, addr(3));
        assert_eq!(hit.entry, "c");
        assert_eq!(hit.list, "ofac_sdn");
        // Keys are unique and stable per promotion.
        assert_ne!(out[0].key, out[1].key);
        assert_eq!(announcements(&facts(), &d, &known)[1].key, out[1].key);
    }

    #[test]
    fn a_large_diff_is_chunked_with_every_address_exactly_once() {
        let live = content(&[]);
        let next = ListContent::new((0..2_500u32).map(|i| {
            let mut bytes = [0u8; 20];
            bytes[..4].copy_from_slice(&i.to_be_bytes());
            Designation {
                address: Address::from(bytes),
                entry: "e".into(),
            }
        }));
        let out = announcements(&facts(), &diff(&live, &next), &HashSet::new());
        assert_eq!(out.len(), 3);
        let mut seen = HashSet::new();
        for (i, a) in out.iter().enumerate() {
            let DomainEvent::SanctionsListUpdated(u) = &a.event else {
                panic!("only list updates");
            };
            assert_eq!((u.chunk, u.chunks), (i as u32, 3));
            assert!(u.added.len() <= CHUNK_ADDRESSES);
            assert_eq!(u.added_total, 2_500);
            for address in &u.added {
                assert!(seen.insert(*address), "no address in two chunks");
            }
        }
        assert_eq!(seen.len(), 2_500);
    }

    /// An entry-text-only change still leaves one (empty) chunk on the record.
    #[test]
    fn an_entry_only_change_still_announces() {
        let d = diff(&content(&[(1, "a")]), &content(&[(1, "b")]));
        let out = announcements(&facts(), &d, &HashSet::new());
        assert_eq!(out.len(), 1);
        let DomainEvent::SanctionsListUpdated(u) = &out[0].event else {
            panic!("a list update");
        };
        assert!(u.added.is_empty() && u.removed.is_empty());
    }
}
