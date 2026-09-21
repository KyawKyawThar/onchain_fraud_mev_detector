//! Scheduled sanctions-list sync (§8.5, readiness Epic E): the I/O shell over
//! [`crate::sanctions_list`]. One run, for one list:
//!
//! ```text
//!  resume unfinished effects of earlier promotions
//!  fetch (conditional GET when the current version has validators)
//!   ├─ 304, or same digest as current ──► confirm (after checking the live
//!   │                                      rows still equal it; if not,
//!   │                                      re-promote it: reconcile)
//!   └─ new content ──► stage snapshot ──► checks ──┬─ refused: record, stop
//!                                                  └─ promote (one txn) ──► effects
//! ```
//!
//! What keeps this path from reporting success it did not earn:
//!
//! - **Freshness is stamped only by a confirmation or a promotion**, both
//!   conditional on the version they were decided against, both using the
//!   database clock, and both at the *fetch* time: the content is as-of when it
//!   was read, so a slow run can only overstate a list's age.
//! - **A confirmation is checked, not assumed.** The live rows are digested and
//!   compared with the current version first; drift (a restore, a manual edit)
//!   is repaired by re-promoting the current version, not stamped fresh.
//! - **Nothing reaches the live table unchecked.** A fetched version is staged
//!   and must pass the [`SnapshotPolicy`]; a refused one waits for an operator
//!   ([`SanctionsSync::promote_staged`]) who promotes exactly the content they
//!   reviewed, by digest, rather than a re-fetch that might differ.
//! - **Post-commit effects are tracked.** Label writes and hot-cache evictions
//!   cannot share the promotion's transaction (the cache is Redis), so the
//!   promotion is logged with `effects_applied_at = NULL` and every run
//!   resumes whatever is unfinished before doing anything else. Screening does
//!   not depend on them: its sanctions read comes from the live rows.
//!
//! Every failure is recorded in the ledger with its reason, and the process
//! exits with a code the CronJob's `podFailurePolicy` reads
//! ([`SyncError::exit_code`]): transient failures are retried, permanent ones
//! and refusals fail the Job at once. The freshness monitor reads the ledger,
//! not the Job, so a Job that never runs is caught too.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use event_bus::Transience;
use events::primitives::AccountAddress;
use outbox::Outbox;
use url::Url;
use uuid::Uuid;

use crate::cache::{CacheError, HotCache};
use crate::model::{PromotionRecord, SanctionsList, Validators};
use crate::sanctions_list::{self, describe, Designation, Finding, ListContent, SnapshotPolicy};
use crate::seed::ParseError;
use crate::store::{
    Confirmation, LabelStore, PromotionOutcome, PromotionRequest, SanctionsListStore,
    StagedSnapshot, StoreError,
};

/// The outbox a promotion's announcements are queued in (migration
/// `20260920000000`), drained by the flusher in the `grpc` run mode and once
/// by each sync run right after it commits.
pub const SANCTIONS_OUTBOX: Outbox = Outbox::new("sanctions_outbox", "intel_sanctions_outbox");

/// Longest failure reason stored in the ledger. Reasons are one-line errors;
/// the cap only stops a pathological one from bloating the row.
const MAX_REASON_CHARS: usize = 1_000;

/// Exit code for a failure worth retrying (EX_TEMPFAIL). The CronJob's
/// `podFailurePolicy` retries only this code.
pub const EXIT_TRANSIENT: u8 = 75;
/// Exit code for a snapshot refused by the checks: it needs a human.
pub const EXIT_REFUSED: u8 = 3;
/// Exit code for any other permanent failure.
pub const EXIT_PERMANENT: u8 = 1;

// ── Fetching ─────────────────────────────────────────────────────

/// A failure reading the list from its source.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("request to {source_name} failed: {error}")]
    Http {
        source_name: String,
        #[source]
        error: reqwest::Error,
    },
    #[error("{source_name} answered HTTP {status}")]
    Status { source_name: String, status: u16 },
    #[error("{source_name} is larger than the {limit}-byte cap")]
    TooLarge { source_name: String, limit: u64 },
    #[error("{source_name} is not UTF-8 text")]
    NotUtf8 { source_name: String },
    #[error("reading {source_name}: {error}")]
    Io {
        source_name: String,
        #[source]
        error: std::io::Error,
    },
}

impl Transience for FetchError {
    /// A network fault, a timeout, a 429 or a 5xx may clear; a 4xx, an
    /// oversized or non-text body, or a missing file will not.
    fn is_transient(&self) -> bool {
        match self {
            FetchError::Http { .. } => true,
            FetchError::Status { status, .. } => *status == 429 || *status >= 500,
            FetchError::TooLarge { .. } | FetchError::NotUtf8 { .. } | FetchError::Io { .. } => {
                false
            }
        }
    }
}

/// What a fetch returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    Body {
        text: String,
        validators: Validators,
    },
    /// The source confirmed the version the conditional request named.
    NotModified,
}

/// Where a list is read from. A seam so the sync is tested without a network,
/// and so the manual `seed` path (a file) and the scheduled one (a URL) run
/// the same sync.
#[async_trait]
pub trait FeedSource: Send + Sync {
    /// What the ledger records as the list's `source`. Must not carry a
    /// credential (see [`HttpFeedSource`]).
    fn describe(&self) -> String;

    /// The list's raw text — or [`Fetched::NotModified`] when `conditional`
    /// is given and the source confirms it is still current.
    async fn fetch(&self, conditional: Option<&Validators>) -> Result<Fetched, FetchError>;
}

/// A list served over HTTP(S): a timeout, a size cap, and conditional GETs.
pub struct HttpFeedSource {
    client: reqwest::Client,
    url: Url,
    max_bytes: u64,
}

impl HttpFeedSource {
    pub fn new(url: Url, timeout: Duration, max_bytes: u64) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder().timeout(timeout).build()?;
        Ok(Self {
            client,
            url,
            max_bytes,
        })
    }
}

/// The URL without its query, fragment or userinfo. Sanctions downloads are
/// commonly token-gated in the query string (the EU FSF's are), and the ledger
/// is readable by anyone with database access.
fn redacted_url(url: &Url) -> String {
    let mut shown = url.clone();
    shown.set_query(None);
    shown.set_fragment(None);
    // Only fails for URLs that cannot carry userinfo, which then have none.
    let _ = shown.set_username("");
    let _ = shown.set_password(None);
    shown.to_string()
}

fn header(response: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[async_trait]
impl FeedSource for HttpFeedSource {
    fn describe(&self) -> String {
        redacted_url(&self.url)
    }

    async fn fetch(&self, conditional: Option<&Validators>) -> Result<Fetched, FetchError> {
        use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};

        let source_name = self.describe();
        let http = |error| FetchError::Http {
            source_name: source_name.clone(),
            error,
        };
        let mut request = self.client.get(self.url.clone());
        if let Some(validators) = conditional {
            if let Some(etag) = &validators.etag {
                request = request.header(IF_NONE_MATCH, etag);
            }
            if let Some(modified) = &validators.last_modified {
                request = request.header(IF_MODIFIED_SINCE, modified);
            }
        }
        let mut response = request.send().await.map_err(http)?;
        if conditional.is_some() && response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Fetched::NotModified);
        }
        if !response.status().is_success() {
            return Err(FetchError::Status {
                source_name,
                status: response.status().as_u16(),
            });
        }
        let validators = Validators {
            etag: header(&response, ETAG),
            last_modified: header(&response, LAST_MODIFIED),
        };
        // Read chunk by chunk so the cap holds even when the server sends no
        // (or a lying) Content-Length.
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(http)? {
            body.extend_from_slice(&chunk);
            if body.len() as u64 > self.max_bytes {
                return Err(FetchError::TooLarge {
                    source_name,
                    limit: self.max_bytes,
                });
            }
        }
        let text = String::from_utf8(body).map_err(|_| FetchError::NotUtf8 { source_name })?;
        Ok(Fetched::Body { text, validators })
    }
}

/// A list already on disk: the manual `seed` path, and an operator re-running
/// a sync against a file they fetched and checked by hand. Never conditional.
pub struct FileFeedSource {
    path: PathBuf,
    max_bytes: u64,
}

impl FileFeedSource {
    pub fn new(path: impl Into<PathBuf>, max_bytes: u64) -> Self {
        Self {
            path: path.into(),
            max_bytes,
        }
    }
}

#[async_trait]
impl FeedSource for FileFeedSource {
    fn describe(&self) -> String {
        format!("file:{}", self.path.display())
    }

    async fn fetch(&self, _conditional: Option<&Validators>) -> Result<Fetched, FetchError> {
        let source_name = self.describe();
        let bytes = tokio::fs::read(&self.path)
            .await
            .map_err(|error| FetchError::Io {
                source_name: source_name.clone(),
                error,
            })?;
        if bytes.len() as u64 > self.max_bytes {
            return Err(FetchError::TooLarge {
                source_name,
                limit: self.max_bytes,
            });
        }
        let text = String::from_utf8(bytes).map_err(|_| FetchError::NotUtf8 { source_name })?;
        Ok(Fetched::Body {
            text,
            validators: Validators::default(),
        })
    }
}

/// Pick the source for a CLI argument: an `http(s)://` URL is fetched,
/// anything else is a path.
pub fn source_for(
    location: &str,
    timeout: Duration,
    max_bytes: u64,
) -> anyhow::Result<Box<dyn FeedSource>> {
    if location.starts_with("http://") || location.starts_with("https://") {
        let url: Url = location
            .parse()
            .map_err(|err| anyhow::anyhow!("sanctions source {location:?} is not a URL: {err}"))?;
        Ok(Box::new(HttpFeedSource::new(url, timeout, max_bytes)?))
    } else {
        Ok(Box::new(FileFeedSource::new(location, max_bytes)))
    }
}

// ── Errors ───────────────────────────────────────────────────────

/// Why a sync or a promotion did not complete.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The fetched version failed its checks and is staged as `refused`.
    #[error("{list} snapshot {digest} refused: {}", describe(findings))]
    Refused {
        list: SanctionsList,
        digest: String,
        findings: Vec<Finding>,
    },
    /// Another promotion of the list landed while this run was deciding.
    #[error("{list} changed while syncing (current is now {current:?}); the next run re-decides")]
    Conflict {
        list: SanctionsList,
        current: Option<String>,
    },
    #[error("{list} has no staged snapshot {digest}")]
    UnknownSnapshot { list: SanctionsList, digest: String },
    #[error("{0}")]
    Invalid(String),
    #[error("the sanctions store: {0}")]
    Store(#[from] StoreError),
    #[error("the hot cache: {0}")]
    Cache(#[from] CacheError),
}

impl Transience for SyncError {
    fn is_transient(&self) -> bool {
        match self {
            SyncError::Fetch(err) => err.is_transient(),
            SyncError::Store(err) => err.is_transient(),
            SyncError::Cache(err) => err.is_transient(),
            SyncError::Conflict { .. } => true,
            SyncError::Parse(_)
            | SyncError::Refused { .. }
            | SyncError::UnknownSnapshot { .. }
            | SyncError::Invalid(_) => false,
        }
    }
}

impl SyncError {
    /// The process exit code for this failure: [`EXIT_TRANSIENT`] (retried by
    /// the Job), [`EXIT_REFUSED`] (a human must look), or [`EXIT_PERMANENT`].
    pub fn exit_code(&self) -> u8 {
        if matches!(self, SyncError::Refused { .. }) {
            EXIT_REFUSED
        } else if self.is_transient() {
            EXIT_TRANSIENT
        } else {
            EXIT_PERMANENT
        }
    }
}

// ── The sync ─────────────────────────────────────────────────────

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The current version is still what the source serves.
    Unchanged {
        digest: String,
        entries: u64,
        /// Confirmed by a `304`, without downloading the list.
        not_modified: bool,
    },
    /// A new version replaced the current one.
    Promoted(PromotionRecord),
    /// The live rows had drifted from the current version and were repaired.
    Reconciled(PromotionRecord),
}

/// What one run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub list: SanctionsList,
    pub outcome: SyncOutcome,
    /// Earlier promotions whose unfinished effects this run completed.
    pub effects_resumed: usize,
}

impl std::fmt::Display for SyncReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.outcome {
            SyncOutcome::Unchanged {
                digest,
                entries,
                not_modified,
            } => {
                let how = if *not_modified { " (HTTP 304)" } else { "" };
                write!(
                    f,
                    "{}: unchanged{how}, {entries} addresses, version {}",
                    self.list,
                    short(digest)
                )?;
            }
            SyncOutcome::Promoted(p) | SyncOutcome::Reconciled(p) => {
                let verb = if matches!(self.outcome, SyncOutcome::Reconciled(_)) {
                    "reconciled"
                } else {
                    "promoted"
                };
                write!(
                    f,
                    "{}: {verb} version {} ({} addresses; +{} -{} ~{}) by {}",
                    self.list,
                    short(&p.digest),
                    p.entries,
                    p.added.len(),
                    p.removed.len(),
                    p.changed.len(),
                    p.promoted_by
                )?;
            }
        }
        if self.effects_resumed > 0 {
            write!(
                f,
                "; resumed effects of {} earlier promotion(s)",
                self.effects_resumed
            )?;
        }
        Ok(())
    }
}

fn short(digest: &str) -> &str {
    digest.get(..12).unwrap_or(digest)
}

/// One list's sync, and the operator's promotion of a refused snapshot.
pub struct SanctionsSync {
    store: Arc<dyn SanctionsListStore>,
    labels: Arc<dyn LabelStore>,
    cache: Arc<dyn HotCache>,
    policy: SnapshotPolicy,
}

impl SanctionsSync {
    pub fn new(
        store: Arc<dyn SanctionsListStore>,
        labels: Arc<dyn LabelStore>,
        cache: Arc<dyn HotCache>,
        policy: SnapshotPolicy,
    ) -> Self {
        Self {
            store,
            labels,
            cache,
            policy,
        }
    }

    /// Sync `list` from `source`, recording any failure in the ledger before
    /// returning it.
    #[tracing::instrument(skip_all, fields(list = %list, source = %source.describe()))]
    pub async fn sync(
        &self,
        list: SanctionsList,
        source: &dyn FeedSource,
    ) -> Result<SyncReport, SyncError> {
        let result = self.sync_inner(list, source).await;
        match &result {
            Ok(report) => tracing::info!(%report, "sanctions list synced"),
            Err(err) => {
                let reason = truncate_reason(&err.to_string());
                tracing::error!(
                    error = %reason,
                    transient = err.is_transient(),
                    "sanctions list sync failed"
                );
                // Stamped with the database clock like every other ledger
                // write. If the store is what failed, this fails too — and the
                // list's clock has stopped anyway, which the staleness alert
                // catches on its own.
                let recorded = match self.store.db_now().await {
                    Ok(at) => self.store.record_sync_failure(list, at, &reason).await,
                    Err(err) => Err(err),
                };
                if let Err(ledger_err) = recorded {
                    tracing::error!(
                        error = %ledger_err,
                        "could not record the failed sync in the ledger"
                    );
                }
            }
        }
        result
    }

    async fn sync_inner(
        &self,
        list: SanctionsList,
        source: &dyn FeedSource,
    ) -> Result<SyncReport, SyncError> {
        let effects_resumed = self.resume_effects(list).await?;
        let fetched_at = self.store.db_now().await?;
        let current = self.store.list_sync(list).await?;
        let source_name = source.describe();

        // Conditional only when there is a current version to confirm: a 304
        // with nothing to compare against would prove nothing.
        let conditional = current
            .content_digest
            .as_ref()
            .filter(|_| !current.validators.is_empty())
            .map(|_| &current.validators);

        let (content, validators) = match source.fetch(conditional).await? {
            Fetched::NotModified => {
                let Some(digest) = current.content_digest.as_deref() else {
                    // Unreachable through `conditional`, but a source that
                    // answers 304 unprompted must not be read as a sync.
                    return Err(SyncError::Invalid(format!(
                        "{source_name} answered 304 to an unconditional request"
                    )));
                };
                let outcome = self
                    .confirm_or_reconcile(
                        list,
                        digest,
                        fetched_at,
                        &source_name,
                        &current.validators,
                        true,
                    )
                    .await?;
                return Ok(SyncReport {
                    list,
                    outcome,
                    effects_resumed,
                });
            }
            Fetched::Body { text, validators } => {
                let feed = list.feed();
                let batch = feed.parse(&text, feed.canonical_detail(), fetched_at)?;
                let content =
                    ListContent::new(batch.sanctions.into_iter().map(|entry| Designation {
                        address: entry.address,
                        entry: entry.entry,
                    }));
                (content, validators)
            }
        };

        if current.content_digest.as_deref() == Some(content.digest()) {
            let outcome = self
                .confirm_or_reconcile(
                    list,
                    content.digest(),
                    fetched_at,
                    &source_name,
                    &validators,
                    false,
                )
                .await?;
            return Ok(SyncReport {
                list,
                outcome,
                effects_resumed,
            });
        }

        self.store
            .stage_snapshot(&StagedSnapshot {
                list,
                content: &content,
                source: &source_name,
                fetched_at,
            })
            .await?;
        let previous_entries = current.content_digest.as_ref().and(current.entries);
        let findings = self.policy.evaluate(list, previous_entries, &content);
        if !findings.is_empty() {
            self.store
                .refuse_snapshot(list, content.digest(), &describe(&findings))
                .await?;
            return Err(SyncError::Refused {
                list,
                digest: content.digest().to_owned(),
                findings,
            });
        }

        let record = self
            .promote(PromotionRequest {
                promotion_id: Uuid::new_v4(),
                list,
                digest: content.digest().to_owned(),
                expected_previous: current.content_digest.clone(),
                promoted_by: sanctions_list::SCHEDULED.to_owned(),
                promoted_at: fetched_at,
                synced_at: fetched_at,
                source: source_name,
                validators,
            })
            .await?;
        Ok(SyncReport {
            list,
            outcome: SyncOutcome::Promoted(record),
            effects_resumed,
        })
    }

    /// Confirm the current version — after checking the live rows still equal
    /// it. If they do not, re-promote it: a confirmation must never stamp a
    /// list fresh while screening reads something else.
    async fn confirm_or_reconcile(
        &self,
        list: SanctionsList,
        digest: &str,
        fetched_at: DateTime<Utc>,
        source: &str,
        validators: &Validators,
        not_modified: bool,
    ) -> Result<SyncOutcome, SyncError> {
        let live = self.store.live_content(list).await?;
        if live.digest() != digest {
            tracing::warn!(
                list = %list,
                expected = digest,
                live = live.digest(),
                "live sanctions rows drifted from the current version; reconciling"
            );
            let record = self
                .promote(PromotionRequest {
                    promotion_id: Uuid::new_v4(),
                    list,
                    digest: digest.to_owned(),
                    expected_previous: Some(digest.to_owned()),
                    promoted_by: sanctions_list::RECONCILE.to_owned(),
                    promoted_at: fetched_at,
                    synced_at: fetched_at,
                    source: source.to_owned(),
                    validators: validators.clone(),
                })
                .await?;
            return Ok(SyncOutcome::Reconciled(record));
        }
        let confirmed = self
            .store
            .confirm_unchanged(&Confirmation {
                list,
                digest,
                synced_at: fetched_at,
                source,
                validators,
            })
            .await?;
        if !confirmed {
            return Err(SyncError::Conflict {
                list,
                current: self.store.list_sync(list).await?.content_digest,
            });
        }
        Ok(SyncOutcome::Unchanged {
            digest: digest.to_owned(),
            entries: live.entries(),
            not_modified,
        })
    }

    /// Promote a staged snapshot by hand, after an operator checked upstream
    /// that what the checks flagged is real (a mass delisting, a large
    /// designation round). Overrides every overridable finding; an empty list
    /// is never promotable. Not recorded as a sync failure if it fails: it is
    /// an operator action, not an attempt of the scheduled sync.
    #[tracing::instrument(skip(self), fields(list = %list))]
    pub async fn promote_staged(
        &self,
        list: SanctionsList,
        digest: &str,
        operator: &str,
    ) -> Result<SyncReport, SyncError> {
        let operator = operator.trim();
        if operator.is_empty()
            || operator == sanctions_list::SCHEDULED
            || operator == sanctions_list::RECONCILE
        {
            return Err(SyncError::Invalid(format!(
                "operator {operator:?} must name the person promoting the snapshot"
            )));
        }
        let effects_resumed = self.resume_effects(list).await?;
        let Some((summary, content)) = self.store.snapshot(list, digest).await? else {
            return Err(SyncError::UnknownSnapshot {
                list,
                digest: digest.to_owned(),
            });
        };
        let current = self.store.list_sync(list).await?;
        if current.content_digest.as_deref() == Some(digest) {
            return Err(SyncError::Invalid(format!(
                "{list} snapshot {digest} is already the current version"
            )));
        }
        let previous_entries = current.content_digest.as_ref().and(current.entries);
        let blocking: Vec<Finding> = self
            .policy
            .evaluate(list, previous_entries, &content)
            .into_iter()
            .filter(|finding| !finding.overridable())
            .collect();
        if !blocking.is_empty() {
            return Err(SyncError::Refused {
                list,
                digest: digest.to_owned(),
                findings: blocking,
            });
        }
        let promoted_at = self.store.db_now().await?;
        let record = self
            .promote(PromotionRequest {
                promotion_id: Uuid::new_v4(),
                list,
                digest: digest.to_owned(),
                expected_previous: current.content_digest,
                promoted_by: operator.to_owned(),
                promoted_at,
                // The operator vouches for the content as of its last fetch.
                synced_at: summary.last_fetched_at,
                source: summary.source,
                validators: Validators::default(),
            })
            .await?;
        Ok(SyncReport {
            list,
            outcome: SyncOutcome::Promoted(record),
            effects_resumed,
        })
    }

    /// Promote, then run the promotion's effects.
    async fn promote(&self, request: PromotionRequest) -> Result<PromotionRecord, SyncError> {
        let list = request.list;
        let record = match self.store.promote(&request).await? {
            PromotionOutcome::Promoted(record) => record,
            PromotionOutcome::Conflict { current } => {
                return Err(SyncError::Conflict { list, current });
            }
            PromotionOutcome::UnknownSnapshot => {
                return Err(SyncError::UnknownSnapshot {
                    list,
                    digest: request.digest,
                });
            }
        };
        tracing::info!(
            list = %list,
            digest = %record.digest,
            added = record.added.len(),
            removed = record.removed.len(),
            changed = record.changed.len(),
            promoted_by = %record.promoted_by,
            "sanctions list promoted"
        );
        self.apply_effects(&record).await?;
        Ok(record)
    }

    /// Finish the post-commit effects of every earlier promotion of `list`
    /// that did not complete them. Returns how many it finished.
    async fn resume_effects(&self, list: SanctionsList) -> Result<usize, SyncError> {
        let pending = self.store.pending_promotions(list).await?;
        for promotion in &pending {
            tracing::warn!(
                promotion_id = %promotion.promotion_id,
                "resuming unfinished effects of an earlier sanctions promotion"
            );
            self.apply_effects(promotion).await?;
        }
        Ok(pending.len())
    }

    /// The promotion's effects outside Postgres's transaction, each
    /// idempotent: seed the canonical `SanctionedEntity` label for every
    /// newly designated address (deterministic ids), revoke it for every
    /// delisted one, evict every touched address from the hot cache, then
    /// mark the promotion done.
    async fn apply_effects(&self, promotion: &PromotionRecord) -> Result<(), SyncError> {
        let list = promotion.list;
        let labels: Vec<_> = promotion
            .added
            .iter()
            .map(|address| list.label(*address, promotion.promoted_at))
            .collect();
        self.labels.add_labels(&labels).await?;
        let reason = format!(
            "delisted from {list} (promotion {})",
            promotion.promotion_id
        );
        for address in &promotion.removed {
            self.labels
                .revoke_label(list.label_id(address), &reason, promotion.promoted_at)
                .await?;
        }
        let touched: BTreeSet<AccountAddress> = promotion
            .added
            .iter()
            .chain(&promotion.changed)
            .chain(&promotion.removed)
            .copied()
            .collect();
        let touched: Vec<AccountAddress> = touched.into_iter().collect();
        self.cache.evict_many(&touched).await?;
        let at = self.store.db_now().await?;
        self.store
            .mark_effects_applied(promotion.promotion_id, at)
            .await?;
        Ok(())
    }
}

/// Cap a reason at [`MAX_REASON_CHARS`] characters (never mid-character).
fn truncate_reason(reason: &str) -> String {
    match reason.char_indices().nth(MAX_REASON_CHARS) {
        Some((cut, _)) => format!("{}…", &reason[..cut]),
        None => reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use crate::model::{LabelKind, LabelRecord, LabelSource, SnapshotStatus};
    use crate::sanctions_list::Announcement;
    use crate::store::SanctionsStore;
    use crate::test_util::{InMemoryHotCache, InMemoryIntelligenceStore};
    use alloy_primitives::Address;
    use events::DomainEvent;

    const OFAC: SanctionsList = SanctionsList::OfacSdn;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    fn list_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{}\n", addr(*b))).collect()
    }

    /// A source that answers from a script: a body, a 304, or an HTTP status.
    struct Scripted {
        answer: Result<Fetched, u16>,
        conditional_seen: Mutex<Option<Validators>>,
    }

    impl Scripted {
        fn body(text: String) -> Self {
            Self::with(Ok(Fetched::Body {
                text,
                validators: Validators {
                    etag: Some("\"v1\"".into()),
                    last_modified: None,
                },
            }))
        }
        fn with(answer: Result<Fetched, u16>) -> Self {
            Self {
                answer,
                conditional_seen: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl FeedSource for Scripted {
        fn describe(&self) -> String {
            "test:scripted".to_owned()
        }
        async fn fetch(&self, conditional: Option<&Validators>) -> Result<Fetched, FetchError> {
            *self.conditional_seen.lock().unwrap() = conditional.cloned();
            self.answer.clone().map_err(|status| FetchError::Status {
                source_name: self.describe(),
                status,
            })
        }
    }

    /// A hot cache that records evictions and can be told to fail.
    #[derive(Default)]
    struct RecordingCache {
        inner: InMemoryHotCache,
        evicted: Mutex<Vec<AccountAddress>>,
        failing: Mutex<bool>,
    }

    #[async_trait]
    impl HotCache for RecordingCache {
        async fn labels(
            &self,
            address: &AccountAddress,
        ) -> Result<Option<Vec<LabelRecord>>, CacheError> {
            self.inner.labels(address).await
        }
        async fn put_labels(
            &self,
            address: &AccountAddress,
            labels: &[LabelRecord],
        ) -> Result<(), CacheError> {
            self.inner.put_labels(address, labels).await
        }
        async fn score(
            &self,
            address: &AccountAddress,
            model_version: &str,
        ) -> Result<Option<crate::cache::CachedScore>, CacheError> {
            self.inner.score(address, model_version).await
        }
        async fn put_score(
            &self,
            address: &AccountAddress,
            score: &crate::cache::CachedScore,
        ) -> Result<(), CacheError> {
            self.inner.put_score(address, score).await
        }
        async fn screening_facts(
            &self,
            address: &AccountAddress,
        ) -> Result<Option<crate::cache::CachedScreeningFacts>, CacheError> {
            self.inner.screening_facts(address).await
        }
        async fn put_screening_facts(
            &self,
            address: &AccountAddress,
            facts: &crate::cache::CachedScreeningFacts,
        ) -> Result<(), CacheError> {
            self.inner.put_screening_facts(address, facts).await
        }
        async fn evict(&self, address: &AccountAddress) -> Result<(), CacheError> {
            if *self.failing.lock().unwrap() {
                return Err(CacheError::Redis(redis::RedisError::from((
                    redis::ErrorKind::Io,
                    "scripted outage",
                ))));
            }
            self.evicted.lock().unwrap().push(*address);
            self.inner.evict(address).await
        }
    }

    struct Harness {
        sync: SanctionsSync,
        store: Arc<InMemoryIntelligenceStore>,
        cache: Arc<RecordingCache>,
    }

    fn harness() -> Harness {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        store.set_now(at(100));
        let cache = Arc::new(RecordingCache::default());
        let policy = SnapshotPolicy::new(20, 100, 5, HashMap::new()).unwrap();
        let sync = SanctionsSync::new(store.clone(), store.clone(), cache.clone(), policy);
        Harness { sync, store, cache }
    }

    fn list_updates(outbox: &[Announcement]) -> Vec<events::intelligence::SanctionsListUpdated> {
        outbox
            .iter()
            .filter_map(|a| match &a.event {
                DomainEvent::SanctionsListUpdated(u) => Some(u.clone()),
                _ => None,
            })
            .collect()
    }

    fn hits(outbox: &[Announcement]) -> Vec<AccountAddress> {
        outbox
            .iter()
            .filter_map(|a| match &a.event {
                DomainEvent::SanctionHit(h) => Some(h.address),
                _ => None,
            })
            .collect()
    }

    async fn is_designated(store: &InMemoryIntelligenceStore, byte: u8) -> bool {
        !store
            .sanction_matches(&addr(byte))
            .await
            .unwrap()
            .is_empty()
    }

    // ── First sync / unchanged ──────────────────────────────────

    #[tokio::test]
    async fn a_first_sync_promotes_and_runs_its_effects() {
        let h = harness();
        let report = h
            .sync
            .sync(OFAC, &Scripted::body(list_of(&[1, 2, 3])))
            .await
            .unwrap();
        let SyncOutcome::Promoted(p) = &report.outcome else {
            panic!("expected a promotion, got {report}");
        };
        assert_eq!(p.entries, 3);
        assert_eq!(p.added.len(), 3);
        assert_eq!(p.previous_digest, None);
        assert_eq!(p.promoted_by, sanctions_list::SCHEDULED);

        let row = h.store.list_sync(OFAC).await.unwrap();
        assert_eq!(row.synced_at, Some(at(100)));
        assert_eq!(row.content_changed_at, Some(at(100)));
        assert_eq!(row.content_digest.as_deref(), Some(p.digest.as_str()));
        assert_eq!(row.validators.etag.as_deref(), Some("\"v1\""));
        assert!(!row.effects_pending);
        assert!(is_designated(&h.store, 2).await);

        // Effects: labels seeded, cache evicted, promotion marked done.
        let labels = h.store.labels_for(&addr(2), at(200)).await.unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].kind, LabelKind::SanctionedEntity);
        assert_eq!(labels[0].label_id, OFAC.label_id(&addr(2)));
        assert_eq!(h.cache.evicted.lock().unwrap().len(), 3);
        assert!(h.store.pending_promotions(OFAC).await.unwrap().is_empty());

        // Announced once, in one chunk.
        let updates = list_updates(&h.store.sanctions_outbox());
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].added_total, 3);
    }

    /// Confirming an unchanged list is still a sync: freshness advances, the
    /// content clock and the live rows do not move, nothing is announced.
    #[tokio::test]
    async fn an_unchanged_list_is_confirmed_not_re_promoted() {
        let h = harness();
        let source = Scripted::body(list_of(&[1, 2]));
        h.sync.sync(OFAC, &source).await.unwrap();
        h.store.set_now(at(200));
        let report = h.sync.sync(OFAC, &source).await.unwrap();
        assert!(matches!(
            report.outcome,
            SyncOutcome::Unchanged {
                entries: 2,
                not_modified: false,
                ..
            }
        ));
        let row = h.store.list_sync(OFAC).await.unwrap();
        assert_eq!(row.synced_at, Some(at(200)));
        assert_eq!(row.content_changed_at, Some(at(100)));
        assert_eq!(h.store.promotions(OFAC, 10).await.unwrap().len(), 1);
        assert_eq!(h.store.sanctions_outbox().len(), 1);
    }

    /// With validators on record the fetch is conditional, and a 304
    /// confirms without downloading.
    #[tokio::test]
    async fn a_304_confirms_the_current_version() {
        let h = harness();
        h.sync
            .sync(OFAC, &Scripted::body(list_of(&[1])))
            .await
            .unwrap();
        h.store.set_now(at(300));
        let source = Scripted::with(Ok(Fetched::NotModified));
        let report = h.sync.sync(OFAC, &source).await.unwrap();
        assert!(matches!(
            report.outcome,
            SyncOutcome::Unchanged {
                not_modified: true,
                ..
            }
        ));
        let sent = source.conditional_seen.lock().unwrap().clone();
        assert_eq!(sent.and_then(|v| v.etag).as_deref(), Some("\"v1\""));
        assert_eq!(
            h.store.list_sync(OFAC).await.unwrap().synced_at,
            Some(at(300))
        );
    }

    /// Drift between the live rows and the current version is repaired, not
    /// stamped fresh.
    #[tokio::test]
    async fn drifted_live_rows_are_reconciled() {
        let h = harness();
        let source = Scripted::body(list_of(&[1, 2]));
        h.sync.sync(OFAC, &source).await.unwrap();
        h.store.corrupt_live_sanctions(OFAC);
        assert!(!is_designated(&h.store, 1).await);

        let report = h.sync.sync(OFAC, &source).await.unwrap();
        let SyncOutcome::Reconciled(p) = &report.outcome else {
            panic!("expected a reconcile, got {report}");
        };
        assert_eq!(p.promoted_by, sanctions_list::RECONCILE);
        assert_eq!(p.added.len(), 2);
        assert!(is_designated(&h.store, 1).await);
    }

    // ── Changes ─────────────────────────────────────────────────

    /// Delisting is modelled: the rows go, the label is revoked, and the
    /// announcement carries the removal.
    #[tokio::test]
    async fn a_delisting_removes_rows_revokes_labels_and_announces() {
        let h = harness();
        h.sync
            .sync(OFAC, &Scripted::body(list_of(&[1, 2, 3, 4, 5])))
            .await
            .unwrap();
        h.store.set_now(at(200));
        let report = h
            .sync
            .sync(OFAC, &Scripted::body(list_of(&[1, 2, 3, 4])))
            .await
            .unwrap();
        let SyncOutcome::Promoted(p) = &report.outcome else {
            panic!("expected a promotion");
        };
        assert_eq!(p.removed, vec![addr(5)]);
        assert!(!is_designated(&h.store, 5).await);
        assert!(h
            .store
            .labels_for(&addr(5), at(300))
            .await
            .unwrap()
            .is_empty());
        let updates = list_updates(&h.store.sanctions_outbox());
        let last = updates.last().unwrap();
        assert_eq!(last.removed, vec![addr(5)]);
        assert_eq!(
            last.previous_digest.as_deref(),
            Some(updates[0].digest.as_str())
        );
    }

    /// §8.5: a newly designated address we already knew raises `SanctionHit`
    /// at promotion time; one known only through another list does not.
    #[tokio::test]
    async fn newly_designated_known_addresses_raise_a_hit() {
        let h = harness();
        h.store
            .add_label(&LabelRecord::new(
                addr(7),
                LabelKind::MevBot,
                "bot",
                LabelSource::Heuristic,
                "test",
                at(1),
            ))
            .await
            .unwrap();
        h.store
            .add_label(&SanctionsList::EuConsolidated.label(addr(8), at(1)))
            .await
            .unwrap();
        h.sync
            .sync(OFAC, &Scripted::body(list_of(&[7, 8, 9])))
            .await
            .unwrap();
        assert_eq!(hits(&h.store.sanctions_outbox()), vec![addr(7)]);
    }

    // ── Refusals and the operator path ──────────────────────────

    #[tokio::test]
    async fn a_sharp_growth_is_staged_refused_and_recorded() {
        let h = harness();
        h.sync
            .sync(OFAC, &Scripted::body(list_of(&[1, 2])))
            .await
            .unwrap();
        h.store.set_now(at(200));
        let grown: Vec<u8> = (1..=20).collect();
        let err = h
            .sync
            .sync(OFAC, &Scripted::body(list_of(&grown)))
            .await
            .unwrap_err();
        let SyncError::Refused {
            digest, findings, ..
        } = &err
        else {
            panic!("expected a refusal, got {err}");
        };
        assert!(matches!(findings[..], [Finding::Grew { .. }]));
        assert_eq!(err.exit_code(), EXIT_REFUSED);

        // Nothing reached the live table; the snapshot waits, refused.
        assert!(!is_designated(&h.store, 20).await);
        let (summary, _) = h.store.snapshot(OFAC, digest).await.unwrap().unwrap();
        assert_eq!(summary.status, SnapshotStatus::Refused);
        let row = h.store.list_sync(OFAC).await.unwrap();
        assert!(row.last_attempt_failed());
        assert!(row
            .failure_reason
            .as_deref()
            .unwrap()
            .contains("grew from 2 to 20"));
        assert_eq!(row.synced_at, Some(at(100)));
    }

    #[tokio::test]
    async fn an_operator_promotes_exactly_the_refused_snapshot() {
        let h = harness();
        h.sync
            .sync(OFAC, &Scripted::body(list_of(&[1, 2, 3, 4, 5])))
            .await
            .unwrap();
        h.store.set_now(at(200));
        let SyncError::Refused { digest, .. } = h
            .sync
            .sync(OFAC, &Scripted::body(list_of(&[1])))
            .await
            .unwrap_err()
        else {
            panic!("the shrink is refused");
        };

        assert!(matches!(
            h.sync.promote_staged(OFAC, &digest, " ").await,
            Err(SyncError::Invalid(_))
        ));
        assert!(matches!(
            h.sync.promote_staged(OFAC, "nope", "alice").await,
            Err(SyncError::UnknownSnapshot { .. })
        ));

        h.store.set_now(at(300));
        let report = h.sync.promote_staged(OFAC, &digest, "alice").await.unwrap();
        let SyncOutcome::Promoted(p) = &report.outcome else {
            panic!("expected a promotion");
        };
        assert_eq!(p.promoted_by, "alice");
        assert_eq!(p.removed.len(), 4);
        let row = h.store.list_sync(OFAC).await.unwrap();
        assert_eq!(row.content_digest.as_deref(), Some(digest.as_str()));
        // Vouched as of the snapshot's fetch, not the promotion.
        assert_eq!(row.synced_at, Some(at(200)));
        assert_eq!(row.content_changed_at, Some(at(300)));
        assert!(!row.last_attempt_failed());
    }

    #[tokio::test]
    async fn an_empty_list_is_never_promotable() {
        let h = harness();
        let err = h
            .sync
            .sync(OFAC, &Scripted::body("# nothing here\n".into()))
            .await
            .unwrap_err();
        let SyncError::Refused { digest, .. } = &err else {
            panic!("expected a refusal");
        };
        assert!(matches!(
            h.sync.promote_staged(OFAC, digest, "alice").await,
            Err(SyncError::Refused { .. })
        ));
    }

    // ── Failures ────────────────────────────────────────────────

    #[tokio::test]
    async fn a_failed_fetch_is_recorded_classified_and_the_clock_stays() {
        let h = harness();
        h.sync
            .sync(OFAC, &Scripted::body(list_of(&[1])))
            .await
            .unwrap();
        h.store.set_now(at(200));
        let err = h
            .sync
            .sync(OFAC, &Scripted::with(Err(503)))
            .await
            .unwrap_err();
        assert!(err.is_transient());
        assert_eq!(err.exit_code(), EXIT_TRANSIENT);
        let row = h.store.list_sync(OFAC).await.unwrap();
        assert_eq!(row.synced_at, Some(at(100)));
        assert_eq!(row.failed_at, Some(at(200)));

        let err = h
            .sync
            .sync(OFAC, &Scripted::with(Err(404)))
            .await
            .unwrap_err();
        assert!(!err.is_transient());
        assert_eq!(err.exit_code(), EXIT_PERMANENT);
    }

    /// An HTML error page served as 200 fails the parser, permanently.
    #[tokio::test]
    async fn a_garbage_body_is_a_permanent_recorded_failure() {
        let h = harness();
        let err = h
            .sync
            .sync(
                OFAC,
                &Scripted::body("<!DOCTYPE html><title>rate limited</title>\n".into()),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SyncError::Parse(_)));
        assert_eq!(err.exit_code(), EXIT_PERMANENT);
        assert!(h.store.list_sync(OFAC).await.unwrap().last_attempt_failed());
    }

    /// A promotion commits before its effects; if they fail, the promotion is
    /// left pending and the next run finishes it first.
    #[tokio::test]
    async fn unfinished_effects_are_resumed_by_the_next_run() {
        let h = harness();
        *h.cache.failing.lock().unwrap() = true;
        let err = h
            .sync
            .sync(OFAC, &Scripted::body(list_of(&[1, 2])))
            .await
            .unwrap_err();
        assert!(matches!(err, SyncError::Cache(_)));
        assert!(err.is_transient());
        // The promotion itself committed: screening already sees the rows.
        assert!(is_designated(&h.store, 1).await);
        assert!(h.store.list_sync(OFAC).await.unwrap().effects_pending);

        *h.cache.failing.lock().unwrap() = false;
        let report = h
            .sync
            .sync(OFAC, &Scripted::body(list_of(&[1, 2])))
            .await
            .unwrap();
        assert_eq!(report.effects_resumed, 1);
        assert!(!h.store.list_sync(OFAC).await.unwrap().effects_pending);
    }

    /// Each list has its own clock: one failing does not age the other.
    #[tokio::test]
    async fn lists_are_tracked_independently() {
        let h = harness();
        h.sync
            .sync(OFAC, &Scripted::body(list_of(&[1])))
            .await
            .unwrap();
        h.sync
            .sync(SanctionsList::EuConsolidated, &Scripted::with(Err(503)))
            .await
            .unwrap_err();
        let ofac = h.store.list_sync(OFAC).await.unwrap();
        let eu = h
            .store
            .list_sync(SanctionsList::EuConsolidated)
            .await
            .unwrap();
        assert!(!ofac.last_attempt_failed());
        assert!(eu.last_attempt_failed());
        assert_eq!(eu.synced_at, None);
    }

    /// A promotion decided against a version that has since been replaced
    /// writes nothing, and the sync classifies the conflict as retryable.
    #[tokio::test]
    async fn a_stale_promotion_conflicts() {
        let h = harness();
        h.sync
            .sync(OFAC, &Scripted::body(list_of(&[1])))
            .await
            .unwrap();
        let content = ListContent::new([Designation {
            address: addr(9),
            entry: "e".into(),
        }]);
        h.store
            .stage_snapshot(&StagedSnapshot {
                list: OFAC,
                content: &content,
                source: "s",
                fetched_at: at(150),
            })
            .await
            .unwrap();
        let outcome = h
            .store
            .promote(&PromotionRequest {
                promotion_id: Uuid::new_v4(),
                list: OFAC,
                digest: content.digest().to_owned(),
                expected_previous: None,
                promoted_by: "alice".into(),
                promoted_at: at(150),
                synced_at: at(150),
                source: "s".into(),
                validators: Validators::default(),
            })
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            PromotionOutcome::Conflict { current: Some(_) }
        ));
        assert!(!is_designated(&h.store, 9).await);
        assert!(SyncError::Conflict {
            list: OFAC,
            current: None
        }
        .is_transient());
    }

    // ── Sources ─────────────────────────────────────────────────

    #[test]
    fn urls_are_recorded_without_credentials() {
        let url: Url = "https://user:pw@example.org/list.txt?token=secret#frag"
            .parse()
            .unwrap();
        assert_eq!(redacted_url(&url), "https://example.org/list.txt");
    }

    #[test]
    fn reasons_are_capped_on_a_character_boundary() {
        let long = "é".repeat(MAX_REASON_CHARS + 5);
        let cut = truncate_reason(&long);
        assert_eq!(cut.chars().count(), MAX_REASON_CHARS + 1);
        assert_eq!(truncate_reason("short"), "short");
    }

    #[test]
    fn fetch_failures_classify_by_whether_they_can_clear() {
        let status = |status| FetchError::Status {
            source_name: "s".into(),
            status,
        };
        assert!(status(503).is_transient());
        assert!(status(429).is_transient());
        assert!(!status(404).is_transient());
        assert!(!status(401).is_transient());
    }

    #[tokio::test]
    async fn a_file_source_enforces_its_cap() {
        let dir = std::env::temp_dir().join(format!("sanctions-sync-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("list.txt");
        std::fs::write(&path, list_of(&[1, 2])).unwrap();

        let Fetched::Body { text, validators } =
            FileFeedSource::new(&path, 1_000).fetch(None).await.unwrap()
        else {
            panic!("a file is never 304");
        };
        assert_eq!(text.lines().count(), 2);
        assert!(validators.is_empty());
        let err = FileFeedSource::new(&path, 10)
            .fetch(None)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::TooLarge { limit: 10, .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
