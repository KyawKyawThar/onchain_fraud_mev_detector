//! The grounding boundary (§20.4) — the check that turns a plausible
//! narrative into a *checkable* one.
//!
//! § 20.4 asks for one thing above all others from an incident narrative:
//! **every factual claim carries the event ids it derives from**, so a
//! reviewer verifies the draft against the event store rather than against the
//! model. This module is where that stops being an instruction in a prompt and
//! becomes a property of the stored draft.
//!
//! # The three questions it answers
//!
//! 1. **What did the narrative actually cite?** The prompt asks for inline
//!    `[uuid, uuid]` citations; [`parse`] reads them back out and pairs each
//!    with the sentence it belongs to. The union of those ids is the draft's
//!    real `grounded_event_ids` — narrowed from "the window the model was
//!    shown" (what t2 recorded) to "what the text stands on".
//! 2. **Does every citation resolve?** An id the model cites that was *not* in
//!    the window is a fabricated reference: the most dangerous possible output
//!    here, because it looks exactly like a verifiable claim until someone
//!    tries to look it up. Those are counted, listed, and — by default —
//!    disqualifying.
//! 3. **Is enough of it cited at all?** A narrative of confident, uncited
//!    prose is the failure mode the whole feature exists to prevent.
//!
//! # This is the narrative's parse boundary
//!
//! §20.4's hallucination-safety argument for *rules* is that a drafted rule
//! must compile through the rule engine's parser before it can run. A
//! narrative has no compiler, and "a human reads it" is a boundary that
//! degrades with queue depth. So the analogue is mechanical: a draft whose
//! citations do not check out never reaches a reviewer as
//! [`DraftStatus::Ready`](crate::model::DraftStatus::Ready) — it lands
//! `blocked`, terminal and billed, exactly like a refusal. Both are the same
//! statement: *the model answered, and the answer is not usable.*
//!
//! # Why the threshold is not 1.0
//!
//! Because the prompt itself requires uncitable sentences. Rule 2 tells the
//! model to say plainly when the record does *not* establish something ("the
//! source of funds is not determinable from the recorded events") — a claim
//! about the absence of evidence, which by construction has no event to cite.
//! Section headings and framing sentences are the same. A 100% requirement
//! would therefore reject the drafts that follow the instructions most
//! carefully, which is how a safety gate becomes something an operator turns
//! off. The default asks that a *majority* of claims be cited and that
//! *nothing* be cited falsely — the second half being the one that is
//! absolute.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Default share of a narrative's claims that must carry a citation.
///
/// See the module docs for why this is not 1.0.
pub const DEFAULT_MIN_CITED_RATIO: f64 = 0.5;

/// Minimum words in a segment for it to count as a *claim*.
///
/// Headings ("Narrative", "Background"), list bullets and one-word fragments
/// are not assertions about the incident, and counting them as uncited claims
/// would penalise a well-structured document for being well structured.
const MIN_CLAIM_WORDS: usize = 4;

/// One asserted sentence and the events it cites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub text: String,
    pub event_ids: Vec<Uuid>,
}

impl Claim {
    pub fn is_cited(&self) -> bool {
        !self.event_ids.is_empty()
    }
}

/// What a narrative's citations amount to, once checked against the window the
/// model was shown.
///
/// Stored on the draft (as JSON) and carried into `IncidentNarrativeDrafted`,
/// because "6 claims, 5 cited, 0 fabricated" is the reviewer's triage signal
/// and the auditor's evidence that the check ran at all. The claim *texts* are
/// deliberately not stored: they are the body, verbatim, and a second copy
/// would be one more thing that can disagree with it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GroundingSummary {
    /// Sentences that assert something about the incident.
    pub claims: usize,
    /// How many of them carry at least one citation.
    pub cited_claims: usize,
    /// The distinct event ids the narrative cites **and** that were in the
    /// window — the draft's narrowed `grounded_event_ids`, in the order the
    /// model was shown them.
    pub cited_event_ids: Vec<Uuid>,
    /// Cited ids that were *not* in the window. Non-empty means the model
    /// invented a reference; the ids are kept because "which one" is the first
    /// question anyone asks.
    pub unknown_event_ids: Vec<Uuid>,
}

impl GroundingSummary {
    /// Share of claims carrying a citation. An empty narrative scores `0.0` —
    /// nothing is grounded by having said nothing.
    pub fn cited_ratio(&self) -> f64 {
        if self.claims == 0 {
            return 0.0;
        }
        self.cited_claims as f64 / self.claims as f64
    }

    pub fn uncited_claims(&self) -> usize {
        self.claims.saturating_sub(self.cited_claims)
    }
}

/// How strictly a narrative is held to its citations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GroundingPolicy {
    /// Minimum share of claims that must be cited.
    pub min_cited_ratio: f64,
    /// Whether a citation that does not resolve in the shown window
    /// disqualifies the draft. Default `true`, and it should stay that way:
    /// an unresolvable id is not a weaker claim, it is a false one.
    pub reject_unknown: bool,
    /// Whether the check is enforced at all. `false` records the summary and
    /// lets the draft through — a deliberate escape hatch for a deployment
    /// tuning the threshold against real traffic, never a default.
    pub enforced: bool,
}

impl Default for GroundingPolicy {
    fn default() -> Self {
        Self {
            min_cited_ratio: DEFAULT_MIN_CITED_RATIO,
            reject_unknown: true,
            enforced: true,
        }
    }
}

/// Why a narrative failed its grounding check.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum GroundingFailure {
    /// The model produced no assertion at all — an empty or non-narrative
    /// answer that would otherwise sit in a reviewer's queue as "ready".
    #[error("the draft makes no citable claim")]
    NoClaims,
    /// Too much of it is uncited.
    #[error(
        "only {cited} of {claims} claims cite an event ({ratio:.0}% < the required {required:.0}%)"
    )]
    Uncited {
        cited: usize,
        claims: usize,
        ratio: f64,
        required: f64,
    },
    /// The narrative cited events it was never shown.
    #[error("the draft cites {} event id(s) that are not in its audit window: {}", ids.len(), render_ids(ids))]
    Fabricated { ids: Vec<Uuid> },
}

impl GroundingFailure {
    /// A short, closed label for metrics (§19) — the open-ended detail stays
    /// in the message written to the draft's `last_error`.
    pub fn reason(&self) -> &'static str {
        match self {
            GroundingFailure::NoClaims => "no_claims",
            GroundingFailure::Uncited { .. } => "uncited",
            GroundingFailure::Fabricated { .. } => "fabricated",
        }
    }
}

fn render_ids(ids: &[Uuid]) -> String {
    ids.iter()
        .take(5)
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Read a narrative's claims and citations, checked against `window` — the
/// event ids the model was actually shown.
///
/// Pure and synchronous: the whole check is a function of the text and the
/// window, which is what lets it run identically in the worker's write, in the
/// cross-pod cache's write, and in a test with no store at all.
pub fn evaluate(text: &str, window: &[Uuid]) -> GroundingSummary {
    let shown: BTreeSet<Uuid> = window.iter().copied().collect();
    let claims = parse(text);

    let cited: BTreeSet<Uuid> = claims
        .iter()
        .flat_map(|claim| claim.event_ids.iter().copied())
        .collect();

    // Ordered by the window, not by the citation order: a reviewer reads the
    // grounded ids against the audit stream, which is chronological. Ids we
    // never showed cannot be placed in that order, so they are listed
    // separately — which is also exactly the distinction the policy cares
    // about.
    let cited_event_ids: Vec<Uuid> = window
        .iter()
        .copied()
        .filter(|id| cited.contains(id))
        .collect();
    let unknown_event_ids: Vec<Uuid> = cited
        .iter()
        .copied()
        .filter(|id| !shown.contains(id))
        .collect();

    GroundingSummary {
        claims: claims.len(),
        cited_claims: claims.iter().filter(|claim| claim.is_cited()).count(),
        cited_event_ids,
        unknown_event_ids,
    }
}

/// Apply `policy` to a summary.
pub fn verdict(
    summary: &GroundingSummary,
    policy: &GroundingPolicy,
) -> Result<(), GroundingFailure> {
    if !policy.enforced {
        return Ok(());
    }
    if policy.reject_unknown && !summary.unknown_event_ids.is_empty() {
        return Err(GroundingFailure::Fabricated {
            ids: summary.unknown_event_ids.clone(),
        });
    }
    if summary.claims == 0 {
        return Err(GroundingFailure::NoClaims);
    }
    let ratio = summary.cited_ratio();
    if ratio < policy.min_cited_ratio {
        return Err(GroundingFailure::Uncited {
            cited: summary.cited_claims,
            claims: summary.claims,
            ratio: ratio * 100.0,
            required: policy.min_cited_ratio * 100.0,
        });
    }
    Ok(())
}

/// Split a narrative into claims, each carrying the event ids cited inside it.
///
/// The segmentation is deliberately simple — sentence terminators and line
/// breaks — and deliberately *not* a natural-language parser. Two consequences
/// are worth stating rather than discovering:
///
/// * a decimal (`$10.5M`, `0.5 ETH`) does not end a sentence, because a split
///   there would manufacture uncited fragments out of every monetary figure —
///   which, in this domain, is most sentences;
/// * an abbreviation that ends in a period will over-split. That costs a claim
///   its citation only if the citation sits in the tail half, and the failure
///   direction is conservative: it makes the draft look *less* grounded than
///   it is, which is the right way for a safety check to be wrong.
pub fn parse(text: &str) -> Vec<Claim> {
    segments(text)
        .into_iter()
        .filter_map(|segment| {
            let trimmed = segment.trim();
            if word_count(trimmed) < MIN_CLAIM_WORDS {
                return None;
            }
            Some(Claim {
                event_ids: citations(trimmed),
                text: trimmed.to_owned(),
            })
        })
        .collect()
}

/// Break the text at sentence terminators and line breaks.
fn segments(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;

    for (i, &c) in chars.iter().enumerate() {
        match c {
            // A citation group may contain nothing that ends a sentence, so
            // brackets suspend splitting entirely.
            '[' => depth += 1,
            ']' => depth = (depth - 1).max(0),
            '\n' if depth == 0 => {
                out.push(chars[start..i].iter().collect());
                start = i + 1;
            }
            '.' | '!' | '?' if depth == 0 => {
                let prev = i.checked_sub(1).map(|p| chars[p]);
                let next = chars.get(i + 1).copied();
                let is_decimal = c == '.'
                    && prev.is_some_and(|p| p.is_ascii_digit())
                    && next.is_some_and(|n| n.is_ascii_digit());
                let ends_here = !is_decimal && next.is_none_or(|n| n.is_whitespace());
                if ends_here {
                    out.push(chars[start..=i].iter().collect());
                    start = i + 1;
                }
            }
            _ => {}
        }
    }
    if start < chars.len() {
        out.push(chars[start..].iter().collect());
    }
    out
}

/// Every UUID inside a `[...]` group in one segment.
///
/// Only bracketed ids count. A uuid that appears in running prose is the model
/// *mentioning* an id, not citing one, and treating the two the same would let
/// a narrative ground itself by quoting the event stream back at us.
fn citations(segment: &str) -> Vec<Uuid> {
    let mut ids = Vec::new();
    let mut rest = segment;
    while let Some(open) = rest.find('[') {
        let after = &rest[open + 1..];
        let Some(close) = after.find(']') else { break };
        for token in after[..close].split([',', ' ', ';', '\n', '\t']) {
            let token = token.trim().trim_matches(|c: char| c == '"' || c == '\'');
            if token.is_empty() {
                continue;
            }
            if let Ok(id) = Uuid::parse_str(token) {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
        rest = &after[close + 1..];
    }
    ids
}

/// Words in a segment, ignoring the citation groups — a sentence that is
/// nothing but a bracketed list of ids asserts nothing.
fn word_count(segment: &str) -> usize {
    let mut without_citations = String::with_capacity(segment.len());
    let mut depth = 0i32;
    for c in segment.chars() {
        match c {
            '[' => depth += 1,
            ']' => depth = (depth - 1).max(0),
            _ if depth == 0 => without_citations.push(c),
            _ => {}
        }
    }
    without_citations
        .split_whitespace()
        .filter(|word| word.chars().any(char::is_alphanumeric))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn narrative(ids: &[Uuid]) -> String {
        format!(
            "The attacker's transaction was placed immediately before the victim's swap [{}]. \
             The victim lost 12.5 ETH in the sandwich [{}]. \
             The record does not establish the source of the attacker's funds.",
            ids[0], ids[1]
        )
    }

    #[test]
    fn a_grounded_narrative_narrows_the_window_to_what_it_cites() {
        let window = vec![id(1), id(2), id(3)];
        let summary = evaluate(&narrative(&window), &window);

        assert_eq!(summary.claims, 3);
        assert_eq!(summary.cited_claims, 2);
        assert_eq!(
            summary.cited_event_ids,
            vec![id(1), id(2)],
            "the third window event was never cited, so it is not what the draft stands on"
        );
        assert!(summary.unknown_event_ids.is_empty());
        assert!(verdict(&summary, &GroundingPolicy::default()).is_ok());
    }

    /// The dangerous output: a citation that looks verifiable and is not.
    #[test]
    fn a_fabricated_citation_blocks_the_draft_by_default() {
        let window = vec![id(1)];
        let text = format!(
            "The attacker front-ran the victim's swap in the same block [{}]. \
             The attacker had been funded by a sanctioned entity three days earlier [{}].",
            id(1),
            id(0xDEAD),
        );
        let summary = evaluate(&text, &window);

        assert_eq!(summary.cited_event_ids, vec![id(1)]);
        assert_eq!(summary.unknown_event_ids, vec![id(0xDEAD)]);
        let err = verdict(&summary, &GroundingPolicy::default()).expect_err("must not be ready");
        assert!(matches!(err, GroundingFailure::Fabricated { .. }));
        assert_eq!(err.reason(), "fabricated");
        assert!(
            err.to_string().contains(&id(0xDEAD).to_string()),
            "the reviewer needs to know *which* id: {err}"
        );
    }

    #[test]
    fn confident_uncited_prose_is_refused() {
        let window = vec![id(1)];
        let text = "The attacker operated a coordinated sandwich campaign across many blocks. \
                    The victim was targeted deliberately over several days. \
                    The funds were laundered through a mixing service afterwards.";
        let summary = evaluate(text, &window);

        assert_eq!(summary.claims, 3);
        assert_eq!(summary.cited_claims, 0);
        let err = verdict(&summary, &GroundingPolicy::default()).expect_err("must not be ready");
        assert_eq!(err.reason(), "uncited");
    }

    /// The whole reason the threshold is not 1.0 (module docs): a draft that
    /// follows the prompt's "say what the record does not establish" rule must
    /// still pass.
    #[test]
    fn a_draft_that_admits_what_the_record_lacks_still_passes() {
        let window = vec![id(1), id(2)];
        let text = format!(
            "The two transactions were included in the same block [{}]. \
             The victim's swap executed at a worse price than quoted [{}]. \
             The record does not establish whether the victim was targeted deliberately. \
             The counterparty's identity is not determinable from the recorded events.",
            id(1),
            id(2)
        );
        let summary = evaluate(&text, &window);
        assert_eq!(summary.claims, 4);
        assert_eq!(summary.cited_claims, 2);
        assert_eq!(summary.cited_ratio(), 0.5);
        assert!(verdict(&summary, &GroundingPolicy::default()).is_ok());
    }

    #[test]
    fn an_empty_answer_is_never_ready() {
        let summary = evaluate("", &[id(1)]);
        assert_eq!(summary.claims, 0);
        assert_eq!(
            verdict(&summary, &GroundingPolicy::default()),
            Err(GroundingFailure::NoClaims)
        );
    }

    /// A monetary figure is not the end of a sentence. Splitting there would
    /// manufacture an uncited fragment out of nearly every claim this domain
    /// makes.
    #[test]
    fn a_decimal_does_not_end_a_claim() {
        let text = format!(
            "The attacker extracted 12.53 ETH, worth $41,204.90 at the time [{}].",
            id(1)
        );
        let claims = parse(&text);
        assert_eq!(claims.len(), 1, "{claims:#?}");
        assert!(claims[0].is_cited());
    }

    /// Only bracketed ids count as citations — otherwise a narrative could
    /// ground itself by quoting the stream back at us in prose.
    #[test]
    fn a_uuid_in_running_prose_is_not_a_citation() {
        let window = vec![id(1)];
        let text = format!(
            "The platform recorded the event {} while processing the block, per the operator.",
            id(1)
        );
        let summary = evaluate(&text, &window);
        assert_eq!(summary.claims, 1);
        assert_eq!(summary.cited_claims, 0);
        assert!(summary.cited_event_ids.is_empty());
    }

    #[test]
    fn a_citation_group_is_read_whole_and_deduplicated() {
        let text = format!(
            "Both transactions were signed by the same key [{}, {}, {}].",
            id(1),
            id(2),
            id(1)
        );
        let claims = parse(&text);
        assert_eq!(claims[0].event_ids, vec![id(1), id(2)]);
        // A line break inside a citation group must not split the claim.
        let wrapped = format!("The swap was sandwiched [{},\n{}].", id(1), id(2));
        assert_eq!(parse(&wrapped).len(), 1);
    }

    #[test]
    fn headings_and_bare_citation_lines_are_not_claims() {
        // A heading and a bare citation line assert nothing about the
        // incident. Counting them as *uncited claims* would penalise a
        // well-structured document for being well structured — and would push
        // the cited ratio below the threshold for reasons that have nothing to
        // do with grounding.
        let text = format!(
            "Narrative\n\nBackground\n[{}]\nThe attacker's transaction preceded the \
             victim's swap in the same block [{}].",
            id(1),
            id(1)
        );
        let claims = parse(&text);
        assert_eq!(claims.len(), 1, "{claims:#?}");
        assert!(claims[0].text.contains("attacker"));
        assert!(claims[0].is_cited());
    }

    /// The escape hatch exists and is off by default — a deployment tuning the
    /// threshold must be able to see what would have been rejected without
    /// rejecting it, and the summary is recorded either way.
    #[test]
    fn an_unenforced_policy_still_records_what_it_saw() {
        let window = vec![id(1)];
        let summary = evaluate("Wholly uncited prose about the incident.", &window);
        assert_eq!(summary.cited_claims, 0);
        assert!(verdict(
            &summary,
            &GroundingPolicy {
                enforced: false,
                ..GroundingPolicy::default()
            }
        )
        .is_ok());
    }
}
