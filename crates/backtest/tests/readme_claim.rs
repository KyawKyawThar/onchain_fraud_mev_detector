//! The README may not say more about false positives than the corpus supports
//! (§18; Hardening Epic E).
//!
//! The README once stated "< 4% false positives" as though it were measured,
//! over a corpus with one negative block. This test makes that a build
//! failure. Until [`claim::evaluate`] returns `Supported` over the committed
//! corpus:
//!
//! - the README's **Measured** row must not mention false positives at all;
//! - the README must name the target, using the same number as
//!   [`claim::ClaimPolicy::COMMITTED`], and call it a target.
//!
//! Once the verdict is `Supported`, the README may state the number as a
//! result. That is a deliberate edit, and this test stops forcing the
//! "target" wording.

use std::path::Path;

use backtest::claim;

fn readme() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn verdict() -> claim::ClaimReport {
    let roster = backtest::boot().expect("the built-in roster links cleanly");
    let corpus = backtest::load_corpus(&roster).expect("the committed corpus loads");
    claim::evaluate(
        &backtest::run_backtest(&corpus, &roster),
        &claim::ClaimPolicy::COMMITTED,
    )
}

/// The README's quoted target, e.g. `< 4%`.
fn target_text() -> String {
    format!("< {}%", claim::ClaimPolicy::COMMITTED.target * 100.0)
}

fn mentions_false_positives(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("false-positive") || lower.contains("false positive") || line.contains("FP")
}

#[test]
fn the_readme_does_not_claim_an_unsupported_false_positive_rate() {
    let claim = verdict();
    if claim.verdict.is_supported() {
        return;
    }
    let readme = readme();

    let measured = readme
        .lines()
        .find(|l| l.starts_with("| **Measured**"))
        .expect("the README keeps its Measured / Enforced / Not yet shown table");
    assert!(
        !mentions_false_positives(measured),
        "the README's Measured row mentions false positives, but the corpus does not support a \
         false-positive rate yet:\n{claim}"
    );

    let target = target_text();
    let stated = readme
        .lines()
        .filter(|l| mentions_false_positives(l))
        .find(|l| l.contains(&target));
    let stated = stated.unwrap_or_else(|| {
        panic!(
            "the README must name the false-positive target as `{target}` \
             (claim::ClaimPolicy::COMMITTED) — the number and the code must not drift apart"
        )
    });
    assert!(
        stated.to_lowercase().contains("target"),
        "the README states `{target}` without calling it a target, but the corpus does not \
         support it as a result yet:\n  {stated}\n{claim}"
    );
}

#[test]
fn the_target_is_formatted_the_way_the_readme_writes_it() {
    assert_eq!(target_text(), "< 4%");
}
