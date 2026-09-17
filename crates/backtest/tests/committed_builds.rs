//! The committed measurement files name the builds this tree actually links
//! (§18, Epic E).
//!
//! `baseline.json` and `model_performance.json` key every number on
//! `(id, version, config_hash)`. `just backtest` already refuses a stale
//! baseline (`REBUILT`), and the detection service exports
//! `detector_performance_stale` for a stale card at boot — but by then the
//! stale file has shipped (it is compiled into the binary). This test is the
//! merge-time gate for both: changing a detector's version or config without
//! regenerating them fails here, with the command that fixes it.

use std::collections::BTreeMap;

use detection::{Build, BuildKeyed, Lookup};

const FIX: &str = "run `just backtest-update-baseline` and review the diff";

fn linked() -> BTreeMap<String, Build> {
    backtest::boot()
        .expect("the built-in roster links cleanly")
        .builds()
        .clone()
}

/// Every entry in `store` must be `Current` for the build this tree links.
fn assert_names_linked_builds<T>(file: &str, store: &BuildKeyed<T>) {
    let builds = linked();
    assert!(!store.is_empty(), "{file} is empty");
    for (id, entry) in store.iter() {
        let running = builds
            .get(id)
            .unwrap_or_else(|| panic!("{file} has {id}, which this tree does not link; {FIX}"));
        match store.lookup(running) {
            Lookup::Current(_) => {}
            Lookup::Stale { measured } => {
                panic!("{file} measured {id} as {measured}, but this tree links {running}; {FIX}")
            }
            Lookup::Missing => unreachable!("{id} came from this store: {:?}", entry.version),
        }
    }
}

#[test]
fn every_baseline_entry_names_the_linked_build() {
    let baseline = backtest::baseline::load(&backtest::baseline::default_path())
        .expect("the committed baseline loads");
    assert_names_linked_builds("baseline.json", &baseline);
}

#[test]
fn every_model_card_record_names_the_linked_build() {
    // The embedded copy is what a deployed binary reads.
    let store = detection::committed_performance_store()
        .expect("the committed model performance store parses");
    assert_names_linked_builds("model_performance.json", &store);
}

#[test]
fn every_linked_config_hash_is_distinct() {
    // `for_build` hashes the id in, so two detectors can never share a
    // triple's hash even with identical configs. A collision here would mean
    // the hash stopped covering what it claims to.
    let mut seen = std::collections::BTreeSet::new();
    for build in linked().values() {
        assert!(
            seen.insert(build.config_hash.clone()),
            "{} shares a config hash with another detector",
            build.id
        );
    }
}
