//! Every ClickHouse table in the workspace, replayed from the migrations that
//! create it.
//!
//! Restating a table's partition key in `model.json` would let the model and
//! the schema disagree, and the disagreement would favour whichever was edited
//! last. So the gate replays each crate's `migrations/` in apply order —
//! `CREATE TABLE … ENGINE`, `RENAME`, `EXCHANGE`, `DROP`, `ALTER … MODIFY TTL` —
//! and judges the tables that will actually exist.
//!
//! Two names are special, by the convention `ch_migrate::swap` owns: a table
//! created as `X__next` *is* the future `X` (the service swaps it in), and an
//! `X__retired` table is on its way out. The suffixes are restated here because
//! this crate is pinned off `ch-migrate`'s `clickhouse` dependency; a test reads
//! `ch-migrate`'s source to keep the two in step.
//!
//! Postgres migrations share some crates' `migrations/` directories. They are
//! ignored by construction: only a `CREATE TABLE` with an `ENGINE` defines a
//! ClickHouse table here.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::key::PartitionKey;

/// `ch_migrate::swap::STAGED_SUFFIX`.
pub const STAGED_SUFFIX: &str = "__next";
/// `ch_migrate::swap::RETIRED_SUFFIX`.
pub const RETIRED_SUFFIX: &str = "__retired";

/// One ClickHouse table as its migrations leave it.
#[derive(Debug, Clone, Serialize)]
pub struct TableDef {
    /// The crate whose migrations own it.
    pub owner: String,
    pub name: String,
    pub engine: String,
    pub key: PartitionKey,
    /// The delete TTL, in days from the table's time column, if it has one.
    pub ttl_days: Option<u32>,
    /// The migration that last defined it.
    pub source: String,
}

impl TableDef {
    /// `owner/name`, the table's identity across the workspace.
    pub fn id(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

/// Replay every crate under `crates_dir`.
pub fn replay_workspace(crates_dir: &Path) -> Result<Vec<TableDef>> {
    let mut crates: Vec<_> = std::fs::read_dir(crates_dir)
        .with_context(|| format!("reading {}", crates_dir.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    crates.sort_by_key(std::fs::DirEntry::file_name);
    let mut tables = Vec::new();
    for entry in crates {
        let migrations = entry.path().join("migrations");
        if !migrations.is_dir() {
            continue;
        }
        let mut files: Vec<_> = std::fs::read_dir(&migrations)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|f| f.path())
            .filter(|p| p.to_string_lossy().ends_with(".up.sql"))
            .collect();
        files.sort();
        let mut sql = Vec::with_capacity(files.len());
        for path in files {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            sql.push((name, std::fs::read_to_string(&path)?));
        }
        let owner = entry.file_name().to_string_lossy().into_owned();
        tables.extend(
            replay(&owner, &sql).with_context(|| format!("replaying {owner}'s migrations"))?,
        );
    }
    Ok(tables)
}

/// Replay one crate's migrations, given as `(file name, sql)` in apply order.
pub fn replay(owner: &str, migrations: &[(String, String)]) -> Result<Vec<TableDef>> {
    let mut tables: BTreeMap<String, TableDef> = BTreeMap::new();
    for (file, raw) in migrations {
        let sql = normalize(raw);
        if let Some(rest) = sql.strip_prefix("CREATE TABLE ") {
            if !sql.contains(" ENGINE") {
                continue; // Postgres
            }
            let rest = rest.strip_prefix("IF NOT EXISTS ").unwrap_or(rest);
            let name = unqualified(rest.split([' ', '(']).next().unwrap_or_default());
            let key = match clause(
                &sql,
                " PARTITION BY ",
                &[
                    " ORDER BY",
                    " PRIMARY KEY",
                    " SAMPLE BY",
                    " TTL ",
                    " SETTINGS",
                    " COMMENT",
                ],
            ) {
                Some(expression) => PartitionKey::parse(expression)
                    .with_context(|| format!("{file}: table {name}"))?,
                None => PartitionKey::unpartitioned(),
            };
            let engine = clause(
                &sql,
                " ENGINE = ",
                &[
                    " PARTITION BY",
                    " ORDER BY",
                    " PRIMARY KEY",
                    " TTL ",
                    " SETTINGS",
                ],
            )
            .unwrap_or_default()
            .to_owned();
            let ttl_days = clause(&sql, " TTL ", &[" SETTINGS", " COMMENT"]).and_then(delete_days);
            tables.insert(
                name.clone(),
                TableDef {
                    owner: owner.to_owned(),
                    name,
                    engine,
                    key,
                    ttl_days,
                    source: file.clone(),
                },
            );
        } else if let Some(rest) = sql.strip_prefix("RENAME TABLE ") {
            for pair in rest.split(',') {
                if let Some((from, to)) = pair.split_once(" TO ") {
                    let (from, to) = (unqualified(from.trim()), unqualified(to.trim()));
                    if let Some(mut def) = tables.remove(&from) {
                        def.name = to.clone();
                        tables.insert(to, def);
                    }
                }
            }
        } else if let Some(rest) = sql.strip_prefix("EXCHANGE TABLES ") {
            if let Some((a, b)) = rest.split_once(" AND ") {
                let (a, b) = (unqualified(a.trim()), unqualified(b.trim()));
                if let (Some(mut left), Some(mut right)) = (tables.remove(&a), tables.remove(&b)) {
                    left.name = b.clone();
                    right.name = a.clone();
                    tables.insert(b, left);
                    tables.insert(a, right);
                }
            }
        } else if let Some(rest) = sql.strip_prefix("DROP TABLE ") {
            let rest = rest.strip_prefix("IF EXISTS ").unwrap_or(rest);
            tables.remove(&unqualified(rest.split(' ').next().unwrap_or_default()));
        } else if let Some(rest) = sql.strip_prefix("ALTER TABLE ") {
            let name = unqualified(rest.split(' ').next().unwrap_or_default());
            if let (Some(def), Some(at)) = (tables.get_mut(&name), rest.find(" MODIFY TTL ")) {
                def.ttl_days = delete_days(&rest[at + " MODIFY TTL ".len()..]);
                def.source = file.clone();
            }
        }
    }

    // The swap convention: a staged table is the future live one; a retired
    // table is leaving and receives no inserts.
    let staged: Vec<String> = tables
        .keys()
        .filter(|name| name.ends_with(STAGED_SUFFIX))
        .cloned()
        .collect();
    for name in staged {
        if let Some(mut def) = tables.remove(&name) {
            let live = name.trim_end_matches(STAGED_SUFFIX).to_owned();
            def.name = live.clone();
            tables.insert(live, def);
        }
    }
    tables.retain(|name, _| !name.ends_with(RETIRED_SUFFIX));
    Ok(tables.into_values().collect())
}

/// One statement: comments stripped, whitespace collapsed to single spaces.
fn normalize(sql: &str) -> String {
    sql.lines()
        .map(|line| line.split("--").next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn unqualified(name: &str) -> String {
    name.rsplit('.')
        .next()
        .unwrap_or(name)
        .trim_matches('`')
        .to_owned()
}

/// The text after `marker` up to the earliest of `ends` (or the end).
fn clause<'a>(sql: &'a str, marker: &str, ends: &[&str]) -> Option<&'a str> {
    let start = sql.find(marker)? + marker.len();
    let tail = &sql[start..];
    let end = ends
        .iter()
        .filter_map(|e| tail.find(e))
        .min()
        .unwrap_or(tail.len());
    Some(tail[..end].trim())
}

/// The delete rule's day count in a TTL clause: the rule without a move target.
fn delete_days(ttl: &str) -> Option<u32> {
    ttl.split(',')
        .map(str::trim)
        .filter(|rule| !rule.contains(" TO VOLUME ") && !rule.contains(" TO DISK "))
        .find_map(|rule| {
            let digits: String = rule
                .split("toIntervalDay(")
                .nth(1)?
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse().ok()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Component;

    fn sql(files: &[(&str, &str)]) -> Vec<(String, String)> {
        files
            .iter()
            .map(|(f, s)| ((*f).to_owned(), (*s).to_owned()))
            .collect()
    }

    #[test]
    fn a_staged_table_is_the_future_live_one_and_a_retired_one_is_gone() {
        let tables = replay(
            "event-store",
            &sql(&[
                ("0001", "-- PARTITION BY nothing\nCREATE TABLE IF NOT EXISTS events (x UInt8) ENGINE = MergeTree PARTITION BY (chain, event_type, toDate(occurred_at)) ORDER BY x"),
                ("0003", "ALTER TABLE events MODIFY TTL toDateTime(occurred_at) + toIntervalDay(2192) DELETE"),
                ("0004", "CREATE TABLE IF NOT EXISTS events__next (x UInt8) ENGINE = ReplacingMergeTree PARTITION BY toYYYYMM(occurred_at) ORDER BY x TTL toDateTime(occurred_at) + toIntervalDay(2192) DELETE SETTINGS a = 1"),
            ]),
        )
        .unwrap();
        assert_eq!(tables.len(), 1);
        let events = &tables[0];
        assert_eq!(events.name, "events");
        assert!(events.key.has(Component::Month));
        assert_eq!(events.engine, "ReplacingMergeTree");
        assert_eq!(events.ttl_days, Some(2192));
    }

    #[test]
    fn rename_exchange_and_drop_are_replayed_and_postgres_is_ignored() {
        let tables = replay(
            "x",
            &sql(&[
                ("1", "CREATE TABLE a (x UInt8) ENGINE = MergeTree PARTITION BY chain ORDER BY x"),
                ("2", "CREATE TABLE b (x UInt8) ENGINE = MergeTree ORDER BY x"),
                ("3", "EXCHANGE TABLES a AND b"),
                ("4", "RENAME TABLE b TO c"),
                ("5", "CREATE TABLE pg (id BIGSERIAL PRIMARY KEY)"),
                ("6", "CREATE TABLE gone (x UInt8) ENGINE = MergeTree ORDER BY x"),
                ("7", "DROP TABLE IF EXISTS gone"),
                ("8", "CREATE TABLE old__retired (x UInt8) ENGINE = MergeTree PARTITION BY toDate(d) ORDER BY x"),
            ]),
        )
        .unwrap();
        let names: Vec<(&str, bool)> = tables
            .iter()
            .map(|t| (t.name.as_str(), t.key.has(Component::Chain)))
            .collect();
        assert_eq!(names, vec![("a", false), ("c", true)]);
    }

    /// The suffixes restated here are the ones `ch-migrate` derives.
    #[test]
    fn the_swap_suffixes_match_ch_migrate() {
        let source = include_str!("../../ch-migrate/src/swap.rs");
        assert!(source.contains(&format!("STAGED_SUFFIX: &str = \"{STAGED_SUFFIX}\"")));
        assert!(source.contains(&format!("RETIRED_SUFFIX: &str = \"{RETIRED_SUFFIX}\"")));
    }
}
