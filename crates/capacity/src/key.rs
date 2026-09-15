//! A partition key as the components it multiplies, not as an enum of the keys
//! someone thought of.
//!
//! The number of partitions a table holds is the product of each component's
//! cardinality over the rows it retains: a chain component multiplies by the
//! number of chains, a day component by the days held. Modelling the key as
//! that product means a new table's key — `(chain, toYYYYMM(day))`,
//! `toStartOfDay(ts)` — is priced without a code change. What cannot be priced
//! (an arbitrary expression, `x % 16`) is an error, never a default.

use anyhow::{bail, Result};
use serde::Serialize;

const DAYS_PER_MONTH: f64 = 30.436_875;

/// One multiplicative component of a partition key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Component {
    /// The `chain` column.
    Chain,
    /// The `event_type` column.
    EventType,
    /// A day truncation of a time column.
    Day,
    /// A month truncation of a time column.
    Month,
}

/// A parsed `PARTITION BY` expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PartitionKey {
    expression: String,
    components: Vec<Component>,
}

/// What a key's cardinality depends on, for one table at one moment.
#[derive(Debug, Clone, Copy)]
pub struct KeyContext<'a> {
    pub chains: f64,
    pub event_types: f64,
    /// Daily events per (chain, event type) pair, when known (the event store).
    pub pair_rates: &'a [f64],
    /// Daily events per event type, when known.
    pub type_rates: &'a [f64],
    /// The growth multiplier the rates are scaled by at this moment.
    pub growth: f64,
}

impl PartitionKey {
    /// A table with no `PARTITION BY`: one partition.
    pub fn unpartitioned() -> Self {
        Self {
            expression: String::new(),
            components: Vec::new(),
        }
    }

    pub fn parse(expression: &str) -> Result<Self> {
        let trimmed = expression.trim();
        let inner = strip_outer_parens(trimmed);
        let mut components = Vec::new();
        for part in split_top_level(inner) {
            let normalized: String = part.chars().filter(|c| !c.is_whitespace()).collect();
            let component = match normalized.as_str() {
                "chain" => Component::Chain,
                "event_type" => Component::EventType,
                n if is_call(n, &["toDate", "toStartOfDay"]) => Component::Day,
                n if is_call(n, &["toYYYYMM", "toStartOfMonth"]) => Component::Month,
                "" | "tuple()" => continue,
                other => bail!(
                    "the capacity model cannot price the partition key component `{other}` in \
                     PARTITION BY {trimmed} — add it to `capacity::key::Component` with its \
                     cardinality"
                ),
            };
            components.push(component);
        }
        Ok(Self {
            expression: trimmed.to_owned(),
            components,
        })
    }

    pub fn expression(&self) -> &str {
        if self.expression.is_empty() {
            "(unpartitioned)"
        } else {
            &self.expression
        }
    }

    pub fn has(&self, component: Component) -> bool {
        self.components.contains(&component)
    }

    /// Days a partition's rows can outlive a TTL with `ttl_only_drop_parts`: a
    /// merged part spans the key's time grain and drops when its newest row
    /// expires.
    pub fn expiry_lag_days(&self) -> u32 {
        if self.has(Component::Month) {
            31
        } else if self.has(Component::Day) {
            1
        } else {
            0
        }
    }

    /// Partitions held after `days_held` days of rows.
    ///
    /// A (type × day) key is priced by occupancy, not by the product: a pair
    /// occupies a day's partition only if one of its events lands that day,
    /// which with Poisson arrivals at `rate` a day is `1 − e^−rate`. Without
    /// that, a type that fires twice a month is priced like one that fires
    /// every block.
    pub fn count(&self, days_held: f64, ctx: &KeyContext<'_>) -> f64 {
        if days_held <= 0.0 {
            return 0.0;
        }
        let days = days_held.max(1.0);
        let months = (days / DAYS_PER_MONTH).ceil().max(1.0);
        let chains = if self.has(Component::Chain) {
            ctx.chains
        } else {
            1.0
        };
        if self.has(Component::EventType) && self.has(Component::Day) {
            let rates = if self.has(Component::Chain) {
                ctx.pair_rates
            } else {
                ctx.type_rates
            };
            let occupied = if rates.is_empty() {
                chains * ctx.event_types
            } else {
                rates
                    .iter()
                    .map(|rate| 1.0 - (-rate * ctx.growth).exp())
                    .sum()
            };
            return occupied * days;
        }
        let types = if self.has(Component::EventType) {
            ctx.event_types
        } else {
            1.0
        };
        let time = if self.has(Component::Day) {
            days
        } else if self.has(Component::Month) {
            months
        } else {
            1.0
        };
        chains * types * time
    }
}

fn is_call(normalized: &str, functions: &[&str]) -> bool {
    functions.iter().any(|f| {
        normalized
            .strip_prefix(f)
            .and_then(|rest| rest.strip_prefix('('))
            .is_some_and(|rest| rest.ends_with(')') && !rest[..rest.len() - 1].contains('('))
    })
}

fn strip_outer_parens(s: &str) -> &str {
    if !(s.starts_with('(') && s.ends_with(')')) {
        return s;
    }
    // Only when the outer pair encloses everything: `(a, b)` yes, `f(a)` no
    // (it does not start with a paren), `(a) + (b)` no.
    let mut depth = 0;
    for (at, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 && at != s.len() - 1 {
                    return s;
                }
            }
            _ => {}
        }
    }
    &s[1..s.len() - 1]
}

fn split_top_level(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut from = 0;
    for (at, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&s[from..at]);
                from = at + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[from..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(pair_rates: &[f64]) -> KeyContext<'_> {
        KeyContext {
            chains: 2.0,
            event_types: 41.0,
            pair_rates,
            type_rates: &[],
            growth: 1.0,
        }
    }

    #[test]
    fn every_key_in_the_workspace_parses() {
        for (expr, expect) in [
            (
                "(chain, event_type, toDate(occurred_at))",
                vec![Component::Chain, Component::EventType, Component::Day],
            ),
            ("toYYYYMM(occurred_at)", vec![Component::Month]),
            (
                "(chain, toDate(occurred_at))",
                vec![Component::Chain, Component::Day],
            ),
            ("chain", vec![Component::Chain]),
            ("toYYYYMM(window_from)", vec![Component::Month]),
        ] {
            let key = PartitionKey::parse(expr).unwrap();
            assert_eq!(key.components, expect, "{expr}");
        }
    }

    #[test]
    fn an_expression_it_cannot_price_is_refused() {
        assert!(PartitionKey::parse("x % 16").is_err());
        assert!(PartitionKey::parse("toDate(toStartOfHour(ts))").is_err());
    }

    #[test]
    fn a_sparse_type_occupies_few_daily_partitions() {
        let key = PartitionKey::parse("(chain, event_type, toDate(occurred_at))").unwrap();
        assert!((key.count(100.0, &ctx(&[7200.0])) - 100.0).abs() < 1e-9);
        assert!(key.count(100.0, &ctx(&[2.0 / 30.0])) < 7.0);
    }

    #[test]
    fn the_monthly_key_ignores_chains_and_types() {
        let key = PartitionKey::parse("toYYYYMM(occurred_at)").unwrap();
        assert_eq!(key.count(2223.0, &ctx(&[1.0; 82])), 74.0);
        let per_chain = PartitionKey::parse("(chain, toYYYYMM(occurred_at))").unwrap();
        assert_eq!(per_chain.count(2223.0, &ctx(&[])), 148.0);
        assert_eq!(PartitionKey::unpartitioned().count(5000.0, &ctx(&[])), 1.0);
    }
}
