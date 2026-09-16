//! What to enrich with: the venues whose pools are trusted and the price
//! feeds tokens are valued by, per chain.
//!
//! Addresses are written EIP-55 checksummed and parsed as such, so a typo in
//! a committed config is a load error instead of a silent mispricing. Feeds
//! also carry the `description()` the enricher checks on the chain at connect
//! time ([`crate::Enricher::connect`]): a feed address pointing at the wrong
//! pair fails boot, not a detection.

use std::collections::BTreeSet;
use std::path::Path;

use alloy_primitives::{Address, B256};
use events::primitives::Chain;
use serde::Deserialize;

use crate::venue::V2Venue;

/// The committed Ethereum mainnet configuration.
pub const ETHEREUM_MAINNET: &str = include_str!("../config/ethereum-mainnet.json");

/// A validated enrichment configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrichConfig {
    pub chain: Chain,
    /// How many contract reads one block may run at once.
    pub concurrency: usize,
    /// Distinct tokens whose metadata is remembered across blocks.
    pub token_cache: usize,
    /// Distinct pools whose identity is remembered across blocks.
    pub pool_cache: usize,
    pub venues: Vec<V2Venue>,
    pub feeds: Vec<PriceFeed>,
}

/// A Chainlink-style aggregator pricing one token in USD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceFeed {
    pub token: Address,
    pub feed: Address,
    /// What the feed's `description()` must return, e.g. `ETH / USD`.
    pub description: String,
    /// An answer older than this, relative to the block's timestamp, is
    /// treated as no price. Set a little above the feed's heartbeat.
    pub max_age_secs: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("parsing enrichment config: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("{field}: {value:?} is not an EIP-55 checksummed address")]
    Address { field: String, value: String },
    #[error("{field}: {value:?} is not a 32-byte hex hash")]
    Hash { field: String, value: String },
    #[error("{0}")]
    Invalid(String),
    #[error("no built-in enrichment config for {0}; pass one explicitly")]
    NoBuiltin(Chain),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    chain: u64,
    concurrency: usize,
    token_cache: usize,
    pool_cache: usize,
    venues: Vec<RawVenue>,
    feeds: Vec<RawFeed>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVenue {
    name: String,
    factory: String,
    init_code_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFeed {
    token: String,
    feed: String,
    description: String,
    max_age_secs: u64,
}

fn checksummed(field: String, value: &str) -> Result<Address, ConfigError> {
    Address::parse_checksummed(value, None).map_err(|_| ConfigError::Address {
        field,
        value: value.to_owned(),
    })
}

impl EnrichConfig {
    /// Parse and validate a configuration.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = serde_json::from_str(text)?;
        let invalid = |msg: String| Err(ConfigError::Invalid(msg));
        if raw.concurrency == 0 || raw.token_cache == 0 || raw.pool_cache == 0 {
            return invalid("concurrency and cache sizes must be positive".into());
        }

        let mut venues = Vec::with_capacity(raw.venues.len());
        let mut factories = BTreeSet::new();
        for (i, v) in raw.venues.into_iter().enumerate() {
            let factory = checksummed(format!("venues[{i}].factory"), &v.factory)?;
            let init_code_hash: B256 = v.init_code_hash.parse().map_err(|_| ConfigError::Hash {
                field: format!("venues[{i}].init_code_hash"),
                value: v.init_code_hash.clone(),
            })?;
            if v.name.trim().is_empty() || !factories.insert(factory) {
                return invalid(format!("venues[{i}]: empty name or duplicate factory"));
            }
            venues.push(V2Venue {
                name: v.name,
                factory,
                init_code_hash,
            });
        }

        let mut feeds = Vec::with_capacity(raw.feeds.len());
        let mut tokens = BTreeSet::new();
        for (i, f) in raw.feeds.into_iter().enumerate() {
            let token = checksummed(format!("feeds[{i}].token"), &f.token)?;
            let feed = checksummed(format!("feeds[{i}].feed"), &f.feed)?;
            if !tokens.insert(token) {
                return invalid(format!("feeds[{i}]: a second feed for {token}"));
            }
            if f.max_age_secs == 0 || f.description.trim().is_empty() {
                return invalid(format!("feeds[{i}]: empty description or zero max age"));
            }
            feeds.push(PriceFeed {
                token,
                feed,
                description: f.description,
                max_age_secs: f.max_age_secs,
            });
        }

        Ok(Self {
            chain: Chain(raw.chain),
            concurrency: raw.concurrency,
            token_cache: raw.token_cache,
            pool_cache: raw.pool_cache,
            venues,
            feeds,
        })
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_json(&text)
    }

    /// The committed configuration for `chain`, if there is one.
    pub fn builtin(chain: Chain) -> Result<Self, ConfigError> {
        match chain {
            Chain::ETHEREUM => Self::from_json(ETHEREUM_MAINNET),
            other => Err(ConfigError::NoBuiltin(other)),
        }
    }

    pub fn feed_for(&self, token: Address) -> Option<&PriceFeed> {
        self.feeds.iter().find(|f| f.token == token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_mainnet_config_is_valid_and_checksummed() {
        let config = EnrichConfig::builtin(Chain::ETHEREUM).expect("committed config loads");
        assert_eq!(config.chain, Chain::ETHEREUM);
        assert_eq!(config.venues.len(), 2);
        assert_eq!(config.feeds.len(), 4);
        assert!(config.feed_for(config.feeds[0].token).is_some());
    }

    #[test]
    fn a_non_checksummed_address_is_refused() {
        let lower = ETHEREUM_MAINNET.replace(
            "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
            "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6e",
        );
        assert!(matches!(
            EnrichConfig::from_json(&lower),
            Err(ConfigError::Address { .. })
        ));
    }

    #[test]
    fn duplicates_and_zero_limits_are_refused() {
        let twice = ETHEREUM_MAINNET.replace(
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        );
        assert!(matches!(
            EnrichConfig::from_json(&twice),
            Err(ConfigError::Invalid(_))
        ));
        let zero = ETHEREUM_MAINNET.replace("\"concurrency\": 16", "\"concurrency\": 0");
        assert!(matches!(
            EnrichConfig::from_json(&zero),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn other_chains_need_an_explicit_config() {
        assert!(matches!(
            EnrichConfig::builtin(Chain::BASE),
            Err(ConfigError::NoBuiltin(_))
        ));
    }
}
