//! Hot/cold storage tiering for the `events` table.
//!
//! Evidence has to be kept for six years and is read almost entirely in its
//! first weeks (replays, audits of recent incidents). Keeping all six years on
//! provisioned SSD is the single largest line of the capacity plan's bill, so a
//! deployment with a tiered storage policy moves parts older than
//! `EVENT_STORE_COLD_AFTER_DAYS` to a cheaper volume — object storage behind a
//! ClickHouse `s3` disk, typically. Nothing is deleted; a move rule and the
//! delete rule are separate rules of one TTL clause.
//!
//! # Owned the way retention is owned
//!
//! [`crate::retention`] owns the `DELETE` rule; this module owns the move rule.
//! Both write through one renderer ([`retention::modify_ttl`]) and read through
//! one parser ([`retention::read_ttl_rules`]), because `MODIFY TTL` replaces the
//! whole clause and two writers with two notions of it would each erase the
//! other's rule.
//!
//! # What boot does, and refuses
//!
//! Moving parts is non-destructive, so boot reconciles it unattended — with
//! three refusals that stop the service rather than guess:
//!
//! * the table's retention window is unreadable (a rewrite would have to
//!   reproduce a clause this build cannot read — never);
//! * the move would come at or after expiry (it would never happen, and the
//!   configuration is certainly a mistake);
//! * the storage policy has no such volume on this server (ClickHouse would
//!   reject the rule anyway; this names the missing server config).

use clickhouse::Client;

use crate::retention::{self, MoveRule, RetentionError, TtlRules, TtlState};
use crate::store::TABLE;

/// A validated tiering configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TieringConfig {
    storage_policy: String,
    cold_volume: String,
    move_after_days: u32,
}

/// Why tiering could not be configured or reconciled.
#[derive(Debug, thiserror::Error)]
pub enum TieringError {
    #[error("{name} {value:?} is not a plain ClickHouse identifier (letters, digits, underscore)")]
    BadIdentifier { name: &'static str, value: String },
    #[error("EVENT_STORE_COLD_AFTER_DAYS must be at least 1")]
    ZeroDays,
    #[error(
        "the events table's retention window is not one this build can read ({0}); tiering is \
         refused so a TTL clause this build cannot reproduce is never rewritten"
    )]
    NoReadableRetention(String),
    #[error(
        "moving parts to cold storage after {move_after} day(s) is not before the {retention}-day \
         retention window, so the move would never happen"
    )]
    MoveNotBeforeExpiry { move_after: u32, retention: u32 },
    #[error(
        "storage policy {policy:?} has no volume {volume:?} on this ClickHouse server — add it to \
         the server's storage_configuration (deploy/clickhouse/storage-tiered.xml) first"
    )]
    VolumeMissing { policy: String, volume: String },
    #[error("the events table is not present in system.tables")]
    TableMissing,
    #[error("clickhouse request failed")]
    Clickhouse(#[from] clickhouse::error::Error),
    #[error(transparent)]
    Retention(#[from] RetentionError),
}

impl TieringConfig {
    pub fn new(
        storage_policy: String,
        cold_volume: String,
        move_after_days: u32,
    ) -> Result<Self, TieringError> {
        identifier("EVENT_STORE_STORAGE_POLICY", &storage_policy)?;
        identifier("EVENT_STORE_COLD_VOLUME", &cold_volume)?;
        if move_after_days == 0 {
            return Err(TieringError::ZeroDays);
        }
        Ok(Self {
            storage_policy,
            cold_volume,
            move_after_days,
        })
    }

    pub fn storage_policy(&self) -> &str {
        &self.storage_policy
    }

    pub fn cold_volume(&self) -> &str {
        &self.cold_volume
    }

    pub fn move_after_days(&self) -> u32 {
        self.move_after_days
    }

    /// The move rule this configuration asks for.
    pub fn move_rule(&self) -> MoveRule {
        MoveRule {
            days: self.move_after_days,
            target: format!("TO VOLUME '{}'", self.cold_volume),
        }
    }
}

/// Both names are interpolated into DDL, so they are restricted to the one
/// shape that needs no quoting and can carry no injection.
fn identifier(name: &'static str, value: &str) -> Result<(), TieringError> {
    let ok = !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(TieringError::BadIdentifier {
            name,
            value: value.to_owned(),
        })
    }
}

/// What reconciliation will do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TieringPlan {
    /// The table already has the policy and exactly the desired move rule.
    Unchanged,
    /// Set the storage policy (when it differs) and rewrite the TTL clause with
    /// the retention window unchanged and the desired move rule.
    Apply {
        set_policy: Option<String>,
        delete_days: u32,
        moves: Vec<MoveRule>,
    },
}

/// **The judgement**, pure. The retention window passes through untouched: it
/// is only read here, to prove the rewrite reproduces it.
pub fn plan(
    observed_policy: &str,
    rules: &TtlRules,
    cfg: &TieringConfig,
) -> Result<TieringPlan, TieringError> {
    let retention = match &rules.delete {
        TtlState::Days(days) => *days,
        other => return Err(TieringError::NoReadableRetention(other.to_string())),
    };
    if cfg.move_after_days >= retention {
        return Err(TieringError::MoveNotBeforeExpiry {
            move_after: cfg.move_after_days,
            retention,
        });
    }
    let desired = vec![cfg.move_rule()];
    let set_policy = (observed_policy != cfg.storage_policy).then(|| cfg.storage_policy.clone());
    if set_policy.is_none() && rules.moves == desired {
        return Ok(TieringPlan::Unchanged);
    }
    Ok(TieringPlan::Apply {
        set_policy,
        delete_days: retention,
        moves: desired,
    })
}

/// Bring the table's storage policy and move rule in line with `cfg`. Run at
/// boot after retention reconciliation, so the window it carries across is the
/// reconciled one.
pub async fn reconcile(client: &Client, cfg: &TieringConfig) -> Result<TieringPlan, TieringError> {
    let policies: Vec<String> = client
        .query("SELECT storage_policy FROM system.tables WHERE database = currentDatabase() AND name = ?")
        .bind(TABLE)
        .fetch_all()
        .await?;
    let observed_policy = policies.first().ok_or(TieringError::TableMissing)?;

    let volumes: u64 = client
        .query(
            "SELECT count() FROM system.storage_policies WHERE policy_name = ? AND volume_name = ?",
        )
        .bind(cfg.storage_policy())
        .bind(cfg.cold_volume())
        .fetch_one()
        .await?;
    if volumes == 0 {
        return Err(TieringError::VolumeMissing {
            policy: cfg.storage_policy.clone(),
            volume: cfg.cold_volume.clone(),
        });
    }

    let rules = retention::observe_rules_current(client).await?;
    let decision = plan(observed_policy, &rules, cfg)?;
    if let TieringPlan::Apply {
        set_policy,
        delete_days,
        moves,
    } = &decision
    {
        if let Some(policy) = set_policy {
            // ClickHouse accepts a new policy only if it contains every disk
            // the old one has, so this cannot strand existing parts.
            client
                .query(&format!(
                    "ALTER TABLE {TABLE} MODIFY SETTING storage_policy = '{policy}'"
                ))
                .execute()
                .await?;
        }
        retention::modify_ttl(client, *delete_days, moves).await?;
    }
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(days: u32) -> TieringConfig {
        TieringConfig::new("tiered".into(), "cold".into(), days).unwrap()
    }

    fn rules(delete: TtlState, moves: Vec<MoveRule>) -> TtlRules {
        TtlRules { delete, moves }
    }

    #[test]
    fn identifiers_that_would_need_quoting_are_refused() {
        for bad in ["", "cold'; DROP TABLE events; --", "has space", "dash-ed"] {
            assert!(
                TieringConfig::new("tiered".into(), bad.into(), 90).is_err(),
                "{bad:?}"
            );
        }
        assert!(matches!(
            TieringConfig::new("tiered".into(), "cold".into(), 0),
            Err(TieringError::ZeroDays)
        ));
    }

    #[test]
    fn a_fresh_table_gets_the_policy_and_the_move_with_the_window_unchanged() {
        let plan = plan("default", &rules(TtlState::Days(2192), vec![]), &cfg(90)).unwrap();
        assert_eq!(
            plan,
            TieringPlan::Apply {
                set_policy: Some("tiered".into()),
                delete_days: 2192,
                moves: vec![cfg(90).move_rule()],
            }
        );
    }

    #[test]
    fn a_table_already_tiered_is_unchanged() {
        let current = rules(TtlState::Days(2192), vec![cfg(90).move_rule()]);
        assert_eq!(
            plan("tiered", &current, &cfg(90)).unwrap(),
            TieringPlan::Unchanged
        );
        // A different threshold is an apply, keeping the policy.
        assert!(matches!(
            plan("tiered", &current, &cfg(30)).unwrap(),
            TieringPlan::Apply {
                set_policy: None,
                ..
            }
        ));
    }

    #[test]
    fn an_unreadable_window_or_a_move_after_expiry_is_refused() {
        assert!(matches!(
            plan(
                "default",
                &rules(TtlState::Unreadable("x".into()), vec![]),
                &cfg(90)
            ),
            Err(TieringError::NoReadableRetention(_))
        ));
        assert!(matches!(
            plan("default", &rules(TtlState::Absent, vec![]), &cfg(90)),
            Err(TieringError::NoReadableRetention(_))
        ));
        assert!(matches!(
            plan("default", &rules(TtlState::Days(60), vec![]), &cfg(90)),
            Err(TieringError::MoveNotBeforeExpiry { .. })
        ));
    }
}
