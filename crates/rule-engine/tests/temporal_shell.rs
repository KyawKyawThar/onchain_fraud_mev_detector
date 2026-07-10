//! The t3 imperative shell end to end, with zero infrastructure: events
//! routed through the address-partitioned [`TemporalPool`], state persisted
//! through the [`TemporalStateStore`] seam (in-memory double), fires arriving
//! on the pool's channel — the §9 sequence/frequency semantics *plus* the
//! shell's own promises: per-address isolation, policy-derived TTLs,
//! `flush()` as a checkpoint barrier, the §15 rewind applied synchronously
//! (flush → scan → route → flush), the worker cache saving store loads
//! without changing answers, retry-not-drop on transient store faults, and
//! prompt cancellation. `pool.shutdown()` (and `flush()`) drain every
//! mailbox, so asserting after them is race-free by construction.

use std::sync::Arc;
use std::time::Duration;

use events::primitives::{AccountAddress, Chain, CustomerId, LabelKind};
use rule_engine::compile::{CompiledRuleSet, RuleSetHandle};
use rule_engine::ctx::{Enrichment, EventCtx, EventFacts};
use rule_engine::model::{Action, Condition, Rule, TemporalConstraint};
use rule_engine::state_store::StateKey;
use rule_engine::temporal::TemporalState;
use rule_engine::test_util::{InMemoryTemporalStore, RuleBuilder};
use rule_engine::worker::{PoolConfig, TemporalFire, TemporalPool};
use rust_decimal::Decimal;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn addr(byte: u8) -> AccountAddress {
    AccountAddress::repeat_byte(byte)
}

fn large_usdc() -> Condition {
    Condition::TransferAmount {
        chain: Chain::ETHEREUM,
        token: Some(addr(0xAA)),
        gt: Some(Decimal::new(1_000_000, 0)),
        lt: None,
    }
}

fn mixer_condition() -> Condition {
    Condition::InteractedWith {
        address: None,
        label_kind: Some(LabelKind::MixerUser),
    }
}

/// §9's compliance sequence: large transfer *then* mixer touch within 100.
fn sequence_rule(owner: CustomerId) -> Rule {
    RuleBuilder::new(owner)
        .name("Large transfer then mixer interaction")
        .condition(large_usdc())
        .condition(mixer_condition())
        .temporal(TemporalConstraint::Sequence {
            events: vec![large_usdc(), mixer_condition()],
            within_blocks: 100,
        })
        .action(Action::WebhookAlert {
            url: "https://compliance.example.com/hook".into(),
        })
        .build()
}

/// `count` large transfers within 50 blocks.
fn frequency_rule(owner: CustomerId, count: u32) -> Rule {
    RuleBuilder::new(owner)
        .name("Repeated large transfers")
        .condition(large_usdc())
        .temporal(TemporalConstraint::Frequency {
            condition: Box::new(large_usdc()),
            count,
            within_blocks: 50,
        })
        .build()
}

/// A large USDC transfer by `address` (matches step 1 / the frequency hit).
fn big_transfer(address: AccountAddress, block: u64) -> EventCtx {
    EventCtx {
        address,
        block,
        facts: EventFacts::Transfer {
            chain: Chain::ETHEREUM,
            token: Some(addr(0xAA)),
            amount: Decimal::new(5_000_000, 0),
            counterparty: addr(0x02),
        },
        enrichment: Enrichment::default(),
    }
}

/// A transfer by `address` to a mixer-labeled counterparty (step 2).
fn mixer_touch(address: AccountAddress, block: u64) -> EventCtx {
    let mut ctx = EventCtx {
        address,
        block,
        facts: EventFacts::Transfer {
            chain: Chain::ETHEREUM,
            token: None,
            amount: Decimal::new(1, 0),
            counterparty: addr(0x99),
        },
        enrichment: Enrichment::default(),
    };
    ctx.enrichment
        .counterparty_labels
        .insert(LabelKind::MixerUser);
    ctx
}

/// Pool + doubles wired the way the t4 consumer will wire them.
fn pool_for(
    rules: &[Rule],
    config: PoolConfig,
) -> (
    TemporalPool,
    Arc<InMemoryTemporalStore>,
    mpsc::Receiver<TemporalFire>,
    CancellationToken,
) {
    let handle = Arc::new(RuleSetHandle::new(
        CompiledRuleSet::compile(rules).expect("compile"),
    ));
    let store = Arc::new(InMemoryTemporalStore::new());
    let (fires_tx, fires_rx) = mpsc::channel(16);
    let shutdown = CancellationToken::new();
    let pool = TemporalPool::spawn(
        config,
        handle,
        Arc::clone(&store) as Arc<_>,
        fires_tx,
        shutdown.clone(),
    );
    (pool, store, fires_rx, shutdown)
}

#[tokio::test]
async fn sequence_fires_through_the_pool_and_state_clears() {
    let owner = CustomerId::new();
    let rule = sequence_rule(owner);
    let (pool, store, mut fires, _shutdown) = pool_for(
        std::slice::from_ref(&rule),
        PoolConfig {
            partitions: 4,
            ..PoolConfig::default()
        },
    );

    let subject = addr(0x01);
    pool.step(big_transfer(subject, 100)).await.expect("step 1");
    pool.step(mixer_touch(subject, 150)).await.expect("step 2");
    pool.shutdown().await;

    // The fire carries everything t4 needs to raise the alert, from the rule
    // version that fired.
    let fire = fires.recv().await.expect("sequence completed");
    assert_eq!(fire.rule_id, rule.id);
    assert_eq!(fire.owner, owner);
    assert_eq!(fire.rule_name, rule.name);
    assert_eq!(fire.actions, rule.actions);
    assert_eq!(fire.address, subject);
    assert_eq!(fire.block, 150);
    assert_eq!(fire.matched_blocks, vec![100, 150]);
    assert!(fires.recv().await.is_none(), "exactly one fire");

    // §9: rules alert per completed window — the machine reset, so the key
    // is gone, not lingering until TTL.
    assert!(store.is_empty());
}

#[tokio::test]
async fn window_state_persists_ttl_bounded_by_the_policy() {
    let rule = sequence_rule(CustomerId::new());
    let config = PoolConfig::default();
    let (pool, store, _fires, _shutdown) = pool_for(std::slice::from_ref(&rule), config);

    let subject = addr(0x01);
    pool.step(big_transfer(subject, 100)).await.expect("step");
    pool.shutdown().await;

    let key = StateKey {
        rule_id: rule.id,
        address: subject,
    };
    assert_eq!(
        store.state(&key),
        Some(TemporalState::Sequence { matched: vec![100] })
    );
    // TTL is the policy's translation of the clause's 100-block window.
    assert_eq!(store.ttl(&key), Some(config.ttl.ttl_for(100)));
}

#[tokio::test]
async fn frequency_state_is_isolated_per_address() {
    let rule = frequency_rule(CustomerId::new(), 2);
    let (pool, store, mut fires, _shutdown) =
        pool_for(std::slice::from_ref(&rule), PoolConfig::default());

    // Interleave two addresses: A hits at 100 and 120, B once at 110. If
    // state were keyed by rule alone, B's hit would complete A's window at
    // block 110.
    let (a, b) = (addr(0x01), addr(0x03));
    pool.step(big_transfer(a, 100)).await.expect("a1");
    pool.step(big_transfer(b, 110)).await.expect("b1");
    pool.step(big_transfer(a, 120)).await.expect("a2");
    pool.shutdown().await;

    let fire = fires.recv().await.expect("A fired");
    assert_eq!(fire.address, a);
    assert_eq!(fire.matched_blocks, vec![100, 120]);
    assert!(fires.recv().await.is_none(), "B must not fire");

    // A's machine reset on fire; B's is still in flight.
    assert_eq!(
        store.state(&StateKey {
            rule_id: rule.id,
            address: b,
        }),
        Some(TemporalState::Frequency { hits: vec![110] })
    );
    assert_eq!(store.len(), 1);
}

#[tokio::test]
async fn rewind_applies_synchronously_between_steps() {
    let rule = sequence_rule(CustomerId::new());
    let (pool, store, mut fires, _shutdown) = pool_for(
        std::slice::from_ref(&rule),
        PoolConfig {
            partitions: 4,
            ..PoolConfig::default()
        },
    );

    // Step 1 matches at block 200 … then block 200 reverts (§15). `rewind`
    // returns only once fully applied (flush → scan → route → flush), so the
    // §15 promise is assertable *immediately* — this is also what lets t4
    // commit the `BlockReverted` offset right after the call.
    let subject = addr(0x01);
    pool.step(big_transfer(subject, 200)).await.expect("step 1");
    pool.rewind(200).await.expect("rewind");
    assert!(store.is_empty(), "rewind returns fully applied");

    // The step-2 event arriving after the revert must find no ordering
    // evidence left — the mixer touch alone must not fire.
    pool.step(mixer_touch(subject, 250)).await.expect("step 2");
    pool.shutdown().await;

    assert!(fires.recv().await.is_none(), "rewound window must not fire");
    assert!(store.is_empty());
}

#[tokio::test]
async fn flush_is_a_checkpoint_barrier() {
    let rule = sequence_rule(CustomerId::new());
    let (pool, store, mut fires, _shutdown) =
        pool_for(std::slice::from_ref(&rule), PoolConfig::default());

    // After `flush` returns, everything enqueued before it is persisted —
    // the t4 consumer's offset-commit point — with the pool still live.
    let subject = addr(0x01);
    pool.step(big_transfer(subject, 100)).await.expect("step 1");
    pool.flush().await.expect("flush");
    assert_eq!(
        store.state(&StateKey {
            rule_id: rule.id,
            address: subject,
        }),
        Some(TemporalState::Sequence { matched: vec![100] })
    );

    // The pool keeps working after a flush.
    pool.step(mixer_touch(subject, 150)).await.expect("step 2");
    pool.shutdown().await;
    assert_eq!(
        fires.recv().await.expect("fired").matched_blocks,
        vec![100, 150]
    );
}

#[tokio::test]
async fn cache_serves_hot_addresses_without_reloading() {
    let rule = sequence_rule(CustomerId::new());
    // Cache on (default): the second event for the same (rule, address) is
    // answered from the worker's cache — single-writer ownership is what
    // makes that sound.
    let (pool, store, _fires, _shutdown) =
        pool_for(std::slice::from_ref(&rule), PoolConfig::default());

    let subject = addr(0x01);
    pool.step(big_transfer(subject, 100)).await.expect("step 1");
    pool.step(big_transfer(subject, 110)).await.expect("step 2");
    pool.flush().await.expect("flush");

    assert_eq!(store.loads(), 1, "second step must be a cache hit");
    // And the cached path computes the same state the store holds.
    assert_eq!(
        store.state(&StateKey {
            rule_id: rule.id,
            address: subject,
        }),
        Some(TemporalState::Sequence { matched: vec![100] })
    );
}

#[tokio::test]
async fn disabling_the_cache_reloads_every_step() {
    let rule = sequence_rule(CustomerId::new());
    let (pool, store, _fires, _shutdown) = pool_for(
        std::slice::from_ref(&rule),
        PoolConfig {
            cache_entries: 0,
            ..PoolConfig::default()
        },
    );

    let subject = addr(0x01);
    pool.step(big_transfer(subject, 100)).await.expect("step 1");
    pool.step(big_transfer(subject, 110)).await.expect("step 2");
    pool.flush().await.expect("flush");

    assert_eq!(store.loads(), 2, "no cache: every step loads");
}

#[tokio::test]
async fn rewind_leaves_untouched_windows_alone() {
    let rule = frequency_rule(CustomerId::new(), 3);
    let (pool, store, _fires, _shutdown) =
        pool_for(std::slice::from_ref(&rule), PoolConfig::default());

    // Hits at 100 and 120; block 110 reverts — neither hit came from it, so
    // the machine (and its TTL anchor) must survive unchanged.
    let subject = addr(0x01);
    pool.step(big_transfer(subject, 100)).await.expect("hit 1");
    pool.step(big_transfer(subject, 120)).await.expect("hit 2");
    pool.rewind(110).await.expect("rewind");
    pool.shutdown().await;

    assert_eq!(
        store.state(&StateKey {
            rule_id: rule.id,
            address: subject,
        }),
        Some(TemporalState::Frequency {
            hits: vec![100, 120]
        })
    );
}

#[tokio::test]
async fn transient_store_faults_are_retried_not_dropped() {
    let rule = sequence_rule(CustomerId::new());
    let (pool, store, _fires, _shutdown) = pool_for(
        std::slice::from_ref(&rule),
        PoolConfig {
            retry_backoff: Duration::from_millis(5),
            ..PoolConfig::default()
        },
    );

    // Two consecutive faults (a Redis blip spanning the load): the state
    // store is correctness-bearing, so the event must still be applied.
    store.inject_transient_faults(2);
    let subject = addr(0x01);
    pool.step(big_transfer(subject, 100)).await.expect("step");
    pool.shutdown().await;

    assert_eq!(
        store.state(&StateKey {
            rule_id: rule.id,
            address: subject,
        }),
        Some(TemporalState::Sequence { matched: vec![100] })
    );
}

#[tokio::test]
async fn cancellation_stops_a_worker_stuck_in_retry() {
    let rule = sequence_rule(CustomerId::new());
    let (pool, store, _fires, shutdown) = pool_for(
        std::slice::from_ref(&rule),
        PoolConfig {
            retry_backoff: Duration::from_millis(5),
            ..PoolConfig::default()
        },
    );

    // An endless outage: without cancellation the worker retries forever
    // (by design — retry-not-drop). The token must break it out promptly.
    store.inject_transient_faults(usize::MAX);
    pool.step(big_transfer(addr(0x01), 100))
        .await
        .expect("step");
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), pool.shutdown())
        .await
        .expect("cancelled workers must exit");
}
