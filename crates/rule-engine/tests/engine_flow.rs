//! The whole §9 evaluation path, end to end, with zero infrastructure:
//! store (in-memory double) → load → compile → evaluate/step → alert →
//! deliver (recording sink) — plus the §15 rewind. This is the shape of the
//! t4 consumer's loop; when t3/t4/t5 land, they replace the doubles with
//! Redis/Kafka/HTTP behind the same seams and this test keeps guarding the
//! logic.

use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, AlertId, Chain, CustomerId, LabelKind};
use rule_engine::action::{ActionSink, RuleAlert};
use rule_engine::compile::{CompiledRuleSet, RuleSetHandle};
use rule_engine::ctx::{Enrichment, EventCtx, EventFacts};
use rule_engine::model::{Action, Condition, TemporalConstraint};
use rule_engine::store::RuleStore;
use rule_engine::temporal::{self, TemporalState};
use rule_engine::test_util::{InMemoryRuleStore, RecordingActionSink, RuleBuilder};
use rust_decimal::Decimal;

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
}

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

fn mixer_touch_condition() -> Condition {
    Condition::InteractedWith {
        address: None,
        label_kind: Some(LabelKind::MixerUser),
    }
}

/// A big-transfer event for the subject address.
fn big_transfer(block: u64) -> EventCtx {
    EventCtx {
        address: addr(0x01),
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

/// A transfer to a mixer-labeled counterparty.
fn mixer_touch(block: u64) -> EventCtx {
    let mut ctx = EventCtx {
        address: addr(0x01),
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

#[tokio::test]
async fn sequence_rule_fires_end_to_end_and_rewinds_on_revert() {
    // ── A customer creates the §9 deliverable rule via the store ──
    let store = InMemoryRuleStore::new();
    let compliance_owner = CustomerId::new();
    let compliance = RuleBuilder::new(compliance_owner)
        .name("Large transfer then mixer interaction")
        .condition(large_usdc())
        .condition(mixer_touch_condition())
        .temporal(TemporalConstraint::Sequence {
            events: vec![large_usdc(), mixer_touch_condition()],
            within_blocks: 100,
        })
        .action(Action::WebhookAlert {
            url: "https://compliance.example.com/hook".into(),
        })
        .build();
    store
        .create_rule(&compliance, at(100))
        .await
        .expect("create");
    // A disabled rule must never reach the evaluation set.
    let parked = RuleBuilder::new(compliance_owner)
        .name("parked")
        .disabled()
        .build();
    store.create_rule(&parked, at(101)).await.expect("create");

    // ── Boot: load the enabled set, compile once, publish the snapshot ──
    let enabled = store.enabled_rules().await.expect("load");
    let handle = RuleSetHandle::new(CompiledRuleSet::compile(&enabled).expect("compile"));
    let set = handle.load();
    assert_eq!(set.len(), 1);
    // The prefetch plan says exactly what this set needs.
    assert!(set.needs().counterparty_labels);
    assert!(!set.needs().risk_score);

    // ── The consumer loop: step the temporal rule per event ──
    let rule = set.temporal_rules().next().expect("temporal rule");
    let clause = rule.temporal().expect("clause");
    let sink = RecordingActionSink::new();

    // Event 1 (block 100): step 1 matches, machine starts, nothing fires.
    let (state, fired) = temporal::step(clause, None, &big_transfer(100));
    assert!(fired.is_none());
    assert_eq!(state, Some(TemporalState::Sequence { matched: vec![100] }));

    // Event 2 (block 150, within the 100-block window): the sequence
    // completes.
    let (state, fired) = temporal::step(clause, state, &mixer_touch(150));
    let fired = fired.expect("sequence completed");
    assert_eq!(state, None);
    assert_eq!(fired.matched_blocks, vec![100, 150]);

    // ── Fire → alert → deliver, one call per action ──
    let alert = RuleAlert {
        alert_id: AlertId::new(),
        rule_id: rule.id,
        owner: rule.owner,
        address: addr(0x01),
        rule_name: rule.name.clone(),
        explanation: "large USDC transfer then mixer interaction".into(),
        matched_blocks: fired.matched_blocks,
    };
    for action in &rule.actions {
        sink.deliver(&alert, action).await.expect("deliver");
    }
    let deliveries = sink.deliveries();
    assert_eq!(deliveries.len(), 1);
    // The alert routes to the rule's owner — the delivery-side isolation half.
    assert_eq!(deliveries[0].0.owner, compliance_owner);
    assert_eq!(
        deliveries[0].1,
        Action::WebhookAlert {
            url: "https://compliance.example.com/hook".into()
        }
    );

    // ── §15: a reverted block rewinds the in-flight window ──
    // Re-run event 1, then revert its block: the machine forgets it, and the
    // mixer touch alone no longer fires (the deliverable's rewind clause).
    let (state, _) = temporal::step(clause, None, &big_transfer(200));
    let state = temporal::rewind(state.expect("in flight"), 200);
    assert_eq!(state, None);
    let (state, fired) = temporal::step(clause, state, &mixer_touch(250));
    assert!(fired.is_none());
    assert_eq!(state, None);
}

#[tokio::test]
async fn instant_rule_fires_on_state_change_and_refresh_swaps_the_set() {
    let store = InMemoryRuleStore::new();
    let owner = CustomerId::new();
    let sanction_rule = RuleBuilder::new(owner)
        .name("Any sanctions hit")
        .condition(Condition::SanctionMatch { list: None })
        .action(Action::SlackAlert {
            channel: "#compliance".into(),
        })
        .build();
    store
        .create_rule(&sanction_rule, at(100))
        .await
        .expect("create");

    let enabled = store.enabled_rules().await.expect("load");
    let handle = RuleSetHandle::new(CompiledRuleSet::compile(&enabled).expect("compile"));

    // A SanctionHit arrives: the consumer refreshes enrichment and evaluates
    // a StateChanged ctx.
    let mut ctx = EventCtx {
        address: addr(0x05),
        block: 500,
        facts: EventFacts::StateChanged,
        enrichment: Enrichment::default(),
    };
    ctx.enrichment.sanction_lists.insert("ofac_sdn".into());

    let set = handle.load();
    let fired = set.evaluate(&ctx);
    assert_eq!(fired.len(), 1);
    assert_eq!(fired[0].id, sanction_rule.id);

    // The customer disables the rule; a refresh recompiles and swaps — new
    // loads see the new set, without touching in-flight snapshots.
    assert!(store
        .set_enabled(owner, sanction_rule.id, false, at(200))
        .await
        .expect("disable"));
    let refreshed = store.enabled_rules().await.expect("reload");
    handle.swap(CompiledRuleSet::compile(&refreshed).expect("recompile"));
    assert!(handle.load().evaluate(&ctx).is_empty());
    // The old snapshot (still held by an in-flight evaluation) is intact.
    assert_eq!(set.evaluate(&ctx).len(), 1);
}
