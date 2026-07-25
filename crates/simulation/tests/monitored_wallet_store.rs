//! Integration test for [`PgMonitoredWalletStore`] (Sprint 15 t5) against a
//! *real* Postgres, spun up on demand via testcontainers — the CRUD +
//! owner-isolation + idempotent-opt-in contract the in-memory double in
//! `simulation::test_util` also honours (`simulation/src/monitored_wallet_store.rs`'s
//! own unit tests cover the row-decoding edge). Marked `#[ignore]` so the
//! default `cargo test` stays hermetic; CI's integration job (and
//! `just test-integration`) run it with `--run-ignored all` — mirrors
//! `tests/projection_store.rs`.

use chrono::Utc;
use events::primitives::{AccountAddress, Chain, CustomerId};
use simulation::monitored_wallet_store::{
    AddOutcome, MonitoredWalletStore, PgMonitoredWalletStore,
};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn monitored_wallets_are_owner_isolated_and_opt_in_is_idempotent() {
    let container = Postgres::default()
        .start()
        .await
        .expect("start Postgres container");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Postgres port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

    let pool = db::connect(&url).await.expect("connect");
    sqlx::migrate!("../db/migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    let store = PgMonitoredWalletStore::new(pool.clone());

    let owner_a = CustomerId::new();
    let owner_b = CustomerId::new();
    let address = AccountAddress::repeat_byte(0x11);

    // First opt-in creates the row.
    let outcome = store
        .add(owner_a, Chain::ETHEREUM, address, Utc::now())
        .await
        .expect("add");
    assert_eq!(outcome, AddOutcome::Added);

    // Re-opting the same pair in is idempotent, not an error or a duplicate.
    let outcome = store
        .add(owner_a, Chain::ETHEREUM, address, Utc::now())
        .await
        .expect("re-add");
    assert_eq!(outcome, AddOutcome::AlreadyMonitored);

    // A second owner can monitor the *same* address independently.
    store
        .add(owner_b, Chain::ETHEREUM, address, Utc::now())
        .await
        .expect("owner_b add");

    // Owner isolation: each owner's list only ever contains their own rows.
    let a_list = store.list_for_owner(owner_a).await.expect("list a");
    assert_eq!(a_list.len(), 1);
    assert_eq!(a_list[0].owner, owner_a);
    assert_eq!(a_list[0].address, address);

    let b_list = store.list_for_owner(owner_b).await.expect("list b");
    assert_eq!(b_list.len(), 1);
    assert_eq!(b_list[0].owner, owner_b);

    // The scheduler's own read crosses owners.
    let all = store.list_all(None, 100).await.expect("list all");
    assert_eq!(all.wallets.len(), 2);
    assert!(
        all.next_cursor.is_none(),
        "both rows fit in one page well under the limit"
    );

    // Opting out removes only that owner's row.
    let removed = store
        .remove(owner_a, Chain::ETHEREUM, address)
        .await
        .expect("remove");
    assert!(removed);
    assert!(store
        .list_for_owner(owner_a)
        .await
        .expect("list a")
        .is_empty());
    assert_eq!(
        store.list_for_owner(owner_b).await.expect("list b").len(),
        1
    );

    // Removing a pair that was never monitored (by this owner) is a no-op,
    // indistinguishable from removing another owner's row.
    let removed_again = store
        .remove(owner_a, Chain::ETHEREUM, address)
        .await
        .expect("remove again");
    assert!(!removed_again);
}

/// [`MonitoredWalletStore::list_all`]'s keyset pagination against real
/// Postgres: walking every page via `next_cursor` visits every row exactly
/// once, in `(created_at, id)` order, regardless of how the limit divides the
/// total — the property `exposure_report::run_cycle`'s page loop depends on.
#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn list_all_pages_through_every_row_exactly_once() {
    let container = Postgres::default()
        .start()
        .await
        .expect("start Postgres container");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Postgres port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

    let pool = db::connect(&url).await.expect("connect");
    sqlx::migrate!("../db/migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    let store = PgMonitoredWalletStore::new(pool.clone());

    // 7 wallets, a page size (3) that doesn't evenly divide the total, so the
    // last page is deliberately partial.
    let mut expected_ids = Vec::new();
    for i in 0..7u8 {
        store
            .add(
                CustomerId::new(),
                Chain::ETHEREUM,
                AccountAddress::repeat_byte(i),
                Utc::now(),
            )
            .await
            .expect("add");
    }
    let first = store.list_all(None, 100).await.expect("seed check");
    for wallet in &first.wallets {
        expected_ids.push(wallet.id);
    }
    assert_eq!(expected_ids.len(), 7);

    let mut visited_ids = Vec::new();
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let page = store.list_all(cursor, 3).await.expect("list page");
        pages += 1;
        assert!(
            page.wallets.len() <= 3,
            "a page must never exceed the requested limit"
        );
        visited_ids.extend(page.wallets.iter().map(|w| w.id));
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    assert_eq!(pages, 3, "7 rows at a page size of 3 is 3 pages (3+3+1)");
    visited_ids.sort_unstable();
    let mut expected_sorted = expected_ids.clone();
    expected_sorted.sort_unstable();
    assert_eq!(
        visited_ids, expected_sorted,
        "every row visited exactly once across all pages"
    );
}
