-- Sprint 15 t5: the opt-in "monitored wallet" list (§25) — a customer names
-- an address they want a scheduled MEV-exposure report pushed for. Owned by
-- simulation-projection (it already computes exposure in-process); the
-- public API service writes to it over that service's internal HTTP proxy,
-- mirroring the split `crates/server/src/upstream.rs` already uses for
-- reads (`wallet_mev_exposure`/`timing_recommendation`).
CREATE TABLE monitored_wallets (
    id BIGSERIAL PRIMARY KEY,
    owner UUID NOT NULL,
    chain_id BIGINT NOT NULL,
    address TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (owner, chain_id, address)
);

-- The scheduler's own read (every monitored wallet, every cycle) is a full
-- table scan by design (no owner in scope); this index backs the customer-
-- facing list/delete lookups instead.
CREATE INDEX monitored_wallets_owner_idx ON monitored_wallets (owner);
