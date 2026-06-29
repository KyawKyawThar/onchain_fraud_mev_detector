//! The revm simulation engine (§7) — the CPU-bound core a worker runs each
//! `SimulationJob` on. Given a fully-described scenario (a block environment, the
//! seeded pre-state, and the transaction bundle to replay), it re-executes the
//! bundle in revm and **diffs balances** to estimate attacker profit / victim loss,
//! then decides whether the alert is confirmed (§7 "what simulation confirms").
//!
//! ## The seam
//!
//! [`Simulator`] is the object-safe trait the [`crate::worker`] holds as
//! `Arc<dyn Simulator>`, so the worker's ack/redelivery logic is testable against a
//! deterministic double with no EVM. [`RevmSimulator`] is the production engine.
//!
//! ## Pure scenario in, outcome out
//!
//! The engine takes a [`SimulationRequest`] — a *self-contained* scenario, not a
//! raw `SimulationJob`. It carries the seeded accounts and the executable bundle, so
//! the engine is a deterministic function of its input with no I/O: a unit test
//! seeds two accounts and asserts the profit, no RPC and no chain access. Turning a
//! `SimulationJob` into a `SimulationRequest` (resolving the implicated `(block,
//! tx_set)` and forking chain state at that block) is the [`crate::resolver`] seam —
//! deliberately separate, because *that* is the part that needs the network and the
//! event-store evidence query (§7), and is the one piece deferred (see the crate
//! docs). The engine itself is real and complete here.
//!
//! ## Why balances, gas-free
//!
//! Profit is measured purely as the change in the implicated accounts' balances
//! across the bundle, with `gas_price = 0` so gas accounting never distorts the
//! diff — the simulation answers "who ended up with the money", not "what did this
//! cost to run". Reverted/halted transactions are a *valid* outcome (the bundle
//! simply didn't extract value), not an error — only a malformed tx or a database
//! fault is an `Err`.
//!
//! ## Hardening — hostile bytecode (§7, Sprint 5 t4)
//!
//! Honeypot-token bytecode runs *here*, in our interpreter, so it is treated as
//! hostile input. Three layers bound it ([`SimLimits`]):
//!
//! - **Per-tx gas cap.** Each tx's `gas_limit` is clamped to
//!   [`SimLimits::per_tx_gas`]. Gas is the EVM's native step meter (every opcode
//!   costs ≥ 1 gas), so the cap is a hard ceiling on opcodes executed — a contract
//!   that loops forever exhausts its budget and *halts* (`OutOfGas`), which is a
//!   valid "no value extracted" outcome, not an error. This is why the step cap
//!   needs no tracing inspector (the heavy revm subtree the workspace `Cargo.toml`
//!   deliberately trims): the meter is already in the interpreter.
//! - **Bundle gas budget.** The whole bundle's cumulative gas is capped at
//!   [`SimLimits::bundle_gas_budget`]; a bundle that blows past it is abandoned as
//!   **poison** (deterministic on retry → dead-letter, don't loop), guarding against
//!   a pathological many-tx bundle the per-tx cap alone wouldn't bound.
//! - **Panic sandbox.** The revm run is wrapped in [`std::panic::catch_unwind`]; a
//!   panic provoked by malformed bytecode becomes poison rather than unwinding the
//!   rayon worker thread. The seeded pre-state already runs over `EmptyDB`, so there
//!   is no chain I/O to escape to.
//!
//! [`SimError`] splits transient from poison, so the new cap/sandbox failures slot
//! in as poison cases without reshaping the worker's ack/redelivery logic. Result
//! memoization keyed by `(block, tx_set)` — the other half of §7 hardening — is the
//! [`crate::cache`] decorator, kept separate so the engine stays a pure function.

use std::sync::Arc;

use events::primitives::{AlertId, AlertKind, Severity};
use revm::bytecode::Bytecode;
use revm::context::{ContextTr, TxEnv};
use revm::database::{CacheDB, DatabaseRef, EmptyDB};
use revm::primitives::{Address, Bytes, TxKind, B256, U256};
use revm::state::AccountInfo;
use revm::{Context, ExecuteCommitEvm, MainBuilder, MainContext};

/// Wei per ether — the divisor turning a balance delta into the ETH-denominated
/// figure the result events carry.
const WEI_PER_ETH: f64 = 1e18;

/// Attacker-profit (ETH) band boundaries for incident [`Severity`]. A **placeholder**
/// banding (see [`severity_for`]); named so the tuning knob is findable, not a magic
/// number buried in a `match`.
const CRITICAL_ETH: f64 = 100.0;
const HIGH_ETH: f64 = 10.0;
const MEDIUM_ETH: f64 = 1.0;

/// The minimum attacker profit (ETH) for a simulation to **confirm** an alert into an
/// incident. A validated newtype (mirrors [`UsdPrice`](events) / `Confidence`): a
/// negative or non-finite threshold is rejected at construction, so a fat-fingered
/// `SIMULATION_MIN_PROFIT_ETH=-1` fails at boot rather than silently confirming every
/// alert (or never confirming any).
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct MinProfit(f64);

/// A [`MinProfit`] was constructed from a value that isn't a finite, non-negative
/// number.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
#[error("min profit {value} ETH is not a finite, non-negative number")]
pub struct InvalidMinProfit {
    pub value: f64,
}

impl MinProfit {
    /// Validate `eth` is finite and `>= 0.0`.
    pub fn try_new(eth: f64) -> Result<Self, InvalidMinProfit> {
        if eth.is_finite() && eth >= 0.0 {
            Ok(Self(eth))
        } else {
            Err(InvalidMinProfit { value: eth })
        }
    }

    pub fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for MinProfit {
    type Error = InvalidMinProfit;

    fn try_from(eth: f64) -> Result<Self, Self::Error> {
        Self::try_new(eth)
    }
}

/// The block environment a simulation runs against. Carries only what the EVM
/// reads; defaults are a clean genesis-like block so a test scenario need only set
/// what it cares about.
#[derive(Debug, Clone)]
pub struct BlockParams {
    pub number: u64,
    pub timestamp: u64,
    /// EIP-1559 base fee. Left `0` so a `gas_price = 0` bundle is always admissible
    /// (a non-zero base fee would reject it) — the engine measures value flow, not
    /// fees.
    pub basefee: u64,
    /// Block gas limit; must be ≥ each tx's `gas_limit`.
    pub gas_limit: u64,
    /// The block's `coinbase` — receives nothing here since `gas_price = 0`, but
    /// carried so a builder-payment scenario (§7) can attribute it later.
    pub beneficiary: Address,
}

impl Default for BlockParams {
    fn default() -> Self {
        Self {
            number: 0,
            timestamp: 0,
            basefee: 0,
            gas_limit: 30_000_000,
            beneficiary: Address::ZERO,
        }
    }
}

/// One account seeded into the simulation's pre-state. In production the
/// [`crate::resolver`] reads these from chain state at the forked block; in tests a
/// scenario constructs them directly.
#[derive(Debug, Clone)]
pub struct SeededAccount {
    pub address: Address,
    pub balance: U256,
    /// Contract bytecode, if this account is a contract. `None` is a plain EOA.
    /// Honeypot bytecode is hostile input executed here (§7) — the [`SimLimits`] gas
    /// caps + panic sandbox bound it, and a malformed result is poison, not a crash.
    pub code: Option<Bytes>,
}

/// One transaction in the bundle to replay. A thin, owned description the engine
/// turns into a revm `TxEnv`; `gas_price` is forced to `0` by the engine so this
/// type can't carry fee policy that would skew the balance diff.
#[derive(Debug, Clone)]
pub struct SimTx {
    pub caller: Address,
    /// `Some(addr)` is a call; `None` is a contract creation.
    pub to: Option<Address>,
    pub value: U256,
    pub data: Bytes,
    pub gas_limit: u64,
}

/// A fully-described simulation scenario — the engine's input. Self-contained: the
/// engine touches nothing outside this struct.
#[derive(Debug, Clone)]
pub struct SimulationRequest {
    /// The alert this confirms or retracts — carried straight through to the result
    /// so it stays the dedup key (§7).
    pub alert_id: AlertId,
    pub kind: AlertKind,
    pub block: BlockParams,
    /// Pre-state: every account the bundle reads or whose balance we diff.
    pub accounts: Vec<SeededAccount>,
    /// The transactions to replay, in order.
    pub bundle: Vec<SimTx>,
    /// The account whose balance gain is the attacker profit.
    pub attacker: Address,
    /// The account whose balance loss is the victim loss, if the pattern names one.
    pub victim: Option<Address>,
    /// The on-chain tx hashes the alert implicated — the incident's `txs` (identity,
    /// not executed here; the executable form is [`bundle`](Self::bundle)).
    pub txs: Vec<B256>,
}

/// What the engine concluded. ETH-denominated; the [`crate::result`] mapping turns
/// this into the `SimulationCompleted` / `IncidentCreated` events.
#[derive(Debug, Clone, PartialEq)]
pub struct SimulationOutcome {
    pub alert_id: AlertId,
    pub kind: AlertKind,
    /// Attacker balance delta across the bundle, in ETH (negative if they lost).
    pub profit: f64,
    /// Victim balance loss across the bundle, in ETH (negative if they gained).
    pub victim_loss: f64,
    /// `profit` cleared the confirmation threshold.
    pub confirmed: bool,
    pub severity: Severity,
    pub txs: Vec<B256>,
}

/// Why a simulation could not produce an outcome. Split transient/poison so the
/// worker maps it to the right RabbitMQ disposition (requeue vs dead-letter),
/// mirroring `queue::JobError`.
#[derive(Debug, thiserror::Error)]
pub enum SimError {
    /// A fault that could succeed on retry — a database/RPC fault from the forked
    /// state backend. The worker **requeues** (at-least-once redelivery).
    #[error("transient simulation fault: {0}")]
    Transient(String),

    /// A fault identical on every retry — a malformed transaction the EVM rejects
    /// outright, the bundle gas budget tripped by hostile bytecode, or a revm panic
    /// caught by the sandbox. The worker **dead-letters** it rather than looping.
    #[error("unsimulatable job (poison): {0}")]
    Poison(String),
}

impl SimError {
    /// Whether re-running the *same* job could plausibly succeed later.
    pub fn is_transient(&self) -> bool {
        matches!(self, SimError::Transient(_))
    }
}

/// Where simulation outcomes come from. Object-safe so the worker holds
/// `Arc<dyn Simulator>` and a test swaps in a deterministic double.
pub trait Simulator: Send + Sync {
    /// Run one scenario to an outcome. CPU-bound — the worker calls this on the
    /// rayon pool, never on the async reactor (§17).
    fn simulate(&self, req: &SimulationRequest) -> Result<SimulationOutcome, SimError>;
}

/// Forward through an `Arc`, so both `Arc<dyn Simulator>` (the worker's erased
/// handle) and `Arc<RevmSimulator>` / `Arc<CountingSimulator>` (a shared concrete
/// engine) are themselves `Simulator`s.
impl<S: Simulator + ?Sized> Simulator for Arc<S> {
    fn simulate(&self, req: &SimulationRequest) -> Result<SimulationOutcome, SimError> {
        (**self).simulate(req)
    }
}

/// Compute bounds that keep hostile honeypot bytecode from running unbounded in the
/// interpreter (§7 hardening). Both are gas figures because gas *is* the EVM's step
/// meter — every opcode costs ≥ 1 gas — so a gas ceiling is a step ceiling without
/// needing a tracing inspector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimLimits {
    /// Max gas any single tx may consume; each tx's `gas_limit` is clamped to this.
    /// A contract that loops forever exhausts it and **halts** (`OutOfGas`) — a valid
    /// "no value extracted" outcome, not an error.
    pub per_tx_gas: u64,
    /// Max cumulative gas the whole bundle may consume. A bundle that exceeds it is
    /// abandoned as **poison** (deterministic on retry → dead-letter), bounding a
    /// pathological many-tx bundle the per-tx cap alone wouldn't catch.
    pub bundle_gas_budget: u64,
}

impl Default for SimLimits {
    fn default() -> Self {
        // Per-tx: one mainnet block's gas — generous for any honest bundle, but a
        // hard stop on a runaway loop. Bundle: a few txs' worth (a sandwich is three),
        // so an honest bundle clears it while an absurd one trips the budget.
        Self {
            per_tx_gas: 30_000_000,
            bundle_gas_budget: 90_000_000,
        }
    }
}

/// The production engine: re-executes the bundle in revm over an in-memory cache of
/// the seeded pre-state and diffs balances.
#[derive(Debug, Clone)]
pub struct RevmSimulator {
    /// Minimum attacker profit for the alert to be `confirmed`. Below it the
    /// simulation *retracts* — the heuristic fired but the money didn't move.
    min_profit: MinProfit,
    /// Gas/step bounds on hostile bytecode (§7 hardening).
    limits: SimLimits,
}

impl RevmSimulator {
    /// Build an engine that confirms only bundles whose attacker profit clears
    /// `min_profit`, with the default hostile-bytecode [`SimLimits`].
    pub fn new(min_profit: MinProfit) -> Self {
        Self::with_limits(min_profit, SimLimits::default())
    }

    /// Build an engine with explicit gas/step [`SimLimits`] — the worker binary wires
    /// the operator-tuned caps here; tests pin tight caps to exercise the bounds.
    pub fn with_limits(min_profit: MinProfit, limits: SimLimits) -> Self {
        Self { min_profit, limits }
    }
}

impl Simulator for RevmSimulator {
    /// Run one scenario, wrapped in the panic sandbox: hostile bytecode that drives
    /// revm into a panic becomes poison rather than unwinding the rayon worker.
    fn simulate(&self, req: &SimulationRequest) -> Result<SimulationOutcome, SimError> {
        run_sandboxed(|| self.simulate_inner(req))
    }
}

impl RevmSimulator {
    /// The engine proper, called inside [`run_sandboxed`].
    fn simulate_inner(&self, req: &SimulationRequest) -> Result<SimulationOutcome, SimError> {
        // 1. Seed the in-memory pre-state. `EmptyDB` returns empty accounts for
        //    anything unseeded, so a tx from an unfunded caller fails validation
        //    (poison) rather than reading phantom funds.
        let mut db = CacheDB::new(EmptyDB::default());
        for acc in &req.accounts {
            let mut info = AccountInfo::from_balance(acc.balance);
            if let Some(code) = &acc.code {
                let bytecode = Bytecode::new_raw(code.clone());
                let hash = bytecode.hash_slow();
                info = info.with_code_and_hash(bytecode, hash);
            }
            db.insert_account_info(acc.address, info);
        }

        // 2. Build the EVM over the seeded state with the scenario's block env.
        let block = &req.block;
        let mut evm = Context::mainnet()
            .with_db(db)
            .modify_block_chained(|b| {
                b.number = U256::from(block.number);
                b.timestamp = U256::from(block.timestamp);
                b.basefee = block.basefee;
                b.gas_limit = block.gas_limit;
                b.beneficiary = block.beneficiary;
            })
            .build_mainnet();

        // 3. Snapshot the implicated balances before the bundle runs.
        let attacker_pre = balance_of(evm.db_ref(), req.attacker)?;
        let victim_pre = match req.victim {
            Some(v) => Some(balance_of(evm.db_ref(), v)?),
            None => None,
        };

        // 4. Replay the bundle in order, committing each tx's state so the next tx
        //    sees it. A revert/halt is a legitimate "no value extracted" outcome —
        //    only an EVM-level error (malformed tx / db fault) aborts. Hostile
        //    bytecode is bounded by the gas caps (§7): each tx's gas is clamped to
        //    `per_tx_gas` so a runaway loop halts `OutOfGas`, and the running total is
        //    held under `bundle_gas_budget` so a pathological bundle dead-letters.
        let mut bundle_gas: u64 = 0;
        for tx in &req.bundle {
            // Match the tx nonce to the caller's current nonce so the bundle isn't
            // rejected for replay protection; reads the committed state each step.
            let nonce = balance_and_nonce(evm.db_ref(), tx.caller)?.1;
            let tx_env = TxEnv {
                caller: tx.caller,
                kind: match tx.to {
                    Some(addr) => TxKind::Call(addr),
                    None => TxKind::Create,
                },
                value: tx.value,
                data: tx.data.clone(),
                // Clamp to the per-tx cap so an unbounded loop in hostile bytecode
                // halts `OutOfGas` (a valid outcome) instead of running for ever.
                gas_limit: tx.gas_limit.min(self.limits.per_tx_gas),
                gas_price: 0, // fee-free: balances reflect value flow only
                nonce,
                chain_id: None, // skip EIP-155 chain binding in simulation
                ..Default::default()
            };
            let result = evm.transact_commit(tx_env).map_err(map_evm_error)?;
            bundle_gas = bundle_gas.saturating_add(result.tx_gas_used());
            if bundle_gas > self.limits.bundle_gas_budget {
                return Err(SimError::Poison(format!(
                    "bundle exceeded gas budget ({bundle_gas} > {} gas) — abandoning \
                     hostile/pathological scenario",
                    self.limits.bundle_gas_budget
                )));
            }
        }

        // 5. Re-read balances and diff. Profit is the attacker's gain; victim loss is
        //    the victim's drop (each sign-aware so an unexpected direction is honest,
        //    not clamped).
        let attacker_post = balance_of(evm.db_ref(), req.attacker)?;
        let profit = signed_eth_delta(attacker_post, attacker_pre);
        let victim_loss = match (req.victim, victim_pre) {
            (Some(v), Some(pre)) => signed_eth_delta(pre, balance_of(evm.db_ref(), v)?),
            _ => 0.0,
        };

        let confirmed = profit > self.min_profit.get();
        Ok(SimulationOutcome {
            alert_id: req.alert_id,
            kind: req.kind,
            profit,
            victim_loss,
            confirmed,
            severity: severity_for(profit),
            txs: req.txs.clone(),
        })
    }
}

/// Read an account's balance from the (cache) database, treating an absent account
/// as zero. A backend error is transient (the forked RPC may recover).
fn balance_of<D: DatabaseRef>(db: &D, address: Address) -> Result<U256, SimError>
where
    D::Error: std::fmt::Display,
{
    Ok(balance_and_nonce(db, address)?.0)
}

/// Read an account's `(balance, nonce)`, treating an absent account as `(0, 0)`.
fn balance_and_nonce<D: DatabaseRef>(db: &D, address: Address) -> Result<(U256, u64), SimError>
where
    D::Error: std::fmt::Display,
{
    match db.basic_ref(address) {
        Ok(Some(info)) => Ok((info.balance, info.nonce)),
        Ok(None) => Ok((U256::ZERO, 0)),
        Err(err) => Err(SimError::Transient(err.to_string())),
    }
}

/// Lift a revm execution error into a [`SimError`]. Only a **database** fault is
/// transient (the forked state backend may recover); a transaction-validation /
/// header / custom failure is identical on every retry, so it's poison.
fn map_evm_error<DBErr: std::fmt::Display, TxErr: std::fmt::Display>(
    err: revm::context::result::EVMError<DBErr, TxErr>,
) -> SimError {
    use revm::context::result::EVMError;
    match err {
        EVMError::Database(e) => SimError::Transient(e.to_string()),
        EVMError::Transaction(e) => SimError::Poison(e.to_string()),
        EVMError::Header(e) => SimError::Poison(e.to_string()),
        EVMError::Custom(e) => SimError::Poison(e),
        EVMError::CustomAny(e) => SimError::Poison(e.to_string()),
    }
}

/// Run the engine inside a panic sandbox (§7 hardening). Hostile bytecode that
/// drives revm into a panic is caught and reported as **poison** — the worker
/// dead-letters it instead of the panic unwinding the rayon thread the simulation
/// runs on. `AssertUnwindSafe` is sound here because a caught panic discards the
/// half-built EVM entirely (we never read state back out of `f` on the panic path).
fn run_sandboxed<F>(f: F) -> Result<SimulationOutcome, SimError>
where
    F: FnOnce() -> Result<SimulationOutcome, SimError>,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(_) => Err(SimError::Poison(
            "revm panicked executing hostile bytecode (sandboxed)".into(),
        )),
    }
}

/// `(a - b)` in ETH, sign-aware (negative when `b > a`). `U256` subtraction can't go
/// negative, so the sign is carried explicitly.
fn signed_eth_delta(a: U256, b: U256) -> f64 {
    if a >= b {
        wei_to_eth(a - b)
    } else {
        -wei_to_eth(b - a)
    }
}

/// Convert a non-negative wei amount to ETH as `f64`. A value too large for `f64`
/// parses to infinity rather than panicking — an absurd profit surfaces as `inf`,
/// not a crash (and won't quietly clear a finite threshold the wrong way).
fn wei_to_eth(wei: U256) -> f64 {
    wei.to_string().parse::<f64>().unwrap_or(f64::INFINITY) / WEI_PER_ETH
}

/// Coarse severity from attacker profit (ETH). A **placeholder** banding, the same
/// shape as the dispatcher's confidence→priority: real severity weighs victim loss,
/// tier, and USD value (§7, §13) and is a follow-up.
fn severity_for(profit_eth: f64) -> Severity {
    match profit_eth {
        p if p >= CRITICAL_ETH => Severity::Critical,
        p if p >= HIGH_ETH => Severity::High,
        p if p >= MEDIUM_ETH => Severity::Medium,
        _ => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `n` ether as wei. `10^18` fits a `u64`, so this is exact.
    fn eth(n: u64) -> U256 {
        U256::from(n) * U256::from(1_000_000_000_000_000_000u64)
    }

    fn attacker() -> Address {
        Address::repeat_byte(0xAA)
    }
    fn victim() -> Address {
        Address::repeat_byte(0xBB)
    }

    fn request(accounts: Vec<SeededAccount>, bundle: Vec<SimTx>) -> SimulationRequest {
        SimulationRequest {
            alert_id: AlertId::new(),
            kind: AlertKind::Sandwich,
            block: BlockParams::default(),
            accounts,
            bundle,
            attacker: attacker(),
            victim: Some(victim()),
            txs: vec![B256::repeat_byte(0x01)],
        }
    }

    /// The canonical confirm: the victim sends value to the attacker; the balance
    /// diff recovers exactly the profit and the loss, and it confirms above the
    /// threshold.
    #[test]
    fn value_extraction_is_measured_and_confirmed() {
        let sim = RevmSimulator::new(MinProfit::try_new(1.0).unwrap());
        let req = request(
            vec![
                SeededAccount {
                    address: victim(),
                    balance: eth(10),
                    code: None,
                },
                SeededAccount {
                    address: attacker(),
                    balance: eth(1),
                    code: None,
                },
            ],
            vec![SimTx {
                caller: victim(),
                to: Some(attacker()),
                value: eth(5),
                data: Bytes::new(),
                gas_limit: 21_000,
            }],
        );

        let out = sim.simulate(&req).expect("simulation runs");
        assert_eq!(out.profit, 5.0, "attacker gained 5 ETH");
        assert_eq!(out.victim_loss, 5.0, "victim lost 5 ETH");
        assert!(out.confirmed, "5 ETH clears the 1 ETH threshold");
        assert_eq!(out.severity, Severity::Medium);
        assert_eq!(out.txs, req.txs);
        assert_eq!(out.alert_id, req.alert_id);
    }

    /// Below the threshold the alert is *retracted*, not confirmed — the heuristic
    /// fired but the money didn't really move.
    #[test]
    fn sub_threshold_profit_is_not_confirmed() {
        let sim = RevmSimulator::new(MinProfit::try_new(1.0).unwrap());
        let req = request(
            vec![
                SeededAccount {
                    address: victim(),
                    balance: eth(10),
                    code: None,
                },
                SeededAccount {
                    address: attacker(),
                    balance: U256::ZERO,
                    code: None,
                },
            ],
            // Half an ETH — real, but under the 1 ETH bar.
            vec![SimTx {
                caller: victim(),
                to: Some(attacker()),
                value: eth(1) / U256::from(2),
                data: Bytes::new(),
                gas_limit: 21_000,
            }],
        );

        let out = sim.simulate(&req).expect("simulation runs");
        assert_eq!(out.profit, 0.5);
        assert!(!out.confirmed);
        assert_eq!(out.severity, Severity::Low);
    }

    /// An empty bundle is a valid no-op simulation: nothing moved, nothing confirmed
    /// — not an error.
    #[test]
    fn empty_bundle_yields_zero_profit() {
        let sim = RevmSimulator::new(MinProfit::try_new(0.0).unwrap());
        let req = request(
            vec![SeededAccount {
                address: attacker(),
                balance: eth(1),
                code: None,
            }],
            vec![],
        );
        let out = sim.simulate(&req).expect("empty bundle simulates");
        assert_eq!(out.profit, 0.0);
        assert!(!out.confirmed, "0 profit does not exceed a 0 threshold");
    }

    /// A malformed tx the EVM rejects outright (caller can't cover the value) is
    /// **poison** — identical on every retry, so the worker must dead-letter it, not
    /// requeue forever. This is the classification t4's gas/step caps extend.
    #[test]
    fn unfunded_caller_is_poison_not_transient() {
        let sim = RevmSimulator::new(MinProfit::try_new(1.0).unwrap());
        // The caller is unseeded (zero balance) but tries to send 5 ETH.
        let req = request(
            vec![SeededAccount {
                address: attacker(),
                balance: U256::ZERO,
                code: None,
            }],
            vec![SimTx {
                caller: victim(), // unfunded
                to: Some(attacker()),
                value: eth(5),
                data: Bytes::new(),
                gas_limit: 21_000,
            }],
        );

        let err = sim
            .simulate(&req)
            .expect_err("an unfunded transfer is rejected");
        assert!(
            !err.is_transient(),
            "a malformed tx is poison, not transient"
        );
    }

    /// Bytecode that loops forever: `JUMPDEST; PUSH1 0; JUMP`. Each iteration burns
    /// gas (JUMPDEST 1 + PUSH1 3 + JUMP 8), so under a finite gas cap it must halt
    /// `OutOfGas` rather than spin — the per-tx cap is the step ceiling (§7).
    fn infinite_loop_code() -> Bytes {
        Bytes::from(vec![0x5b, 0x60, 0x00, 0x56])
    }

    /// A contract whose bytecode loops forever is **bounded** by the per-tx gas cap:
    /// it halts `OutOfGas`, which is a *valid* "no value extracted" outcome (profit 0,
    /// not confirmed), not an error. This is the step cap doing its job on hostile
    /// honeypot bytecode.
    #[test]
    fn per_tx_gas_cap_halts_runaway_bytecode_as_valid_outcome() {
        let honeypot = Address::repeat_byte(0xCC);
        let sim = RevmSimulator::with_limits(
            MinProfit::try_new(1.0).unwrap(),
            // A tight per-tx cap; a generous bundle budget so this exercises the
            // *per-tx* halt, not the bundle abort.
            SimLimits {
                per_tx_gas: 100_000,
                bundle_gas_budget: 90_000_000,
            },
        );
        let req = request(
            vec![
                SeededAccount {
                    address: attacker(),
                    balance: eth(1),
                    code: None,
                },
                SeededAccount {
                    address: honeypot,
                    balance: U256::ZERO,
                    code: Some(infinite_loop_code()),
                },
            ],
            // Call the honeypot; its loop would never return without the cap. The tx
            // asks for far more gas than the cap allows — the engine clamps it.
            vec![SimTx {
                caller: attacker(),
                to: Some(honeypot),
                value: U256::ZERO,
                data: Bytes::new(),
                gas_limit: 30_000_000,
            }],
        );

        let out = sim
            .simulate(&req)
            .expect("a capped runaway loop halts, it does not error");
        assert_eq!(out.profit, 0.0, "the honeypot extracted no value");
        assert!(!out.confirmed);
    }

    /// A bundle whose cumulative gas blows past the budget is **poison** — abandoned
    /// and dead-lettered, not requeued, because it fails identically every retry.
    #[test]
    fn bundle_gas_budget_exceeded_is_poison() {
        let honeypot = Address::repeat_byte(0xCC);
        let sim = RevmSimulator::with_limits(
            MinProfit::try_new(1.0).unwrap(),
            // The single capped tx burns its full 100k (it halts OutOfGas), which
            // already exceeds the 50k bundle budget.
            SimLimits {
                per_tx_gas: 100_000,
                bundle_gas_budget: 50_000,
            },
        );
        let req = request(
            vec![
                SeededAccount {
                    address: attacker(),
                    balance: eth(1),
                    code: None,
                },
                SeededAccount {
                    address: honeypot,
                    balance: U256::ZERO,
                    code: Some(infinite_loop_code()),
                },
            ],
            vec![SimTx {
                caller: attacker(),
                to: Some(honeypot),
                value: U256::ZERO,
                data: Bytes::new(),
                gas_limit: 30_000_000,
            }],
        );

        let err = sim
            .simulate(&req)
            .expect_err("blowing the gas budget aborts the simulation");
        assert!(
            !err.is_transient(),
            "a gas-budget trip is poison (deterministic), not transient"
        );
    }

    /// The panic sandbox turns a panic inside the engine into poison rather than
    /// letting it unwind the worker thread. Tested at the wrapper so it doesn't depend
    /// on coaxing revm itself into a panic.
    #[test]
    fn sandbox_maps_a_panic_to_poison() {
        let err = run_sandboxed(|| panic!("hostile bytecode tripped a panic"))
            .expect_err("a panic is caught");
        assert!(
            !err.is_transient(),
            "a caught panic is poison, not transient"
        );
    }
}
