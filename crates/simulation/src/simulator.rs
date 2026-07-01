//! The revm simulation engine (§7) — the CPU-bound core a worker runs each
//! `SimulationJob` on. Given a fully-described scenario (a block environment, the
//! seeded pre-state, and the confirmation [`Scenario`] to run), it re-executes
//! bundles in revm and **diffs balances** to estimate attacker profit / victim loss,
//! then decides whether the alert is confirmed (§7 "what simulation confirms").
//!
//! ## The four confirmations (§7), as one [`Scenario`] enum
//!
//! §7 names four things a simulation confirms; they are genuinely different
//! computations over the same seeded pre-state, so the request carries a [`Scenario`]
//! that the resolver picks from the alert's `AlertKind`:
//!
//! - **Attacker profit + victim loss** ([`Scenario::ValueExtraction`]) — replay the
//!   bundle once, diff the attacker's balance (profit) and the victim's (loss).
//!   Arbitrage / generic value extraction.
//! - **Counterfactual** ([`Scenario::Sandwich`]) — replay the full attack for attacker
//!   profit, then re-simulate the victim's swap *alone* (the frontrun removed) from
//!   the same pre-state and diff the victim's outcome: the loss the sandwich actually
//!   caused, not merely the victim's raw balance move.
//! - **Honeypot** ([`Scenario::Honeypot`]) — from a fresh funded address, buy the token
//!   then sell it; a buy that succeeds while the sell reverts/halts is the honeypot
//!   signature (detected from revm's per-tx `ExecutionResult`, no token accounting).
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
    /// Which of the §7 confirmations to run, and its executable inputs (bundle,
    /// implicated accounts). The resolver picks the variant from the alert's `kind`.
    pub scenario: Scenario,
    /// The on-chain tx hashes the alert implicated — the incident's `txs` (identity,
    /// not executed here; the executable bundle lives on the [`Scenario`]).
    pub txs: Vec<B256>,
}

/// How an alert is confirmed (§7 "what simulation confirms") — the strategy plus its
/// executable inputs. Each variant runs a different diff over the request's shared
/// seeded pre-state; the engine dispatches on it and every variant produces the same
/// uniform [`SimulationOutcome`].
#[derive(Debug, Clone)]
pub enum Scenario {
    /// Replay the bundle once and diff balances: the attacker's gain is the profit,
    /// the victim's drop (if the pattern names one) is the loss. Arbitrage and
    /// generic value extraction (§7 attacker profit / victim loss).
    ValueExtraction {
        /// The transactions to replay, in order.
        bundle: Vec<SimTx>,
        /// The account whose balance gain is the attacker profit.
        attacker: Address,
        /// The account whose balance drop is the victim loss, if any.
        victim: Option<Address>,
    },

    /// Sandwich **counterfactual** (§7): replay the full attack bundle for attacker
    /// profit, then re-simulate the victim's own swap in isolation — the frontrun
    /// removed — from the *same* pre-state, and take the victim's loss as how much
    /// better their swap executed without the frontrun. Measures the harm the
    /// sandwich caused, not the victim's raw balance move.
    Sandwich {
        /// The full attack: frontrun, victim swap, backrun, in order.
        bundle: Vec<SimTx>,
        /// The account whose balance gain is the attacker profit.
        attacker: Address,
        /// The sandwiched account, whose counterfactual outcome we diff.
        victim: Address,
        /// The victim's transaction(s) alone — the counterfactual bundle, replayed
        /// against the untouched pre-state (no frontrun).
        victim_swap: Vec<SimTx>,
    },

    /// **Honeypot** probe (§7): from a fresh funded address, buy the token then sell
    /// it. A buy that succeeds while the sell reverts/halts is the honeypot
    /// signature — you can get in but not out.
    Honeypot {
        /// The fresh, funded probing address whose trapped ETH is the victim loss.
        prober: Address,
        /// The buy transaction (ETH → token).
        buy: SimTx,
        /// The sell transaction (token → ETH); a honeypot makes this revert.
        sell: SimTx,
    },
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

/// The financial verdict a [`Scenario`] arm computes, before it is stamped with the
/// request's identity into a [`SimulationOutcome`]. Keeps each arm to the numbers it
/// actually decides.
struct Verdict {
    profit: f64,
    victim_loss: f64,
    confirmed: bool,
    severity: Severity,
}

/// One probed account's balance either side of a replay.
struct ProbedBalance {
    address: Address,
    pre: U256,
    post: U256,
}

/// What one bundle replay produced over a freshly-seeded pre-state: each tx's
/// execution success (for the honeypot buy/sell check) and the probed accounts'
/// before/after balances. Queried **by address** (not by position), so a caller reads
/// the account it means without tracking where it sat in the probe slice.
struct RunResult {
    tx_success: Vec<bool>,
    balances: Vec<ProbedBalance>,
}

impl RunResult {
    /// The probed account — a caller only ever asks for one it probed, so a miss is a
    /// programming error, not a runtime condition.
    fn probed(&self, address: Address) -> &ProbedBalance {
        self.balances
            .iter()
            .find(|b| b.address == address)
            .expect("queried an address that was not probed in this run")
    }

    /// ETH the account **gained** across the run (post − pre) — the attacker-profit
    /// direction. Sign-aware, so a net loss reads negative.
    fn gain(&self, address: Address) -> f64 {
        let b = self.probed(address);
        signed_eth_delta(b.post, b.pre)
    }

    /// ETH the account **lost** across the run (pre − post) — the victim-loss
    /// direction. Sign-aware, so an unexpected gain reads negative.
    fn loss(&self, address: Address) -> f64 {
        let b = self.probed(address);
        signed_eth_delta(b.pre, b.post)
    }

    /// The account's absolute balance after the run — for diffing the *same* account
    /// across two runs (the sandwich counterfactual).
    fn balance_after(&self, address: Address) -> U256 {
        self.probed(address).post
    }
}

impl RevmSimulator {
    /// The engine proper, called inside [`run_sandboxed`]. Dispatches on the
    /// scenario, each arm running one or more [`RevmSimulator::run`]s over the shared
    /// pre-state and reducing them to a [`Verdict`] (§7 "what simulation confirms").
    fn simulate_inner(&self, req: &SimulationRequest) -> Result<SimulationOutcome, SimError> {
        let verdict = match &req.scenario {
            Scenario::ValueExtraction {
                bundle,
                attacker,
                victim,
            } => self.value_extraction(&req.block, &req.accounts, bundle, *attacker, *victim)?,
            Scenario::Sandwich {
                bundle,
                attacker,
                victim,
                victim_swap,
            } => self.sandwich(
                &req.block,
                &req.accounts,
                bundle,
                *attacker,
                *victim,
                victim_swap,
            )?,
            Scenario::Honeypot { prober, buy, sell } => {
                self.honeypot(&req.block, &req.accounts, *prober, buy, sell)?
            }
        };

        Ok(SimulationOutcome {
            alert_id: req.alert_id,
            kind: req.kind,
            profit: verdict.profit,
            victim_loss: verdict.victim_loss,
            confirmed: verdict.confirmed,
            severity: verdict.severity,
            txs: req.txs.clone(),
        })
    }

    /// Build the verdict for a profit-threshold strategy (value extraction, sandwich):
    /// confirm above `min_profit`, severity from the profit band. The one home for the
    /// "did the money clear the bar" rule the two balance-diff confirmations share.
    fn profit_verdict(&self, profit: f64, victim_loss: f64) -> Verdict {
        Verdict {
            profit,
            victim_loss,
            confirmed: profit > self.min_profit.get(),
            severity: severity_for(profit),
        }
    }

    /// Attacker profit + victim loss from one replay (§7): the attacker's balance gain
    /// is the profit, the victim's drop (if named) the loss. Confirms above the profit
    /// threshold.
    fn value_extraction(
        &self,
        block: &BlockParams,
        accounts: &[SeededAccount],
        bundle: &[SimTx],
        attacker: Address,
        victim: Option<Address>,
    ) -> Result<Verdict, SimError> {
        // Probe the attacker, and the victim too when the pattern names one.
        let mut probe = vec![attacker];
        probe.extend(victim);
        let run = self.run(block, accounts, bundle, &probe)?;

        let profit = run.gain(attacker);
        let victim_loss = victim.map_or(0.0, |v| run.loss(v));
        Ok(self.profit_verdict(profit, victim_loss))
    }

    /// Sandwich counterfactual (§7): attacker profit from the full attack, victim loss
    /// from re-running the victim's swap *without* the frontrun. The loss is how much
    /// better the victim did in the counterfactual — the harm the sandwich caused.
    fn sandwich(
        &self,
        block: &BlockParams,
        accounts: &[SeededAccount],
        bundle: &[SimTx],
        attacker: Address,
        victim: Address,
        victim_swap: &[SimTx],
    ) -> Result<Verdict, SimError> {
        // The full attack: attacker profit, and the victim's balance *with* the
        // frontrun in place.
        let full = self.run(block, accounts, bundle, &[attacker, victim])?;
        let profit = full.gain(attacker);

        // The counterfactual: the victim's swap alone against the same untouched
        // pre-state (no frontrun) — the outcome they'd have had unsandwiched.
        let cf = self.run(block, accounts, victim_swap, &[victim])?;

        // The harm: how much better off the victim was without the frontrun. Positive
        // when the sandwich cost them; sign-aware so a no-harm case reads exactly 0.
        let victim_loss = signed_eth_delta(cf.balance_after(victim), full.balance_after(victim));
        Ok(self.profit_verdict(profit, victim_loss))
    }

    /// Honeypot probe (§7): buy then sell from the fresh prober. The honeypot
    /// signature is a buy that succeeds while the sell reverts/halts — read straight
    /// off revm's per-tx `ExecutionResult`, no token accounting. The prober's trapped
    /// ETH (what it put in and can't recover) is reported as the victim loss.
    fn honeypot(
        &self,
        block: &BlockParams,
        accounts: &[SeededAccount],
        prober: Address,
        buy: &SimTx,
        sell: &SimTx,
    ) -> Result<Verdict, SimError> {
        let run = self.run(block, accounts, &[buy.clone(), sell.clone()], &[prober])?;
        let bought = run.tx_success[0];
        let sold = run.tx_success[1];
        let confirmed = bought && !sold;

        // ETH the prober spent and couldn't get back out — what a victim loses to the
        // trap.
        let victim_loss = run.loss(prober);
        Ok(Verdict {
            profit: 0.0, // the probe measures a trap, not an attacker's balance gain
            victim_loss,
            confirmed,
            // Profit is 0 here so the profit bands don't apply; a confirmed honeypot is
            // treated High, unconfirmed Low. Placeholder banding, like `severity_for`.
            severity: if confirmed {
                Severity::High
            } else {
                Severity::Low
            },
        })
    }

    /// Seed a fresh `CacheDB<EmptyDB>` from `accounts`, build the mainnet EVM with
    /// `block`, snapshot the `probe` balances, replay `bundle` in order under the §7
    /// gas caps, and re-read the `probe` balances. Returns each tx's execution success
    /// plus the probed accounts' before/after balances (queried by address, not
    /// position). The whole EVM is local, so every arm gets an independent run over the
    /// same pre-state.
    fn run(
        &self,
        block: &BlockParams,
        accounts: &[SeededAccount],
        bundle: &[SimTx],
        probe: &[Address],
    ) -> Result<RunResult, SimError> {
        // Seed the in-memory pre-state. `EmptyDB` returns empty accounts for anything
        // unseeded, so a tx from an unfunded caller fails validation (poison) rather
        // than reading phantom funds.
        let mut db = CacheDB::new(EmptyDB::default());
        for acc in accounts {
            let mut info = AccountInfo::from_balance(acc.balance);
            if let Some(code) = &acc.code {
                let bytecode = Bytecode::new_raw(code.clone());
                let hash = bytecode.hash_slow();
                info = info.with_code_and_hash(bytecode, hash);
            }
            db.insert_account_info(acc.address, info);
        }

        // Build the EVM over the seeded state with the scenario's block env.
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

        // Snapshot the probed balances before the bundle runs.
        let pre = probe
            .iter()
            .map(|a| balance_of(evm.db_ref(), *a))
            .collect::<Result<Vec<_>, _>>()?;

        // Replay the bundle in order, committing each tx's state so the next tx sees
        // it. A revert/halt is a legitimate "no value extracted" outcome (recorded in
        // `tx_success`) — only an EVM-level error (malformed tx / db fault) aborts.
        // Hostile bytecode is bounded by the gas caps (§7): each tx's gas is clamped
        // to `per_tx_gas` so a runaway loop halts `OutOfGas`, and the running total is
        // held under `bundle_gas_budget` so a pathological bundle dead-letters.
        let mut tx_success = Vec::with_capacity(bundle.len());
        let mut bundle_gas: u64 = 0;
        for tx in bundle {
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
            tx_success.push(result.is_success());
            if bundle_gas > self.limits.bundle_gas_budget {
                return Err(SimError::Poison(format!(
                    "bundle exceeded gas budget ({bundle_gas} > {} gas) — abandoning \
                     hostile/pathological scenario",
                    self.limits.bundle_gas_budget
                )));
            }
        }

        // Re-read the probed balances after the bundle, and pair each with its address
        // and pre-balance so the result is queried by address rather than position.
        let balances = probe
            .iter()
            .zip(pre)
            .map(|(&address, pre)| {
                Ok(ProbedBalance {
                    address,
                    pre,
                    post: balance_of(evm.db_ref(), address)?,
                })
            })
            .collect::<Result<Vec<_>, SimError>>()?;

        Ok(RunResult {
            tx_success,
            balances,
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

    /// A value-extraction request over `bundle`, probing the canonical attacker and
    /// victim — the shape the balance-diff tests below assert against.
    fn request(accounts: Vec<SeededAccount>, bundle: Vec<SimTx>) -> SimulationRequest {
        SimulationRequest {
            alert_id: AlertId::new(),
            kind: AlertKind::Sandwich,
            block: BlockParams::default(),
            accounts,
            scenario: Scenario::ValueExtraction {
                bundle,
                attacker: attacker(),
                victim: Some(victim()),
            },
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

    // --- §7 counterfactual (sandwich) & honeypot strategies ---------------------

    fn pool() -> Address {
        Address::repeat_byte(0xDD)
    }

    /// A "pool" contract that, on any call, sends its **entire** balance to the caller
    /// (`CALL(caller, SELFBALANCE)`), then stops. Standing in for AMM liquidity: the
    /// first caller drains it, a later caller gets nothing — so a frontrun changes what
    /// the victim's swap yields, without any hand-written pricing math. A call to an
    /// already-empty pool sends 0 and still succeeds (no revert, no poison).
    fn drain_to_caller_code() -> Bytes {
        Bytes::from(vec![
            0x60, 0x00, // PUSH1 0   retSize
            0x60, 0x00, // PUSH1 0   retOffset
            0x60, 0x00, // PUSH1 0   argsSize
            0x60, 0x00, // PUSH1 0   argsOffset
            0x47, // SELFBALANCE     value
            0x33, // CALLER          addr
            0x5a, // GAS             gas
            0xf1, // CALL
            0x00, // STOP
        ])
    }

    /// The canonical sandwich counterfactual (§7): the attacker's frontrun drains the
    /// pool, so the victim's swap — replayed inside the full attack — yields nothing,
    /// while the same swap alone against the untouched pool yields 5 ETH. Victim loss
    /// is that counterfactual difference; attacker profit is what the frontrun took.
    #[test]
    fn sandwich_counterfactual_measures_the_frontrun_harm() {
        let sim = RevmSimulator::new(MinProfit::try_new(1.0).unwrap());
        let accounts = vec![
            SeededAccount {
                address: pool(),
                balance: eth(5),
                code: Some(drain_to_caller_code()),
            },
            SeededAccount {
                address: attacker(),
                balance: eth(1),
                code: None,
            },
            SeededAccount {
                address: victim(),
                balance: eth(1),
                code: None,
            },
        ];
        // The victim's own swap: call the pool to draw its liquidity.
        let victim_swap = SimTx {
            caller: victim(),
            to: Some(pool()),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 100_000,
        };
        // The full attack: the attacker frontruns the pool, then the victim swaps into
        // the now-empty pool.
        let frontrun = SimTx {
            caller: attacker(),
            to: Some(pool()),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 100_000,
        };
        let req = SimulationRequest {
            alert_id: AlertId::new(),
            kind: AlertKind::Sandwich,
            block: BlockParams::default(),
            accounts,
            scenario: Scenario::Sandwich {
                bundle: vec![frontrun, victim_swap.clone()],
                attacker: attacker(),
                victim: victim(),
                victim_swap: vec![victim_swap],
            },
            txs: vec![B256::repeat_byte(0x01)],
        };

        let out = sim.simulate(&req).expect("sandwich simulates");
        assert_eq!(out.profit, 5.0, "the frontrun drained 5 ETH from the pool");
        assert_eq!(
            out.victim_loss, 5.0,
            "the victim got 5 ETH unsandwiched but 0 with the frontrun ahead of them"
        );
        assert!(out.confirmed, "5 ETH profit clears the 1 ETH bar");
        assert_eq!(out.severity, Severity::Medium);
    }

    /// A frontrun that leaves the victim's swap untouched inflicts no counterfactual
    /// harm: the victim draws the same liquidity with or without it, so victim loss is
    /// exactly 0 (the sign-aware diff, not a clamp).
    #[test]
    fn sandwich_with_no_counterfactual_harm_is_zero_loss() {
        let sim = RevmSimulator::new(MinProfit::try_new(1.0).unwrap());
        let accounts = vec![
            SeededAccount {
                address: pool(),
                balance: eth(5),
                code: Some(drain_to_caller_code()),
            },
            SeededAccount {
                address: attacker(),
                balance: eth(1),
                code: None,
            },
            SeededAccount {
                address: victim(),
                balance: eth(1),
                code: None,
            },
        ];
        let victim_swap = SimTx {
            caller: victim(),
            to: Some(pool()),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 100_000,
        };
        // A benign "frontrun" that touches neither the pool nor the victim.
        let harmless = SimTx {
            caller: attacker(),
            to: Some(victim()),
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21_000,
        };
        let req = SimulationRequest {
            alert_id: AlertId::new(),
            kind: AlertKind::Sandwich,
            block: BlockParams::default(),
            accounts,
            scenario: Scenario::Sandwich {
                bundle: vec![harmless, victim_swap.clone()],
                attacker: attacker(),
                victim: victim(),
                victim_swap: vec![victim_swap],
            },
            txs: vec![B256::repeat_byte(0x01)],
        };

        let out = sim.simulate(&req).expect("sandwich simulates");
        assert_eq!(out.victim_loss, 0.0, "the victim's swap was unaffected");
    }

    fn prober() -> Address {
        Address::repeat_byte(0xEE)
    }
    fn token() -> Address {
        Address::repeat_byte(0xCC)
    }

    /// A honeypot token: `if CALLVALUE != 0 { STOP } else { REVERT }` — it accepts a
    /// buy (ETH in) but reverts the sell (a zero-value call). The buy/sell signature
    /// is exactly what the honeypot probe looks for.
    fn honeypot_token_code() -> Bytes {
        Bytes::from(vec![
            0x34, // CALLVALUE
            0x60, 0x09, // PUSH1 9   (buy path: the JUMPDEST below)
            0x57, // JUMPI          value != 0 → jump to STOP
            0x60, 0x00, // PUSH1 0   sell path: REVERT(0, 0)
            0x60, 0x00, // PUSH1 0
            0xfd, // REVERT
            0x5b, // JUMPDEST (offset 9)
            0x00, // STOP
        ])
    }

    fn honeypot_request(token_code: Bytes) -> SimulationRequest {
        let accounts = vec![
            SeededAccount {
                address: token(),
                balance: U256::ZERO,
                code: Some(token_code),
            },
            SeededAccount {
                address: prober(),
                balance: eth(5),
                code: None,
            },
        ];
        SimulationRequest {
            alert_id: AlertId::new(),
            kind: AlertKind::Rugpull,
            block: BlockParams::default(),
            accounts,
            scenario: Scenario::Honeypot {
                prober: prober(),
                // Buy: send 1 ETH into the token.
                buy: SimTx {
                    caller: prober(),
                    to: Some(token()),
                    value: eth(1),
                    data: Bytes::new(),
                    gas_limit: 100_000,
                },
                // Sell: a zero-value call back — a honeypot reverts here.
                sell: SimTx {
                    caller: prober(),
                    to: Some(token()),
                    value: U256::ZERO,
                    data: Bytes::new(),
                    gas_limit: 100_000,
                },
            },
            txs: vec![B256::repeat_byte(0x01)],
        }
    }

    /// Buy succeeds, sell reverts → confirmed honeypot. The 1 ETH the prober spent is
    /// trapped in the token, surfaced as the victim loss; a confirmed honeypot is High.
    #[test]
    fn honeypot_buy_ok_sell_reverts_is_confirmed() {
        let sim = RevmSimulator::new(MinProfit::try_new(1.0).unwrap());
        let out = sim
            .simulate(&honeypot_request(honeypot_token_code()))
            .expect("honeypot probe simulates");
        assert!(
            out.confirmed,
            "bought in but couldn't sell out — a honeypot"
        );
        assert_eq!(out.profit, 0.0, "the probe measures a trap, not a gain");
        assert_eq!(out.victim_loss, 1.0, "1 ETH is trapped in the token");
        assert_eq!(out.severity, Severity::High);
    }

    /// A clean token whose sell also succeeds is **not** flagged — the honeypot
    /// signature is specifically buy-ok/sell-fails.
    #[test]
    fn honeypot_clean_token_when_sell_succeeds_is_not_confirmed() {
        let sim = RevmSimulator::new(MinProfit::try_new(1.0).unwrap());
        // A token that always stops (both buy and sell succeed).
        let out = sim
            .simulate(&honeypot_request(Bytes::from(vec![0x00])))
            .expect("clean token simulates");
        assert!(!out.confirmed, "a sellable token is not a honeypot");
    }

    /// If the buy itself reverts, the prober never got in — not a honeypot (the trap
    /// needs a successful entry followed by a blocked exit).
    #[test]
    fn honeypot_when_buy_fails_is_not_confirmed() {
        let sim = RevmSimulator::new(MinProfit::try_new(1.0).unwrap());
        // A token that always reverts — the buy can't even land.
        let always_revert = Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xfd]);
        let out = sim
            .simulate(&honeypot_request(always_revert))
            .expect("a reverting buy is a valid, non-erroring outcome");
        assert!(!out.confirmed, "no successful entry → not a honeypot");
    }
}
