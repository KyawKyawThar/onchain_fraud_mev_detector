//! Historical-chain state for `revm`, backed by `chain_enrich::ArchiveRpc`.
//!
//! `revm` asks its database synchronously while executing on a rayon worker, while
//! archive RPC is async. [`ForkDb`] bridges those models only on the rayon side:
//! every read is pinned to the *parent* block hash and is cached for the life of
//! one simulation. It intentionally does not use revm's `alloydb`, which would
//! introduce alloy-provider 2.x alongside the workspace's 1.x client.

use std::collections::HashMap;
use std::sync::Mutex;

use alloy_primitives::{Address, B256, U256};
use chain_enrich::{ArchiveRpc, RpcError, StateAt};
use revm::bytecode::Bytecode;
use revm::database::DatabaseRef;
use revm::database_interface::bal::EvmDatabaseError;
use revm::primitives::KECCAK_EMPTY;
use revm::state::AccountInfo;

/// A classified archive read failure surfaced through revm's database boundary.
pub type ForkDbError = EvmDatabaseError<RpcError>;

/// Historical `DatabaseRef` over the workspace's archive-read seam.
///
/// Construct one per resolved job. Its cache is deliberately job-local: sharing it
/// across forks would make block-hash part of every cache key and risks answering a
/// reorged job from another block.
pub struct ForkDb<R> {
    rpc: R,
    state: StateAt,
    parent_number: u64,
    parent_hash: B256,
    runtime: tokio::runtime::Handle,
    accounts: Mutex<HashMap<Address, AccountInfo>>,
    codes: Mutex<HashMap<B256, Bytecode>>,
    storage: Mutex<HashMap<(Address, U256), U256>>,
}

impl<R: ArchiveRpc> ForkDb<R> {
    /// Pin all reads to the parent state of `block`. A simulation replays the
    /// block's transactions, so forking *after* it would double-apply them.
    pub fn at_parent(rpc: R, parent_number: u64, parent_hash: B256) -> Self {
        Self {
            rpc,
            state: StateAt::Block(parent_hash),
            parent_number,
            parent_hash,
            runtime: tokio::runtime::Handle::current(),
            accounts: Mutex::new(HashMap::new()),
            codes: Mutex::new(HashMap::new()),
            storage: Mutex::new(HashMap::new()),
        }
    }

    fn read<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, RpcError>>,
    ) -> Result<T, ForkDbError> {
        // `DatabaseRef` is called only by the revm rayon pool. Blocking its worker
        // is intentional: revm cannot advance until the state word arrives, and
        // keeping this out of Tokio prevents the async reactor from being pinned.
        self.runtime
            .block_on(future)
            .map_err(EvmDatabaseError::Database)
    }

    fn load_account(&self, address: Address) -> Result<AccountInfo, ForkDbError> {
        if let Some(account) = self.accounts.lock().unwrap().get(&address).cloned() {
            return Ok(account);
        }

        let balance = self.read(self.rpc.balance(address, self.state))?;
        let nonce = self.read(self.rpc.nonce(address, self.state))?;
        let code = self.read(self.rpc.code(address, self.state))?;
        let account = if code.is_empty() {
            AccountInfo {
                balance,
                nonce,
                code_hash: KECCAK_EMPTY,
                code: Some(Bytecode::default()),
                ..Default::default()
            }
        } else {
            let bytecode = Bytecode::new_raw(code);
            let code_hash = bytecode.hash_slow();
            self.codes
                .lock()
                .unwrap()
                .insert(code_hash, bytecode.clone());
            AccountInfo {
                balance,
                nonce,
                code_hash,
                code: Some(bytecode),
                ..Default::default()
            }
        };
        self.accounts
            .lock()
            .unwrap()
            .insert(address, account.clone());
        Ok(account)
    }
}

impl<R: ArchiveRpc> DatabaseRef for ForkDb<R> {
    type Error = ForkDbError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(Some(self.load_account(address)?))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self
            .codes
            .lock()
            .unwrap()
            .get(&code_hash)
            .cloned()
            .unwrap_or_default())
    }

    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        if let Some(value) = self.storage.lock().unwrap().get(&(address, slot)).copied() {
            return Ok(value);
        }
        let value = self.read(self.rpc.storage(address, slot, self.state))?;
        self.storage.lock().unwrap().insert((address, slot), value);
        Ok(value)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        // The only block hash independently guaranteed by the resolved evidence is
        // the fork parent. Returning zero for other heights matches an unavailable
        // historical BLOCKHASH rather than silently reading today's canonical chain.
        Ok(if number == self.parent_number {
            self.parent_hash
        } else {
            B256::ZERO
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::{Address, Bytes, B256, U256};
    use chain_enrich::{test_util::FakeChain, StateAt};
    use revm::database::DatabaseRef;

    use super::ForkDb;

    #[tokio::test(flavor = "multi_thread")]
    async fn reads_and_caches_historical_account_and_storage() {
        let parent = B256::repeat_byte(7);
        let address = Address::repeat_byte(3);
        let slot = U256::from(9);
        let rpc = Arc::new(FakeChain::new(1));
        rpc.set_account(
            address,
            StateAt::Block(parent),
            U256::from(42),
            5,
            Bytes::from_static(&[0x60, 0x00]),
        );
        rpc.set_storage(address, slot, StateAt::Block(parent), U256::from(99));

        let db = ForkDb::at_parent(rpc, 100, parent);
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        rayon::spawn_fifo(move || {
            let account = db.basic_ref(address).unwrap().unwrap();
            let first = db.storage_ref(address, slot).unwrap();
            let second = db.storage_ref(address, slot).unwrap();
            send.send((
                account,
                first,
                second,
                db.block_hash_ref(100).unwrap(),
                db.block_hash_ref(99).unwrap(),
            ))
            .unwrap();
        });
        let (account, first, second, parent_hash, other_hash) = receive.recv().unwrap();

        assert_eq!(account.balance, U256::from(42));
        assert_eq!(account.nonce, 5);
        assert_eq!(first, U256::from(99));
        assert_eq!(
            second, first,
            "a repeated EVM storage read is served from the job cache"
        );
        assert_eq!(parent_hash, parent);
        assert_eq!(other_hash, B256::ZERO);
    }
}
