use alloy::{
    network::{primitives::HeaderResponse, BlockResponse, Network},
    providers::Provider,
    rpc::types::EIP1186AccountProofResponse,
    transports::TransportError,
};
use alloy_primitives::{map::B256HashMap, Address, BlockHash, StorageKey, B256, U256};
use openvm_stateless_executor::io::decode_bytecode;
use revm::{
    database::DBErrorMarker,
    primitives::KECCAK_EMPTY,
    state::{AccountInfo, Bytecode},
    Database as RevmDatabase,
};
use std::{future::IntoFuture, marker::PhantomData};
use tokio::runtime::Handle;
use tracing::{error, trace};

/// Errors returned by the [ProviderDb].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0} failed")]
    Rpc(&'static str, #[source] TransportError),
    #[error("block not found")]
    BlockNotFound,
    #[error("inconsistent RPC response: {0}")]
    InconsistentResponse(&'static str),
}

impl DBErrorMarker for Error {}

/// A [RevmDatabase] backed by an alloy [Provider].
///
/// When accessing the database, it'll use the given provider to fetch the corresponding account's
/// data. It will block the current thread to execute provider calls, Therefore, its methods
/// must *not* be executed inside an async runtime, or it will panic when trying to block. If the
/// immediate context is only synchronous, but a transitive caller is async, use
/// [tokio::task::spawn_blocking] around the calls that need to be blocked.
#[derive(Clone)]
pub struct ProviderDb<N: Network, P: Provider<N>> {
    /// Provider to fetch the data from.
    provider: P,
    /// Configuration of the provider.
    provider_config: ProviderConfig,
    /// Hash of the block on which the queries will be based.
    block: BlockHash,
    /// Handle to the Tokio runtime.
    handle: Handle,
    /// Bytecode cache to allow querying bytecode by hash instead of address.
    contracts: B256HashMap<Bytecode>,

    phantom: PhantomData<N>,
}

/// Additional configuration for a [Provider].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub(crate) struct ProviderConfig {
    /// Max number of storage keys to request in a single `eth_getProof` call.
    pub eip1186_proof_chunk_size: usize,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self { eip1186_proof_chunk_size: 1000 }
    }
}

impl<N: Network, P: Provider<N>> ProviderDb<N, P> {
    /// Creates a new AlloyDb instance, with a [Provider] and a block.
    ///
    /// This will panic if called outside the context of a Tokio runtime.
    pub(crate) fn new(provider: P, config: ProviderConfig, block_hash: BlockHash) -> Self {
        Self {
            provider,
            provider_config: config,
            block: block_hash,
            handle: Handle::current(),
            contracts: Default::default(),
            phantom: PhantomData,
        }
    }

    /// Returns the [Provider].
    pub(crate) fn provider(&self) -> &P {
        &self.provider
    }

    /// Returns the block hash used for the queries.
    pub(crate) fn block(&self) -> BlockHash {
        self.block
    }

    /// Gets the bytecode located at the corresponding [Address].
    pub(crate) fn get_code_at(&mut self, address: Address) -> Result<Bytecode, Error> {
        trace!(%address, "eth_getCode");
        let get_code = self.provider.get_code_at(address).hash(self.block);
        let code = self
            .handle
            .block_on(get_code.into_future())
            .map_err(|err| Error::Rpc("eth_getCode", err))?;

        if code.is_empty() {
            return Ok(Bytecode::new());
        }

        let bytecode = decode_bytecode(code);
        self.contracts.insert(bytecode.hash_slow(), bytecode.clone());

        Ok(bytecode)
    }

    /// Get the EIP-1186 account and storage merkle proofs.
    pub(crate) async fn get_proof(
        &self,
        address: Address,
        mut keys: Vec<StorageKey>,
    ) -> Result<EIP1186AccountProofResponse, Error> {
        trace!(%address, num_keys=keys.len(), "eth_getProof");
        let block = self.block();

        // for certain RPC nodes it seemed beneficial when the keys are in the correct order
        keys.sort_unstable();

        let mut iter = keys.chunks(self.provider_config.eip1186_proof_chunk_size);
        // always make at least one call even if the keys are empty
        let chunk_keys = iter.next().unwrap_or_default();
        let mut account_proof = self
            .provider()
            .get_proof(address, chunk_keys.into())
            .hash(block)
            .await
            .map_err(|err| {
                error!(
                    %err,
                    %address,
                    %block,
                    keys = ?chunk_keys,
                    "eth_getProof failed. Request: {{\"method\": \"eth_getProof\", \"params\": [\"{}\", {:?}, \"{}\"]}}",
                    address, chunk_keys, block
                );
                Error::Rpc("eth_getProof", err)
            })?;
        if account_proof.address != address {
            return Err(Error::InconsistentResponse("response does not match request"));
        }

        for chunk_keys in iter {
            let proof = self
                .provider()
                .get_proof(address, chunk_keys.into())
                .hash(block)
                .await
                .map_err(|err| {
                    error!(
                        %err,
                        %address,
                        %block,
                        keys = ?chunk_keys,
                        "eth_getProof failed. Request: {{\"method\": \"eth_getProof\", \"params\": [\"{}\", {:?}, \"{}\"]}}",
                        address, chunk_keys, block
                    );
                    Error::Rpc("eth_getProof", err)
                })?;
            // only the keys have changed, the account proof should not change
            if proof.account_proof != account_proof.account_proof {
                return Err(Error::InconsistentResponse(
                    "account_proof not consistent between calls",
                ));
            }

            account_proof.storage_proof.extend(proof.storage_proof);
        }

        Ok(account_proof)
    }

    /// Get the EIP-1186 account and storage merkle proofs.
    pub(crate) fn get_proof_blocking(
        &self,
        address: Address,
        keys: Vec<StorageKey>,
    ) -> Result<EIP1186AccountProofResponse, Error> {
        self.handle.block_on(self.get_proof(address, keys))
    }
}

impl<N: Network, P: Provider<N>> RevmDatabase for ProviderDb<N, P> {
    type Error = Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        trace!(%address, "getAccountInfo");
        let f = async {
            let get_nonce = self.provider.get_transaction_count(address).hash(self.block);
            let get_balance = self.provider.get_balance(address).hash(self.block);
            let get_code = self.provider.get_code_at(address).hash(self.block);

            tokio::join!(get_nonce.into_future(), get_balance.into_future(), get_code.into_future())
        };
        let (nonce, balance, code) = self.handle.block_on(f);

        let nonce = nonce.map_err(|err| Error::Rpc("eth_getTransactionCount", err))?;
        let balance = balance.map_err(|err| Error::Rpc("eth_getBalance", err))?;
        let code = code.map_err(|err| Error::Rpc("eth_getCode", err))?;
        let bytecode = decode_bytecode(code);

        // if the account is empty return None
        // in the EVM, emptiness is treated as equivalent to nonexistence
        if nonce == 0 && balance.is_zero() && bytecode.is_empty() {
            return Ok(None);
        }

        // index the code by its hash, so that we can later use code_by_hash
        let code_hash = bytecode.hash_slow();
        self.contracts.insert(code_hash, bytecode);

        Ok(Some(AccountInfo {
            nonce,
            balance,
            code_hash,
            code: None, // will be queried later using code_by_hash
            account_id: None,
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::new());
        }

        // this works because `basic` is always called first
        let code = self
            .contracts
            .get(&code_hash)
            .expect("`basic` must be called first for the corresponding account");

        Ok(code.clone())
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        trace!(%address, %index, "eth_getStorageAt");
        let storage = self
            .handle
            .block_on(self.provider.get_storage_at(address, index).hash(self.block).into_future())
            .map_err(|err| Error::Rpc("eth_getStorageAt", err))?;

        Ok(storage)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        trace!(number, "eth_getBlockByNumber");
        let block_response = self
            .handle
            .block_on(self.provider.get_block_by_number(number.into()).into_future())
            .map_err(|err| Error::Rpc("eth_getBlockByNumber", err))?;
        let block = block_response.ok_or(Error::BlockNotFound)?;

        Ok(block.header().hash())
    }
}
