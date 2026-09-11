//! Alloy signer adapter for the standard zkVM accelerator C interface.

use alloc::{boxed::Box, sync::Arc};
use core::error::Error;

use crate::status_ok;
use alloy_consensus::crypto::{
    backend::{install_default_provider, CryptoProvider},
    RecoveryError,
};
use alloy_primitives::Address;
use openvm_accelerators::{
    zkvm_keccak256, zkvm_keccak256_hash, zkvm_secp256k1_ecrecover, zkvm_secp256k1_hash,
    zkvm_secp256k1_pubkey, zkvm_secp256k1_signature, zkvm_secp256k1_verify,
};

#[derive(Debug, Default)]
struct OpenVmK256Provider;

impl CryptoProvider for OpenVmK256Provider {
    fn recover_signer_unchecked(
        &self,
        signature: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        let msg = zkvm_secp256k1_hash { data: *msg };
        let sig = zkvm_secp256k1_signature { data: signature[..64].try_into().unwrap() };
        let mut pubkey = zkvm_secp256k1_pubkey { data: [0; 64] };
        let status = unsafe { zkvm_secp256k1_ecrecover(&msg, &sig, signature[64], &mut pubkey) };
        if !status_ok(status) {
            return Err(RecoveryError::new());
        }
        Ok(address_from_pubkey(&pubkey.data))
    }

    fn verify_and_compute_signer_unchecked(
        &self,
        pubkey: &[u8; 65],
        sig: &[u8; 64],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        if pubkey[0] != 0x04 {
            return Err(RecoveryError::new());
        }
        let msg = zkvm_secp256k1_hash { data: *msg };
        let sig = zkvm_secp256k1_signature { data: *sig };
        let pubkey = zkvm_secp256k1_pubkey { data: pubkey[1..].try_into().unwrap() };
        let mut verified = false;
        let status = unsafe { zkvm_secp256k1_verify(&msg, &sig, &pubkey, &mut verified) };
        if !status_ok(status) || !verified {
            return Err(RecoveryError::new());
        }
        Ok(address_from_pubkey(&pubkey.data))
    }
}

fn address_from_pubkey(pubkey: &[u8; 64]) -> Address {
    let mut hash = zkvm_keccak256_hash { data: [0; 32] };
    let status = unsafe { zkvm_keccak256(pubkey.as_ptr(), pubkey.len(), &mut hash) };
    assert!(status_ok(status), "zkVM accelerator call failed");
    Address::from_slice(&hash.data[12..])
}

pub(super) fn install() -> Result<(), Box<dyn Error>> {
    install_default_provider(Arc::new(OpenVmK256Provider))?;
    Ok(())
}
