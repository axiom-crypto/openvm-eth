//! secp256k1 ECDSA accelerator.

#[cfg(any(target_os = "none", target_os = "openvm"))]
use openvm_k256 as k256;

use crate::types::{zkvm_status, ZkvmBytes, ZKVM_EFAIL, ZKVM_EOK};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, Signature, VerifyingKey};

pub type zkvm_secp256k1_hash = ZkvmBytes<32>;
pub type zkvm_secp256k1_signature = ZkvmBytes<64>;
pub type zkvm_secp256k1_pubkey = ZkvmBytes<64>;

/// Recover an uncompressed public key from a signature and recovery ID.
///
/// # Safety
///
/// Every non-NULL pointer must be valid for a read or write of its pointed-to type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_secp256k1_ecrecover(
    msg: *const zkvm_secp256k1_hash,
    sig: *const zkvm_secp256k1_signature,
    recid: u8,
    output: *mut zkvm_secp256k1_pubkey,
) -> zkvm_status {
    if msg.is_null() || sig.is_null() || output.is_null() {
        return ZKVM_EFAIL;
    }
    // SAFETY: the caller guarantees that the non-NULL inputs are valid for reads. Copying both
    // inputs before writing supports overlap with `output`.
    let (msg, sig) = unsafe { (msg.read(), sig.read()) };
    let Some(data) = recover(&msg.data, &sig.data, recid) else {
        return ZKVM_EFAIL;
    };
    // SAFETY: `output` is non-NULL and valid for writes.
    unsafe { output.write(zkvm_secp256k1_pubkey { data }) };
    ZKVM_EOK
}

/// Verify a signature, writing `false` for malformed or invalid cryptographic inputs.
///
/// # Safety
///
/// Every non-NULL pointer must be valid for a read or write of its pointed-to type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_secp256k1_verify(
    msg: *const zkvm_secp256k1_hash,
    sig: *const zkvm_secp256k1_signature,
    pubkey: *const zkvm_secp256k1_pubkey,
    verified: *mut bool,
) -> zkvm_status {
    if msg.is_null() || sig.is_null() || pubkey.is_null() || verified.is_null() {
        return ZKVM_EFAIL;
    }
    // SAFETY: the caller guarantees that the non-NULL inputs are valid for reads. Copying every
    // input before writing supports overlap with `verified`.
    let (msg, sig, pubkey) = unsafe { (msg.read(), sig.read(), pubkey.read()) };
    let value = verify(&msg.data, &sig.data, &pubkey.data);
    // SAFETY: `verified` is non-NULL and valid for writes.
    unsafe { verified.write(value) };
    ZKVM_EOK
}

fn recover(msg: &[u8; 32], sig: &[u8; 64], mut recid: u8) -> Option<[u8; 64]> {
    let mut signature = Signature::from_slice(sig).ok()?;
    // k256 recovery requires low-s; changing s to -s also flips the recovery-ID parity.
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
        recid ^= 1;
    }
    let recovery_id = RecoveryId::from_byte(recid)?;

    #[cfg(any(target_os = "none", target_os = "openvm"))]
    let key = VerifyingKey::recover_from_prehash_noverify(msg, &signature.to_bytes(), recovery_id)
        .ok()?;
    #[cfg(not(any(target_os = "none", target_os = "openvm")))]
    let key = VerifyingKey::recover_from_prehash(msg, &signature, recovery_id).ok()?;

    key.to_encoded_point(false).as_bytes().get(1..65)?.try_into().ok()
}

fn verify(msg: &[u8; 32], sig: &[u8; 64], pubkey: &[u8; 64]) -> bool {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(pubkey);
    let Ok(key) = VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    let Ok(mut signature) = Signature::from_slice(sig) else {
        return false;
    };
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
    }
    key.verify_prehash(msg, &signature).is_ok()
}
