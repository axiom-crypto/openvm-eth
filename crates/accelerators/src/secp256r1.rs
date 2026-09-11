//! secp256r1 ECDSA accelerator.

use crate::types::{zkvm_status, ZkvmBytes, ZKVM_EFAIL, ZKVM_EOK};
use openvm_p256::{
    ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
    EncodedPoint,
};

pub type zkvm_secp256r1_hash = ZkvmBytes<32>;
pub type zkvm_secp256r1_signature = ZkvmBytes<64>;
pub type zkvm_secp256r1_pubkey = ZkvmBytes<64>;

/// Verify a signature, writing `false` for malformed or invalid cryptographic inputs.
///
/// # Safety
///
/// Every non-NULL pointer must be valid for a read or write of its pointed-to type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_secp256r1_verify(
    msg: *const zkvm_secp256r1_hash,
    sig: *const zkvm_secp256r1_signature,
    pubkey: *const zkvm_secp256r1_pubkey,
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

fn verify(msg: &[u8; 32], sig: &[u8; 64], pubkey: &[u8; 64]) -> bool {
    let encoded_point = EncodedPoint::from_untagged_bytes(&(*pubkey).into());
    let Ok(key) = VerifyingKey::from_encoded_point(&encoded_point) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(sig) else {
        return false;
    };
    key.verify_prehash(msg, &signature).is_ok()
}
