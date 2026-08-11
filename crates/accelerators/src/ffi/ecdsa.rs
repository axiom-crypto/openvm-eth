//! C ABI for the ECDSA accelerators.

use crate::{
    ops,
    types::{
        ZkvmSecp256k1Hash, ZkvmSecp256k1Pubkey, ZkvmSecp256k1Signature, ZkvmSecp256r1Hash,
        ZkvmSecp256r1Pubkey, ZkvmSecp256r1Signature, ZkvmStatus,
    },
};

/// Recover the uncompressed secp256k1 public key from an ECDSA signature
/// over `msg` into `output`.
///
/// Returns [`ZkvmStatus::Fail`] if any pointer is NULL, the signature cannot
/// be parsed, or the recovery id is invalid.
///
/// # Safety
///
/// - `msg`, if non-NULL, must be valid for reads of 32 bytes.
/// - `sig`, if non-NULL, must be valid for reads of 64 bytes.
/// - `output`, if non-NULL, must be valid for writes of 64 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_secp256k1_ecrecover(
    msg: *const ZkvmSecp256k1Hash,
    sig: *const ZkvmSecp256k1Signature,
    recid: u8,
    output: *mut ZkvmSecp256k1Pubkey,
) -> ZkvmStatus {
    if msg.is_null() || sig.is_null() || output.is_null() {
        return ZkvmStatus::Fail;
    }
    // SAFETY: the non-NULL inputs are valid for reads. Copying before writing supports overlap.
    let (msg, sig) = unsafe { (msg.read(), sig.read()) };
    let mut value = ZkvmSecp256k1Pubkey { data: [0; 64] };
    match ops::secp256k1_ecrecover(&msg, &sig, recid, &mut value) {
        Ok(()) => {
            // SAFETY: `output` is non-NULL and valid for writes.
            unsafe { output.write(value) };
            ZkvmStatus::Ok
        }
        Err(_) => ZkvmStatus::Fail,
    }
}

/// Verify an ECDSA signature over secp256k1 against an uncompressed public
/// key, writing the result to `verified`.
///
/// Returns [`ZkvmStatus::Fail`] if any pointer is NULL. Malformed or invalid
/// cryptographic inputs return [`ZkvmStatus::Ok`] with `verified == false`.
///
/// # Safety
///
/// - `msg`, if non-NULL, must be valid for reads of 32 bytes.
/// - `sig`, if non-NULL, must be valid for reads of 64 bytes.
/// - `pubkey`, if non-NULL, must be valid for reads of 64 bytes.
/// - `verified`, if non-NULL, must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_secp256k1_verify(
    msg: *const ZkvmSecp256k1Hash,
    sig: *const ZkvmSecp256k1Signature,
    pubkey: *const ZkvmSecp256k1Pubkey,
    verified: *mut bool,
) -> ZkvmStatus {
    if msg.is_null() || sig.is_null() || pubkey.is_null() || verified.is_null() {
        return ZkvmStatus::Fail;
    }
    // SAFETY: the non-NULL inputs are valid for reads.
    let (msg, sig, pubkey) = unsafe { (msg.read(), sig.read(), pubkey.read()) };
    let mut value = false;
    let _ = ops::secp256k1_verify(&msg, &sig, &pubkey, &mut value);
    // SAFETY: `verified` is non-NULL and valid for writes.
    unsafe { verified.write(value) };
    ZkvmStatus::Ok
}

/// Verify an ECDSA signature over secp256r1 (P-256) against an uncompressed
/// public key, writing the result to `verified`.
///
/// Returns [`ZkvmStatus::Fail`] if any pointer is NULL. Malformed or invalid
/// cryptographic inputs return [`ZkvmStatus::Ok`] with `verified == false`.
///
/// # Safety
///
/// - `msg`, if non-NULL, must be valid for reads of 32 bytes.
/// - `sig`, if non-NULL, must be valid for reads of 64 bytes.
/// - `pubkey`, if non-NULL, must be valid for reads of 64 bytes.
/// - `verified`, if non-NULL, must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_secp256r1_verify(
    msg: *const ZkvmSecp256r1Hash,
    sig: *const ZkvmSecp256r1Signature,
    pubkey: *const ZkvmSecp256r1Pubkey,
    verified: *mut bool,
) -> ZkvmStatus {
    if msg.is_null() || sig.is_null() || pubkey.is_null() || verified.is_null() {
        return ZkvmStatus::Fail;
    }
    // SAFETY: the non-NULL inputs are valid for reads.
    let (msg, sig, pubkey) = unsafe { (msg.read(), sig.read(), pubkey.read()) };
    let mut value = false;
    let _ = ops::secp256r1_verify(&msg, &sig, &pubkey, &mut value);
    // SAFETY: `verified` is non-NULL and valid for writes.
    unsafe { verified.write(value) };
    ZkvmStatus::Ok
}
