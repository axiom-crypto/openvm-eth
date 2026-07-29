//! C ABI for the ECDSA accelerators.

use crate::{
    ops,
    types::{ZkvmSecp256k1Hash, ZkvmSecp256k1Pubkey, ZkvmSecp256k1Signature, ZkvmStatus},
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
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let (msg, sig, output) = unsafe { (&*msg, &*sig, &mut *output) };
    match ops::secp256k1_ecrecover(msg, sig, recid, output) {
        Ok(()) => ZkvmStatus::Ok,
        Err(_) => ZkvmStatus::Fail,
    }
}

/// Verify an ECDSA signature over secp256k1 against an uncompressed public
/// key, writing the result to `verified`.
///
/// Returns [`ZkvmStatus::Fail`] if any pointer is NULL or the inputs are
/// malformed; `verified` is `false` when a well-formed signature does not
/// verify.
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
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let (msg, sig, pubkey, verified) = unsafe { (&*msg, &*sig, &*pubkey, &mut *verified) };
    match ops::secp256k1_verify(msg, sig, pubkey, verified) {
        Ok(()) => ZkvmStatus::Ok,
        Err(_) => ZkvmStatus::Fail,
    }
}
