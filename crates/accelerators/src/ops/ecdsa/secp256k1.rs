//! ECDSA over the secp256k1 curve.

// In the guest, secp256k1 operations use the OpenVM-accelerated k256; on
// the host they use upstream RustCrypto k256 (the ECDSA recovery
// relies on zkVM hints and is unimplemented outside the guest).
#[cfg(any(target_os = "none", target_os = "openvm"))]
use openvm_k256 as k256;

use k256::ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, Signature, VerifyingKey};

use crate::ops::Error;

/// Recover the uncompressed secp256k1 public key from an ECDSA signature
/// over `msg`.
///
/// Both low-s and high-s signatures are accepted.
pub fn secp256k1_ecrecover(
    msg: &[u8; 32],
    sig: &[u8; 64],
    mut recid: u8,
) -> Result<[u8; 64], Error> {
    let mut signature = Signature::from_slice(sig).map_err(|_| Error::InvalidSignature)?;
    // k256 requires a low-s signature for recovery; normalizing flips the
    // recovery id parity but recovers the same key.
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
        recid ^= 1;
    }
    let recovery_id = RecoveryId::from_byte(recid).ok_or(Error::InvalidSignature)?;

    #[cfg(any(target_os = "none", target_os = "openvm"))]
    let key = VerifyingKey::recover_from_prehash_noverify(msg, &signature.to_bytes(), recovery_id)
        .map_err(|_| Error::InvalidSignature)?;
    #[cfg(not(any(target_os = "none", target_os = "openvm")))]
    let key = VerifyingKey::recover_from_prehash(msg, &signature, recovery_id)
        .map_err(|_| Error::InvalidSignature)?;

    let point = key.to_encoded_point(false);
    Ok(point.as_bytes()[1..65].try_into().unwrap())
}

/// Verify an ECDSA signature over secp256k1 against an uncompressed public key.
///
/// Both low-s and high-s signatures are accepted.
pub fn secp256k1_verify(msg: &[u8; 32], sig: &[u8; 64], pubkey: &[u8; 64]) -> bool {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(pubkey);
    let Ok(key) = VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    let Ok(mut signature) = Signature::from_slice(sig) else {
        return false;
    };
    // k256 rejects high-s signatures in verification. Normalize to accept both forms.
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
    }
    key.verify_prehash(msg, &signature).is_ok()
}
