//! ECDSA operations.

#[cfg(any(target_os = "none", target_os = "openvm"))]
use openvm_k256 as k256;

use k256::ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, Signature, VerifyingKey};

use crate::{
    ops::Error,
    types::{
        ZkvmSecp256k1Hash, ZkvmSecp256k1Pubkey, ZkvmSecp256k1Signature, ZkvmSecp256r1Hash,
        ZkvmSecp256r1Pubkey, ZkvmSecp256r1Signature,
    },
};

/// Recover the uncompressed secp256k1 public key from an ECDSA signature
/// over `msg` into `output`.
///
/// Both low-s and high-s signatures are accepted.
pub fn secp256k1_ecrecover(
    msg: &ZkvmSecp256k1Hash,
    sig: &ZkvmSecp256k1Signature,
    mut recid: u8,
    output: &mut ZkvmSecp256k1Pubkey,
) -> Result<(), Error> {
    let mut signature = Signature::from_slice(&sig.data).map_err(|_| Error::InvalidSignature)?;
    // k256 requires a low-s signature for recovery; normalizing flips the
    // recovery id parity but recovers the same key.
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
        recid ^= 1;
    }
    let recovery_id = RecoveryId::from_byte(recid).ok_or(Error::InvalidSignature)?;

    #[cfg(any(target_os = "none", target_os = "openvm"))]
    let key =
        VerifyingKey::recover_from_prehash_noverify(&msg.data, &signature.to_bytes(), recovery_id)
            .map_err(|_| Error::InvalidSignature)?;
    #[cfg(not(any(target_os = "none", target_os = "openvm")))]
    let key = VerifyingKey::recover_from_prehash(&msg.data, &signature, recovery_id)
        .map_err(|_| Error::InvalidSignature)?;

    let point = key.to_encoded_point(false);
    output.data.copy_from_slice(&point.as_bytes()[1..65]);
    Ok(())
}

/// Verify an ECDSA signature over secp256k1 against an uncompressed public
/// key, writing the result to `verified`.
///
/// Both low-s and high-s signatures are accepted.
pub fn secp256k1_verify(
    msg: &ZkvmSecp256k1Hash,
    sig: &ZkvmSecp256k1Signature,
    pubkey: &ZkvmSecp256k1Pubkey,
    verified: &mut bool,
) -> Result<(), Error> {
    *verified = false;

    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(&pubkey.data);
    let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| Error::PointNotOnCurve)?;
    let mut signature = Signature::from_slice(&sig.data).map_err(|_| Error::InvalidSignature)?;
    // k256 rejects high-s signatures in verification. Normalize to accept both forms.
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
    }
    *verified = key.verify_prehash(&msg.data, &signature).is_ok();
    Ok(())
}

/// Verify an ECDSA signature over secp256r1 (P-256) against an uncompressed
/// public key, writing the result to `verified`.
pub fn secp256r1_verify(
    msg: &ZkvmSecp256r1Hash,
    sig: &ZkvmSecp256r1Signature,
    pubkey: &ZkvmSecp256r1Pubkey,
    verified: &mut bool,
) -> Result<(), Error> {
    use openvm_p256::{
        ecdsa::{Signature, VerifyingKey},
        EncodedPoint,
    };

    *verified = false;

    let encoded_point = EncodedPoint::from_untagged_bytes(&pubkey.data.into());
    let key =
        VerifyingKey::from_encoded_point(&encoded_point).map_err(|_| Error::PointNotOnCurve)?;
    let signature = Signature::from_slice(&sig.data).map_err(|_| Error::InvalidSignature)?;
    *verified = key.verify_prehash(&msg.data, &signature).is_ok();
    Ok(())
}
