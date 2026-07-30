//! ECDSA over the secp256r1 (P-256) curve.

use openvm_p256::{
    ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
    EncodedPoint,
};

use crate::{
    ops::Error,
    types::{ZkvmSecp256r1Hash, ZkvmSecp256r1Pubkey, ZkvmSecp256r1Signature},
};

/// Verify an ECDSA signature over secp256r1 (P-256) against an uncompressed
/// public key, writing the result to `verified`.
pub fn secp256r1_verify(
    msg: &ZkvmSecp256r1Hash,
    sig: &ZkvmSecp256r1Signature,
    pubkey: &ZkvmSecp256r1Pubkey,
    verified: &mut bool,
) -> Result<(), Error> {
    *verified = false;

    let encoded_point = EncodedPoint::from_untagged_bytes(&pubkey.data.into());
    let key =
        VerifyingKey::from_encoded_point(&encoded_point).map_err(|_| Error::PointNotOnCurve)?;
    let signature = Signature::from_slice(&sig.data).map_err(|_| Error::InvalidSignature)?;
    *verified = key.verify_prehash(&msg.data, &signature).is_ok();
    Ok(())
}
