//! ECDSA over the secp256r1 (P-256) curve.

use openvm_p256::{
    ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
    EncodedPoint,
};

/// Verify an ECDSA signature over secp256r1 (P-256) against an uncompressed public key.
pub fn secp256r1_verify(msg: &[u8; 32], sig: &[u8; 64], pubkey: &[u8; 64]) -> bool {
    let encoded_point = EncodedPoint::from_untagged_bytes(&(*pubkey).into());
    let Ok(key) = VerifyingKey::from_encoded_point(&encoded_point) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(sig) else {
        return false;
    };
    key.verify_prehash(msg, &signature).is_ok()
}
