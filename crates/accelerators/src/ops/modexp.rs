//! Modular exponentiation with a BN254-Fr fast path.

use alloc::{vec, vec::Vec};

use openvm_ecc_guest::algebra::{ExpBytes, IntMod, Reduce};
use openvm_pairing::bn254 as bn;

/// The number of bytes needed to represent an element of BN254's scalar
/// field Fr.
const BN_SCALAR_LEN: usize = 32;

/// Compute `base^exp % modulus` into `output`, left-padded with zeros.
///
/// # Panics
///
/// Panics if `output.len() != modulus.len()`.
pub fn modexp(base: &[u8], exp: &[u8], modulus: &[u8], output: &mut [u8]) {
    assert_eq!(output.len(), modulus.len(), "output must be exactly modulus-sized");

    let result = if is_bn254_fr(modulus) {
        accelerated_modexp_bn254_fr(base, exp)
    } else {
        aurora_engine_modexp::modexp(base, exp, modulus)
    };

    // The result is numerically reduced, but its byte representation may be
    // shorter or longer (leading zeros); right-align it.
    if result.len() >= output.len() {
        output.copy_from_slice(&result[result.len() - output.len()..]);
    } else {
        let pad = output.len() - result.len();
        output[..pad].fill(0);
        output[pad..].copy_from_slice(&result);
    }
}

/// Returns true if the modulus (big-endian, possibly with leading zeros) equals BN254 Fr.
fn is_bn254_fr(modulus: &[u8]) -> bool {
    // Strip leading zeros
    let stripped = match modulus.iter().position(|&b| b != 0) {
        Some(i) => &modulus[i..],
        None => return false, // all zeros
    };
    // bn::Scalar::MODULUS is little-endian; compare against reversed input
    stripped.len() == BN_SCALAR_LEN && stripped.iter().rev().eq(bn::Scalar::MODULUS.as_ref().iter())
}

/// Accelerated modexp for BN254 Fr using field arithmetic intrinsics.
fn accelerated_modexp_bn254_fr(base: &[u8], exp: &[u8]) -> Vec<u8> {
    // OpenVM's field reduction requires inputs to be aligned to the field byte size.
    let padded_len = base.len().next_multiple_of(BN_SCALAR_LEN).max(BN_SCALAR_LEN);
    let mut padded = vec![0u8; padded_len];
    padded[padded_len - base.len()..].copy_from_slice(base);
    let base_fr = bn::Scalar::reduce_be_bytes(&padded);

    base_fr.exp_bytes(true, exp).to_be_bytes().as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BN254 Fr modulus in big-endian bytes
    fn bn254_fr_modulus_be() -> Vec<u8> {
        bn::Scalar::MODULUS.as_ref().iter().rev().copied().collect()
    }

    /// Helper: run the accelerated path and compare against the aurora
    /// reference. The accelerated path always returns BN_SCALAR_LEN bytes,
    /// so the reference output is left-padded to match.
    fn check(base: &[u8], exp: &[u8]) {
        let modulus = bn254_fr_modulus_be();
        let expected = aurora_engine_modexp::modexp(base, exp, &modulus);
        let actual = accelerated_modexp_bn254_fr(base, exp);
        let mut expected_padded = vec![0u8; BN_SCALAR_LEN];
        let offset = BN_SCALAR_LEN - expected.len();
        expected_padded[offset..].copy_from_slice(&expected);
        assert_eq!(actual, expected_padded, "base={base:?}, exp={exp:?}");
    }

    #[test]
    fn test_is_bn254_fr() {
        // Exact modulus
        assert!(is_bn254_fr(&bn254_fr_modulus_be()));

        // With leading zeros
        let mut padded = vec![0u8; 10];
        padded.extend_from_slice(&bn254_fr_modulus_be());
        assert!(is_bn254_fr(&padded));

        // All zeros → false
        assert!(!is_bn254_fr(&[0u8; 32]));

        // Wrong modulus (flip last bit)
        let mut m = bn254_fr_modulus_be();
        *m.last_mut().unwrap() ^= 1;
        assert!(!is_bn254_fr(&m));
    }

    #[test]
    fn test_accelerated_modexp_bn254_fr() {
        // --- short base (<=32 bytes), value < modulus ---
        check(&[3], &[5]); // 3^5 mod Fr
        check(&[0], &[5]); // 0^5 = 0
        check(&[3], &[0]); // 3^0 = 1
        check(&[0], &[0]); // 0^0 = 1 by convention
        check(&[], &[]); // empty inputs
        check(&[0, 0, 0, 3], &[5]); // leading zeros in base

        // --- short base, value >= modulus (triggers the reduce fallback) ---
        let m = bn254_fr_modulus_be();
        check(&m, &[1]); // Fr mod Fr = 0, so 0^1 = 0
        let mut m_plus_1 = m.clone();
        *m_plus_1.last_mut().unwrap() += 1;
        check(&m_plus_1, &[2]); // (Fr+1)^2 mod Fr = 1
        check(&[0xff; 32], &[1]); // max 256-bit value, >= modulus

        // --- large base (> 32 bytes, reduce_be_bytes path) ---
        check(&[0xab; 64], &[3]); // aligned (multiple of 32)
        check(&[0x42; 100], &[2]); // unaligned (tests the padding)
        check(&[0xab; 64], &[0xff; 32]); // large base + large exponent

        // --- larger exponents ---
        check(&[2], &[0xff; 32]); // 2^(2^256-1) mod Fr
        check(&[2], &[0, 0, 0, 5]); // leading zeros in exponent
        check(&[3], &[0xab; 64]); // exponent > 32 bytes

        // --- same value through both base-parsing code paths ---
        let base_32 = [0xab; 32];
        let mut base_33 = vec![0u8];
        base_33.extend_from_slice(&base_32);
        let exp = &[7];
        assert_eq!(
            accelerated_modexp_bn254_fr(&base_32, exp),
            accelerated_modexp_bn254_fr(&base_33, exp),
            "33-byte base with leading zero must match 32-byte base"
        );
    }
}
