//! Modular exponentiation accelerator.

use alloc::{vec, vec::Vec};

use crate::types::{zkvm_status, ZKVM_EFAIL, ZKVM_EOK};
use openvm_ecc_guest::algebra::{ExpBytes, IntMod, Reduce};
use openvm_pairing::bn254 as bn;

const BN_SCALAR_LEN: usize = 32;

/// Compute `base^exp mod modulus`.
///
/// # Safety
///
/// Each non-empty input must be valid for its corresponding length, and `output`
/// must be valid for `mod_len` writes when `mod_len != 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_modexp(
    base: *const u8,
    base_len: usize,
    exp: *const u8,
    exp_len: usize,
    modulus: *const u8,
    mod_len: usize,
    output: *mut u8,
) -> zkvm_status {
    if (base.is_null() && base_len != 0) ||
        (exp.is_null() && exp_len != 0) ||
        (modulus.is_null() && mod_len != 0) ||
        (output.is_null() && mod_len != 0)
    {
        return ZKVM_EFAIL;
    }

    // SAFETY: non-NULL pointers and lengths were checked above; the caller guarantees validity.
    let base =
        if base_len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(base, base_len) } };
    // SAFETY: see above.
    let exp = if exp_len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(exp, exp_len) } };
    // SAFETY: see above.
    let modulus =
        if mod_len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(modulus, mod_len) } };
    let value = modexp(base, exp, modulus);
    if mod_len != 0 {
        // SAFETY: all input reads are complete and `output` is valid for `mod_len` writes.
        unsafe { core::ptr::copy_nonoverlapping(value.as_ptr(), output, mod_len) };
    }
    ZKVM_EOK
}

fn modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    let mut result = if is_bn254_fr(modulus) {
        accelerated_modexp_bn254_fr(base, exp)
    } else {
        aurora_engine_modexp::modexp(base, exp, modulus)
    };

    let output_len = modulus.len();
    match result.len().cmp(&output_len) {
        core::cmp::Ordering::Greater => {
            let start = result.len() - output_len;
            result.copy_within(start.., 0);
            result.truncate(output_len);
        }
        core::cmp::Ordering::Less => {
            let value_len = result.len();
            let padding = output_len - value_len;
            result.resize(output_len, 0);
            result.copy_within(0..value_len, padding);
            result[..padding].fill(0);
        }
        core::cmp::Ordering::Equal => {}
    }
    result
}

fn is_bn254_fr(modulus: &[u8]) -> bool {
    let stripped = match modulus.iter().position(|&byte| byte != 0) {
        Some(index) => &modulus[index..],
        None => return false,
    };
    stripped.len() == BN_SCALAR_LEN && stripped.iter().rev().eq(bn::Scalar::MODULUS.as_ref().iter())
}

fn accelerated_modexp_bn254_fr(base: &[u8], exp: &[u8]) -> Vec<u8> {
    let padded_len = base.len().next_multiple_of(BN_SCALAR_LEN).max(BN_SCALAR_LEN);
    let mut padded = vec![0u8; padded_len];
    padded[padded_len - base.len()..].copy_from_slice(base);
    let base_fr = bn::Scalar::reduce_be_bytes(&padded);
    let result = base_fr.exp_bytes(true, exp);
    result.assert_reduced();
    result.to_be_bytes().as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BN254_FR: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];

    fn check(base: &[u8], exp: &[u8]) {
        let expected = aurora_engine_modexp::modexp(base, exp, &BN254_FR);
        let actual = accelerated_modexp_bn254_fr(base, exp);
        let mut expected_padded = vec![0u8; BN_SCALAR_LEN];
        let offset = BN_SCALAR_LEN - expected.len();
        expected_padded[offset..].copy_from_slice(&expected);
        assert_eq!(actual, expected_padded, "base={base:?}, exp={exp:?}");
    }

    #[test]
    fn recognizes_bn254_fr() {
        assert!(is_bn254_fr(&BN254_FR));
        let mut padded = vec![0u8; 10];
        padded.extend_from_slice(&BN254_FR);
        assert!(is_bn254_fr(&padded));
        assert!(!is_bn254_fr(&[0u8; 32]));
        let mut wrong = BN254_FR;
        *wrong.last_mut().unwrap() ^= 1;
        assert!(!is_bn254_fr(&wrong));
    }

    #[test]
    fn accelerated_bn254_fr_matches_software() {
        for (base, exp) in [
            (&[3][..], &[5][..]),
            (&[0], &[5]),
            (&[3], &[0]),
            (&[][..], &[][..]),
            (&[0xff; 32], &[1]),
            (&[0xab; 64], &[3]),
            (&[0x42; 100], &[2]),
            (&[2], &[0xff; 32]),
        ] {
            check(base, exp);
        }
    }
}
