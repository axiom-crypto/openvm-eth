//! Modexp conformance vectors.

use hex_literal::hex;
use openvm_accelerators::{zkvm_modexp, ZKVM_EFAIL, ZKVM_EOK};

/// BN254 Fr (the scalar field) modulus, big-endian. Not to be confused with
/// the base field prime, which shares the leading bytes.
const BN254_FR: [u8; 32] = hex!("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");

#[test]
fn bn254_fr_accelerated_path_matches_reference() {
    let base = [0xab; 32];
    let exp = [0x07];
    let mut output = [0; 32];
    let status = unsafe {
        zkvm_modexp(
            base.as_ptr(),
            base.len(),
            exp.as_ptr(),
            exp.len(),
            BN254_FR.as_ptr(),
            BN254_FR.len(),
            output.as_mut_ptr(),
        )
    };
    assert_eq!(status, ZKVM_EOK);
    let reference = aurora_engine_modexp::modexp(&[0xab; 32], &[0x07], &BN254_FR);
    let mut expected = [0; 32];
    expected[32 - reference.len()..].copy_from_slice(&reference);
    assert_eq!(output, expected);
}

#[test]
fn zkvm_modexp_smoke() {
    // 3^5 mod 7 = 5
    let base = [3u8];
    let exp = [5u8];
    let modulus = [7u8];
    let mut output = [0xffu8; 1];
    let status = unsafe {
        zkvm_modexp(base.as_ptr(), 1, exp.as_ptr(), 1, modulus.as_ptr(), 1, output.as_mut_ptr())
    };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(output, [5]);
}

#[test]
fn zkvm_modexp_null_pointers() {
    let base = [3u8];
    let exp = [5u8];
    let modulus = [7u8];
    let mut output = [0xffu8; 1];

    // NULL base and exp with zero lengths are empty inputs: 0^0 mod 7 = 1.
    let status = unsafe {
        zkvm_modexp(
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            modulus.as_ptr(),
            1,
            output.as_mut_ptr(),
        )
    };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(output, [1]);

    // A NULL pointer with a non-zero length fails.
    let status = unsafe {
        zkvm_modexp(core::ptr::null(), 1, exp.as_ptr(), 1, modulus.as_ptr(), 1, output.as_mut_ptr())
    };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe {
        zkvm_modexp(
            base.as_ptr(),
            1,
            core::ptr::null(),
            1,
            modulus.as_ptr(),
            1,
            output.as_mut_ptr(),
        )
    };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe {
        zkvm_modexp(base.as_ptr(), 1, exp.as_ptr(), 1, core::ptr::null(), 1, output.as_mut_ptr())
    };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe {
        zkvm_modexp(base.as_ptr(), 1, exp.as_ptr(), 1, modulus.as_ptr(), 1, core::ptr::null_mut())
    };
    assert_eq!(status, ZKVM_EFAIL);
}
