//! Modexp conformance vectors.

use hex_literal::hex;
use openvm_accelerators::{ffi::zkvm_modexp, ops::modexp, types::ZkvmStatus};

/// BN254 Fr (the scalar field) modulus, big-endian. Not to be confused with
/// the base field prime, which shares the leading bytes.
const BN254_FR: [u8; 32] = hex!("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");

#[test]
fn modexp_small() {
    // 3^5 mod 7 = 5
    let mut output = [0xffu8; 1];
    modexp(&[3], &[5], &[7], &mut output);
    assert_eq!(output, [5]);

    // Output is left-padded to the modulus length.
    let mut output = [0xffu8; 2];
    modexp(&[3], &[5], &[0, 7], &mut output);
    assert_eq!(output, [0, 5]);

    // A zero-length modulus writes nothing.
    modexp(&[3], &[5], &[], &mut []);
}

#[test]
fn modexp_matches_reference() {
    // The BN254-Fr accelerated path, compared right-aligned against the
    // aurora reference.
    let mut output = [0xa5; 32];
    modexp(&[0xab; 32], &[0x07], &BN254_FR, &mut output);
    let reference = aurora_engine_modexp::modexp(&[0xab; 32], &[0x07], &BN254_FR);
    let mut expected = [0; 32];
    expected[32 - reference.len()..].copy_from_slice(&reference);
    assert_eq!(output, expected);

    // The generic path with a non-special modulus.
    let modulus = [0xef; 24];
    let mut output = [0xa5; 24];
    modexp(&[0x12; 40], &[0x34; 3], &modulus, &mut output);
    let reference = aurora_engine_modexp::modexp(&[0x12; 40], &[0x34; 3], &modulus);
    let mut expected = [0; 24];
    expected[24 - reference.len()..].copy_from_slice(&reference);
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
    assert_eq!(status, ZkvmStatus::Ok);
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
    assert_eq!(status, ZkvmStatus::Ok);
    assert_eq!(output, [1]);

    // A NULL pointer with a non-zero length fails.
    let status = unsafe {
        zkvm_modexp(core::ptr::null(), 1, exp.as_ptr(), 1, modulus.as_ptr(), 1, output.as_mut_ptr())
    };
    assert_eq!(status, ZkvmStatus::Fail);

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
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe {
        zkvm_modexp(base.as_ptr(), 1, exp.as_ptr(), 1, core::ptr::null(), 1, output.as_mut_ptr())
    };
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe {
        zkvm_modexp(base.as_ptr(), 1, exp.as_ptr(), 1, modulus.as_ptr(), 1, core::ptr::null_mut())
    };
    assert_eq!(status, ZkvmStatus::Fail);
}
