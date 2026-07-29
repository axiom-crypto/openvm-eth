//! Modexp conformance vectors.

use hex_literal::hex;
use openvm_accelerators::ops::modexp;

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
    let mut output = [0u8; 32];
    modexp(&[0xab; 32], &[0x07], &BN254_FR, &mut output);
    let reference = aurora_engine_modexp::modexp(&[0xab; 32], &[0x07], &BN254_FR);
    assert_eq!(output[32 - reference.len()..], reference[..]);

    // The generic path with a non-special modulus.
    let modulus = [0xef; 24];
    let mut output = [0u8; 24];
    modexp(&[0x12; 40], &[0x34; 3], &modulus, &mut output);
    let reference = aurora_engine_modexp::modexp(&[0x12; 40], &[0x34; 3], &modulus);
    assert_eq!(output[24 - reference.len()..], reference[..]);
}
