//! BN254 add/mul/pairing conformance vectors.

use hex_literal::hex;
use openvm_accelerators::{
    zkvm_bn254_g1_add, zkvm_bn254_g1_mul, zkvm_bn254_g1_point as ZkvmBn254G1Point,
    zkvm_bn254_g2_point as ZkvmBn254G2Point, zkvm_bn254_pairing,
    zkvm_bn254_pairing_pair as ZkvmBn254PairingPair, zkvm_bn254_scalar as ZkvmBn254Scalar,
    ZKVM_EFAIL, ZKVM_EOK,
};

fn scalar(value: u8) -> ZkvmBn254Scalar {
    let mut scalar = ZkvmBn254Scalar { data: [0; 32] };
    scalar.data[31] = value;
    scalar
}

/// BN254 generator (1, 2).
fn generator() -> ZkvmBn254G1Point {
    let mut point = ZkvmBn254G1Point { data: [0; 64] };
    point.data[31] = 1;
    point.data[63] = 2;
    point
}

/// Doubled BN254 generator, from the EIP-196 reference vectors.
const BN254_2GEN: ZkvmBn254G1Point = ZkvmBn254G1Point {
    data: hex!(
        "030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3"
        "15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4"
    ),
};

/// BN254 negated generator (1, p - 2).
const BN254_NEG_GEN: ZkvmBn254G1Point = ZkvmBn254G1Point {
    data: hex!(
        "0000000000000000000000000000000000000000000000000000000000000001"
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"
    ),
};

/// BN254 G2 generator in EIP-197 order (`x_c1 || x_c0 || y_c1 || y_c0`).
const BN254_G2_GEN: ZkvmBn254G2Point = ZkvmBn254G2Point {
    data: hex!(
        "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
        "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
        "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"
        "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"
    ),
};

#[test]
fn zkvm_bn254_add_mul_smoke() {
    let point = generator();
    let mut output = ZkvmBn254G1Point { data: [0; 64] };

    let status = unsafe { zkvm_bn254_g1_add(&point, &point, &mut output) };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(output.data, BN254_2GEN.data);

    output.data = [0; 64];
    let status = unsafe { zkvm_bn254_g1_mul(&point, &scalar(2), &mut output) };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(output.data, BN254_2GEN.data);
}

#[test]
fn zkvm_bn254_pairing_smoke() {
    let pairs = [
        ZkvmBn254PairingPair { g1: generator(), g2: BN254_G2_GEN },
        ZkvmBn254PairingPair { g1: BN254_NEG_GEN, g2: BN254_G2_GEN },
    ];
    let mut verified = false;

    let status = unsafe { zkvm_bn254_pairing(pairs.as_ptr(), pairs.len(), &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(verified);

    let status = unsafe { zkvm_bn254_pairing(pairs.as_ptr(), 1, &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(!verified);
}

#[test]
fn bn254_rejects_invalid_point() {
    let mut not_on_curve = generator();
    not_on_curve.data[63] = 3;
    let mut output = ZkvmBn254G1Point { data: [0; 64] };

    let status = unsafe { zkvm_bn254_g1_mul(&not_on_curve, &scalar(2), &mut output) };
    assert_eq!(status, ZKVM_EFAIL);

    let pairs = [ZkvmBn254PairingPair { g1: not_on_curve, g2: BN254_G2_GEN }];
    let mut verified = true;
    let status = unsafe { zkvm_bn254_pairing(pairs.as_ptr(), pairs.len(), &mut verified) };
    assert_eq!(status, ZKVM_EFAIL);
    assert!(verified);
}

#[test]
fn zkvm_bn254_null_pointers() {
    let point = generator();
    let scalar = scalar(2);
    let mut output = ZkvmBn254G1Point { data: [0; 64] };

    let status = unsafe { zkvm_bn254_g1_add(core::ptr::null(), &point, &mut output) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_bn254_g1_add(&point, core::ptr::null(), &mut output) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_bn254_g1_add(&point, &point, core::ptr::null_mut()) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_bn254_g1_mul(core::ptr::null(), &scalar, &mut output) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_bn254_g1_mul(&point, core::ptr::null(), &mut output) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_bn254_g1_mul(&point, &scalar, core::ptr::null_mut()) };
    assert_eq!(status, ZKVM_EFAIL);

    let pairs = [ZkvmBn254PairingPair { g1: point, g2: BN254_G2_GEN }];
    let mut verified = false;

    let status = unsafe { zkvm_bn254_pairing(core::ptr::null(), 0, &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(verified);

    let status = unsafe { zkvm_bn254_pairing(core::ptr::null(), 1, &mut verified) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_bn254_pairing(pairs.as_ptr(), pairs.len(), core::ptr::null_mut()) };
    assert_eq!(status, ZKVM_EFAIL);
}
