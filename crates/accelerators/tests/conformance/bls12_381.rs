//! BLS12-381 add/MSM/pairing conformance vectors.

use hex_literal::hex;
use openvm_accelerators::{
    ffi::{
        zkvm_bls12_g1_add, zkvm_bls12_g1_msm, zkvm_bls12_g2_add, zkvm_bls12_g2_msm,
        zkvm_bls12_pairing,
    },
    ops::{
        bls12_381_g1_add, bls12_381_g1_msm, bls12_381_g2_add, bls12_381_g2_msm,
        bls12_381_pairing_check,
    },
    types::{
        ZkvmBls12381G1MsmPair, ZkvmBls12381G1Point, ZkvmBls12381G2MsmPair, ZkvmBls12381G2Point,
        ZkvmBls12381PairingPair, ZkvmBls12381Scalar, ZkvmStatus,
    },
};

fn scalar(value: u8) -> ZkvmBls12381Scalar {
    let mut scalar = ZkvmBls12381Scalar { data: [0; 32] };
    scalar.data[31] = value;
    scalar
}

/// BLS12-381 G1 generator (`x || y`).
const BLS_G1_GEN: ZkvmBls12381G1Point = ZkvmBls12381G1Point {
    data: hex!(
        "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
    ),
};

/// Doubled BLS12-381 G1 generator, stripped from the EIP-2537 test-vector padding.
const BLS_G1_2GEN: ZkvmBls12381G1Point = ZkvmBls12381G1Point {
    data: hex!(
        "0572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e"
        "166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28"
    ),
};

/// BLS12-381 G2 generator in EIP-2537 order (`x_c0 || x_c1 || y_c0 || y_c1`).
const BLS_G2_GEN: ZkvmBls12381G2Point = ZkvmBls12381G2Point {
    data: hex!(
        "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
        "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
    ),
};

/// Doubled BLS12-381 G2 generator, stripped from the EIP-2537 test-vector padding.
const BLS_G2_2GEN: ZkvmBls12381G2Point = ZkvmBls12381G2Point {
    data: hex!(
        "1638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053"
        "0a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577"
        "0468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899"
        "0f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3"
    ),
};

/// BLS12-381 scalar field order minus one; multiplying by it negates a point.
const BLS_R_MINUS_1: ZkvmBls12381Scalar = ZkvmBls12381Scalar {
    data: hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
};

fn neg_g1_generator() -> ZkvmBls12381G1Point {
    let pairs = [ZkvmBls12381G1MsmPair { point: BLS_G1_GEN, scalar: BLS_R_MINUS_1 }];
    let mut output = ZkvmBls12381G1Point { data: [0; 96] };
    bls12_381_g1_msm(&pairs, &mut output).unwrap();
    output
}

#[test]
fn bls12_g1_add_msm_vectors() {
    let mut output = ZkvmBls12381G1Point { data: [0; 96] };
    bls12_381_g1_add(&BLS_G1_GEN, &BLS_G1_GEN, &mut output).unwrap();
    assert_eq!(output, BLS_G1_2GEN);

    let pairs = [ZkvmBls12381G1MsmPair { point: BLS_G1_GEN, scalar: scalar(2) }];
    output.data = [0; 96];
    bls12_381_g1_msm(&pairs, &mut output).unwrap();
    assert_eq!(output, BLS_G1_2GEN);

    output.data = [0xff; 96];
    bls12_381_g1_msm(&[], &mut output).unwrap();
    assert_eq!(output.data, [0u8; 96]);
}

#[test]
fn bls12_g2_add_msm_vectors() {
    let mut output = ZkvmBls12381G2Point { data: [0; 192] };
    bls12_381_g2_add(&BLS_G2_GEN, &BLS_G2_GEN, &mut output).unwrap();
    assert_eq!(output, BLS_G2_2GEN);

    let pairs = [ZkvmBls12381G2MsmPair { point: BLS_G2_GEN, scalar: scalar(2) }];
    output.data = [0; 192];
    bls12_381_g2_msm(&pairs, &mut output).unwrap();
    assert_eq!(output, BLS_G2_2GEN);

    output.data = [0xff; 192];
    bls12_381_g2_msm(&[], &mut output).unwrap();
    assert_eq!(output.data, [0u8; 192]);
}

#[test]
fn bls12_pairing_vectors() {
    let neg_g1 = neg_g1_generator();
    let pairs = [
        ZkvmBls12381PairingPair { g1: BLS_G1_GEN, g2: BLS_G2_GEN },
        ZkvmBls12381PairingPair { g1: neg_g1, g2: BLS_G2_GEN },
    ];
    let mut verified = false;

    bls12_381_pairing_check(&pairs, &mut verified).unwrap();
    assert!(verified);

    bls12_381_pairing_check(&pairs[..1], &mut verified).unwrap();
    assert!(!verified);

    bls12_381_pairing_check(&[], &mut verified).unwrap();
    assert!(verified);
}

#[test]
fn zkvm_bls12_add_msm_smoke() {
    let mut g1_output = ZkvmBls12381G1Point { data: [0; 96] };
    let status = unsafe { zkvm_bls12_g1_add(&BLS_G1_GEN, &BLS_G1_GEN, &mut g1_output) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert_eq!(g1_output, BLS_G1_2GEN);

    let g1_pairs = [ZkvmBls12381G1MsmPair { point: BLS_G1_GEN, scalar: scalar(2) }];
    g1_output.data = [0; 96];
    let status = unsafe { zkvm_bls12_g1_msm(g1_pairs.as_ptr(), g1_pairs.len(), &mut g1_output) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert_eq!(g1_output, BLS_G1_2GEN);

    let mut g2_output = ZkvmBls12381G2Point { data: [0; 192] };
    let status = unsafe { zkvm_bls12_g2_add(&BLS_G2_GEN, &BLS_G2_GEN, &mut g2_output) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert_eq!(g2_output, BLS_G2_2GEN);

    let g2_pairs = [ZkvmBls12381G2MsmPair { point: BLS_G2_GEN, scalar: scalar(2) }];
    g2_output.data = [0; 192];
    let status = unsafe { zkvm_bls12_g2_msm(g2_pairs.as_ptr(), g2_pairs.len(), &mut g2_output) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert_eq!(g2_output, BLS_G2_2GEN);
}

#[test]
fn zkvm_bls12_pairing_smoke() {
    let neg_g1 = neg_g1_generator();
    let pairs = [
        ZkvmBls12381PairingPair { g1: BLS_G1_GEN, g2: BLS_G2_GEN },
        ZkvmBls12381PairingPair { g1: neg_g1, g2: BLS_G2_GEN },
    ];
    let mut verified = false;

    let status = unsafe { zkvm_bls12_pairing(pairs.as_ptr(), pairs.len(), &mut verified) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert!(verified);

    let status = unsafe { zkvm_bls12_pairing(pairs.as_ptr(), 1, &mut verified) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert!(!verified);
}

#[test]
fn bls12_rejects_invalid_points() {
    let mut off_curve_g1 = BLS_G1_GEN;
    off_curve_g1.data[95] ^= 1;
    let mut g1_output = ZkvmBls12381G1Point { data: [0; 96] };
    assert!(bls12_381_g1_add(&off_curve_g1, &BLS_G1_GEN, &mut g1_output).is_err());

    let mut off_curve_g2 = BLS_G2_GEN;
    off_curve_g2.data[191] ^= 1;
    let mut g2_output = ZkvmBls12381G2Point { data: [0; 192] };
    assert!(bls12_381_g2_add(&off_curve_g2, &BLS_G2_GEN, &mut g2_output).is_err());

    let pairs = [ZkvmBls12381PairingPair { g1: off_curve_g1, g2: BLS_G2_GEN }];
    let mut verified = true;
    assert!(bls12_381_pairing_check(&pairs, &mut verified).is_err());
    assert!(!verified);
}

#[test]
fn zkvm_bls12_null_pointers() {
    let mut g1_output = ZkvmBls12381G1Point { data: [0; 96] };
    let status = unsafe { zkvm_bls12_g1_add(core::ptr::null(), &BLS_G1_GEN, &mut g1_output) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe { zkvm_bls12_g1_add(&BLS_G1_GEN, &BLS_G1_GEN, core::ptr::null_mut()) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe { zkvm_bls12_g1_msm(core::ptr::null(), 0, &mut g1_output) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert_eq!(g1_output.data, [0u8; 96]);

    let status = unsafe { zkvm_bls12_g1_msm(core::ptr::null(), 1, &mut g1_output) };
    assert_eq!(status, ZkvmStatus::Fail);

    let mut g2_output = ZkvmBls12381G2Point { data: [0; 192] };
    let status = unsafe { zkvm_bls12_g2_add(core::ptr::null(), &BLS_G2_GEN, &mut g2_output) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe { zkvm_bls12_g2_add(&BLS_G2_GEN, &BLS_G2_GEN, core::ptr::null_mut()) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe { zkvm_bls12_g2_msm(core::ptr::null(), 0, &mut g2_output) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert_eq!(g2_output.data, [0u8; 192]);

    let status = unsafe { zkvm_bls12_g2_msm(core::ptr::null(), 1, &mut g2_output) };
    assert_eq!(status, ZkvmStatus::Fail);

    let pairs = [ZkvmBls12381PairingPair { g1: BLS_G1_GEN, g2: BLS_G2_GEN }];
    let mut verified = false;

    let status = unsafe { zkvm_bls12_pairing(core::ptr::null(), 0, &mut verified) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert!(verified);

    let status = unsafe { zkvm_bls12_pairing(core::ptr::null(), 1, &mut verified) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe { zkvm_bls12_pairing(pairs.as_ptr(), pairs.len(), core::ptr::null_mut()) };
    assert_eq!(status, ZkvmStatus::Fail);
}
