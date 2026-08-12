//! BLS12-381 add/MSM/pairing/map conformance vectors.

use hex_literal::hex;
use openvm_accelerators::{
    zkvm_bls12_381_fp, zkvm_bls12_381_fp2, zkvm_bls12_381_g1_msm_pair, zkvm_bls12_381_g1_point,
    zkvm_bls12_381_g2_msm_pair, zkvm_bls12_381_g2_point, zkvm_bls12_381_pairing_pair,
    zkvm_bls12_381_scalar, zkvm_bls12_g1_add, zkvm_bls12_g1_msm, zkvm_bls12_g2_add,
    zkvm_bls12_g2_msm, zkvm_bls12_map_fp2_to_g2, zkvm_bls12_map_fp_to_g1, zkvm_bls12_pairing,
    ZKVM_EFAIL, ZKVM_EOK,
};

fn scalar(value: u8) -> zkvm_bls12_381_scalar {
    let mut scalar = zkvm_bls12_381_scalar { data: [0; 32] };
    scalar.data[31] = value;
    scalar
}

/// BLS12-381 G1 generator (`x || y`).
const BLS_G1_GEN: zkvm_bls12_381_g1_point = zkvm_bls12_381_g1_point {
    data: hex!(
        "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
    ),
};

/// Doubled BLS12-381 G1 generator, stripped from the EIP-2537 test-vector padding.
const BLS_G1_2GEN: zkvm_bls12_381_g1_point = zkvm_bls12_381_g1_point {
    data: hex!(
        "0572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e"
        "166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28"
    ),
};

/// BLS12-381 G2 generator in EIP-2537 order (`x_c0 || x_c1 || y_c0 || y_c1`).
const BLS_G2_GEN: zkvm_bls12_381_g2_point = zkvm_bls12_381_g2_point {
    data: hex!(
        "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
        "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
    ),
};

/// Doubled BLS12-381 G2 generator, stripped from the EIP-2537 test-vector padding.
const BLS_G2_2GEN: zkvm_bls12_381_g2_point = zkvm_bls12_381_g2_point {
    data: hex!(
        "1638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053"
        "0a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577"
        "0468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899"
        "0f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3"
    ),
};

/// BLS12-381 scalar field order minus one; multiplying by it negates a point.
const BLS_R_MINUS_1: zkvm_bls12_381_scalar = zkvm_bls12_381_scalar {
    data: hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
};

fn neg_g1_generator() -> zkvm_bls12_381_g1_point {
    let pairs = [zkvm_bls12_381_g1_msm_pair { point: BLS_G1_GEN, scalar: BLS_R_MINUS_1 }];
    let mut output = zkvm_bls12_381_g1_point { data: [0; 96] };
    let status = unsafe { zkvm_bls12_g1_msm(pairs.as_ptr(), pairs.len(), &mut output) };
    assert_eq!(status, ZKVM_EOK);
    output
}

#[test]
fn bls12_g1_add_msm_vectors() {
    let mut output = zkvm_bls12_381_g1_point { data: [0; 96] };
    let status = unsafe { zkvm_bls12_g1_add(&BLS_G1_GEN, &BLS_G1_GEN, &mut output) };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(output.data, BLS_G1_2GEN.data);

    let pairs = [zkvm_bls12_381_g1_msm_pair { point: BLS_G1_GEN, scalar: scalar(2) }];
    output.data.fill(0);
    let status = unsafe { zkvm_bls12_g1_msm(pairs.as_ptr(), pairs.len(), &mut output) };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(output.data, BLS_G1_2GEN.data);
}

#[test]
fn bls12_g2_add_msm_vectors() {
    let mut output = zkvm_bls12_381_g2_point { data: [0; 192] };
    let status = unsafe { zkvm_bls12_g2_add(&BLS_G2_GEN, &BLS_G2_GEN, &mut output) };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(output.data, BLS_G2_2GEN.data);

    let pairs = [zkvm_bls12_381_g2_msm_pair { point: BLS_G2_GEN, scalar: scalar(2) }];
    output.data.fill(0);
    let status = unsafe { zkvm_bls12_g2_msm(pairs.as_ptr(), pairs.len(), &mut output) };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(output.data, BLS_G2_2GEN.data);
}

#[test]
fn bls12_pairing_vectors() {
    let neg_g1 = neg_g1_generator();
    let pairs = [
        zkvm_bls12_381_pairing_pair { g1: BLS_G1_GEN, g2: BLS_G2_GEN },
        zkvm_bls12_381_pairing_pair { g1: neg_g1, g2: BLS_G2_GEN },
    ];
    let mut verified = false;

    let status = unsafe { zkvm_bls12_pairing(pairs.as_ptr(), pairs.len(), &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(verified);

    let status = unsafe { zkvm_bls12_pairing(pairs.as_ptr(), 1, &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(!verified);
}

#[test]
fn bls12_rejects_invalid_points() {
    let mut off_curve_g1 = BLS_G1_GEN;
    off_curve_g1.data[95] ^= 1;
    let mut g1_output = zkvm_bls12_381_g1_point { data: [0; 96] };
    let status = unsafe { zkvm_bls12_g1_add(&off_curve_g1, &BLS_G1_GEN, &mut g1_output) };
    assert_eq!(status, ZKVM_EFAIL);

    let mut off_curve_g2 = BLS_G2_GEN;
    off_curve_g2.data[191] ^= 1;
    let mut g2_output = zkvm_bls12_381_g2_point { data: [0; 192] };
    let status = unsafe { zkvm_bls12_g2_add(&off_curve_g2, &BLS_G2_GEN, &mut g2_output) };
    assert_eq!(status, ZKVM_EFAIL);

    let pairs = [zkvm_bls12_381_pairing_pair { g1: off_curve_g1, g2: BLS_G2_GEN }];
    let mut verified = true;
    let status = unsafe { zkvm_bls12_pairing(pairs.as_ptr(), pairs.len(), &mut verified) };
    assert_eq!(status, ZKVM_EFAIL);
    assert!(verified);
}

#[test]
fn zkvm_bls12_null_pointers() {
    let mut g1_output = zkvm_bls12_381_g1_point { data: [0; 96] };
    let status = unsafe { zkvm_bls12_g1_add(core::ptr::null(), &BLS_G1_GEN, &mut g1_output) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_bls12_g1_add(&BLS_G1_GEN, &BLS_G1_GEN, core::ptr::null_mut()) };
    assert_eq!(status, ZKVM_EFAIL);

    g1_output.data.fill(0xff);
    let status = unsafe { zkvm_bls12_g1_msm(core::ptr::null(), 0, &mut g1_output) };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(g1_output.data, [0u8; 96]);

    let status = unsafe { zkvm_bls12_g1_msm(core::ptr::null(), 1, &mut g1_output) };
    assert_eq!(status, ZKVM_EFAIL);

    let mut g2_output = zkvm_bls12_381_g2_point { data: [0; 192] };
    let status = unsafe { zkvm_bls12_g2_add(core::ptr::null(), &BLS_G2_GEN, &mut g2_output) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_bls12_g2_add(&BLS_G2_GEN, &BLS_G2_GEN, core::ptr::null_mut()) };
    assert_eq!(status, ZKVM_EFAIL);

    g2_output.data.fill(0xff);
    let status = unsafe { zkvm_bls12_g2_msm(core::ptr::null(), 0, &mut g2_output) };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(g2_output.data, [0u8; 192]);

    let status = unsafe { zkvm_bls12_g2_msm(core::ptr::null(), 1, &mut g2_output) };
    assert_eq!(status, ZKVM_EFAIL);

    let pairs = [zkvm_bls12_381_pairing_pair { g1: BLS_G1_GEN, g2: BLS_G2_GEN }];
    let mut verified = false;

    let status = unsafe { zkvm_bls12_pairing(core::ptr::null(), 0, &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(verified);

    let status = unsafe { zkvm_bls12_pairing(core::ptr::null(), 1, &mut verified) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_bls12_pairing(pairs.as_ptr(), pairs.len(), core::ptr::null_mut()) };
    assert_eq!(status, ZKVM_EFAIL);
}

/* ============================================================================
 * Map to curve
 * ============================================================================ */

/// Official EIP-2537 vectors for MAP_FP_TO_G1, from https://github.com/ethereum/EIPs/blob/master/assets/eip-2537/map_fp_to_G1_bls.json
const MAP_FP_TO_G1_VECTORS: [([u8; 48], [u8; 96]); 2] = [
    // "bls_g1map_"
    (
        hex!("156c8a6a2c184569d69a76be144b5cdc5141d2d2ca4fe341f011e25e3969c55ad9e9b9ce2eb833c81a908e5fa4ac5f03"),
        hex!(
            "184bb665c37ff561a89ec2122dd343f20e0f4cbcaec84e3c3052ea81d1834e192c426074b02ed3dca4e7676ce4ce48ba"
            "04407b8d35af4dacc809927071fc0405218f1401a6d15af775810e4e460064bcc9468beeba82fdc751be70476c888bf3"
        ),
    ),
    // "bls_g1map_616263"
    (
        hex!("147e1ed29f06e4c5079b9d14fc89d2820d32419b990c1c7bb7dbea2a36a045124b31ffbde7c99329c05c559af1c6cc82"),
        hex!(
            "009769f3ab59bfd551d53a5f846b9984c59b97d6842b20a2c565baa167945e3d026a3755b6345df8ec7e6acb6868ae6d"
            "1532c00cf61aa3d0ce3e5aa20c3b531a2abd2c770a790a2613818303c6b830ffc0ecf6c357af3317b9575c567f11cd2c"
        ),
    ),
];

/// Official EIP-2537 vectors for MAP_FP2_TO_G2, from https://github.com/ethereum/EIPs/blob/master/assets/eip-2537/map_fp2_to_G2_bls.json
const MAP_FP2_TO_G2_VECTORS: [([u8; 96], [u8; 192]); 2] = [
    // "bls_g2map_"
    (
        hex!(
            "07355d25caf6e7f2f0cb2812ca0e513bd026ed09dda65b177500fa31714e09ea0ded3a078b526bed3307f804d4b93b04"
            "02829ce3c021339ccb5caf3e187f6370e1e2a311dec9b75363117063ab2015603ff52c3d3b98f19c2f65575e99e8b78c"
        ),
        hex!(
            "00e7f4568a82b4b7dc1f14c6aaa055edf51502319c723c4dc2688c7fe5944c213f510328082396515734b6612c4e7bb7"
            "126b855e9e69b1f691f816e48ac6977664d24d99f8724868a184186469ddfd4617367e94527d4b74fc86413483afb35b"
            "0caead0fd7b6176c01436833c79d305c78be307da5f6af6c133c47311def6ff1e0babf57a0fb5539fce7ee12407b0a42"
            "1498aadcf7ae2b345243e281ae076df6de84455d766ab6fcdaad71fab60abb2e8b980a440043cd305db09d283c895e3d"
        ),
    ),
    // "bls_g2map_616263"
    (
        hex!(
            "138879a9559e24cecee8697b8b4ad32cced053138ab913b99872772dc753a2967ed50aabc907937aefb2439ba06cc50c"
            "0a1ae7999ea9bab1dcc9ef8887a6cb6e8f1e22566015428d220b7eec90ffa70ad1f624018a9ad11e78d588bd3617f9f2"
        ),
        hex!(
            "108ed59fd9fae381abfd1d6bce2fd2fa220990f0f837fa30e0f27914ed6e1454db0d1ee957b219f61da6ff8be0d6441f"
            "0296238ea82c6d4adb3c838ee3cb2346049c90b96d602d7bb1b469b905c9228be25c627bffee872def773d5b2a2eb57d"
            "033f90f6057aadacae7963b0a0b379dd46750c1c94a6357c99b65f63b79e321ff50fe3053330911c56b6ceea08fee656"
            "153606c417e59fb331b7ae6bce4fbf7c5190c33ce9402b5ebe2b70e44fca614f3f1382a3625ed5493843d0b0a652fc3f"
        ),
    ),
];

/// The largest canonical field element.
const BLS_FP_MAX: [u8; 48] =
    hex!("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa");

/// The base field modulus itself, which is not a canonical field element.
const BLS_FP_MODULUS: [u8; 48] =
    hex!("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");

#[test]
fn bls12_map_fp_to_g1_vectors() {
    for (input, expected) in MAP_FP_TO_G1_VECTORS {
        let field_element = zkvm_bls12_381_fp { data: input };
        let mut output = zkvm_bls12_381_g1_point { data: [0; 96] };
        let status = unsafe { zkvm_bls12_map_fp_to_g1(&field_element, &mut output) };
        assert_eq!(status, ZKVM_EOK, "input={input:?}");
        assert_eq!(output.data, expected, "input={input:?}");
    }
}

#[test]
fn bls12_map_fp2_to_g2_vectors() {
    for (input, expected) in MAP_FP2_TO_G2_VECTORS {
        let field_element = zkvm_bls12_381_fp2 { data: input };
        let mut output = zkvm_bls12_381_g2_point { data: [0; 192] };
        let status = unsafe { zkvm_bls12_map_fp2_to_g2(&field_element, &mut output) };
        assert_eq!(status, ZKVM_EOK, "input={input:?}");
        assert_eq!(output.data, expected, "input={input:?}");
    }
}

/// Mapped points must be valid members of the prime-order subgroup.
///
/// MSM re-parses the point and validates subgroup membership, so this is an
/// independent check that the cofactor was cleared; multiplying by one must
/// return the point itself.
#[test]
fn bls12_map_lands_in_prime_order_subgroup() {
    let fp = zkvm_bls12_381_fp { data: MAP_FP_TO_G1_VECTORS[0].0 };
    let mut mapped_g1 = zkvm_bls12_381_g1_point { data: [0; 96] };
    let status = unsafe { zkvm_bls12_map_fp_to_g1(&fp, &mut mapped_g1) };
    assert_eq!(status, ZKVM_EOK);

    let pairs = [zkvm_bls12_381_g1_msm_pair { point: mapped_g1, scalar: scalar(1) }];
    let mut output_g1 = zkvm_bls12_381_g1_point { data: [0; 96] };
    let status = unsafe { zkvm_bls12_g1_msm(pairs.as_ptr(), pairs.len(), &mut output_g1) };
    assert_eq!(status, ZKVM_EOK, "mapped G1 point must pass the subgroup check");
    assert_eq!(output_g1.data, mapped_g1.data);

    let fp2 = zkvm_bls12_381_fp2 { data: MAP_FP2_TO_G2_VECTORS[0].0 };
    let mut mapped_g2 = zkvm_bls12_381_g2_point { data: [0; 192] };
    let status = unsafe { zkvm_bls12_map_fp2_to_g2(&fp2, &mut mapped_g2) };
    assert_eq!(status, ZKVM_EOK);

    let pairs = [zkvm_bls12_381_g2_msm_pair { point: mapped_g2, scalar: scalar(1) }];
    let mut output_g2 = zkvm_bls12_381_g2_point { data: [0; 192] };
    let status = unsafe { zkvm_bls12_g2_msm(pairs.as_ptr(), pairs.len(), &mut output_g2) };
    assert_eq!(status, ZKVM_EOK, "mapped G2 point must pass the subgroup check");
    assert_eq!(output_g2.data, mapped_g2.data);
}

#[test]
fn bls12_map_field_element_range() {
    // The largest canonical element is accepted, the modulus itself is not.
    let mut output = zkvm_bls12_381_g1_point { data: [0; 96] };
    let field_element = zkvm_bls12_381_fp { data: BLS_FP_MAX };
    let status = unsafe { zkvm_bls12_map_fp_to_g1(&field_element, &mut output) };
    assert_eq!(status, ZKVM_EOK);

    for input in [BLS_FP_MODULUS, [0xff; 48]] {
        let field_element = zkvm_bls12_381_fp { data: input };
        let status = unsafe { zkvm_bls12_map_fp_to_g1(&field_element, &mut output) };
        assert_eq!(status, ZKVM_EFAIL);
    }

    // Either half of an Fp2 input is checked.
    let mut g2 = zkvm_bls12_381_g2_point { data: [0; 192] };
    for modulus_offset in [0, 48] {
        let mut input = [0; 96];
        input[modulus_offset..modulus_offset + 48].copy_from_slice(&BLS_FP_MODULUS);
        let field_element = zkvm_bls12_381_fp2 { data: input };
        let status = unsafe { zkvm_bls12_map_fp2_to_g2(&field_element, &mut g2) };
        assert_eq!(status, ZKVM_EFAIL);
    }
}

#[test]
fn zkvm_bls12_map_null_pointers() {
    let field_element = zkvm_bls12_381_fp { data: MAP_FP_TO_G1_VECTORS[0].0 };
    let mut g1 = zkvm_bls12_381_g1_point { data: [0; 96] };
    let status = unsafe { zkvm_bls12_map_fp_to_g1(core::ptr::null(), &mut g1) };
    assert_eq!(status, ZKVM_EFAIL);
    let status = unsafe { zkvm_bls12_map_fp_to_g1(&field_element, core::ptr::null_mut()) };
    assert_eq!(status, ZKVM_EFAIL);

    let field_element = zkvm_bls12_381_fp2 { data: MAP_FP2_TO_G2_VECTORS[0].0 };
    let mut g2 = zkvm_bls12_381_g2_point { data: [0; 192] };
    let status = unsafe { zkvm_bls12_map_fp2_to_g2(core::ptr::null(), &mut g2) };
    assert_eq!(status, ZKVM_EFAIL);
    let status = unsafe { zkvm_bls12_map_fp2_to_g2(&field_element, core::ptr::null_mut()) };
    assert_eq!(status, ZKVM_EFAIL);
}
