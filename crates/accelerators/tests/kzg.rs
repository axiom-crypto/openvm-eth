//! KZG point-evaluation conformance.

use hex_literal::hex;
use openvm_accelerators::{
    zkvm_kzg_commitment, zkvm_kzg_field_element, zkvm_kzg_point_eval, zkvm_kzg_proof, ZKVM_EFAIL,
    ZKVM_EOK,
};

// ethereum/consensus-spec-tests:
// verify_kzg_proof_case_correct_proof_1ce8e4f69d5df899.
const COMMITMENT: [u8; 48] =
    hex!("93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878d97b05f5c8d900acf1fbbbca6f146556");
const Z: [u8; 32] = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
const Y: [u8; 32] = [0; 32];
const PROOF: [u8; 48] =
    hex!("92c51ff81dd71dab71cefecd79e8274b4b7ba36a0f40e2dc086bc4061c7f63249877db23297212991fd63e07b7ebc348");

/// The compressed point at infinity: 0xc0 followed by zeros.
fn infinity() -> zkvm_kzg_commitment {
    let mut point = zkvm_kzg_commitment { data: [0; 48] };
    point.data[0] = 0xc0;
    point
}

fn scalar(value: u8) -> zkvm_kzg_field_element {
    let mut s = zkvm_kzg_field_element { data: [0; 32] };
    s.data[31] = value;
    s
}

#[test]
fn zkvm_kzg_point_eval_smoke() {
    let commitment = zkvm_kzg_commitment { data: COMMITMENT };
    let proof = zkvm_kzg_proof { data: PROOF };
    let z = zkvm_kzg_field_element { data: Z };
    let y = zkvm_kzg_field_element { data: Y };
    let mut verified = false;

    let status = unsafe { zkvm_kzg_point_eval(&commitment, &z, &y, &proof, &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(verified);

    // Malformed cryptographic inputs are a completed verification with a false result.
    let mut garbage = zkvm_kzg_commitment { data: [0; 48] };
    garbage.data[0] = 0x01;
    let status = unsafe { zkvm_kzg_point_eval(&garbage, &z, &y, &proof, &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(!verified);
}

#[test]
fn zkvm_kzg_point_eval_null_pointers() {
    let commitment = infinity();
    let proof: zkvm_kzg_proof = infinity();
    let z = scalar(2);
    let y = scalar(0);
    let mut verified = false;

    let status = unsafe { zkvm_kzg_point_eval(core::ptr::null(), &z, &y, &proof, &mut verified) };
    assert_eq!(status, ZKVM_EFAIL);

    let status =
        unsafe { zkvm_kzg_point_eval(&commitment, core::ptr::null(), &y, &proof, &mut verified) };
    assert_eq!(status, ZKVM_EFAIL);

    let status =
        unsafe { zkvm_kzg_point_eval(&commitment, &z, core::ptr::null(), &proof, &mut verified) };
    assert_eq!(status, ZKVM_EFAIL);

    let status =
        unsafe { zkvm_kzg_point_eval(&commitment, &z, &y, core::ptr::null(), &mut verified) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_kzg_point_eval(&commitment, &z, &y, &proof, core::ptr::null_mut()) };
    assert_eq!(status, ZKVM_EFAIL);
}
