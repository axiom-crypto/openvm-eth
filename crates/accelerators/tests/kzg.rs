//! KZG point-evaluation conformance using the point-at-infinity commitment,
//! which commits to the zero polynomial (p(z) = 0 for every z).

#![cfg(feature = "ffi")]

use openvm_accelerators::{
    kzg_point_eval, zkvm_kzg_point_eval, Error, ZkvmKzgCommitment, ZkvmKzgFieldElement,
    ZkvmKzgProof, ZkvmStatus,
};

/// The compressed point at infinity: 0xc0 followed by zeros.
fn infinity() -> ZkvmKzgCommitment {
    let mut point = ZkvmKzgCommitment { data: [0; 48] };
    point.data[0] = 0xc0;
    point
}

fn scalar(value: u8) -> ZkvmKzgFieldElement {
    let mut s = ZkvmKzgFieldElement { data: [0; 32] };
    s.data[31] = value;
    s
}

#[test]
fn kzg_point_eval_infinity_commitment() {
    let commitment = infinity();
    let proof: ZkvmKzgProof = infinity();
    let z = scalar(2);
    // The zero polynomial evaluates to 0 at every z; the infinity proof
    // attests it.
    assert!(kzg_point_eval(&commitment.data, &z.data, &scalar(0).data, &proof.data).unwrap());

    // Claiming y = 1 for the zero polynomial must not verify.
    assert!(!kzg_point_eval(&commitment.data, &z.data, &scalar(1).data, &proof.data).unwrap());
}

#[test]
fn kzg_point_eval_malformed_inputs() {
    let z = scalar(2);
    let y = scalar(0);
    // Not a valid compressed-point prefix.
    let mut garbage = ZkvmKzgCommitment { data: [0; 48] };
    garbage.data[0] = 0x01;
    let result = kzg_point_eval(&garbage.data, &z.data, &y.data, &infinity().data);
    assert_eq!(result, Err(Error::KzgInvalidInput));

    // An out-of-range evaluation point (>= the BLS scalar field order).
    let big_z = ZkvmKzgFieldElement { data: [0xff; 32] };
    let result = kzg_point_eval(&infinity().data, &big_z.data, &y.data, &infinity().data);
    assert_eq!(result, Err(Error::KzgInvalidInput));
}

#[test]
fn zkvm_kzg_point_eval_smoke() {
    let commitment = infinity();
    let proof: ZkvmKzgProof = infinity();
    let z = scalar(2);
    let y = scalar(0);
    let mut verified = false;

    let status = unsafe { zkvm_kzg_point_eval(&commitment, &z, &y, &proof, &mut verified) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert!(verified);

    // Malformed cryptographic inputs are a completed verification with a false result.
    let mut garbage = ZkvmKzgCommitment { data: [0; 48] };
    garbage.data[0] = 0x01;
    let status = unsafe { zkvm_kzg_point_eval(&garbage, &z, &y, &proof, &mut verified) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert!(!verified);
}

#[test]
fn zkvm_kzg_point_eval_null_pointers() {
    let commitment = infinity();
    let proof: ZkvmKzgProof = infinity();
    let z = scalar(2);
    let y = scalar(0);
    let mut verified = false;

    let status = unsafe { zkvm_kzg_point_eval(core::ptr::null(), &z, &y, &proof, &mut verified) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status =
        unsafe { zkvm_kzg_point_eval(&commitment, core::ptr::null(), &y, &proof, &mut verified) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status =
        unsafe { zkvm_kzg_point_eval(&commitment, &z, core::ptr::null(), &proof, &mut verified) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status =
        unsafe { zkvm_kzg_point_eval(&commitment, &z, &y, core::ptr::null(), &mut verified) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe { zkvm_kzg_point_eval(&commitment, &z, &y, &proof, core::ptr::null_mut()) };
    assert_eq!(status, ZkvmStatus::Fail);
}
