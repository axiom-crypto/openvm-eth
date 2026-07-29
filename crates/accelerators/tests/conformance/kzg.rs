//! KZG point-evaluation conformance using the point-at-infinity commitment,
//! which commits to the zero polynomial (p(z) = 0 for every z).

use openvm_accelerators::{
    ffi::zkvm_kzg_point_eval,
    ops::{kzg_point_eval, Error},
    types::{ZkvmKzgCommitment, ZkvmKzgFieldElement, ZkvmKzgProof, ZkvmStatus},
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
    let mut verified = false;

    // The zero polynomial evaluates to 0 at every z; the infinity proof
    // attests it.
    kzg_point_eval(&commitment, &z, &scalar(0), &proof, &mut verified).unwrap();
    assert!(verified);

    // Claiming y = 1 for the zero polynomial must not verify.
    kzg_point_eval(&commitment, &z, &scalar(1), &proof, &mut verified).unwrap();
    assert!(!verified);
}

#[test]
fn kzg_point_eval_malformed_inputs() {
    let z = scalar(2);
    let y = scalar(0);
    let mut verified = true;

    // Not a valid compressed-point prefix.
    let mut garbage = ZkvmKzgCommitment { data: [0; 48] };
    garbage.data[0] = 0x01;
    let result = kzg_point_eval(&garbage, &z, &y, &infinity(), &mut verified);
    assert_eq!(result, Err(Error::KzgInvalidInput));
    assert!(!verified);

    // An out-of-range evaluation point (>= the BLS scalar field order).
    let big_z = ZkvmKzgFieldElement { data: [0xff; 32] };
    verified = true;
    let result = kzg_point_eval(&infinity(), &big_z, &y, &infinity(), &mut verified);
    assert_eq!(result, Err(Error::KzgInvalidInput));
    assert!(!verified);
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

    // Malformed inputs map to the failure status.
    let mut garbage = ZkvmKzgCommitment { data: [0; 48] };
    garbage.data[0] = 0x01;
    let status = unsafe { zkvm_kzg_point_eval(&garbage, &z, &y, &proof, &mut verified) };
    assert_eq!(status, ZkvmStatus::Fail);
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
