//! C ABI for KZG point evaluation.

use crate::{
    ops,
    types::{ZkvmKzgCommitment, ZkvmKzgFieldElement, ZkvmKzgProof, ZkvmStatus},
};

/// Verify a KZG proof that the blob committed to by `commitment` evaluates
/// to `y` at point `z`, writing the result to `verified`.
///
/// Returns [`ZkvmStatus::Fail`] if any pointer is NULL or the inputs are
/// malformed; `verified` is `false` when a well-formed proof does not
/// verify.
///
/// # Safety
///
/// - `commitment` and `proof`, if non-NULL, must be valid for reads of 48 bytes.
/// - `z` and `y`, if non-NULL, must be valid for reads of 32 bytes.
/// - `verified`, if non-NULL, must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_kzg_point_eval(
    commitment: *const ZkvmKzgCommitment,
    z: *const ZkvmKzgFieldElement,
    y: *const ZkvmKzgFieldElement,
    proof: *const ZkvmKzgProof,
    verified: *mut bool,
) -> ZkvmStatus {
    if commitment.is_null() || z.is_null() || y.is_null() || proof.is_null() || verified.is_null() {
        return ZkvmStatus::Fail;
    }
    // SAFETY: non-NULL checked above; validity is guaranteed by the caller.
    let (commitment, z, y, proof, verified) =
        unsafe { (&*commitment, &*z, &*y, &*proof, &mut *verified) };
    match ops::kzg_point_eval(commitment, z, y, proof, verified) {
        Ok(()) => ZkvmStatus::Ok,
        Err(_) => ZkvmStatus::Fail,
    }
}
