//! KZG point-evaluation proof verification (EIP-4844).

use openvm_kzg::{Bytes32, Bytes48, KzgProof};

use crate::{
    ops::Error,
    types::{ZkvmKzgCommitment, ZkvmKzgFieldElement, ZkvmKzgProof},
};

/// Verify a KZG proof that the blob committed to by `commitment` evaluates
/// to `y` at point `z`, writing the result to `verified`.
///
/// Errors mean the check could not run — a commitment or proof that is not
/// a valid compressed G1 point, or an out-of-range field element; `verified`
/// is `false` only when a well-formed proof does not verify.
pub fn kzg_point_eval(
    commitment: &ZkvmKzgCommitment,
    z: &ZkvmKzgFieldElement,
    y: &ZkvmKzgFieldElement,
    proof: &ZkvmKzgProof,
    verified: &mut bool,
) -> Result<(), Error> {
    *verified = false;

    let env = openvm_kzg::EnvKzgSettings::default();
    let kzg_settings = env.get();

    let commitment = Bytes48::from_slice(&commitment.data).map_err(|_| Error::KzgInvalidInput)?;
    let z = Bytes32::from_slice(&z.data).map_err(|_| Error::KzgInvalidInput)?;
    let y = Bytes32::from_slice(&y.data).map_err(|_| Error::KzgInvalidInput)?;
    let proof = Bytes48::from_slice(&proof.data).map_err(|_| Error::KzgInvalidInput)?;

    *verified = KzgProof::verify_kzg_proof(&commitment, &z, &y, &proof, kzg_settings)
        .map_err(|_| Error::KzgInvalidInput)?;
    Ok(())
}
