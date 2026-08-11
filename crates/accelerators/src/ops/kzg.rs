//! KZG point-evaluation proof verification (EIP-4844).

use openvm_kzg::{Bytes32, Bytes48, KzgProof};

use crate::ops::Error;

/// Verify a KZG proof that the blob committed to by `commitment` evaluates
/// to `y` at point `z`.
///
/// Errors mean the check could not run — a commitment or proof that is not
/// a valid compressed G1 point, or an out-of-range field element. `Ok(false)`
/// means a well-formed proof did not verify.
pub fn kzg_point_eval(
    commitment: &[u8; 48],
    z: &[u8; 32],
    y: &[u8; 32],
    proof: &[u8; 48],
) -> Result<bool, Error> {
    let env = openvm_kzg::EnvKzgSettings::default();
    let kzg_settings = env.get();

    let commitment = Bytes48::from_slice(commitment).map_err(|_| Error::KzgInvalidInput)?;
    let z = Bytes32::from_slice(z).map_err(|_| Error::KzgInvalidInput)?;
    let y = Bytes32::from_slice(y).map_err(|_| Error::KzgInvalidInput)?;
    let proof = Bytes48::from_slice(proof).map_err(|_| Error::KzgInvalidInput)?;

    KzgProof::verify_kzg_proof(&commitment, &z, &y, &proof, kzg_settings)
        .map_err(|_| Error::KzgInvalidInput)
}
