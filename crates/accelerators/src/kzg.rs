//! KZG point-evaluation accelerator (EIP-4844).

use crate::types::{zkvm_status, ZkvmBytes, ZKVM_EFAIL, ZKVM_EOK};
use openvm_kzg::{Bytes32, Bytes48, KzgProof};

pub type zkvm_kzg_commitment = ZkvmBytes<48>;
pub type zkvm_kzg_proof = ZkvmBytes<48>;
pub type zkvm_kzg_field_element = ZkvmBytes<32>;

/// Verify a KZG point-evaluation proof.
///
/// # Safety
///
/// Every pointer must be non-NULL and valid for one read or write of its pointee type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkvm_kzg_point_eval(
    commitment: *const zkvm_kzg_commitment,
    z: *const zkvm_kzg_field_element,
    y: *const zkvm_kzg_field_element,
    proof: *const zkvm_kzg_proof,
    verified: *mut bool,
) -> zkvm_status {
    if commitment.is_null() || z.is_null() || y.is_null() || proof.is_null() || verified.is_null() {
        return ZKVM_EFAIL;
    }
    // SAFETY: the caller guarantees valid reads. `verified` is written only after these
    // shared borrows are no longer used, so overlapping storage is supported.
    let value = unsafe { verify(&(*commitment).data, &(*z).data, &(*y).data, &(*proof).data) }
        .unwrap_or(false);
    // SAFETY: `verified` is non-NULL and valid for writes.
    unsafe { verified.write(value) };
    ZKVM_EOK
}

fn verify(commitment: &[u8; 48], z: &[u8; 32], y: &[u8; 32], proof: &[u8; 48]) -> Result<bool, ()> {
    let commitment = Bytes48::from_slice(commitment).map_err(|_| ())?;
    let z = Bytes32::from_slice(z).map_err(|_| ())?;
    let y = Bytes32::from_slice(y).map_err(|_| ())?;
    let proof = Bytes48::from_slice(proof).map_err(|_| ())?;
    KzgProof::verify_kzg_proof(
        &commitment,
        &z,
        &y,
        &proof,
        openvm_kzg::EnvKzgSettings::default().get(),
    )
    .map_err(|_| ())
}
