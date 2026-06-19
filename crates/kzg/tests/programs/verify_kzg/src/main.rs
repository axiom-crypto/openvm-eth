#![no_std]
#![no_main]

extern crate alloc;

use openvm::io::read;
use openvm_kzg::{get_kzg_settings, KzgInputs, KzgProof};
#[allow(unused_imports)] // init! macro needs it
use openvm_pairing::bls12_381::Bls12_381G1Affine;

// Init moduli, curves, and complex extensions
openvm::init!();

openvm::entry!(main);

pub fn main() {
    // Get const trusted setup from disk
    let kzg_settings = get_kzg_settings();

    let io: KzgInputs = read();

    let success = KzgProof::verify_kzg_proof(
        &io.commitment_bytes,
        &io.z_bytes,
        &io.y_bytes,
        &io.proof_bytes,
        &kzg_settings,
    )
    .unwrap();
    assert!(success);
}
