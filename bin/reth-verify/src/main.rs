use std::{fs, path::PathBuf};

use clap::Parser;
use eyre::{eyre, Result, WrapErr};
use openvm_circuit::system::memory::{merkle::public_values::UserPublicValuesProof, CHUNK};
use openvm_stark_sdk::{
    config::baby_bear_poseidon2::{BabyBearPoseidon2Config as SC, F},
    openvm_stark_backend::proof::Proof,
};
use openvm_verify_stark_host::{
    verify_vm_stark_proof_decoded,
    vk::{read_vk_from_file, VmStarkVerifyingKey},
    VmStarkProof,
};

const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Verify a STARK final proof using only a cached VM verifying key bundle"
)]
struct Args {
    /// Path to the copied STARK final proof file.
    #[arg(long)]
    proof: PathBuf,

    /// Path to a cached VM verifying key bundle.
    #[arg(long)]
    vm_vk: PathBuf,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct StarkProofWithPublicValue<Field> {
    proof: Proof<SC>,
    user_public_values: Option<UserPublicValuesProof<CHUNK, Field>>,
}

fn decode_persisted_final_proof_bytes(path: &PathBuf, proof_bytes: Vec<u8>) -> Result<Vec<u8>> {
    if proof_bytes.starts_with(&ZSTD_FRAME_MAGIC) {
        return zstd::decode_all(&proof_bytes[..]).wrap_err_with(|| {
            format!("Failed to zstd-decompress STARK final proof {}", path.display())
        });
    }

    Ok(proof_bytes)
}

fn load_stark_final_proof(path: &PathBuf) -> Result<VmStarkProof> {
    let proof_bytes = fs::read(path)
        .wrap_err_with(|| format!("Failed to read STARK final proof {}", path.display()))?;
    let proof_bytes = decode_persisted_final_proof_bytes(path, proof_bytes)?;
    let proof: StarkProofWithPublicValue<F> = bincode1::deserialize(&proof_bytes)
        .wrap_err_with(|| format!("Failed to deserialize STARK final proof {}", path.display()))?;

    let user_pvs_proof = proof.user_public_values.ok_or_else(|| {
        eyre!(
            "Proof {} does not include user public values; this is not a final STARK proof",
            path.display()
        )
    })?;

    Ok(VmStarkProof { inner: proof.proof, user_pvs_proof, deferral_merkle_proofs: None })
}

fn main() -> Result<()> {
    let args = Args::parse();
    let vk: VmStarkVerifyingKey = read_vk_from_file(&args.vm_vk)
        .wrap_err_with(|| format!("Failed to read VM verifying key {}", args.vm_vk.display()))?;
    let proof = load_stark_final_proof(&args.proof)?;

    verify_vm_stark_proof_decoded(&vk, &proof).wrap_err("OpenVM STARK verification failed")?;

    println!("Proof verified successfully: {}", args.proof.display());
    Ok(())
}
