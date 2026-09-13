use std::{fs, path::PathBuf};

use clap::Parser;
use eyre::{Result, WrapErr};
use openvm_stark_sdk::openvm_stark_backend::codec::Decode;
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
    VmStarkProof::decode_from_bytes(&proof_bytes)
        .wrap_err_with(|| format!("Failed to decode STARK final proof {}", path.display()))
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
