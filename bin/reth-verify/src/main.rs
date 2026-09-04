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

/// Load a cached VM verifying key, accepting either encoding it may carry.
///
/// axiom-edge's `generate_edge_vm_vk` writes **bincode 1.x**: the manager serves
/// the same bytes at `GET /vk/{name}` and its clients decode with bincode, so
/// that is the format of every vk generated since. openvm's own
/// `vk::read_vk_from_file` is **bitcode**, which is what older checked-in vks
/// are. Neither encoding is self-describing, so try both rather than force a
/// flag day — a vk that predates the bincode switch still verifies.
fn load_vm_vk(path: &PathBuf) -> Result<VmStarkVerifyingKey> {
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("Failed to read VM verifying key {}", path.display()))?;

    let bincode_err = match bincode1::deserialize::<VmStarkVerifyingKey>(&bytes) {
        Ok(vk) => return Ok(vk),
        Err(e) => e,
    };
    // Bitcode path goes through openvm's own reader so this stays in lockstep
    // with whatever bitcode version openvm pins, instead of us declaring a
    // second copy of it.
    let bitcode_err = match read_vk_from_file(path) {
        Ok(vk) => return Ok(vk),
        Err(e) => e,
    };

    Err(eyre::eyre!(
        "Failed to decode VM verifying key {} as either encoding.\n           bincode (axiom-edge generate_edge_vm_vk): {bincode_err}\n           bitcode (openvm write_vk_to_file):       {bitcode_err}",
        path.display()
    ))
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
    let vk: VmStarkVerifyingKey = load_vm_vk(&args.vm_vk)?;
    let proof = load_stark_final_proof(&args.proof)?;

    verify_vm_stark_proof_decoded(&vk, &proof).wrap_err("OpenVM STARK verification failed")?;

    println!("Proof verified successfully: {}", args.proof.display());
    Ok(())
}
