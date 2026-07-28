//! Types mirroring the complete interface standard header.

/// Status code returned by every accelerator function (`zkvm_status`).
///
/// Pinned to `i32` so the layout does not depend on target conventions.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkvmStatus {
    /// Success (`ZKVM_EOK`).
    Ok = 0,
    /// Failure (`ZKVM_EFAIL`).
    Fail = -1,
}

/// 16-byte buffer.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkvmBytes16 {
    pub data: [u8; 16],
}

/// 32-byte buffer.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkvmBytes32 {
    pub data: [u8; 32],
}

/// 48-byte buffer.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkvmBytes48 {
    pub data: [u8; 48],
}

/// 64-byte buffer.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkvmBytes64 {
    pub data: [u8; 64],
}

/// 96-byte buffer.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkvmBytes96 {
    pub data: [u8; 96],
}

/// 128-byte buffer.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkvmBytes128 {
    pub data: [u8; 128],
}

/// 192-byte buffer.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkvmBytes192 {
    pub data: [u8; 192],
}

/* Hash types */
pub type ZkvmKeccak256Hash = ZkvmBytes32;
pub type ZkvmSha256Hash = ZkvmBytes32;
/// 20-byte hash padded to 32 bytes, first 12 bytes zero.
pub type ZkvmRipemd160Hash = ZkvmBytes32;

/* secp256k1 types */
pub type ZkvmSecp256k1Hash = ZkvmBytes32;
/// `r || s`, 32 bytes each, big-endian.
pub type ZkvmSecp256k1Signature = ZkvmBytes64;
/// uncompressed `x || y`, 32 bytes each, big-endian.
pub type ZkvmSecp256k1Pubkey = ZkvmBytes64;

/* secp256r1 (P-256) types */
pub type ZkvmSecp256r1Hash = ZkvmBytes32;
/// `r || s`, 32 bytes each, big-endian.
pub type ZkvmSecp256r1Signature = ZkvmBytes64;
/// uncompressed `x || y`, 32 bytes each, big-endian.
pub type ZkvmSecp256r1Pubkey = ZkvmBytes64;

/* BN254 types */
/// `x || y`, 32 bytes each, big-endian.
pub type ZkvmBn254G1Point = ZkvmBytes64;
/// `x_c1 || x_c0 || y_c1 || y_c0` (EIP-197 order).
pub type ZkvmBn254G2Point = ZkvmBytes128;
pub type ZkvmBn254Scalar = ZkvmBytes32;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkvmBn254PairingPair {
    pub g1: ZkvmBn254G1Point,
    pub g2: ZkvmBn254G2Point,
}

/* BLS12-381 types */
/// `x || y`, 48 bytes each, big-endian.
pub type ZkvmBls12381G1Point = ZkvmBytes96;
/// `x_c0 || x_c1 || y_c0 || y_c1` (EIP-2537 order).
pub type ZkvmBls12381G2Point = ZkvmBytes192;
pub type ZkvmBls12381Scalar = ZkvmBytes32;
pub type ZkvmBls12381Fp = ZkvmBytes48;
/// `c0 || c1`, 48 bytes each, big-endian.
pub type ZkvmBls12381Fp2 = ZkvmBytes96;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkvmBls12381G1MsmPair {
    pub point: ZkvmBls12381G1Point,
    pub scalar: ZkvmBls12381Scalar,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkvmBls12381G2MsmPair {
    pub point: ZkvmBls12381G2Point,
    pub scalar: ZkvmBls12381Scalar,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkvmBls12381PairingPair {
    pub g1: ZkvmBls12381G1Point,
    pub g2: ZkvmBls12381G2Point,
}

/* BLAKE2f types */
/// 8 × u64 little-endian.
pub type ZkvmBlake2fState = ZkvmBytes64;
/// 16 × u64 little-endian.
pub type ZkvmBlake2fMessage = ZkvmBytes128;
/// 2 × u64 little-endian.
pub type ZkvmBlake2fOffset = ZkvmBytes16;

/* KZG types */
pub type ZkvmKzgCommitment = ZkvmBytes48;
pub type ZkvmKzgProof = ZkvmBytes48;
pub type ZkvmKzgFieldElement = ZkvmBytes32;

// Assert 8-byte alignment and sizes.
const _: () = {
    use core::mem::{align_of, size_of};

    assert!(size_of::<ZkvmStatus>() == 4);
    assert!(align_of::<ZkvmStatus>() == 4);

    assert!(size_of::<ZkvmBytes16>() == 16);
    assert!(size_of::<ZkvmBytes32>() == 32);
    assert!(size_of::<ZkvmBytes48>() == 48);
    assert!(size_of::<ZkvmBytes64>() == 64);
    assert!(size_of::<ZkvmBytes96>() == 96);
    assert!(size_of::<ZkvmBytes128>() == 128);
    assert!(size_of::<ZkvmBytes192>() == 192);
    assert!(size_of::<ZkvmBn254PairingPair>() == 192);
    assert!(size_of::<ZkvmBls12381G1MsmPair>() == 128);
    assert!(size_of::<ZkvmBls12381G2MsmPair>() == 224);
    assert!(size_of::<ZkvmBls12381PairingPair>() == 288);

    assert!(align_of::<ZkvmBytes16>() == 8);
    assert!(align_of::<ZkvmBytes32>() == 8);
    assert!(align_of::<ZkvmBytes48>() == 8);
    assert!(align_of::<ZkvmBytes64>() == 8);
    assert!(align_of::<ZkvmBytes96>() == 8);
    assert!(align_of::<ZkvmBytes128>() == 8);
    assert!(align_of::<ZkvmBytes192>() == 8);
    assert!(align_of::<ZkvmBn254PairingPair>() == 8);
    assert!(align_of::<ZkvmBls12381G1MsmPair>() == 8);
    assert!(align_of::<ZkvmBls12381G2MsmPair>() == 8);
    assert!(align_of::<ZkvmBls12381PairingPair>() == 8);
};
