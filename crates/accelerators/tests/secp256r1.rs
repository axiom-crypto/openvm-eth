//! secp256r1 C-interface conformance vectors.
//!
//! Vectors are from https://github.com/daimo-eth/p256-verifier/tree/master/test-vectors.

use hex_literal::hex;
use openvm_accelerators::{
    zkvm_secp256r1_hash, zkvm_secp256r1_pubkey, zkvm_secp256r1_signature, zkvm_secp256r1_verify,
    ZKVM_EFAIL, ZKVM_EOK,
};

fn parts(
    input: &[u8; 160],
) -> (zkvm_secp256r1_hash, zkvm_secp256r1_signature, zkvm_secp256r1_pubkey) {
    (
        zkvm_secp256r1_hash { data: input[..32].try_into().unwrap() },
        zkvm_secp256r1_signature { data: input[32..96].try_into().unwrap() },
        zkvm_secp256r1_pubkey { data: input[96..].try_into().unwrap() },
    )
}

const VALID: [u8; 160] = hex!(
    "4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4d"
    "a73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac"
    "36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d60"
    "4aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff3"
    "7618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e"
);

#[test]
fn secp256r1_verify_vectors() {
    let (msg, sig, pubkey) = parts(&VALID);
    let mut verified = false;
    let status = unsafe { zkvm_secp256r1_verify(&msg, &sig, &pubkey, &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(verified);

    let mut wrong_msg = msg;
    wrong_msg.data[0] = 0x3c;
    let status = unsafe { zkvm_secp256r1_verify(&wrong_msg, &sig, &pubkey, &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(!verified);
}

#[test]
fn secp256r1_verify_malformed_inputs() {
    let (msg, sig, pubkey) = parts(&VALID);
    let mut verified = true;

    let bad_sig = zkvm_secp256r1_signature { data: [0xff; 64] };
    let status = unsafe { zkvm_secp256r1_verify(&msg, &bad_sig, &pubkey, &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(!verified);

    let bad_pubkey = zkvm_secp256r1_pubkey { data: [0; 64] };
    let status = unsafe { zkvm_secp256r1_verify(&msg, &sig, &bad_pubkey, &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(!verified);
}

#[test]
fn secp256r1_verify_null_pointers() {
    let (msg, sig, pubkey) = parts(&VALID);
    let mut verified = false;

    assert_eq!(
        unsafe { zkvm_secp256r1_verify(core::ptr::null(), &sig, &pubkey, &mut verified) },
        ZKVM_EFAIL
    );
    assert_eq!(
        unsafe { zkvm_secp256r1_verify(&msg, core::ptr::null(), &pubkey, &mut verified) },
        ZKVM_EFAIL
    );
    assert_eq!(
        unsafe { zkvm_secp256r1_verify(&msg, &sig, core::ptr::null(), &mut verified) },
        ZKVM_EFAIL
    );
    assert_eq!(
        unsafe { zkvm_secp256r1_verify(&msg, &sig, &pubkey, core::ptr::null_mut()) },
        ZKVM_EFAIL
    );
}
