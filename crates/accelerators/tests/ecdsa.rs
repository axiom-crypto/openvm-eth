//! ECDSA conformance vectors.
//!
//! Tested with vectors from https://github.com/daimo-eth/p256-verifier/tree/master/test-vectors.

#![cfg(feature = "ffi")]

use hex_literal::hex;
use openvm_accelerators::{
    keccak256, secp256k1_ecrecover, secp256k1_verify, secp256r1_verify, zkvm_secp256k1_ecrecover,
    zkvm_secp256k1_verify, zkvm_secp256r1_verify, Error, ZkvmSecp256k1Hash, ZkvmSecp256k1Pubkey,
    ZkvmSecp256k1Signature, ZkvmSecp256r1Hash, ZkvmSecp256r1Pubkey, ZkvmSecp256r1Signature,
    ZkvmStatus,
};

/// Splits a 160-byte P256VERIFY input (msg || sig || pk) into its parts.
fn parts(input: &[u8; 160]) -> (ZkvmSecp256r1Hash, ZkvmSecp256r1Signature, ZkvmSecp256r1Pubkey) {
    (
        ZkvmSecp256r1Hash { data: input[..32].try_into().unwrap() },
        ZkvmSecp256r1Signature { data: input[32..96].try_into().unwrap() },
        ZkvmSecp256r1Pubkey { data: input[96..].try_into().unwrap() },
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
    assert!(secp256r1_verify(&msg.data, &sig.data, &pubkey.data));

    let mut wrong_msg = msg;
    wrong_msg.data[0] = 0x3c;
    assert!(!secp256r1_verify(&wrong_msg.data, &sig.data, &pubkey.data));
}

#[test]
fn secp256r1_verify_malformed_inputs() {
    let (msg, sig, _) = parts(&VALID);
    let bad_sig = ZkvmSecp256r1Signature { data: [0xff; 64] };
    assert!(!secp256r1_verify(&msg.data, &bad_sig.data, &parts(&VALID).2.data));

    let bad_pubkey = ZkvmSecp256r1Pubkey { data: [0; 64] };
    assert!(!secp256r1_verify(&msg.data, &sig.data, &bad_pubkey.data));
}

#[test]
fn zkvm_secp256r1_verify_smoke() {
    let (msg, sig, pubkey) = parts(&VALID);
    let mut verified = false;

    let status = unsafe { zkvm_secp256r1_verify(&msg, &sig, &pubkey, &mut verified) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert!(verified);

    // Malformed cryptographic inputs are a completed verification with a false result.
    let bad_pubkey = ZkvmSecp256r1Pubkey { data: [0; 64] };
    let status = unsafe { zkvm_secp256r1_verify(&msg, &sig, &bad_pubkey, &mut verified) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert!(!verified);
}

#[test]
fn zkvm_secp256r1_verify_null_pointers() {
    let (msg, sig, pubkey) = parts(&VALID);
    let mut verified = false;

    let status = unsafe { zkvm_secp256r1_verify(core::ptr::null(), &sig, &pubkey, &mut verified) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe { zkvm_secp256r1_verify(&msg, core::ptr::null(), &pubkey, &mut verified) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe { zkvm_secp256r1_verify(&msg, &sig, core::ptr::null(), &mut verified) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe { zkvm_secp256r1_verify(&msg, &sig, &pubkey, core::ptr::null_mut()) };
    assert_eq!(status, ZkvmStatus::Fail);
}

const K1_MSG: ZkvmSecp256k1Hash = ZkvmSecp256k1Hash {
    data: hex!("456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"),
};
const K1_SIG: ZkvmSecp256k1Signature = ZkvmSecp256k1Signature {
    data: hex!(
        "9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"
        "4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"
    ),
};
const K1_ADDRESS: [u8; 20] = hex!("7156526fbd7a3c72969b54f64e42c10fbb768c8a");

#[test]
fn secp256k1_ecrecover_vector() {
    let pubkey = secp256k1_ecrecover(&K1_MSG.data, &K1_SIG.data, 1).unwrap();

    // The Ethereum address is keccak(pubkey)[12..], derived here exactly as
    // a caller of the interface would.
    assert_eq!(keccak256(&pubkey)[12..], K1_ADDRESS);
}

#[test]
fn secp256k1_ecrecover_invalid_inputs() {
    // Recovery ids above 3 are invalid.
    let result = secp256k1_ecrecover(&K1_MSG.data, &K1_SIG.data, 4);
    assert_eq!(result, Err(Error::InvalidSignature));

    // The zero signature cannot be parsed.
    let zero_sig = ZkvmSecp256k1Signature { data: [0; 64] };
    let result = secp256k1_ecrecover(&K1_MSG.data, &zero_sig.data, 0);
    assert_eq!(result, Err(Error::InvalidSignature));
}

#[test]
fn secp256k1_verify_roundtrip() {
    let pubkey = secp256k1_ecrecover(&K1_MSG.data, &K1_SIG.data, 1).unwrap();
    assert!(secp256k1_verify(&K1_MSG.data, &K1_SIG.data, &pubkey));

    let mut wrong_msg = K1_MSG;
    wrong_msg.data[0] ^= 1;
    assert!(!secp256k1_verify(&wrong_msg.data, &K1_SIG.data, &pubkey));

    let bad_pubkey = ZkvmSecp256k1Pubkey { data: [0xff; 64] };
    assert!(!secp256k1_verify(&K1_MSG.data, &K1_SIG.data, &bad_pubkey.data));
}

#[test]
fn zkvm_secp256k1_recover_and_verify() {
    let mut pubkey = core::mem::MaybeUninit::<ZkvmSecp256k1Pubkey>::uninit();
    let status = unsafe { zkvm_secp256k1_ecrecover(&K1_MSG, &K1_SIG, 1, pubkey.as_mut_ptr()) };
    assert_eq!(status, ZkvmStatus::Ok);
    let pubkey = unsafe { pubkey.assume_init() };

    let mut verified = core::mem::MaybeUninit::<bool>::uninit();
    let status = unsafe { zkvm_secp256k1_verify(&K1_MSG, &K1_SIG, &pubkey, verified.as_mut_ptr()) };
    assert_eq!(status, ZkvmStatus::Ok);
    let mut verified = unsafe { verified.assume_init() };
    assert!(verified);

    let bad_pubkey = ZkvmSecp256k1Pubkey { data: [0xff; 64] };
    let status = unsafe { zkvm_secp256k1_verify(&K1_MSG, &K1_SIG, &bad_pubkey, &mut verified) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert!(!verified);
}
