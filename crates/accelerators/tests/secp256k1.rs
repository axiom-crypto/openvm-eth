//! secp256k1 C-interface conformance vectors.

use hex_literal::hex;
use openvm_accelerators::{
    zkvm_keccak256, zkvm_keccak256_hash, zkvm_secp256k1_ecrecover, zkvm_secp256k1_hash,
    zkvm_secp256k1_pubkey, zkvm_secp256k1_signature, zkvm_secp256k1_verify, ZKVM_EFAIL, ZKVM_EOK,
};

const MSG: zkvm_secp256k1_hash = zkvm_secp256k1_hash {
    data: hex!("456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"),
};
const SIG: zkvm_secp256k1_signature = zkvm_secp256k1_signature {
    data: hex!(
        "9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"
        "4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"
    ),
};
const ADDRESS: [u8; 20] = hex!("7156526fbd7a3c72969b54f64e42c10fbb768c8a");

#[test]
fn secp256k1_ecrecover_vector() {
    let mut pubkey = zkvm_secp256k1_pubkey { data: [0; 64] };
    let status = unsafe { zkvm_secp256k1_ecrecover(&MSG, &SIG, 1, &mut pubkey) };
    assert_eq!(status, ZKVM_EOK);

    let mut digest = zkvm_keccak256_hash { data: [0; 32] };
    let status = unsafe { zkvm_keccak256(pubkey.data.as_ptr(), pubkey.data.len(), &mut digest) };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(digest.data[12..], ADDRESS);
}

#[test]
fn secp256k1_ecrecover_invalid_inputs() {
    let unchanged = [0x55; 64];
    let mut pubkey = zkvm_secp256k1_pubkey { data: unchanged };

    let status = unsafe { zkvm_secp256k1_ecrecover(&MSG, &SIG, 4, &mut pubkey) };
    assert_eq!(status, ZKVM_EFAIL);
    assert_eq!(pubkey.data, unchanged);

    let zero_sig = zkvm_secp256k1_signature { data: [0; 64] };
    let status = unsafe { zkvm_secp256k1_ecrecover(&MSG, &zero_sig, 0, &mut pubkey) };
    assert_eq!(status, ZKVM_EFAIL);
    assert_eq!(pubkey.data, unchanged);
}

#[test]
fn secp256k1_recover_and_verify() {
    let mut pubkey = zkvm_secp256k1_pubkey { data: [0; 64] };
    let status = unsafe { zkvm_secp256k1_ecrecover(&MSG, &SIG, 1, &mut pubkey) };
    assert_eq!(status, ZKVM_EOK);

    let mut verified = false;
    let status = unsafe { zkvm_secp256k1_verify(&MSG, &SIG, &pubkey, &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(verified);

    let mut wrong_msg = MSG;
    wrong_msg.data[0] ^= 1;
    let status = unsafe { zkvm_secp256k1_verify(&wrong_msg, &SIG, &pubkey, &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(!verified);

    let bad_pubkey = zkvm_secp256k1_pubkey { data: [0xff; 64] };
    let status = unsafe { zkvm_secp256k1_verify(&MSG, &SIG, &bad_pubkey, &mut verified) };
    assert_eq!(status, ZKVM_EOK);
    assert!(!verified);
}

#[test]
fn secp256k1_null_pointers() {
    let mut pubkey = zkvm_secp256k1_pubkey { data: [0; 64] };
    assert_eq!(
        unsafe { zkvm_secp256k1_ecrecover(core::ptr::null(), &SIG, 1, &mut pubkey) },
        ZKVM_EFAIL
    );
    assert_eq!(
        unsafe { zkvm_secp256k1_ecrecover(&MSG, core::ptr::null(), 1, &mut pubkey) },
        ZKVM_EFAIL
    );
    assert_eq!(
        unsafe { zkvm_secp256k1_ecrecover(&MSG, &SIG, 1, core::ptr::null_mut()) },
        ZKVM_EFAIL
    );

    let mut verified = false;
    assert_eq!(
        unsafe { zkvm_secp256k1_verify(core::ptr::null(), &SIG, &pubkey, &mut verified) },
        ZKVM_EFAIL
    );
    assert_eq!(
        unsafe { zkvm_secp256k1_verify(&MSG, core::ptr::null(), &pubkey, &mut verified) },
        ZKVM_EFAIL
    );
    assert_eq!(
        unsafe { zkvm_secp256k1_verify(&MSG, &SIG, core::ptr::null(), &mut verified) },
        ZKVM_EFAIL
    );
    assert_eq!(
        unsafe { zkvm_secp256k1_verify(&MSG, &SIG, &pubkey, core::ptr::null_mut()) },
        ZKVM_EFAIL
    );
}
