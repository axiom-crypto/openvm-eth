//! SHA-256 C-interface conformance vectors.

use hex_literal::hex;
use openvm_accelerators::{zkvm_sha256, zkvm_sha256_hash, ZKVM_EFAIL, ZKVM_EOK};

#[test]
fn sha256_abc() {
    let data = *b"abc";
    let mut output = zkvm_sha256_hash { data: [0; 32] };
    let status = unsafe { zkvm_sha256(data.as_ptr(), data.len(), &mut output) };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(
        output.data,
        hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn sha256_null_pointers() {
    let data = *b"abc";
    let mut output = zkvm_sha256_hash { data: [0; 32] };

    // A NULL `data` with `len == 0` is the empty input.
    let status = unsafe { zkvm_sha256(core::ptr::null(), 0, &mut output) };
    assert_eq!(status, ZKVM_EOK);
    assert_eq!(
        output.data,
        hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );

    let status = unsafe { zkvm_sha256(core::ptr::null(), data.len(), &mut output) };
    assert_eq!(status, ZKVM_EFAIL);

    let status = unsafe { zkvm_sha256(data.as_ptr(), data.len(), core::ptr::null_mut()) };
    assert_eq!(status, ZKVM_EFAIL);
}
