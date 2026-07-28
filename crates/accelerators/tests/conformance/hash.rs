//! Hash conformance vectors.

use hex_literal::hex;
use openvm_accelerators::{
    ffi::{zkvm_keccak256, zkvm_sha256},
    ops::{keccak256, sha256},
    types::{ZkvmKeccak256Hash, ZkvmSha256Hash, ZkvmStatus},
};

#[test]
fn keccak256_vectors() {
    let mut output = ZkvmKeccak256Hash { data: [0; 32] };

    keccak256(b"", &mut output);
    assert_eq!(
        output.data,
        hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    );

    keccak256(b"abc", &mut output);
    assert_eq!(
        output.data,
        hex!("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    );
}

#[test]
fn zkvm_keccak256_smoke() {
    let data = *b"abc";
    let mut output = ZkvmKeccak256Hash { data: [0; 32] };
    let status = unsafe { zkvm_keccak256(data.as_ptr(), data.len(), &mut output) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert_eq!(
        output.data,
        hex!("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    );
}

#[test]
fn zkvm_keccak256_null_pointers() {
    let data = *b"abc";
    let mut output = ZkvmKeccak256Hash { data: [0; 32] };

    // A NULL `data` with `len == 0` is the empty input.
    let status = unsafe { zkvm_keccak256(core::ptr::null(), 0, &mut output) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert_eq!(
        output.data,
        hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    );

    let status = unsafe { zkvm_keccak256(core::ptr::null(), data.len(), &mut output) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe { zkvm_keccak256(data.as_ptr(), data.len(), core::ptr::null_mut()) };
    assert_eq!(status, ZkvmStatus::Fail);
}

#[test]
fn sha256_vectors() {
    let mut output = ZkvmSha256Hash { data: [0; 32] };

    sha256(b"", &mut output);
    assert_eq!(
        output.data,
        hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );

    sha256(b"abc", &mut output);
    assert_eq!(
        output.data,
        hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn zkvm_sha256_smoke() {
    let data = *b"abc";
    let mut output = ZkvmSha256Hash { data: [0; 32] };
    let status = unsafe { zkvm_sha256(data.as_ptr(), data.len(), &mut output) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert_eq!(
        output.data,
        hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn zkvm_sha256_null_pointers() {
    let data = *b"abc";
    let mut output = ZkvmSha256Hash { data: [0; 32] };

    // A NULL `data` with `len == 0` is the empty input.
    let status = unsafe { zkvm_sha256(core::ptr::null(), 0, &mut output) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert_eq!(
        output.data,
        hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );

    let status = unsafe { zkvm_sha256(core::ptr::null(), data.len(), &mut output) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe { zkvm_sha256(data.as_ptr(), data.len(), core::ptr::null_mut()) };
    assert_eq!(status, ZkvmStatus::Fail);
}
