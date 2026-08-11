#![cfg(feature = "ffi")]

//! Hash conformance vectors.

use hex_literal::hex;
use openvm_accelerators::{
    keccak256, ripemd160, sha256, zkvm_keccak256, zkvm_ripemd160, zkvm_sha256, ZkvmKeccak256Hash,
    ZkvmRipemd160Hash, ZkvmSha256Hash, ZkvmStatus,
};

#[test]
fn keccak256_vectors() {
    assert_eq!(
        keccak256(b""),
        hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    );

    assert_eq!(
        keccak256(b"abc"),
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
    assert_eq!(
        sha256(b""),
        hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );

    assert_eq!(
        sha256(b"abc"),
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

#[test]
fn ripemd160_vectors() {
    assert_eq!(
        ripemd160(b""),
        hex!("0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31")
    );

    assert_eq!(
        ripemd160(b"abc"),
        hex!("0000000000000000000000008eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
    );
}

#[test]
fn zkvm_ripemd160_smoke() {
    let data = *b"abc";
    let mut output = ZkvmRipemd160Hash { data: [0xff; 32] };
    let status = unsafe { zkvm_ripemd160(data.as_ptr(), data.len(), &mut output) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert_eq!(
        output.data,
        hex!("0000000000000000000000008eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
    );
}

#[test]
fn zkvm_ripemd160_null_pointers() {
    let data = *b"abc";
    let mut output = ZkvmRipemd160Hash { data: [0xff; 32] };

    // A NULL `data` with `len == 0` is the empty input.
    let status = unsafe { zkvm_ripemd160(core::ptr::null(), 0, &mut output) };
    assert_eq!(status, ZkvmStatus::Ok);
    assert_eq!(
        output.data,
        hex!("0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31")
    );

    let status = unsafe { zkvm_ripemd160(core::ptr::null(), data.len(), &mut output) };
    assert_eq!(status, ZkvmStatus::Fail);

    let status = unsafe { zkvm_ripemd160(data.as_ptr(), data.len(), core::ptr::null_mut()) };
    assert_eq!(status, ZkvmStatus::Fail);
}
