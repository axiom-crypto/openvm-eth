//! Hash conformance vectors.

use hex_literal::hex;
use openvm_accelerators::{
    ffi::zkvm_keccak256,
    ops::keccak256,
    types::{ZkvmKeccak256Hash, ZkvmStatus},
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
