use crate::{types::KzgSettings, NUM_G1_POINTS, NUM_G2_POINTS, NUM_ROOTS_OF_UNITY};

use bls12_381::{G1Affine, G2Affine, Scalar};
use core::{mem::align_of, slice};
use spin::Once;

// https://users.rust-lang.org/t/can-i-conveniently-compile-bytes-into-a-rust-program-with-a-specific-alignment/24049/2
#[repr(C)] // guarantee 'bytes' comes after '_align'
#[derive(Debug)]
pub struct AlignedAs<Align, Bytes: ?Sized> {
    pub _align: [Align; 0],
    pub bytes: Bytes,
}

macro_rules! include_bytes_align_as {
    ($align_ty:ty, $path:expr) => {{
        // const block expression to encapsulate the static

        // this assignment is made possible by CoerceUnsized
        static ALIGNED: &AlignedAs<$align_ty, [u8]> =
            &AlignedAs { _align: [], bytes: *include_bytes!($path) };

        &ALIGNED.bytes
    }};
}

pub fn get_roots_of_unity() -> &'static [Scalar] {
    static ROOTS_OF_UNITY: Once<&'static [Scalar]> = Once::new();
    ROOTS_OF_UNITY.call_once(|| {
        static ALIGNED_BYTES: &[u8] = include_bytes_align_as!(
            Scalar,
            concat!(env!("CARGO_MANIFEST_DIR"), "/assets/trusted_setup/roots_of_unity.bin")
        );
        // The minimum alignment required is 4
        assert!((ALIGNED_BYTES.as_ptr() as usize).is_multiple_of(align_of::<Scalar>()));
        unsafe {
            slice::from_raw_parts::<Scalar>(
                ALIGNED_BYTES.as_ptr() as *const Scalar,
                NUM_ROOTS_OF_UNITY,
            )
        }
    })
}

pub fn get_g1_points() -> &'static [G1Affine] {
    static G1_POINTS: Once<&'static [G1Affine]> = Once::new();
    G1_POINTS.call_once(|| {
        static ALIGNED_BYTES: &[u8] = include_bytes_align_as!(
            G1Affine,
            concat!(env!("CARGO_MANIFEST_DIR"), "/assets/trusted_setup/g1.bin")
        );
        // The minimum alignment required is 4
        assert!((ALIGNED_BYTES.as_ptr() as usize).is_multiple_of(align_of::<G1Affine>()));
        unsafe {
            slice::from_raw_parts::<G1Affine>(
                ALIGNED_BYTES.as_ptr() as *const G1Affine,
                NUM_G1_POINTS,
            )
        }
    })
}

pub fn get_g2_points() -> &'static [G2Affine] {
    static G2_POINTS: Once<&'static [G2Affine]> = Once::new();
    G2_POINTS.call_once(|| {
        static ALIGNED_BYTES: &[u8] = include_bytes_align_as!(
            G2Affine,
            concat!(env!("CARGO_MANIFEST_DIR"), "/assets/trusted_setup/g2.bin")
        );
        // The minimum alignment required is 4
        assert!((ALIGNED_BYTES.as_ptr() as usize).is_multiple_of(align_of::<G2Affine>()));
        unsafe {
            slice::from_raw_parts::<G2Affine>(
                ALIGNED_BYTES.as_ptr() as *const G2Affine,
                NUM_G2_POINTS,
            )
        }
    })
}

pub fn get_kzg_settings() -> KzgSettings {
    KzgSettings {
        roots_of_unity: get_roots_of_unity(),
        g1_points: get_g1_points(),
        g2_points: get_g2_points(),
    }
}
