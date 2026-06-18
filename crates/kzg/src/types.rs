use alloc::sync::Arc;
use core::hash::{Hash, Hasher};

use bls12_381::{G1Affine, G2Affine, Scalar};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use spin::Once;

use crate::get_kzg_settings;
use crate::{Bytes32, Bytes48, KzgError};

/// Inputs to pass to the VM for KZG proof verification
/// Excludes `KzgSettings`, which is read from disk by the VM
#[derive(Clone, Deserialize, Serialize)]
pub struct KzgInputs {
    pub commitment_bytes: Bytes48,
    pub z_bytes: Bytes32,
    pub y_bytes: Bytes32,
    pub proof_bytes: Bytes48,
}

impl Serialize for Bytes48 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Get the underlying array and serialize it
        BigArray::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Bytes48 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize into a temporary array
        let arr = <[u8; 48] as BigArray<u8>>::deserialize(deserializer)?;
        // Convert the array to Bytes48
        Ok(Bytes48::from_slice(&arr).unwrap())
    }
}

impl Serialize for Bytes32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Serialize::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Bytes32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Bytes32::from_slice(&<[u8; 32] as BigArray<u8>>::deserialize(deserializer)?).unwrap())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C, align(4))]
pub struct KzgSettings {
    pub roots_of_unity: &'static [Scalar],
    pub g1_points: &'static [G1Affine],
    pub g2_points: &'static [G2Affine],
}

#[derive(Debug, Clone, Default, Eq)]
pub enum EnvKzgSettings {
    #[default]
    Default,
    Custom(Arc<KzgSettings>),
}

impl PartialEq for EnvKzgSettings {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Default, Self::Default) => true,
            (Self::Custom(a), Self::Custom(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl Hash for EnvKzgSettings {
    fn hash<H: Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::Default => {}
            Self::Custom(settings) => Arc::as_ptr(settings).hash(state),
        }
    }
}

impl EnvKzgSettings {
    pub fn get(&self) -> &KzgSettings {
        match self {
            Self::Default => {
                static DEFAULT: Once<KzgSettings> = Once::new();
                DEFAULT.call_once(|| {
                    KzgSettings::load_trusted_setup_file()
                        .expect("failed to load default trusted setup")
                })
            }
            Self::Custom(settings) => settings,
        }
    }
}

impl KzgSettings {
    pub fn load_trusted_setup_file() -> Result<Self, KzgError> {
        Ok(get_kzg_settings())
    }
}
