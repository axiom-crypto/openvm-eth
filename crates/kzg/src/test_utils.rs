use alloc::vec::Vec;
use serde::Deserialize;

use crate::{Blob, Bytes32, Bytes48, KzgError};

pub trait FromHex {
    fn from_hex(hex: &str) -> Result<Self, KzgError>
    where
        Self: Sized;
}

fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, KzgError> {
    let trimmed_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(trimmed_str)
        .map_err(|e| KzgError::InvalidHexFormat(format!("Failed to decode hex: {}", e)))
}

impl FromHex for Bytes48 {
    fn from_hex(hex_str: &str) -> Result<Self, KzgError> {
        Self::from_slice(&hex_to_bytes(hex_str).unwrap())
    }
}

impl FromHex for Bytes32 {
    fn from_hex(hex_str: &str) -> Result<Self, KzgError> {
        Self::from_slice(&hex_to_bytes(hex_str).unwrap())
    }
}

impl FromHex for Blob {
    fn from_hex(hex_str: &str) -> Result<Self, KzgError> {
        Self::from_slice(&hex_to_bytes(hex_str).unwrap())
    }
}

#[derive(Debug, Deserialize)]
pub struct Test<I> {
    pub input: I,
    output: Option<bool>,
}

impl<I> Test<I> {
    pub fn get_output(&self) -> Option<bool> {
        self.output
    }
}

#[derive(Debug, Deserialize)]
pub struct Input<'a> {
    commitment: &'a str,
    z: &'a str,
    y: &'a str,
    proof: &'a str,
}

impl Input<'_> {
    pub fn get_commitment(&self) -> Result<Bytes48, KzgError> {
        Bytes48::from_hex(self.commitment)
    }

    pub fn get_z(&self) -> Result<Bytes32, KzgError> {
        Bytes32::from_hex(self.z)
    }

    pub fn get_y(&self) -> Result<Bytes32, KzgError> {
        Bytes32::from_hex(self.y)
    }

    pub fn get_proof(&self) -> Result<Bytes48, KzgError> {
        Bytes48::from_hex(self.proof)
    }
}
