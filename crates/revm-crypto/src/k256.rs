#[cfg(all(not(target_os = "zkvm"), feature = "native-k256"))]
mod backend {
    use revm::precompile::{Crypto, DefaultCrypto, PrecompileHalt};

    pub(crate) fn install_alloy_provider() -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    pub(crate) fn secp256k1_ecrecover(
        sig_bytes: &[u8; 64],
        recid: u8,
        msg_hash: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        DefaultCrypto.secp256k1_ecrecover(sig_bytes, recid, msg_hash)
    }
}

#[cfg(not(all(not(target_os = "zkvm"), feature = "native-k256")))]
mod backend {
    use alloy_consensus::crypto::{
        backend::{install_default_provider, CryptoProvider},
        RecoveryError,
    };
    use alloy_primitives::Address;
    use openvm_k256::ecdsa::{
        signature::hazmat::PrehashVerifier, RecoveryId, Signature, VerifyingKey,
    };
    use openvm_keccak256::keccak256;
    use revm::precompile::PrecompileHalt;
    use std::sync::Arc;

    #[derive(Debug)]
    enum K256RecoveryError {
        InvalidSignature,
        InvalidRecoveryId,
        KeyRecoveryFailed,
    }

    impl K256RecoveryError {
        fn message(self) -> &'static str {
            match self {
                Self::InvalidSignature => "Invalid signature format",
                Self::InvalidRecoveryId => "Invalid recovery ID",
                Self::KeyRecoveryFailed => "Key recovery failed",
            }
        }
    }

    #[inline(always)]
    fn address_from_uncompressed_pubkey(pubkey: &[u8]) -> [u8; 20] {
        let pubkey_hash = keccak256(pubkey);
        let mut address = [0u8; 20];
        address.copy_from_slice(&pubkey_hash[12..]);
        address
    }

    #[inline(always)]
    fn recover_address(
        sig_bytes: &[u8],
        mut recid: u8,
        msg_hash: &[u8; 32],
    ) -> Result<[u8; 20], K256RecoveryError> {
        let mut signature =
            Signature::from_slice(sig_bytes).map_err(|_| K256RecoveryError::InvalidSignature)?;

        if let Some(normalized_signature) = signature.normalize_s() {
            signature = normalized_signature;
            recid ^= 1;
        }

        let recovery_id =
            RecoveryId::from_byte(recid).ok_or(K256RecoveryError::InvalidRecoveryId)?;
        let recovered_key = VerifyingKey::recover_from_prehash_noverify(
            msg_hash,
            &signature.to_bytes(),
            recovery_id,
        )
        .map_err(|_| K256RecoveryError::KeyRecoveryFailed)?;
        let public_key = recovered_key.to_encoded_point(false);
        Ok(address_from_uncompressed_pubkey(&public_key.as_bytes()[1..65]))
    }

    /// OpenVM k256 backend for Alloy crypto operations (transaction validation)
    #[derive(Debug, Default)]
    struct OpenVmK256Provider;

    impl CryptoProvider for OpenVmK256Provider {
        fn recover_signer_unchecked(
            &self,
            sig: &[u8; 65],
            msg: &[u8; 32],
        ) -> Result<Address, RecoveryError> {
            let address =
                recover_address(&sig[..64], sig[64], msg).map_err(|_| RecoveryError::new())?;
            Ok(Address::from(address))
        }

        fn verify_and_compute_signer_unchecked(
            &self,
            pubkey: &[u8; 65],
            sig: &[u8; 64],
            msg: &[u8; 32],
        ) -> Result<Address, RecoveryError> {
            let vk = VerifyingKey::from_sec1_bytes(pubkey).map_err(|_| RecoveryError::new())?;

            let mut signature = Signature::from_slice(sig).map_err(|_| RecoveryError::new())?;
            if let Some(sig_normalized) = signature.normalize_s() {
                signature = sig_normalized;
            }

            vk.verify_prehash(msg.as_ref(), &signature).map_err(|_| RecoveryError::new())?;

            Ok(Address::from(address_from_uncompressed_pubkey(&pubkey[1..65])))
        }
    }

    pub(crate) fn install_alloy_provider() -> Result<(), Box<dyn std::error::Error>> {
        install_default_provider(Arc::new(OpenVmK256Provider))?;
        Ok(())
    }

    pub(crate) fn secp256k1_ecrecover(
        sig_bytes: &[u8; 64],
        recid: u8,
        msg_hash: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        let recovered_address = recover_address(sig_bytes, recid, msg_hash)
            .map_err(|error| PrecompileHalt::other(error.message()))?;
        let mut address = [0u8; 32];
        address[12..].copy_from_slice(&recovered_address);

        Ok(address)
    }
}

pub(super) use backend::{install_alloy_provider, secp256k1_ecrecover};
