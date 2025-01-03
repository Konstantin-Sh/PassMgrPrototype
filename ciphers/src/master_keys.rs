// ciphers/src/master_keys.rs
use crate::structures::CipherOption;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug)]
pub struct MasterKeys {
    pub aes256_key: [u8; 32],
    pub xchacha20_key: [u8; 32],
    pub grasshopper_key: [u8; 32],
    pub ntrup1277_seed: [u8; 64], // NTRU Prime seed
    pub twofish_key: [u8; 32],
    pub kyber1024_seed: [u8; 84], // Kyber1024 requires 84 bytes for seed
}

#[derive(Debug, thiserror::Error)]
pub enum KeyDerivationError {
    #[error("HMAC operation failed")]
    HmacError,
    #[error("Invalid entropy length")]
    InvalidEntropyLength,
}

impl MasterKeys {
    /// Derive master keys from BIP39 entropy
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, KeyDerivationError> {
        if entropy.len() < 32 {
            return Err(KeyDerivationError::InvalidEntropyLength);
        }

        // Derive base key material using HKDF
        let base_key = Self::derive_base_key(entropy);

        Ok(Self {
            aes256_key: Self::derive_symmetric_key(&base_key, CipherOption::AES256)?,
            xchacha20_key: Self::derive_symmetric_key(&base_key, CipherOption::XChaCha20)?,
            grasshopper_key: Self::derive_symmetric_key(&base_key, CipherOption::GRASSHOPPER)?,
            ntrup1277_seed: Self::derive_quantum_seed::<64>(&base_key, CipherOption::NTRUP1277)?,
            twofish_key: Self::derive_symmetric_key(&base_key, CipherOption::TWOFISH)?,
            kyber1024_seed: Self::derive_quantum_seed::<84>(&base_key, CipherOption::Kyber1024)?,
        })
    }

    // Derive base key material using HKDF
    fn derive_base_key(entropy: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(b"PASSMGR_MASTER_KEY");
        hasher.update(entropy);

        let mut base_key = [0u8; 64];
        base_key.copy_from_slice(&hasher.finalize());
        base_key
    }

    // Derive 32-byte key for symmetric ciphers
    fn derive_symmetric_key(
        base_key: &[u8],
        cipher: CipherOption,
    ) -> Result<[u8; 32], KeyDerivationError> {
        let mut mac =
            HmacSha512::new_from_slice(base_key).map_err(|_| KeyDerivationError::HmacError)?;

        // Use cipher code as context
        mac.update(&[cipher.code()]);
        mac.update(b"SYMMETRIC_KEY");

        let result = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        Ok(key)
    }

    // Derive N-byte seed for quantum-resistant algorithms
    fn derive_quantum_seed<const N: usize>(
        base_key: &[u8],
        cipher: CipherOption,
    ) -> Result<[u8; N], KeyDerivationError> {
        let mut mac =
            HmacSha512::new_from_slice(base_key).map_err(|_| KeyDerivationError::HmacError)?;

        mac.update(&[cipher.code()]);
        mac.update(b"QUANTUM_SEED");
        let initial = mac.finalize().into_bytes();

        // For seeds larger than 64 bytes, we need additional iterations
        let mut seed = [0u8; N];
        let mut offset = 0;

        while offset < N {
            let chunk_size = std::cmp::min(64, N - offset);
            if offset == 0 {
                seed[..chunk_size].copy_from_slice(&initial[..chunk_size]);
            } else {
                // Generate additional bytes using the previous chunk
                let mut mac = HmacSha512::new_from_slice(base_key)
                    .map_err(|_| KeyDerivationError::HmacError)?;
                mac.update(&seed[..offset]);
                mac.update(&[cipher.code()]);
                mac.update(&[offset as u8]);
                let next = mac.finalize().into_bytes();
                seed[offset..offset + chunk_size].copy_from_slice(&next[..chunk_size]);
            }
            offset += chunk_size;
        }

        Ok(seed)
    }

    // Get key for specific cipher
    pub fn get_key(&self, cipher: CipherOption) -> &[u8] {
        match cipher {
            CipherOption::AES256 => &self.aes256_key,
            CipherOption::XChaCha20 => &self.xchacha20_key,
            CipherOption::GRASSHOPPER => &self.grasshopper_key,
            CipherOption::NTRUP1277 => &self.ntrup1277_seed,
            CipherOption::TWOFISH => &self.twofish_key,
            CipherOption::Kyber1024 => &self.kyber1024_seed,
            CipherOption::END => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn test_master_keys_generation() {
        // Generate random entropy
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);

        // Generate master keys
        let master_keys = MasterKeys::from_entropy(&entropy).unwrap();

        // Verify all keys are different
        let keys = [
            &master_keys.aes256_key[..],
            &master_keys.xchacha20_key[..],
            &master_keys.grasshopper_key[..],
            &master_keys.twofish_key[..],
        ];

        for (i, key1) in keys.iter().enumerate() {
            for (j, key2) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(key1, key2, "Keys at indices {} and {} are identical", i, j);
                }
            }
        }
    }

    #[test]
    fn test_quantum_seeds() {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);

        let master_keys = MasterKeys::from_entropy(&entropy).unwrap();

        // Verify seed lengths
        assert_eq!(master_keys.ntrup1277_seed.len(), 64);
        assert_eq!(master_keys.kyber1024_seed.len(), 84);

        // Verify seeds are different
        assert_ne!(
            &master_keys.ntrup1277_seed[..64],
            &master_keys.kyber1024_seed[..64],
            "Quantum seeds share common prefix"
        );
    }

    #[test]
    fn test_invalid_entropy() {
        let entropy = [0u8; 16]; // Too short
        assert!(matches!(
            MasterKeys::from_entropy(&entropy),
            Err(KeyDerivationError::InvalidEntropyLength)
        ));
    }
}
