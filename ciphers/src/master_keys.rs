use crate::structures::CipherOption;
use argon2::{
    password_hash::{Output, Salt},
    Argon2, Params, Version,
};

#[derive(Debug)]
pub struct MasterKeys {
    pub aes256_key: [u8; 32],
    pub xchacha20_key: [u8; 32],
    pub grasshopper_key: [u8; 32],
    pub ntrup1277_seed: [u8; 64],
    pub twofish_key: [u8; 32],
    pub kyber1024_seed: [u8; 84],
}

#[derive(Debug, thiserror::Error)]
pub enum KeyDerivationError {
    #[error("Argon2 operation failed: {0}")]
    Argon2Error(String),
    #[error("Invalid entropy length")]
    InvalidEntropyLength,
}

impl MasterKeys {
    // Argon2id parameters
    const MEMORY_SIZE: u32 = 64 * 1024; // 64MB
    const TIME_COST: u32 = 3;
    const PARALLELISM: u32 = 4;

    /// Derive master keys from BIP39 entropy using Argon2id
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, KeyDerivationError> {
        if entropy.len() < 32 {
            return Err(KeyDerivationError::InvalidEntropyLength);
        }

        // Initialize Argon2id with default parameters
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(
                Self::MEMORY_SIZE,
                Self::TIME_COST,
                Self::PARALLELISM,
                Some(32), // Output length in bytes
            )
            .map_err(|e| KeyDerivationError::Argon2Error(e.to_string()))?,
        );

        Ok(Self {
            aes256_key: Self::derive_symmetric_key(&argon2, entropy, CipherOption::AES256)?,
            xchacha20_key: Self::derive_symmetric_key(&argon2, entropy, CipherOption::XChaCha20)?,
            grasshopper_key: Self::derive_symmetric_key(
                &argon2,
                entropy,
                CipherOption::GRASSHOPPER,
            )?,
            ntrup1277_seed: Self::derive_quantum_seed::<64>(
                &argon2,
                entropy,
                CipherOption::NTRUP1277,
            )?,
            twofish_key: Self::derive_symmetric_key(&argon2, entropy, CipherOption::TWOFISH)?,
            kyber1024_seed: Self::derive_quantum_seed::<84>(
                &argon2,
                entropy,
                CipherOption::Kyber1024,
            )?,
        })
    }

    // Generate unique salt for each cipher
    fn generate_salt(cipher: CipherOption) -> Salt<'static> {
        let mut salt = [0u8; 16];
        salt[0] = cipher.code();
        salt[1..].copy_from_slice(b"PASSMGR_SALT_V1");

        Salt::from_b64(&base64::encode(salt)).expect("Static salt generation should never fail")
    }

    // Derive 32-byte key for symmetric ciphers
    fn derive_symmetric_key(
        argon2: &Argon2,
        entropy: &[u8],
        cipher: CipherOption,
    ) -> Result<[u8; 32], KeyDerivationError> {
        let salt = Self::generate_salt(cipher);
        let mut output = [0u8; 32];

        argon2
            .hash_password_into(entropy, salt.as_ref(), &mut output)
            .map_err(|e| KeyDerivationError::Argon2Error(e.to_string()))?;

        Ok(output)
    }

    // Derive N-byte seed for quantum-resistant algorithms
    fn derive_quantum_seed<const N: usize>(
        argon2: &Argon2,
        entropy: &[u8],
        cipher: CipherOption,
    ) -> Result<[u8; N], KeyDerivationError> {
        let mut seed = [0u8; N];
        let salt = Self::generate_salt(cipher);

        // For seeds larger than 32 bytes, we need multiple derivations
        for (i, chunk) in seed.chunks_mut(32).enumerate() {
            let mut temp_salt = [0u8; 20]; // 16 bytes salt + 4 bytes counter
            temp_salt[..16].copy_from_slice(salt.as_ref());
            temp_salt[16..].copy_from_slice(&(i as u32).to_le_bytes());

            argon2
                .hash_password_into(entropy, &temp_salt, chunk)
                .map_err(|e| KeyDerivationError::Argon2Error(e.to_string()))?;
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
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);

        let master_keys = MasterKeys::from_entropy(&entropy).unwrap();

        // Verify all symmetric keys are different
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

    #[test]
    fn test_deterministic_derivation() {
        // Test that same entropy produces same keys
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);

        let keys1 = MasterKeys::from_entropy(&entropy).unwrap();
        let keys2 = MasterKeys::from_entropy(&entropy).unwrap();

        assert_eq!(keys1.aes256_key, keys2.aes256_key);
        assert_eq!(keys1.xchacha20_key, keys2.xchacha20_key);
        assert_eq!(keys1.grasshopper_key, keys2.grasshopper_key);
        assert_eq!(keys1.ntrup1277_seed, keys2.ntrup1277_seed);
        assert_eq!(keys1.twofish_key, keys2.twofish_key);
        assert_eq!(keys1.kyber1024_seed, keys2.kyber1024_seed);
    }
}
