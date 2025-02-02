use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MasterPasswordError {
    #[error("Password hashing failed: {0}")]
    HashingError(String),
    #[error("Password verification failed")]
    VerificationError,
    #[error("Encryption failed: {0}")]
    EncryptionError(String),
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
}

pub struct MasterPassword {
    argon2: Argon2<'static>,
    password_hash: String,
    encryption_key: [u8; 32],
}

impl MasterPassword {
    // Argon2id parameters for master password
    const MEMORY_SIZE: u32 = 128 * 1024; // 128MB
    const TIME_COST: u32 = 4;
    const PARALLELISM: u32 = 4;

    /// Create new master password
    pub fn new(password: &str) -> Result<Self, MasterPasswordError> {
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                Self::MEMORY_SIZE,
                Self::TIME_COST,
                Self::PARALLELISM,
                Some(32),
            )
            .map_err(|e| MasterPasswordError::HashingError(e.to_string()))?,
        );

        // Generate random salt
        let salt = SaltString::generate(&mut OsRng);

        // Hash password
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| MasterPasswordError::HashingError(e.to_string()))?
            .to_string();

        // Derive encryption key
        let mut encryption_key = [0u8; 32];
        argon2
            .hash_password_into(
                password.as_bytes(),
                salt.as_str().as_bytes(),
                &mut encryption_key,
            )
            .map_err(|e| MasterPasswordError::HashingError(e.to_string()))?;

        Ok(Self {
            argon2,
            password_hash,
            encryption_key,
        })
    }

    /// Load existing master password
    pub fn load(password: &str, stored_hash: &str) -> Result<Self, MasterPasswordError> {
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                Self::MEMORY_SIZE,
                Self::TIME_COST,
                Self::PARALLELISM,
                Some(32),
            )
            .map_err(|e| MasterPasswordError::HashingError(e.to_string()))?,
        );

        // Verify password
        let parsed_hash = PasswordHash::new(stored_hash)
            .map_err(|e| MasterPasswordError::HashingError(e.to_string()))?;

        if argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err(MasterPasswordError::VerificationError);
        }

        // Derive encryption key
        let mut encryption_key = [0u8; 32];
        argon2
            .hash_password_into(
                password.as_bytes(),
                parsed_hash
                    .salt
                    .ok_or_else(|| {
                        MasterPasswordError::HashingError("Missing salt in hash".to_string())
                    })?
                    .as_str()
                    .as_bytes(),
                &mut encryption_key,
            )
            .map_err(|e| MasterPasswordError::HashingError(e.to_string()))?;

        Ok(Self {
            argon2,
            password_hash: stored_hash.to_string(),
            encryption_key,
        })
    }

    /// Get stored password hash
    pub fn get_hash(&self) -> &str {
        &self.password_hash
    }

    /// Encrypt data using master password derived key
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, MasterPasswordError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|e| MasterPasswordError::EncryptionError(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut encrypted = cipher
            .encrypt(nonce, data)
            .map_err(|e| MasterPasswordError::EncryptionError(e.to_string()))?;

        // Prepend nonce to encrypted data
        let mut result = nonce.to_vec();
        result.append(&mut encrypted);
        Ok(result)
    }

    /// Decrypt data using master password derived key
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, MasterPasswordError> {
        if encrypted_data.len() < 12 {
            return Err(MasterPasswordError::DecryptionError(
                "Data too short".to_string(),
            ));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|e| MasterPasswordError::DecryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| MasterPasswordError::DecryptionError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_password_creation() {
        let mp = MasterPassword::new("test_password").unwrap();
        assert!(!mp.password_hash.is_empty());
    }

    #[test]
    fn test_master_password_verification() {
        let mp = MasterPassword::new("test_password").unwrap();
        let hash = mp.get_hash();

        // Should succeed
        assert!(MasterPassword::load("test_password", hash).is_ok());

        // Should fail
        assert!(matches!(
            MasterPassword::load("wrong_password", hash),
            Err(MasterPasswordError::VerificationError)
        ));
    }

    #[test]
    fn test_encryption_decryption() {
        let mp = MasterPassword::new("test_password").unwrap();
        let data = b"secret data";

        let encrypted = mp.encrypt(data).unwrap();
        let decrypted = mp.decrypt(&encrypted).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }
}
