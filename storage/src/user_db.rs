use crate::db::Storage;
use crate::error::StorageError;
use crate::structures::{CipherRecord, Record};
use bincode::{deserialize, serialize};
use crypto::cipher_chain::{Cipher, CipherChain, CipherKey};
use crypto::structures::CipherOption;
use crypto::MasterKeys;
use soft_aes::aes::{aes_dec_cbc, aes_enc_cbc};
use std::path::Path;

// AES implementation
pub struct AesCipher;
pub struct AesKey {
    key: [u8; 32],
    iv: [u8; 16],
}

impl CipherKey for AesKey {
    fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    fn rotate(&mut self, new_key: &[u8]) {
        self.key.copy_from_slice(&new_key[..32]);
        // Generate new IV on rotation
        //OsRng.fill_bytes(&mut self.iv);
    }
}

impl Cipher for AesCipher {
    fn encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let key = &key[..32];
        let iv: [u8; 16] = [0; 16]; //key[32..48];
        let padding = Some("PKCS7");

        aes_enc_cbc(data, key, &iv, padding).expect("Encryption failed")
    }

    fn decrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let key = &key[..32];
        let iv = [0; 16]; //key[32..48];
        let padding = Some("PKCS7");

        aes_dec_cbc(data, key, &iv, padding).expect("Decryption failed")
    }
}

pub struct UserDb {
    storage: Storage,
    cipher_chain: CipherChain,
    user_id: u128,
}

#[derive(Debug, thiserror::Error)]
pub enum UserDbError {
    #[error("Storage error: {0}")]
    StorageError(#[from] StorageError),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Encryption error")]
    EncryptionError,
    #[error("Decryption error")]
    DecryptionError,
}

impl UserDb {
    pub fn new(path: &Path, user_id: u128, master_keys: &MasterKeys) -> Result<Self, UserDbError> {
        let storage = Storage::open(path, user_id as u128).map_err(UserDbError::StorageError)?;

        let mut cipher_chain = CipherChain::new();

        // cipher_chain.add_cipher_with_key(AesCipher, master_keys.aes256_key);
        // cipher_chain.add_cipher_with_key(ChaCha20Cipher::new(), ChaChaKey::new(master_keys.xchacha20_key));

        Ok(Self {
            storage,
            cipher_chain,
            user_id,
        })
    }

    pub fn create(&self, record: Record) -> Result<u128, UserDbError> {
        // Generate new record ID
        let record_id = self.generate_record_id();

        // Serialize the record
        let data =
            serialize(&record).map_err(|e| UserDbError::SerializationError(e.to_string()))?;

        // Encrypt the serialized data
        let encrypted_data = self.cipher_chain.encrypt(&data);

        // Create cipher record
        let cipher_record = CipherRecord {
            user_id: self.user_id,
            cipher_record_id: record_id,
            ver: 1, // Initial version
            cipher_options: self.get_cipher_options(),
            data: encrypted_data,
        };

        // Save to storage
        self.storage
            .set(record_id as u128, &cipher_record)
            .map_err(UserDbError::StorageError)?;

        Ok(record_id)
    }

    pub fn read(&self, record_id: u64) -> Result<Record, UserDbError> {
        // Retrieve cipher record from storage
        let cipher_record = self
            .storage
            .get(record_id as u128)
            .map_err(UserDbError::StorageError)?;

        // Verify user ID
        if cipher_record.user_id != self.user_id {
            return Err(UserDbError::DecryptionError);
        }

        // Decrypt data
        let decrypted_data = self.cipher_chain.decrypt(&cipher_record.data);

        // Deserialize into Record
        let record = deserialize(&decrypted_data)
            .map_err(|e| UserDbError::SerializationError(e.to_string()))?;

        Ok(record)
    }

    pub fn update(&self, record_id: u128, record: Record) -> Result<(), UserDbError> {
        // First read existing record to get current version
        let current = self
            .storage
            .get(record_id as u128)
            .map_err(UserDbError::StorageError)?;

        // Serialize and encrypt new data
        let data =
            serialize(&record).map_err(|e| UserDbError::SerializationError(e.to_string()))?;
        let encrypted_data = self.cipher_chain.encrypt(&data);

        // Create updated cipher record
        let cipher_record = CipherRecord {
            user_id: self.user_id,
            cipher_record_id: record_id,
            ver: current.ver + 1,
            cipher_options: self.get_cipher_options(),
            data: encrypted_data,
        };

        // Update storage
        self.storage
            .up(record_id as u128, &cipher_record, &current)
            .map_err(UserDbError::StorageError)
    }

    pub fn delete(&self, record_id: u64) -> Result<(), UserDbError> {
        self.storage
            .remove(record_id as u128)
            .map_err(UserDbError::StorageError)
    }

    /// List all record IDs belonging to the current user
    pub fn list_records(&self) -> Result<Vec<u128>, UserDbError> {
        // Get all record IDs from storage
        let ids = self.storage.list_ids().map_err(UserDbError::StorageError)?;

        // Filter and convert IDs
        let mut record_ids = Vec::new();
        for id_128 in ids {
            // Read the record to verify ownership
            if let Ok(record) = self.storage.get(id_128) {
                if record.user_id == self.user_id {
                    // Convert u128 to u64 for the record ID
                    record_ids.push(record.cipher_record_id);
                }
            }
        }

        Ok(record_ids)
    }

    /// List all records with their metadata
    pub fn list_records_with_metadata(&self) -> Result<Vec<(u128, u64, u128)>, UserDbError> {
        // Returns vector of (record_id, version, timestamp)
        let ids = self.storage.list_ids().map_err(UserDbError::StorageError)?;

        let mut records = Vec::new();
        for id_128 in ids {
            if let Ok(record) = self.storage.get(id_128) {
                if record.user_id == self.user_id {
                    records.push((record.cipher_record_id, record.ver, record.user_id));
                }
            }
        }

        Ok(records)
    }

    // Helper methods

    fn generate_record_id(&self) -> u128 {
        // Implementation needed: Generate unique record ID
        // Could use timestamps, random numbers, or a combination
        // For now, using a simple timestamp-based approach
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .into()
    }

    fn get_cipher_options(&self) -> Vec<u8> {
        // Return list of currently used cipher options
        // This would depend on the specific cipher implementations used
        vec![
            CipherOption::AES256.code(),
            CipherOption::XChaCha20.code(),
            // Add other ciphers as needed
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;
    /*
    #[test]
    fn test_list_records() {
        // Create temporary directory for testing
        let temp_dir = TempDir::new("user_db_test").unwrap();
        let master_keys = // Initialize test master keys
        let db = UserDb::new(temp_dir.path(), 1, &master_keys).unwrap();

        // Create several test records
        let record1 = Record { /* data */ };
        let record2 = Record { /* data */ };
        let record3 = Record { /* data */ };

        let id1 = db.create(record1).unwrap();
        let id2 = db.create(record2).unwrap();
        let id3 = db.create(record3).unwrap();

        // Test listing records
        let record_ids = db.list_records().unwrap();
        assert_eq!(record_ids.len(), 3);
        assert!(record_ids.contains(&id1));
        assert!(record_ids.contains(&id2));
        assert!(record_ids.contains(&id3));

        // Test listing with metadata
        let records_meta = db.list_records_with_metadata().unwrap();
        assert_eq!(records_meta.len(), 3);
        for (id, ver, user_id) in records_meta {
            assert!(vec![id1, id2, id3].contains(&id));
            assert_eq!(ver, 1); // All records should be version 1
            assert_eq!(user_id, 1); // All records should belong to user 1
        }
    }

    #[test]
    fn test_crud_operations() {
        // Create temporary directory for testing
        let temp_dir = TempDir::new("user_db_test").unwrap();

        // Create test record
        let record = Record {
            // Initialize test record data
        };

        // Initialize UserDb
        let master_keys = // Initialize test master keys
        let db = UserDb::new(temp_dir.path(), 1, &master_keys).unwrap();

        // Test create
        let record_id = db.create(record.clone()).unwrap();

        // Test read
        let retrieved = db.read(record_id).unwrap();
        assert_eq!(retrieved, record);

        // Test update
        let updated_record = Record {
            // Modified test record data
        };
        db.update(record_id, updated_record.clone()).unwrap();

        let retrieved_updated = db.read(record_id).unwrap();
        assert_eq!(retrieved_updated, updated_record);

        // Test delete
        db.delete(record_id).unwrap();
        assert!(matches!(
            db.read(record_id),
            Err(UserDbError::StorageError(StorageError::StorageDataNotFound(_)))
        ));
    }
     */
}
