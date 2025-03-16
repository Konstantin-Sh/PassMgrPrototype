use crate::db::Storage;
use crate::error::StorageError;
use crate::structures::{CipherRecord, Record};
use bincode::{deserialize, serialize};
use crypto::cipher_chain::CipherChain;
use crypto::structures::{CipherOption, UserId};
use crypto::MasterKeys;
use std::path::Path;

pub struct UserDb<'a> {
    pub storage: Storage,
    ciphers: CipherChain<'a>,
    user_id: UserId,
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

impl<'a> UserDb<'a> {
    pub fn new(
        path: &Path,
        user_id: UserId,
        master_keys: &'a MasterKeys,
        cipher_chain: Vec<CipherOption>,
    ) -> Result<UserDb<'a>, UserDbError> {
        let storage = Storage::open(path, user_id).map_err(UserDbError::StorageError)?;

        //let mut cipher_chain = CipherChain::new();
        let ciphers = CipherChain {
            cipher_chain,
            keys: master_keys,
        };
        Ok(Self {
            storage,
            ciphers,
            user_id,
        })
    }

    pub fn create(&self, record: Record) -> Result<u64, UserDbError> {
        // Generate new record ID
        let record_id = self.generate_record_id();

        // Serialize the record
        let mut data =
            serialize(&record).map_err(|e| UserDbError::SerializationError(e.to_string()))?;

        // Encrypt the serialized data
        let encrypted_data = self.ciphers.encrypt(&mut data);

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
            .set(record_id, &cipher_record)
            .map_err(UserDbError::StorageError)?;

        Ok(record_id)
    }

    pub fn read(&self, record_id: u64) -> Result<Record, UserDbError> {
        // Retrieve cipher record from storage
        let mut cipher_record = self
            .storage
            .get(record_id)
            .map_err(UserDbError::StorageError)?;

        // Verify user ID
        if cipher_record.user_id != self.user_id {
            return Err(UserDbError::DecryptionError);
        }

        // Decrypt data
        let decrypted_data = self.ciphers.decrypt(&mut cipher_record.data);

        // Deserialize into Record
        let record = deserialize(&decrypted_data)
            .map_err(|e| UserDbError::SerializationError(e.to_string()))?;

        Ok(record)
    }

    pub fn update(&self, record_id: u64, record: Record) -> Result<(), UserDbError> {
        // First read existing record to get current version
        let current = self
            .storage
            .get(record_id)
            .map_err(UserDbError::StorageError)?;

        // Serialize and encrypt new data
        let mut data =
            serialize(&record).map_err(|e| UserDbError::SerializationError(e.to_string()))?;
        let encrypted_data = self.ciphers.encrypt(&mut data);

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
            .up(record_id, &cipher_record /*&current */)
            .map_err(UserDbError::StorageError)
    }

    pub fn delete(&self, record_id: u64) -> Result<(), UserDbError> {
        self.storage
            .remove(record_id)
            .map_err(UserDbError::StorageError)
    }

    /// List all record IDs belonging to the current user
    pub fn list_records(&self) -> Result<Vec<u64>, UserDbError> {
        // Get all record IDs from storage
        let ids = self.storage.list_ids().map_err(UserDbError::StorageError)?;

        // Filter and convert IDs
        let mut record_ids = Vec::new();
        for id_64 in ids {
            // Read the record to verify ownership
            if let Ok(record) = self.storage.get(id_64) {
                if record.user_id == self.user_id {
                    // Convert u128 to u64 for the record ID
                    record_ids.push(record.cipher_record_id);
                }
            }
        }

        Ok(record_ids)
    }

    /// List all records with their metadata
    pub fn list_records_with_metadata(&self) -> Result<Vec<(u64, u64, [u8; 32])>, UserDbError> {
        // Returns vector of (record_id, version, timestamp)
        let ids = self.storage.list_ids().map_err(UserDbError::StorageError)?;

        let mut records = Vec::new();
        for id_64 in ids {
            if let Ok(record) = self.storage.get(id_64) {
                if record.user_id == self.user_id {
                    records.push((record.cipher_record_id, record.ver, record.user_id));
                }
            }
        }

        Ok(records)
    }

    // Helper methods

    fn generate_record_id(&self) -> u64 {
        // Implementation needed: Generate unique record ID
        // Could use timestamps, random numbers, or a combination
        // For now, using a simple timestamp-based approach
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
        // .into()
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
    use crate::structures::{Atributes, Item};

    use super::*;
    use rand::{rngs::OsRng, RngCore};
    use tempdir::TempDir;

    fn create_test_keys() -> MasterKeys {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        MasterKeys::from_entropy(&entropy).unwrap()
    }
    fn create_test_cipher_chain() -> Vec<CipherOption> {
        vec![
            CipherOption::AES256,
            CipherOption::XChaCha20,
            CipherOption::Kuznyechik,
        ]
    }
    fn create_record(password: &str) -> Record {
        let item1 = Item {
            title: String::from("Login"),
            value: String::from("user"),
            types: vec![],
        };

        let item2 = Item {
            title: String::from("Password"),
            value: password.to_string(),
            types: vec![Atributes::Hide],
        };
        Record {
            icon: String::from("icon"),
            created: 1,
            updated: 2,
            fields: vec![item1, item2],
        }
    }

    #[test]
    fn test_list_records() {
        // Create temporary directory for testing
        let temp_dir = TempDir::new("user_db_test").unwrap();
        let master_keys = create_test_keys(); // Initialize test master keys
        let db = UserDb::new(
            temp_dir.path(),
            [1; 32],
            &master_keys,
            create_test_cipher_chain(),
        )
        .unwrap();

        // Create several test records
        let record1 = create_record("Password1");
        let record2 = create_record("Password2");
        let record3 = create_record("Password3");

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
            assert_eq!(user_id, [1; 32]); // All records should belong to user 1
        }
    }

    #[test]
    fn test_crud_operations() {
        // Create temporary directory for testing
        let temp_dir = TempDir::new("user_db_test").unwrap();

        // Create test record
        let record = create_record("Password1");

        // Initialize UserDb
        let master_keys = create_test_keys(); // Initialize test master keys
        let db = UserDb::new(
            temp_dir.path(),
            [1; 32],
            &master_keys,
            create_test_cipher_chain(),
        )
        .unwrap();

        // Test create
        let record_id = db.create(record.clone()).unwrap();

        // Test read
        let retrieved = db.read(record_id).unwrap();
        assert_eq!(retrieved, record);

        // Test update
        let updated_record = create_record("password");
        db.update(record_id, updated_record.clone()).unwrap();

        let retrieved_updated = db.read(record_id).unwrap();
        assert_eq!(retrieved_updated, updated_record);

        // Test delete
        db.delete(record_id).unwrap();
        assert!(matches!(
            db.read(record_id),
            Err(UserDbError::StorageError(
                StorageError::StorageDataNotFound(_)
            ))
        ));
    }
}
