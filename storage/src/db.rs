use bincode::{deserialize, serialize};
use directories::ProjectDirs;
use sled::{Config, Db};

use crate::structures::CipherRecord;
use crate::StorageError;

pub struct Storage {
    tree: Db,
    //    path: ProjectDirs,
}

impl Storage {
    fn new() -> Result<Self, StorageError> {
        let config = Config::new().temporary(true);

        let db = config
            .open()
            .map_err(|e| StorageError::StorageOpenError(e.to_string()))?;
        Ok(Self { tree: db })
    }
    fn set(&self, key: &str, payload: &CipherRecord) -> Result<(), StorageError> {
        self.tree
            .insert(key, serialize(payload).unwrap())
            .map_err(|e| StorageError::StorageWriteError(e.to_string()))?;

        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<CipherRecord, StorageError> {
        let some_value = self
            .tree
            .get(key)
            .map_err(|e| StorageError::StorageReadError(e.to_string()))?
            .ok_or(StorageError::StorageDataNotFound(key.to_string()))?;
        Ok(deserialize(&some_value).unwrap())
    }
    pub fn remove(&self, key: &str) -> Result<(), StorageError> {
        self.tree
            .remove(key)
            .map_err(|e| StorageError::StorageReadError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    #[test]
    fn test_read_write() {
        const KEY: &str = "TEST_KEY_FOR_STORAGE";

        let db = Storage::new().unwrap();
        let payload = CipherRecord {
            user_id: 1,
            cipher_record_id: 1,
            ver: 1,
            cipher_options: [0].to_vec(),
            data: [0, 42, 0, 42].to_vec(),
        };

        db.set(KEY, &payload).unwrap();

        let out = db.get(KEY).unwrap();

        assert_eq!(out, payload);
    }
    #[test]
    fn test_remove() {
        const KEY: &str = "TEST_KEY_FOR_STORAGE1";
        let db = Storage::new().unwrap();
        let payload = CipherRecord {
            user_id: 1,
            cipher_record_id: 1,
            ver: 1,
            cipher_options: [0].to_vec(),
            data: [0, 42, 0, 42].to_vec(),
        };
        db.set(KEY, &payload).unwrap();
        db.remove(KEY).unwrap();
        let out = db.get(KEY);
        assert_eq!(out, Error::StorageError::StorageDataNotFound());
    }
}
