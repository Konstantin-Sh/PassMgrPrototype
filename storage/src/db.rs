use crate::{
    error::{Result, StorageError},
    structures::CipherRecord,
};

use bincode::{deserialize, serialize};
use sled::{Config, Db};
use std::path::PathBuf;

pub struct Storage {
    db: Db,
    path: PathBuf,
}

impl Storage {
    //TODO check path exist and db open correct, fix error
    fn open(path: PathBuf) -> Result<Self> {
        let config = Config::new().temporary(true);

        let db = config
            .open()
            .map_err(|e| StorageError::StorageOpenError(e.to_string()))?;
        Ok(Self { db, path })
    }
    //TODO check path don't exist and create new db, fix errors
    pub fn init(path: PathBuf) -> Result<Self> {
        let config = Config::new()
            .path(&path)
            .mode(sled::Mode::HighThroughput)
            .cache_capacity(1024 * 1024 * 128) // 128MB cache
            .flush_every_ms(Some(1000));

        let db = config
            .open()
            .map_err(|e| StorageError::StorageOpenError(e.to_string()))?;

        Ok(Self { db, path })
    }
    fn create(&self, key: &str, payload: &CipherRecord) -> Result<()> {
        self.db
            .insert(key, serialize(payload).unwrap())
            .map_err(|e| StorageError::StorageWriteError(e.to_string()))?;

        Ok(())
    }
    pub fn read(&self, key: &str) -> Result<CipherRecord> {
        let some_value = self
            .db
            .get(key)
            .map_err(|e| StorageError::StorageReadError(e.to_string()))?
            .ok_or(StorageError::StorageDataNotFound(key.to_string()))?;
        Ok(deserialize(&some_value).unwrap())
    }
    //TODO implement it
    fn update(&self, key: &str, payload: &CipherRecord) -> Result<()> {
        self.db
            .insert(key, serialize(payload).unwrap())
            .map_err(|e| StorageError::StorageWriteError(e.to_string()))?;

        Ok(())
    }
    pub fn delete(&self, key: &str) -> Result<()> {
        self.db
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
        //TODO create random path for test
        let db = Storage::init().unwrap();
        let payload = CipherRecord {
            user_id: 1,
            cipher_record_id: 1,
            ver: 1,
            cipher_options: [0].to_vec(),
            data: [0, 42, 0, 42].to_vec(),
        };

        db.create(KEY, &payload).unwrap();

        let out = db.read(KEY).unwrap();

        assert_eq!(out, payload);
    }
    #[test]
    fn test_remove() {
        const KEY: &str = "TEST_KEY_FOR_STORAGE1";
        //TODO create random path for test
        let db = Storage::init().unwrap();
        let payload = CipherRecord {
            user_id: 1,
            cipher_record_id: 1,
            ver: 1,
            cipher_options: [0].to_vec(),
            data: [0, 42, 0, 42].to_vec(),
        };
        db.create(KEY, &payload).unwrap();
        db.delete(KEY).unwrap();
        let out = db.read(KEY);
        assert_eq!(out, Error::StorageError::StorageDataNotFound());
    }
}
