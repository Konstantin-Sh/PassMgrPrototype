use crate::{
    error::{Result, StorageError},
    structures::CipherRecord,
};

use bincode::{deserialize, serialize};
use sled::{Config, Db, Tree};
use std::path::{Path, PathBuf};

pub struct Storage {
    db: Db,
    path: PathBuf,
    user_db: Tree,
}

impl Storage {
    //TODO check path exist and db open correct, fix error
    pub fn open(path: &Path, uid: [u8; 32]) -> Result<Self> {
        // Check if the path not exists
        // if !path.exists() {
        //     return Err(StorageError::SroragePathNotFoundError(format!(
        //         "Path {:?} does not exist",
        //         path
        //     )));
        // }
        let config = Config::new()
            .path(&path)
            .mode(sled::Mode::HighThroughput)
            .cache_capacity(1024 * 1024 * 128) // 128MB cache
            .flush_every_ms(Some(1000));
        let db = config
            .open()
            .map_err(|e| StorageError::StorageOpenError(e.to_string()))?;
        let user_db = db
            .open_tree(uid)
            .map_err(|e| StorageError::StorageOpenError(e.to_string()))?;
        Ok(Self {
            db,
            path: path.to_path_buf(),
            user_db,
        })
    }
    //TODO check path don't exist and create new db, fix errors

    pub fn init(path: &Path, uid: u128) -> Result<Self> {
        // Check if the path exists
        if path.exists() {
            return Err(StorageError::SrorageExistError(format!(
                "Path {:?} is already exist",
                path
            )));
        }
        let config = Config::new()
            .path(&path)
            .mode(sled::Mode::HighThroughput)
            .cache_capacity(1024 * 1024 * 128) // 128MB cache
            .flush_every_ms(Some(1000));

        let db = config
            .open()
            .map_err(|e| StorageError::StorageOpenError(e.to_string()))?;
        let user_db = db
            .open_tree(uid.to_le_bytes())
            .map_err(|e| StorageError::StorageOpenError(e.to_string()))?;
        Ok(Self {
            db,
            path: path.to_path_buf(),
            user_db,
        })
    }

    pub fn set(&self, key: u64, payload: &CipherRecord) -> Result<()> {
        self.user_db
            .insert(key.to_be_bytes(), serialize(payload).unwrap())
            .map_err(|e| StorageError::StorageWriteError(e.to_string()))?;

        Ok(())
    }
    pub fn get(&self, key: u64) -> Result<CipherRecord> {
        let some_value = self
            .user_db
            .get(key.to_be_bytes())
            .map_err(|e| StorageError::StorageReadError(e.to_string()))?
            .ok_or(StorageError::StorageDataNotFound(key.to_string()))?;
        Ok(deserialize(&some_value).unwrap())
    }
    //TODO implement it  /*old_payload: &CipherRecord*/
    pub fn up(&self, key: u64, payload: &CipherRecord) -> Result<()> {
        // match self.user_db.compare_and_swap(key.to_be_bytes(), old_payload, payload)?

        self.user_db
            .remove(key.to_be_bytes())
            .map_err(|e| StorageError::StorageWriteError(e.to_string()))?;

        self.user_db
            .insert(key.to_be_bytes(), serialize(payload).unwrap())
            .map_err(|e| StorageError::StorageWriteError(e.to_string()))?;

        Ok(())
    }
    //TODO remove all old version `contains_key`
    pub fn remove(&self, key: u64) -> Result<()> {
        self.user_db
            .remove(key.to_be_bytes())
            .map_err(|e| StorageError::StorageWriteError(e.to_string()))?;
        Ok(())
    }
    pub fn list_ids(&self) -> Result<Vec<u64>> {
        self.user_db
            .iter()
            .map(|item| {
                item.map_err(|e| StorageError::StorageReadError(e.to_string()))
                    .and_then(|(key, _value)| {
                        let key_u64 = u64::from_be_bytes(key.as_ref().try_into().map_err(
                            |e: std::array::TryFromSliceError| {
                                StorageError::StorageKeyError(e.to_string())
                            },
                        )?);
                        Ok(key_u64)
                    })
            })
            .collect()
    }
    // TODO refactor to sleed interface
    pub fn list_ids_with_metadata(&self) -> Result<Vec<(u64, u64, [u8; 32])>> {
        // Returns vector of (record_id, version, timestamp)
        let ids = self
            .list_ids()
            .map_err(|e| StorageError::StorageReadError(e.to_string()))?;

        let mut records = Vec::new();
        for id_64 in ids {
            if let Ok(record) = self.get(id_64) {
                // if record.user_id == self.user_id {
                records.push((record.cipher_record_id, record.ver, record.user_id));
                // }
            }
        }

        Ok(records)
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    use crate::StorageError;
    use tempdir::TempDir;

    #[test]
    fn test_read_write() {
        const KEY: u64 = 4242;

        // Create a temporary directory for this test
        let tmp_dir = TempDir::new("test_storage").unwrap();
        let tmp_path = tmp_dir.path(); // Get path as string

        let db = Storage::open(tmp_path, [42; 32]).unwrap();
        let payload = CipherRecord {
            user_id: [1; 32],
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
        const KEY: u64 = 4242;

        // Create a temporary directory for this test
        let tmp_dir = TempDir::new("test_storage").unwrap();
        let tmp_path = tmp_dir.path(); // Get path as string

        let db = Storage::open(tmp_path, [42; 32]).unwrap();
        let payload = CipherRecord {
            user_id: [1; 32],
            cipher_record_id: 1,
            ver: 1,
            cipher_options: [0].to_vec(),
            data: [0, 42, 0, 42].to_vec(),
        };
        db.set(KEY, &payload).unwrap();
        db.remove(KEY).unwrap();

        // Now we expect the data not to be found, so handle the error properly
        //let result = db.read(KEY);

        // Assert that the result is an Err variant with the specific error
        assert!(matches!(
            db.get(KEY),
            Err(StorageError::StorageDataNotFound(_))
        ));
        /*        match result {
            Err(StorageError::StorageDataNotFound(_)) => (),
            _ => panic!("Expected StorageDataNotFound error, but got: {:?}", result),
        }  */
    }
}
