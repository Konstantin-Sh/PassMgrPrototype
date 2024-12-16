use bincode::{deserialize, serialize};
use directories::ProjectDirs;
use sled::{Config, Db, IVec};

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
        //let ivec = IVec::from(payload);
        //let ivec = IVec::from(payload.into_iter().flat_map(|s| s.as_bytes()).collect::<Vec<u8>>());

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
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    #[test]
    fn test_read_write() {
        const KEY: &str = "TEST_KEY_FOR_STORAGE";

        //        let db = Storage::new("com.test_write", "WriteTest Corp", "WriteTest App").unwrap();
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
}
