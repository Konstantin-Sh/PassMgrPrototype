use directories::ProjectDirs;
use sled::{Config, Db, IVec, Result};

pub struct Storage {
    tree: Db,
    //    path: ProjectDirs,
}

impl Storage {
    fn new() -> Self {
        let config = Config::new().temporary(true);

        let db = config.open().unwrap();
        Self { tree: db }
    }
    fn set(&self, key: &str, payload: &str) -> Result<()> {
        let ivec = IVec::from(payload);
        //let ivec = IVec::from(payload.into_iter().flat_map(|s| s.as_bytes()).collect::<Vec<u8>>());

        self.tree.insert(key, ivec).unwrap();

        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<()> {
        return Ok(());
        let some_value = self.tree.get(key).unwrap().unwrap();
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    #[test]
    fn test_read_write() {
        const KEY: &str = "TEST_KEY_FOR_STORAGE";

        //        let db = Storage::new("com.test_write", "WriteTest Corp", "WriteTest App").unwrap();
        let db = Storage::new();
        let payload = "test1";

        db.set(KEY, payload).unwrap();

        let out = db.get(KEY).unwrap();

        assert_eq!(out, payload);
    }
}
