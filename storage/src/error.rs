use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    //    StoragePathError,
    // #[from] sled::Error
    // TODO Rename it
    #[error("Storage open error: {0}")]
    StorageOpenError(String),
    #[error("Key not found: {0}")]
    StorageDataNotFound(String),
    #[error("Storage set error: {0}")]
    StorageWriteError(String),
    #[error("Storage get error: {0}")]
    StorageReadError(String),
    // other variants
}

/*
impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
*/
