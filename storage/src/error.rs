use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    //    StoragePathError,
    // TODO Rename it
    #[error("Storage open error: {0}")]
    StorageOpenError(String),
    #[error("Key not found: {0}")]
    StorageDataNotFound(String),
    #[error("Storage write error: {0}")]
    StorageWriteError(String),
    #[error("Storage read error: {0}")]
    StorageReadError(String),
    #[error("Storage open error: {0}")]
    SroragePathNotFoundError(String),
    #[error("Storage create error: {0}")]
    SrorageExistError(String),
    // other variants
}

pub type Result<T> = std::result::Result<T, StorageError>;
