use crypto::UserId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum Atributes {
    Hide,
    Copy,
    Reload,
}

impl Atributes {
    pub fn code(&self) -> u8 {
        match self {
            Self::Hide => 0,
            Self::Copy => 1,
            Self::Reload => 2,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Item {
    pub title: String,
    pub value: String,
    pub types: Vec<Atributes>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Record {
    pub icon: String,
    pub created: u64,
    pub updated: u64,
    pub fields: Vec<Item>,
}

pub struct DataBase {
    version: u64,
    timestamp: u64,
    nonce: u64,
    records: Vec<Record>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct CipherRecord {
    pub user_id: UserId,
    pub cipher_record_id: u64,
    pub ver: u64, // TODO research
    pub cipher_options: Vec<u8>,
    pub data: Vec<u8>,
}
// TODO Add index cipher_record_id -> record_id + ver

pub struct CipherDataBase {
    version: u64,
    timestamp: u64,
    records: Vec<CipherRecord>,
}
