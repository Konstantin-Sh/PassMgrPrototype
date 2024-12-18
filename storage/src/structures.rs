use serde::{Deserialize, Serialize};


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

pub struct Item {
    title: String,
    value: String,
    types: Vec<Atributes>,
}

pub struct Record {
    icon: String,
    created: u64,
    updated: u64,
    fields: Vec<Item>,
}

pub struct DataBase {
    version: u64,
    timestamp: u64,
    records: Vec<Record>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct CipherRecord {
    pub user_id: u64,
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
