// Represents a single field in a record (like username, password, etc.)
pub struct ItemOld {
    pub title: String, // Label for the field
    pub value: String, // The actual value stored
    pub hide: bool,    // Whether the field should be hidden (like passwords)
    pub copy: bool,    // Whether the field can be copied to clipboard
    pub reload: bool,  // Whether the field can be regenerated/reloaded
}

// Base structure for all record types
pub struct Element {
    pub icon: String,            // Icon URL/identifier
    pub created: i64,            // Creation timestamp
    pub updated: i64,            // Last update timestamp
    pub favorite: bool,          // Whether it's marked as favorite
    pub note: String,            // Additional notes
    pub name: String,            // Record name
    pub fields: Vec<Item>,       // Primary fields
    pub extra_fields: Vec<Item>, // Additional custom fields
}

// Different types of records that can be stored
/*
pub enum Categories {
    Login(Element),          // Website/application login credentials
    CryptoWallet(Element),   // Cryptocurrency wallet information
    CreditCard(Element),     // Credit card details
    Identity(Element),       // Personal identity information
    BankAccount(Element),    // Bank account details
    EmailAccount(Element),   // Email account credentials
    Passport(Element),       // Passport information
    DriverLicense(Element),  // Driver's license information
    WifiPassword(Element),   // WiFi network credentials
    Other(Element),         // Miscellaneous records
}
*/

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

pub struct CipherRecord {
    ver: u64,
    cipher_options: Vec<u8>,
    data: Vec<u8>,
}

pub struct CipherDataBase {
    version: u64,
    timestamp: u64,
    records: Vec<CipherRecord>,
}
