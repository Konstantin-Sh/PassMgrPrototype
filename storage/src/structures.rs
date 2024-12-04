// Represents a single field in a record (like username, password, etc.)
pub struct Item {
    pub title: String,     // Label for the field
    pub value: String,     // The actual value stored
    pub hide: bool,        // Whether the field should be hidden (like passwords)
    pub copy: bool,        // Whether the field can be copied to clipboard
    pub reload: bool,      // Whether the field can be regenerated/reloaded
}

// Base structure for all record types
pub struct Element {
    pub icon: String,              // Icon URL/identifier
    pub created: i64,              // Creation timestamp
    pub updated: i64,              // Last update timestamp
    pub favorite: bool,           // Whether it's marked as favorite
    pub note: String,             // Additional notes
    pub name: String,             // Record name
    pub fields: Vec<Item>,        // Primary fields
    pub extra_fields: Vec<Item>,  // Additional custom fields
}

// Different types of records that can be stored
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
