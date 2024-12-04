Looking at the codebase, I can identify the core data structures used for the password management system. Let me break them down with explanations:

The main record-related structures are defined in `src/core/record.rs`:

```rust
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
    pub favourite: bool,           // Whether it's marked as favorite
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
```

For security and encryption, the system uses several key structures defined in `src/keychain/keys.rs`:

```rust
// Encryption methods available
pub enum CipherOrders {
    AES256,      // AES-256 symmetric encryption
    NTRUP1277,   // NTRU Prime asymmetric encryption
}

// Handles encryption/decryption operations
pub struct KeyChain {
    pub ntrup_keys: (Arc<PrivKey>, Arc<PubKey>),  // Asymmetric key pair
    pub aes_key: [u8; SHA256_SIZE],               // Symmetric encryption key
    num_threads: usize,                           // For parallel operations
}
```

The application state is managed through structures in `src/state/mod.rs`:

```rust
pub struct State<'a> {
    pub email: Option<Cow<'a, str>>,         // User's email
    pub server_sync: bool,                   // Whether to sync with server
    pub restoreble: bool,                    // Password recovery enabled
    pub inited: bool,                        // Initialization status
    pub address: Cow<'a, str>,               // User's unique address
    pub secure_key_store: Cow<'a, str>,      // Encrypted keys
    pub secure_data_store: Cow<'a, str>,     // Encrypted user data
    pub settings: SettingsPayload,           // User settings
    pub ready: bool,                         // Storage ready status
    pub version: u16,                        // Data format version
}
```

These structures work together to provide:
1. Secure storage of different types of sensitive information
2. Flexible field customization through the Item structure
3. Strong encryption using both symmetric and asymmetric algorithms
4. State management for syncing and recovery options

The system uses a hierarchical approach where Categories contain Elements, which in turn contain Items, providing a clean and organized way to store different types of sensitive information while maintaining consistent structure and security measures across all record types.
