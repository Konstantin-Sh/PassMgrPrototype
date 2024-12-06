Let me analyze the core data structures used in this Proton Pass codebase. I'll focus on the fundamental types and explain their purpose and design.

The most important data structures appear to be:

1. Password-Related Structures:
```rust
pub struct RandomPasswordConfig {
    pub length: u32,
    pub numbers: bool,
    pub uppercase_letters: bool,
    pub symbols: bool,
}

pub struct PassphraseConfig {
    pub separator: WordSeparator,
    pub capitalise: bool,
    pub include_numbers: bool,
    pub count: u32,
}

pub enum PasswordScore {
    Vulnerable,
    Weak, 
    Strong,
}

pub struct PasswordScoreResult {
    pub numeric_score: f64,
    pub password_score: PasswordScore,
    pub penalties: Vec<PasswordPenalty>,
}
```
These structures handle password generation and scoring. `RandomPasswordConfig` and `PassphraseConfig` define options for generating passwords, while `PasswordScore` and `PasswordScoreResult` handle password strength evaluation.

2. TOTP Authentication:
```rust
pub struct TOTP {
    pub label: Option<String>,
    pub secret: String,
    pub issuer: Option<String>,
    pub algorithm: Option<Algorithm>,
    pub digits: Option<u8>,
    pub period: Option<u16>,
}

pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}
```
This handles Time-based One-Time Password authentication, storing configuration like the secret key, hash algorithm, and digit count.

3. Host/Domain Parsing:
```rust
pub enum HostInfo {
    Host {
        protocol: String,
        subdomain: Option<String>,
        domain: String,
        tld: Option<String>,
    },
    Ip {
        ip: String,
    }
}
```
This enum represents parsed URL information, distinguishing between domain names and IP addresses.

4. File Handling:
```rust
pub enum FileGroup {
    Image,
    Photo,
    VectorImage,
    Video,
    Audio,
    Key,
    Text,
    Calendar,
    Pdf,
    Word,
    PowerPoint,
    Excel,
    Document,
    Unknown,
}
```
This enum categorizes different types of files that the system can handle.

5. Credit Card Detection:
```rust
pub enum CreditCardType {
    Visa,
    Mastercard,
    AmericanExpress,
    DinersClub,
    Discover,
    JCB,
    UnionPay,
    Maestro,
    Elo,
    Mir,
    Hiper,
    Hipercard,
    Unknown,
}
```
This enum represents different credit card types that can be detected based on card numbers.

The key design patterns I notice here are:

1. Extensive use of enums for type-safe state representation
2. Optional fields using `Option<T>` for nullable values
3. Clear separation of concerns between different types of functionality
4. Comprehensive error types for each module
5. Configuration structs that encapsulate related settings

These data structures form the foundation of a password manager system that handles:
- Password generation and strength assessment
- Two-factor authentication
- URL/domain parsing
- File type detection
- Credit card validation
- Error handling across different contexts

---

Let me locate these data structures in the codebase:

Password-Related Structures (RandomPasswordConfig, PassphraseConfig, PasswordScore, etc.) are found in:
proton-pass-common/src/password/mod.rs
TOTP Authentication structures (TOTP, Algorithm) are defined in:
proton-pass-common/src/totp/totp.rs and proton-pass-common/src/totp/algorithm.rs
Host/Domain Parsing (HostInfo) is located in:
proton-pass-common/src/host.rs
File Handling (FileGroup) is defined in:
proton-pass-common/src/file/mod.rs
Credit Card Detection (CreditCardType) is found in:
proton-pass-common/src/creditcard/detector.rs

These core data structures are all located in the proton-pass-common directory, which serves as the main library containing the business logic. The other directories (proton-pass-mobile and proton-pass-web) then use these structures through bindings for their respective platforms.

---

from https://github.com/protonpass/pass-contents-proto-definition/blob/main/protos/item_v1.proto

```
message PasskeyCreationData {
	string os_name = 1;
	string os_version = 2;
	string device_name = 3;
	string app_version = 4;
}

message Passkey {
	string key_id = 1;
	bytes content = 2;
	string domain = 3;
	string rp_id = 4;
	string rp_name = 5;
	string user_name = 6;
	string user_display_name = 7;
	bytes user_id = 8;
	uint32 create_time = 9;
	string note = 10;
	bytes credential_id = 11;
	bytes user_handle = 12;
	PasskeyCreationData creation_data = 13;
}

message ItemLogin {
	string item_email = 1;
	string password = 2;
	repeated string urls = 3;
	string totp_uri = 4;
	repeated Passkey passkeys = 5;
	string item_username = 6;
}

...

message ItemCreditCard {
	string cardholder_name = 1;
	CardType card_type = 2;
	string number = 3;
	string verification_number = 4;
	// Expected format: YYYY-MM, always containing two numbers for the month, even if is 01
	string expiration_date = 5;
	string pin = 6;
}

message ItemIdentity {

	// Personal details
	// Shown
	string full_name = 1;
	string email = 2;
	string phone_number = 3;
	// Additional
	string first_name = 4;
	string middle_name = 5;
	string last_name = 6;
	string birthdate = 7;
	string gender = 8;
	repeated ExtraField extra_personal_details = 9;

	// Address details
	// Shown
	string organization = 10;
	string street_address = 11;
	string zip_or_postal_code = 12;
	string city = 13;
	string state_or_province = 14;
	string country_or_region = 15;
	// Additional
	string floor = 16;
	string county = 17;
	repeated ExtraField extra_address_details = 18;

	// Contact details
	// Shown
	string social_security_number = 19;
	string passport_number = 20;
	string license_number = 21;
	string website = 22;
	string x_handle = 23;
	string second_phone_number = 24;
	// Additional
	string linkedin = 25;
	string reddit = 26;
	string facebook = 27;
	string yahoo = 28;
	string instagram = 29;
	repeated ExtraField extra_contact_details = 30;

	// Work details
	// Shown
	string company = 31;
	string job_title = 32;
	// Additional
	string personal_website = 33;
	string work_phone_number = 34;
	string work_email = 35;
	repeated ExtraField extra_work_details = 36;

	// Extra sections
	repeated ExtraIdentitySection extra_sections = 37;
}
```
