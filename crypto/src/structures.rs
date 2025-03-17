pub type UserId = [u8; 32];

pub enum CipherOption {
    AES256,     // USA standart
    ARIA,       // Korea standart
    BelT,       // Belarus standart
    Camellia,   // Japan standart
    CAST6,      // AES candidate
    Dilithium,  // quantum secure
    Kuznyechik, // Russia standart
    Kyber1024,
    NTRUP1277,
    Serpent,   // AES finalist
    Spec,      // NASA lightweight block cipher
    Twofish,   // AES finalist
    XChaCha20, // lightweight block cipher
}

impl CipherOption {
    pub fn code(&self) -> u8 {
        match self {
            // Self::END => 0,
            Self::AES256 => 1,
            Self::ARIA => 2,
            Self::BelT => 3,
            Self::Camellia => 4,
            Self::CAST6 => 5,
            Self::Dilithium => 6,
            Self::Kuznyechik => 7,
            Self::Kyber1024 => 8,
            Self::NTRUP1277 => 9,
            Self::Serpent => 10,
            Self::Spec => 11,
            Self::Twofish => 12,
            Self::XChaCha20 => 13,
        }
    }
}
