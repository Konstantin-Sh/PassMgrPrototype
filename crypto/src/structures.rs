pub enum CipherOption {
    AES256,     // USA standart
    ARIA,       // Korea standart
    BelT,       // Belarus standart
    Camellia,   // Japan standart
    CAST6,      // AES candidate
    Kuznyechik, // Russia standart
    Kyber1024,
    NTRUP1277,
    Serpent, // AES finalist
    Spec,    // NASA lightweight block cipher
    Twofish, // AES finalist
    XChaCha20, // lightweight block cipher
             // END,       // Terminal symbol
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
            Self::Kuznyechik => 6,
            Self::Kyber1024 => 7,
            Self::NTRUP1277 => 8,
            Self::Serpent => 9,
            Self::Spec => 10,
            Self::Twofish => 11,
            Self::XChaCha20 => 12,
        }
    }
}
