pub enum CipherOption {
    AES256,
    XChaCha20,
    GRASSHOPPER,
    NTRUP1277,
    TWOFISH,
    Kyber1024,
    // TODO Add quantum-resistant ciphers
    // TODO Research terminal symbol
    END, // Terminal symbol
}

impl CipherOption {
    pub fn code(&self) -> u8 {
        match self {
            Self::END => 0,
            Self::AES256 => 1,
            Self::XChaCha20 => 3,
            Self::GRASSHOPPER => 4,
            Self::NTRUP1277 => 5,
            Self::TWOFISH => 6,
            Self::Kyber1024 => 7,
        }
    }
}
