pub enum CipherOption {
    AES256,
    GOST,
    GRASSHOPPER,
    NTRUP1277,
    TWOFISH,
    // TODO Add quantum-resistant ciphers
    // TODO Research terminal symbol
    END, // Terminal symbol
}

impl CipherOption {
    pub fn code(&self) -> u8 {
        match self {
            Self::END => 0,
            Self::AES256 => 1,
            Self::GOST => 3,
            Self::GRASSHOPPER => 4,
            Self::NTRUP1277 => 5,
            Self::TWOFISH => 6,
        }
    }
}
