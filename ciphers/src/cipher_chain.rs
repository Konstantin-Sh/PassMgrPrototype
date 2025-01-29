// cipher_chain.rs
pub trait Cipher {
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
}

pub struct CipherChain {
    ciphers: Vec<Box<dyn Cipher>>,
}

impl CipherChain {
    pub fn new() -> Self {
        Self { ciphers: Vec::new() }
    }

    pub fn add_cipher<C: Cipher + 'static>(&mut self, cipher: C) {
        self.ciphers.push(Box::new(cipher));
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.ciphers.iter()
            .fold(data.to_vec(), |data, cipher| cipher.encrypt(&data))
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.ciphers.iter()
            .rev()  // Reverse order for decryption
            .fold(data.to_vec(), |data, cipher| cipher.decrypt(&data))
    }
}