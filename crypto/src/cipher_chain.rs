pub trait Cipher {
    fn encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8>;
    fn decrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8>;
}
pub trait CipherKey {
    fn as_bytes(&self) -> &[u8];
    fn rotate(&mut self, new_key: &[u8]);
}

pub struct CipherChain {
    ciphers: Vec<Box<dyn Cipher>>,
    keys: Vec<Box<dyn CipherKey>>,
}

#[derive(Debug)]
pub enum Error {
    KeyNotFound,
    InvalidKeyLength,
}

impl Default for CipherChain {
    fn default() -> Self {
        Self::new()
    }
}

impl CipherChain {
    pub fn new() -> Self {
        Self {
            ciphers: Vec::new(),
            keys: Vec::new(),
        }
    }

    pub fn add_cipher_with_key<C, K>(&mut self, cipher: C, key: K)
    where
        C: Cipher + 'static,
        K: CipherKey + 'static,
    {
        self.ciphers.push(Box::new(cipher));
        self.keys.push(Box::new(key));
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.ciphers
            .iter()
            .zip(self.keys.iter())
            .fold(data.to_vec(), |data, (cipher, key)| {
                cipher.encrypt(&data, key.as_bytes())
            })
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.ciphers
            .iter()
            .rev() // Reverse order for decryption
            .zip(self.keys.iter().rev())
            .fold(data.to_vec(), |data, (cipher, key)| {
                cipher.decrypt(&data, key.as_bytes())
            })
    }

    pub fn rotate_key(&mut self, index: usize, new_key: &[u8]) -> Result<(), Error> {
        self.keys
            .get_mut(index)
            .ok_or(Error::KeyNotFound)?
            .rotate(new_key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    pub struct XorKey {
        key: u8,
    }

    impl CipherKey for XorKey {
        fn as_bytes(&self) -> &[u8] {
            std::slice::from_ref(&self.key)
        }

        fn rotate(&mut self, new_key: &[u8]) {
            self.key = new_key[0];
        }
    }

    #[derive(Debug)]
    pub struct XorCipher;

    impl Cipher for XorCipher {
        fn encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
            data.iter().map(|byte| byte ^ key[0]).collect()
        }

        fn decrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
            // XOR is its own inverse
            self.encrypt(data, key)
        }
    }

    #[derive(Debug)]
    pub struct AddCipher;

    impl Cipher for AddCipher {
        fn encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
            data.iter().map(|byte| byte.wrapping_add(key[0])).collect()
        }

        fn decrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
            data.iter().map(|byte| byte.wrapping_sub(key[0])).collect()
        }
    }

    #[test]
    fn test_xor_cipher_chain() {
        let mut chain = CipherChain::new();

        // Add first XOR cipher with key 0x42
        chain.add_cipher_with_key(XorCipher, XorKey { key: 0x42 });

        // Add second XOR cipher with key 0x13
        chain.add_cipher_with_key(XorCipher, XorKey { key: 0x13 });

        let test_data = b"Hello, World!";

        // Encrypt
        let encrypted = chain.encrypt(test_data);

        // Decrypt
        let decrypted = chain.decrypt(&encrypted);

        assert_eq!(test_data, &decrypted[..]);

        // Test intermediate state (after first XOR)
        let expected_first_xor: Vec<u8> = test_data.iter().map(|&b| b ^ 0x42).collect();

        // Verify first XOR transformation
        assert_ne!(&encrypted[..], &expected_first_xor[..]);

        // Test key rotation
        chain.rotate_key(0, &[0x55]).unwrap();
        let encrypted_after_rotation = chain.encrypt(test_data);
        assert_ne!(encrypted, encrypted_after_rotation);
    }

    #[test]
    fn test_single_byte_operations() {
        let cipher = XorCipher;
        let key = XorKey { key: 0x42 };

        let test_byte = 0x55;
        let encrypted = cipher.encrypt(&[test_byte], key.as_bytes());
        let decrypted = cipher.decrypt(&encrypted, key.as_bytes());

        assert_eq!(decrypted[0], test_byte);
        assert_eq!(encrypted[0], test_byte ^ 0x42);
    }

    #[test]
    fn test_mixed_cipher_chain() {
        let mut chain = CipherChain::new();

        // Add XOR cipher with key 0x42
        chain.add_cipher_with_key(XorCipher, XorKey { key: 0x42 });

        // Add Add cipher with key 0x05
        chain.add_cipher_with_key(
            AddCipher,
            XorKey { key: 0x05 }, // Reusing XorKey struct since it's the same concept
        );

        let test_data = b"Hello, World!";

        // Test full chain
        let encrypted = chain.encrypt(test_data);
        let decrypted = chain.decrypt(&encrypted);
        assert_eq!(test_data, &decrypted[..]);

        // Test intermediate states
        let after_xor: Vec<u8> = test_data.iter().map(|&b| b ^ 0x42).collect();

        let after_add: Vec<u8> = after_xor.iter().map(|&b| b.wrapping_add(0x05)).collect();

        assert_eq!(&encrypted[..], &after_add[..]);
    }

    #[test]
    fn test_add_cipher() {
        let cipher = AddCipher;
        let key = XorKey { key: 0x05 };

        // Test wrapping behavior
        let test_bytes = vec![0xFF, 0x00, 0x42];
        let encrypted = cipher.encrypt(&test_bytes, key.as_bytes());

        assert_eq!(encrypted[0], 0x04); // 0xFF + 0x05 = 0x04 (wrapped)
        assert_eq!(encrypted[1], 0x05); // 0x00 + 0x05 = 0x05
        assert_eq!(encrypted[2], 0x47); // 0x42 + 0x05 = 0x47

        let decrypted = cipher.decrypt(&encrypted, key.as_bytes());
        assert_eq!(decrypted, test_bytes);
    }

    #[test]
    fn test_cipher_order() {
        let mut chain_xor_then_add = CipherChain::new();
        chain_xor_then_add.add_cipher_with_key(XorCipher, XorKey { key: 0x42 });
        chain_xor_then_add.add_cipher_with_key(AddCipher, XorKey { key: 0x05 });

        let mut chain_add_then_xor = CipherChain::new();
        chain_add_then_xor.add_cipher_with_key(AddCipher, XorKey { key: 0x05 });
        chain_add_then_xor.add_cipher_with_key(XorCipher, XorKey { key: 0x42 });

        let test_data = b"Test";
        let result1 = chain_xor_then_add.encrypt(test_data);
        let result2 = chain_add_then_xor.encrypt(test_data);

        // Results should be different due to different cipher order
        assert_ne!(result1, result2);

        // But both should decrypt correctly
        assert_eq!(test_data, &chain_xor_then_add.decrypt(&result1)[..]);
        assert_eq!(test_data, &chain_add_then_xor.decrypt(&result2)[..]);
    }

    #[test]
    fn test_key_rotation() {
        let mut chain = CipherChain::new();
        chain.add_cipher_with_key(AddCipher, XorKey { key: 0x05 });

        let test_data = b"Test";
        let encrypted1 = chain.encrypt(test_data);

        // Rotate key
        chain.rotate_key(0, &[0x0A]).unwrap();
        let encrypted2 = chain.encrypt(test_data);

        // Results should be different with different key
        assert_ne!(encrypted1, encrypted2);

        // Should still decrypt correctly after rotation
        let decrypted = chain.decrypt(&encrypted2);
        assert_eq!(test_data, &decrypted[..]);
    }
}
