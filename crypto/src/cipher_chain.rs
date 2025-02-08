use crate::{CipherOption, MasterKeys};
use chacha20::cipher::StreamCipher;
/*
use chacha20poly1305::{
    aead::{AeadCore, AeadInPlace, OsRng},
    ChaCha20Poly1305, Nonce,
};
 */
use pcbc::cipher::{
    generic_array::GenericArray, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockSizeUser,
    KeyInit, KeyIvInit, Unsigned,
};
use pcbc::{Decryptor, Encryptor};
use rand::RngCore;

pub struct CipherChain {
    cipher_chain: Vec<CipherOption>,
    keys: MasterKeys,
}

#[derive(Debug)]
pub enum Error {
    KeyNotFound,
    InvalidKeyLength,
}

impl CipherChain {
    pub fn init(mut self, keys: MasterKeys, cipher_chain: Vec<CipherOption>) {
        self.cipher_chain = cipher_chain;
        self.keys = keys;
    }

    pub fn encrypt(&self, data: &mut Vec<u8>) -> Vec<u8> {
        for cipher in self.cipher_chain.iter() {
            let key = self.keys.get_key(cipher);
            match cipher {
                CipherOption::AES256 => self.process::<aes::Aes256>(data, key),
                CipherOption::ARIA => self.process::<aria::Aria256>(data, key),
                CipherOption::BelT => self.process::<belt_block::BeltBlock>(data, key),
                CipherOption::Camellia => self.process::<camellia::Camellia256>(data, key),
                CipherOption::CAST6 => self.process::<cast6::Cast6>(data, key),
                CipherOption::Kuznyechik => self.process::<kuznyechik::Kuznyechik>(data, key),
                CipherOption::Serpent => self.process::<serpent::Serpent>(data, key),
                CipherOption::Spec => self.process::<speck_cipher::Speck128_256>(data, key),
                CipherOption::Twofish => self.process::<twofish::Twofish>(data, key),
                CipherOption::XChaCha20 => {
                    //let cipher = ChaCha20Poly1305::new(key.into());
                    //let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                    //let _ = cipher.encrypt_in_place(&nonce, b"", data);

                    let mut iv = [0u8; 24];
                    rand::thread_rng().fill_bytes(&mut iv);
                    data.splice(0..0, iv.iter().copied());
                    chacha20::XChaCha20::new(key.into(), &iv.into())
                        .apply_keystream(&mut data[24..]);
                }
                _ => unimplemented!("Cipher not supported for encryption"),
            }
        }
        data.to_vec()
    }

    pub fn decrypt(&self, data: &mut Vec<u8>) -> Vec<u8> {
        for cipher in self.cipher_chain.iter().rev() {
            let key = self.keys.get_key(cipher);
            match cipher {
                CipherOption::AES256 => self.reverse_process::<aes::Aes256>(data, key),
                CipherOption::ARIA => self.reverse_process::<aria::Aria256>(data, key),
                CipherOption::BelT => self.reverse_process::<belt_block::BeltBlock>(data, key),
                CipherOption::Camellia => self.reverse_process::<camellia::Camellia256>(data, key),
                CipherOption::CAST6 => self.reverse_process::<cast6::Cast6>(data, key),
                CipherOption::Kuznyechik => {
                    self.reverse_process::<kuznyechik::Kuznyechik>(data, key)
                }
                CipherOption::Serpent => self.reverse_process::<serpent::Serpent>(data, key),
                CipherOption::Spec => self.reverse_process::<speck_cipher::Speck128_256>(data, key),
                CipherOption::Twofish => self.reverse_process::<twofish::Twofish>(data, key),
                CipherOption::XChaCha20 => {
                    if data.len() < 24 {
                        panic!("Invalid data length");
                    }
                    //let cipher = ChaCha20Poly1305::new(key.into());
                    //let nonce = GenericArray::from_slice(&data[0..24]);
                    //data.drain(0..24);
                    //let _ = cipher.decrypt_in_place(&nonce, b"", data);

                    let iv = &data[0..24];

                    chacha20::XChaCha20::new(key.into(), iv.into())
                        .apply_keystream(&mut data[24..]);
                    data.drain(0..24);
                }
                _ => unimplemented!("Cipher not supported for decryption"),
            }
        }
        data.to_vec()
    }

    fn process<C>(&self, data: &mut Vec<u8>, key: &[u8])
    where
        C: KeyInit + BlockEncryptMut + BlockCipher + BlockSizeUser,
    {
        // Generate IV matching cipher's block size
        let mut iv = GenericArray::<u8, <C as BlockSizeUser>::BlockSize>::default();
        rand::thread_rng().fill_bytes(&mut iv);

        // Prepend IV to data
        data.splice(0..0, iv.iter().copied());

        // Apply PKCS#7 padding
        let block_size = iv.len();
        let len_after_iv = data.len() - block_size;
        let padding = block_size - (len_after_iv % block_size);
        for _ in 0..padding {
            data.push(padding as u8);
        }

        let mut mode = Encryptor::<C>::new(key.into(), &iv);
        for chunk in data[iv.len()..].chunks_mut(block_size) {
            mode.encrypt_block_mut(GenericArray::from_mut_slice(chunk));
        }
    }

    fn reverse_process<C>(&self, data: &mut Vec<u8>, key: &[u8])
    where
        C: KeyInit + BlockDecryptMut + BlockCipher + BlockSizeUser,
    {
        let block_size = <C as BlockSizeUser>::BlockSize::to_usize();
        if data.len() < block_size || (data.len() - block_size) % block_size != 0 {
            panic!("Invalid data length");
        }

        let iv = GenericArray::clone_from_slice(&data[0..block_size]);
        let mut mode = Decryptor::<C>::new(key.into(), &iv);

        for chunk in data[block_size..].chunks_mut(block_size) {
            mode.decrypt_block_mut(GenericArray::from_mut_slice(chunk));
        }

        // Remove padding
        let padding = *data.last().unwrap() as usize;
        if padding <= block_size {
            data.truncate(data.len() - padding);
        }

        // Remove IV
        data.drain(0..block_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MasterKeys;
    use rand::{rngs::OsRng, RngCore};

    fn create_test_keys() -> MasterKeys {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        MasterKeys::from_entropy(&entropy).unwrap()
    }

    #[test]
    fn test_single_cipher_roundtrip() {
        let keys = create_test_keys();
        let chain = CipherChain {
            cipher_chain: vec![CipherOption::AES256],
            keys,
        };

        let original = b"Hello PCBC mode!".to_vec();
        let mut encrypted = original.clone();
        encrypted = chain.encrypt(&mut encrypted);

        let mut decrypted = encrypted.clone();
        decrypted = chain.decrypt(&mut decrypted);

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_multi_cipher_chain() {
        let keys = create_test_keys();
        let chain = CipherChain {
            cipher_chain: vec![
                CipherOption::AES256,
                CipherOption::XChaCha20,
                CipherOption::Kuznyechik,
            ],
            keys,
        };

        let original = b"Multi-cipher chain test".to_vec();
        let mut encrypted = original.clone();
        encrypted = chain.encrypt(&mut encrypted);

        let mut decrypted = encrypted.clone();
        decrypted = chain.decrypt(&mut decrypted);

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_empty_data() {
        let keys = create_test_keys();
        let chain = CipherChain {
            cipher_chain: vec![CipherOption::Twofish],
            keys,
        };

        let original = vec![];
        let mut encrypted = original.clone();
        encrypted = chain.encrypt(&mut encrypted);

        let mut decrypted = encrypted.clone();
        decrypted = chain.decrypt(&mut decrypted);

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_different_block_sizes() {
        let keys = create_test_keys();
        let chain = CipherChain {
            cipher_chain: vec![CipherOption::Kuznyechik],
            keys,
        };

        // Kuznyechik uses 128-bit blocks
        let original = b"Testing 128-bit block cipher".to_vec();
        let mut encrypted = original.clone();
        encrypted = chain.encrypt(&mut encrypted);

        // Verify IV size is 16 bytes for Kuznyechik
        assert_eq!(encrypted.len() % 16, 0);

        let mut decrypted = encrypted.clone();
        decrypted = chain.decrypt(&mut decrypted);

        assert_eq!(original, decrypted);
    }
//TODO Test with other algorithm (Serpent has problem)
    #[test]
    fn test_padding_handling() {
        let keys = create_test_keys();
        let chain = CipherChain {
            cipher_chain: vec![CipherOption::AES256],
            keys,
        };

        // Test data that needs padding (13 bytes)
        let original = b"13-byte test".to_vec();
        let mut encrypted = original.clone();
        encrypted = chain.encrypt(&mut encrypted);

        // Encrypted length should be IV + padded data
        assert_eq!(encrypted.len(), 16 + 16); // IV + 1 block

        let mut decrypted = encrypted.clone();
        decrypted = chain.decrypt(&mut decrypted);

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_stream_cipher_handling() {
        let keys = create_test_keys();
        let chain = CipherChain {
            cipher_chain: vec![CipherOption::XChaCha20],
            keys,
        };

        let original = b"Stream cipher test".to_vec();
        let mut encrypted = original.clone();
        encrypted = chain.encrypt(&mut encrypted);

        // Verify IV/nonce is 24 bytes for XChaCha20
        assert_eq!(encrypted.len(), original.len() + 24);

        let mut decrypted = encrypted.clone();
        decrypted = chain.decrypt(&mut decrypted);

        assert_eq!(original, decrypted);
    }
}
