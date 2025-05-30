use hmac::Hmac;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Bip39Error {
    #[error("Invalid entropy length")]
    InvalidEntropyLength,
    #[error("Invalid mnemonic")]
    InvalidMnemonic,
    #[error("Invalid str hex conv: {0}")]
    InvalidStrHex(String),
    #[error("passmg-cli err: {0}")]
    PassmgrCliError(String),
    #[error("Invalid seed checksum")]
    InvalidChecksum,
    #[error("Random number generation failed")]
    RngError,
}

pub struct Bip39 {
    entropy: Vec<u8>,
    mnemonic: Vec<String>,
}

impl Bip39 {
    pub fn new(strength: u32) -> Result<Self, Bip39Error> {
        let entropy_bytes = match strength {
            128 => 16,
            160 => 20,
            192 => 24,
            224 => 28,
            256 => 32,
            _ => return Err(Bip39Error::InvalidEntropyLength),
        };

        let mut entropy = vec![0u8; entropy_bytes];
        OsRng.fill_bytes(&mut entropy);

        let mnemonic = Self::entropy_to_mnemonic(&entropy)?;
        Ok(Self { entropy, mnemonic })
    }

    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, Bip39Error> {
        let words: Vec<String> = mnemonic.split_whitespace().map(String::from).collect();

        if !Self::verify_mnemonic(&words) {
            return Err(Bip39Error::InvalidMnemonic);
        }

        let entropy = Self::mnemonic_to_entropy(&words)?;
        Ok(Self {
            entropy,
            mnemonic: words,
        })
    }

    pub fn get_mnemonic(&self) -> String {
        self.mnemonic.join(" ")
    }
    pub fn get_entropy(&self) -> &Vec<u8> {
        &self.entropy
    }

    pub fn get_seed(&self, passphrase: &str) -> Vec<u8> {
        let mnemonic = self.get_mnemonic();
        let salt = format!("mnemonic{passphrase}");

        let mut seed = [0u8; 64];
        let _ =
            pbkdf2::pbkdf2::<Hmac<Sha512>>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed);

        seed.to_vec()
    }

    fn entropy_to_mnemonic(entropy: &[u8]) -> Result<Vec<String>, Bip39Error> {
        let checksum = Self::generate_checksum(entropy);

        // Convert entropy to bits
        let mut bits = String::new();
        for &byte in entropy {
            bits.push_str(&format!("{byte:08b}"));
        }

        // Add checksum bits
        let checksum_bits = entropy.len() / 4;
        bits.push_str(&format!("{checksum:08b}")[..checksum_bits]);

        let wordlist = include_str!("wordlist/english.txt")
            .lines()
            .collect::<Vec<&str>>();

        let mut words = Vec::new();
        // Process bits in chunks of 11 bits
        for i in (0..bits.len()).step_by(11) {
            let chunk = &bits[i..i + 11];
            let idx = usize::from_str_radix(chunk, 2)
                .map_err(|e| Bip39Error::InvalidStrHex(e.to_string()))?;
            words.push(wordlist[idx].to_string());
        }

        Ok(words)
    }

    fn mnemonic_to_entropy(words: &[String]) -> Result<Vec<u8>, Bip39Error> {
        let wordlist = include_str!("wordlist/english.txt")
            .lines()
            .collect::<Vec<&str>>();

        let mut bits = String::new();
        for word in words {
            let idx = wordlist
                .iter()
                .position(|&w| w == word)
                .ok_or(Bip39Error::InvalidMnemonic)?;
            bits.push_str(&format!("{idx:011b}"));
        }

        let checksum_bits = bits.len() / 33;
        let entropy_bits = bits.len() - checksum_bits;

        let mut entropy = Vec::new();
        for i in (0..entropy_bits).step_by(8) {
            let byte = u8::from_str_radix(&bits[i..i + 8], 2)
                .map_err(|e| Bip39Error::InvalidStrHex(e.to_string()))?;
            entropy.push(byte);
        }

        if !Self::verify_checksum(&entropy) {
            return Err(Bip39Error::InvalidChecksum);
        }

        Ok(entropy)
    }

    fn generate_checksum(entropy: &[u8]) -> u8 {
        let mut hasher = Sha256::new();
        hasher.update(entropy);
        let hash = hasher.finalize();
        hash[0]
    }
    // TODO Implement it!!!
    fn verify_checksum(entropy: &[u8]) -> bool {
        let checksum = Self::generate_checksum(entropy);
        let expected_bits = entropy.len() * 8 / 32;
        true //(checksum >> (8 - expected_bits)) == (entropy[entropy.len() - 1] >> (8 - expected_bits))
    }

    fn verify_mnemonic(words: &[String]) -> bool {
        matches!(words.len(), 12 | 15 | 18 | 21 | 24)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_restore() {
        let bip39 = Bip39::new(128).unwrap();
        let mnemonic = bip39.get_mnemonic();

        let restored = Bip39::from_mnemonic(&mnemonic).unwrap();
        assert_eq!(bip39.entropy, restored.entropy);
    }

    #[test]
    fn test_invalid_mnemonic() {
        let result = Bip39::from_mnemonic("invalid mnemonic phrase");
        assert!(matches!(result, Err(Bip39Error::InvalidMnemonic)));
    }
}
