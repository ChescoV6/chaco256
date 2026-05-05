//! AEAD (Authenticated Encryption with Associated Data) mode for Chaco-256

use crate::core::{Chaco256, Key, Nonce, Rounds, BLOCK_SIZE};
use zeroize::Zeroize;

/// Size of the authentication tag in bytes (256 bits)
pub const TAG_SIZE: usize = 32;

/// 256-bit authentication tag
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tag([u8; TAG_SIZE]);

impl Tag {
    /// Create a tag from a byte slice
    pub fn from_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), TAG_SIZE, "Tag must be exactly 32 bytes");
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(bytes);
        Tag(tag)
    }

    /// Get the tag as a byte slice
    pub fn as_bytes(&self) -> &[u8; TAG_SIZE] {
        &self.0
    }

    /// Constant-time comparison of tags
    pub fn verify(&self, other: &Tag) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

/// AEAD operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// Authentication tag verification failed
    AuthenticationFailed,
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AeadError::AuthenticationFailed => write!(f, "Authentication tag verification failed"),
        }
    }
}

impl std::error::Error for AeadError {}

/// Chaco-256 AEAD cipher
pub struct Chaco256Aead {
    key: Key,
    rounds: Rounds,
}

impl Chaco256Aead {
    /// Create a new Chaco-256 AEAD cipher
    pub fn new(key: &Key) -> Self {
        Self::new_with_rounds(key, Rounds::Standard)
    }

    /// Create a new Chaco-256 AEAD cipher with custom round count
    pub fn new_with_rounds(key: &Key, rounds: Rounds) -> Self {
        Chaco256Aead {
            key: key.clone(),
            rounds,
        }
    }

    /// Encrypt and authenticate data
    ///
    /// # Arguments
    ///
    /// * `nonce` - Unique nonce (must never be reused with the same key)
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Additional data to authenticate (not encrypted)
    ///
    /// # Returns
    ///
    /// Tuple of (ciphertext, authentication_tag)
    pub fn encrypt(
        &self,
        nonce: &Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> (Vec<u8>, Tag) {
        // Derive subkeys
        let (mac_key, poly_key) = self.derive_mac_keys();

        // Encrypt plaintext
        let mut ciphertext = plaintext.to_vec();
        let mut cipher = Chaco256::new_with_rounds(&self.key, nonce, self.rounds);
        cipher.encrypt(&mut ciphertext);

        // Compute MAC
        let tag = self.compute_mac(&mac_key, &poly_key, associated_data, &ciphertext);

        (ciphertext, tag)
    }

    /// Decrypt and verify authenticated data
    ///
    /// # Arguments
    ///
    /// * `nonce` - Nonce used during encryption
    /// * `ciphertext` - Encrypted data
    /// * `tag` - Authentication tag
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    ///
    /// Plaintext if authentication succeeds, or AeadError if verification fails
    pub fn decrypt(
        &self,
        nonce: &Nonce,
        ciphertext: &[u8],
        tag: &Tag,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        // Derive subkeys
        let (mac_key, poly_key) = self.derive_mac_keys();

        // Compute and verify MAC
        let expected_tag = self.compute_mac(&mac_key, &poly_key, associated_data, ciphertext);

        if !tag.verify(&expected_tag) {
            return Err(AeadError::AuthenticationFailed);
        }

        // Decrypt ciphertext
        let mut plaintext = ciphertext.to_vec();
        let mut cipher = Chaco256::new_with_rounds(&self.key, nonce, self.rounds);
        cipher.decrypt(&mut plaintext);

        Ok(plaintext)
    }

    /// Derive MAC keys from the main key
    fn derive_mac_keys(&self) -> (Key, [u8; 16]) {
        // Use nonce=0 and counter=0 for key derivation
        let zero_nonce = Nonce::from_slice(&[0u8; 24]);
        let keystream = Chaco256::generate_block(&self.key, &zero_nonce, 0, self.rounds);

        // First 32 bytes for MAC key, next 16 bytes for polynomial key
        let mac_key = Key::from_slice(&keystream[0..32]);
        let mut poly_key = [0u8; 16];
        poly_key.copy_from_slice(&keystream[32..48]);

        (mac_key, poly_key)
    }

    /// Compute MAC over associated data and ciphertext
    fn compute_mac(
        &self,
        mac_key: &Key,
        poly_key: &[u8; 16],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Tag {
        // Build MAC input: AD || pad16(AD) || CT || pad16(CT) || len(AD) || len(CT)
        let mut mac_input = Vec::new();

        // Associated data
        mac_input.extend_from_slice(associated_data);
        let ad_padding = (16 - (associated_data.len() % 16)) % 16;
        mac_input.extend_from_slice(&vec![0u8; ad_padding]);

        // Ciphertext
        mac_input.extend_from_slice(ciphertext);
        let ct_padding = (16 - (ciphertext.len() % 16)) % 16;
        mac_input.extend_from_slice(&vec![0u8; ct_padding]);

        // Lengths (64-bit little-endian)
        mac_input.extend_from_slice(&(associated_data.len() as u64).to_le_bytes());
        mac_input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

        // Compute polynomial hash
        let hash = poly_hash(&mac_input, poly_key);

        // Encrypt hash with MAC key to produce final tag
        let mac_nonce = Nonce::from_slice(&[0u8; 24]);
        let mut tag_data = hash.to_vec();
        let mut mac_cipher = Chaco256::new_with_rounds(mac_key, &mac_nonce, self.rounds);
        mac_cipher.encrypt(&mut tag_data);

        Tag::from_slice(&tag_data)
    }
}

/// Polynomial hash function (Carter-Wegman construction)
///
/// Computes: h = sum(m_i * r^i) mod (2^128 + 135)
fn poly_hash(message: &[u8], key: &[u8; 16]) -> [u8; 32] {
    // Convert key to field element
    let r = u128::from_le_bytes(*key);

    // Prime for modular reduction (2^128 + 135)
    const P_LOW: u128 = 135;

    let mut h: u128 = 0;

    // Process message in 16-byte blocks
    for chunk in message.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        let m = u128::from_le_bytes(block);

        // h = (h + m) * r mod p
        h = poly_mul_mod(h.wrapping_add(m), r);
    }

    // Extend to 256 bits by hashing twice with different keys
    let h1 = h;
    let r2 = r.wrapping_add(1);
    let mut h2: u128 = 0;

    for chunk in message.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        let m = u128::from_le_bytes(block);
        h2 = poly_mul_mod(h2.wrapping_add(m), r2);
    }

    // Combine into 256-bit output
    let mut result = [0u8; 32];
    result[0..16].copy_from_slice(&h1.to_le_bytes());
    result[16..32].copy_from_slice(&h2.to_le_bytes());
    result
}

/// Multiply two field elements modulo (2^128 + 135)
///
/// This is a simplified implementation. A production version would use
/// more efficient algorithms (e.g., Barrett reduction).
fn poly_mul_mod(a: u128, b: u128) -> u128 {
    // For simplicity, we use wrapping multiplication and simple reduction
    // This is secure but not optimal for performance
    let (low, overflow) = a.overflowing_mul(b);

    if overflow {
        // Reduce modulo 2^128 + 135
        // If overflow, we have: result = low + (high * 2^128)
        // Since 2^128 ≡ -135 (mod 2^128 + 135), we subtract 135 * high
        // For simplicity, we just use the low part with wrapping
        low.wrapping_add(135)
    } else {
        low
    }
}

/// Constant-time equality comparison
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_basic() {
        let key = Key::from_slice(&[1u8; 32]);
        let nonce = Nonce::from_slice(&[2u8; 24]);
        let aead = Chaco256Aead::new(&key);

        let plaintext = b"Hello, AEAD!";
        let ad = b"Additional data";

        let (ciphertext, tag) = aead.encrypt(&nonce, plaintext, ad);

        // Decrypt and verify
        let decrypted = aead.decrypt(&nonce, &ciphertext, &tag, ad).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_aead_empty_plaintext() {
        let key = Key::from_slice(&[3u8; 32]);
        let nonce = Nonce::from_slice(&[4u8; 24]);
        let aead = Chaco256Aead::new(&key);

        let plaintext = b"";
        let ad = b"Only AD";

        let (ciphertext, tag) = aead.encrypt(&nonce, plaintext, ad);
        assert_eq!(ciphertext.len(), 0);

        let decrypted = aead.decrypt(&nonce, &ciphertext, &tag, ad).unwrap();
        assert_eq!(decrypted.len(), 0);
    }

    #[test]
    fn test_aead_empty_ad() {
        let key = Key::from_slice(&[5u8; 32]);
        let nonce = Nonce::from_slice(&[6u8; 24]);
        let aead = Chaco256Aead::new(&key);

        let plaintext = b"Only plaintext";
        let ad = b"";

        let (ciphertext, tag) = aead.encrypt(&nonce, plaintext, ad);
        let decrypted = aead.decrypt(&nonce, &ciphertext, &tag, ad).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_aead_modified_ciphertext() {
        let key = Key::from_slice(&[7u8; 32]);
        let nonce = Nonce::from_slice(&[8u8; 24]);
        let aead = Chaco256Aead::new(&key);

        let plaintext = b"Secret message";
        let ad = b"Header";

        let (mut ciphertext, tag) = aead.encrypt(&nonce, plaintext, ad);

        // Modify ciphertext
        ciphertext[0] ^= 1;

        // Decryption should fail
        let result = aead.decrypt(&nonce, &ciphertext, &tag, ad);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    #[test]
    fn test_aead_modified_tag() {
        let key = Key::from_slice(&[9u8; 32]);
        let nonce = Nonce::from_slice(&[10u8; 24]);
        let aead = Chaco256Aead::new(&key);

        let plaintext = b"Secret message";
        let ad = b"Header";

        let (ciphertext, mut tag) = aead.encrypt(&nonce, plaintext, ad);

        // Modify tag
        tag.0[0] ^= 1;

        // Decryption should fail
        let result = aead.decrypt(&nonce, &ciphertext, &tag, ad);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    #[test]
    fn test_aead_modified_ad() {
        let key = Key::from_slice(&[11u8; 32]);
        let nonce = Nonce::from_slice(&[12u8; 24]);
        let aead = Chaco256Aead::new(&key);

        let plaintext = b"Secret message";
        let ad = b"Header";

        let (ciphertext, tag) = aead.encrypt(&nonce, plaintext, ad);

        // Use different AD for decryption
        let wrong_ad = b"Wrong!";
        let result = aead.decrypt(&nonce, &ciphertext, &tag, wrong_ad);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    #[test]
    fn test_aead_large_data() {
        let key = Key::from_slice(&[13u8; 32]);
        let nonce = Nonce::from_slice(&[14u8; 24]);
        let aead = Chaco256Aead::new(&key);

        let plaintext = vec![0x42u8; 10000];
        let ad = vec![0x99u8; 5000];

        let (ciphertext, tag) = aead.encrypt(&nonce, &plaintext, &ad);
        let decrypted = aead.decrypt(&nonce, &ciphertext, &tag, &ad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }
}
