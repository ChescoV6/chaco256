//! Core Chaco-256 stream cipher implementation

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of the encryption key in bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// Size of the nonce in bytes (192 bits)
pub const NONCE_SIZE: usize = 24;

/// Size of one block in bytes (128 bytes = 1024 bits)
pub const BLOCK_SIZE: usize = 128;

/// Number of 64-bit words in the state
const STATE_WORDS: usize = 16;

/// Constants for state initialization (ASCII "chaco256", "security", "andpriv", "acy2026")
const CONSTANTS: [u64; 4] = [
    0x636861636f323536, // "chaco256"
    0x7365637572697479, // "security"
    0x616e6470726976,   // "andpriv"
    0x6163793230323600, // "acy2026\0"
];

/// Extended key XOR constants for additional key material
const EXTENDED_KEY_CONSTANTS: [u64; 4] = [
    0x0123456789abcdef,
    0xfedcba9876543210,
    0x13579bdf02468ace,
    0xeca8642fdb975310,
];

/// 256-bit encryption key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_SIZE]);

impl Key {
    /// Create a new key from a byte slice
    ///
    /// # Panics
    ///
    /// Panics if the slice length is not exactly 32 bytes
    pub fn from_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), KEY_SIZE, "Key must be exactly 32 bytes");
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(bytes);
        Key(key)
    }

    /// Generate a random key using the system's secure random number generator
    #[cfg(feature = "std")]
    pub fn generate() -> Self {
        use std::io::Read;
        let mut key = [0u8; KEY_SIZE];
        std::fs::File::open("/dev/urandom")
            .expect("Failed to open /dev/urandom")
            .read_exact(&mut key)
            .expect("Failed to read random bytes");
        Key(key)
    }

    /// Get the key as a byte slice
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

/// 192-bit nonce
#[derive(Clone, Copy)]
pub struct Nonce([u8; NONCE_SIZE]);

impl Nonce {
    /// Create a new nonce from a byte slice
    ///
    /// # Panics
    ///
    /// Panics if the slice length is not exactly 24 bytes
    pub fn from_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), NONCE_SIZE, "Nonce must be exactly 24 bytes");
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(bytes);
        Nonce(nonce)
    }

    /// Generate a random nonce using the system's secure random number generator
    #[cfg(feature = "std")]
    pub fn generate() -> Self {
        use std::io::Read;
        let mut nonce = [0u8; NONCE_SIZE];
        std::fs::File::open("/dev/urandom")
            .expect("Failed to open /dev/urandom")
            .read_exact(&mut nonce)
            .expect("Failed to read random bytes");
        Nonce(nonce)
    }

    /// Get the nonce as a byte slice
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.0
    }
}

/// Number of rounds for encryption
#[derive(Clone, Copy, Debug)]
pub enum Rounds {
    /// 16 rounds - high performance, short-term security
    Light = 16,
    /// 20 rounds - recommended default
    Standard = 20,
    /// 24 rounds - maximum security margin
    Paranoid = 24,
}

/// Chaco-256 stream cipher
pub struct Chaco256 {
    key: Key,
    nonce: Nonce,
    counter: u64,
    rounds: Rounds,
    keystream_buffer: Vec<u8>,
    keystream_pos: usize,
}

impl Chaco256 {
    /// Create a new Chaco-256 cipher instance
    ///
    /// # Arguments
    ///
    /// * `key` - 256-bit encryption key
    /// * `nonce` - 192-bit nonce (must be unique for each message with the same key)
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        Self::new_with_rounds(key, nonce, Rounds::Standard)
    }

    /// Create a new Chaco-256 cipher instance with custom round count
    pub fn new_with_rounds(key: &Key, nonce: &Nonce, rounds: Rounds) -> Self {
        Chaco256 {
            key: key.clone(),
            nonce: *nonce,
            counter: 0,
            rounds,
            keystream_buffer: Vec::new(),
            keystream_pos: 0,
        }
    }

    /// Encrypt data in place
    ///
    /// This XORs the data with the keystream. Can be called multiple times
    /// to encrypt a stream of data.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }

    /// Decrypt data in place
    ///
    /// Identical to encrypt (XOR is self-inverse)
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }

    /// Seek to a specific block position
    ///
    /// This allows random access within the keystream
    pub fn seek(&mut self, block_index: u64) {
        self.counter = block_index;
        self.keystream_buffer.clear();
        self.keystream_pos = 0;
    }

    /// Apply keystream to data
    fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut offset = 0;

        while offset < data.len() {
            // Refill keystream buffer if needed
            if self.keystream_pos >= self.keystream_buffer.len() {
                self.generate_keystream_block();
                self.keystream_pos = 0;
            }

            // XOR data with keystream
            let available = self.keystream_buffer.len() - self.keystream_pos;
            let to_process = (data.len() - offset).min(available);

            for i in 0..to_process {
                data[offset + i] ^= self.keystream_buffer[self.keystream_pos + i];
            }

            offset += to_process;
            self.keystream_pos += to_process;
        }
    }

    /// Generate one block of keystream
    fn generate_keystream_block(&mut self) {
        let mut state = self.initialize_state();
        let initial_state = state;

        // Apply rounds
        let num_rounds = self.rounds as usize;
        for _ in 0..num_rounds {
            Self::round(&mut state);
        }

        // Add initial state (feedforward)
        for i in 0..STATE_WORDS {
            state[i] = state[i].wrapping_add(initial_state[i]);
        }

        // Convert state to bytes
        self.keystream_buffer.clear();
        self.keystream_buffer.reserve(BLOCK_SIZE);
        for word in state.iter() {
            self.keystream_buffer.extend_from_slice(&word.to_le_bytes());
        }

        // Increment counter
        self.counter = self.counter.wrapping_add(1);
    }

    /// Initialize the cipher state
    fn initialize_state(&self) -> [u64; STATE_WORDS] {
        let mut state = [0u64; STATE_WORDS];

        // Constants
        state[0] = CONSTANTS[0];
        state[1] = CONSTANTS[1];
        state[2] = CONSTANTS[2];
        state[3] = CONSTANTS[3];

        // Key (first 256 bits)
        state[4] = u64::from_le_bytes(self.key.0[0..8].try_into().unwrap());
        state[5] = u64::from_le_bytes(self.key.0[8..16].try_into().unwrap());
        state[6] = u64::from_le_bytes(self.key.0[16..24].try_into().unwrap());
        state[7] = u64::from_le_bytes(self.key.0[24..32].try_into().unwrap());

        // Nonce (192 bits) and counter (64 bits)
        state[8] = u64::from_le_bytes(self.nonce.0[0..8].try_into().unwrap());
        state[9] = u64::from_le_bytes(self.nonce.0[8..16].try_into().unwrap());
        state[10] = u64::from_le_bytes(self.nonce.0[16..24].try_into().unwrap());
        state[11] = self.counter;

        // Extended key material (XOR with constants)
        state[12] = state[4] ^ EXTENDED_KEY_CONSTANTS[0];
        state[13] = state[5] ^ EXTENDED_KEY_CONSTANTS[1];
        state[14] = state[6] ^ EXTENDED_KEY_CONSTANTS[2];
        state[15] = state[7] ^ EXTENDED_KEY_CONSTANTS[3];

        state
    }

    /// Perform one complete round (column + diagonal phases)
    #[inline]
    fn round(state: &mut [u64; STATE_WORDS]) {
        // Column phase
        Self::quarter_round(state, 0, 4, 8, 12);
        Self::quarter_round(state, 1, 5, 9, 13);
        Self::quarter_round(state, 2, 6, 10, 14);
        Self::quarter_round(state, 3, 7, 11, 15);

        // Diagonal phase
        Self::quarter_round(state, 0, 5, 10, 15);
        Self::quarter_round(state, 1, 6, 11, 12);
        Self::quarter_round(state, 2, 7, 8, 13);
        Self::quarter_round(state, 3, 4, 9, 14);
    }

    /// Quarter-round function (ARX operations)
    #[inline]
    fn quarter_round(state: &mut [u64; STATE_WORDS], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(32);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(24);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(63);
    }

    /// Generate a single block of keystream without updating internal state
    ///
    /// Useful for deriving keys or generating MACs
    pub fn generate_block(key: &Key, nonce: &Nonce, counter: u64, rounds: Rounds) -> [u8; BLOCK_SIZE] {
        let mut cipher = Self::new_with_rounds(key, nonce, rounds);
        cipher.counter = counter;
        cipher.generate_keystream_block();
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(&cipher.keystream_buffer);
        block
    }
}

impl Drop for Chaco256 {
    fn drop(&mut self) {
        // Zeroize sensitive data
        self.keystream_buffer.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encryption() {
        let key = Key::from_slice(&[0u8; 32]);
        let nonce = Nonce::from_slice(&[0u8; 24]);
        let mut cipher = Chaco256::new(&key, &nonce);

        let plaintext = b"Hello, World!";
        let mut ciphertext = plaintext.to_vec();
        cipher.encrypt(&mut ciphertext);

        // Ciphertext should be different from plaintext
        assert_ne!(&ciphertext[..], plaintext);

        // Decrypt
        let mut cipher2 = Chaco256::new(&key, &nonce);
        cipher2.decrypt(&mut ciphertext);
        assert_eq!(&ciphertext[..], plaintext);
    }

    #[test]
    fn test_empty_input() {
        let key = Key::from_slice(&[0u8; 32]);
        let nonce = Nonce::from_slice(&[0u8; 24]);
        let mut cipher = Chaco256::new(&key, &nonce);

        let mut data = vec![];
        cipher.encrypt(&mut data);
        assert_eq!(data.len(), 0);
    }

    #[test]
    fn test_large_input() {
        let key = Key::from_slice(&[1u8; 32]);
        let nonce = Nonce::from_slice(&[2u8; 24]);
        let mut cipher = Chaco256::new(&key, &nonce);

        let plaintext = vec![0x42u8; 10000];
        let mut ciphertext = plaintext.clone();
        cipher.encrypt(&mut ciphertext);

        assert_ne!(ciphertext, plaintext);

        let mut cipher2 = Chaco256::new(&key, &nonce);
        cipher2.decrypt(&mut ciphertext);
        assert_eq!(ciphertext, plaintext);
    }

    #[test]
    fn test_seek() {
        let key = Key::from_slice(&[3u8; 32]);
        let nonce = Nonce::from_slice(&[4u8; 24]);

        // Encrypt with seeking
        let mut cipher1 = Chaco256::new(&key, &nonce);
        cipher1.seek(5);
        let mut data1 = vec![0u8; 100];
        cipher1.encrypt(&mut data1);

        // Encrypt sequentially
        let mut cipher2 = Chaco256::new(&key, &nonce);
        let mut skip = vec![0u8; 5 * BLOCK_SIZE];
        cipher2.encrypt(&mut skip);
        let mut data2 = vec![0u8; 100];
        cipher2.encrypt(&mut data2);

        assert_eq!(data1, data2);
    }

    #[test]
    fn test_different_rounds() {
        let key = Key::from_slice(&[5u8; 32]);
        let nonce = Nonce::from_slice(&[6u8; 24]);
        let plaintext = b"Test data";

        let mut data_light = plaintext.to_vec();
        let mut cipher_light = Chaco256::new_with_rounds(&key, &nonce, Rounds::Light);
        cipher_light.encrypt(&mut data_light);

        let mut data_standard = plaintext.to_vec();
        let mut cipher_standard = Chaco256::new_with_rounds(&key, &nonce, Rounds::Standard);
        cipher_standard.encrypt(&mut data_standard);

        let mut data_paranoid = plaintext.to_vec();
        let mut cipher_paranoid = Chaco256::new_with_rounds(&key, &nonce, Rounds::Paranoid);
        cipher_paranoid.encrypt(&mut data_paranoid);

        // Different round counts should produce different ciphertexts
        assert_ne!(data_light, data_standard);
        assert_ne!(data_standard, data_paranoid);
        assert_ne!(data_light, data_paranoid);
    }
}
