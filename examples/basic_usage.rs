//! Basic usage examples for Chaco-256

use chaco256::{Chaco256, Chaco256Aead, Key, Nonce, Rounds};

fn main() {
    println!("Chaco-256 Usage Examples");
    println!("========================\n");

    // Example 1: Basic stream cipher encryption
    example_stream_cipher();

    // Example 2: AEAD mode
    example_aead();

    // Example 3: File encryption
    example_file_encryption();

    // Example 4: Different security levels
    example_security_levels();
}

fn example_stream_cipher() {
    println!("1. Stream Cipher Mode");
    println!("---------------------");

    // Generate random key and nonce
    // In production, use a proper key derivation function
    let key = Key::from_slice(&[0x42u8; 32]);
    let nonce = Nonce::from_slice(&[0x24u8; 24]);

    // Create cipher
    let mut cipher = Chaco256::new(&key, &nonce);

    // Encrypt data
    let plaintext = b"Hello, Chaco-256! This is a secret message.";
    let mut ciphertext = plaintext.to_vec();
    cipher.encrypt(&mut ciphertext);

    println!("Plaintext:  {:?}", String::from_utf8_lossy(plaintext));
    println!("Ciphertext: {}", hex::encode(&ciphertext));

    // Decrypt data
    let mut cipher2 = Chaco256::new(&key, &nonce);
    cipher2.decrypt(&mut ciphertext);

    println!("Decrypted:  {:?}", String::from_utf8_lossy(&ciphertext));
    println!();
}

fn example_aead() {
    println!("2. AEAD Mode (Authenticated Encryption)");
    println!("----------------------------------------");

    let key = Key::from_slice(&[0x11u8; 32]);
    let nonce = Nonce::from_slice(&[0x22u8; 24]);

    // Create AEAD cipher
    let aead = Chaco256Aead::new(&key);

    // Encrypt with authentication
    let plaintext = b"Confidential data";
    let associated_data = b"Public header information";

    let (ciphertext, tag) = aead.encrypt(&nonce, plaintext, associated_data);

    println!("Plaintext:  {:?}", String::from_utf8_lossy(plaintext));
    println!("AD:         {:?}", String::from_utf8_lossy(associated_data));
    println!("Ciphertext: {}", hex::encode(&ciphertext));
    println!("Tag:        {}", hex::encode(tag.as_bytes()));

    // Decrypt and verify
    match aead.decrypt(&nonce, &ciphertext, &tag, associated_data) {
        Ok(decrypted) => {
            println!("Decrypted:  {:?}", String::from_utf8_lossy(&decrypted));
            println!("✓ Authentication successful");
        }
        Err(e) => {
            println!("✗ Authentication failed: {}", e);
        }
    }

    // Try with modified ciphertext
    let mut bad_ciphertext = ciphertext.clone();
    bad_ciphertext[0] ^= 1;

    match aead.decrypt(&nonce, &bad_ciphertext, &tag, associated_data) {
        Ok(_) => println!("✗ Should have failed!"),
        Err(_) => println!("✓ Correctly rejected tampered data"),
    }

    println!();
}

fn example_file_encryption() {
    println!("3. File Encryption Pattern");
    println!("--------------------------");

    let key = Key::from_slice(&[0x33u8; 32]);
    let nonce = Nonce::from_slice(&[0x44u8; 24]);

    // Simulate file data
    let file_data = b"This is the content of a file that we want to encrypt.\n\
                      It can be quite large, and Chaco-256 will handle it efficiently.\n\
                      The cipher processes data in 128-byte blocks.";

    println!("Original size: {} bytes", file_data.len());

    // Encrypt
    let mut encrypted = file_data.to_vec();
    let mut cipher = Chaco256::new(&key, &nonce);
    cipher.encrypt(&mut encrypted);

    println!("Encrypted size: {} bytes (same as original)", encrypted.len());

    // Decrypt
    let mut cipher2 = Chaco256::new(&key, &nonce);
    cipher2.decrypt(&mut encrypted);

    println!("Decrypted successfully: {}", encrypted == file_data);
    println!();
}

fn example_security_levels() {
    println!("4. Different Security Levels");
    println!("----------------------------");

    let key = Key::from_slice(&[0x55u8; 32]);
    let nonce = Nonce::from_slice(&[0x66u8; 24]);
    let plaintext = b"Test data for different security levels";

    // Light (16 rounds) - High performance
    let mut cipher_light = Chaco256::new_with_rounds(&key, &nonce, Rounds::Light);
    let mut data_light = plaintext.to_vec();
    cipher_light.encrypt(&mut data_light);
    println!("Light (16 rounds):    {} bytes encrypted", data_light.len());

    // Standard (20 rounds) - Recommended
    let mut cipher_standard = Chaco256::new_with_rounds(&key, &nonce, Rounds::Standard);
    let mut data_standard = plaintext.to_vec();
    cipher_standard.encrypt(&mut data_standard);
    println!("Standard (20 rounds): {} bytes encrypted", data_standard.len());

    // Paranoid (24 rounds) - Maximum security
    let mut cipher_paranoid = Chaco256::new_with_rounds(&key, &nonce, Rounds::Paranoid);
    let mut data_paranoid = plaintext.to_vec();
    cipher_paranoid.encrypt(&mut data_paranoid);
    println!("Paranoid (24 rounds): {} bytes encrypted", data_paranoid.len());

    println!("\nNote: Different round counts produce different ciphertexts");
    println!("Use Standard (20 rounds) for most applications");
    println!();
}

/// Example: Encrypting a large file in chunks
#[allow(dead_code)]
fn encrypt_large_file_example() {
    let key = Key::from_slice(&[0x77u8; 32]);
    let nonce = Nonce::from_slice(&[0x88u8; 24]);
    let mut cipher = Chaco256::new(&key, &nonce);

    // Simulate reading and encrypting file in chunks
    let chunk_size = 4096; // 4KB chunks
    let total_size = 1_000_000; // 1MB file

    for chunk_num in 0..(total_size / chunk_size) {
        // In real code, read chunk from file
        let mut chunk = vec![0u8; chunk_size];

        // Encrypt chunk in place
        cipher.encrypt(&mut chunk);

        // In real code, write encrypted chunk to output file
        println!("Encrypted chunk {} ({} bytes)", chunk_num, chunk.len());
    }
}

/// Example: Random access encryption (seeking)
#[allow(dead_code)]
fn random_access_example() {
    let key = Key::from_slice(&[0x99u8; 32]);
    let nonce = Nonce::from_slice(&[0xaau8; 24]);

    // Encrypt block at position 1000
    let mut cipher = Chaco256::new(&key, &nonce);
    cipher.seek(1000);

    let mut data = vec![0u8; 128];
    cipher.encrypt(&mut data);

    println!("Encrypted block at position 1000");

    // Later, decrypt the same block
    let mut cipher2 = Chaco256::new(&key, &nonce);
    cipher2.seek(1000);
    cipher2.decrypt(&mut data);

    println!("Decrypted block at position 1000");
}
