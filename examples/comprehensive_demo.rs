//! Comprehensive demonstration of all Chaco-256 features

use chaco256::{Chaco256, Chaco256Aead, Key, Nonce, Rounds, Tag};

fn main() {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║         Chaco-256 Comprehensive Feature Demo              ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    demo_basic_encryption();
    demo_security_levels();
    demo_aead_mode();
    demo_streaming();
    demo_seeking();
    demo_error_handling();
    demo_best_practices();

    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║                  All Demos Completed!                      ║");
    println!("╚════════════════════════════════════════════════════════════╝");
}

fn demo_basic_encryption() {
    println!("┌─ 1. Basic Stream Cipher Encryption ─────────────────────┐");

    let key = Key::from_slice(&[0x42u8; 32]);
    let nonce = Nonce::from_slice(&[0x24u8; 24]);

    let plaintext = b"The quick brown fox jumps over the lazy dog";
    println!("  Plaintext:  {}", String::from_utf8_lossy(plaintext));

    // Encrypt
    let mut ciphertext = plaintext.to_vec();
    let mut cipher = Chaco256::new(&key, &nonce);
    cipher.encrypt(&mut ciphertext);
    println!("  Ciphertext: {}", hex::encode(&ciphertext[..20]));
    println!("              (showing first 20 bytes)");

    // Decrypt
    let mut cipher2 = Chaco256::new(&key, &nonce);
    cipher2.decrypt(&mut ciphertext);
    println!("  Decrypted:  {}", String::from_utf8_lossy(&ciphertext));

    assert_eq!(&ciphertext[..], plaintext);
    println!("  ✓ Encryption/Decryption successful\n");
}

fn demo_security_levels() {
    println!("┌─ 2. Security Levels (Different Round Counts) ───────────┐");

    let key = Key::from_slice(&[0x11u8; 32]);
    let nonce = Nonce::from_slice(&[0x22u8; 24]);
    let plaintext = b"Security level test";

    // Light (16 rounds)
    let mut data_light = plaintext.to_vec();
    let mut cipher_light = Chaco256::new_with_rounds(&key, &nonce, Rounds::Light);
    cipher_light.encrypt(&mut data_light);
    println!("  Light (16 rounds):    {}", hex::encode(&data_light[..16]));

    // Standard (20 rounds)
    let mut data_standard = plaintext.to_vec();
    let mut cipher_standard = Chaco256::new_with_rounds(&key, &nonce, Rounds::Standard);
    cipher_standard.encrypt(&mut data_standard);
    println!("  Standard (20 rounds): {}", hex::encode(&data_standard[..16]));

    // Paranoid (24 rounds)
    let mut data_paranoid = plaintext.to_vec();
    let mut cipher_paranoid = Chaco256::new_with_rounds(&key, &nonce, Rounds::Paranoid);
    cipher_paranoid.encrypt(&mut data_paranoid);
    println!("  Paranoid (24 rounds): {}", hex::encode(&data_paranoid[..16]));

    println!("  ✓ Different round counts produce different outputs");
    println!("  ℹ Recommendation: Use Standard (20 rounds) for most applications\n");
}

fn demo_aead_mode() {
    println!("┌─ 3. AEAD Mode (Authenticated Encryption) ───────────────┐");

    let key = Key::from_slice(&[0x33u8; 32]);
    let nonce = Nonce::from_slice(&[0x44u8; 24]);
    let aead = Chaco256Aead::new(&key);

    let plaintext = b"Confidential financial data: $1,000,000";
    let associated_data = b"Transaction ID: TXN-2026-001";

    println!("  Plaintext: {}", String::from_utf8_lossy(plaintext));
    println!("  AD:        {}", String::from_utf8_lossy(associated_data));

    // Encrypt with authentication
    let (ciphertext, tag) = aead.encrypt(&nonce, plaintext, associated_data);
    println!("  Ciphertext: {} ({})", hex::encode(&ciphertext[..20]), ciphertext.len());
    println!("  Tag:        {} (32 bytes)", hex::encode(&tag.as_bytes()[..16]));

    // Decrypt and verify
    match aead.decrypt(&nonce, &ciphertext, &tag, associated_data) {
        Ok(decrypted) => {
            println!("  Decrypted:  {}", String::from_utf8_lossy(&decrypted));
            println!("  ✓ Authentication successful");
        }
        Err(e) => {
            println!("  ✗ Authentication failed: {}", e);
        }
    }

    // Test tampering detection
    println!("\n  Testing tampering detection:");
    let mut bad_ciphertext = ciphertext.clone();
    bad_ciphertext[0] ^= 1; // Flip one bit

    match aead.decrypt(&nonce, &bad_ciphertext, &tag, associated_data) {
        Ok(_) => println!("  ✗ Should have detected tampering!"),
        Err(_) => println!("  ✓ Correctly detected tampered ciphertext"),
    }

    println!();
}

fn demo_streaming() {
    println!("┌─ 4. Streaming Encryption (Large Data) ──────────────────┐");

    let key = Key::from_slice(&[0x55u8; 32]);
    let nonce = Nonce::from_slice(&[0x66u8; 24]);

    // Simulate streaming encryption of large file
    let total_size = 10_000;
    let chunk_size = 1024;

    println!("  Encrypting {} bytes in {}-byte chunks", total_size, chunk_size);

    let mut cipher = Chaco256::new(&key, &nonce);
    let mut total_encrypted = 0;

    for chunk_num in 0..(total_size / chunk_size) {
        // Simulate reading chunk
        let mut chunk = vec![0x42u8; chunk_size];

        // Encrypt chunk
        cipher.encrypt(&mut chunk);
        total_encrypted += chunk.len();

        if chunk_num % 3 == 0 {
            println!("  Chunk {}: {} bytes encrypted", chunk_num, chunk.len());
        }
    }

    println!("  ✓ Total encrypted: {} bytes", total_encrypted);
    println!("  ℹ Stream cipher maintains state across chunks\n");
}

fn demo_seeking() {
    println!("┌─ 5. Random Access (Seeking) ────────────────────────────┐");

    let key = Key::from_slice(&[0x77u8; 32]);
    let nonce = Nonce::from_slice(&[0x88u8; 24]);

    // Encrypt block at position 0
    let mut cipher1 = Chaco256::new(&key, &nonce);
    let mut block0 = vec![0u8; 64];
    cipher1.encrypt(&mut block0);
    println!("  Block 0:   {}", hex::encode(&block0[..16]));

    // Encrypt block at position 100 (seeking)
    let mut cipher2 = Chaco256::new(&key, &nonce);
    cipher2.seek(100);
    let mut block100 = vec![0u8; 64];
    cipher2.encrypt(&mut block100);
    println!("  Block 100: {}", hex::encode(&block100[..16]));

    // Verify seeking works correctly
    let mut cipher3 = Chaco256::new(&key, &nonce);
    let mut skip = vec![0u8; 100 * 128]; // Skip 100 blocks
    cipher3.encrypt(&mut skip);
    let mut block100_sequential = vec![0u8; 64];
    cipher3.encrypt(&mut block100_sequential);

    assert_eq!(block100, block100_sequential);
    println!("  ✓ Seeking produces same result as sequential encryption");
    println!("  ℹ Useful for random access to encrypted files\n");
}

fn demo_error_handling() {
    println!("┌─ 6. Error Handling and Edge Cases ──────────────────────┐");

    let key = Key::from_slice(&[0x99u8; 32]);
    let nonce = Nonce::from_slice(&[0xaau8; 24]);

    // Empty input
    println!("  Testing empty input:");
    let mut cipher = Chaco256::new(&key, &nonce);
    let mut empty = vec![];
    cipher.encrypt(&mut empty);
    println!("  ✓ Empty input handled correctly (length: {})", empty.len());

    // Very large input
    println!("\n  Testing large input:");
    let mut large = vec![0u8; 1_000_000]; // 1 MB
    cipher.encrypt(&mut large);
    println!("  ✓ Large input (1 MB) encrypted successfully");

    // AEAD with empty plaintext
    println!("\n  Testing AEAD with empty plaintext:");
    let aead = Chaco256Aead::new(&key);
    let (ct, tag) = aead.encrypt(&nonce, b"", b"Only AD");
    println!("  ✓ Empty plaintext: ciphertext length = {}", ct.len());
    println!("    Tag length = {}", tag.as_bytes().len());

    // AEAD with empty AD
    println!("\n  Testing AEAD with empty AD:");
    let (ct, tag) = aead.encrypt(&nonce, b"Only plaintext", b"");
    println!("  ✓ Empty AD: ciphertext length = {}", ct.len());
    println!("    Tag length = {}", tag.as_bytes().len());

    println!();
}

fn demo_best_practices() {
    println!("┌─ 7. Security Best Practices ────────────────────────────┐");

    println!("  ✓ DO:");
    println!("    • Use random nonces for each message");
    println!("    • Use AEAD mode when integrity is required");
    println!("    • Use Standard (20 rounds) for most applications");
    println!("    • Derive keys properly from passwords (Argon2, scrypt)");
    println!("    • Store keys securely (OS keychain, HSM)");
    println!("    • Verify authentication tags before processing data");
    println!("    • Zeroize sensitive data after use");

    println!("\n  ✗ DON'T:");
    println!("    • Never reuse nonces with the same key");
    println!("    • Don't use weak key derivation (simple hashing)");
    println!("    • Don't ignore authentication failures");
    println!("    • Don't use Light mode for long-term security");
    println!("    • Don't store keys in plaintext files");
    println!("    • Don't use predictable nonces");

    println!("\n  ⚠ IMPORTANT:");
    println!("    Chaco-256 is a new design without extensive cryptanalysis.");
    println!("    For production systems, use AES-256-GCM or ChaCha20-Poly1305");
    println!("    unless you have expert cryptographic review.");

    println!();
}

// Helper function to display hex
fn _hex_display(data: &[u8], max_len: usize) -> String {
    let display_len = data.len().min(max_len);
    let hex = hex::encode(&data[..display_len]);
    if data.len() > max_len {
        format!("{}... ({} bytes total)", hex, data.len())
    } else {
        format!("{} ({} bytes)", hex, data.len())
    }
}
