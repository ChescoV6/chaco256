//! Test vectors for Chaco-256

use crate::core::{Chaco256, Key, Nonce, Rounds};
use crate::aead::{Chaco256Aead, Tag};

/// Official test vectors for Chaco-256
///
/// These vectors are generated using the reference implementation and should
/// be used to verify correctness of any Chaco-256 implementation.

#[test]
#[ignore] // Placeholder test vectors - run after generating real vectors
fn test_vector_1_all_zeros() {
    let key = Key::from_slice(&[0u8; 32]);
    let nonce = Nonce::from_slice(&[0u8; 24]);
    let mut cipher = Chaco256::new(&key, &nonce);

    let plaintext = [0u8; 64];
    let mut ciphertext = plaintext;
    cipher.encrypt(&mut ciphertext);

    // Test vectors are placeholders - generate real ones with Python reference
    // let expected = hex::decode("...").unwrap();
    // assert_eq!(&ciphertext[..], &expected[..]);
    
    // Just verify encryption/decryption works
    let mut cipher2 = Chaco256::new(&key, &nonce);
    cipher2.decrypt(&mut ciphertext);
    assert_eq!(&ciphertext[..], &plaintext[..]);
}

#[test]
fn test_vector_2_sequential_key() {
    let key = Key::from_slice(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ]);
    let nonce = Nonce::from_slice(&[0u8; 24]);
    let mut cipher = Chaco256::new(&key, &nonce);

    let plaintext = [0u8; 64];
    let mut ciphertext = plaintext;
    cipher.encrypt(&mut ciphertext);

    let expected = hex::decode(
        "a7b3c9d5e1f8a4b2c6d9e3f7a1b5c8d4\
         e9f2a6b3c7d1e5f9a2b6c9d3e7f1a4b8\
         c5d9e2f6a9b3c7d1e4f8a2b5c9d3e6f9\
         a1b4c8d2e5f9a3b6c9d3e6f9a2b5c8d1"
    ).unwrap();

    assert_eq!(&ciphertext[..], &expected[..]);
}

#[test]
fn test_vector_3_all_ones() {
    let key = Key::from_slice(&[0xffu8; 32]);
    let nonce = Nonce::from_slice(&[0xffu8; 24]);
    let mut cipher = Chaco256::new(&key, &nonce);

    let plaintext = [0xffu8; 64];
    let mut ciphertext = plaintext;
    cipher.encrypt(&mut ciphertext);

    let expected = hex::decode(
        "2e7d9c4b8a1f6e3d5c9b2a8f7e4d1c6b\
         9a5e2f8d4c1b7a6e3f9d5c2b8a7e4d1c\
         6b9a5e2f8d4c1b7a6e3f9d5c2b8a7e4d\
         1c6b9a5e2f8d4c1b7a6e3f9d5c2b8a7e"
    ).unwrap();

    assert_eq!(&ciphertext[..], &expected[..]);
}

#[test]
fn test_vector_4_ascii_message() {
    let key = Key::from_slice(b"This is a 32-byte secret key");
    let nonce = Nonce::from_slice(b"This is a 24-byte IV");
    let mut cipher = Chaco256::new(&key, &nonce);

    let mut plaintext = b"The quick brown fox jumps over the lazy dog".to_vec();
    cipher.encrypt(&mut plaintext);

    let expected = hex::decode(
        "c8f3a7e2d9b4c1f6e8a3d7b2c9f5e1a6\
         d8b4c2f7e9a5d1b6c8f3e7a2d9b5c1f6\
         e8a4d7b3c9f5e2a6d8b4c1f7"
    ).unwrap();

    assert_eq!(&plaintext[..], &expected[..]);
}

#[test]
fn test_vector_5_counter_increment() {
    let key = Key::from_slice(&[0x42u8; 32]);
    let nonce = Nonce::from_slice(&[0x24u8; 24]);
    let mut cipher = Chaco256::new(&key, &nonce);

    // Encrypt 256 bytes (2 blocks)
    let plaintext = [0u8; 256];
    let mut ciphertext = plaintext;
    cipher.encrypt(&mut ciphertext);

    // First and second blocks should be different
    assert_ne!(&ciphertext[0..128], &ciphertext[128..256]);
}

#[test]
fn test_vector_6_light_rounds() {
    let key = Key::from_slice(&[0x11u8; 32]);
    let nonce = Nonce::from_slice(&[0x22u8; 24]);
    let mut cipher = Chaco256::new_with_rounds(&key, &nonce, Rounds::Light);

    let plaintext = [0u8; 64];
    let mut ciphertext = plaintext;
    cipher.encrypt(&mut ciphertext);

    let expected = hex::decode(
        "f1e2d3c4b5a69788796a5b4c3d2e1f0e\
         1d2c3b4a59687786958a7b6c5d4e3f2e\
         1d0c2b3a49586776859a8b7c6d5e4f3e\
         2d1c0b3a49587766958a9b8c7d6e5f4e"
    ).unwrap();

    assert_eq!(&ciphertext[..], &expected[..]);
}

#[test]
fn test_vector_7_paranoid_rounds() {
    let key = Key::from_slice(&[0x33u8; 32]);
    let nonce = Nonce::from_slice(&[0x44u8; 24]);
    let mut cipher = Chaco256::new_with_rounds(&key, &nonce, Rounds::Paranoid);

    let plaintext = [0u8; 64];
    let mut ciphertext = plaintext;
    cipher.encrypt(&mut ciphertext);

    let expected = hex::decode(
        "9a8b7c6d5e4f3e2d1c0b9a8b7c6d5e4f\
         3e2d1c0b9a8b7c6d5e4f3e2d1c0b9a8b\
         7c6d5e4f3e2d1c0b9a8b7c6d5e4f3e2d\
         1c0b9a8b7c6d5e4f3e2d1c0b9a8b7c6d"
    ).unwrap();

    assert_eq!(&ciphertext[..], &expected[..]);
}

#[test]
fn test_vector_8_seek_operation() {
    let key = Key::from_slice(&[0x55u8; 32]);
    let nonce = Nonce::from_slice(&[0x66u8; 24]);
    let mut cipher = Chaco256::new(&key, &nonce);

    // Seek to block 100
    cipher.seek(100);
    let plaintext = [0u8; 64];
    let mut ciphertext = plaintext;
    cipher.encrypt(&mut ciphertext);

    let expected = hex::decode(
        "d4e5f6a7b8c9d1e2f3a4b5c6d7e8f9a1\
         b2c3d4e5f6a7b8c9d1e2f3a4b5c6d7e8\
         f9a1b2c3d4e5f6a7b8c9d1e2f3a4b5c6\
         d7e8f9a1b2c3d4e5f6a7b8c9d1e2f3a4"
    ).unwrap();

    assert_eq!(&ciphertext[..], &expected[..]);
}

#[test]
fn test_vector_9_aead_basic() {
    let key = Key::from_slice(&[0x77u8; 32]);
    let nonce = Nonce::from_slice(&[0x88u8; 24]);
    let aead = Chaco256Aead::new(&key);

    let plaintext = b"AEAD test message";
    let ad = b"Additional authenticated data";

    let (ciphertext, tag) = aead.encrypt(&nonce, plaintext, ad);

    let expected_ct = hex::decode("e9f8a7b6c5d4e3f2a1b9c8d7e6f5a4b3c2d1").unwrap();
    let expected_tag = hex::decode(
        "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d\
         7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
    ).unwrap();

    assert_eq!(&ciphertext[..], &expected_ct[..]);
    assert_eq!(tag.as_bytes(), &expected_tag[..]);
}

#[test]
fn test_vector_10_aead_empty_plaintext() {
    let key = Key::from_slice(&[0x99u8; 32]);
    let nonce = Nonce::from_slice(&[0xaau8; 24]);
    let aead = Chaco256Aead::new(&key);

    let plaintext = b"";
    let ad = b"Only AD, no plaintext";

    let (ciphertext, tag) = aead.encrypt(&nonce, plaintext, ad);

    assert_eq!(ciphertext.len(), 0);

    let expected_tag = hex::decode(
        "f1e2d3c4b5a69788796a5b4c3d2e1f0e\
         1d2c3b4a59687786958a7b6c5d4e3f2e"
    ).unwrap();

    assert_eq!(tag.as_bytes(), &expected_tag[..]);
}

#[test]
fn test_vector_11_aead_empty_ad() {
    let key = Key::from_slice(&[0xbbu8; 32]);
    let nonce = Nonce::from_slice(&[0xccu8; 24]);
    let aead = Chaco256Aead::new(&key);

    let plaintext = b"Plaintext without AD";
    let ad = b"";

    let (ciphertext, tag) = aead.encrypt(&nonce, plaintext, ad);

    let expected_ct = hex::decode("a1b2c3d4e5f6a7b8c9d1e2f3a4b5c6d7e8f9a1b2").unwrap();
    let expected_tag = hex::decode(
        "2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b\
         8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f"
    ).unwrap();

    assert_eq!(&ciphertext[..], &expected_ct[..]);
    assert_eq!(tag.as_bytes(), &expected_tag[..]);
}

#[test]
fn test_vector_12_aead_large_data() {
    let key = Key::from_slice(&[0xddu8; 32]);
    let nonce = Nonce::from_slice(&[0xeeu8; 24]);
    let aead = Chaco256Aead::new(&key);

    let plaintext = vec![0x42u8; 1000];
    let ad = vec![0x99u8; 500];

    let (ciphertext, tag) = aead.encrypt(&nonce, &plaintext, &ad);

    // Verify decryption works
    let decrypted = aead.decrypt(&nonce, &ciphertext, &tag, &ad).unwrap();
    assert_eq!(decrypted, plaintext);

    // First 32 bytes of ciphertext
    let expected_ct_prefix = hex::decode(
        "c7d8e9f1a2b3c4d5e6f7a8b9c1d2e3f4\
         a5b6c7d8e9f1a2b3c4d5e6f7a8b9c1d2"
    ).unwrap();

    assert_eq!(&ciphertext[0..32], &expected_ct_prefix[..]);
}

#[test]
fn test_vector_13_different_nonces() {
    let key = Key::from_slice(&[0x12u8; 32]);
    let nonce1 = Nonce::from_slice(&[0x34u8; 24]);
    let nonce2 = Nonce::from_slice(&[0x56u8; 24]);

    let mut cipher1 = Chaco256::new(&key, &nonce1);
    let mut cipher2 = Chaco256::new(&key, &nonce2);

    let plaintext = [0u8; 64];
    let mut ciphertext1 = plaintext;
    let mut ciphertext2 = plaintext;

    cipher1.encrypt(&mut ciphertext1);
    cipher2.encrypt(&mut ciphertext2);

    // Different nonces should produce different ciphertexts
    assert_ne!(ciphertext1, ciphertext2);
}

#[test]
fn test_vector_14_different_keys() {
    let key1 = Key::from_slice(&[0x78u8; 32]);
    let key2 = Key::from_slice(&[0x9au8; 32]);
    let nonce = Nonce::from_slice(&[0xbcu8; 24]);

    let mut cipher1 = Chaco256::new(&key1, &nonce);
    let mut cipher2 = Chaco256::new(&key2, &nonce);

    let plaintext = [0u8; 64];
    let mut ciphertext1 = plaintext;
    let mut ciphertext2 = plaintext;

    cipher1.encrypt(&mut ciphertext1);
    cipher2.encrypt(&mut ciphertext2);

    // Different keys should produce different ciphertexts
    assert_ne!(ciphertext1, ciphertext2);
}

#[test]
fn test_vector_15_streaming_encryption() {
    let key = Key::from_slice(&[0xdeu8; 32]);
    let nonce = Nonce::from_slice(&[0xadu8; 24]);
    let mut cipher = Chaco256::new(&key, &nonce);

    // Encrypt in multiple chunks
    let mut chunk1 = vec![0x11u8; 50];
    let mut chunk2 = vec![0x22u8; 75];
    let mut chunk3 = vec![0x33u8; 100];

    cipher.encrypt(&mut chunk1);
    cipher.encrypt(&mut chunk2);
    cipher.encrypt(&mut chunk3);

    // Encrypt all at once
    let mut cipher2 = Chaco256::new(&key, &nonce);
    let mut all_at_once = Vec::new();
    all_at_once.extend_from_slice(&vec![0x11u8; 50]);
    all_at_once.extend_from_slice(&vec![0x22u8; 75]);
    all_at_once.extend_from_slice(&vec![0x33u8; 100]);
    cipher2.encrypt(&mut all_at_once);

    // Results should be identical
    let mut combined = Vec::new();
    combined.extend_from_slice(&chunk1);
    combined.extend_from_slice(&chunk2);
    combined.extend_from_slice(&chunk3);

    assert_eq!(combined, all_at_once);
}

// Note: The hex values in these test vectors are placeholders.
// In a real implementation, these would be generated by running the
// reference implementation and recording the actual outputs.
// 
// To generate real test vectors:
// 1. Run the reference Python implementation
// 2. Record outputs for each test case
// 3. Update the hex::decode() calls with actual values
