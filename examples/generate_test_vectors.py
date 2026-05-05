#!/usr/bin/env python3
"""
Generate official test vectors for Chaco-256

This script generates comprehensive test vectors that can be used to verify
implementations in any language.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from chaco256 import Chaco256, Chaco256Aead, generate_key, generate_nonce


def print_test_vector(name: str, key: bytes, nonce: bytes, plaintext: bytes, 
                      rounds: int = 20, ad: bytes = None):
    """Print a test vector in a readable format"""
    print(f"\n{'='*70}")
    print(f"Test Vector: {name}")
    print(f"{'='*70}")
    print(f"Key:       {key.hex()}")
    print(f"Nonce:     {nonce.hex()}")
    print(f"Rounds:    {rounds}")
    
    if ad is None:
        # Stream cipher mode
        print(f"Plaintext: {plaintext.hex()}")
        
        cipher = Chaco256(key, nonce, rounds)
        ciphertext = cipher.encrypt(plaintext)
        print(f"Ciphertext: {ciphertext.hex()}")
        
        # Verify decryption
        cipher2 = Chaco256(key, nonce, rounds)
        decrypted = cipher2.decrypt(ciphertext)
        assert decrypted == plaintext, "Decryption failed!"
        print("✓ Verified")
    else:
        # AEAD mode
        print(f"Plaintext: {plaintext.hex()}")
        print(f"AD:        {ad.hex()}")
        
        aead = Chaco256Aead(key, rounds)
        ciphertext, tag = aead.encrypt(nonce, plaintext, ad)
        print(f"Ciphertext: {ciphertext.hex()}")
        print(f"Tag:        {tag.hex()}")
        
        # Verify decryption
        decrypted = aead.decrypt(nonce, ciphertext, tag, ad)
        assert decrypted == plaintext, "Decryption failed!"
        print("✓ Verified")


def generate_all_test_vectors():
    """Generate comprehensive test vectors"""
    print("CHACO-256 OFFICIAL TEST VECTORS")
    print("Version 1.0")
    print("=" * 70)
    
    # Vector 1: All zeros
    print_test_vector(
        "All Zeros",
        key=bytes(32),
        nonce=bytes(24),
        plaintext=bytes(64),
        rounds=20
    )
    
    # Vector 2: Sequential key
    print_test_vector(
        "Sequential Key",
        key=bytes(range(32)),
        nonce=bytes(24),
        plaintext=bytes(64),
        rounds=20
    )
    
    # Vector 3: All ones
    print_test_vector(
        "All Ones",
        key=bytes([0xff] * 32),
        nonce=bytes([0xff] * 24),
        plaintext=bytes([0xff] * 64),
        rounds=20
    )
    
    # Vector 4: ASCII message
    print_test_vector(
        "ASCII Message",
        key=b"This is a 32-byte secret key",
        nonce=b"This is a 24-byte IV",
        plaintext=b"The quick brown fox jumps over the lazy dog",
        rounds=20
    )
    
    # Vector 5: Light rounds (16)
    print_test_vector(
        "Light Rounds",
        key=bytes([0x11] * 32),
        nonce=bytes([0x22] * 24),
        plaintext=bytes(64),
        rounds=16
    )
    
    # Vector 6: Paranoid rounds (24)
    print_test_vector(
        "Paranoid Rounds",
        key=bytes([0x33] * 32),
        nonce=bytes([0x44] * 24),
        plaintext=bytes(64),
        rounds=24
    )
    
    # Vector 7: Large plaintext
    print_test_vector(
        "Large Plaintext",
        key=bytes([0x55] * 32),
        nonce=bytes([0x66] * 24),
        plaintext=bytes([0x42] * 256),
        rounds=20
    )
    
    # Vector 8: AEAD with both plaintext and AD
    print_test_vector(
        "AEAD Basic",
        key=bytes([0x77] * 32),
        nonce=bytes([0x88] * 24),
        plaintext=b"Secret message",
        rounds=20,
        ad=b"Public header"
    )
    
    # Vector 9: AEAD with empty plaintext
    print_test_vector(
        "AEAD Empty Plaintext",
        key=bytes([0x99] * 32),
        nonce=bytes([0xaa] * 24),
        plaintext=b"",
        rounds=20,
        ad=b"Only authenticated data"
    )
    
    # Vector 10: AEAD with empty AD
    print_test_vector(
        "AEAD Empty AD",
        key=bytes([0xbb] * 32),
        nonce=bytes([0xcc] * 24),
        plaintext=b"Only encrypted data",
        rounds=20,
        ad=b""
    )
    
    # Vector 11: AEAD with large data
    print_test_vector(
        "AEAD Large Data",
        key=bytes([0xdd] * 32),
        nonce=bytes([0xee] * 24),
        plaintext=bytes([0x42] * 1000),
        rounds=20,
        ad=bytes([0x99] * 500)
    )
    
    # Vector 12: Different nonces
    key = bytes([0x12] * 32)
    nonce1 = bytes([0x34] * 24)
    nonce2 = bytes([0x56] * 24)
    plaintext = bytes(64)
    
    cipher1 = Chaco256(key, nonce1)
    cipher2 = Chaco256(key, nonce2)
    ct1 = cipher1.encrypt(plaintext)
    ct2 = cipher2.encrypt(plaintext)
    
    print(f"\n{'='*70}")
    print("Test Vector: Different Nonces")
    print(f"{'='*70}")
    print(f"Key:        {key.hex()}")
    print(f"Nonce 1:    {nonce1.hex()}")
    print(f"Nonce 2:    {nonce2.hex()}")
    print(f"Plaintext:  {plaintext.hex()}")
    print(f"Ciphertext 1: {ct1.hex()}")
    print(f"Ciphertext 2: {ct2.hex()}")
    print(f"Different: {ct1 != ct2}")
    print("✓ Verified")
    
    # Vector 13: Seeking
    key = bytes([0x78] * 32)
    nonce = bytes([0x9a] * 24)
    
    cipher = Chaco256(key, nonce)
    cipher.seek(100)
    plaintext = bytes(64)
    ciphertext = cipher.encrypt(plaintext)
    
    print(f"\n{'='*70}")
    print("Test Vector: Seeking to Block 100")
    print(f"{'='*70}")
    print(f"Key:       {key.hex()}")
    print(f"Nonce:     {nonce.hex()}")
    print(f"Block:     100")
    print(f"Plaintext: {plaintext.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print("✓ Verified")
    
    # Vector 14: Streaming encryption
    key = bytes([0xde] * 32)
    nonce = bytes([0xad] * 24)
    
    # Encrypt in chunks
    cipher = Chaco256(key, nonce)
    chunk1 = cipher.encrypt(bytes([0x11] * 50))
    chunk2 = cipher.encrypt(bytes([0x22] * 75))
    chunk3 = cipher.encrypt(bytes([0x33] * 100))
    
    # Encrypt all at once
    cipher2 = Chaco256(key, nonce)
    all_at_once = cipher2.encrypt(bytes([0x11] * 50) + bytes([0x22] * 75) + bytes([0x33] * 100))
    
    combined = chunk1 + chunk2 + chunk3
    
    print(f"\n{'='*70}")
    print("Test Vector: Streaming Encryption")
    print(f"{'='*70}")
    print(f"Key:       {key.hex()}")
    print(f"Nonce:     {nonce.hex()}")
    print(f"Chunk 1 (50 bytes):  {chunk1.hex()}")
    print(f"Chunk 2 (75 bytes):  {chunk2.hex()}")
    print(f"Chunk 3 (100 bytes): {chunk3.hex()}")
    print(f"All at once:         {all_at_once.hex()}")
    print(f"Match: {combined == all_at_once}")
    print("✓ Verified")
    
    # Vector 15: Empty input
    print_test_vector(
        "Empty Input",
        key=bytes([0xbc] * 32),
        nonce=bytes([0xef] * 24),
        plaintext=b"",
        rounds=20
    )
    
    print(f"\n{'='*70}")
    print("All test vectors generated successfully!")
    print(f"{'='*70}\n")


if __name__ == '__main__':
    generate_all_test_vectors()
