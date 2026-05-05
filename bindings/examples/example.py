#!/usr/bin/env python3
"""
Chaco-256 Python Example
Simple encryption/decryption demo
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from chaco256 import Chaco256, Chaco256Aead, generate_key, generate_nonce

print('╔════════════════════════════════════════════════════════════╗')
print('║         Chaco-256 Python Example                          ║')
print('╚════════════════════════════════════════════════════════════╝\n')

# Example 1: Stream Cipher
print('1. Stream Cipher Mode')
print('─────────────────────')

key = generate_key()
nonce = generate_nonce()

plaintext = b'Hello, Chaco-256! This is a secret message.'
print(f'Plaintext: {plaintext.decode()}')

cipher = Chaco256(key, nonce)
ciphertext = cipher.encrypt(plaintext)
print(f'Ciphertext: {ciphertext[:20].hex()}...')

cipher2 = Chaco256(key, nonce)
decrypted = cipher2.decrypt(ciphertext)
print(f'Decrypted: {decrypted.decode()}')
print('✓ Success!\n')

# Example 2: AEAD Mode
print('2. AEAD Mode (Authenticated Encryption)')
print('────────────────────────────────────────')

aead = Chaco256Aead(key)
aead_plaintext = b'Confidential data'
associated_data = b'Public header'

ciphertext, tag = aead.encrypt(nonce, aead_plaintext, associated_data)
print(f'Plaintext: {aead_plaintext.decode()}')
print(f'Ciphertext: {ciphertext[:16].hex()}')
print(f'Tag: {tag[:16].hex()}...')

try:
    decrypted = aead.decrypt(nonce, ciphertext, tag, associated_data)
    print(f'Decrypted: {decrypted.decode()}')
    print('✓ Authentication successful!\n')
except ValueError as e:
    print(f'✗ Authentication failed: {e}\n')

# Example 3: Tampering Detection
print('3. Tampering Detection')
print('──────────────────────')

tampered_ct = bytearray(ciphertext)
tampered_ct[0] ^= 1  # Flip one bit

try:
    aead.decrypt(nonce, bytes(tampered_ct), tag, associated_data)
    print('✗ Should have detected tampering!')
except ValueError:
    print('✓ Correctly detected tampered data')

# Example 4: Different Security Levels
print('\n4. Security Levels')
print('──────────────────')

test_data = b'Test data for different security levels'

cipher_light = Chaco256(key, nonce, rounds=16)
ct_light = cipher_light.encrypt(test_data)
print(f'Light (16 rounds): {ct_light[:16].hex()}')

cipher_standard = Chaco256(key, nonce, rounds=20)
ct_standard = cipher_standard.encrypt(test_data)
print(f'Standard (20 rounds): {ct_standard[:16].hex()}')

cipher_paranoid = Chaco256(key, nonce, rounds=24)
ct_paranoid = cipher_paranoid.encrypt(test_data)
print(f'Paranoid (24 rounds): {ct_paranoid[:16].hex()}')

print('\n╔════════════════════════════════════════════════════════════╗')
print('║                  All Examples Complete!                   ║')
print('╚════════════════════════════════════════════════════════════╝')
