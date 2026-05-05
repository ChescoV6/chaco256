#!/usr/bin/env python3
"""
Simple Chaco-256 Example
Shows basic encryption and decryption with clean output
"""

import chaco256

# Generate key and nonce
key = chaco256.generate_key()
nonce = chaco256.generate_nonce()

# Create AEAD cipher
aead = chaco256.Chaco256Aead(key)

# Original message
message = "Hello, World!"
print(f"Original message: {message}")

# Encrypt
plaintext = message.encode('utf-8')  # Convert string to bytes
ciphertext, tag = aead.encrypt(nonce, plaintext, b"")
print(f"Encrypted (hex): {ciphertext.hex()}")

# Decrypt
decrypted_bytes = aead.decrypt(nonce, ciphertext, tag, b"")
decrypted_message = decrypted_bytes.decode('utf-8')  # Convert bytes back to string
print(f"Decrypted message: {decrypted_message}")

# Verify it matches
if message == decrypted_message:
    print("✓ Success! Messages match.")
else:
    print("✗ Error: Messages don't match.")
