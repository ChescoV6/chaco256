#!/usr/bin/env python3
"""
Chaco-256: High-Security Symmetric Encryption Algorithm
Reference Implementation in Python

This is a reference implementation for verification and testing.
For production use, use the optimized Rust implementation.

Author: Chaco-256 Project
License: MIT
Version: 1.0.0
"""

import struct
from typing import List, Tuple
import secrets

# Constants
KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 24  # 192 bits
BLOCK_SIZE = 128  # 1024 bits
STATE_WORDS = 16  # 16 x 64-bit words
TAG_SIZE = 32  # 256 bits

# State initialization constants (ASCII strings)
CONSTANTS = [
    0x636861636f323536,  # "chaco256"
    0x7365637572697479,  # "security"
    0x616e6470726976,    # "andpriv"
    0x6163793230323600,  # "acy2026\0"
]

# Extended key XOR constants
EXTENDED_KEY_CONSTANTS = [
    0x0123456789abcdef,
    0xfedcba9876543210,
    0x13579bdf02468ace,
    0xeca8642fdb975310,
]


def rotl64(value: int, shift: int) -> int:
    """Rotate left a 64-bit value"""
    value &= 0xFFFFFFFFFFFFFFFF
    shift &= 63
    return ((value << shift) | (value >> (64 - shift))) & 0xFFFFFFFFFFFFFFFF


def bytes_to_u64_le(data: bytes) -> int:
    """Convert 8 bytes to u64 (little-endian)"""
    return struct.unpack('<Q', data)[0]


def u64_to_bytes_le(value: int) -> bytes:
    """Convert u64 to 8 bytes (little-endian)"""
    return struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF)


def quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    """
    Chaco-256 quarter-round function (ARX operations)
    
    Operates on 4 words of the state, mixing them using:
    - Addition (modulo 2^64)
    - XOR
    - Rotation
    """
    # First step
    state[a] = (state[a] + state[b]) & 0xFFFFFFFFFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl64(state[d], 32)
    
    # Second step
    state[c] = (state[c] + state[d]) & 0xFFFFFFFFFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl64(state[b], 24)
    
    # Third step
    state[a] = (state[a] + state[b]) & 0xFFFFFFFFFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl64(state[d], 16)
    
    # Fourth step
    state[c] = (state[c] + state[d]) & 0xFFFFFFFFFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl64(state[b], 63)


def chaco_round(state: List[int]) -> None:
    """
    Perform one complete Chaco-256 round
    
    Consists of:
    1. Column phase (parallel diffusion)
    2. Diagonal phase (cross-mixing)
    """
    # Column phase
    quarter_round(state, 0, 4, 8, 12)
    quarter_round(state, 1, 5, 9, 13)
    quarter_round(state, 2, 6, 10, 14)
    quarter_round(state, 3, 7, 11, 15)
    
    # Diagonal phase
    quarter_round(state, 0, 5, 10, 15)
    quarter_round(state, 1, 6, 11, 12)
    quarter_round(state, 2, 7, 8, 13)
    quarter_round(state, 3, 4, 9, 14)


class Chaco256:
    """Chaco-256 stream cipher"""
    
    def __init__(self, key: bytes, nonce: bytes, rounds: int = 20):
        """
        Initialize Chaco-256 cipher
        
        Args:
            key: 32-byte encryption key
            nonce: 24-byte nonce (must be unique per message)
            rounds: Number of rounds (16=light, 20=standard, 24=paranoid)
        """
        if len(key) != KEY_SIZE:
            raise ValueError(f"Key must be {KEY_SIZE} bytes")
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"Nonce must be {NONCE_SIZE} bytes")
        if rounds not in [16, 20, 24]:
            raise ValueError("Rounds must be 16, 20, or 24")
        
        self.key = key
        self.nonce = nonce
        self.rounds = rounds
        self.counter = 0
        self.keystream_buffer = b''
        self.keystream_pos = 0
    
    def _initialize_state(self) -> List[int]:
        """Initialize the cipher state"""
        state = [0] * STATE_WORDS
        
        # Constants
        state[0] = CONSTANTS[0]
        state[1] = CONSTANTS[1]
        state[2] = CONSTANTS[2]
        state[3] = CONSTANTS[3]
        
        # Key (256 bits)
        state[4] = bytes_to_u64_le(self.key[0:8])
        state[5] = bytes_to_u64_le(self.key[8:16])
        state[6] = bytes_to_u64_le(self.key[16:24])
        state[7] = bytes_to_u64_le(self.key[24:32])
        
        # Nonce (192 bits) and counter (64 bits)
        state[8] = bytes_to_u64_le(self.nonce[0:8])
        state[9] = bytes_to_u64_le(self.nonce[8:16])
        state[10] = bytes_to_u64_le(self.nonce[16:24])
        state[11] = self.counter
        
        # Extended key material
        state[12] = state[4] ^ EXTENDED_KEY_CONSTANTS[0]
        state[13] = state[5] ^ EXTENDED_KEY_CONSTANTS[1]
        state[14] = state[6] ^ EXTENDED_KEY_CONSTANTS[2]
        state[15] = state[7] ^ EXTENDED_KEY_CONSTANTS[3]
        
        return state
    
    def _generate_block(self) -> bytes:
        """Generate one block of keystream"""
        # Initialize state
        initial_state = self._initialize_state()
        state = initial_state.copy()
        
        # Apply rounds
        for _ in range(self.rounds):
            chaco_round(state)
        
        # Add initial state (feedforward)
        for i in range(STATE_WORDS):
            state[i] = (state[i] + initial_state[i]) & 0xFFFFFFFFFFFFFFFF
        
        # Convert to bytes
        keystream = b''.join(u64_to_bytes_le(word) for word in state)
        
        # Increment counter
        self.counter = (self.counter + 1) & 0xFFFFFFFFFFFFFFFF
        
        return keystream
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Ciphertext
        """
        ciphertext = bytearray()
        
        for byte in plaintext:
            # Refill keystream buffer if needed
            if self.keystream_pos >= len(self.keystream_buffer):
                self.keystream_buffer = self._generate_block()
                self.keystream_pos = 0
            
            # XOR with keystream
            ciphertext.append(byte ^ self.keystream_buffer[self.keystream_pos])
            self.keystream_pos += 1
        
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext (identical to encrypt)
        
        Args:
            ciphertext: Data to decrypt
            
        Returns:
            Plaintext
        """
        return self.encrypt(ciphertext)
    
    def seek(self, block_index: int) -> None:
        """
        Seek to a specific block position
        
        Args:
            block_index: Block number to seek to
        """
        self.counter = block_index
        self.keystream_buffer = b''
        self.keystream_pos = 0
    
    @staticmethod
    def generate_block(key: bytes, nonce: bytes, counter: int, rounds: int = 20) -> bytes:
        """
        Generate a single block without maintaining state
        
        Useful for key derivation and MAC computation
        """
        cipher = Chaco256(key, nonce, rounds)
        cipher.counter = counter
        return cipher._generate_block()


def poly_hash(message: bytes, key: bytes) -> bytes:
    """
    Polynomial hash function for MAC
    
    Computes a Carter-Wegman style universal hash over the message.
    
    Args:
        message: Data to hash
        key: 16-byte hash key
        
    Returns:
        32-byte hash value
    """
    if len(key) != 16:
        raise ValueError("Poly hash key must be 16 bytes")
    
    # Convert key to integer
    r = int.from_bytes(key, 'little')
    
    # Process message in 16-byte blocks
    h1 = 0
    h2 = 0
    r2 = (r + 1) & ((1 << 128) - 1)
    
    for i in range(0, len(message), 16):
        # Get block (pad with zeros if needed)
        block = message[i:i+16]
        if len(block) < 16:
            block = block + b'\x00' * (16 - len(block))
        
        m = int.from_bytes(block, 'little')
        
        # h = (h + m) * r (with wrapping)
        h1 = ((h1 + m) * r) & ((1 << 128) - 1)
        h2 = ((h2 + m) * r2) & ((1 << 128) - 1)
    
    # Combine into 256-bit output
    result = h1.to_bytes(16, 'little') + h2.to_bytes(16, 'little')
    return result


class Chaco256Aead:
    """Chaco-256 AEAD (Authenticated Encryption with Associated Data)"""
    
    def __init__(self, key: bytes, rounds: int = 20):
        """
        Initialize Chaco-256 AEAD
        
        Args:
            key: 32-byte encryption key
            rounds: Number of rounds (16=light, 20=standard, 24=paranoid)
        """
        if len(key) != KEY_SIZE:
            raise ValueError(f"Key must be {KEY_SIZE} bytes")
        
        self.key = key
        self.rounds = rounds
        
        # Derive MAC keys
        zero_nonce = b'\x00' * NONCE_SIZE
        keystream = Chaco256.generate_block(key, zero_nonce, 0, rounds)
        self.mac_key = keystream[0:32]
        self.poly_key = keystream[32:48]
    
    def _compute_mac(self, associated_data: bytes, ciphertext: bytes) -> bytes:
        """Compute MAC over associated data and ciphertext"""
        # Build MAC input
        mac_input = bytearray()
        
        # Associated data with padding
        mac_input.extend(associated_data)
        ad_padding = (16 - (len(associated_data) % 16)) % 16
        mac_input.extend(b'\x00' * ad_padding)
        
        # Ciphertext with padding
        mac_input.extend(ciphertext)
        ct_padding = (16 - (len(ciphertext) % 16)) % 16
        mac_input.extend(b'\x00' * ct_padding)
        
        # Lengths (64-bit little-endian)
        mac_input.extend(struct.pack('<Q', len(associated_data)))
        mac_input.extend(struct.pack('<Q', len(ciphertext)))
        
        # Compute polynomial hash
        hash_value = poly_hash(bytes(mac_input), self.poly_key)
        
        # Encrypt hash to produce final tag
        mac_nonce = b'\x00' * NONCE_SIZE
        mac_cipher = Chaco256(self.mac_key, mac_nonce, self.rounds)
        tag = mac_cipher.encrypt(hash_value)
        
        return tag
    
    def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes = b'') -> Tuple[bytes, bytes]:
        """
        Encrypt and authenticate data
        
        Args:
            nonce: 24-byte nonce (must be unique per message)
            plaintext: Data to encrypt
            associated_data: Additional data to authenticate (not encrypted)
            
        Returns:
            Tuple of (ciphertext, tag)
        """
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"Nonce must be {NONCE_SIZE} bytes")
        
        # Encrypt plaintext
        cipher = Chaco256(self.key, nonce, self.rounds)
        ciphertext = cipher.encrypt(plaintext)
        
        # Compute MAC
        tag = self._compute_mac(associated_data, ciphertext)
        
        return ciphertext, tag
    
    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes = b'') -> bytes:
        """
        Decrypt and verify authenticated data
        
        Args:
            nonce: 24-byte nonce used during encryption
            ciphertext: Encrypted data
            tag: 32-byte authentication tag
            associated_data: Additional authenticated data
            
        Returns:
            Plaintext if authentication succeeds
            
        Raises:
            ValueError: If authentication fails
        """
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"Nonce must be {NONCE_SIZE} bytes")
        if len(tag) != TAG_SIZE:
            raise ValueError(f"Tag must be {TAG_SIZE} bytes")
        
        # Compute and verify MAC
        expected_tag = self._compute_mac(associated_data, ciphertext)
        
        # Constant-time comparison
        if not constant_time_compare(tag, expected_tag):
            raise ValueError("Authentication failed")
        
        # Decrypt ciphertext
        cipher = Chaco256(self.key, nonce, self.rounds)
        plaintext = cipher.decrypt(ciphertext)
        
        return plaintext


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of byte strings"""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


def generate_key() -> bytes:
    """Generate a random 256-bit key"""
    return secrets.token_bytes(KEY_SIZE)


def generate_nonce() -> bytes:
    """Generate a random 192-bit nonce"""
    return secrets.token_bytes(NONCE_SIZE)


# Example usage
if __name__ == '__main__':
    print("Chaco-256 Reference Implementation")
    print("=" * 50)
    
    # Stream cipher example
    print("\n1. Stream Cipher Mode:")
    key = generate_key()
    nonce = generate_nonce()
    cipher = Chaco256(key, nonce)
    
    plaintext = b"Hello, Chaco-256!"
    print(f"Plaintext:  {plaintext}")
    
    ciphertext = cipher.encrypt(plaintext)
    print(f"Ciphertext: {ciphertext.hex()}")
    
    # Decrypt
    cipher2 = Chaco256(key, nonce)
    decrypted = cipher2.decrypt(ciphertext)
    print(f"Decrypted:  {decrypted}")
    
    # AEAD example
    print("\n2. AEAD Mode:")
    aead = Chaco256Aead(key)
    
    plaintext = b"Secret message"
    ad = b"Additional authenticated data"
    
    ciphertext, tag = aead.encrypt(nonce, plaintext, ad)
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Tag:        {tag.hex()}")
    
    # Decrypt and verify
    try:
        decrypted = aead.decrypt(nonce, ciphertext, tag, ad)
        print(f"Decrypted:  {decrypted}")
        print("✓ Authentication successful")
    except ValueError as e:
        print(f"✗ {e}")
    
    # Test with modified ciphertext
    print("\n3. Testing Authentication:")
    bad_ciphertext = bytearray(ciphertext)
    bad_ciphertext[0] ^= 1  # Flip one bit
    
    try:
        aead.decrypt(nonce, bytes(bad_ciphertext), tag, ad)
        print("✗ Authentication should have failed!")
    except ValueError:
        print("✓ Authentication correctly rejected modified ciphertext")
    
    print("\n" + "=" * 50)
    print("All examples completed successfully!")
