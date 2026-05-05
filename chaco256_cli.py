#!/usr/bin/env python3
"""
Chaco-256 Command Line Interface
"""

import sys
import argparse
import os
from pathlib import Path
import chaco256


def encrypt_file(args):
    """Encrypt a file"""
    # Read input file
    with open(args.input, 'rb') as f:
        plaintext = f.read()
    
    # Generate or load key
    if args.key:
        with open(args.key, 'rb') as f:
            key = f.read()
            if len(key) != 32:
                print(f"Error: Key file must be exactly 32 bytes, got {len(key)}", file=sys.stderr)
                return 1
    else:
        key = chaco256.generate_key()
        key_file = args.output + '.key'
        with open(key_file, 'wb') as f:
            f.write(key)
        print(f"Generated key saved to: {key_file}")
    
    # Generate nonce
    nonce = chaco256.generate_nonce()
    
    # Encrypt
    aead = chaco256.Chaco256Aead(key, rounds=args.rounds)
    ciphertext, tag = aead.encrypt(nonce, plaintext, b'')
    
    # Write output: nonce + ciphertext + tag
    with open(args.output, 'wb') as f:
        f.write(nonce)
        f.write(ciphertext)
        f.write(tag)
    
    print(f"Encrypted: {args.input} -> {args.output}")
    print(f"Size: {len(plaintext)} bytes -> {len(nonce) + len(ciphertext) + len(tag)} bytes")
    return 0


def decrypt_file(args):
    """Decrypt a file"""
    # Read key
    if not args.key:
        print("Error: --key is required for decryption", file=sys.stderr)
        return 1
    
    with open(args.key, 'rb') as f:
        key = f.read()
        if len(key) != 32:
            print(f"Error: Key file must be exactly 32 bytes, got {len(key)}", file=sys.stderr)
            return 1
    
    # Read encrypted file
    with open(args.input, 'rb') as f:
        data = f.read()
    
    # Parse: nonce (24) + ciphertext + tag (32)
    if len(data) < 56:
        print("Error: File too small to be valid encrypted data", file=sys.stderr)
        return 1
    
    nonce = data[:24]
    tag = data[-32:]
    ciphertext = data[24:-32]
    
    # Decrypt
    try:
        aead = chaco256.Chaco256Aead(key, rounds=args.rounds)
        plaintext = aead.decrypt(nonce, ciphertext, tag, b'')
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    # Write output
    with open(args.output, 'wb') as f:
        f.write(plaintext)
    
    print(f"Decrypted: {args.input} -> {args.output}")
    print(f"Size: {len(data)} bytes -> {len(plaintext)} bytes")
    return 0


def generate_key_cmd(args):
    """Generate a random key"""
    key = chaco256.generate_key()
    
    if args.output:
        with open(args.output, 'wb') as f:
            f.write(key)
        print(f"Key saved to: {args.output}")
    else:
        print(f"Key (hex): {key.hex()}")
    
    return 0


def encrypt_text(args):
    """Encrypt text from command line"""
    plaintext = args.text.encode('utf-8')
    
    # Generate key and nonce
    key = chaco256.generate_key()
    nonce = chaco256.generate_nonce()
    
    # Encrypt
    aead = chaco256.Chaco256Aead(key, rounds=args.rounds)
    ciphertext, tag = aead.encrypt(nonce, plaintext, b'')
    
    # Output
    print(f"Key:        {key.hex()}")
    print(f"Nonce:      {nonce.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Tag:        {tag.hex()}")
    
    return 0


def decrypt_text(args):
    """Decrypt text from command line"""
    try:
        key = bytes.fromhex(args.key)
        nonce = bytes.fromhex(args.nonce)
        ciphertext = bytes.fromhex(args.ciphertext)
        tag = bytes.fromhex(args.tag)
    except ValueError as e:
        print(f"Error: Invalid hex input - {e}", file=sys.stderr)
        return 1
    
    # Decrypt
    try:
        aead = chaco256.Chaco256Aead(key, rounds=args.rounds)
        plaintext = aead.decrypt(nonce, ciphertext, tag, b'')
        print(f"Plaintext: {plaintext.decode('utf-8')}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except UnicodeDecodeError:
        print(f"Plaintext (hex): {plaintext.hex()}")
    
    return 0


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Chaco-256: High-Security Symmetric Encryption',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt a file
  chaco256 encrypt input.txt output.enc
  
  # Decrypt a file
  chaco256 decrypt output.enc decrypted.txt --key output.enc.key
  
  # Generate a key
  chaco256 keygen --output my.key
  
  # Encrypt text
  chaco256 encrypt-text "Hello, World!"
  
  # Decrypt text
  chaco256 decrypt-text --key <hex> --nonce <hex> --ciphertext <hex> --tag <hex>
        """
    )
    
    parser.add_argument('--version', action='version', version='Chaco-256 v1.0.0')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Encrypt file
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('input', help='Input file')
    encrypt_parser.add_argument('output', help='Output file')
    encrypt_parser.add_argument('--key', help='Key file (generates new if not provided)')
    encrypt_parser.add_argument('--rounds', type=int, default=20, choices=[16, 20, 24],
                               help='Number of rounds (16=light, 20=standard, 24=paranoid)')
    
    # Decrypt file
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('input', help='Input file')
    decrypt_parser.add_argument('output', help='Output file')
    decrypt_parser.add_argument('--key', required=True, help='Key file')
    decrypt_parser.add_argument('--rounds', type=int, default=20, choices=[16, 20, 24],
                               help='Number of rounds (16=light, 20=standard, 24=paranoid)')
    
    # Generate key
    keygen_parser = subparsers.add_parser('keygen', help='Generate a random key')
    keygen_parser.add_argument('--output', '-o', help='Output file (prints to stdout if not provided)')
    
    # Encrypt text
    encrypt_text_parser = subparsers.add_parser('encrypt-text', help='Encrypt text')
    encrypt_text_parser.add_argument('text', help='Text to encrypt')
    encrypt_text_parser.add_argument('--rounds', type=int, default=20, choices=[16, 20, 24],
                                     help='Number of rounds')
    
    # Decrypt text
    decrypt_text_parser = subparsers.add_parser('decrypt-text', help='Decrypt text')
    decrypt_text_parser.add_argument('--key', required=True, help='Key (hex)')
    decrypt_text_parser.add_argument('--nonce', required=True, help='Nonce (hex)')
    decrypt_text_parser.add_argument('--ciphertext', required=True, help='Ciphertext (hex)')
    decrypt_text_parser.add_argument('--tag', required=True, help='Tag (hex)')
    decrypt_text_parser.add_argument('--rounds', type=int, default=20, choices=[16, 20, 24],
                                     help='Number of rounds')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    # Execute command
    if args.command == 'encrypt':
        return encrypt_file(args)
    elif args.command == 'decrypt':
        return decrypt_file(args)
    elif args.command == 'keygen':
        return generate_key_cmd(args)
    elif args.command == 'encrypt-text':
        return encrypt_text(args)
    elif args.command == 'decrypt-text':
        return decrypt_text(args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
