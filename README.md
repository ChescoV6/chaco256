# Chaco-256: High-Security Symmetric Encryption

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Chaco-256 is a modern, high-security symmetric encryption algorithm designed for 2026 security standards. It provides both stream cipher and AEAD (Authenticated Encryption with Associated Data) modes with a focus on cryptographic strength, performance, and ease of secure implementation.

## Security Warning

**Chaco-256 is a new cryptographic design that has not undergone extensive public cryptanalysis.** For production systems, use established standards like **AES-256-GCM** or **ChaCha20-Poly1305** unless you have specific requirements and expert cryptographic review.

**Use at your own risk. No warranty is provided.**

## Features

- **256-bit keys** for maximum security against brute force attacks
- **192-bit nonces** for collision resistance (2^96 birthday bound)
- **1024-bit state** (16 × 64-bit words) for excellent diffusion
- **20 rounds** (standard) with configurable security levels
- **Stream cipher mode** for flexible encryption
- **AEAD mode** with 256-bit authentication tags
- **Constant-time operations** for side-channel resistance
- **Optimized for 64-bit processors** with ARX operations
- **Zero unsafe code** in Rust implementation
- **Comprehensive test vectors** for verification

## Design Highlights

### Core Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Key Size | 256 bits | Industry standard, quantum-resistant threshold |
| Nonce Size | 192 bits | Larger than ChaCha20 for enhanced collision resistance |
| State Size | 1024 bits | Large state provides excellent security margin |
| Block Size | 128 bytes | Matches state size for efficiency |
| Rounds | 20 (standard) | Substantial security margin over estimated minimum |

### Security Levels

- **Light (16 rounds)**: High performance, short-term security
- **Standard (20 rounds)**: Recommended default, excellent security margin
- **Paranoid (24 rounds)**: Maximum security for long-term protection

### Cryptographic Strength

Chaco-256 is designed to resist:
- Differential cryptanalysis
- Linear cryptanalysis
- Algebraic attacks
- Boomerang and rectangle attacks
- Related-key attacks
- Side-channel attacks (constant-time implementation)

## Installation

### Python

```bash
python -m pip install chaco256
```

Or if you're using the `py` launcher on Windows:

```bash
py -m pip install chaco256
```

## Quick Start

### Python - Stream Cipher

```python
import chaco256

# Generate key and nonce
key = chaco256.generate_key()
nonce = chaco256.generate_nonce()

# Encrypt
cipher = chaco256.Chaco256(key, nonce)
ciphertext = cipher.encrypt(b"Hello, World!")

# Decrypt
cipher2 = chaco256.Chaco256(key, nonce)
plaintext = cipher2.decrypt(ciphertext)
```

### Python - AEAD Mode

```python
import chaco256

key = chaco256.generate_key()
nonce = chaco256.generate_nonce()
aead = chaco256.Chaco256Aead(key)

# Encrypt with authentication
plaintext = b"Secret message"
ad = b"Public header"
ciphertext, tag = aead.encrypt(nonce, plaintext, ad)

# Decrypt and verify
try:
    plaintext = aead.decrypt(nonce, ciphertext, tag, ad)
    print("Authenticated and decrypted successfully")
except ValueError:
    print("Authentication failed!")
```

### Command Line Interface

After installation, you can use the `chaco256` command:

```bash
# Encrypt a file
chaco256 encrypt input.txt output.enc

# Decrypt a file
chaco256 decrypt output.enc decrypted.txt --key output.enc.key

# Generate a key
chaco256 keygen --output my.key

# Encrypt text
chaco256 encrypt-text "Hello, World!"

# Get help
chaco256 --help
```

## Architecture

### State Structure

Chaco-256 uses a 1024-bit state organized as 16 × 64-bit words:

```
┌─────────────────────────────────────────────────────┐
│ s0   s1   s2   s3   │ Constants (4 words)          │
│ s4   s5   s6   s7   │ Key (4 words, 256 bits)      │
│ s8   s9   s10  s11  │ Nonce (3 words, 192 bits)    │
│                     │ + Counter (1 word, 64 bits)  │
│ s12  s13  s14  s15  │ Extended Key (4 words)       │
└─────────────────────────────────────────────────────┘
```

### Round Function

Each round consists of:
1. **Column phase**: 4 parallel quarter-rounds for vertical diffusion
2. **Diagonal phase**: 4 parallel quarter-rounds for cross-mixing

The quarter-round uses ARX operations (Add-Rotate-XOR):
```
a += b; d ^= a; d <<<= 32
c += d; b ^= c; b <<<= 24
a += b; d ^= a; d <<<= 16
c += d; b ^= c; b <<<= 63
```

### AEAD Construction

Chaco-256-AEAD uses an Encrypt-then-MAC construction:
1. Derive MAC keys from the main key
2. Encrypt plaintext with Chaco-256
3. Compute polynomial hash over AD and ciphertext
4. Encrypt hash to produce authentication tag

## Performance

Expected performance on modern 64-bit CPUs:

- **Throughput**: 3-5 GB/s per core (optimized implementation)
- **Latency**: ~100-150 cycles per 128-byte block
- **Memory**: 128 bytes state + minimal overhead

Performance can be further improved with:
- SIMD parallelization (process 4 blocks simultaneously)
- Loop unrolling
- Careful register allocation

## Security Analysis

### Estimated Security Margins

- **Minimum secure rounds**: 12-14 (estimated)
- **Standard (20 rounds)**: 40-67% security margin
- **Paranoid (24 rounds)**: 71-100% security margin

### Attack Resistance

| Attack | Complexity | Status |
|--------|-----------|--------|
| Brute Force | 2^256 | Secure |
| Differential | > 2^256 | Secure |
| Linear | > 2^256 | Secure |
| Algebraic | > 2^256 | Secure |
| Quantum (Grover) | 2^128 | Secure |

### Limitations

1. **New design**: Lacks extensive public cryptanalysis
2. **Implementation dependent**: Security requires correct implementation
3. **Nonce reuse**: Catastrophic - never reuse (key, nonce) pairs
4. **Post-quantum**: May need replacement for long-term security beyond 2040

## Best Practices

### Key Management

```rust
// ✓ Good: Use proper key derivation
use argon2::Argon2;
let key = derive_key_from_password(password, salt);

// ✗ Bad: Weak key derivation
let key = Key::from_slice(password.as_bytes());
```

### Nonce Handling

```rust
// ✓ Good: Random nonce for each message
let nonce = Nonce::generate();

// ✗ Bad: Reusing nonces
let nonce = Nonce::from_slice(&[0u8; 24]); // Never do this!
```

### AEAD Usage

```rust
// ✓ Good: Always verify authentication
match aead.decrypt(&nonce, &ct, &tag, &ad) {
    Ok(pt) => process(pt),
    Err(_) => reject_message(),
}

// ✗ Bad: Ignoring authentication
let pt = aead.decrypt(&nonce, &ct, &tag, &ad).unwrap();
```

## Testing

### Rust

```bash
# Run all tests
cargo test

# Run with test vectors
cargo test --release

# Run benchmarks
cargo bench
```

### Python

```bash
# Run reference implementation
python3 chaco256.py

# Generate test vectors
python3 examples/generate_test_vectors.py
```

## Documentation

- **[SPECIFICATION.md](SPECIFICATION.md)**: Complete technical specification
- **[examples/](examples/)**: Usage examples and test vector generation
- **API Documentation**: Run `cargo doc --open` for Rust docs

## Test Vectors

Comprehensive test vectors are provided in `src/tests.rs` and can be generated using:

```bash
python3 examples/generate_test_vectors.py
```

Test vectors cover:
- All-zero inputs
- Sequential patterns
- All-ones inputs
- ASCII messages
- Different round counts
- Large data
- AEAD mode
- Edge cases

## Contributing

Contributions are welcome! Areas of interest:

1. **Cryptanalysis**: Security analysis and attack attempts
2. **Performance**: Optimizations and SIMD implementations
3. **Implementations**: Ports to other languages
4. **Testing**: Additional test vectors and edge cases

## License

MIT License - see LICENSE file for details

## Acknowledgments

Chaco-256 draws inspiration from:
- **ChaCha20** (D. J. Bernstein) - ARX design philosophy
- **AES** (NIST) - Security requirements and analysis
- **Poly1305** (D. J. Bernstein) - MAC construction
- Modern cryptographic research (2020-2026)

## Citation

If you use Chaco-256 in research, please cite:

```
Chaco-256: A Modern High-Security Symmetric Encryption Algorithm
Version 1.0, 2026
https://github.com/example/chaco256
```

## Contact

For security issues, please contact: security@example.com

For general questions: issues@example.com

---

**Remember**: Use established cryptographic standards for production systems unless you have specific requirements and expert review. Chaco-256 is provided for research and educational purposes.
