# Chaco-256 Language Bindings

Easy-to-use Chaco-256 implementations for multiple programming languages.

## 🚀 Quick Start by Language

### JavaScript / Node.js

**Single file**: `javascript/chaco256.js`

```javascript
// Node.js
const { Chaco256, Chaco256AEAD, generateKey, generateNonce } = require('./chaco256.js');

// Browser
<script src="chaco256.js"></script>

// Encrypt
const key = generateKey();
const nonce = generateNonce();
const cipher = new Chaco256(key, nonce);
const ciphertext = cipher.encrypt(new TextEncoder().encode("Hello!"));

// AEAD
const aead = new Chaco256AEAD(key);
const { ciphertext, tag } = aead.encrypt(nonce, plaintext, ad);
```

### C++

**Single header**: `cpp/chaco256.hpp`

```cpp
#include "chaco256.hpp"

using namespace chaco256;

// Encrypt
uint8_t key[KEY_SIZE], nonce[NONCE_SIZE];
generate_key(key);
generate_nonce(nonce);

Chaco256 cipher(key, nonce);
cipher.encrypt(data, length);

// AEAD
Chaco256AEAD aead(key);
aead.encrypt(nonce, plaintext, pt_len, ad, ad_len, ciphertext, tag);
```

### Python

**Single file**: `../chaco256.py`

```python
from chaco256 import Chaco256, Chaco256Aead, generate_key, generate_nonce

# Encrypt
key = generate_key()
nonce = generate_nonce()
cipher = Chaco256(key, nonce)
ciphertext = cipher.encrypt(b"Hello!")

# AEAD
aead = Chaco256Aead(key)
ciphertext, tag = aead.encrypt(nonce, plaintext, ad)
```

### Rust

**Cargo dependency**: See main project

```rust
use chaco256::{Chaco256, Chaco256Aead, Key, Nonce};

// Encrypt
let key = Key::from_slice(&[0u8; 32]);
let nonce = Nonce::from_slice(&[0u8; 24]);
let mut cipher = Chaco256::new(&key, &nonce);
cipher.encrypt(&mut data);

// AEAD
let aead = Chaco256Aead::new(&key);
let (ciphertext, tag) = aead.encrypt(&nonce, plaintext, ad);
```

### HTML / Web

**Interactive demo**: `html/chaco256-simple.html`

Just open in browser - includes full UI for encryption/decryption!

## 📦 Installation

### JavaScript

```bash
# Node.js
npm install # (or just copy chaco256.js)

# Browser
<script src="chaco256.js"></script>
```

### C++

```bash
# Just include the header
#include "chaco256.hpp"

# Compile with C++11 or later
g++ -std=c++11 your_program.cpp -o your_program
```

### Python

```bash
# Just copy the file
cp chaco256.py your_project/

# Or add to path
export PYTHONPATH=$PYTHONPATH:/path/to/chaco256
```

### Rust

```toml
[dependencies]
chaco256 = "1.0"
```

## 📖 Complete Examples

### JavaScript: Encrypt a File

```javascript
const fs = require('fs');
const { Chaco256AEAD, generateKey, generateNonce } = require('./chaco256.js');

function encryptFile(inputPath, outputPath) {
    const key = generateKey();
    const nonce = generateNonce();
    const aead = new Chaco256AEAD(key);
    
    const plaintext = fs.readFileSync(inputPath);
    const filename = new TextEncoder().encode(inputPath);
    
    const { ciphertext, tag } = aead.encrypt(nonce, plaintext, filename);
    
    // Save: nonce || ciphertext || tag
    const output = Buffer.concat([
        Buffer.from(nonce),
        Buffer.from(ciphertext),
        Buffer.from(tag)
    ]);
    
    fs.writeFileSync(outputPath, output);
    
    // Save key separately (securely!)
    fs.writeFileSync(outputPath + '.key', Buffer.from(key));
}

encryptFile('document.pdf', 'document.pdf.encrypted');
```

### C++: Secure Communication

```cpp
#include "chaco256.hpp"
#include <iostream>
#include <vector>

using namespace chaco256;

class SecureChannel {
    Chaco256AEAD aead;
    uint64_t counter;
    
public:
    SecureChannel(const uint8_t* key) : aead(key), counter(0) {}
    
    std::vector<uint8_t> send(const uint8_t* message, size_t len) {
        uint8_t nonce[NONCE_SIZE] = {0};
        memcpy(nonce, &counter, sizeof(counter));
        counter++;
        
        std::vector<uint8_t> ciphertext(len);
        std::vector<uint8_t> tag(TAG_SIZE);
        
        aead.encrypt(nonce, message, len, nullptr, 0, 
                     ciphertext.data(), tag.data());
        
        // Pack: nonce || ciphertext || tag
        std::vector<uint8_t> packet;
        packet.insert(packet.end(), nonce, nonce + NONCE_SIZE);
        packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
        packet.insert(packet.end(), tag.begin(), tag.end());
        
        return packet;
    }
};
```

### Python: Database Encryption

```python
from chaco256 import Chaco256Aead, generate_key
import hashlib

class EncryptedDatabase:
    def __init__(self, master_key):
        self.aead = Chaco256Aead(master_key)
    
    def encrypt_record(self, record_id, data):
        # Derive deterministic nonce from record ID
        nonce_hash = hashlib.sha256(record_id.encode()).digest()
        nonce = nonce_hash[:24]
        
        # Encrypt with record ID as additional data
        ciphertext, tag = self.aead.encrypt(
            nonce, 
            data, 
            record_id.encode()
        )
        
        return ciphertext + tag
    
    def decrypt_record(self, record_id, encrypted_data):
        nonce_hash = hashlib.sha256(record_id.encode()).digest()
        nonce = nonce_hash[:24]
        
        ciphertext = encrypted_data[:-32]
        tag = encrypted_data[-32:]
        
        return self.aead.decrypt(
            nonce,
            ciphertext,
            tag,
            record_id.encode()
        )

# Usage
db = EncryptedDatabase(generate_key())
encrypted = db.encrypt_record("user_123", b"sensitive data")
decrypted = db.decrypt_record("user_123", encrypted)
```

## 🎯 Feature Comparison

| Feature | JavaScript | C++ | Python | Rust |
|---------|-----------|-----|--------|------|
| Stream Cipher | ✓ | ✓ | ✓ | ✓ |
| AEAD Mode | ✓ | ✓ | ✓ | ✓ |
| Seeking | ✓ | ✓ | ✓ | ✓ |
| Security Levels | ✓ | ✓ | ✓ | ✓ |
| Dependencies | 0 | 0 | 0 | 1 (zeroize) |
| File Size | ~15 KB | ~10 KB | ~20 KB | Compiled |
| Performance | Medium | Fast | Slow | Fastest |

## 🔐 Security Best Practices

### ✓ DO

```javascript
// Generate random nonces
const nonce = generateNonce();

// Use AEAD for most applications
const aead = new Chaco256AEAD(key);
const { ciphertext, tag } = aead.encrypt(nonce, plaintext, ad);

// Verify authentication
try {
    const plaintext = aead.decrypt(nonce, ciphertext, tag, ad);
} catch (e) {
    console.error('Authentication failed!');
}
```

### ✗ DON'T

```javascript
// NEVER reuse nonces
const nonce = new Uint8Array(24); // All zeros - BAD!
for (let msg of messages) {
    cipher.encrypt(msg); // INSECURE!
}

// Don't ignore authentication failures
const plaintext = aead.decrypt(nonce, ct, tag, ad); // Might throw!
process(plaintext); // Could process tampered data!
```

## 📱 Platform Support

### JavaScript
- ✓ Node.js 12+
- ✓ Modern browsers (Chrome, Firefox, Safari, Edge)
- ✓ React, Vue, Angular
- ✓ Electron, React Native

### C++
- ✓ C++11 or later
- ✓ GCC, Clang, MSVC
- ✓ Linux, macOS, Windows
- ✓ Embedded systems

### Python
- ✓ Python 3.6+
- ✓ CPython, PyPy
- ✓ All platforms

### Rust
- ✓ Rust 2021 edition
- ✓ All platforms

## 🚀 Performance Tips

### JavaScript
```javascript
// Reuse cipher instances
const cipher = new Chaco256(key, nonce);
for (let chunk of chunks) {
    cipher.encrypt(chunk); // Maintains state
}
```

### C++
```cpp
// Compile with optimizations
g++ -O3 -march=native your_program.cpp

// Process in larger chunks
cipher.encrypt(data, 4096); // Better than many small calls
```

### Python
```python
# Use for reference/testing only
# For production, use Rust or C++ bindings
```

## 📚 Documentation

- **Full Specification**: See `../SPECIFICATION.md`
- **Security Analysis**: See `../SECURITY_ANALYSIS.md`
- **Usage Guide**: See `../USAGE_GUIDE.md`
- **API Reference**: See language-specific comments in source files

## ⚠️ Important Notes

1. **Experimental**: Chaco-256 is a new design without extensive cryptanalysis
2. **Production Use**: Prefer AES-256-GCM or ChaCha20-Poly1305 for production
3. **Expert Review**: Get cryptographic expert review before production use
4. **Testing**: All implementations pass the same test vectors

## 🧪 Testing

### JavaScript
```bash
node chaco256.js
```

### C++
```bash
g++ -std=c++11 test.cpp -o test && ./test
```

### Python
```bash
python3 chaco256.py
```

## 📄 License

MIT License - See LICENSE file

## 🤝 Contributing

Contributions welcome! Please ensure:
- Code passes all test vectors
- Constant-time operations maintained
- Documentation updated
- Examples provided

## 📞 Support

- **Issues**: https://github.com/example/chaco256/issues
- **Security**: security@example.com
- **General**: issues@example.com
