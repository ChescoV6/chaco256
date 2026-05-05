/**
 * Chaco-256 C++ Example
 * 
 * Demonstrates usage of Chaco-256 from C++ with RAII wrappers
 */

#include "../chaco256.h"
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <iomanip>
#include <cstring>

// RAII wrapper for stream cipher
class Chaco256Cipher {
private:
    std::unique_ptr<uint8_t[]> ctx_mem;
    chaco256_ctx_t* ctx;

public:
    Chaco256Cipher(const std::vector<uint8_t>& key, 
                   const std::vector<uint8_t>& nonce,
                   chaco256_rounds_t rounds = CHACO256_ROUNDS_STANDARD) {
        if (key.size() != CHACO256_KEY_SIZE) {
            throw std::runtime_error("Invalid key size");
        }
        if (nonce.size() != CHACO256_NONCE_SIZE) {
            throw std::runtime_error("Invalid nonce size");
        }

        ctx_mem = std::make_unique<uint8_t[]>(chaco256_ctx_size());
        ctx = reinterpret_cast<chaco256_ctx_t*>(ctx_mem.get());

        auto err = chaco256_init(ctx, key.data(), nonce.data(), rounds);
        if (err != CHACO256_OK) {
            throw std::runtime_error(chaco256_error_string(err));
        }
    }

    ~Chaco256Cipher() {
        if (ctx_mem) {
            chaco256_zeroize(ctx_mem.get(), chaco256_ctx_size());
        }
    }

    void encrypt(std::vector<uint8_t>& data) {
        auto err = chaco256_encrypt(ctx, data.data(), data.size());
        if (err != CHACO256_OK) {
            throw std::runtime_error(chaco256_error_string(err));
        }
    }

    void decrypt(std::vector<uint8_t>& data) {
        auto err = chaco256_decrypt(ctx, data.data(), data.size());
        if (err != CHACO256_OK) {
            throw std::runtime_error(chaco256_error_string(err));
        }
    }

    void seek(uint64_t block_index) {
        auto err = chaco256_seek(ctx, block_index);
        if (err != CHACO256_OK) {
            throw std::runtime_error(chaco256_error_string(err));
        }
    }
};

// RAII wrapper for AEAD
class Chaco256AEAD {
private:
    std::unique_ptr<uint8_t[]> ctx_mem;
    chaco256_aead_ctx_t* ctx;

public:
    Chaco256AEAD(const std::vector<uint8_t>& key,
                 chaco256_rounds_t rounds = CHACO256_ROUNDS_STANDARD) {
        if (key.size() != CHACO256_KEY_SIZE) {
            throw std::runtime_error("Invalid key size");
        }

        ctx_mem = std::make_unique<uint8_t[]>(chaco256_aead_ctx_size());
        ctx = reinterpret_cast<chaco256_aead_ctx_t*>(ctx_mem.get());

        auto err = chaco256_aead_init(ctx, key.data(), rounds);
        if (err != CHACO256_OK) {
            throw std::runtime_error(chaco256_error_string(err));
        }
    }

    ~Chaco256AEAD() {
        if (ctx_mem) {
            chaco256_zeroize(ctx_mem.get(), chaco256_aead_ctx_size());
        }
    }

    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> 
    encrypt(const std::vector<uint8_t>& nonce,
            const std::vector<uint8_t>& plaintext,
            const std::vector<uint8_t>& ad = {}) {
        if (nonce.size() != CHACO256_NONCE_SIZE) {
            throw std::runtime_error("Invalid nonce size");
        }

        std::vector<uint8_t> ciphertext(plaintext.size());
        std::vector<uint8_t> tag(CHACO256_TAG_SIZE);

        auto err = chaco256_aead_encrypt(
            ctx,
            nonce.data(),
            plaintext.data(),
            plaintext.size(),
            ad.empty() ? nullptr : ad.data(),
            ad.size(),
            ciphertext.data(),
            tag.data()
        );

        if (err != CHACO256_OK) {
            throw std::runtime_error(chaco256_error_string(err));
        }

        return {ciphertext, tag};
    }

    std::vector<uint8_t> 
    decrypt(const std::vector<uint8_t>& nonce,
            const std::vector<uint8_t>& ciphertext,
            const std::vector<uint8_t>& tag,
            const std::vector<uint8_t>& ad = {}) {
        if (nonce.size() != CHACO256_NONCE_SIZE) {
            throw std::runtime_error("Invalid nonce size");
        }
        if (tag.size() != CHACO256_TAG_SIZE) {
            throw std::runtime_error("Invalid tag size");
        }

        std::vector<uint8_t> plaintext(ciphertext.size());

        auto err = chaco256_aead_decrypt(
            ctx,
            nonce.data(),
            ciphertext.data(),
            ciphertext.size(),
            ad.empty() ? nullptr : ad.data(),
            ad.size(),
            tag.data(),
            plaintext.data()
        );

        if (err == CHACO256_ERROR_AUTH_FAILED) {
            throw std::runtime_error("Authentication failed");
        } else if (err != CHACO256_OK) {
            throw std::runtime_error(chaco256_error_string(err));
        }

        return plaintext;
    }
};

// Utility functions
void print_hex(const std::string& label, const std::vector<uint8_t>& data, size_t max_len = 32) {
    std::cout << label << ": ";
    size_t len = std::min(data.size(), max_len);
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(data[i]);
    }
    if (data.size() > max_len) {
        std::cout << "... (" << std::dec << data.size() << " bytes total)";
    }
    std::cout << std::dec << std::endl;
}

std::vector<uint8_t> string_to_bytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string bytes_to_string(const std::vector<uint8_t>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

void example_stream_cipher() {
    std::cout << "=== Stream Cipher Example ===" << std::endl;

    // Prepare key and nonce
    std::vector<uint8_t> key(CHACO256_KEY_SIZE, 0x42);
    std::vector<uint8_t> nonce(CHACO256_NONCE_SIZE, 0x24);

    // Create cipher
    Chaco256Cipher cipher(key, nonce);

    // Encrypt
    std::string plaintext = "Hello, Chaco-256 from C++!";
    auto data = string_to_bytes(plaintext);

    std::cout << "Plaintext:  " << plaintext << std::endl;

    cipher.encrypt(data);
    print_hex("Ciphertext", data);

    // Decrypt
    Chaco256Cipher cipher2(key, nonce);
    cipher2.decrypt(data);

    std::cout << "Decrypted:  " << bytes_to_string(data) << std::endl;
    std::cout << "✓ Stream cipher example completed\n" << std::endl;
}

void example_aead() {
    std::cout << "=== AEAD Example ===" << std::endl;

    // Prepare key and nonce
    std::vector<uint8_t> key(CHACO256_KEY_SIZE, 0x11);
    std::vector<uint8_t> nonce(CHACO256_NONCE_SIZE, 0x22);

    // Create AEAD
    Chaco256AEAD aead(key);

    // Encrypt with authentication
    auto plaintext = string_to_bytes("Secret message");
    auto ad = string_to_bytes("Public header");

    std::cout << "Plaintext:  " << bytes_to_string(plaintext) << std::endl;
    std::cout << "AD:         " << bytes_to_string(ad) << std::endl;

    auto [ciphertext, tag] = aead.encrypt(nonce, plaintext, ad);

    print_hex("Ciphertext", ciphertext);
    print_hex("Tag", tag);

    // Decrypt and verify
    try {
        auto decrypted = aead.decrypt(nonce, ciphertext, tag, ad);
        std::cout << "Decrypted:  " << bytes_to_string(decrypted) << std::endl;
        std::cout << "✓ Authentication successful" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "✗ Decryption failed: " << e.what() << std::endl;
    }

    // Test tampering detection
    std::cout << "\nTesting tampering detection..." << std::endl;
    ciphertext[0] ^= 1;  // Flip one bit

    try {
        auto decrypted = aead.decrypt(nonce, ciphertext, tag, ad);
        std::cout << "✗ Should have detected tampering!" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "✓ Correctly detected tampered ciphertext" << std::endl;
    }

    std::cout << "✓ AEAD example completed\n" << std::endl;
}

int main() {
    std::cout << "Chaco-256 C++ Examples" << std::endl;
    std::cout << "======================" << std::endl << std::endl;

    try {
        example_stream_cipher();
        example_aead();

        std::cout << "All examples completed successfully!" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
