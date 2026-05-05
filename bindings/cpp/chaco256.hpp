/**
 * Chaco-256: High-Security Symmetric Encryption
 * C++ Header-Only Implementation
 * 
 * Single-file drop-in encryption for C++ applications
 * 
 * Usage:
 *   Chaco256 cipher(key, nonce);
 *   cipher.encrypt(data);
 *   cipher.decrypt(data);
 * 
 * @version 1.0.0
 * @license MIT
 */

#ifndef CHACO256_HPP
#define CHACO256_HPP

#include <cstdint>
#include <cstring>
#include <vector>
#include <array>
#include <stdexcept>
#include <random>

namespace chaco256 {

// Constants
constexpr size_t KEY_SIZE = 32;
constexpr size_t NONCE_SIZE = 24;
constexpr size_t BLOCK_SIZE = 128;
constexpr size_t TAG_SIZE = 32;
constexpr size_t STATE_WORDS = 16;

// State initialization constants
constexpr uint64_t CONSTANTS[4] = {
    0x636861636f323536ULL, // "chaco256"
    0x7365637572697479ULL, // "security"
    0x616e6470726976ULL,   // "andpriv"
    0x6163793230323600ULL, // "acy2026\0"
};

constexpr uint64_t EXTENDED_KEY_CONSTANTS[4] = {
    0x0123456789abcdefULL,
    0xfedcba9876543210ULL,
    0x13579bdf02468aceULL,
    0xeca8642fdb975310ULL,
};

// Rotate left 64-bit
inline uint64_t rotl64(uint64_t value, unsigned int shift) {
    shift &= 63;
    return (value << shift) | (value >> (64 - shift));
}

// Bytes to u64 little-endian
inline uint64_t bytes_to_u64(const uint8_t* bytes) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    }
    return result;
}

// U64 to bytes little-endian
inline void u64_to_bytes(uint64_t value, uint8_t* bytes) {
    for (int i = 0; i < 8; i++) {
        bytes[i] = static_cast<uint8_t>(value >> (i * 8));
    }
}

// Quarter round function
inline void quarter_round(uint64_t* state, int a, int b, int c, int d) {
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = rotl64(state[d], 32);
    
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = rotl64(state[b], 24);
    
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = rotl64(state[d], 16);
    
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = rotl64(state[b], 63);
}

// Full round
inline void chaco_round(uint64_t* state) {
    // Column phase
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);
    
    // Diagonal phase
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}

// Chaco-256 Stream Cipher
class Chaco256 {
private:
    std::array<uint8_t, KEY_SIZE> key_;
    std::array<uint8_t, NONCE_SIZE> nonce_;
    uint64_t counter_;
    int rounds_;
    std::vector<uint8_t> keystream_buffer_;
    size_t keystream_pos_;

    void initialize_state(uint64_t* state) {
        // Constants
        state[0] = CONSTANTS[0];
        state[1] = CONSTANTS[1];
        state[2] = CONSTANTS[2];
        state[3] = CONSTANTS[3];
        
        // Key
        state[4] = bytes_to_u64(&key_[0]);
        state[5] = bytes_to_u64(&key_[8]);
        state[6] = bytes_to_u64(&key_[16]);
        state[7] = bytes_to_u64(&key_[24]);
        
        // Nonce and counter
        state[8] = bytes_to_u64(&nonce_[0]);
        state[9] = bytes_to_u64(&nonce_[8]);
        state[10] = bytes_to_u64(&nonce_[16]);
        state[11] = counter_;
        
        // Extended key
        state[12] = state[4] ^ EXTENDED_KEY_CONSTANTS[0];
        state[13] = state[5] ^ EXTENDED_KEY_CONSTANTS[1];
        state[14] = state[6] ^ EXTENDED_KEY_CONSTANTS[2];
        state[15] = state[7] ^ EXTENDED_KEY_CONSTANTS[3];
    }

    void generate_block() {
        uint64_t initial_state[STATE_WORDS];
        uint64_t state[STATE_WORDS];
        
        initialize_state(initial_state);
        std::memcpy(state, initial_state, sizeof(state));
        
        // Apply rounds
        for (int i = 0; i < rounds_; i++) {
            chaco_round(state);
        }
        
        // Feedforward
        for (int i = 0; i < STATE_WORDS; i++) {
            state[i] += initial_state[i];
        }
        
        // Convert to bytes
        keystream_buffer_.resize(BLOCK_SIZE);
        for (int i = 0; i < STATE_WORDS; i++) {
            u64_to_bytes(state[i], &keystream_buffer_[i * 8]);
        }
        
        counter_++;
    }

public:
    Chaco256(const uint8_t* key, const uint8_t* nonce, int rounds = 20)
        : counter_(0), rounds_(rounds), keystream_pos_(0) {
        if (rounds != 16 && rounds != 20 && rounds != 24) {
            throw std::invalid_argument("Rounds must be 16, 20, or 24");
        }
        std::memcpy(key_.data(), key, KEY_SIZE);
        std::memcpy(nonce_.data(), nonce, NONCE_SIZE);
    }

    void encrypt(uint8_t* data, size_t length) {
        for (size_t i = 0; i < length; i++) {
            if (keystream_pos_ >= keystream_buffer_.size()) {
                generate_block();
                keystream_pos_ = 0;
            }
            data[i] ^= keystream_buffer_[keystream_pos_++];
        }
    }

    void decrypt(uint8_t* data, size_t length) {
        encrypt(data, length); // XOR is self-inverse
    }

    void seek(uint64_t block_index) {
        counter_ = block_index;
        keystream_buffer_.clear();
        keystream_pos_ = 0;
    }
};

// Chaco-256 AEAD
class Chaco256AEAD {
private:
    std::array<uint8_t, KEY_SIZE> key_;
    std::array<uint8_t, KEY_SIZE> mac_key_;
    std::array<uint8_t, 16> poly_key_;
    int rounds_;

    std::array<uint8_t, TAG_SIZE> poly_hash(const uint8_t* message, size_t length) {
        uint64_t h1 = 0, h2 = 0;
        uint64_t r = bytes_to_u64(poly_key_.data());
        uint64_t r2 = r + 1;
        
        for (size_t i = 0; i < length; i += 16) {
            uint8_t block[16] = {0};
            size_t block_len = std::min(size_t(16), length - i);
            std::memcpy(block, message + i, block_len);
            
            uint64_t m = bytes_to_u64(block);
            h1 = (h1 + m) * r;
            h2 = (h2 + m) * r2;
        }
        
        std::array<uint8_t, TAG_SIZE> result;
        u64_to_bytes(h1, &result[0]);
        u64_to_bytes(h2, &result[16]);
        return result;
    }

    std::array<uint8_t, TAG_SIZE> compute_mac(
        const uint8_t* ad, size_t ad_len,
        const uint8_t* ct, size_t ct_len) {
        
        // Build MAC input
        size_t ad_padding = (16 - (ad_len % 16)) % 16;
        size_t ct_padding = (16 - (ct_len % 16)) % 16;
        size_t mac_input_len = ad_len + ad_padding + ct_len + ct_padding + 16;
        
        std::vector<uint8_t> mac_input(mac_input_len, 0);
        size_t pos = 0;
        
        std::memcpy(&mac_input[pos], ad, ad_len);
        pos += ad_len + ad_padding;
        
        std::memcpy(&mac_input[pos], ct, ct_len);
        pos += ct_len + ct_padding;
        
        // Lengths
        for (int i = 0; i < 8; i++) {
            mac_input[pos++] = (ad_len >> (i * 8)) & 0xFF;
        }
        for (int i = 0; i < 8; i++) {
            mac_input[pos++] = (ct_len >> (i * 8)) & 0xFF;
        }
        
        // Hash
        auto hash = poly_hash(mac_input.data(), mac_input.size());
        
        // Encrypt hash
        uint8_t zero_nonce[NONCE_SIZE] = {0};
        Chaco256 mac_cipher(mac_key_.data(), zero_nonce, rounds_);
        mac_cipher.encrypt(hash.data(), TAG_SIZE);
        
        return hash;
    }

public:
    Chaco256AEAD(const uint8_t* key, int rounds = 20) : rounds_(rounds) {
        std::memcpy(key_.data(), key, KEY_SIZE);
        
        // Derive MAC keys
        uint8_t zero_nonce[NONCE_SIZE] = {0};
        Chaco256 cipher(key, zero_nonce, rounds);
        uint8_t keystream[BLOCK_SIZE];
        std::memset(keystream, 0, BLOCK_SIZE);
        cipher.encrypt(keystream, BLOCK_SIZE);
        
        std::memcpy(mac_key_.data(), keystream, KEY_SIZE);
        std::memcpy(poly_key_.data(), keystream + KEY_SIZE, 16);
    }

    void encrypt(
        const uint8_t* nonce,
        const uint8_t* plaintext, size_t pt_len,
        const uint8_t* ad, size_t ad_len,
        uint8_t* ciphertext,
        uint8_t* tag) {
        
        // Encrypt
        std::memcpy(ciphertext, plaintext, pt_len);
        Chaco256 cipher(key_.data(), nonce, rounds_);
        cipher.encrypt(ciphertext, pt_len);
        
        // Compute MAC
        auto computed_tag = compute_mac(ad, ad_len, ciphertext, pt_len);
        std::memcpy(tag, computed_tag.data(), TAG_SIZE);
    }

    bool decrypt(
        const uint8_t* nonce,
        const uint8_t* ciphertext, size_t ct_len,
        const uint8_t* tag,
        const uint8_t* ad, size_t ad_len,
        uint8_t* plaintext) {
        
        // Verify MAC
        auto expected_tag = compute_mac(ad, ad_len, ciphertext, ct_len);
        
        // Constant-time comparison
        uint8_t diff = 0;
        for (size_t i = 0; i < TAG_SIZE; i++) {
            diff |= tag[i] ^ expected_tag[i];
        }
        
        if (diff != 0) {
            return false; // Authentication failed
        }
        
        // Decrypt
        std::memcpy(plaintext, ciphertext, ct_len);
        Chaco256 cipher(key_.data(), nonce, rounds_);
        cipher.decrypt(plaintext, ct_len);
        
        return true;
    }
};

// Utility functions
inline void generate_key(uint8_t* key) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    for (size_t i = 0; i < KEY_SIZE; i++) {
        key[i] = dis(gen);
    }
}

inline void generate_nonce(uint8_t* nonce) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    for (size_t i = 0; i < NONCE_SIZE; i++) {
        nonce[i] = dis(gen);
    }
}

} // namespace chaco256

#endif // CHACO256_HPP
