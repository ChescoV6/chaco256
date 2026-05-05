/**
 * Chaco-256 C/C++ Header
 * 
 * C bindings for the Chaco-256 encryption library
 * 
 * @file chaco256.h
 * @version 1.0.0
 * @license MIT
 */

#ifndef CHACO256_H
#define CHACO256_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Constants */
#define CHACO256_KEY_SIZE 32
#define CHACO256_NONCE_SIZE 24
#define CHACO256_TAG_SIZE 32
#define CHACO256_BLOCK_SIZE 128

/* Security levels */
typedef enum {
    CHACO256_ROUNDS_LIGHT = 16,
    CHACO256_ROUNDS_STANDARD = 20,
    CHACO256_ROUNDS_PARANOID = 24
} chaco256_rounds_t;

/* Error codes */
typedef enum {
    CHACO256_OK = 0,
    CHACO256_ERROR_INVALID_KEY_SIZE = -1,
    CHACO256_ERROR_INVALID_NONCE_SIZE = -2,
    CHACO256_ERROR_INVALID_TAG_SIZE = -3,
    CHACO256_ERROR_AUTH_FAILED = -4,
    CHACO256_ERROR_NULL_POINTER = -5,
    CHACO256_ERROR_INVALID_ROUNDS = -6
} chaco256_error_t;

/* Opaque cipher context */
typedef struct chaco256_ctx chaco256_ctx_t;
typedef struct chaco256_aead_ctx chaco256_aead_ctx_t;

/**
 * Get the size of the cipher context
 * @return Size in bytes
 */
size_t chaco256_ctx_size(void);

/**
 * Get the size of the AEAD context
 * @return Size in bytes
 */
size_t chaco256_aead_ctx_size(void);

/**
 * Initialize a stream cipher context
 * 
 * @param ctx Pointer to context (must be at least chaco256_ctx_size() bytes)
 * @param key 32-byte encryption key
 * @param nonce 24-byte nonce
 * @param rounds Number of rounds (16, 20, or 24)
 * @return CHACO256_OK on success, error code otherwise
 */
chaco256_error_t chaco256_init(
    chaco256_ctx_t* ctx,
    const uint8_t* key,
    const uint8_t* nonce,
    chaco256_rounds_t rounds
);

/**
 * Encrypt data in place (stream cipher mode)
 * 
 * @param ctx Cipher context
 * @param data Data to encrypt (modified in place)
 * @param len Length of data in bytes
 * @return CHACO256_OK on success, error code otherwise
 */
chaco256_error_t chaco256_encrypt(
    chaco256_ctx_t* ctx,
    uint8_t* data,
    size_t len
);

/**
 * Decrypt data in place (stream cipher mode)
 * 
 * @param ctx Cipher context
 * @param data Data to decrypt (modified in place)
 * @param len Length of data in bytes
 * @return CHACO256_OK on success, error code otherwise
 */
chaco256_error_t chaco256_decrypt(
    chaco256_ctx_t* ctx,
    uint8_t* data,
    size_t len
);

/**
 * Seek to a specific block position
 * 
 * @param ctx Cipher context
 * @param block_index Block number to seek to
 * @return CHACO256_OK on success, error code otherwise
 */
chaco256_error_t chaco256_seek(
    chaco256_ctx_t* ctx,
    uint64_t block_index
);

/**
 * Initialize an AEAD context
 * 
 * @param ctx Pointer to AEAD context
 * @param key 32-byte encryption key
 * @param rounds Number of rounds (16, 20, or 24)
 * @return CHACO256_OK on success, error code otherwise
 */
chaco256_error_t chaco256_aead_init(
    chaco256_aead_ctx_t* ctx,
    const uint8_t* key,
    chaco256_rounds_t rounds
);

/**
 * Encrypt and authenticate data (AEAD mode)
 * 
 * @param ctx AEAD context
 * @param nonce 24-byte nonce (must be unique per message)
 * @param plaintext Plaintext data
 * @param plaintext_len Length of plaintext
 * @param associated_data Additional authenticated data (can be NULL)
 * @param ad_len Length of associated data
 * @param ciphertext Output buffer for ciphertext (must be >= plaintext_len)
 * @param tag Output buffer for 32-byte authentication tag
 * @return CHACO256_OK on success, error code otherwise
 */
chaco256_error_t chaco256_aead_encrypt(
    chaco256_aead_ctx_t* ctx,
    const uint8_t* nonce,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* associated_data,
    size_t ad_len,
    uint8_t* ciphertext,
    uint8_t* tag
);

/**
 * Decrypt and verify authenticated data (AEAD mode)
 * 
 * @param ctx AEAD context
 * @param nonce 24-byte nonce used during encryption
 * @param ciphertext Ciphertext data
 * @param ciphertext_len Length of ciphertext
 * @param associated_data Additional authenticated data (can be NULL)
 * @param ad_len Length of associated data
 * @param tag 32-byte authentication tag
 * @param plaintext Output buffer for plaintext (must be >= ciphertext_len)
 * @return CHACO256_OK on success, CHACO256_ERROR_AUTH_FAILED if verification fails
 */
chaco256_error_t chaco256_aead_decrypt(
    chaco256_aead_ctx_t* ctx,
    const uint8_t* nonce,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* associated_data,
    size_t ad_len,
    const uint8_t* tag,
    uint8_t* plaintext
);

/**
 * Securely zero a context
 * 
 * @param ctx Context to zero
 * @param size Size of context
 */
void chaco256_zeroize(void* ctx, size_t size);

/**
 * Get error message for error code
 * 
 * @param error Error code
 * @return Human-readable error message
 */
const char* chaco256_error_string(chaco256_error_t error);

#ifdef __cplusplus
}
#endif

#endif /* CHACO256_H */
