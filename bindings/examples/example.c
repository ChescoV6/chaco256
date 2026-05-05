/**
 * Chaco-256 C Example
 * 
 * Demonstrates basic usage of Chaco-256 from C
 */

#include "../chaco256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) {
        printf("... (%zu bytes total)", len);
    }
    printf("\n");
}

int example_stream_cipher() {
    printf("=== Stream Cipher Example ===\n");
    
    // Prepare key and nonce
    uint8_t key[CHACO256_KEY_SIZE];
    uint8_t nonce[CHACO256_NONCE_SIZE];
    memset(key, 0x42, sizeof(key));
    memset(nonce, 0x24, sizeof(nonce));
    
    // Allocate context
    chaco256_ctx_t* ctx = malloc(chaco256_ctx_size());
    if (!ctx) {
        fprintf(stderr, "Failed to allocate context\n");
        return 1;
    }
    
    // Initialize cipher
    chaco256_error_t err = chaco256_init(ctx, key, nonce, CHACO256_ROUNDS_STANDARD);
    if (err != CHACO256_OK) {
        fprintf(stderr, "Init failed: %s\n", chaco256_error_string(err));
        free(ctx);
        return 1;
    }
    
    // Encrypt data
    const char* plaintext = "Hello, Chaco-256 from C!";
    size_t len = strlen(plaintext);
    uint8_t* data = malloc(len);
    memcpy(data, plaintext, len);
    
    printf("Plaintext:  %s\n", plaintext);
    
    err = chaco256_encrypt(ctx, data, len);
    if (err != CHACO256_OK) {
        fprintf(stderr, "Encrypt failed: %s\n", chaco256_error_string(err));
        free(data);
        free(ctx);
        return 1;
    }
    
    print_hex("Ciphertext", data, len);
    
    // Decrypt (need new context with same key/nonce)
    chaco256_zeroize(ctx, chaco256_ctx_size());
    err = chaco256_init(ctx, key, nonce, CHACO256_ROUNDS_STANDARD);
    if (err != CHACO256_OK) {
        fprintf(stderr, "Re-init failed: %s\n", chaco256_error_string(err));
        free(data);
        free(ctx);
        return 1;
    }
    
    err = chaco256_decrypt(ctx, data, len);
    if (err != CHACO256_OK) {
        fprintf(stderr, "Decrypt failed: %s\n", chaco256_error_string(err));
        free(data);
        free(ctx);
        return 1;
    }
    
    printf("Decrypted:  %.*s\n", (int)len, data);
    
    // Cleanup
    chaco256_zeroize(ctx, chaco256_ctx_size());
    chaco256_zeroize(data, len);
    free(data);
    free(ctx);
    
    printf("✓ Stream cipher example completed\n\n");
    return 0;
}

int example_aead() {
    printf("=== AEAD Example ===\n");
    
    // Prepare key and nonce
    uint8_t key[CHACO256_KEY_SIZE];
    uint8_t nonce[CHACO256_NONCE_SIZE];
    memset(key, 0x11, sizeof(key));
    memset(nonce, 0x22, sizeof(nonce));
    
    // Allocate AEAD context
    chaco256_aead_ctx_t* ctx = malloc(chaco256_aead_ctx_size());
    if (!ctx) {
        fprintf(stderr, "Failed to allocate AEAD context\n");
        return 1;
    }
    
    // Initialize AEAD
    chaco256_error_t err = chaco256_aead_init(ctx, key, CHACO256_ROUNDS_STANDARD);
    if (err != CHACO256_OK) {
        fprintf(stderr, "AEAD init failed: %s\n", chaco256_error_string(err));
        free(ctx);
        return 1;
    }
    
    // Prepare data
    const char* plaintext = "Secret message";
    const char* ad = "Public header";
    size_t pt_len = strlen(plaintext);
    size_t ad_len = strlen(ad);
    
    uint8_t* ciphertext = malloc(pt_len);
    uint8_t tag[CHACO256_TAG_SIZE];
    
    printf("Plaintext:  %s\n", plaintext);
    printf("AD:         %s\n", ad);
    
    // Encrypt with authentication
    err = chaco256_aead_encrypt(
        ctx,
        nonce,
        (const uint8_t*)plaintext,
        pt_len,
        (const uint8_t*)ad,
        ad_len,
        ciphertext,
        tag
    );
    
    if (err != CHACO256_OK) {
        fprintf(stderr, "AEAD encrypt failed: %s\n", chaco256_error_string(err));
        free(ciphertext);
        free(ctx);
        return 1;
    }
    
    print_hex("Ciphertext", ciphertext, pt_len);
    print_hex("Tag", tag, CHACO256_TAG_SIZE);
    
    // Decrypt and verify
    uint8_t* decrypted = malloc(pt_len);
    
    err = chaco256_aead_decrypt(
        ctx,
        nonce,
        ciphertext,
        pt_len,
        (const uint8_t*)ad,
        ad_len,
        tag,
        decrypted
    );
    
    if (err != CHACO256_OK) {
        fprintf(stderr, "AEAD decrypt failed: %s\n", chaco256_error_string(err));
        free(decrypted);
        free(ciphertext);
        free(ctx);
        return 1;
    }
    
    printf("Decrypted:  %.*s\n", (int)pt_len, decrypted);
    printf("✓ Authentication successful\n");
    
    // Test tampering detection
    printf("\nTesting tampering detection...\n");
    ciphertext[0] ^= 1;  // Flip one bit
    
    err = chaco256_aead_decrypt(
        ctx,
        nonce,
        ciphertext,
        pt_len,
        (const uint8_t*)ad,
        ad_len,
        tag,
        decrypted
    );
    
    if (err == CHACO256_ERROR_AUTH_FAILED) {
        printf("✓ Correctly detected tampered ciphertext\n");
    } else {
        printf("✗ Failed to detect tampering!\n");
    }
    
    // Cleanup
    chaco256_zeroize(ctx, chaco256_aead_ctx_size());
    chaco256_zeroize(decrypted, pt_len);
    chaco256_zeroize(ciphertext, pt_len);
    free(decrypted);
    free(ciphertext);
    free(ctx);
    
    printf("✓ AEAD example completed\n\n");
    return 0;
}

int main() {
    printf("Chaco-256 C Examples\n");
    printf("====================\n\n");
    
    if (example_stream_cipher() != 0) {
        return 1;
    }
    
    if (example_aead() != 0) {
        return 1;
    }
    
    printf("All examples completed successfully!\n");
    return 0;
}
