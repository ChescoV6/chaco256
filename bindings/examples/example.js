#!/usr/bin/env node
/**
 * Chaco-256 JavaScript Example
 * Simple encryption/decryption demo
 */

const { Chaco256, Chaco256AEAD, generateKey, generateNonce } = require('../javascript/chaco256.js');

console.log('╔════════════════════════════════════════════════════════════╗');
console.log('║         Chaco-256 JavaScript Example                      ║');
console.log('╚════════════════════════════════════════════════════════════╝\n');

// Example 1: Basic Stream Cipher
console.log('1. Stream Cipher Mode');
console.log('─────────────────────');

const key = generateKey();
const nonce = generateNonce();

const plaintext = 'Hello, Chaco-256! This is a secret message.';
console.log('Plaintext:', plaintext);

const cipher = new Chaco256(key, nonce);
const ciphertext = cipher.encrypt(new TextEncoder().encode(plaintext));
console.log('Ciphertext:', Array.from(ciphertext.slice(0, 20))
    .map(b => b.toString(16).padStart(2, '0')).join(''));

const cipher2 = new Chaco256(key, nonce);
const decrypted = cipher2.decrypt(ciphertext);
console.log('Decrypted:', new TextDecoder().decode(decrypted));
console.log('✓ Success!\n');

// Example 2: AEAD Mode
console.log('2. AEAD Mode (Authenticated Encryption)');
console.log('────────────────────────────────────────');

const aead = new Chaco256AEAD(key);
const aeadPlaintext = new TextEncoder().encode('Confidential data');
const associatedData = new TextEncoder().encode('Public header');

const { ciphertext: aeadCt, tag } = aead.encrypt(nonce, aeadPlaintext, associatedData);
console.log('Plaintext:', new TextDecoder().decode(aeadPlaintext));
console.log('Ciphertext:', Array.from(aeadCt.slice(0, 16))
    .map(b => b.toString(16).padStart(2, '0')).join(''));
console.log('Tag:', Array.from(tag.slice(0, 16))
    .map(b => b.toString(16).padStart(2, '0')).join(''));

try {
    const aeadDecrypted = aead.decrypt(nonce, aeadCt, tag, associatedData);
    console.log('Decrypted:', new TextDecoder().decode(aeadDecrypted));
    console.log('✓ Authentication successful!\n');
} catch (e) {
    console.log('✗ Authentication failed:', e.message);
}

// Example 3: Tampering Detection
console.log('3. Tampering Detection');
console.log('──────────────────────');

const tamperedCt = new Uint8Array(aeadCt);
tamperedCt[0] ^= 1; // Flip one bit

try {
    aead.decrypt(nonce, tamperedCt, tag, associatedData);
    console.log('✗ Should have detected tampering!');
} catch (e) {
    console.log('✓ Correctly detected tampered data');
}

console.log('\n╔════════════════════════════════════════════════════════════╗');
console.log('║                  All Examples Complete!                   ║');
console.log('╚════════════════════════════════════════════════════════════╝');
