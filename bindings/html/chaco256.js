/**
 * Chaco-256: High-Security Symmetric Encryption
 * JavaScript/Node.js Implementation
 * 
 * Drop-in encryption for web and Node.js applications
 * 
 * Usage:
 *   const chaco = new Chaco256(key, nonce);
 *   const ciphertext = chaco.encrypt(plaintext);
 *   const plaintext = chaco.decrypt(ciphertext);
 * 
 * @version 1.0.0
 * @license MIT
 */

class Chaco256 {
    constructor(key, nonce, rounds = 20) {
        if (key.length !== 32) throw new Error('Key must be 32 bytes');
        if (nonce.length !== 24) throw new Error('Nonce must be 24 bytes');
        if (![16, 20, 24].includes(rounds)) throw new Error('Rounds must be 16, 20, or 24');
        
        this.key = new Uint8Array(key);
        this.nonce = new Uint8Array(nonce);
        this.rounds = rounds;
        this.counter = 0n;
        this.keystreamBuffer = new Uint8Array(0);
        this.keystreamPos = 0;
    }

    // Constants
    static CONSTANTS = [
        0x636861636f323536n, // "chaco256"
        0x7365637572697479n, // "security"
        0x616e6470726976n,   // "andpriv"
        0x6163793230323600n, // "acy2026\0"
    ];

    static EXTENDED_KEY_CONSTANTS = [
        0x0123456789abcdefn,
        0xfedcba9876543210n,
        0x13579bdf02468acen,
        0xeca8642fdb975310n,
    ];

    // Rotate left 64-bit
    static rotl64(value, shift) {
        const mask = 0xFFFFFFFFFFFFFFFFn;
        value = value & mask;
        shift = Number(shift & 63n);
        return ((value << BigInt(shift)) | (value >> BigInt(64 - shift))) & mask;
    }

    // Bytes to u64 little-endian
    static bytesToU64(bytes, offset = 0) {
        let result = 0n;
        for (let i = 0; i < 8; i++) {
            result |= BigInt(bytes[offset + i]) << BigInt(i * 8);
        }
        return result;
    }

    // U64 to bytes little-endian
    static u64ToBytes(value) {
        const bytes = new Uint8Array(8);
        for (let i = 0; i < 8; i++) {
            bytes[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
        }
        return bytes;
    }

    // Quarter round
    static quarterRound(state, a, b, c, d) {
        const mask = 0xFFFFFFFFFFFFFFFFn;
        
        state[a] = (state[a] + state[b]) & mask;
        state[d] ^= state[a];
        state[d] = Chaco256.rotl64(state[d], 32n);
        
        state[c] = (state[c] + state[d]) & mask;
        state[b] ^= state[c];
        state[b] = Chaco256.rotl64(state[b], 24n);
        
        state[a] = (state[a] + state[b]) & mask;
        state[d] ^= state[a];
        state[d] = Chaco256.rotl64(state[d], 16n);
        
        state[c] = (state[c] + state[d]) & mask;
        state[b] ^= state[c];
        state[b] = Chaco256.rotl64(state[b], 63n);
    }

    // Full round
    static round(state) {
        // Column phase
        Chaco256.quarterRound(state, 0, 4, 8, 12);
        Chaco256.quarterRound(state, 1, 5, 9, 13);
        Chaco256.quarterRound(state, 2, 6, 10, 14);
        Chaco256.quarterRound(state, 3, 7, 11, 15);
        
        // Diagonal phase
        Chaco256.quarterRound(state, 0, 5, 10, 15);
        Chaco256.quarterRound(state, 1, 6, 11, 12);
        Chaco256.quarterRound(state, 2, 7, 8, 13);
        Chaco256.quarterRound(state, 3, 4, 9, 14);
    }

    // Initialize state
    initializeState() {
        const state = new Array(16);
        
        // Constants
        state[0] = Chaco256.CONSTANTS[0];
        state[1] = Chaco256.CONSTANTS[1];
        state[2] = Chaco256.CONSTANTS[2];
        state[3] = Chaco256.CONSTANTS[3];
        
        // Key
        state[4] = Chaco256.bytesToU64(this.key, 0);
        state[5] = Chaco256.bytesToU64(this.key, 8);
        state[6] = Chaco256.bytesToU64(this.key, 16);
        state[7] = Chaco256.bytesToU64(this.key, 24);
        
        // Nonce and counter
        state[8] = Chaco256.bytesToU64(this.nonce, 0);
        state[9] = Chaco256.bytesToU64(this.nonce, 8);
        state[10] = Chaco256.bytesToU64(this.nonce, 16);
        state[11] = this.counter;
        
        // Extended key
        state[12] = state[4] ^ Chaco256.EXTENDED_KEY_CONSTANTS[0];
        state[13] = state[5] ^ Chaco256.EXTENDED_KEY_CONSTANTS[1];
        state[14] = state[6] ^ Chaco256.EXTENDED_KEY_CONSTANTS[2];
        state[15] = state[7] ^ Chaco256.EXTENDED_KEY_CONSTANTS[3];
        
        return state;
    }

    // Generate keystream block
    generateBlock() {
        const initialState = this.initializeState();
        const state = [...initialState];
        
        // Apply rounds
        for (let i = 0; i < this.rounds; i++) {
            Chaco256.round(state);
        }
        
        // Feedforward
        const mask = 0xFFFFFFFFFFFFFFFFn;
        for (let i = 0; i < 16; i++) {
            state[i] = (state[i] + initialState[i]) & mask;
        }
        
        // Convert to bytes
        const keystream = new Uint8Array(128);
        for (let i = 0; i < 16; i++) {
            const bytes = Chaco256.u64ToBytes(state[i]);
            keystream.set(bytes, i * 8);
        }
        
        this.counter++;
        return keystream;
    }

    // Encrypt/decrypt (XOR with keystream)
    process(data) {
        const input = new Uint8Array(data);
        const output = new Uint8Array(input.length);
        
        for (let i = 0; i < input.length; i++) {
            if (this.keystreamPos >= this.keystreamBuffer.length) {
                this.keystreamBuffer = this.generateBlock();
                this.keystreamPos = 0;
            }
            
            output[i] = input[i] ^ this.keystreamBuffer[this.keystreamPos++];
        }
        
        return output;
    }

    encrypt(plaintext) {
        return this.process(plaintext);
    }

    decrypt(ciphertext) {
        return this.process(ciphertext);
    }

    seek(blockIndex) {
        this.counter = BigInt(blockIndex);
        this.keystreamBuffer = new Uint8Array(0);
        this.keystreamPos = 0;
    }
}

// AEAD Mode
class Chaco256AEAD {
    constructor(key, rounds = 20) {
        if (key.length !== 32) throw new Error('Key must be 32 bytes');
        
        this.key = new Uint8Array(key);
        this.rounds = rounds;
        
        // Derive MAC keys
        const zeroNonce = new Uint8Array(24);
        const cipher = new Chaco256(key, zeroNonce, rounds);
        const keystream = cipher.generateBlock();
        
        this.macKey = keystream.slice(0, 32);
        this.polyKey = keystream.slice(32, 48);
    }

    // Simple polynomial hash
    polyHash(message) {
        let h1 = 0n;
        let h2 = 0n;
        
        const r = Chaco256.bytesToU64(this.polyKey, 0);
        const r2 = (r + 1n) & ((1n << 128n) - 1n);
        
        for (let i = 0; i < message.length; i += 16) {
            const block = new Uint8Array(16);
            const len = Math.min(16, message.length - i);
            block.set(message.slice(i, i + len));
            
            const m = Chaco256.bytesToU64(block, 0);
            h1 = ((h1 + m) * r) & ((1n << 128n) - 1n);
            h2 = ((h2 + m) * r2) & ((1n << 128n) - 1n);
        }
        
        const result = new Uint8Array(32);
        result.set(Chaco256.u64ToBytes(h1), 0);
        result.set(Chaco256.u64ToBytes(h2), 16);
        return result;
    }

    // Compute MAC
    computeMAC(associatedData, ciphertext) {
        const macInput = new Uint8Array(
            associatedData.length + 
            ((16 - (associatedData.length % 16)) % 16) +
            ciphertext.length +
            ((16 - (ciphertext.length % 16)) % 16) +
            16
        );
        
        let pos = 0;
        
        // Associated data with padding
        macInput.set(associatedData, pos);
        pos += associatedData.length + ((16 - (associatedData.length % 16)) % 16);
        
        // Ciphertext with padding
        macInput.set(ciphertext, pos);
        pos += ciphertext.length + ((16 - (ciphertext.length % 16)) % 16);
        
        // Lengths
        const adLen = new Uint8Array(8);
        const ctLen = new Uint8Array(8);
        for (let i = 0; i < 8; i++) {
            adLen[i] = (associatedData.length >> (i * 8)) & 0xFF;
            ctLen[i] = (ciphertext.length >> (i * 8)) & 0xFF;
        }
        macInput.set(adLen, pos);
        macInput.set(ctLen, pos + 8);
        
        // Hash and encrypt
        const hash = this.polyHash(macInput);
        const macNonce = new Uint8Array(24);
        const macCipher = new Chaco256(this.macKey, macNonce, this.rounds);
        return macCipher.encrypt(hash);
    }

    encrypt(nonce, plaintext, associatedData = new Uint8Array(0)) {
        if (nonce.length !== 24) throw new Error('Nonce must be 24 bytes');
        
        // Encrypt
        const cipher = new Chaco256(this.key, nonce, this.rounds);
        const ciphertext = cipher.encrypt(plaintext);
        
        // Compute MAC
        const tag = this.computeMAC(associatedData, ciphertext);
        
        return { ciphertext, tag };
    }

    decrypt(nonce, ciphertext, tag, associatedData = new Uint8Array(0)) {
        if (nonce.length !== 24) throw new Error('Nonce must be 24 bytes');
        if (tag.length !== 32) throw new Error('Tag must be 32 bytes');
        
        // Verify MAC
        const expectedTag = this.computeMAC(associatedData, ciphertext);
        
        // Constant-time comparison
        let diff = 0;
        for (let i = 0; i < 32; i++) {
            diff |= tag[i] ^ expectedTag[i];
        }
        
        if (diff !== 0) {
            throw new Error('Authentication failed');
        }
        
        // Decrypt
        const cipher = new Chaco256(this.key, nonce, this.rounds);
        return cipher.decrypt(ciphertext);
    }
}

// Utility functions
function generateKey() {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        return crypto.getRandomValues(new Uint8Array(32));
    } else if (typeof require !== 'undefined') {
        const crypto = require('crypto');
        return new Uint8Array(crypto.randomBytes(32));
    } else {
        throw new Error('No secure random source available');
    }
}

function generateNonce() {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        return crypto.getRandomValues(new Uint8Array(24));
    } else if (typeof require !== 'undefined') {
        const crypto = require('crypto');
        return new Uint8Array(crypto.randomBytes(24));
    } else {
        throw new Error('No secure random source available');
    }
}

// Export for Node.js and browsers
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { Chaco256, Chaco256AEAD, generateKey, generateNonce };
}

// Example usage
if (typeof require !== 'undefined' && require.main === module) {
    console.log('Chaco-256 JavaScript Implementation');
    console.log('===================================\n');
    
    // Stream cipher example
    const key = generateKey();
    const nonce = generateNonce();
    const cipher = new Chaco256(key, nonce);
    
    const plaintext = new TextEncoder().encode('Hello, Chaco-256!');
    console.log('Plaintext:', new TextDecoder().decode(plaintext));
    
    const ciphertext = cipher.encrypt(plaintext);
    console.log('Ciphertext:', Array.from(ciphertext.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    const cipher2 = new Chaco256(key, nonce);
    const decrypted = cipher2.decrypt(ciphertext);
    console.log('Decrypted:', new TextDecoder().decode(decrypted));
    
    // AEAD example
    console.log('\nAEAD Mode:');
    const aead = new Chaco256AEAD(key);
    const { ciphertext: ct, tag } = aead.encrypt(nonce, plaintext, new Uint8Array(0));
    console.log('Ciphertext:', Array.from(ct.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('Tag:', Array.from(tag.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    const pt = aead.decrypt(nonce, ct, tag, new Uint8Array(0));
    console.log('Decrypted:', new TextDecoder().decode(pt));
}
