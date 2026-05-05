//! # Chaco-256: High-Security Symmetric Encryption
//!
//! Chaco-256 is a modern symmetric encryption algorithm providing both stream cipher
//! and AEAD (Authenticated Encryption with Associated Data) modes.
//!
//! ## Security Warning
//!
//! Chaco-256 is a new cryptographic design that has not undergone extensive public
//! cryptanalysis. For production systems, use established standards like AES-256-GCM
//! or ChaCha20-Poly1305 unless you have specific requirements and expert review.
//!
//! ## Features
//!
//! - 256-bit keys for maximum security
//! - 192-bit nonces (collision-resistant)
//! - Stream cipher mode for flexible encryption
//! - AEAD mode with 256-bit authentication tags
//! - Constant-time operations (side-channel resistant)
//! - Optimized for 64-bit processors
//!
//! ## Example Usage
//!
//! ```rust
//! use chaco256::{Chaco256, Key, Nonce};
//!
//! // Stream cipher mode
//! let key = Key::from_slice(&[0u8; 32]);
//! let nonce = Nonce::from_slice(&[0u8; 24]);
//! let mut cipher = Chaco256::new(&key, &nonce);
//!
//! let plaintext = b"Hello, World!";
//! let mut ciphertext = plaintext.to_vec();
//! cipher.encrypt(&mut ciphertext);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use zeroize::{Zeroize, ZeroizeOnDrop};

mod core;
mod aead;

pub use crate::core::{Chaco256, Key, Nonce, Rounds};
pub use crate::aead::{Chaco256Aead, Tag, AeadError};

/// Re-export zeroize for users who need it
pub use zeroize;

// C FFI bindings
#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(test)]
mod tests;
