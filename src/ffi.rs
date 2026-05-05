//! C FFI bindings for Chaco-256
//!
//! This module provides C-compatible functions for using Chaco-256 from C/C++.

use crate::core::{Chaco256, Key, Nonce, Rounds};
use crate::aead::{Chaco256Aead, Tag};
use std::slice;
use std::ptr;

/// Error codes for C API
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Chaco256Error {
    Ok = 0,
    InvalidKeySize = -1,
    InvalidNonceSize = -2,
    InvalidTagSize = -3,
    AuthFailed = -4,
    NullPointer = -5,
    InvalidRounds = -6,
}

/// Opaque cipher context
#[repr(C)]
pub struct Chaco256Ctx {
    cipher: Chaco256,
}

/// Opaque AEAD context
#[repr(C)]
pub struct Chaco256AeadCtx {
    aead: Chaco256Aead,
}

/// Get the size of the cipher context
#[no_mangle]
pub extern "C" fn chaco256_ctx_size() -> usize {
    std::mem::size_of::<Chaco256Ctx>()
}

/// Get the size of the AEAD context
#[no_mangle]
pub extern "C" fn chaco256_aead_ctx_size() -> usize {
    std::mem::size_of::<Chaco256AeadCtx>()
}

/// Initialize a stream cipher context
#[no_mangle]
pub extern "C" fn chaco256_init(
    ctx: *mut Chaco256Ctx,
    key: *const u8,
    nonce: *const u8,
    rounds: u32,
) -> Chaco256Error {
    if ctx.is_null() || key.is_null() || nonce.is_null() {
        return Chaco256Error::NullPointer;
    }

    let rounds_enum = match rounds {
        16 => Rounds::Light,
        20 => Rounds::Standard,
        24 => Rounds::Paranoid,
        _ => return Chaco256Error::InvalidRounds,
    };

    unsafe {
        let key_slice = slice::from_raw_parts(key, 32);
        let nonce_slice = slice::from_raw_parts(nonce, 24);

        let key_obj = Key::from_slice(key_slice);
        let nonce_obj = Nonce::from_slice(nonce_slice);

        let cipher = Chaco256::new_with_rounds(&key_obj, &nonce_obj, rounds_enum);
        ptr::write(ctx, Chaco256Ctx { cipher });
    }

    Chaco256Error::Ok
}

/// Encrypt data in place
#[no_mangle]
pub extern "C" fn chaco256_encrypt(
    ctx: *mut Chaco256Ctx,
    data: *mut u8,
    len: usize,
) -> Chaco256Error {
    if ctx.is_null() || data.is_null() {
        return Chaco256Error::NullPointer;
    }

    unsafe {
        let ctx_ref = &mut (*ctx).cipher;
        let data_slice = slice::from_raw_parts_mut(data, len);
        ctx_ref.encrypt(data_slice);
    }

    Chaco256Error::Ok
}

/// Decrypt data in place
#[no_mangle]
pub extern "C" fn chaco256_decrypt(
    ctx: *mut Chaco256Ctx,
    data: *mut u8,
    len: usize,
) -> Chaco256Error {
    if ctx.is_null() || data.is_null() {
        return Chaco256Error::NullPointer;
    }

    unsafe {
        let ctx_ref = &mut (*ctx).cipher;
        let data_slice = slice::from_raw_parts_mut(data, len);
        ctx_ref.decrypt(data_slice);
    }

    Chaco256Error::Ok
}

/// Seek to a specific block position
#[no_mangle]
pub extern "C" fn chaco256_seek(
    ctx: *mut Chaco256Ctx,
    block_index: u64,
) -> Chaco256Error {
    if ctx.is_null() {
        return Chaco256Error::NullPointer;
    }

    unsafe {
        let ctx_ref = &mut (*ctx).cipher;
        ctx_ref.seek(block_index);
    }

    Chaco256Error::Ok
}

/// Initialize an AEAD context
#[no_mangle]
pub extern "C" fn chaco256_aead_init(
    ctx: *mut Chaco256AeadCtx,
    key: *const u8,
    rounds: u32,
) -> Chaco256Error {
    if ctx.is_null() || key.is_null() {
        return Chaco256Error::NullPointer;
    }

    let rounds_enum = match rounds {
        16 => Rounds::Light,
        20 => Rounds::Standard,
        24 => Rounds::Paranoid,
        _ => return Chaco256Error::InvalidRounds,
    };

    unsafe {
        let key_slice = slice::from_raw_parts(key, 32);
        let key_obj = Key::from_slice(key_slice);
        let aead = Chaco256Aead::new_with_rounds(&key_obj, rounds_enum);
        ptr::write(ctx, Chaco256AeadCtx { aead });
    }

    Chaco256Error::Ok
}

/// Encrypt and authenticate data
#[no_mangle]
pub extern "C" fn chaco256_aead_encrypt(
    ctx: *mut Chaco256AeadCtx,
    nonce: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
    associated_data: *const u8,
    ad_len: usize,
    ciphertext: *mut u8,
    tag: *mut u8,
) -> Chaco256Error {
    if ctx.is_null() || nonce.is_null() || tag.is_null() {
        return Chaco256Error::NullPointer;
    }

    if plaintext_len > 0 && (plaintext.is_null() || ciphertext.is_null()) {
        return Chaco256Error::NullPointer;
    }

    unsafe {
        let ctx_ref = &(*ctx).aead;
        let nonce_slice = slice::from_raw_parts(nonce, 24);
        let nonce_obj = Nonce::from_slice(nonce_slice);

        let plaintext_slice = if plaintext_len > 0 {
            slice::from_raw_parts(plaintext, plaintext_len)
        } else {
            &[]
        };

        let ad_slice = if ad_len > 0 && !associated_data.is_null() {
            slice::from_raw_parts(associated_data, ad_len)
        } else {
            &[]
        };

        let (ct, tag_obj) = ctx_ref.encrypt(&nonce_obj, plaintext_slice, ad_slice);

        if plaintext_len > 0 {
            let ciphertext_slice = slice::from_raw_parts_mut(ciphertext, plaintext_len);
            ciphertext_slice.copy_from_slice(&ct);
        }

        let tag_slice = slice::from_raw_parts_mut(tag, 32);
        tag_slice.copy_from_slice(tag_obj.as_bytes());
    }

    Chaco256Error::Ok
}

/// Decrypt and verify authenticated data
#[no_mangle]
pub extern "C" fn chaco256_aead_decrypt(
    ctx: *mut Chaco256AeadCtx,
    nonce: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    associated_data: *const u8,
    ad_len: usize,
    tag: *const u8,
    plaintext: *mut u8,
) -> Chaco256Error {
    if ctx.is_null() || nonce.is_null() || tag.is_null() {
        return Chaco256Error::NullPointer;
    }

    if ciphertext_len > 0 && (ciphertext.is_null() || plaintext.is_null()) {
        return Chaco256Error::NullPointer;
    }

    unsafe {
        let ctx_ref = &(*ctx).aead;
        let nonce_slice = slice::from_raw_parts(nonce, 24);
        let nonce_obj = Nonce::from_slice(nonce_slice);

        let ciphertext_slice = if ciphertext_len > 0 {
            slice::from_raw_parts(ciphertext, ciphertext_len)
        } else {
            &[]
        };

        let ad_slice = if ad_len > 0 && !associated_data.is_null() {
            slice::from_raw_parts(associated_data, ad_len)
        } else {
            &[]
        };

        let tag_slice = slice::from_raw_parts(tag, 32);
        let tag_obj = Tag::from_slice(tag_slice);

        match ctx_ref.decrypt(&nonce_obj, ciphertext_slice, &tag_obj, ad_slice) {
            Ok(pt) => {
                if ciphertext_len > 0 {
                    let plaintext_slice = slice::from_raw_parts_mut(plaintext, ciphertext_len);
                    plaintext_slice.copy_from_slice(&pt);
                }
                Chaco256Error::Ok
            }
            Err(_) => Chaco256Error::AuthFailed,
        }
    }
}

/// Securely zero memory
#[no_mangle]
pub extern "C" fn chaco256_zeroize(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            let slice = slice::from_raw_parts_mut(ptr, len);
            for byte in slice {
                *byte = 0;
            }
        }
    }
}

/// Get error message
#[no_mangle]
pub extern "C" fn chaco256_error_string(error: Chaco256Error) -> *const i8 {
    let msg = match error {
        Chaco256Error::Ok => "Success\0",
        Chaco256Error::InvalidKeySize => "Invalid key size (must be 32 bytes)\0",
        Chaco256Error::InvalidNonceSize => "Invalid nonce size (must be 24 bytes)\0",
        Chaco256Error::InvalidTagSize => "Invalid tag size (must be 32 bytes)\0",
        Chaco256Error::AuthFailed => "Authentication failed\0",
        Chaco256Error::NullPointer => "Null pointer provided\0",
        Chaco256Error::InvalidRounds => "Invalid rounds (must be 16, 20, or 24)\0",
    };
    msg.as_ptr() as *const i8
}
