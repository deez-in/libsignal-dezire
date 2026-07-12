//! FFI bindings for Double Ratchet.
//!
//! This module provides C-compatible FFI wrappers
//! that call the memory-safe native Rust API in [`crate::ratchet`].

use crate::ratchet::{
    RatchetError, RatchetState, decrypt, encrypt, init_receiver_state, init_sender_state,
};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use x25519_dalek::{PublicKey, StaticSecret};

// ============================================================================
// C FFI Types
// ============================================================================

/// Structure for returning multiple values from encrypt (C-compatible).
/// We return byte arrays by pointer-length pairs or fixed buffers.
/// Since ciphertext is variable length, we might need a way to return it.
/// Common FFI pattern: User provides buffer, we write to it.
/// OR we return a new struct that must be freed.
///
/// For simplicity and safety in this project's context, let's use a struct that
/// requires one copy or return heap allocated buffers that C must free?
/// Checking `x3dh.rs`: it uses `X3DHInitOutput` with fixed size arrays.
/// Ratchet encryption returns variable size ciphertext.
///
/// We will use a callback-style or buffer-size query style?
/// Or simpler: Just return a struct with pointers that RUST manages? No, that's hard.
///
/// Decision: `ratchet_encrypt_ffi` will allocate memory using `malloc` (via Rust Vec -> raw)
/// and return a struct containing pointers and lengths.
/// C consumer MUST free these buffers.
/// Actually, to be safe across allocators, we should provide a `free_buffer` function,
/// or just ask C to provide the buffer (typical C style).
///
/// Let's use the "Output Struct" approach where Rust allocates and C must call `signal_free_buffer`.
/// Or, we can use `RatchetEncryptedOutput` struct.
#[repr(C)]
pub struct RatchetEncryptResult {
    pub header: *mut u8,
    pub header_len: usize,
    pub ciphertext: *mut u8,
    pub ciphertext_len: usize,
    pub status: i32, // 0 = Success, Error codes < 0
}

#[repr(C)]
pub struct RatchetDecryptResult {
    pub plaintext: *mut u8,
    pub plaintext_len: usize,
    pub status: i32, // 0 = Success, Error codes < 0
}

/// Free buffers returned by ratchet_encrypt_ffi.
///
/// # Safety
/// * `header` and `ciphertext` must be valid pointers returned by encryption, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ratchet_free_result_buffers(
    header: *mut u8,
    header_len: usize,
    ciphertext: *mut u8,
    ciphertext_len: usize,
) {
    unsafe {
        if !header.is_null() && header_len > 0 {
            let _ = Vec::from_raw_parts(header, header_len, header_len);
        }
        if !ciphertext.is_null() && ciphertext_len > 0 {
            let _ = Vec::from_raw_parts(ciphertext, ciphertext_len, ciphertext_len);
        }
    }
}

/// Free a byte buffer.
///
/// # Safety
/// * `buffer` must be a valid pointer returned by decryption, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ratchet_free_byte_buffer(buffer: *mut u8, len: usize) {
    unsafe {
        if !buffer.is_null() && len > 0 {
            let _ = Vec::from_raw_parts(buffer, len, len);
        }
    }
}

// ============================================================================
// C FFI Functions
// ============================================================================

/// Initialize sender state.
/// Returns a pointer to the opaque RatchetState object.
/// Returns NULL on failure.
///
/// # Safety
/// * `sk` must be a valid pointer to a 32-byte secret key.
/// * `receiver_dh_public` must be a valid pointer to a 33-byte public key.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ratchet_init_sender_ffi(
    sk: &[u8; 32],
    receiver_dh_public: &[u8; 33],
) -> *mut RatchetState {
    let receiver_dh_decrypted = match crate::utils::decode_public_key(receiver_dh_public) {
        Ok(k) => k,
        Err(_) => return ptr::null_mut(),
    };
    let receiver_pub = PublicKey::from(receiver_dh_decrypted);
    match init_sender_state(*sk, receiver_pub) {
        Ok(state) => Box::into_raw(Box::new(state)),
        Err(_) => ptr::null_mut(),
    }
}

/// Initialize receiver state.
/// Returns a pointer to the opaque RatchetState object.
///
/// # Safety
/// * `sk` must be a valid pointer to a 32-byte secret key.
/// * `receiver_dh_private` must be a valid pointer to a 32-byte private key.
/// * `receiver_dh_public` must be a valid pointer to a 33-byte public key.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ratchet_init_receiver_ffi(
    sk: &[u8; 32],
    receiver_dh_private: &[u8; 32],
    receiver_dh_public: &[u8; 33],
) -> *mut RatchetState {
    let receiver_dh_decrypted = match crate::utils::decode_public_key(receiver_dh_public) {
        Ok(k) => k,
        Err(_) => return ptr::null_mut(),
    };
    let key_pair = (
        StaticSecret::from(*receiver_dh_private),
        PublicKey::from(receiver_dh_decrypted),
    );
    let state = init_receiver_state(*sk, key_pair);
    Box::into_raw(Box::new(state))
}

/// Free the RatchetState object.
///
/// # Safety
/// * `state` must be a valid pointer to a RatchetState returned by an init function, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ratchet_free_ffi(state: *mut RatchetState) {
    unsafe {
        if !state.is_null() {
            drop(Box::from_raw(state));
        }
    }
}

/// Encrypt a message.
/// Caller MUST free the returned buffers using `ratchet_free_result_buffers`.
///
/// # Safety
/// * `state_ptr` must be a valid pointer to a RatchetState.
/// * `plaintext` must point to `plaintext_len` valid bytes.
/// * `ad` must point to `ad_len` valid bytes.
/// * `output` must point to a valid RatchetEncryptResult struct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ratchet_encrypt_ffi(
    state_ptr: *mut RatchetState,
    plaintext: *const u8,
    plaintext_len: usize,
    ad: *const u8,
    ad_len: usize,
    output: *mut RatchetEncryptResult,
) -> i32 {
    if state_ptr.is_null() || output.is_null() {
        return -100; // Null pointer error
    }

    // SAFETY: We checked for null, and we trust C Caller to pass valid pointer from init
    let state = unsafe { &mut *state_ptr };

    let plaintext_slice = if plaintext.is_null() || plaintext_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(plaintext, plaintext_len) }
    };

    let ad_slice = if ad.is_null() || ad_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ad, ad_len) }
    };

    match encrypt(state, plaintext_slice, ad_slice) {
        Ok((header, ciphertext)) => {
            // Leak memory to pass to C
            let mut header_vec = header;
            let mut cipher_vec = ciphertext;

            // Should shrink to fit?
            header_vec.shrink_to_fit();
            cipher_vec.shrink_to_fit();

            let h_len = header_vec.len();
            let c_len = cipher_vec.len();

            let h_ptr = header_vec.as_mut_ptr();
            let c_ptr = cipher_vec.as_mut_ptr();

            std::mem::forget(header_vec);
            std::mem::forget(cipher_vec);

            unsafe {
                (*output).header = h_ptr;
                (*output).header_len = h_len;
                (*output).ciphertext = c_ptr;
                (*output).ciphertext_len = c_len;
                (*output).status = 0;
            }
            0
        }
        Err(e) => {
            let err_code = map_error(e);
            unsafe {
                (*output).header = ptr::null_mut();
                (*output).header_len = 0;
                (*output).ciphertext = ptr::null_mut();
                (*output).ciphertext_len = 0;
                (*output).status = err_code;
            }
            err_code
        }
    }
}

/// Decrypt a message.
/// Caller MUST free the returned buffer using `ratchet_free_byte_buffer`.
///
/// # Safety
/// * `state_ptr` must be a valid pointer to a RatchetState.
/// * `header`, `ciphertext`, and `ad` must point to valid byte arrays of their respective lengths.
/// * `output` must point to a valid RatchetDecryptResult struct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ratchet_decrypt_ffi(
    state_ptr: *mut RatchetState,
    header: *const u8,
    header_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    ad: *const u8,
    ad_len: usize,
    output: *mut RatchetDecryptResult,
) -> i32 {
    if state_ptr.is_null() || output.is_null() {
        return -100;
    }
    match validate_inputs(header, header_len) {
        Ok(_) => {}
        Err(_) => return -101, // Invalid header input
    }
    // Ciphertext can be empty? Technically yes, but usually no.
    // Decrypt AEAD checks size >= 48.

    let state = unsafe { &mut *state_ptr };

    let header_slice = unsafe { slice::from_raw_parts(header, header_len) };

    let ciphertext_slice = if ciphertext.is_null() || ciphertext_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ciphertext, ciphertext_len) }
    };

    let ad_slice = if ad.is_null() || ad_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ad, ad_len) }
    };

    match decrypt(state, header_slice, ciphertext_slice, ad_slice) {
        Ok(plaintext) => {
            let mut p_vec = plaintext;
            p_vec.shrink_to_fit();
            let p_len = p_vec.len();
            let p_ptr = p_vec.as_mut_ptr();
            std::mem::forget(p_vec);

            unsafe {
                (*output).plaintext = p_ptr;
                (*output).plaintext_len = p_len;
                (*output).status = 0;
            }
            0
        }
        Err(e) => {
            let err_code = map_error(e);
            unsafe {
                (*output).plaintext = ptr::null_mut();
                (*output).plaintext_len = 0;
                (*output).status = err_code;
            }
            err_code
        }
    }
}

fn validate_inputs(ptr: *const u8, len: usize) -> Result<(), ()> {
    if ptr.is_null() && len > 0 {
        Err(())
    } else {
        Ok(())
    }
}

fn map_error(e: RatchetError) -> i32 {
    match e {
        RatchetError::InvalidKey => -1,
        RatchetError::DecryptionFailed => -2,
        RatchetError::OldMessageKeysLimitReached => -3,
        RatchetError::DuplicateMessage => -4,
        RatchetError::InvalidHeader => -5,
        RatchetError::HeaderDecryptionFailed => -6,
        RatchetError::CounterOverflow => -7,
        RatchetError::ADTooLarge => -8,
        RatchetError::InvalidState => -9,
        RatchetError::TooManyMessages => -10,
    }
}

// ============================================================================
// Serialization FFI
// ============================================================================

/// Serialize RatchetState to JSON string.
/// Returns pointer to C string (null-terminated).
/// Caller MUST free the string using `ratchet_free_string`.
///
/// # Safety
/// * `state_ptr` must be a valid pointer to a RatchetState.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ratchet_serialize(state_ptr: *const RatchetState) -> *mut c_char {
    if state_ptr.is_null() {
        return ptr::null_mut();
    }
    let state = unsafe { &*state_ptr };

    match serde_json::to_string(state) {
        Ok(json_str) => match CString::new(json_str) {
            Ok(c_str) => c_str.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Deserialize RatchetState from JSON string.
/// Returns pointer to RatchetState or NULL on failure.
///
/// # Safety
/// * `json_ptr` must be a valid pointer to a null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ratchet_deserialize(json_ptr: *const c_char) -> *mut RatchetState {
    if json_ptr.is_null() {
        return ptr::null_mut();
    }
    let c_str = unsafe { CStr::from_ptr(json_ptr) };
    let json_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    match serde_json::from_str::<RatchetState>(json_str) {
        Ok(state) => Box::into_raw(Box::new(state)),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a string returned by ratchet_serialize.
///
/// # Safety
/// * `s` must be a valid pointer to a string allocated by `ratchet_serialize`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ratchet_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}
