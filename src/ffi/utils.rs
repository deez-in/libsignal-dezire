//! FFI bindings for utility functions.
//!
//! This module provides C-compatible FFI wrappers
//! that call the native Rust API in [`crate::utils`].

use crate::utils::encode_public_key;

// ============================================================================
// C FFI Functions (Thin wrappers with _ffi suffix)
// ============================================================================

/// Encodes a public key by prepending 0x05 (Curve25519) to the 32-byte key.
/// Wrapper around [`crate::utils::encode_public_key`].
///
/// # Safety
/// The caller must ensure that `out` is valid for writes of 33 bytes.
#[unsafe(no_mangle)]
pub extern "C" fn encode_public_key_ffi(key: &[u8; 32], out: *mut u8) {
    if out.is_null() {
        return;
    }

    // Call native API
    let encoded = encode_public_key(key);

    // Copy to output buffer
    unsafe {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), out, 33);
    }
}
