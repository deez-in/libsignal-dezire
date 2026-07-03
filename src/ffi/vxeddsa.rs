//! FFI bindings for VXEdDSA operations.
//!
//! This module provides C-compatible FFI wrappers
//! that call the native Rust API in [`crate::vxeddsa`].

use crate::vxeddsa::{
    KeyPair, VXEdDSAOutput, gen_keypair, gen_pubkey, gen_secret, vxeddsa_sign, vxeddsa_verify,
};

// ============================================================================
// C FFI Functions (Thin wrappers around native API with _ffi suffix)
// ============================================================================

/// Generates a random Curve25519 key pair.
///
/// Wrapper around [`crate::vxeddsa::gen_keypair`].
///
/// # Returns
/// A `KeyPair` struct containing the secret and public keys.
#[unsafe(no_mangle)]
pub extern "C" fn gen_keypair_ffi() -> KeyPair {
    gen_keypair()
}

/// Generates a random 32-byte secret key and writes it to the provided buffer.
///
/// # Safety
/// * `secret_out` must be a valid pointer to a writable 32-byte memory region.
/// * The pointer must be properly aligned.
#[unsafe(no_mangle)]
pub extern "C" fn gen_secret_ffi(secret_out: *mut [u8; 32]) {
    let secret = gen_secret();
    unsafe {
        (*secret_out) = secret;
    }
}

/// Derives a public key from a given 32-byte secret key.
///
/// # Safety
/// * `k` must be a valid pointer to a readable 32-byte secret key.
/// * `pubkey` must be a valid pointer to a writable 32-byte memory region.
#[unsafe(no_mangle)]
pub extern "C" fn gen_pubkey_ffi(k: &[u8; 32], pubkey: *mut [u8; 33]) {
    let public = gen_pubkey(k);
    unsafe {
        (*pubkey) = public;
    }
}

/// Computes a VXEdDSA signature and generates the associated VRF output.
/// Wrapper around [`crate::vxeddsa::vxeddsa_sign`].
///
/// # Safety
/// * `msg_ptr` must point to a valid memory region of size `msg_len`.
/// * `output` must point to a writable `VXEdDSAOutput` struct.
///
/// # Returns
/// * `0` on success.
/// * `-1` on error.
#[unsafe(no_mangle)]
pub extern "C" fn vxeddsa_sign_ffi(
    k: &[u8; 32],
    msg_ptr: *const u8,
    msg_len: usize,
    output: *mut VXEdDSAOutput,
) -> i32 {
    // Convert raw pointer to slice
    let message = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };

    // Call native API
    match vxeddsa_sign(k, message) {
        Ok(result) => {
            unsafe {
                (*output) = result;
            }
            0
        }
        Err(()) => -1,
    }
}

/// Verifies a VXEdDSA signature.
/// Wrapper around [`crate::vxeddsa::vxeddsa_verify`].
///
/// # Safety
/// * `msg_ptr` must point to a valid memory region of size `msg_len`.
/// * `v_out` can be null. If not null, it must point to a writable 32-byte buffer.
///
/// # Returns
/// `true` if signature is valid, `false` otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn vxeddsa_verify_ffi(
    u: &[u8; 33],
    msg_ptr: *const u8,
    msg_len: usize,
    signature: &[u8; 96],
    v_out: *mut [u8; 32],
) -> bool {
    // Convert raw pointer to slice
    let message = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };

    // Call native API
    match vxeddsa_verify(u, message, signature) {
        Some(vrf_output) => {
            if !v_out.is_null() {
                unsafe {
                    (*v_out) = vrf_output;
                }
            }
            true
        }
        None => false,
    }
}
