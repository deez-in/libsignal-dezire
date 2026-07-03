//! FFI bindings for X3DH.
//!
//! This module provides C-compatible FFI wrappers
//! that call the memory-safe native Rust API in [`crate::x3dh`].

use crate::x3dh::{
    OneTimePreKey, PreKeyBundle, SignedPreKey, X3DHError, X3DHInitResult, x3dh_initiator,
    x3dh_responder,
};

// ============================================================================
// C FFI Types
// ============================================================================

/// Structure for returning multiple values from x3dh_initiator (C-compatible).
#[repr(C)]
pub struct X3DHInitOutput {
    pub shared_secret: [u8; 32],
    pub ephemeral_public: [u8; 33],
    pub status: i32, // 0 = Success, -1 = Invalid Signature, -2 = Invalid Key, -3 = Missing OTK
}

impl X3DHInitOutput {
    fn from_result(result: Result<X3DHInitResult, X3DHError>) -> Self {
        match result {
            Ok(r) => X3DHInitOutput {
                shared_secret: r.shared_secret,
                ephemeral_public: r.ephemeral_public,
                status: 0,
            },
            Err(X3DHError::InvalidSignature) => X3DHInitOutput {
                shared_secret: [0u8; 32],
                ephemeral_public: [0u8; 33],
                status: -1,
            },
            Err(X3DHError::InvalidKey) => X3DHInitOutput {
                shared_secret: [0u8; 32],
                ephemeral_public: [0u8; 33],
                status: -2,
            },
            Err(X3DHError::MissingOneTimeKey) => X3DHInitOutput {
                shared_secret: [0u8; 32],
                ephemeral_public: [0u8; 33],
                status: -3,
            },
            Err(X3DHError::DecodeFailed) => X3DHInitOutput {
                shared_secret: [0u8; 32],
                ephemeral_public: [0u8; 33],
                status: -4,
            },
        }
    }
}

/// Structure for returning x3dh_responder result (C-compatible).
#[repr(C)]
pub struct X3DHResponderOutput {
    pub shared_secret: [u8; 32],
    pub status: i32, // 0 = Success, -1 = Invalid Key, -2 = Other Error
}

impl X3DHResponderOutput {
    fn from_result(result: Result<[u8; 32], X3DHError>) -> Self {
        match result {
            Ok(shared_secret) => X3DHResponderOutput {
                shared_secret,
                status: 0,
            },
            Err(X3DHError::InvalidKey) => X3DHResponderOutput {
                shared_secret: [0u8; 32],
                status: -1,
            },
            Err(_) => X3DHResponderOutput {
                shared_secret: [0u8; 32],
                status: -2,
            },
        }
    }
}

/// C-compatible PreKey Bundle input for x3dh_initiator_ffi.
#[repr(C)]
pub struct X3DHBundleInput {
    pub identity_public: [u8; 33],
    pub spk_id: u32,
    pub spk_public: [u8; 33],
    pub spk_signature: [u8; 96],
    pub opk_id: u32,          // ignored if has_opk = false
    pub opk_public: [u8; 33], // ignored if has_opk = false
    pub has_opk: bool,
}

/// C-compatible responder keys input.
#[repr(C)]
pub struct X3DHResponderInput {
    pub identity_private: [u8; 32],
    pub spk_private: [u8; 32],
    pub opk_private: [u8; 32], // ignored if has_opk = false
    pub has_opk: bool,
}

/// C-compatible initiator keys from Alice.
#[repr(C)]
pub struct X3DHAliceKeys {
    pub identity_public: [u8; 33],
    pub ephemeral_public: [u8; 33],
}

// ============================================================================
// C FFI Functions
// ============================================================================

/// Alice (Initiator) performs the X3DH key agreement.
///
/// # Safety
/// * `identity_private` must point to a valid 32-byte array.
/// * `bundle` must point to a valid `X3DHBundleInput` struct.
/// * `output` must point to a writable `X3DHInitOutput` struct.
/// * All pointers must be properly aligned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x3dh_initiator_ffi(
    identity_private: &[u8; 32],
    bundle: &X3DHBundleInput,
    output: *mut X3DHInitOutput,
) {
    // Build the PreKeyBundle from input struct
    let signed_prekey = SignedPreKey {
        id: bundle.spk_id,
        public_key: bundle.spk_public,
        signature: bundle.spk_signature,
    };

    let one_time_prekey = if bundle.has_opk {
        Some(OneTimePreKey {
            id: bundle.opk_id,
            public_key: bundle.opk_public,
        })
    } else {
        None
    };

    let prekey_bundle = PreKeyBundle {
        identity_key: bundle.identity_public,
        signed_prekey,
        one_time_prekey,
    };

    // Call the native Rust API
    let result = x3dh_initiator(identity_private, &prekey_bundle);

    // Write output
    unsafe {
        *output = X3DHInitOutput::from_result(result);
    }
}

/// Bob (Responder) performs the X3DH key agreement.
///
/// # Safety
/// * `responder` must point to a valid `X3DHResponderInput` struct.
/// * `alice` must point to a valid `X3DHAliceKeys` struct.
/// * `output` must point to a writable `X3DHResponderOutput` struct.
/// * All pointers must be properly aligned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x3dh_responder_ffi(
    responder: &X3DHResponderInput,
    alice: &X3DHAliceKeys,
    output: *mut X3DHResponderOutput,
) {
    // Convert optional OPK
    let opk_private = if responder.has_opk {
        Some(&responder.opk_private)
    } else {
        None
    };

    // Call the native Rust API
    let result = x3dh_responder(
        &responder.identity_private,
        &responder.spk_private,
        opk_private,
        &alice.identity_public,
        &alice.ephemeral_public,
    );

    // Write output
    unsafe {
        *output = X3DHResponderOutput::from_result(result);
    }
}

// Old FFI functions (commented out for reference):
// #[unsafe(no_mangle)]
// pub unsafe extern "C" fn x3dh_initiator_ffi_old(
//     identity_private: &[u8; 32],
//     bob_identity_public: &[u8; 32],
//     bob_spk_id: u32,
//     bob_spk_public: &[u8; 32],
//     bob_spk_signature: &[u8; 96],
//     bob_opk_id: u32,
//     bob_opk_public: *const u8,
//     has_opk: bool,
//     output: *mut X3DHInitOutput,
// ) { ... }
//
// #[unsafe(no_mangle)]
// pub unsafe extern "C" fn x3dh_responder_ffi_old(
//     identity_private: &[u8; 32],
//     signed_prekey_private: &[u8; 32],
//     one_time_prekey_private: *const u8,
//     has_opk: bool,
//     alice_identity_public: &[u8; 32],
//     alice_ephemeral_public: &[u8; 32],
//     shared_secret_out: *mut [u8; 32],
// ) -> i32 { ... }
