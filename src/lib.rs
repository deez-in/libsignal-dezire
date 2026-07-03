//! # Signal Protocol Rust Library
//!
//! This library provides a pure Rust implementation of the Signal Protocol, designed for
//! secure end-to-end encryption. It includes support for the Double Ratchet algorithm,
//! X3DH key agreement, and VXEdDSA signatures.
//!
//! ## Feaures
//!
//! * **Pure Rust**: Core logic is memory-safe and platform-independent.
//! * **FFI & JNI**: Built-in support for integrating with Android (via JNI) and iOS (via C FFI).
//! * **Zeroization**: Sensitive keys are automatically zeroized on drop.
//!
//! ## Security
//!
//! This library implements the official Signal specifications. While it includes measures
//! like constant-time operations and memory zeroization, users should ensure they
//! manage keys securely on their persistent storage.
//!
//! ## Modules
//!
//! * `ratchet` - The Double Ratchet algorithm (session management, encryption/decryption).
//! * `x3dh` - The Extended Triple Diffie-Hellman (X3DH) key agreement protocol.
//! * `vxeddsa` - Implementation of the VXEdDSA signing scheme.
//! * `ffi` - C and JNI bindings for Android/iOS integration.
//! * `utils` - Utility functions for curve operations and key conversions.
//! * `hashes` - Cryptographic hash function abstractions.
//!
//! ## Specifications
//!
//! This library implements the following Signal specifications:
//! * [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
//! * [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
//! * [XEdDSA and VXEdDSA Signature Schemes](https://signal.org/docs/specifications/xeddsa/)

#[cfg(feature = "ffi")]
pub mod ffi;
pub(crate) mod hashes;
#[cfg(feature = "jni")]
pub mod jni;
pub mod ratchet;
pub mod utils;
pub mod vxeddsa;
pub mod x3dh;
