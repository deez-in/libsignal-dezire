//! JNI module - Java bindings for cryptographic operations.
//!
//! This module provides JNI wrappers around the native Rust APIs to support
//! integration with Java/Kotlin (Android).

pub mod ratchet;
pub mod utils;
pub mod vxeddsa;
pub mod x3dh;
