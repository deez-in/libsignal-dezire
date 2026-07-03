//! JNI bindings for utils.
//!
//! This module provides Android JNI bindings that call the native Rust API in [`crate::utils`].

use crate::utils::*;

// ============================================================================
// JNI Bindings (Android Only)
// ============================================================================

#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use jni::objects::JByteArray;
#[cfg(target_os = "android")]
use jni::sys::{jbyteArray, jclass};

#[cfg(target_os = "android")]
fn create_byte_array(env: &mut JNIEnv, bytes: &[u8]) -> jni::errors::Result<jbyteArray> {
    let array = env.byte_array_from_slice(bytes)?;
    Ok(array.into_raw())
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_encodePublicKey(
    mut env: JNIEnv,
    _class: jclass,
    key_byte_array: jbyteArray,
) -> jbyteArray {
    let key_obj = unsafe { JByteArray::from_raw(key_byte_array) };
    let key = match env.convert_byte_array(&key_obj) {
        Ok(k) => k,
        Err(_) => return std::ptr::null_mut(),
    };

    if key.len() != 32 {
        return std::ptr::null_mut();
    }

    let key_arr: [u8; 32] = match key.try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    // Call native API directly
    let encoded = encode_public_key(&key_arr);

    create_byte_array(&mut env, &encoded).unwrap_or(std::ptr::null_mut())
}
