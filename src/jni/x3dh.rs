//! JNI bindings for x3dh.
//!
//! This module provides Android JNI bindings that call the native Rust API in [`crate::x3dh`].

use crate::x3dh::*;

// ============================================================================
// JNI Bindings (Android Only)
// ============================================================================

#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use jni::objects::{JByteArray, JObject, JValue};
#[cfg(target_os = "android")]
use jni::sys::{jbyteArray, jclass, jint, jobject};

#[cfg(target_os = "android")]
fn create_byte_array(env: &mut JNIEnv, bytes: &[u8]) -> jni::errors::Result<jbyteArray> {
    let array = env.byte_array_from_slice(bytes)?;
    Ok(array.into_raw())
}

#[cfg(target_os = "android")]
fn get_byte_array(env: &mut JNIEnv, arr: jbyteArray) -> Option<Vec<u8>> {
    if arr.is_null() {
        return None;
    }
    let obj = unsafe { JByteArray::from_raw(arr) };
    env.convert_byte_array(&obj).ok()
}

/// JNI binding for X3DH initiator.
///
/// Calls the native Rust API using internal struct conversion.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_x3dhInitiator(
    mut env: JNIEnv,
    _class: jclass,
    identity_private_arr: jbyteArray,
    bob_identity_public_arr: jbyteArray,
    bob_spk_id: jint,
    bob_spk_public_arr: jbyteArray,
    bob_spk_signature_arr: jbyteArray,
    bob_opk_id: jint,
    bob_opk_public_arr: jbyteArray,
) -> jobject {
    // Extract byte arrays
    let id_priv = match get_byte_array(&mut env, identity_private_arr) {
        Some(v) if v.len() == 32 => v,
        _ => return JObject::null().into_raw(),
    };
    let bob_id_pub = match get_byte_array(&mut env, bob_identity_public_arr) {
        Some(v) if v.len() == 33 => v,
        _ => return JObject::null().into_raw(),
    };
    let bob_spk_pub = match get_byte_array(&mut env, bob_spk_public_arr) {
        Some(v) if v.len() == 33 => v,
        _ => return JObject::null().into_raw(),
    };
    let bob_spk_sig = match get_byte_array(&mut env, bob_spk_signature_arr) {
        Some(v) if v.len() == 96 => v,
        _ => return JObject::null().into_raw(),
    };
    let bob_opk_pub = get_byte_array(&mut env, bob_opk_public_arr);

    // Convert to fixed arrays
    let id_priv_fixed: [u8; 32] = id_priv.try_into().unwrap();

    // Build X3DHBundleInput struct (shared pattern with C FFI)
    let bundle = X3DHBundleInput {
        identity_public: bob_id_pub.try_into().unwrap(),
        spk_id: bob_spk_id as u32,
        spk_public: bob_spk_pub.try_into().unwrap(),
        spk_signature: bob_spk_sig.try_into().unwrap(),
        opk_id: bob_opk_id as u32,
        opk_public: bob_opk_pub
            .as_ref()
            .and_then(|v| v.clone().try_into().ok())
            .unwrap_or([0u8; 33]),
        has_opk: bob_opk_pub.as_ref().map_or(false, |v| v.len() == 33),
    };

    // Build PreKeyBundle and call native API
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

    // Call native Rust API
    let result = match x3dh_initiator(&id_priv_fixed, &prekey_bundle) {
        Ok(r) => r,
        Err(_) => return JObject::null().into_raw(),
    };

    // Return HashMap { "shared_secret": byte[], "ephemeral_public": byte[] }
    let map_class = match env.find_class("java/util/HashMap") {
        Ok(c) => c,
        Err(_) => return JObject::null().into_raw(),
    };
    let map = match env.new_object(map_class, "()V", &[]) {
        Ok(m) => m,
        Err(_) => return JObject::null().into_raw(),
    };

    let secret_array = match create_byte_array(&mut env, &result.shared_secret) {
        Ok(a) => a,
        Err(_) => return JObject::null().into_raw(),
    };
    let public_array = match create_byte_array(&mut env, &result.ephemeral_public) {
        Ok(a) => a,
        Err(_) => return JObject::null().into_raw(),
    };

    let secret_key = match env.new_string("sharedSecret") {
        Ok(s) => s,
        Err(_) => return JObject::null().into_raw(),
    };
    let public_key = match env.new_string("ephemeralPublic") {
        Ok(s) => s,
        Err(_) => return JObject::null().into_raw(),
    };

    let secret_key_obj = JObject::from(secret_key);
    let secret_array_obj = unsafe { JObject::from_raw(secret_array) };
    let public_key_obj = JObject::from(public_key);
    let public_array_obj = unsafe { JObject::from_raw(public_array) };

    let _ = env.call_method(
        &map,
        "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[
            JValue::Object(&secret_key_obj),
            JValue::Object(&secret_array_obj),
        ],
    );

    let _ = env.call_method(
        &map,
        "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[
            JValue::Object(&public_key_obj),
            JValue::Object(&public_array_obj),
        ],
    );

    map.into_raw()
}

/// JNI binding for X3DH responder.
///
/// Calls the native Rust API using internal struct conversion.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_x3dhResponder(
    mut env: JNIEnv,
    _class: jclass,
    identity_private_arr: jbyteArray,
    signed_prekey_private_arr: jbyteArray,
    one_time_prekey_private_arr: jbyteArray,
    alice_identity_public_arr: jbyteArray,
    alice_ephemeral_public_arr: jbyteArray,
) -> jbyteArray {
    // Extract byte arrays
    let id_priv = match get_byte_array(&mut env, identity_private_arr) {
        Some(v) if v.len() == 32 => v,
        _ => return std::ptr::null_mut(),
    };
    let spk_priv = match get_byte_array(&mut env, signed_prekey_private_arr) {
        Some(v) if v.len() == 32 => v,
        _ => return std::ptr::null_mut(),
    };
    let alice_id_pub = match get_byte_array(&mut env, alice_identity_public_arr) {
        Some(v) if v.len() == 33 => v,
        _ => return std::ptr::null_mut(),
    };
    let alice_ek_pub = match get_byte_array(&mut env, alice_ephemeral_public_arr) {
        Some(v) if v.len() == 33 => v,
        _ => return std::ptr::null_mut(),
    };
    let opk_priv = get_byte_array(&mut env, one_time_prekey_private_arr);

    // Build X3DHResponderInput struct (shared pattern with C FFI)
    let responder = X3DHResponderInput {
        identity_private: id_priv.try_into().unwrap(),
        spk_private: spk_priv.try_into().unwrap(),
        opk_private: opk_priv
            .as_ref()
            .and_then(|v| v.clone().try_into().ok())
            .unwrap_or([0u8; 32]),
        has_opk: opk_priv.as_ref().map_or(false, |v| v.len() == 32),
    };

    // Build X3DHAliceKeys struct (shared pattern with C FFI)
    let alice = X3DHAliceKeys {
        identity_public: alice_id_pub.try_into().unwrap(),
        ephemeral_public: alice_ek_pub.try_into().unwrap(),
    };

    // Convert optional OPK
    let opk_private = if responder.has_opk {
        Some(&responder.opk_private)
    } else {
        None
    };

    // Call native Rust API
    let result = x3dh_responder(
        &responder.identity_private,
        &responder.spk_private,
        opk_private,
        &alice.identity_public,
        &alice.ephemeral_public,
    );

    match result {
        Ok(shared_secret) => {
            create_byte_array(&mut env, &shared_secret).unwrap_or(std::ptr::null_mut())
        }
        Err(_) => std::ptr::null_mut(),
    }
}
