//! JNI bindings for ratchet.
//!
//! This module provides Android JNI bindings that call the native Rust API in [`crate::ratchet`].

#[cfg(target_os = "android")]
use crate::ratchet::*;
#[cfg(target_os = "android")]
use crate::utils::decode_public_key;
#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use jni::objects::{JByteArray, JObject, JValue};
#[cfg(target_os = "android")]
use jni::sys::{jbyteArray, jlong, jobject};
#[cfg(target_os = "android")]
use std::ptr;
#[cfg(target_os = "android")]
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(target_os = "android")]
fn get_byte_array(env: &mut JNIEnv, arr: jbyteArray) -> Option<Vec<u8>> {
    if arr.is_null() {
        return None;
    }
    let obj = unsafe { JByteArray::from_raw(arr) };
    env.convert_byte_array(&obj).ok()
}

#[cfg(target_os = "android")]
fn create_byte_array(env: &mut JNIEnv, bytes: &[u8]) -> jni::errors::Result<jbyteArray> {
    let array = env.byte_array_from_slice(bytes)?;
    Ok(array.into_raw())
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_ratchetInitSender(
    mut env: JNIEnv,
    _class: jni::objects::JClass,
    sk_arr: jbyteArray,
    receiver_pub_arr: jbyteArray,
) -> jlong {
    let sk_vec = match get_byte_array(&mut env, sk_arr) {
        Some(v) if v.len() == 32 => v,
        _ => return 0,
    };
    let pub_vec = match get_byte_array(&mut env, receiver_pub_arr) {
        Some(v) if v.len() == 33 => v,
        _ => return 0,
    };

    let sk: [u8; 32] = sk_vec.try_into().unwrap();
    let pub_key: [u8; 33] = pub_vec.try_into().unwrap();

    let decoded = match decode_public_key(&pub_key) {
        Ok(k) => k,
        Err(_) => return 0,
    };
    let receiver_pub = PublicKey::from(decoded);
    match init_sender_state(sk, receiver_pub) {
        Ok(state) => Box::into_raw(Box::new(state)) as jlong,
        Err(_) => 0,
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_ratchetInitReceiver(
    mut env: JNIEnv,
    _class: jni::objects::JClass,
    sk_arr: jbyteArray,
    priv_arr: jbyteArray,
    pub_arr: jbyteArray,
) -> jlong {
    let sk_vec = match get_byte_array(&mut env, sk_arr) {
        Some(v) if v.len() == 32 => v,
        _ => return 0,
    };
    let priv_vec = match get_byte_array(&mut env, priv_arr) {
        Some(v) if v.len() == 32 => v,
        _ => return 0,
    };
    let pub_vec = match get_byte_array(&mut env, pub_arr) {
        Some(v) if v.len() == 33 => v,
        _ => return 0,
    };

    let sk: [u8; 32] = sk_vec.try_into().unwrap();
    let priv_key: [u8; 32] = priv_vec.try_into().unwrap();
    let pub_key: [u8; 33] = pub_vec.try_into().unwrap();

    let decoded = match decode_public_key(&pub_key) {
        Ok(k) => k,
        Err(_) => return 0,
    };
    let key_pair = (StaticSecret::from(priv_key), PublicKey::from(decoded));
    let state = init_receiver_state(sk, key_pair);
    Box::into_raw(Box::new(state)) as jlong
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_ratchetFree(
    mut _env: JNIEnv,
    _class: jni::objects::JClass,
    state_ptr: jlong,
) {
    if state_ptr != 0 {
        unsafe {
            drop(Box::from_raw(state_ptr as *mut RatchetState));
        }
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_ratchetEncrypt(
    mut env: JNIEnv,
    _class: jni::objects::JClass,
    state_ptr: jlong,
    plaintext_arr: jbyteArray,
    ad_arr: jbyteArray,
) -> jobject {
    if state_ptr == 0 {
        return JObject::null().into_raw();
    }

    let plaintext_vec = match get_byte_array(&mut env, plaintext_arr) {
        Some(v) => v,
        _ => return JObject::null().into_raw(),
    };

    // AD can be null or empty
    let ad_vec = get_byte_array(&mut env, ad_arr).unwrap_or_default();

    let state = unsafe { &mut *(state_ptr as *mut RatchetState) };

    match encrypt(state, &plaintext_vec, &ad_vec) {
        Ok((header, ciphertext)) => {
            // Return HashMap { "header": byte[], "ciphertext": byte[] }
            let map_class = env.find_class("java/util/HashMap").unwrap();
            let map = env.new_object(map_class, "()V", &[]).unwrap();

            let h_arr = create_byte_array(&mut env, &header).unwrap();
            let c_arr = create_byte_array(&mut env, &ciphertext).unwrap();

            let h_key = env.new_string("header").unwrap();
            let c_key = env.new_string("ciphertext").unwrap();

            let h_obj = unsafe { JObject::from_raw(h_arr) };
            let c_obj = unsafe { JObject::from_raw(c_arr) };

            let _ = env.call_method(
                &map,
                "put",
                "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
                &[
                    JValue::Object(&JObject::from(h_key)),
                    JValue::Object(&h_obj),
                ],
            );

            let _ = env.call_method(
                &map,
                "put",
                "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
                &[
                    JValue::Object(&JObject::from(c_key)),
                    JValue::Object(&c_obj),
                ],
            );

            map.into_raw()
        }
        Err(_) => JObject::null().into_raw(),
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_ratchetDecrypt(
    mut env: JNIEnv,
    _class: jni::objects::JClass,
    state_ptr: jlong,
    header_arr: jbyteArray,
    ciphertext_arr: jbyteArray,
    ad_arr: jbyteArray,
) -> jbyteArray {
    if state_ptr == 0 {
        return ptr::null_mut();
    }

    let header_vec = match get_byte_array(&mut env, header_arr) {
        Some(v) => v,
        None => return ptr::null_mut(),
    };
    let cipher_vec = match get_byte_array(&mut env, ciphertext_arr) {
        Some(v) => v,
        None => return ptr::null_mut(),
    };
    let ad_vec = get_byte_array(&mut env, ad_arr).unwrap_or_default();

    let state = unsafe { &mut *(state_ptr as *mut RatchetState) };

    match decrypt(state, &header_vec, &cipher_vec, &ad_vec) {
        Ok(plaintext) => create_byte_array(&mut env, &plaintext).unwrap_or(ptr::null_mut()),
        Err(_) => ptr::null_mut(),
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_ratchetSerialize(
    env: JNIEnv,
    _class: jni::objects::JClass,
    state_ptr: jlong,
) -> jni::sys::jstring {
    if state_ptr == 0 {
        return ptr::null_mut();
    }
    let state = unsafe { &*(state_ptr as *const RatchetState) };

    match serde_json::to_string(state) {
        Ok(json_str) => match env.new_string(json_str) {
            Ok(j_str) => j_str.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_ratchetDeserialize(
    mut env: JNIEnv,
    _class: jni::objects::JClass,
    json_str: jni::objects::JString,
) -> jlong {
    if json_str.is_null() {
        return 0;
    }

    let json_string: String = match env.get_string(&json_str) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    match serde_json::from_str::<RatchetState>(&json_string) {
        Ok(state) => Box::into_raw(Box::new(state)) as jlong,
        Err(_) => 0,
    }
}
