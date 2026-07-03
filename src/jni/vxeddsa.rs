//! JNI bindings for VXEdDSA operations.
//!
//! This module provides Android JNI bindings that call the native Rust API in [`crate::vxeddsa`].

use crate::vxeddsa::{gen_keypair, gen_pubkey, gen_secret, vxeddsa_sign, vxeddsa_verify};

use jni::JNIEnv;
use jni::objects::{JByteArray, JObject, JValue};
use jni::sys::{jbyteArray, jclass, jobject};

fn create_byte_array(env: &mut JNIEnv, bytes: &[u8]) -> jni::errors::Result<jbyteArray> {
    let array = env.byte_array_from_slice(bytes)?;
    Ok(array.into_raw())
}

#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_genKeyPair(
    mut env: JNIEnv,
    _class: jclass,
) -> jobject {
    let keys = gen_keypair();

    let map_class = match env.find_class("java/util/HashMap") {
        Ok(c) => c,
        Err(_) => return JObject::null().into_raw(),
    };
    let map = match env.new_object(map_class, "()V", &[]) {
        Ok(m) => m,
        Err(_) => return JObject::null().into_raw(),
    };

    let secret_array = match create_byte_array(&mut env, &keys.secret) {
        Ok(a) => a,
        Err(_) => return JObject::null().into_raw(),
    };
    let public_array = match create_byte_array(&mut env, &keys.public) {
        Ok(a) => a,
        Err(_) => return JObject::null().into_raw(),
    };

    let secret_key = match env.new_string("secret") {
        Ok(s) => s,
        Err(_) => return JObject::null().into_raw(),
    };
    let public_key = match env.new_string("public") {
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

#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_vxeddsaSign(
    mut env: JNIEnv,
    _class: jclass,
    k_byte_array: jbyteArray,
    m_byte_array: jbyteArray,
) -> jobject {
    let k_obj = unsafe { JByteArray::from_raw(k_byte_array) };
    let m_obj = unsafe { JByteArray::from_raw(m_byte_array) };

    let k = match env.convert_byte_array(&k_obj) {
        Ok(k) => k,
        Err(_) => return JObject::null().into_raw(),
    };
    let m = match env.convert_byte_array(&m_obj) {
        Ok(m) => m,
        Err(_) => return JObject::null().into_raw(),
    };

    if k.len() != 32 {
        return JObject::null().into_raw();
    }

    let k_arr: [u8; 32] = k.try_into().unwrap();

    // Call native API directly
    let output = match vxeddsa_sign(&k_arr, &m) {
        Ok(o) => o,
        Err(()) => return JObject::null().into_raw(),
    };

    let map_class = match env.find_class("java/util/HashMap") {
        Ok(c) => c,
        Err(_) => return JObject::null().into_raw(),
    };
    let map = match env.new_object(map_class, "()V", &[]) {
        Ok(m) => m,
        Err(_) => return JObject::null().into_raw(),
    };

    let signature_array = match create_byte_array(&mut env, &output.signature) {
        Ok(a) => a,
        Err(_) => return JObject::null().into_raw(),
    };
    let vrf_array = match create_byte_array(&mut env, &output.vrf) {
        Ok(a) => a,
        Err(_) => return JObject::null().into_raw(),
    };

    let signature_key = match env.new_string("signature") {
        Ok(s) => s,
        Err(_) => return JObject::null().into_raw(),
    };
    let vrf_key = match env.new_string("vrf") {
        Ok(s) => s,
        Err(_) => return JObject::null().into_raw(),
    };

    let signature_key_obj = JObject::from(signature_key);
    let signature_array_obj = unsafe { JObject::from_raw(signature_array) };
    let vrf_key_obj = JObject::from(vrf_key);
    let vrf_array_obj = unsafe { JObject::from_raw(vrf_array) };

    let _ = env.call_method(
        &map,
        "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[
            JValue::Object(&signature_key_obj),
            JValue::Object(&signature_array_obj),
        ],
    );

    let _ = env.call_method(
        &map,
        "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[JValue::Object(&vrf_key_obj), JValue::Object(&vrf_array_obj)],
    );

    map.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_vxeddsaVerify(
    mut env: JNIEnv,
    _class: jclass,
    u_byte_array: jbyteArray,
    m_byte_array: jbyteArray,
    signature_byte_array: jbyteArray,
) -> jbyteArray {
    let u_obj = unsafe { JByteArray::from_raw(u_byte_array) };
    let m_obj = unsafe { JByteArray::from_raw(m_byte_array) };
    let sig_obj = unsafe { JByteArray::from_raw(signature_byte_array) };

    let u = match env.convert_byte_array(&u_obj) {
        Ok(u) => u,
        Err(_) => return std::ptr::null_mut(),
    };
    let m = match env.convert_byte_array(&m_obj) {
        Ok(m) => m,
        Err(_) => return std::ptr::null_mut(),
    };
    let sig = match env.convert_byte_array(&sig_obj) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    if u.len() != 33 || sig.len() != 96 {
        return std::ptr::null_mut();
    }

    let u_arr: [u8; 33] = u.try_into().unwrap();
    let sig_arr: [u8; 96] = sig.try_into().unwrap();

    // Call native API directly
    // verify expects encoded key (33 bytes)
    match vxeddsa_verify(&u_arr, &m, &sig_arr) {
        Some(v_out) => create_byte_array(&mut env, &v_out).unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_genPubKey(
    mut env: JNIEnv,
    _class: jclass,
    k_byte_array: jbyteArray,
) -> jbyteArray {
    let k_obj = unsafe { JByteArray::from_raw(k_byte_array) };

    let k = match env.convert_byte_array(&k_obj) {
        Ok(k) => k,
        Err(_) => return std::ptr::null_mut(),
    };

    if k.len() != 32 {
        return std::ptr::null_mut();
    }

    let k_arr: [u8; 32] = k.try_into().unwrap();

    // Call native API directly
    let k_out = gen_pubkey(&k_arr);

    create_byte_array(&mut env, &k_out).unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_genSecret(
    mut env: JNIEnv,
    _class: jclass,
) -> jbyteArray {
    // Call native API directly
    let secret = gen_secret();
    create_byte_array(&mut env, &secret).unwrap_or(std::ptr::null_mut())
}
