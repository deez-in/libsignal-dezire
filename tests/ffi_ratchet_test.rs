#![cfg(feature = "ffi")]
use libsignal_dezire::ffi::ratchet::*;
use std::ptr;
use std::slice;

#[test]
fn test_ffi_ratchet_flow() {
    let sk = [0x99u8; 32];

    // Simulate C caller
    // 1. Setup keys
    // Just use random placeholders for test simplicity since actual logic is tested in unit tests
    // But we need valid keys for X25519
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    let bob_secret = StaticSecret::random_from_rng(&mut OsRng);
    let bob_public = PublicKey::from(&bob_secret);

    let alice_secret = StaticSecret::random_from_rng(&mut OsRng);
    let alice_public = PublicKey::from(&alice_secret);

    let bob_priv_bytes = bob_secret.to_bytes();
    let bob_pub_bytes_32 = bob_public.to_bytes();
    let mut bob_pub_bytes = [0u8; 33];
    bob_pub_bytes[0] = 0x05;
    bob_pub_bytes[1..].copy_from_slice(&bob_pub_bytes_32);
    let _alice_pub_bytes = alice_public.to_bytes();

    unsafe {
        // Init Sender (Alice)
        let sender_state = ratchet_init_sender_ffi(&sk, &bob_pub_bytes);
        assert!(!sender_state.is_null());

        // Init Receiver (Bob)
        let receiver_state = ratchet_init_receiver_ffi(&sk, &bob_priv_bytes, &bob_pub_bytes);
        assert!(!receiver_state.is_null());

        // Encrypt (Alice -> Bob)
        let msg = b"Hello FFI";
        let ad = b"AD";
        let mut enc_result = RatchetEncryptResult {
            header: ptr::null_mut(),
            header_len: 0,
            ciphertext: ptr::null_mut(),
            ciphertext_len: 0,
            status: -1,
        };

        let status = ratchet_encrypt_ffi(
            sender_state,
            msg.as_ptr(),
            msg.len(),
            ad.as_ptr(),
            ad.len(),
            &mut enc_result,
        );
        assert_eq!(status, 0);
        assert_eq!(enc_result.status, 0);
        assert!(!enc_result.header.is_null());
        assert!(!enc_result.ciphertext.is_null());

        // Decrypt (Bob <- Alice)
        let mut dec_result = RatchetDecryptResult {
            plaintext: ptr::null_mut(),
            plaintext_len: 0,
            status: -1,
        };

        let status = ratchet_decrypt_ffi(
            receiver_state,
            enc_result.header,
            enc_result.header_len,
            enc_result.ciphertext,
            enc_result.ciphertext_len,
            ad.as_ptr(),
            ad.len(),
            &mut dec_result,
        );
        assert_eq!(status, 0);
        assert_eq!(dec_result.status, 0);

        let plaintext_slice = slice::from_raw_parts(dec_result.plaintext, dec_result.plaintext_len);
        assert_eq!(plaintext_slice, msg);

        // Cleanup Buffers
        ratchet_free_result_buffers(
            enc_result.header,
            enc_result.header_len,
            enc_result.ciphertext,
            enc_result.ciphertext_len,
        );
        ratchet_free_byte_buffer(dec_result.plaintext, dec_result.plaintext_len);

        // Cleanup States
        ratchet_free_ffi(sender_state);
        ratchet_free_ffi(receiver_state);
    }
}
