//! # VXEdDSA Signature Scheme
//!
//! This module implements the VXEdDSA (Verifiable XEdDSA) signature scheme.
//! It extends XEdDSA (which allows signing with X25519 DH keys) to include
//! a Verifiable Random Function (VRF) output.
//!
//! ## Specification
//! See [XEdDSA and VXEdDSA Signature Schemes](https://signal.org/docs/specifications/xeddsa/).

#![allow(non_snake_case)]
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::utils::calculate_key_pair;

// ============================================================================
// Types
// ============================================================================

/// Represents a key pair containing a 32-byte secret key and a 32-byte public key.
///
/// Used for both X25519 DH and VXEdDSA signing (via XEdDSA).
#[repr(C)]
pub struct KeyPair {
    /// The 32-byte secret key.
    pub secret: [u8; 32],
    /// The 33-byte public key.
    pub public: [u8; 33],
}

/// Represents the output of a VXEdDSA signature operation.
#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct VXEdDSAOutput {
    /// The 96-byte signature, consisting of `V || h || s`.
    pub signature: [u8; 96],
    /// The 32-byte VRF output `v`, which serves as a proof of randomness.
    pub vrf: [u8; 32],
}

/// Error type for VXEdDSA operations.
#[derive(Debug, PartialEq)]
pub enum VXEdDSAError {
    /// The provided scalar was invalid (e.g. zero or non-canonical).
    InvalidScalar,
}

// ============================================================================
// Native Rust API (used internally and by FFI wrappers)
// ============================================================================

/// Generates a random Curve25519 key pair.
///
/// Use this function to create a new identity. It uses a cryptographically secure
/// random number generator to create the secret key.
pub fn gen_keypair() -> KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public_raw = PublicKey::from(&secret);
    let public_bytes = crate::utils::encode_public_key(public_raw.as_bytes());
    KeyPair {
        secret: secret.to_bytes(),
        public: public_bytes,
    }
}

/// Generates a random 32-byte secret key.
pub fn gen_secret() -> [u8; 32] {
    let secret = StaticSecret::random_from_rng(OsRng);
    secret.to_bytes()
}

/// Derives a public key from a given 32-byte secret key.
pub fn gen_pubkey(k: &[u8; 32]) -> [u8; 33] {
    let secret = StaticSecret::from(*k);
    let raw = PublicKey::from(&secret);
    crate::utils::encode_public_key(raw.as_bytes())
}

/// Computes a VXEdDSA signature and generates the associated VRF output.
///
/// This function implements the signing logic specified in the VXEdDSA protocol (Signal).
/// It produces a deterministic signature and a proof of randomness (v).
///
/// See [XEdDSA Spec](https://signal.org/docs/specifications/xeddsa/#vxeddsa-signing).
///
/// # Arguments
///
/// * `k` - The 32-byte private key seed.
/// * `message` - The message bytes to sign.
///
/// # Returns
///
/// * `Ok(VXEdDSAOutput)` on success.
/// * `Err(VXEdDSAError)` on error (e.g. invalid scalar).
pub fn vxeddsa_sign(k: &[u8; 32], message: &[u8]) -> Result<VXEdDSAOutput, VXEdDSAError> {
    use crate::hashes::{SignalHash2, hash_i};
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use rand_core::RngCore;
    use subtle::ConstantTimeEq;
    use zeroize::Zeroize;

    // Generate random nonce internally for security
    let mut Z = [0u8; 64];
    OsRng.fill_bytes(&mut Z);

    let (a, A) = calculate_key_pair(*k);

    let a_bytes = A.compress().to_bytes();
    let mut point_msg = Vec::with_capacity(a_bytes.iter().len() + message.len());
    point_msg.extend_from_slice(&a_bytes);
    point_msg.extend_from_slice(message);

    #[allow(deprecated)]
    let Bv = EdwardsPoint::nonspec_map_to_curve::<SignalHash2>(&point_msg).mul_by_cofactor();

    let V = Bv * a;
    let V_bytes = V.compress().to_bytes();

    let mut r_msg = Vec::new();
    r_msg.extend_from_slice(a.as_bytes());
    r_msg.extend_from_slice(&V_bytes);
    r_msg.extend_from_slice(&Z);

    let r_hash = hash_i(3, &r_msg);

    Z.zeroize();
    r_msg.zeroize();

    let r = Scalar::from_bytes_mod_order_wide(&r_hash);

    if r.ct_eq(&Scalar::ZERO).into() {
        return Err(VXEdDSAError::InvalidScalar);
    }

    let R_point = ED25519_BASEPOINT_POINT * r;
    let R_bytes = R_point.compress().to_bytes();

    let Rv_point = Bv * r;
    let Rv_bytes = Rv_point.compress().to_bytes();

    let mut h_msg = Vec::new();
    h_msg.extend_from_slice(&a_bytes);
    h_msg.extend_from_slice(&V_bytes);
    h_msg.extend_from_slice(&R_bytes);
    h_msg.extend_from_slice(&Rv_bytes);
    h_msg.extend_from_slice(message);

    let h_hash = hash_i(4, &h_msg);
    let h = Scalar::from_bytes_mod_order_wide(&h_hash);

    let s = r + (h * a);

    let cV_point = V.mul_by_cofactor();
    let cV_bytes = cV_point.compress().to_bytes();

    let v_hash_full = hash_i(5, &cV_bytes);
    let mut v = [0u8; 32];
    v.copy_from_slice(&v_hash_full[0..32]);

    let mut signature = [0u8; 96];
    signature[0..32].copy_from_slice(&V_bytes);
    signature[32..64].copy_from_slice(&h.to_bytes());
    signature[64..96].copy_from_slice(&s.to_bytes());

    Ok(VXEdDSAOutput { signature, vrf: v })
}

/// Verifies a VXEdDSA signature.
///
/// See [XEdDSA Spec](https://signal.org/docs/specifications/xeddsa/#vxeddsa-verification).
///
/// # Arguments
///
/// * `public_key` - The 32-byte public key (Montgomery u-coordinate).
/// * `message` - The message bytes.
/// * `signature` - The 96-byte signature.
///
/// # Returns
///
/// * `Some(vrf)` if signature is valid, containing the 32-byte VRF output.
/// * `None` if signature is invalid.
pub fn vxeddsa_verify(
    public_key: &[u8; 33],
    message: &[u8],
    signature: &[u8; 96],
) -> Option<[u8; 32]> {
    use crate::hashes::{SignalHash2, hash_i};
    use crate::utils::convert_mont;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::traits::IsIdentity;

    let V_bytes = &signature[0..32];
    let h_bytes = &signature[32..64];
    let s_bytes = &signature[64..96];

    let h = Option::<Scalar>::from(Scalar::from_canonical_bytes(h_bytes.try_into().ok()?))?;

    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes.try_into().ok()?))?;

    let public_key_decoded = crate::utils::decode_public_key(public_key).ok()?;
    let A = convert_mont(public_key_decoded);
    let A_bytes = A.compress().to_bytes();

    let V_arr: [u8; 32] = V_bytes.try_into().ok()?;
    let V = CompressedEdwardsY(V_arr).decompress()?;

    let mut point_msg = Vec::with_capacity(A_bytes.len() + message.len());
    point_msg.extend_from_slice(&A_bytes);
    point_msg.extend_from_slice(message);

    #[allow(deprecated)]
    let Bv = EdwardsPoint::nonspec_map_to_curve::<SignalHash2>(&point_msg).mul_by_cofactor();

    let cA = A.mul_by_cofactor();
    let cV = V.mul_by_cofactor();
    if cA.is_identity() || cV.is_identity() || Bv.is_identity() {
        return None;
    }

    let R = (ED25519_BASEPOINT_POINT * s) - (A * h);
    let R_bytes = R.compress().to_bytes();

    let Rv = (Bv * s) - (V * h);
    let Rv_bytes = Rv.compress().to_bytes();

    let mut h_msg = Vec::new();
    h_msg.extend_from_slice(&A_bytes);
    h_msg.extend_from_slice(V_bytes);
    h_msg.extend_from_slice(&R_bytes);
    h_msg.extend_from_slice(&Rv_bytes);
    h_msg.extend_from_slice(message);

    let hcheck_hash = hash_i(4, &h_msg);
    let hcheck = Scalar::from_bytes_mod_order_wide(&hcheck_hash);

    if h != hcheck {
        return None;
    }

    let v_hash_full = hash_i(5, &cV.compress().to_bytes());
    let mut v = [0u8; 32];
    v.copy_from_slice(&v_hash_full[0..32]);

    Some(v)
}
