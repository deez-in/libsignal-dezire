//! # X3DH Key Agreement Protocol
//!
//! This module implements the "Extended Triple Diffie-Hellman" (X3DH) key agreement protocol.
//! X3DH establishes a shared secret key between two parties who mutually authenticate each other
//! based on public keys.
//!
//! ## Specification
//! See [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/).

use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::utils::{DecodeError, decode_public_key, is_valid_public_key};
use crate::vxeddsa::{gen_pubkey, gen_secret, vxeddsa_verify};

// ============================================================================
// Types
// ============================================================================

/// Represents a 33-byte X25519 Public Key (Encoded with 0x05 prefix).
pub type X3DHPublicKey = [u8; 33];

/// Represents a 32-byte Private Key (scalar).
pub type X3DHPrivateKey = [u8; 32];

/// Represents a Signed Prekey (Public Part).
///
/// Published by Bob, signed by his Identity Key.
#[derive(Clone, Debug)]
pub struct SignedPreKey {
    pub id: u32,
    pub public_key: X3DHPublicKey,
    /// VXEdDSA signature (64 bytes signature + 32 bytes VRF).
    pub signature: [u8; 96],
}

impl SignedPreKey {
    pub fn new(id: u32, identity_secret: &[u8; 32]) -> Result<Self, X3DHError> {
        use crate::vxeddsa::{gen_keypair, vxeddsa_sign};

        let spk_keypair = gen_keypair();
        let sig_output = vxeddsa_sign(identity_secret, &spk_keypair.public)
            .map_err(|_| X3DHError::InvalidSignature)?;

        Ok(SignedPreKey {
            id,
            public_key: spk_keypair.public,
            signature: sig_output.signature,
        })
    }
}

/// Represents a One-Time Prekey (Public Part).
#[derive(Clone, Debug)]
pub struct OneTimePreKey {
    pub id: u32,
    pub public_key: X3DHPublicKey,
}

/// Represents a PreKey Bundle that Bob publishes to the server.
///
/// Alice fetches this bundle to establish a session with Bob.
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    pub identity_key: X3DHPublicKey,
    pub signed_prekey: SignedPreKey,
    pub one_time_prekey: Option<OneTimePreKey>,
}

impl PreKeyBundle {
    pub fn new(
        identity_public: X3DHPublicKey,
        identity_secret: &X3DHPrivateKey,
        spk_id: u32,
        one_time_prekey: Option<OneTimePreKey>,
    ) -> Result<Self, X3DHError> {
        let signed_prekey = SignedPreKey::new(spk_id, identity_secret)?;
        Ok(PreKeyBundle {
            identity_key: identity_public,
            signed_prekey,
            one_time_prekey,
        })
    }
}

/// Error types for X3DH operations.
#[derive(Debug, Clone, PartialEq)]
pub enum X3DHError {
    InvalidSignature,
    InvalidKey,
    MissingOneTimeKey,
    DecodeFailed,
}

/// Result of a successful X3DH initiator operation.
#[derive(Clone, Debug, PartialEq)]
pub struct X3DHInitResult {
    /// The 32-byte shared secret key.
    pub shared_secret: [u8; 32],
    /// Alice's ephemeral public key (to be sent to Bob, encoded).
    pub ephemeral_public: [u8; 33],
}

// ============================================================================
// Core Cryptographic Functions
// ============================================================================

/// KDF as defined in X3DH: HKDF using SHA-512.
/// Inputs: F || KM. F = 32 bytes of 0xFF (for X25519).
pub(crate) fn kdf(km: &[u8]) -> [u8; 32] {
    let mut input_key_material = Vec::with_capacity(32 + km.len());
    input_key_material.extend_from_slice(&[0xFF; 32]);
    input_key_material.extend_from_slice(km);

    // HKDF-SHA512 with 64-byte zero salt
    let salt = [0u8; 64];
    let info = b"X3DH";

    let mut okm = [0u8; 32];
    hkdf::Hkdf::<Sha512>::new(Some(&salt), &input_key_material)
        .expand(info, &mut okm)
        .expect("HKDF expansion failed");
    okm
}

/// Perform Diffie-Hellman: DH(priv, pub)
fn dh(
    private: &X3DHPrivateKey,
    public_key_encoded: &X3DHPublicKey,
) -> Result<[u8; 32], DecodeError> {
    let secret = StaticSecret::from(*private);
    let public_bytes = decode_public_key(public_key_encoded)?;
    let public = PublicKey::from(public_bytes);
    Ok(*secret.diffie_hellman(&public).as_bytes())
}

/// Generate an ephemeral keypair for X3DH.
pub(crate) fn generate_ephemeral_keypair() -> (X3DHPrivateKey, X3DHPublicKey) {
    let private = gen_secret();
    let public = gen_pubkey(&private);
    (private, public)
}

// ============================================================================
// Native Rust API (Memory-Safe, No Raw Pointers)
// ============================================================================

/// Alice (Initiator) performs the X3DH key agreement.
///
/// Implements the logic for Alice to calculate the shared secret key using Bob's prekey bundle.
///
/// See [X3DH Spec Section 3.3](https://signal.org/docs/specifications/x3dh/#sending-the-initial-message).
///
/// # Arguments
/// * `identity_private` - Alice's identity private key.
/// * `bundle` - Bob's prekey bundle.
///
/// # Returns
/// * `Ok(X3DHInitResult)` - Shared secret and ephemeral public key.
/// * `Err(X3DHError)` - If signature verification or key validation fails.
pub fn x3dh_initiator(
    identity_private: &X3DHPrivateKey,
    bundle: &PreKeyBundle,
) -> Result<X3DHInitResult, X3DHError> {
    // 0. Verify Key Validity
    if !is_valid_public_key(&bundle.identity_key)
        || !is_valid_public_key(&bundle.signed_prekey.public_key)
    {
        return Err(X3DHError::InvalidKey);
    }

    if let Some(ref opk) = bundle.one_time_prekey {
        if !is_valid_public_key(&opk.public_key) {
            return Err(X3DHError::InvalidKey);
        }
    }

    // 1. Verify Signed PreKey Signature: Sig(IKB, Encode(SPKB))
    // SPK is already encoded in the bundle
    let encoded_spk = bundle.signed_prekey.public_key;

    // Use native vxeddsa_verify
    if vxeddsa_verify(
        &bundle.identity_key,
        &encoded_spk,
        &bundle.signed_prekey.signature,
    )
    .is_none()
    {
        return Err(X3DHError::InvalidSignature);
    }

    // 2. Generate Ephemeral Key EKA
    let (mut ephemeral_private, ephemeral_public) = generate_ephemeral_keypair();

    // 3. Calculate DH outputs
    let mut dh1 = dh(identity_private, &bundle.signed_prekey.public_key)
        .map_err(|_| X3DHError::DecodeFailed)?; // DH(IKA, SPKB)
    let mut dh2 =
        dh(&ephemeral_private, &bundle.identity_key).map_err(|_| X3DHError::DecodeFailed)?; // DH(EKA, IKB)
    let mut dh3 = dh(&ephemeral_private, &bundle.signed_prekey.public_key)
        .map_err(|_| X3DHError::DecodeFailed)?; // DH(EKA, SPKB)

    let mut chained_key_material = Vec::with_capacity(32 * 4);
    chained_key_material.extend_from_slice(&dh1);
    chained_key_material.extend_from_slice(&dh2);
    chained_key_material.extend_from_slice(&dh3);

    // DH4 = DH(EKA, OPKB) if present
    let mut dh4_opt: Option<[u8; 32]> = None;
    if let Some(ref opk) = bundle.one_time_prekey {
        let dh4 = dh(&ephemeral_private, &opk.public_key).map_err(|_| X3DHError::DecodeFailed)?;
        chained_key_material.extend_from_slice(&dh4);
        dh4_opt = Some(dh4);
    }

    // 4. KDF(DH1 || DH2 || DH3 [|| DH4])
    let shared_secret = kdf(&chained_key_material);

    ephemeral_private.zeroize();
    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();
    if let Some(ref mut dh4) = dh4_opt {
        dh4.zeroize();
    }
    chained_key_material.zeroize();

    Ok(X3DHInitResult {
        shared_secret,
        ephemeral_public,
    })
}

/// Bob (Responder) performs the X3DH key agreement.
///
/// Calculates the shared secret using Alice's public keys and Bob's private keys.
///
/// See [X3DH Spec Section 3.4](https://signal.org/docs/specifications/x3dh/#receiving-the-initial-message).
///
/// # Arguments
/// * `identity_private` - Bob's identity private key.
/// * `signed_prekey_private` - Bob's signed prekey private key.
/// * `one_time_prekey_private` - Bob's one-time prekey private key (optional).
/// * `alice_identity_public` - Alice's identity public key.
/// * `alice_ephemeral_public` - Alice's ephemeral public key.
///
/// # Returns
/// * `Ok([u8; 32])` - The shared secret.
/// * `Err(X3DHError)` - If key validation fails.
pub fn x3dh_responder(
    identity_private: &X3DHPrivateKey,
    signed_prekey_private: &X3DHPrivateKey,
    one_time_prekey_private: Option<&X3DHPrivateKey>,
    alice_identity_public: &X3DHPublicKey,
    alice_ephemeral_public: &X3DHPublicKey,
) -> Result<[u8; 32], X3DHError> {
    // 0. Verify Key Validity
    if !is_valid_public_key(alice_identity_public) || !is_valid_public_key(alice_ephemeral_public) {
        return Err(X3DHError::InvalidKey);
    }

    // 1. Calculate DHs (role reversal from initiator)
    let mut dh1 =
        dh(signed_prekey_private, alice_identity_public).map_err(|_| X3DHError::DecodeFailed)?; // DH(SPKB, IKA)
    let mut dh2 =
        dh(identity_private, alice_ephemeral_public).map_err(|_| X3DHError::DecodeFailed)?; // DH(IKB, EKA)
    let mut dh3 =
        dh(signed_prekey_private, alice_ephemeral_public).map_err(|_| X3DHError::DecodeFailed)?; // DH(SPKB, EKA)

    let mut chained_key_material = Vec::with_capacity(32 * 4);
    chained_key_material.extend_from_slice(&dh1);
    chained_key_material.extend_from_slice(&dh2);
    chained_key_material.extend_from_slice(&dh3);

    // DH4 = DH(OPKB, EKA) if OPK used
    let mut dh4_opt: Option<[u8; 32]> = None;
    if let Some(opk_private) = one_time_prekey_private {
        let dh4 = dh(opk_private, alice_ephemeral_public).map_err(|_| X3DHError::DecodeFailed)?;
        chained_key_material.extend_from_slice(&dh4);
        dh4_opt = Some(dh4);
    }

    // 2. KDF
    let shared_secret = kdf(&chained_key_material);

    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();
    if let Some(ref mut dh4) = dh4_opt {
        dh4.zeroize();
    }
    chained_key_material.zeroize();

    Ok(shared_secret)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vxeddsa::{gen_keypair, vxeddsa_sign};

    #[test]
    fn test_x3dh_native_api() {
        // Setup Bob's keys
        let bob_identity = gen_keypair();
        let bob_identity_public = bob_identity.public;
        let bob_spk = gen_keypair();
        let bob_spk_public = bob_spk.public;

        // Sign the SPK using native API
        // SPK is already encoded
        let sig_output =
            vxeddsa_sign(&bob_identity.secret, &bob_spk_public).expect("Signing failed");

        let bundle = PreKeyBundle {
            identity_key: bob_identity_public,
            signed_prekey: SignedPreKey {
                id: 1,
                public_key: bob_spk_public,
                signature: sig_output.signature,
            },
            one_time_prekey: None,
        };

        // Alice initiates
        let alice_identity = gen_keypair();
        let alice_identity_public = alice_identity.public;
        let alice_result =
            x3dh_initiator(&alice_identity.secret, &bundle).expect("Alice init failed");

        // Bob responds
        let bob_result = x3dh_responder(
            &bob_identity.secret,
            &bob_spk.secret,
            None,
            &alice_identity_public,
            &alice_result.ephemeral_public,
        )
        .expect("Bob respond failed");

        // Shared secrets must match
        assert_eq!(alice_result.shared_secret, bob_result);
    }

    #[test]
    fn test_x3dh_native_with_opk() {
        // Setup Bob's keys
        let bob_identity = gen_keypair();
        let bob_identity_public = bob_identity.public;
        let bob_spk = gen_keypair();
        let bob_spk_public = bob_spk.public;
        let bob_opk = gen_keypair();
        let bob_opk_public = bob_opk.public;

        // Sign the SPK
        let sig_output =
            vxeddsa_sign(&bob_identity.secret, &bob_spk_public).expect("Signing failed");

        let bundle = PreKeyBundle {
            identity_key: bob_identity_public,
            signed_prekey: SignedPreKey {
                id: 1,
                public_key: bob_spk_public,
                signature: sig_output.signature,
            },
            one_time_prekey: Some(OneTimePreKey {
                id: 1,
                public_key: bob_opk_public,
            }),
        };

        // Alice initiates
        let alice_identity = gen_keypair();
        let alice_identity_public = alice_identity.public;
        let alice_result =
            x3dh_initiator(&alice_identity.secret, &bundle).expect("Alice init failed");

        // Bob responds with OPK
        let bob_result = x3dh_responder(
            &bob_identity.secret,
            &bob_spk.secret,
            Some(&bob_opk.secret),
            &alice_identity_public,
            &alice_result.ephemeral_public,
        )
        .expect("Bob respond failed");

        // Shared secrets must match
        assert_eq!(alice_result.shared_secret, bob_result);
    }
}
