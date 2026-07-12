//! # Double Ratchet Algorithm
//!
//! This module implements the Double Ratchet key management algorithm, which provides
//! cryptographic guarantees for instant messaging:
//! * **Confidentiality**: Messages are encrypted.
//! * **Authenticity**: Messages are authenticated.
//! * **Forward Secrecy**: Compromise of current keys does not reveal past keys.
//! * **break-in Recovery**: Post-compromise security (future secrecy).
//!
//! ## Specification
//! This implementation follows the [Signal Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/).
use aes::Aes256;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor, ser::SerializeSeq};
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use std::time::SystemTime;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Error types for Double Ratchet operations.
#[derive(Debug, PartialEq)]
pub enum RatchetError {
    /// The provided key was invalid or missing.
    InvalidKey,
    /// Decryption of the message or header failed (authentication failure).
    DecryptionFailed,
    /// The message key was too old and has been discarded (max skip limit reached).
    OldMessageKeysLimitReached,
    /// The message has already been received and processed.
    DuplicateMessage,
    /// The message header was invalid or malformed.
    InvalidHeader,
    /// Failed to decrypt the message header.
    HeaderDecryptionFailed,
    /// A counter (message number) overflowed its limit.
    CounterOverflow,
    /// The associated data was too large to process.
    ADTooLarge,
    /// The session state is invalid (e.g. missing required keys).
    InvalidState,
    /// Too many messages received in this session (replay protection limit).
    TooManyMessages,
}

// ----------------------------------------------------------------------------
// Constants and Configuration
// ----------------------------------------------------------------------------

const MAX_SKIP: u32 = 1000;
const MAX_SKIPPED_KEYS: usize = 2000;
const MAX_AD_SIZE: usize = 64 * 1024; // 64KB
const MAX_RECEIVED_TRACKING: usize = 10000;
const HKDF_INFO_ROOT: &[u8] = b"Signal-DoubleRatchet-Root";

// ----------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------

pub type DhPublicKey = PublicKey;
pub type DhPrivateKey = StaticSecret;
pub type KeyPair = (DhPrivateKey, DhPublicKey);

/// Type alias for the skipped message keys map.
type SkippedKeyMap = HashMap<([u8; 32], u32), SkippedKey>;

/// Type alias for the KDF root key output triple (root_key, chain_key, next_header_key).
type KdfRkOutput = ([u8; 32], [u8; 32], [u8; 32]);

/// Skipped message key with timestamp for LRU eviction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkippedKey {
    pub mk: [u8; 32],
    pub timestamp: SystemTime,
}

/// The Header sent with every message (unencrypted form).
///
/// See [Double Ratchet Spec Section 3.5](https://signal.org/docs/specifications/doubleratchet/#header-encryption).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RatchetHeader {
    /// The sender's current Diffie-Hellman public key.
    pub dh_pub: DhPublicKey,
    /// The number of the previous sending chain.
    pub pn: u32,
    /// The message number in the current chain.
    pub n: u32,
}

impl RatchetHeader {
    /// Serializes the header to a byte vector.
    /// Format: [dh_pub (32)] || [pn (4, be)] || [n (4, be)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 4 + 4);
        bytes.extend_from_slice(self.dh_pub.as_bytes());
        bytes.extend_from_slice(&self.pn.to_be_bytes());
        bytes.extend_from_slice(&self.n.to_be_bytes());
        bytes
    }

    /// Deserializes the header from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
        if bytes.len() != 32 + 4 + 4 {
            return Err(RatchetError::InvalidHeader);
        }

        let mut dh_bytes = [0u8; 32];
        dh_bytes.copy_from_slice(&bytes[0..32]);
        let dh_pub = PublicKey::from(dh_bytes);

        let mut pn_bytes = [0u8; 4];
        pn_bytes.copy_from_slice(&bytes[32..36]);
        let pn = u32::from_be_bytes(pn_bytes);

        let mut n_bytes = [0u8; 4];
        n_bytes.copy_from_slice(&bytes[36..40]);
        let n = u32::from_be_bytes(n_bytes);

        Ok(RatchetHeader { dh_pub, pn, n })
    }
}

// ----------------------------------------------------------------------------
// Core State Structure
// ----------------------------------------------------------------------------

/// The Double Ratchet Session State.
///
/// This structure holds all the state required for a Double Ratchet session, including
/// the Root Key (RK), Chain Keys (CKs), and Ratchet Diffie-Hellman keys.
///
/// See [Double Ratchet Spec Section 3.2](https://signal.org/docs/specifications/doubleratchet/#cryptographic-properties).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RatchetState {
    // Diffie-Hellman Ratchet
    #[zeroize(skip)]
    pub(crate) dh_pair: KeyPair,
    #[zeroize(skip)]
    pub(crate) dh_remote: Option<DhPublicKey>,

    // Root Chain
    pub(crate) rk: [u8; 32],

    // Symmetric-Key Ratchets
    pub(crate) ck_s: Option<[u8; 32]>,
    pub(crate) ck_r: Option<[u8; 32]>,

    // Header Encryption Keys
    pub(crate) hk_s: Option<[u8; 32]>, // Sending header key
    pub(crate) hk_r: Option<[u8; 32]>, // Receiving header key
    pub(crate) nhk_s: [u8; 32],        // Next sending header key
    pub(crate) nhk_r: [u8; 32],        // Next receiving header key

    // State
    #[zeroize(skip)]
    pub(crate) ns: u32, // Sending chain message number
    #[zeroize(skip)]
    pub(crate) nr: u32, // Receiving chain message number
    #[zeroize(skip)]
    pub(crate) pn: u32, // Previous sending chain length

    // Skipped Message Keys: (HeaderKey, message_number) -> SkippedKey
    #[zeroize(skip)]
    #[serde(
        serialize_with = "serialize_skipped_map",
        deserialize_with = "deserialize_skipped_map"
    )]
    pub(crate) mkskipped: SkippedKeyMap,

    // Nonce counter for header encryption (stateful, per-session)
    #[zeroize(skip)]
    pub(crate) header_nonce_counter: u64,

    // Party identifier for nonce uniqueness (true = sender/initiator)
    #[zeroize(skip)]
    pub(crate) is_sender: bool,

    // Received message tracking for replay attack prevention
    #[zeroize(skip)]
    pub(crate) received_messages: std::collections::HashSet<([u8; 32], u32)>,
}

// ----------------------------------------------------------------------------
// State Initialization Functions
// ----------------------------------------------------------------------------

/// Initialize sender's session state with header encryption.
///
/// Header keys are derived internally from the shared secret.
pub fn init_sender_state(
    sk: [u8; 32],
    receiver_dh_public_key: DhPublicKey,
) -> Result<RatchetState, RatchetError> {
    let rng = rand_core::OsRng;
    let dh_s = StaticSecret::random_from_rng(rng);
    let dh_s_pub = PublicKey::from(&dh_s);

    let dh_out = dh_s.diffie_hellman(&receiver_dh_public_key);
    let (rk, ck_s, nhk_s) = kdf_rk_he(&sk, dh_out.as_bytes())?;

    // Derive header keys from shared secret
    let (initiator_hk, responder_hk) = derive_header_keys(&sk);

    Ok(RatchetState {
        dh_pair: (dh_s, dh_s_pub),
        dh_remote: Some(receiver_dh_public_key),
        rk,
        ck_s: Some(ck_s),
        ck_r: None,
        hk_s: Some(initiator_hk), // Sender uses initiator key for sending
        hk_r: None,
        nhk_s,
        nhk_r: responder_hk, // Will receive with responder key
        ns: 0,
        nr: 0,
        pn: 0,
        mkskipped: HashMap::new(),
        header_nonce_counter: 0,
        is_sender: true,
        received_messages: std::collections::HashSet::new(),
    })
}

/// Initialize receiver's session state with header encryption.
///
/// Header keys are derived internally from the shared secret.
pub fn init_receiver_state(sk: [u8; 32], receiver_key_pair: KeyPair) -> RatchetState {
    // Derive header keys from shared secret
    let (initiator_hk, responder_hk) = derive_header_keys(&sk);

    RatchetState {
        dh_pair: receiver_key_pair,
        dh_remote: None,
        rk: sk,
        ck_s: None,
        ck_r: None,
        hk_s: None,
        hk_r: None,
        nhk_s: responder_hk, // Receiver will send with responder key
        nhk_r: initiator_hk, // Receiver receives with initiator key
        ns: 0,
        nr: 0,
        pn: 0,
        mkskipped: HashMap::new(),
        header_nonce_counter: 0,
        is_sender: false,
        received_messages: std::collections::HashSet::new(),
    }
}

// ----------------------------------------------------------------------------
// Core Encryption/Decryption Functions (Pure, State-returning)
// ----------------------------------------------------------------------------

/// Encrypt a message with header encryption.
///
/// Returns (new_state, encrypted_header, ciphertext).
/// Encrypt a message with header encryption.
///
/// Returns (encrypted_header, ciphertext).
/// Encrypt a message with header encryption.
///
/// Returns (encrypted_header, ciphertext).
pub fn encrypt(
    state: &mut RatchetState,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), RatchetError> {
    // Validate state before encryption.
    validate_encryption_state(state)?;

    if associated_data.len() > MAX_AD_SIZE {
        return Err(RatchetError::ADTooLarge);
    }

    // Derive message key
    let (ck_s, mut mk) = kdf_ck(&state.ck_s.expect("Sender chain key missing"));
    state.ck_s = Some(ck_s);

    // Create header
    let header = RatchetHeader {
        dh_pub: state.dh_pair.1,
        pn: state.pn,
        n: state.ns,
    };

    // Check for counter overflow.
    state.ns = state
        .ns
        .checked_add(1)
        .ok_or(RatchetError::CounterOverflow)?;

    // Encrypt header
    let (new_nonce_counter, enc_header) = encrypt_header(state, &header)?;
    state.header_nonce_counter = new_nonce_counter;

    let ad = concat_ad(associated_data, &enc_header);
    let ciphertext = encrypt_aead(&mk, plaintext, &ad)?;

    mk.zeroize();

    Ok((enc_header, ciphertext))
}

/// Decrypt a message with header encryption.
///
/// Returns (new_state, plaintext).
/// Decrypt a message with header encryption.
///
/// Returns plaintext.
/// Decrypt a message with header encryption.
///
/// Returns plaintext.
pub fn decrypt(
    state: &mut RatchetState,
    enc_header: &[u8],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, RatchetError> {
    if associated_data.len() > MAX_AD_SIZE {
        return Err(RatchetError::ADTooLarge);
    }

    // Prepare AD
    let ad = concat_ad(associated_data, enc_header);

    // 1. Try skipped message keys first
    let mkskipped = std::mem::take(&mut state.mkskipped);
    let (mkskipped_ret, result) = try_skipped_message_keys(mkskipped, enc_header, ciphertext, &ad)?;
    state.mkskipped = mkskipped_ret;

    if let Some(plaintext) = result {
        return Ok(plaintext);
    }

    // 2. Decrypt header
    let (header, dh_ratchet) = decrypt_header(state, enc_header)?;

    // 3. Check for duplicate message.
    let msg_id = (header.dh_pub.to_bytes(), header.n);
    if state.received_messages.contains(&msg_id) {
        return Err(RatchetError::DuplicateMessage);
    }

    // 4. Compute the message key WITHOUT modifying state
    let mut mk = compute_message_key(state, &header, dh_ratchet)?;

    // 5. Attempt decryption - this is the authentication step
    let plaintext = decrypt_aead(&mk, ciphertext, &ad)?;

    mk.zeroize();

    // 6. SUCCESS - Now commit state changes atomically
    commit_state_changes(state, &header, dh_ratchet)?;

    // 7. Track this message to prevent replay.
    if state.received_messages.len() >= MAX_RECEIVED_TRACKING {
        return Err(RatchetError::TooManyMessages);
    }
    state.received_messages.insert(msg_id);

    Ok(plaintext)
}

// ----------------------------------------------------------------------------
// Internal Helper Functions (Pure)
// ----------------------------------------------------------------------------

/// Try to decrypt with skipped message keys
/// Returns (updated_mkskipped, Some(plaintext)) if successful
/// Returns (original_mkskipped, None) if not found
fn try_skipped_message_keys(
    mut mkskipped: SkippedKeyMap,
    enc_header: &[u8],
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<(SkippedKeyMap, Option<Vec<u8>>), RatchetError> {
    // Try to decrypt header with each skipped header key
    // We need to collect keys to iterate to avoid borrow checker issues if we modify map
    // But we only remove if we find it and return immediately.
    // However, iterating and modifying is tricky.
    // Best strategy: Iterate keys/values. If match found, remove and return.

    let candidates: Vec<_> = mkskipped.keys().cloned().collect();

    for (hk, n) in candidates {
        if let Some(skipped_key) = mkskipped.get(&(hk, n))
            && let Ok(header) = decrypt_header_with_key(&hk, enc_header)
            && bool::from(n.ct_eq(&header.n))
        {
            // Try to decrypt message
            match decrypt_aead(&skipped_key.mk, ciphertext, ad) {
                Ok(plaintext) => {
                    // Success! Remove via key and return
                    mkskipped.remove(&(hk, n));
                    return Ok((mkskipped, Some(plaintext)));
                }
                Err(_) => {
                    // Failed authentication, continue trying other keys
                    continue;
                }
            }
        }
    }
    Ok((mkskipped, None))
}

/// Decrypt header and determine if DH ratchet is needed
fn decrypt_header(
    state: &RatchetState,
    enc_header: &[u8],
) -> Result<(RatchetHeader, bool), RatchetError> {
    // Try current receiving header key
    if let Some(hk_r) = state.hk_r
        && let Ok(header) = decrypt_header_with_key(&hk_r, enc_header)
    {
        return Ok((header, false)); // No DH ratchet needed
    }

    // Try next receiving header key (indicates DH ratchet)
    if let Ok(header) = decrypt_header_with_key(&state.nhk_r, enc_header) {
        return Ok((header, true)); // DH ratchet needed
    }

    Err(RatchetError::HeaderDecryptionFailed)
}

/// Compute the message key without modifying state
fn compute_message_key(
    state: &RatchetState,
    header: &RatchetHeader,
    dh_ratchet: bool,
) -> Result<[u8; 32], RatchetError> {
    let mut ck_r = state.ck_r;
    let mut nr = state.nr;

    if dh_ratchet {
        // Perform simulated DH ratchet
        let dh_out = state.dh_pair.0.diffie_hellman(&header.dh_pub);
        let mut dh_bytes = *dh_out.as_bytes();
        let (_, new_ck_r, _) = kdf_rk_he(&state.rk, &dh_bytes)?;
        dh_bytes.zeroize();
        ck_r = Some(new_ck_r);
        nr = 0;
    }

    // Check skip limit
    if nr + MAX_SKIP < header.n {
        return Err(RatchetError::OldMessageKeysLimitReached);
    }

    // Advance chain to message number
    let mut current_ck = ck_r.ok_or(RatchetError::InvalidKey)?;
    while nr < header.n {
        let mut old_ck = current_ck;
        let (next_ck, _) = kdf_ck(&current_ck);
        old_ck.zeroize();
        current_ck = next_ck;
        nr += 1;
    }

    // Derive message key
    let (_, mk) = kdf_ck(&current_ck);
    current_ck.zeroize();
    Ok(mk)
}

/// Commit state changes after successful decryption (ATOMIC)
/// Returns new state with all changes applied
/// Commit state changes after successful decryption (ATOMIC)
/// Returns new state with all changes applied
fn commit_state_changes(
    state: &mut RatchetState,
    header: &RatchetHeader,
    dh_ratchet: bool,
) -> Result<(), RatchetError> {
    if dh_ratchet {
        // Store skipped keys from previous receiving chain
        if let Some(ck_r) = state.ck_r
            && let Some(hk_r) = state.hk_r
        {
            state.mkskipped = skip_message_keys(
                std::mem::take(&mut state.mkskipped),
                ck_r,
                hk_r,
                state.nr,
                header.pn,
            )?;
        }

        // Perform DH ratchet
        state.pn = state.ns;
        state.ns = 0;
        state.nr = 0;
        state.hk_s = Some(state.nhk_s);
        state.hk_r = Some(state.nhk_r);
        state.dh_remote = Some(header.dh_pub);

        // First KDF: derive receiving chain
        let dh_out_recv = state.dh_pair.0.diffie_hellman(&header.dh_pub);
        let (new_rk, new_ck_r, new_nhk_r) = kdf_rk_he(&state.rk, dh_out_recv.as_bytes())?;
        state.rk = new_rk;
        state.ck_r = Some(new_ck_r);
        state.nhk_r = new_nhk_r;

        // Generate new DH key pair
        let rng = rand_core::OsRng;
        let new_dh_s = StaticSecret::random_from_rng(rng);
        let new_dh_s_pub = PublicKey::from(&new_dh_s);

        // Second KDF: derive sending chain
        let dh_out_send = new_dh_s.diffie_hellman(&header.dh_pub);
        let (new_rk_2, new_ck_s, new_nhk_s) = kdf_rk_he(&state.rk, dh_out_send.as_bytes())?;
        state.rk = new_rk_2;
        state.ck_s = Some(new_ck_s);
        state.nhk_s = new_nhk_s;
        state.dh_pair = (new_dh_s, new_dh_s_pub);

        // Clear received messages after DH ratchet.
        state.received_messages.clear();
    }

    // Store skipped keys in current receiving chain
    if let Some(ck_r) = state.ck_r
        && let Some(hk_r) = state.hk_r
    {
        state.mkskipped = skip_message_keys(
            std::mem::take(&mut state.mkskipped),
            ck_r,
            hk_r,
            state.nr,
            header.n,
        )?;
    }

    // Advance to current message
    let (new_ck_r, _) = kdf_ck(&state.ck_r.expect("Receiving chain key missing"));
    state.ck_r = Some(new_ck_r);

    // Add overflow protection.
    state.nr = state
        .nr
        .checked_add(1)
        .ok_or(RatchetError::CounterOverflow)?;

    Ok(())
}

/// Skip message keys in the current receiving chain
/// Returns updated mkskipped map
fn skip_message_keys(
    mut mkskipped: SkippedKeyMap,
    mut ck: [u8; 32],
    hk: [u8; 32],
    from: u32,
    to: u32,
) -> Result<SkippedKeyMap, RatchetError> {
    // Validate range.
    if to < from {
        return Err(RatchetError::InvalidHeader);
    }

    // Double-check skip limit (defense in depth)
    let skip_count = to.saturating_sub(from);
    if skip_count > MAX_SKIP {
        return Err(RatchetError::OldMessageKeysLimitReached);
    }

    let mut current = from;
    while current < to {
        // Enforce total size limit before adding.
        if mkskipped.len() >= MAX_SKIPPED_KEYS {
            mkskipped = evict_oldest_skipped_keys(mkskipped, MAX_SKIPPED_KEYS / 2);
        }

        let (next_ck, mk) = kdf_ck(&ck);
        mkskipped.insert(
            (hk, current),
            SkippedKey {
                mk,
                timestamp: SystemTime::now(),
            },
        );

        ck = next_ck;

        // Add overflow protection.
        current = current
            .checked_add(1)
            .ok_or(RatchetError::CounterOverflow)?;
    }
    Ok(mkskipped)
}

/// Validate encryption state.
fn validate_encryption_state(state: &RatchetState) -> Result<(), RatchetError> {
    if state.ck_s.is_none() {
        return Err(RatchetError::InvalidState);
    }
    if state.hk_s.is_none() {
        return Err(RatchetError::InvalidState);
    }
    if state.dh_remote.is_none() {
        return Err(RatchetError::InvalidState);
    }
    Ok(())
}

/// Evict oldest skipped keys to prevent memory exhaustion.
/// Returns updated mkskipped map
fn evict_oldest_skipped_keys(mut mkskipped: SkippedKeyMap, target_size: usize) -> SkippedKeyMap {
    let mut entries: Vec<_> = mkskipped.iter().map(|(k, v)| (*k, v.timestamp)).collect();

    // Sort by timestamp (oldest first)
    entries.sort_by_key(|(_, time)| *time);

    // Remove oldest entries
    let to_remove = entries.len().saturating_sub(target_size);
    for (key, _) in entries.iter().take(to_remove) {
        mkskipped.remove(key);
    }

    mkskipped
}

// ----------------------------------------------------------------------------
// Cryptographic Helper Functions (Pure)
// ----------------------------------------------------------------------------

/// KDF_RK_HE: Derive root key, chain key, and next header key
fn kdf_rk_he(rk: &[u8; 32], dh_out: &[u8; 32]) -> Result<KdfRkOutput, RatchetError> {
    let hk = Hkdf::<Sha512>::new(Some(rk), dh_out);
    let mut okm = [0u8; 96];
    hk.expand(HKDF_INFO_ROOT, &mut okm)
        .map_err(|_| RatchetError::InvalidKey)?; // Should technically not fail if KDF is correct

    let mut new_rk = [0u8; 32];
    let mut new_ck = [0u8; 32];
    let mut new_nhk = [0u8; 32];
    new_rk.copy_from_slice(&okm[0..32]);
    new_ck.copy_from_slice(&okm[32..64]);
    new_nhk.copy_from_slice(&okm[64..96]);

    Ok((new_rk, new_ck, new_nhk))
}

/// Derive header encryption keys from shared secret using HKDF
/// Returns (initiator_header_key, responder_header_key)
/// Per Signal spec: Header keys are derived with proper context separation
fn derive_header_keys(sk: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Derive initiator header key
    let hk_initiator = Hkdf::<Sha256>::new(None, sk);
    let mut initiator_hk = [0u8; 32];
    hk_initiator
        .expand(b"Signal-Header-Initiator-v1", &mut initiator_hk)
        .expect("HKDF expand should not fail");

    // Derive responder header key
    let hk_responder = Hkdf::<Sha256>::new(None, sk);
    let mut responder_hk = [0u8; 32];
    hk_responder
        .expand(b"Signal-Header-Responder-v1", &mut responder_hk)
        .expect("HKDF expand should not fail");

    (initiator_hk, responder_hk)
}

/// KDF_CK: Derive next chain key and message key
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    type HmacSha256 = Hmac<Sha256>;

    // 1. Next Chain Key (0x01 per Signal spec)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("HMAC initialization failed");
    mac.update(&[0x01]);
    let mut next_ck_bytes = mac.finalize().into_bytes();

    // 2. Message Key (0x02 per Signal spec)
    let mut mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("HMAC initialization failed");
    mac.update(&[0x02]);
    let mut mk_bytes = mac.finalize().into_bytes();

    let mut next_ck = [0u8; 32];
    let mut mk = [0u8; 32];
    next_ck.copy_from_slice(&next_ck_bytes);
    mk.copy_from_slice(&mk_bytes);

    // Zeroize intermediates.
    next_ck_bytes.zeroize();
    mk_bytes.zeroize();

    (next_ck, mk)
}

/// Encrypt header with current sending header key
/// Returns (new_nonce_counter, encrypted_header)
fn encrypt_header(
    state: &RatchetState,
    header: &RatchetHeader,
) -> Result<(u64, Vec<u8>), RatchetError> {
    let hk = state.hk_s.ok_or(RatchetError::InvalidKey)?;
    let plaintext = header.to_bytes();

    // Use stateful counter as nonce with party identifier.
    let nonce_value = state.header_nonce_counter;
    // Check for overflow.
    let new_nonce_counter = nonce_value
        .checked_add(1)
        .ok_or(RatchetError::CounterOverflow)?;

    let mut nonce_bytes = [0u8; 12];
    // Include party identifier to prevent nonce reuse between sender and receiver
    nonce_bytes[0] = if state.is_sender { 0x00 } else { 0xFF };
    nonce_bytes[4..12].copy_from_slice(&nonce_value.to_be_bytes());

    let key = Key::<Aes256Gcm>::from_slice(&hk);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|_| RatchetError::HeaderDecryptionFailed)?; // Close enough error, or add new one

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok((new_nonce_counter, result))
}

/// Decrypt header with a specific header key
fn decrypt_header_with_key(
    hk: &[u8; 32],
    enc_header: &[u8],
) -> Result<RatchetHeader, RatchetError> {
    if enc_header.len() < 12 {
        return Err(RatchetError::HeaderDecryptionFailed);
    }

    let nonce_bytes = &enc_header[0..12];
    let ciphertext = &enc_header[12..];

    let key = Key::<Aes256Gcm>::from_slice(hk);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| RatchetError::HeaderDecryptionFailed)?;

    RatchetHeader::from_bytes(&plaintext)
}

/// Concatenate associated data with encrypted header per Signal spec
fn concat_ad(associated_data: &[u8], header: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(8 + associated_data.len() + header.len());
    ad.extend_from_slice(&(associated_data.len() as u64).to_be_bytes());
    ad.extend_from_slice(associated_data);
    ad.extend_from_slice(header);
    ad
}

/// Encrypt message with CBC+HMAC (per Signal spec section 7.2)
///
/// Uses HKDF to derive 80 bytes: 32-byte encryption key, 32-byte auth key, 16-byte IV
/// Then AES-256-CBC with PKCS#7, followed by HMAC-SHA256 authentication
fn encrypt_aead(mk: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RatchetError> {
    type HmacSha256 = Hmac<Sha256>;
    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    // Derive encryption key (32), auth key (32), and IV (16) from message key
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), mk);
    let mut okm = [0u8; 80];
    hk.expand(b"Signal-DoubleRatchet-Encrypt", &mut okm)
        .expect("HKDF expansion failed");

    let enc_key: [u8; 32] = okm[0..32].try_into().unwrap();
    let auth_key: [u8; 32] = okm[32..64].try_into().unwrap();
    let iv: [u8; 16] = okm[64..80].try_into().unwrap();

    // Encrypt with AES-256-CBC + PKCS#7 padding
    let cipher = Aes256CbcEnc::new((&enc_key).into(), (&iv).into());
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    // Calculate HMAC over (AD || ciphertext)
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&auth_key).expect("HMAC initialization failed");
    mac.update(ad);
    mac.update(&ciphertext);
    let tag = mac.finalize().into_bytes();

    // Return ciphertext || tag (32 bytes)
    let mut result = ciphertext;
    result.extend_from_slice(&tag);
    Ok(result)
}

/// Decrypt message with CBC+HMAC (per Signal spec section 7.2)
///
/// # Security
/// This function implements the "Authenticate-then-Decrypt" pattern.
/// It verifies the HMAC before attempting any decryption or unpadding to prevent
/// padding oracle attacks.
fn decrypt_aead(mk: &[u8; 32], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RatchetError> {
    type HmacSha256 = Hmac<Sha256>;
    type Aes256CbcDec = cbc::Decryptor<Aes256>;

    // Minimum size: 16 bytes (one AES block) + 32 bytes (HMAC tag)
    if ciphertext.len() < 48 {
        return Err(RatchetError::DecryptionFailed);
    }

    // Split ciphertext and tag
    let tag_start = ciphertext.len() - 32;
    let ct_bytes = &ciphertext[..tag_start];
    let received_tag = &ciphertext[tag_start..];

    // Derive encryption key (32), auth key (32), and IV (16) from message key
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), mk);
    let mut okm = [0u8; 80];
    hk.expand(b"Signal-DoubleRatchet-Encrypt", &mut okm)
        .expect("HKDF expansion failed");

    let enc_key: [u8; 32] = okm[0..32].try_into().unwrap();
    let auth_key: [u8; 32] = okm[32..64].try_into().unwrap();
    let iv: [u8; 16] = okm[64..80].try_into().unwrap();

    // Verify HMAC first (authenticate-then-decrypt)
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&auth_key).expect("HMAC initialization failed");
    mac.update(ad);
    mac.update(ct_bytes);
    let expected_tag = mac.finalize().into_bytes();

    // Constant-time tag comparison
    if !bool::from(expected_tag.ct_eq(received_tag)) {
        return Err(RatchetError::DecryptionFailed);
    }

    // Decrypt with AES-256-CBC + PKCS#7 unpadding
    let cipher = Aes256CbcDec::new((&enc_key).into(), (&iv).into());
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(ct_bytes)
        .map_err(|_| RatchetError::DecryptionFailed)
}

// ----------------------------------------------------------------------------
// Serialization Helpers
// ----------------------------------------------------------------------------

fn serialize_skipped_map<S>(map: &SkippedKeyMap, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(map.len()))?;
    for (k, v) in map {
        seq.serialize_element(&(k, v))?;
    }
    seq.end()
}

fn deserialize_skipped_map<'de, D>(deserializer: D) -> Result<SkippedKeyMap, D::Error>
where
    D: Deserializer<'de>,
{
    struct MapVisitor;

    impl<'de> Visitor<'de> for MapVisitor {
        type Value = SkippedKeyMap;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a sequence of skipped key entries")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut map = HashMap::new();
            while let Some((k, v)) = seq.next_element()? {
                map.insert(k, v);
            }
            Ok(map)
        }
    }

    deserializer.deserialize_seq(MapVisitor)
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_basic_flow() {
        let sk = [0x55u8; 32];

        let mut rng = rand_core::OsRng;
        let receiver_dh_private = StaticSecret::random_from_rng(&mut rng);
        let receiver_dh_public = PublicKey::from(&receiver_dh_private);

        let mut sender = init_sender_state(sk, receiver_dh_public).unwrap();
        let mut receiver = init_receiver_state(sk, (receiver_dh_private, receiver_dh_public));

        let msg1 = b"Hello Receiver!";
        let ad1 = b"Metadata";
        let (enc_header1, cipher1) = encrypt(&mut sender, msg1, ad1).expect("Sender encrypts msg1");

        let decrypted1 =
            decrypt(&mut receiver, &enc_header1, &cipher1, ad1).expect("Receiver decrypts msg1");
        assert_eq!(decrypted1, msg1);

        let msg2 = b"Hello Sender!";
        let (enc_header2, cipher2) =
            encrypt(&mut receiver, msg2, &[]).expect("Receiver encrypts msg2");

        let decrypted2 =
            decrypt(&mut sender, &enc_header2, &cipher2, &[]).expect("Sender decrypts msg2");
        assert_eq!(decrypted2, msg2);
    }

    #[test]
    fn test_out_of_order_messages() {
        let sk = [0x66u8; 32];

        let mut rng = rand_core::OsRng;
        let receiver_dh_private = StaticSecret::random_from_rng(&mut rng);
        let receiver_dh_public = PublicKey::from(&receiver_dh_private);

        let mut sender = init_sender_state(sk, receiver_dh_public).unwrap();
        let mut receiver = init_receiver_state(sk, (receiver_dh_private, receiver_dh_public));

        // Sender sends 3 messages
        let (h1, c1) = encrypt(&mut sender, b"Message 1", &[]).expect("encrypts 1");
        let (h2, c2) = encrypt(&mut sender, b"Message 2", &[]).expect("encrypts 2");
        let (h3, c3) = encrypt(&mut sender, b"Message 3", &[]).expect("encrypts 3");

        // Receiver receives them out of order: 1, 3, 2
        let d1 = decrypt(&mut receiver, &h1, &c1, &[]).expect("Decrypt 1");
        assert_eq!(d1, b"Message 1");

        let d3 = decrypt(&mut receiver, &h3, &c3, &[]).expect("Decrypt 3");
        assert_eq!(d3, b"Message 3");

        let d2 = decrypt(&mut receiver, &h2, &c2, &[]).expect("Decrypt 2");
        assert_eq!(d2, b"Message 2");
    }

    #[test]
    fn test_max_skip_exceeded() {
        let sk = [0x88u8; 32];

        let mut rng = rand_core::OsRng;
        let receiver_dh_private = StaticSecret::random_from_rng(&mut rng);
        let receiver_dh_public = PublicKey::from(&receiver_dh_private);

        let mut sender = init_sender_state(sk, receiver_dh_public).unwrap();
        let mut receiver = init_receiver_state(sk, (receiver_dh_private, receiver_dh_public));

        let (h1, c1) = encrypt(&mut sender, b"Message 1", &[]).expect("encrypt 1");
        // sender = new_sender; // Removed
        let _ = decrypt(&mut receiver, &h1, &c1, &[]).expect("Decrypt 1");

        // Sender sends MAX_SKIP + 2 more messages
        for _ in 0..(MAX_SKIP + 2) {
            let (_, _) = encrypt(&mut sender, b"Skip me", &[]).unwrap();
            // sender = new_sender; // Removed
        }

        let (h_final, c_final) = encrypt(&mut sender, b"Final", &[]).expect("encrypt final");

        // Receiver tries to decrypt - should fail due to MAX_SKIP
        let err = decrypt(&mut receiver, &h_final, &c_final, &[]);
        assert!(matches!(err, Err(RatchetError::OldMessageKeysLimitReached)));
    }

    #[test]
    fn test_tampered_ciphertext() {
        let sk = [0x77u8; 32];

        let mut rng = rand_core::OsRng;
        let receiver_dh_private = StaticSecret::random_from_rng(&mut rng);
        let receiver_dh_public = PublicKey::from(&receiver_dh_private);

        let mut sender = init_sender_state(sk, receiver_dh_public).unwrap();
        let mut receiver = init_receiver_state(sk, (receiver_dh_private, receiver_dh_public));

        let msg = b"Tampered";
        let (enc_header, mut cipher) = encrypt(&mut sender, msg, &[]).expect("encrypt tampered");

        // Tamper ciphertext
        if !cipher.is_empty() {
            cipher[0] ^= 0xFF;
        }

        let err = decrypt(&mut receiver, &enc_header, &cipher, &[]);
        assert!(matches!(err, Err(RatchetError::DecryptionFailed)));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let sk = [0x99u8; 32];

        let mut rng = rand_core::OsRng;
        let receiver_dh_private = StaticSecret::random_from_rng(&mut rng);
        let receiver_dh_public = PublicKey::from(&receiver_dh_private);

        let mut sender = init_sender_state(sk, receiver_dh_public).unwrap();
        let mut receiver = init_receiver_state(sk, (receiver_dh_private, receiver_dh_public));

        // Exchange messages
        let (h1, c1) = encrypt(&mut sender, b"Msg1", &[]).unwrap();
        let _ = decrypt(&mut receiver, &h1, &c1, &[]).unwrap();

        // Serialize sender
        let json = serde_json::to_string(&sender).expect("Serialize sender");

        // Deserialize sender
        let mut restored_sender: RatchetState =
            serde_json::from_str(&json).expect("Deserialize sender");

        // Continue session with restored sender
        let (h2, c2) = encrypt(&mut restored_sender, b"Msg2", &[]).unwrap();
        let d2 = decrypt(&mut receiver, &h2, &c2, &[]).unwrap();
        assert_eq!(d2, b"Msg2");

        // Verify skipped keys serialization
        // Advance sender (restored) to skip a key
        let (h3, c3) = encrypt(&mut restored_sender, b"Msg3", &[]).unwrap();
        let (h4, c4) = encrypt(&mut restored_sender, b"Msg4", &[]).unwrap();

        // Receiver receives Msg4 (skipping 3)
        let d4 = decrypt(&mut receiver, &h4, &c4, &[]).unwrap();
        assert_eq!(d4, b"Msg4");

        // Serialize receiver
        let rec_json = serde_json::to_string(&receiver).expect("Serialize receiver");
        let mut restored_receiver: RatchetState =
            serde_json::from_str(&rec_json).expect("Deserialize receiver");

        // Restored receiver receives Msg3 (using skipped key)
        let d3 = decrypt(&mut restored_receiver, &h3, &c3, &[]).unwrap();
        assert_eq!(d3, b"Msg3");
    }
}
