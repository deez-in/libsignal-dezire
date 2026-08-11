# libsignal-dezire

[![Crates.io](https://img.shields.io/crates/v/libsignal-dezire.svg)](https://crates.io/crates/libsignal-dezire)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-orange.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Security Audit](https://img.shields.io/badge/Audit-Production_Ready-brightgreen.svg)](AUDIT.md)

A pure Rust implementation of the [Signal Protocol](https://signal.org/docs/), providing end-to-end encryption for messaging applications. This is the **cryptographic foundation** of the [DeezChatz](https://github.com/deez-in) ecosystem — every encrypted message, every key exchange, and every signature verification flows through this crate. Double ratchet secrecy, zero trust. Because ain't nobody reading Deez Chatz — least of all our servers. 🔒🔥

## Where This Fits

```
┌──────────────────────────────────────────────────────┐
│  DeezChatz Mobile (React Native app)                 │
│    └─ expo-libsignal-dezire (Expo Native Module)     │
│         └─ ⭐ libsignal-dezire (this crate)          │  ← C-FFI / JNI
│                                                      │
│  DeezChatz API (Rust / Axum backend)                 │
│    └─ ⭐ libsignal-dezire (this crate)               │  ← cargo dependency
└──────────────────────────────────────────────────────┘
```

| Consumer | How it depends | What it uses |
|----------|---------------|--------------|
| **DeezChatz API** | Cargo git dependency | `vxeddsa_verify` — to verify signatures during registration and per-request auth |
| **expo-libsignal-dezire** | Compiled to `.a` (iOS) / `.so` (Android) via FFI | Everything — key generation, X3DH, Double Ratchet, signing, verification |

> Changes to this crate's public API ripple across the entire stack. If you modify a function signature, the FFI bindings (`src/ffi/`, `libsignal-dezire.h`), JNI bindings (`src/jni/`), and the `expo-libsignal-dezire` wrappers all need updating.

---

## Concepts

The Signal Protocol consists of three building blocks, each solving a specific problem:

### VXEdDSA — Signatures & Identity Proof

**Problem it solves**: How do you prove you own a key without revealing the key itself?

VXEdDSA is a signature scheme that produces two outputs:
- A **signature** (96 bytes) — cryptographic proof that the signer holds the private key.
- A **VRF output** (32 bytes) — a deterministic, verifiable random value unique to the (key, message) pair. This acts as an additional integrity check.

**When it's used**: Every time a user registers, signs their pre-keys, or authenticates an API request.

### X3DH — Asynchronous Key Agreement

**Problem it solves**: How do two people establish a shared secret when one of them is offline?

X3DH (Extended Triple Diffie-Hellman) is a key agreement protocol. Bob publishes a bundle of public keys to the server ahead of time. When Alice wants to message Bob — even if he's offline — she downloads his bundle and performs the key exchange locally. Both sides end up with the same shared secret without ever communicating directly.

**When it's used**: The very first message between two users. After this, the Double Ratchet takes over.

### Double Ratchet — Session Encryption

**Problem it solves**: How do you encrypt a stream of messages with forward secrecy (compromising one key doesn't reveal past messages) and break-in recovery (compromising one key is automatically healed)?

The Double Ratchet algorithm derives a new encryption key for every single message. It combines a "symmetric ratchet" (hash chain) with a "DH ratchet" (new Diffie-Hellman exchange on every reply). The result: every message uses a unique key, old keys are deleted, and a key compromise is automatically healed when the next DH exchange happens.

**When it's used**: Every message after the initial X3DH handshake.

---

## Installation

```toml
[dependencies]
libsignal-dezire = "0.1.146"
```

Or from git:

```toml
[dependencies]
libsignal-dezire = { git = "https://github.com/deez-in/libsignal-dezire" }
```

---

## Quick Start

### 1. Generate Keys

```rust
use libsignal_dezire::vxeddsa::gen_keypair;

// Each party generates a long-term identity key pair
let alice_identity = gen_keypair();  // { secret: [u8; 32], public: CompressedEdwardsY }
let bob_identity = gen_keypair();
```

### 2. X3DH Key Exchange

```rust
use libsignal_dezire::x3dh::{x3dh_initiator, x3dh_responder, PreKeyBundle, SignedPreKey};
use libsignal_dezire::vxeddsa::{gen_keypair, vxeddsa_sign};
use libsignal_dezire::utils::encode_public_key;

// ── Bob publishes a pre-key bundle (uploaded to the server) ──

let bob_spk = gen_keypair();  // Signed pre-key
let encoded_spk = encode_public_key(&bob_spk.public);

// Bob signs his pre-key with his identity key (VXEdDSA)
let sig = vxeddsa_sign(&bob_identity.secret, &encoded_spk).unwrap();

let bundle = PreKeyBundle {
    identity_key: bob_identity.public,
    signed_prekey: SignedPreKey {
        id: 1,
        public_key: bob_spk.public,
        signature: sig.signature,
    },
    one_time_prekey: None,  // Optional: adds extra forward secrecy
};

// ── Alice fetches the bundle and initiates ──

let alice_identity = gen_keypair();
let result = x3dh_initiator(&alice_identity.secret, &bundle).unwrap();
// result.shared_secret  → [u8; 32] — the shared secret
// result.ephemeral_public → Alice's ephemeral public key (sent to Bob)

// ── Bob computes the same shared secret ──

let bob_sk = x3dh_responder(
    &bob_identity.secret,
    &bob_spk.secret,
    None,                         // one-time pre-key (if used)
    &alice_identity.public,
    &result.ephemeral_public,
).unwrap();

assert_eq!(result.shared_secret, bob_sk);
```

### 3. Double Ratchet Session

```rust
use libsignal_dezire::ratchet::{init_sender_state, init_receiver_state, encrypt, decrypt};
use libsignal_dezire::utils::encode_public_key;

// Construct Associated Data (binds both identities to the session)
let ad = [
    encode_public_key(&alice_identity.public),  // 33 bytes
    encode_public_key(&bob_identity.public),    // 33 bytes
].concat();  // 66 bytes total

// Alice initializes as sender (she initiated X3DH)
let mut alice_state = init_sender_state(shared_secret, bob_dh_public).unwrap();

// Bob initializes as receiver
let mut bob_state = init_receiver_state(shared_secret, bob_keypair);

// Alice encrypts a message
let (header, ciphertext) = encrypt(&mut alice_state, b"Hello Bob!", &ad).unwrap();

// Bob decrypts it
let plaintext = decrypt(&mut bob_state, &header, &ciphertext, &ad).unwrap();
assert_eq!(plaintext, b"Hello Bob!");
```

---

## API Overview

### `vxeddsa` — Signatures

| Function | Description |
|----------|-------------|
| `gen_keypair() → KeyPair` | Generate a Curve25519 key pair (secret + public) |
| `vxeddsa_sign(secret, message) → VXEdDSAOutput` | Sign a message, producing a 96-byte signature + 32-byte VRF output |
| `vxeddsa_verify(public, message, signature) → Option<[u8; 32]>` | Verify a signature, returning the VRF output on success or `None` on failure |

### `x3dh` — Key Agreement

| Function | Description |
|----------|-------------|
| `x3dh_initiator(identity_secret, bundle) → X3DHInitResult` | Perform initiator-side X3DH, returns shared secret + ephemeral public key |
| `x3dh_responder(identity_secret, spk_secret, opk_secret, alice_identity, alice_ephemeral) → [u8; 32]` | Perform responder-side X3DH, returns the same shared secret |

### `ratchet` — Session Encryption

| Function | Description |
|----------|-------------|
| `init_sender_state(shared_secret, receiver_pub) → RatchetState` | Initialize the sender's ratchet state from an X3DH shared secret |
| `init_receiver_state(shared_secret, keypair) → RatchetState` | Initialize the receiver's ratchet state |
| `encrypt(state, plaintext, ad) → (Header, Ciphertext)` | Encrypt a message, advancing the ratchet |
| `decrypt(state, header, ciphertext, ad) → Plaintext` | Decrypt a message, advancing the ratchet |

### `utils` — Helpers

| Function | Description |
|----------|-------------|
| `encode_public_key(point) → [u8; 33]` | Encode an Edwards point as a 33-byte Curve25519 public key (0x05 prefix) |
| `convert_mont(montgomery) → EdwardsPoint` | Convert a Montgomery point to Edwards form |

---

## FFI & Cross-Platform

This crate compiles to a static library (`.a` / `.so` / `.dylib`) with C-compatible bindings when the `ffi` feature is enabled:

```toml
[features]
ffi = []    # C bindings via extern "C"
jni = []    # Android JNI bindings
```

For React Native / Expo integration, see [expo-libsignal-dezire](https://github.com/deez-in/expo-libsignal-dezire), which wraps this crate's FFI in an Expo Native Module.

For direct C integration:

```c
#include "libsignal-dezire.h"

X3DHInitOutput output;
x3dh_initiator_ffi(identity_private, &bundle, &output);
```

---

## Security

This crate has been [security audited](AUDIT.md) and is rated **Production Ready**.

| Property | How it's achieved |
|----------|-------------------|
| **Forward Secrecy** | DH ratchet generates new keys on every exchange |
| **Break-in Recovery** | Compromise is automatically healed after the next DH ratchet step |
| **Constant-time Operations** | `subtle::ct_eq` and `conditional_select` — no branching on secrets |
| **Memory Zeroization** | All sensitive state derives `Zeroize` + `ZeroizeOnDrop`; temporaries are explicitly zeroized |
| **Low-order Point Rejection** | Cofactor multiplication prevents small-subgroup attacks |
| **Deniability** | No long-term signatures on messages |

### Spec Compliance

| Specification | Compliance |
|--------------|------------|
| [XEdDSA and VXEdDSA](https://signal.org/docs/specifications/xeddsa/) | 98% |
| [X3DH](https://signal.org/docs/specifications/x3dh/) | 98% |
| [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) | 95% |

See [AUDIT.md](AUDIT.md) for the full audit report, including design differences from Signal's official `libsignal`.

---

## License

AGPL-v3 — see [LICENSE](LICENSE)
