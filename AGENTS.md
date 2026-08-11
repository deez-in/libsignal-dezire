# AGENTS.md — libsignal-dezire

This document provides instructions and context for AI coding agents working in this repository.

## Ecosystem Context

> **This is the cryptographic foundation of the DeezChatz ecosystem.** Every other repo depends on this crate — directly or indirectly.

```
deezchatz-mobile  →  expo-libsignal-dezire  →  ⭐ libsignal-dezire (this crate)
deezchatz-api  →  ⭐ libsignal-dezire (this crate)
```

| Consumer | Dependency type | What it uses |
|----------|----------------|--------------|
| **deezchatz-api** | `cargo` git dependency | `vxeddsa_verify` for signature verification during registration and auth |
| **expo-libsignal-dezire** | Compiled to `.a` / `.so` via FFI/JNI features | Full API — key generation, X3DH, Double Ratchet, VXEdDSA |

### Cross-Repo Impact Rules

- **If you change a public function signature**: you MUST also update:
  1. `libsignal-dezire.h` (C header)
  2. `src/ffi/` (C FFI bindings)
  3. `src/jni/` (Android JNI bindings)
  4. Flag that `expo-libsignal-dezire` native wrappers (Swift + Kotlin) need updating
- **If you change VXEdDSA verification behavior**: `nijhum-api` uses `vxeddsa_verify` in its auth middleware — breaking changes will break authentication across the entire platform.
- **If you change X3DH or Ratchet output formats**: the mobile app's session encryption will break.

---

## Environment & Commands

The project uses standard Rust tooling (`cargo`).

### Build
- **Check (Fast):** `cargo check`
- **Build (Dev):** `cargo build`
- **Build (Release):** `cargo build --release`
- **Build with FFI:** `cargo build --features ffi`
- **Build with JNI:** `cargo build --features jni`
- **Clean:** `cargo clean`

### Testing
- **Run All Tests:** `cargo test`
- **Run Specific Test:** `cargo test <test_name>` (e.g., `cargo test test_ratchet_basic_flow`)
- **Run Tests with Output:** `cargo test -- --nocapture`
- **Run Ignored Tests:** `cargo test -- --ignored`

### Code Quality
- **Format:** `cargo fmt` (always run before committing)
- **Lint:** `cargo clippy -- -D warnings` (ensure zero warnings)
- **Documentation:** `cargo doc --open`

---

## Project Structure

```
src/
  lib.rs          # Crate root, module exports
  vxeddsa.rs      # VXEdDSA signature scheme (sign + verify + VRF)
  x3dh.rs         # X3DH key agreement protocol
  ratchet.rs      # Double Ratchet algorithm (session encrypt/decrypt)
  utils.rs        # Curve operations, key encoding/conversion
  hashes.rs       # Domain-separated hash functions (hash_1..hash_5 per spec)
  ffi/            # C-compatible extern "C" functions (behind `ffi` feature)
  jni/            # Android JNI bindings (behind `jni` feature)
tests/
  ratchet_test.rs # Integration tests for the ratchet module
  e2e_*.rs        # End-to-end scenarios
```

---

## Code Style & Conventions

### Rust Style
- **Formatting:** Strictly follow `rustfmt` defaults (4-space indent)
- **Naming:** Structs/Enums: `PascalCase`, Functions/Variables: `snake_case`, Constants: `SCREAMING_SNAKE_CASE`
- **Import ordering:**
  ```rust
  // Std library
  use std::collections::HashMap;

  // External crates
  use aes_gcm::Aes256Gcm;
  use zeroize::Zeroize;

  // Internal modules
  use crate::ratchet::RatchetState;
  ```

### Error Handling
- Use specific error enums (e.g., `RatchetError`) — not `Box<dyn Error>`.
- Public functions return `Result<T, ErrorEnum>`.
- **`unwrap()` / `expect()` are FORBIDDEN in library code** (`src/`). Use `?` or handle errors.
- `unwrap()` is allowed in tests (`tests/` and `#[cfg(test)]`).

### Documentation
- Module-level: `//!` at the top of files describing purpose and spec references.
- Public API: `///` doc comments on all public structs, enums, and functions.
- Include code examples in doc comments for complex operations.

---

## Security & Cryptography Mandates

**CRITICAL: This is a security-sensitive codebase. Follow these rules without exception.**

### MUST DO
1. **Zeroization**: All structs containing private keys or sensitive state MUST derive `Zeroize` and `ZeroizeOnDrop`. Explicitly `.zeroize()` temporary sensitive buffers.
2. **Constant-time comparisons**: Use `subtle::ConstantTimeEq` (`ct_eq`) for comparing MACs, signatures, and secrets. NEVER use `==` on secret data.
3. **Cryptographic RNG**: Use `rand_core::OsRng` for all key generation. Never use `rand::thread_rng` or similar weak RNGs.
4. **Dependency vetting**: Prefer established crypto crates (`dalek`, `RustCrypto` organization). Vet new dependencies carefully.

### DO NOT
- **DO NOT** log key material, secrets, or intermediate cryptographic values (no `println!`, `tracing::debug!`, `dbg!` on sensitive data).
- **DO NOT** use `unsafe` without explicit justification documented in a comment explaining why it's necessary and why it's sound.
- **DO NOT** branch on secret data (no `if secret == ...`). All comparisons on secrets must be constant-time.
- **DO NOT** return distinguishable errors for different failure modes in verification functions (this leaks information). Return a generic failure.
- **DO NOT** use `Vec::with_capacity` with attacker-controlled sizes without bounds checking.

---

## Testing Guidelines

- **Unit tests**: Place in the same file as the code in a `#[cfg(test)] mod tests { ... }` block.
- **Integration tests**: Place in `tests/*.rs`. These test the public API as a consumer would use it.
- **Edge cases to test**: Replay attacks (duplicate messages), out-of-order delivery, malformed headers/inputs, `MAX_SKIP` limit exhaustion, low-order/invalid public keys.

---

## Workflow for Agents

When implementing features or fixing bugs:

1. **Read context**: Read related files first (e.g., if touching `ratchet.rs`, also read `tests/ratchet_test.rs`).
2. **Plan**: Check if changes impact the state machine, crypto properties, or FFI surface.
3. **Implement**: Write code following the style and security rules above.
4. **Test**: Create or update tests covering the change. Run `cargo test`, `cargo clippy`, `cargo fmt`.
5. **Review**: Double-check for security violations — leaked secrets in logs, timing side-channels, missing zeroization.

---

## Troubleshooting

- **Borrow checker errors with Zeroize**: Ensure you aren't using a value after it's been dropped/zeroized.
- **Linker errors**: If modifying FFI, ensure C dependencies and correct target architectures are set.
- **Crypto test failures**: Check endianness — Signal uses big-endian for network, little-endian for curve math.

---

## Security Audit

This codebase has been security audited. See [AUDIT.md](./AUDIT.md) for:
- Compliance with Signal specifications (XEdDSA, X3DH, Double Ratchet)
- Identified issues and their resolutions
- Security properties verified

**Current Status:** ✅ Production Ready
