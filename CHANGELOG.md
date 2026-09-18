# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-18

### Added
- **Docs**: Comprehensive documentation revamp including ecosystem context and the addition of `AGENTS.md`.
- **API**: Introduced `VXEdDSAError` as a dedicated error type for VXEdDSA signature operations.
- **API**: Added `DecodeFailed` variant to the `X3DHError` enum.
- **CI**: Added GitHub Action workflow (`publish.yml`) for automated publishing to crates.io upon GitHub releases.

### Changed
- **BREAKING (Rust API)**: `vxeddsa::vxeddsa_sign` now returns `Result<VXEdDSAOutput, VXEdDSAError>` instead of `Result<VXEdDSAOutput, ()>`.
- **BREAKING (Rust API)**: Added new variant `DecodeFailed` to `X3DHError` (without `#[non_exhaustive]`), requiring an update to exhaustive match statements.
- **BREAKING (FFI)**: `gen_pubkey_ffi` signature updated to accept a 33-byte array pointer (`*mut [u8; 33]`) instead of 32 bytes, enforcing proper Signal protocol public key encoding (with the `0x05` prefix).
- **BREAKING (Cargo Features)**: Android JNI bindings are no longer bundled implicitly with the `ffi` feature. They have been decoupled into a standalone `jni` feature.
- **Org Name / URLs**: Project renamed to align with the `DeezChat` ecosystem and updated repository URLs to the `deez-in` organization.
- **Profiles**: Heavily optimized the Cargo `release` profile, enabling LTO (`lto = true`), symbol stripping (`strip = true`), and `panic = "abort"` to reduce binary sizes and improve performance.

### Fixed
- Fixed an internal FFI ratchet test (`ffi_ratchet_test.rs`) that incorrectly mocked 32-byte public keys without the standard Signal `0x05` prefix.
- Addressed various JNI compilation issues and removed intermediate FFI structs in JNI bindings to improve memory safety.
