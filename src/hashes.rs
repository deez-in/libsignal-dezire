use sha2::{Digest, Sha512};

/// The function calculates `H( ((2^256 - 1) - i) || x )`.
/// This is used in the VXEdDSA protocol to derive various scalars and points
/// while ensuring domain separation.
///
/// See [XEdDSA Spec](https://signal.org/docs/specifications/xeddsa/#vxeddsa).
///
/// # Arguments
///
/// * `i` - The domain separation index (a small integer, e.g., 0, 1, 2, 3, 4).
/// * `x` - The input byte slice.
///
/// # Returns
///
/// A 64-byte array containing the SHA-512 digest.
pub fn hash_i(i: u8, x: &[u8]) -> [u8; 64] {
    // 1. Calculate the prefix: (2^256 - 1) - i
    // In Little Endian, (2^256 - 1) is [0xFF; 32].
    // Subtracting 'i' (where i is small) simply subtracts from the first byte.
    let mut prefix = [0xFFu8; 32];
    prefix[0] -= i; // e.g., 0xFF - 1 = 0xFE

    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(x);
    hasher.finalize().into()
}

/// A wrapper around SHA-512 that prepends the Signal domain separation prefix.
/// Used for Elligator2 mapping in VXEdDSA.
#[derive(Clone)]
pub struct SignalHash2(Sha512);

impl Default for SignalHash2 {
    fn default() -> Self {
        let mut hasher = Sha512::new();
        // Prefix for "hash2": (2^256 - 1) - 2.
        // In little-endian representation of 2^256-1 (32 bytes of 0xFF),
        // we subtract 2 from the first byte. 0xFF - 2 = 0xFD.
        let mut prefix = [0xFFu8; 32];
        prefix[0] = 0xFD;
        hasher.update(prefix);
        Self(hasher)
    }
}

impl sha2::digest::Update for SignalHash2 {
    fn update(&mut self, data: &[u8]) {
        sha2::digest::Update::update(&mut self.0, data);
    }
}

impl sha2::digest::FixedOutput for SignalHash2 {
    fn finalize_into(self, out: &mut sha2::digest::Output<Self>) {
        sha2::digest::FixedOutput::finalize_into(self.0, out);
    }
}

impl sha2::digest::HashMarker for SignalHash2 {}

impl sha2::digest::OutputSizeUser for SignalHash2 {
    type OutputSize = <Sha512 as sha2::digest::OutputSizeUser>::OutputSize;
}
