pub use gxcrypt::*;

/// Compatibility wrapper for verify_signature with the old 4-argument API.
pub fn verify_signature(
    signature: &[u8; 256],
    hash: &[u8; 20],
    _salt: &[u8],
    key: &rsa::ExCryptRsa,
) -> Option<bool> {
    let full_key = unsafe { &*(key as *const rsa::ExCryptRsa as *const rsa::ExCryptRsaPub1024) };
    Some(gxcrypt::keys::verify_signature(hash, signature, full_key))
}
