/*
  crypto.rs - Compatibility wrapper for gxcrypt

  Copyright (c) 2026 gxBuild Contributors and Developers

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/

// Re-export everything from gxcrypt
pub use gxcrypt::*;

/// Compatibility wrapper for verify_signature with the old 4-argument API.
/// The salt parameter is now ignored (the new implementation handles PKCS1v1.5 internally).
///
/// # Arguments
/// * `signature` - The RSA signature (256 bytes)
/// * `hash` - The 20-byte SHA1 hash
/// * `_salt` - The salt string (unused, kept for compatibility)
/// * `key` - The RSA public key (ExCryptRsa, which is the first field of ExCryptRsaPub1024)
///
/// # Safety
/// This function assumes the passed `key` pointer is actually a pointer to an `ExCryptRsaPub1024`
/// structure (since `ExCryptRsa` is the first field). This is how the original C/FFI code worked.
pub fn verify_signature(
    signature: &[u8; 256],
    hash: &[u8; 20],
    _salt: &[u8],
    key: &rsa::ExCryptRsa,
) -> Option<bool> {
    // Safety: ExCryptRsa is #[repr(C)] and is the first field of ExCryptRsaPub1024.
    // The callers always pass a pointer to an ExCryptRsaPub1024 structure but cast it to &ExCryptRsa.
    // This matches the original C behavior where ExCryptRsa* was used to access the full key.
    let full_key = unsafe { &*(key as *const rsa::ExCryptRsa as *const rsa::ExCryptRsaPub1024) };
    Some(gxcrypt::keys::verify_signature(hash, signature, full_key))
}
