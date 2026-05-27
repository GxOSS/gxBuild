use super::{CryptoError, Result};
use xecrypt::symmetric;

#[repr(C)]
pub struct ExCryptRsa {
    pub num_digits: u32,
    pub pub_exponent: u32,
    pub reserved: u64,
}

#[repr(C)]
pub struct ExCryptRsaPub1024 {
    pub rsa: ExCryptRsa,
    pub modulus: [u64; 16],
}

#[repr(C)]
pub struct ExCryptRsaPub2048 {
    pub rsa: ExCryptRsa,
    pub modulus: [u64; 32],
}

#[repr(C)]
pub struct ExCryptSig {
    pub padding: [u64; 28],
    pub one: u8,
    pub salt: [u8; 10],
    pub hash: [u8; 20],
    pub end: u8,
}

extern "C" {
    pub fn ExCryptBnQwBeSigVerify(sig: *const ExCryptSig, hash: *const u8, salt: *const u8, pubkey: *const ExCryptRsa) -> i32;
}

pub struct Aes {
    key: [u8; 16],
}

impl Aes {
    pub fn new(key: &[u8]) -> Result<Self> {
        let key: [u8; 16] = key.try_into().map_err(|_| CryptoError::InvalidKeySize {
            expected: 16,
            got: key.len(),
        })?;
        Ok(Self { key })
    }

    pub fn decrypt_cbc(&mut self, data: &mut [u8], iv: &[u8; 16]) -> Result<()> {
        symmetric::xe_crypt_aes_cbc_decrypt(&self.key, iv, data);
        Ok(())
    }

    pub fn encrypt_cbc(&mut self, data: &mut [u8], iv: &[u8; 16]) -> Result<()> {
        symmetric::xe_crypt_aes_cbc_encrypt(&self.key, iv, data);
        Ok(())
    }
}

pub fn verify_signature(sig: &[u8; 256], hash: &[u8; 20], salt: &[u8], pubkey: &ExCryptRsa) -> Result<bool> {
    let signature_ptr = sig.as_ptr() as *const ExCryptSig;
    unsafe {
        let result = ExCryptBnQwBeSigVerify(signature_ptr, hash.as_ptr(), salt.as_ptr(), pubkey);
        Ok(result == 1)
    }
}