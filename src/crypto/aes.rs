use super::{CryptoError, Result};
use xecrypt::symmetric;

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
