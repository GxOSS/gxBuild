/*
BSD 3-Clause License

Copyright (c) 2020, emoose
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

use super::{CryptoError, Result};
use xecrypt::symmetric;

pub struct Aes {
    key: [u8; 16],
}

impl Aes {
    pub fn new(key: &[u8]) -> Result<Self> {
        let key: [u8; 16] = key.try_into().map_err(|_| CryptoError::InvalidKeySize { expected: 16, got: key.len() })?;
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
