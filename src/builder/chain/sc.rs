/*
    sc.rs - Handling for Xbox 360 SC bootloader stages.
    Copyright 2024 Emma https://ipg.gay/

    Modified in 2026 by Exposure / Zach for gxBuild

    This file has been taken from xenon-bltool and modified, and therefore retains the original
    License.

    xenon-bltool is free software: you can redistribute it and/or modify it under the terms of
    the GNU General Public License as published by the Free Software Foundation, version 2 of
    the License.

    xenon-bltool is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with xenon-bltool.
    If not, see <https://www.gnu.org/licenses/>.
*/

use super::BootloaderHeader;
use crate::crypto::rsa::ExCryptRsa;
use crate::crypto::{hmac_sha, rot_sum_sha, verify_signature, Rc4};
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Error, Debug)]
pub enum ScError {
    #[error("SC data too short: got {got}, need {need}")]
    DataTooShort { got: usize, need: usize },
    #[error("Failed to parse SC header")]
    ParseError,
    #[error("HMAC-SHA key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("RC4 initialization failed: {0}")]
    Rc4Init(String),
    #[error("RC4 operation failed: {0}")]
    Rc4Crypt(String),
    #[error("Signature verification failed")]
    SignatureVerification,
}

pub type Result<T> = std::result::Result<T, ScError>;

impl From<ScError> for String {
    fn from(e: ScError) -> Self {
        e.to_string()
    }
}

#[derive(
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    Clone,
    Copy,
)]
#[repr(C)]
pub struct BootloaderScHeader {
    pub header: BootloaderHeader,
    pub signature: [u8; 0x100],
}

#[derive(Clone)]
pub struct BootloaderSc {
    pub header: BootloaderHeader,
    pub data: Vec<u8>,
}

impl BootloaderSc {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (header, payload) =
            BootloaderHeader::read_from_prefix(data).map_err(|_| ScError::ParseError)?;
        Ok(Self {
            header: header.clone(),
            data: payload.to_vec(),
        })
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) -> Result<()> {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = (size_aligned - 0x10) as usize;

        if self.data.len() < payload_len {
            return Err(ScError::DataTooShort {
                got: self.data.len(),
                need: payload_len,
            });
        }

        let hash = rot_sum_sha(
            &IntoBytes::as_bytes(&self.header)[..0x10],
            &self.data[0x110..payload_len],
        )
        .map_err(|e| ScError::KeyDerivation(e.to_string()))?;
        sha_out.copy_from_slice(&hash);
        Ok(())
    }

    pub fn verify_signature(&self, salt: &[u8], pubkey: &ExCryptRsa) -> Result<()> {
        let mut bl_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut bl_hash)?;

        if self.data.len() < 0x110 {
            return Err(ScError::DataTooShort {
                got: self.data.len(),
                need: 0x110,
            });
        }
        let signature: &[u8; 256] = self.data[0x10..0x110]
            .try_into()
            .map_err(|_| ScError::ParseError)?;

        if verify_signature(signature, &bl_hash, salt, pubkey).unwrap_or(false) {
            Ok(())
        } else {
            Err(ScError::SignatureVerification)
        }
    }

    pub fn decrypt(&mut self, dec_key: &[u8; 16]) -> Result<()> {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = (size_aligned - 0x10) as usize;

        if self.data.len() < payload_size {
            return Err(ScError::DataTooShort {
                got: self.data.len(),
                need: payload_size,
            });
        }

        let derived_key = hmac_sha(dec_key, &[&self.data[0..16]])
            .map_err(|e| ScError::KeyDerivation(e.to_string()))?;
        let mut decrypt_key = [0u8; 16];
        decrypt_key.copy_from_slice(&derived_key[..16]);

        let mut rc4 = Rc4::new(&decrypt_key).map_err(|e| ScError::Rc4Init(e.to_string()))?;
        rc4.crypt(&mut self.data[0x10..payload_size])
            .map_err(|e| ScError::Rc4Crypt(e.to_string()))?;
        Ok(())
    }

    pub fn decrypt_stock(&mut self) -> Result<()> {
        let zero_key = [0u8; 16];
        self.decrypt(&zero_key)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
