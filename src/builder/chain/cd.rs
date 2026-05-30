/*
    cd.rs - Handling for Xbox 360 CD/4BL bootloader stages.
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

use zerocopy::{FromBytes, IntoBytes};

use super::BootloaderHeader;
use crate::crypto::rsa::ExCryptRsa;
use crate::crypto::{hmac_sha, rot_sum_sha, verify_signature, Rc4};
use log::{info, warn};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CdError {
    #[error("CD data too short: got {got}, need {need}")]
    DataTooShort { got: usize, need: usize },
    #[error("Failed to parse CD header")]
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

pub type Result<T> = std::result::Result<T, CdError>;

impl From<CdError> for String {
    fn from(e: CdError) -> Self {
        e.to_string()
    }
}

#[derive(Clone, Debug)]
pub struct CdMetadata {
    pub signature: [u8; 0x100],
    pub rsa_pub_key: [u8; 0x110],
    pub nonce_6bl: [u8; 0x10],
    pub salt_6bl: [u8; 10],
    pub digest_5bl: [u8; 0x14],
}

#[derive(Clone)]
pub struct BootloaderCd {
    pub header: BootloaderHeader,
    pub data: Vec<u8>,
    pub metadata: Option<CdMetadata>,
    pub derived_key: Option<[u8; 16]>,
}

impl BootloaderCd {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (header, payload) =
            BootloaderHeader::read_from_prefix(data).map_err(|_| CdError::ParseError)?;
        let mut cd = Self {
            header: header.clone(),
            data: payload.to_vec(),
            metadata: None,
            derived_key: None,
        };
        cd.populate_metadata();
        Ok(cd)
    }

    pub fn populate_metadata(&mut self) {
        if !self.is_decrypted() {
            return;
        }
        if self.data.len() < 0x250 {
            warn!("[builder] CD data too short for metadata: got 0x{:x}, need 0x250", self.data.len());
            return;
        }

        let mut signature = [0u8; 0x100];
        signature.copy_from_slice(&self.data[0x10..0x110]);

        let mut rsa_pub_key = [0u8; 0x110];
        rsa_pub_key.copy_from_slice(&self.data[0x110..0x220]);

        let mut nonce_6bl = [0u8; 0x10];
        nonce_6bl.copy_from_slice(&self.data[0x220..0x230]);

        let mut salt_6bl = [0u8; 10];
        salt_6bl.copy_from_slice(&self.data[0x230..0x23A]);

        let mut digest_5bl = [0u8; 0x14];
        digest_5bl.copy_from_slice(&self.data[0x23C..0x250]);

        self.metadata = Some(CdMetadata {
            signature,
            rsa_pub_key,
            nonce_6bl,
            salt_6bl,
            digest_5bl,
        });
    }

    pub fn sync_metadata(&mut self) {
        if let Some(ref meta) = self.metadata {
            if self.data.len() < 0x250 {
                warn!("[builder] CD data too short for sync_metadata: got 0x{:x}, need 0x250", self.data.len());
                return;
            }

            self.data[0x10..0x110].copy_from_slice(&meta.signature);
            self.data[0x110..0x220].copy_from_slice(&meta.rsa_pub_key);
            self.data[0x220..0x230].copy_from_slice(&meta.nonce_6bl);
            self.data[0x230..0x23A].copy_from_slice(&meta.salt_6bl);
            self.data[0x23C..0x250].copy_from_slice(&meta.digest_5bl);
        }
    }

    pub fn is_decrypted(&self) -> bool {
        if self.data.len() < 0x111 {
            return false;
        }
        self.data[0x110] == 0x00
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) -> Result<()> {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = (size_aligned - 0x10) as usize;

        if self.data.len() < payload_len {
            return Err(CdError::DataTooShort {
                got: self.data.len(),
                need: payload_len,
            });
        }

        let hash = rot_sum_sha(
            &IntoBytes::as_bytes(&self.header)[..0x10],
            &self.data[0x110..payload_len],
        )
        .map_err(|e| CdError::KeyDerivation(e.to_string()))?;
        sha_out.copy_from_slice(&hash);
        Ok(())
    }

    pub fn print_info(&self) {
        let indicator = if (self.header.magic.get() & 0xF000) == 0x5000 {
            "SD"
        } else {
            "CD"
        };
        info!(
            "[builder] {} version: {}",
            indicator,
            self.header.version.get()
        );
        info!(
            "[builder] {} size: 0x{:x}",
            indicator,
            self.header.size.get()
        );
        info!(
            "[builder] {} entrypoint: 0x{:x}",
            indicator,
            self.header.entrypoint.get()
        );

        if let Some(ref meta) = self.metadata {
            if self.is_decrypted() {
                info!("[builder] {}-F nonce: {:02x?}", indicator, meta.nonce_6bl);
                info!("[builder] {}-F salt: {:02x?}", indicator, meta.salt_6bl);
                info!("[builder] {}-E digest: {:02x?}", indicator, meta.digest_5bl);
            }
        }

        if !self.is_decrypted() {
            info!("[builder] {} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, cbb_key: &[u8; 16], cpu_key: Option<&[u8; 16]>) -> Result<()> {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = (size_aligned - 0x10) as usize;

        if self.data.len() < payload_size {
            return Err(CdError::DataTooShort {
                got: self.data.len(),
                need: payload_size,
            });
        }

        let derived_key = hmac_sha(cbb_key, &[&self.data[0..16]])
            .map_err(|e| CdError::KeyDerivation(e.to_string()))?;
        let mut final_key = [0u8; 16];
        final_key.copy_from_slice(&derived_key[..16]);
        info!("[builder] CD Decryption Key Derived: {:02x?}", final_key);

        if let Some(key) = cpu_key {
            if let Ok(derived_key_cpu) = hmac_sha(key, &[&final_key]) {
                final_key.copy_from_slice(&derived_key_cpu[..16]);
            } else {
                warn!("[builder] CPU key HMAC derivation failed, continuing with CBB-derived key");
            }
        }

        self.derived_key = Some(final_key);
        let mut rc4 = Rc4::new(&final_key).map_err(|e| CdError::Rc4Init(e.to_string()))?;
        rc4.crypt(&mut self.data[0x10..payload_size])
            .map_err(|e| CdError::Rc4Crypt(e.to_string()))?;
        Ok(())
    }

    pub fn derived_key(&self) -> [u8; 16] {
        if let Some(key) = self.derived_key {
            return key;
        }
        if self.data.len() >= 16 {
            self.data[0..16].try_into().unwrap_or([0u8; 16])
        } else {
            [0u8; 16]
        }
    }

    pub fn verify_signature_devkit(&self, pubkey: &ExCryptRsa) -> Result<()> {
        let mut cd_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut cd_hash)?;

        if self.data.len() < 0x110 {
            return Err(CdError::DataTooShort {
                got: self.data.len(),
                need: 0x110,
            });
        }
        let signature: &[u8; 256] = self.data[0x10..0x110]
            .try_into()
            .map_err(|_| CdError::ParseError)?;

        let expected_salt = b"XBOX_ROM_4\0";
        if verify_signature(signature, &cd_hash, expected_salt, pubkey).unwrap_or(false) {
            Ok(())
        } else {
            Err(CdError::SignatureVerification)
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = zerocopy::IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
