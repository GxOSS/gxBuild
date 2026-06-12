/*
    cf.rs - Handling for Xbox 360 CF/6BL bootloader stages.
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
use byteorder::{BigEndian, ByteOrder};
use log::{info, warn};
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Error, Debug)]
pub enum CfError {
    #[error("CF data too short: got {got}, need {need}")]
    DataTooShort { got: usize, need: usize },
    #[error("Invalid CF size in header")]
    InvalidSize,
    #[error("Failed to parse CF header")]
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

pub type Result<T> = std::result::Result<T, CfError>;

impl From<CfError> for String {
    fn from(e: CfError) -> Self {
        e.to_string()
    }
}

#[derive(Clone, Debug)]
pub struct CfMetadata {
    // Plain - Offset 0x0 in payload / 0x10 Absolute
    pub source_version: u16,
    pub target_version: u16,
    pub reserved_prefix: u32,
    pub cg_size: u32,
    pub hmac_salt: [u8; 16],

    // Decrypted - 7BL Bridge - Offset 0x20 in payload / 0x30 Absolute
    pub cg_blocks_used: u16,
    pub cg_block_numbers: Vec<u16>, // 223 entries

    // Decrypted - PerBoxData
    pub reserved_per_box: [u8; 0x2B],
    pub update_slot: u8,
    pub pairing_data: [u8; 3],
    pub lockdown_value: u8,
    pub per_box_digest: [u8; 0x10],

    // Decrypted - Chain Bridge
    pub signature: [u8; 0x100],
    pub cg_nonce: [u8; 0x10],
    pub cg_digest: [u8; 0x14],
}

#[derive(Clone)]
pub struct BootloaderCf {
    pub header: BootloaderHeader,
    pub data: Vec<u8>,
    pub metadata: Option<CfMetadata>,
}

impl BootloaderCf {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (header, payload) =
            BootloaderHeader::read_from_prefix(data).map_err(|_| CfError::ParseError)?;
        let total_size = ((header.size.get() as usize) + 0xF) & !0xF;
        if total_size < core::mem::size_of::<BootloaderHeader>() {
            return Err(CfError::InvalidSize);
        }
        if data.len() < total_size {
            return Err(CfError::DataTooShort {
                got: data.len(),
                need: total_size,
            });
        }
        let payload_len = total_size - core::mem::size_of::<BootloaderHeader>();
        let mut cf = Self {
            header: header.clone(),
            data: payload[..payload_len].to_vec(),
            metadata: None,
        };
        cf.populate_metadata();
        Ok(cf)
    }

    pub fn populate_metadata(&mut self) {
        if !self.is_decrypted() {
            return;
        }
        if self.data.len() < 0x344 {
            warn!(
                "[builder] CF data too short for metadata: got 0x{:x}, need 0x344",
                self.data.len()
            );
            return;
        }
        self.populate_metadata_unchecked();
    }

    pub fn populate_metadata_unchecked(&mut self) {
        if self.data.len() < 0x344 {
            warn!("[builder] CF data too short for populate_metadata_unchecked: got 0x{:x}, need 0x344", self.data.len());
            return;
        }

        let source_version = BigEndian::read_u16(&self.data[0x0..0x2]);
        let target_version = BigEndian::read_u16(&self.data[0x4..0x6]);
        let reserved_prefix = BigEndian::read_u32(&self.data[0x8..0xC]);
        let cg_size = BigEndian::read_u32(&self.data[0xC..0x10]);
        let mut hmac_salt = [0u8; 16];
        hmac_salt.copy_from_slice(&self.data[0x10..0x20]);

        let cg_blocks_used = BigEndian::read_u16(&self.data[0x20..0x22]);
        let mut cg_block_numbers = Vec::with_capacity(223);
        for i in 0..223 {
            let offset = 0x22 + (i * 2);
            cg_block_numbers.push(BigEndian::read_u16(&self.data[offset..offset + 2]));
        }

        let mut reserved_per_box = [0u8; 0x2B];
        reserved_per_box.copy_from_slice(&self.data[0x1E0..0x20B]);
        let update_slot = self.data[0x20B];

        let mut pairing_data = [0u8; 3];
        pairing_data.copy_from_slice(&self.data[0x20C..0x20F]);
        pairing_data.reverse();

        let lockdown_value = self.data[0x20F];
        let mut per_box_digest = [0u8; 0x10];
        per_box_digest.copy_from_slice(&self.data[0x210..0x220]);

        let mut signature = [0u8; 0x100];
        signature.copy_from_slice(&self.data[0x220..0x320]);

        let mut cg_nonce = [0u8; 0x10];
        cg_nonce.copy_from_slice(&self.data[0x320..0x330]);

        let mut cg_digest = [0u8; 0x14];
        cg_digest.copy_from_slice(&self.data[0x330..0x344]);

        self.metadata = Some(CfMetadata {
            source_version,
            target_version,
            reserved_prefix,
            cg_size,
            hmac_salt,
            cg_blocks_used,
            cg_block_numbers,
            reserved_per_box,
            update_slot,
            pairing_data,
            lockdown_value,
            per_box_digest,
            signature,
            cg_nonce,
            cg_digest,
        });
    }

    pub fn sync_metadata(&mut self) {
        if let Some(ref meta) = self.metadata {
            if self.data.len() < 0x344 {
                warn!(
                    "[builder] CF data too short for sync_metadata: got 0x{:x}, need 0x344",
                    self.data.len()
                );
                return;
            }

            BigEndian::write_u16(&mut self.data[0x0..0x2], meta.source_version);
            BigEndian::write_u16(&mut self.data[0x4..0x6], meta.target_version);
            BigEndian::write_u32(&mut self.data[0x8..0xC], meta.reserved_prefix);
            BigEndian::write_u32(&mut self.data[0xC..0x10], meta.cg_size);
            self.data[0x10..0x20].copy_from_slice(&meta.hmac_salt);

            BigEndian::write_u16(&mut self.data[0x20..0x22], meta.cg_blocks_used);
            for (i, &block) in meta.cg_block_numbers.iter().enumerate() {
                if i >= 223 {
                    break;
                }
                let offset = 0x22 + (i * 2);
                BigEndian::write_u16(&mut self.data[offset..offset + 2], block);
            }

            self.data[0x1E0..0x20B].copy_from_slice(&meta.reserved_per_box);
            self.data[0x20B] = meta.update_slot;

            let mut pd_sync = meta.pairing_data;
            pd_sync.reverse();
            self.data[0x20C..0x20F].copy_from_slice(&pd_sync);

            self.data[0x20F] = meta.lockdown_value;
            self.data[0x210..0x220].copy_from_slice(&meta.per_box_digest);

            self.data[0x220..0x320].copy_from_slice(&meta.signature);
            self.data[0x320..0x330].copy_from_slice(&meta.cg_nonce);
            self.data[0x330..0x344].copy_from_slice(&meta.cg_digest);
        }
    }

    // Should probably remove this and just call verify_decrypted directly
    pub fn is_decrypted(&self) -> bool {
        self.verify_decrypted()
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) -> Result<()> {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = size_aligned as usize - 0x10;

        if self.data.len() < payload_len {
            return Err(CfError::DataTooShort {
                got: self.data.len(),
                need: payload_len,
            });
        }

        let mut combined_header = [0u8; 0x20];
        combined_header[..0x10].copy_from_slice(&IntoBytes::as_bytes(&self.header)[..0x10]);
        combined_header[0x10..].copy_from_slice(&self.data[0x0..0x10]);

        let hash = rot_sum_sha(&combined_header, &self.data[0x320..payload_len])
            .map_err(|e| CfError::KeyDerivation(e.to_string()))?;
        sha_out.copy_from_slice(&hash);
        Ok(())
    }

    pub fn verify_signature(&self, rsa_1bl: &ExCryptRsa) -> Result<()> {
        let mut cf_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut cf_hash)?;

        if self.data.len() < 0x320 {
            return Err(CfError::DataTooShort {
                got: self.data.len(),
                need: 0x320,
            });
        }
        let signature: &[u8; 256] = self.data[0x220..0x320]
            .try_into()
            .map_err(|_| CfError::ParseError)?;

        let expected_salt = b"XBOX_ROM_6\0";
        if verify_signature(signature, &cf_hash, expected_salt, rsa_1bl).unwrap_or(false) {
            Ok(())
        } else {
            Err(CfError::SignatureVerification)
        }
    }

    pub fn print_info(&self) {
        let indicator = if (self.header.magic.get() & 0xF000) == 0x5000 {
            "SF"
        } else {
            "CF"
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
            info!(
                "[builder] {} source build: {}",
                indicator, meta.source_version
            );
            info!(
                "[builder] {} target build: {}",
                indicator, meta.target_version
            );
            info!("[builder] {}-G size: 0x{:x}", indicator, meta.cg_size);

            if self.is_decrypted() {
                info!("[builder] {} slot: {}", indicator, meta.update_slot);
                info!(
                    "[builder] {} pairing: {:02x?}",
                    indicator, meta.pairing_data
                );
                info!(
                    "[builder] {} CG block count: {}",
                    indicator, meta.cg_blocks_used
                );
                if meta.cg_blocks_used > 0 {
                    info!(
                        "[builder] {} CG first block: {}",
                        indicator, meta.cg_block_numbers[0]
                    );
                }
                info!("[builder] {}-G nonce: {:02x?}", indicator, meta.cg_nonce);
                info!("[builder] {}-G digest: {:02x?}", indicator, meta.cg_digest);
            }
        } else if self.data.len() >= 0x10 {
            let base_ver = BigEndian::read_u16(&self.data[0x0..0x2]);
            let target_ver = BigEndian::read_u16(&self.data[0x4..0x6]);
            let cg_size = BigEndian::read_u32(&self.data[0xC..0x10]);

            info!("[builder] {} base version: {}", indicator, base_ver);
            info!("[builder] {} target version: {}", indicator, target_ver);
            info!("[builder] {}-G size: 0x{:x}", indicator, cg_size);
        }

        if !self.is_decrypted() {
            info!("[builder] {} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, onebl_key: &[u8; 16]) -> Result<()> {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = (size_aligned - 0x10) as usize;

        if self.data.len() < payload_size {
            return Err(CfError::DataTooShort {
                got: self.data.len(),
                need: payload_size,
            });
        }

        let derived_key = hmac_sha(onebl_key, &[&self.data[0x10..0x20]])
            .map_err(|e| CfError::KeyDerivation(e.to_string()))?;
        let mut final_key = [0u8; 16];
        final_key.copy_from_slice(&derived_key[..16]);
        info!("[builder] CF Decryption Key Derived: {:02x?}", final_key);

        let mut rc4 = Rc4::new(&final_key).map_err(|e| CfError::Rc4Init(e.to_string()))?;
        rc4.crypt(&mut self.data[0x20..payload_size])
            .map_err(|e| CfError::Rc4Crypt(e.to_string()))?;
        Ok(())
    }

    pub fn verify_decrypted(&self) -> bool {
        if self.data.len() < 0x21 {
            return false;
        }
        // xenon-bltool uses the first byte of the decrypted pairing area.
        self.data[0x20] == 0
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
