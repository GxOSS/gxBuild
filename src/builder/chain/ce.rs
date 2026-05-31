/*
    ce.rs - Handling for Xbox 360 CE/5BL bootloader stages.
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
// use crate::builder::chain::cf::BootloaderCf;
// use crate::builder::chain::cg::BootloaderCg;
use crate::crypto::{hmac_sha, rot_sum_sha, Rc4};
use byteorder::{BigEndian as RealBigEndian, ByteOrder};
use log::{info, warn};
use thiserror::Error;
use zerocopy::byteorder::{BigEndian, U32, U64};
use zerocopy::{FromBytes, IntoBytes};

#[derive(Error, Debug)]
pub enum CeError {
    #[error("CE data too short: got {got}, need {need}")]
    DataTooShort { got: usize, need: usize },
    #[error("Failed to parse CE header")]
    ParseError,
    #[error("HMAC-SHA key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("RC4 initialization failed: {0}")]
    Rc4Init(String),
    #[error("RC4 operation failed: {0}")]
    Rc4Crypt(String),
}

pub type Result<T> = std::result::Result<T, CeError>;

impl From<CeError> for String {
    fn from(e: CeError) -> Self {
        e.to_string()
    }
}

#[derive(Clone, Debug)]
pub struct CeMetadata {
    pub target_address: u64,
    pub uncompressed_size: u32,
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
pub struct BootloaderCeHeader {
    pub header: BootloaderHeader,
    pub target_address: U64<BigEndian>,
    pub uncompressed_size: U32<BigEndian>,
    pub unknown: U32<BigEndian>,
}

#[derive(Clone)]
pub struct BootloaderCe {
    pub header: BootloaderHeader,
    pub data: Vec<u8>,
    pub metadata: Option<CeMetadata>,
    pub data_ce: Option<Vec<u8>>,
    pub data_kernel: Option<Vec<u8>>,
    pub data_hv: Option<Vec<u8>>,
}

impl BootloaderCe {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (header, payload) =
            BootloaderHeader::read_from_prefix(data).map_err(|_| CeError::ParseError)?;

        let mut data_vec = payload.to_vec();
        let expected_payload_size = ((header.size.get() as usize + 0xF) & 0xFFFFFFF0) - 0x10;
        if data_vec.len() < expected_payload_size {
            warn!(
                "[builder] CE data resized from {} to {} bytes",
                data_vec.len(),
                expected_payload_size
            );
            data_vec.resize(expected_payload_size, 0);
        }

        Ok(Self {
            header: header.clone(),
            data: data_vec,
            metadata: None,
            data_ce: None,
            data_kernel: None,
            data_hv: None,
        })
    }

    pub fn populate_metadata(&mut self) {
        if !self.is_decrypted() {
            return;
        }
        if self.data.len() < 0x20 {
            warn!(
                "[builder] CE data too short for metadata: got 0x{:x}, need 0x20",
                self.data.len()
            );
            return;
        }

        let target_address = RealBigEndian::read_u64(&self.data[0x10..0x18]);
        let uncompressed_size = RealBigEndian::read_u32(&self.data[0x18..0x1C]);

        self.metadata = Some(CeMetadata {
            target_address,
            uncompressed_size,
        });
    }

    pub fn sync_metadata(&mut self) {
        if !self.is_decrypted() {
            return;
        }
        if self.data.len() < 0x20 {
            warn!(
                "[builder] CE data too short for sync_metadata: got 0x{:x}, need 0x20",
                self.data.len()
            );
            return;
        }
        if let Some(meta) = &self.metadata {
            RealBigEndian::write_u64(&mut self.data[0x10..0x18], meta.target_address);
            RealBigEndian::write_u32(&mut self.data[0x18..0x1C], meta.uncompressed_size);
        }
    }

    pub fn is_decrypted(&self) -> bool {
        if self.data.len() < 0x20 {
            return false;
        }
        &self.data[0x1C..0x20] == &[0, 0, 0, 0]
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) -> Result<()> {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = (size_aligned - 0x10) as usize;

        if self.data.len() < payload_len {
            return Err(CeError::DataTooShort {
                got: self.data.len(),
                need: payload_len,
            });
        }

        let hash = rot_sum_sha(
            &IntoBytes::as_bytes(&self.header)[..0x10],
            &self.data[0x10..payload_len],
        )
        .map_err(|e| CeError::KeyDerivation(e.to_string()))?;
        sha_out.copy_from_slice(&hash);
        Ok(())
    }

    pub fn print_info(&self) {
        let indicator = if (self.header.magic.get() & 0xF000) == 0x5000 {
            "SE"
        } else {
            "CE"
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

        if self.is_decrypted() {
            let target_address = RealBigEndian::read_u64(&self.data[0x10..0x18]);
            let uncompressed_size = RealBigEndian::read_u32(&self.data[0x18..0x1C]);

            info!(
                "[builder] {} decompressed size: 0x{:x}",
                indicator, uncompressed_size
            );
            info!(
                "[builder] {} load address: 0x{:x}",
                indicator, target_address
            );
        } else {
            info!("[builder] {} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, cd_key: &[u8; 16]) -> Result<()> {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = (size_aligned - 0x10) as usize;

        if self.data.len() < payload_size {
            return Err(CeError::DataTooShort {
                got: self.data.len(),
                need: payload_size,
            });
        }

        let derived_key = hmac_sha(cd_key, &[&self.data[0..16]])
            .map_err(|e| CeError::KeyDerivation(e.to_string()))?;
        let mut final_key = [0u8; 16];
        final_key.copy_from_slice(&derived_key[..16]);
        info!("[builder] CE Decryption Key Derived: {:02x?}", final_key);

        let mut rc4 = Rc4::new(&final_key).map_err(|e| CeError::Rc4Init(e.to_string()))?;
        rc4.crypt(&mut self.data[0x10..payload_size])
            .map_err(|e| CeError::Rc4Crypt(e.to_string()))?;

        if self.data.len() >= 0x20 {
            self.data_ce = Some(self.data[0x20..payload_size].to_vec());
        }

        self.populate_metadata();
        Ok(())
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
