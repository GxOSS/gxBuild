/*
    cg.rs - Handling for Xbox 360 CG/7BL bootloader stages.
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
use crate::crypto::{hmac_sha, rot_sum_sha, Rc4};
// use crate::builder::deps::xenia;
use byteorder::{BigEndian, ByteOrder};
use log::info;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Clone, Debug)]
pub struct CgMetadata {
    pub original_size: u32,
    pub original_hash: [u8; 0x14],
    pub new_size: u32,
    pub new_hash: [u8; 0x14],
}

#[derive(Clone)]
pub struct BootloaderCg {
    pub header: BootloaderHeader,
    pub data: Vec<u8>,
    pub metadata: Option<CgMetadata>,
}

impl BootloaderCg {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let (header, payload): (BootloaderHeader, &[u8]) = BootloaderHeader::read_from_prefix(data).map_err(|_| "Failed to parse CG header")?;
        let mut cg = Self { header, data: payload.to_vec(), metadata: None };
        cg.populate_metadata();
        Ok(cg)
    }

    pub fn populate_metadata(&mut self) {
        if self.data.len() < 0x40 {
            return;
        }

        let original_size = BigEndian::read_u32(&self.data[0x10..0x14]);
        let mut original_hash = [0u8; 0x14];
        original_hash.copy_from_slice(&self.data[0x14..0x28]);

        let new_size = BigEndian::read_u32(&self.data[0x28..0x2C]);
        let mut new_hash = [0u8; 0x14];
        new_hash.copy_from_slice(&self.data[0x2C..0x40]);

        self.metadata = Some(CgMetadata { original_size, original_hash, new_size, new_hash });
    }

    pub fn sync_metadata(&mut self) {
        if let Some(ref meta) = self.metadata {
            if self.data.len() < 0x40 {
                return;
            }

            BigEndian::write_u32(&mut self.data[0x10..0x14], meta.original_size);
            self.data[0x14..0x28].copy_from_slice(&meta.original_hash);
            BigEndian::write_u32(&mut self.data[0x28..0x2C], meta.new_size);
            self.data[0x2C..0x40].copy_from_slice(&meta.new_hash);
        }
    }

    pub fn is_decrypted(&self) -> bool {
        if self.data.len() < 0x14 {
            return false;
        }

        (BigEndian::read_u32(&self.data[0x10..0x14]) & 0xFFF) == 0x000
    }

    pub fn print_info(&self) {
        let indicator = if (self.header.magic.get() & 0xF000) == 0x5000 { "SG" } else { "CG" };
        info!("[builder] {} version: {}", indicator, self.header.version.get());
        info!("[builder] {} size: 0x{:x}", indicator, self.header.size.get());

        if self.is_decrypted() {
            if let Some(ref meta) = self.metadata {
                info!("[builder] {} base size: 0x{:x}", indicator, meta.original_size);
                info!("[builder] {}-G base hash: {:02x?}", indicator, meta.original_hash);
                info!("[builder] {} target size: 0x{:x}", indicator, meta.new_size);
                info!("[builder] {}-G target hash: {:02x?}", indicator, meta.new_hash);
            } else {
                let original_size = BigEndian::read_u32(&self.data[0x10..0x14]);
                let original_hash = &self.data[0x14..0x28];
                let new_size = BigEndian::read_u32(&self.data[0x28..0x2C]);
                let new_hash = &self.data[0x2C..0x40];

                info!("[builder] {} base size: 0x{:x}", indicator, original_size);
                info!("[builder] {}-G base hash: {:02x?}", indicator, original_hash);
                info!("[builder] {} target size: 0x{:x}", indicator, new_size);
                info!("[builder] {}-G target hash: {:02x?}", indicator, new_hash);
            }
        } else {
            info!("[builder] {} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, cg_hmac: &[u8; 16]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = (size_aligned - 0x10) as usize;

        if self.data.len() < payload_size {
            return;
        }

        if let Ok(cg_key) = hmac_sha(cg_hmac, &[&self.data[0..16]]) {
            let mut final_key = [0u8; 16];
            final_key.copy_from_slice(&cg_key[..16]);
            info!("[builder] CG Decryption Key Derived: {:02x?}", final_key);

            if let Ok(mut rc4) = Rc4::new(&final_key) {
                let _ = rc4.crypt(&mut self.data[0x10..payload_size]);
            }
        }
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = (size_aligned - 0x10) as usize;

        if self.data.len() < payload_len {
            return;
        }

        if let Ok(hash) = rot_sum_sha(&IntoBytes::as_bytes(&self.header)[..0x10], &self.data[0x10..payload_len]) {
            sha_out.copy_from_slice(&hash);
        }
    }

    /*
        pub fn apply_patch(&self, base_data: &[u8]) -> Result<Vec<u8>, String> {
            if self.data.len() < 0x40 {
                return Err("CG data too small to read patch header".into());
            }
            let original_size = BigEndian::read_u32(&self.data[0x10..0x14]) as usize;
            let original_hash = &self.data[0x14..0x28];
            let new_size = BigEndian::read_u32(&self.data[0x28..0x2C]) as usize;
            let new_hash = &self.data[0x2C..0x40];

            if base_data.len() < original_size {
                return Err("Base data provided is smaller than original_size".into());
            }

            if let Ok(base_kernel_hash) = sha(&[base_data]) {
                if base_kernel_hash != original_hash {
                    return Err("Base kernel hash did not match expected".into());
                }
            }

            let mut output_buf = vec![0u8; new_size];
            output_buf[..original_size].copy_from_slice(&base_data[..original_size]);
            // The rest is automatically padded with 0 since vec! initializes with 0

            info!("[builder] Applying LZX delta patch to kernel (base: 0x{:X} bytes -> target: 0x{:X} bytes)...", original_size, new_size);
            // Skip the 0x40 bytes of CG metadata (key + original_size + original_hash + new_size + new_hash)
            // The LZX delta patch data starts after this metadata
            xenia::apply_patch(&self.data[0x40..], 0x8000, &mut output_buf)
                .map_err(|e| format!("lzxdelta_apply_patch returned error code {}", e))?;

            if let Ok(updated_kernel_hash) = sha(&[&output_buf]) {
                if updated_kernel_hash != new_hash {
                    return Err("Updated kernel hash did not match expected".into());
                }
            }

            info!("[builder] LZX delta patch applied and hash verified OK.");
            Ok(output_buf)
        }
    */

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
