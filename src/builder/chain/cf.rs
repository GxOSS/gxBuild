/*
    cf.rs - Handling for Xbox 360 CF/6BL bootloader stages.
    Copyright 2024 Emma https://ipg.gay/
    
    Modified in 2026 by Exposure / Zach for GGX

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
use crate::builder::deps::excrypt::{self, Rc4, ExCryptRsa};
use byteorder::{BigEndian, ByteOrder};
use log::info;

#[derive(Clone, Debug)]
pub struct CfMetadata {
    pub base_version: u16,
    pub target_version: u16,
    pub cg_size: u32,
    pub cg_hmac: [u8; 16],
    pub cg_hash: [u8; 0x14],
}

#[derive(Clone)]
pub struct BootloaderCf {
    pub header: BootloaderHeader,
    pub data: Vec<u8>,
    pub metadata: Option<CfMetadata>,
}

impl BootloaderCf {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let (header, payload) = BootloaderHeader::read_from_prefix(data)
            .map_err(|_| "Failed to parse CF header")?;
        let mut cf = Self {
            header: header.clone(),
            data: payload.to_vec(),
            metadata: None,
        };
        cf.populate_metadata();
        Ok(cf)
    }

    pub fn populate_metadata(&mut self) {
        if self.data.len() < 0x344 { return; } // Need enough for cg_hash at 0x330 + 0x14

        let base_version = BigEndian::read_u16(&self.data[0x0..0x2]);
        let target_version = BigEndian::read_u16(&self.data[0x4..0x6]);
        let cg_size = BigEndian::read_u32(&self.data[0xC..0x10]);

        let mut cg_hmac = [0u8; 16];
        cg_hmac.copy_from_slice(&self.data[0x320..0x330]);

        let mut cg_hash = [0u8; 0x14];
        cg_hash.copy_from_slice(&self.data[0x330..0x344]);

        self.metadata = Some(CfMetadata {
            base_version,
            target_version,
            cg_size,
            cg_hmac,
            cg_hash,
        });
    }

    pub fn is_decrypted(&self) -> bool {
        if self.data.len() < 0x21 { return false; }
        // pairing[0] is at offset 0x20 into payload (absolute 0x30)
        self.data[0x20] == 0x00
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = size_aligned as usize - 0x10; // total payload size after 0x10 header

        if self.data.len() < payload_len { return; }

        // rotsum covers first 0x20 bytes (header + version info)
        // and everything from cg_hmac (0x320 rel / 0x330 abs) to the end
        let mut combined_header = [0u8; 0x20];
        combined_header[..0x10].copy_from_slice(&IntoBytes::as_bytes(&self.header)[..0x10]);
        combined_header[0x10..].copy_from_slice(&self.data[0x0..0x10]);

        if let Ok(hash) = excrypt::rot_sum_sha(
            &combined_header,
            &self.data[0x320..payload_len],
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn verify_signature(&self, rsa_1bl: &ExCryptRsa) -> bool {
        let mut cf_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut cf_hash);

        if self.data.len() < 0x320 { return false; }
        let signature: &[u8; 256] = self.data[0x220..0x320].try_into().unwrap();

        let expected_salt = b"XBOX_ROM_6\0";
        excrypt::verify_signature(signature, &cf_hash, expected_salt, rsa_1bl).unwrap_or(false)
    }

    pub fn print_info(&self) {
        let indicator = if (self.header.magic.get() & 0xF000) == 0x5000 {
            "SF"
        } else {
            "CF"
        };
        info!("{} version: {}", indicator, self.header.version.get());
        info!("{} size: 0x{:x}", indicator, self.header.size.get());
        info!("{} entrypoint: 0x{:x}", indicator, self.header.entrypoint.get());

        if self.data.len() >= 0x10 {
            let base_ver = BigEndian::read_u16(&self.data[0x0..0x2]);
            let target_ver = BigEndian::read_u16(&self.data[0x4..0x6]);
            let cg_size = BigEndian::read_u32(&self.data[0xC..0x10]);

            info!("{} base version: {}", indicator, base_ver);
            info!("{} target version: {}", indicator, target_ver);
            info!("{}-G size: 0x{:x}", indicator, cg_size);
        }

        if self.is_decrypted() {
            if let Some(ref meta) = self.metadata {
                info!("{}-G key: {:02x?}", indicator, meta.cg_hmac);
                info!("{}-G checksum: {:02x?}", indicator, meta.cg_hash);
            } else if self.data.len() >= 0x334 {
                info!("{}-G key: {:02x?}", indicator, &self.data[0x310..0x320]);
                info!("{}-G checksum: {:02x?}", indicator, &self.data[0x320..0x334]);
            }
            info!("{} signature: (requires keys to verify)", indicator);
        } else {
            info!("{} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, onebl_key: &[u8; 16]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = (size_aligned - 0x10) as usize; // size of data after the header

        if self.data.len() < payload_size { return; }

        // HMAC key for CF is at Absolute 0x20, which is data[0x10..0x20]
        if let Ok(derived_key) = excrypt::hmac_sha(onebl_key, &[&self.data[0x10..0x20]]) {
            let mut final_key = [0u8; 16];
            final_key.copy_from_slice(&derived_key[..16]);
            info!(" -> CF Decryption Key Derived: {:02x?}", final_key);

            if let Ok(mut rc4) = Rc4::new(&final_key) {
                // Encryption starts at pairing, which is 0x20 deep into the payload (0x30 deep into file)
                let _ = rc4.crypt(&mut self.data[0x20..payload_size]);
            }
        }
    }

    /// Verifies that a CF bootloader has been successfully decrypted.
    /// Based on x360Utils Cryptography.VerifyCFDecrypted():
    /// After decryption, bytes 0x1F0..0x210 (0x20 bytes) should be all zeros.
    /// This region is part of the `pairing` data in the decrypted CF payload.
    /// Note: x360Utils offsets are from the full bootloader start (including 16-byte header).
    /// gxBuild's `data` field is the payload AFTER the header, so we subtract 0x10.
    pub fn verify_decrypted(&self) -> bool {
        if self.data.len() < 0x200 { return false; }
        self.data[0x1E0..0x200].iter().all(|&b| b == 0)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
