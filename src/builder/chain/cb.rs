/*
    cb.rs - Handling for Xbox 360 CB/2BL bootloader stages.
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

    

use super::BootloaderHeader;
use crate::builder::deps::excrypt::{self, Rc4, ExCryptRsa};
use zerocopy::{FromBytes, IntoBytes};
use log::info;

#[derive(Clone, Debug)]
pub struct CbMetadata {
    pub ldv: u8,
    pub b_flags: u16,         // Often unused in v2
    pub signature: [u8; 0x100],
    pub cd_cbb_hash: [u8; 0x14],
}

#[derive(Clone)]
pub struct BootloaderCb {
    pub header: BootloaderHeader,
    pub data: Vec<u8>,
    pub metadata: Option<CbMetadata>,
}

impl BootloaderCb {
    /// Construct a CB bootloader from raw binary data (full blob including header).
    /// This matches xenon-bltool's pattern of working directly with raw byte buffers.
    /// The input should be the complete CB binary as found in a NAND image or bootloader file.
    pub fn new(bytes: &[u8]) -> Self {
        // Parse header from the beginning of the data
        let (header, payload) = match BootloaderHeader::read_from_prefix(bytes) {
            Ok(result) => result,
            Err(_) => {
                // If parsing fails, create an empty placeholder
                // This allows construction to succeed even with invalid data
                let empty_header = BootloaderHeader {
                    magic: zerocopy::byteorder::U16::new(0),
                    version: zerocopy::byteorder::U16::new(0),
                    pairing: zerocopy::byteorder::U16::new(0),
                    flags: zerocopy::byteorder::U16::new(0),
                    entrypoint: zerocopy::byteorder::U32::new(0),
                    size: zerocopy::byteorder::U32::new(0),
                };
                return Self {
                    header: empty_header,
                    data: bytes.to_vec(),
                    metadata: None,
                };
            }
        };

        let mut cb = Self {
            header: header.clone(),
            data: payload.to_vec(),
            metadata: None,
        };
        // Attempt to populate metadata if the size looks like a decrypted or valid CB
        cb.populate_metadata();
        cb
    }

    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let (header, payload) = BootloaderHeader::read_from_prefix(data)
            .map_err(|_| "Failed to parse CB header")?;
        let mut cb = Self {
            header: header.clone(),
            data: payload.to_vec(),
            metadata: None,
        };
        // Attempt to populate metadata if the size looks like a decrypted or valid CB
        cb.populate_metadata();
        Ok(cb)
    }

    pub fn populate_metadata(&mut self) {
        if !self.is_decrypted() || self.data.len() < 0x3B6 { return; }

        let mut signature = [0u8; 0x100];
        // signature is after header (16), key (16), padding (32) = 64 bytes (Absolute 0x40)
        // 0x40 - 0x10 (pay start) = 0x30 relative
        signature.copy_from_slice(&self.data[0x30..0x130]); 

        let mut next_hash = [0u8; 0x14];
        // cd_cbb_hash is at Absolute 0x39C. Rel = 0x38C
        next_hash.copy_from_slice(&self.data[0x38C..0x3A0]); 

        // more_globals[1] (LDV) is at Absolute 0x3B1. Rel = 0x3A1
        let ldv = self.data[0x3A1];

        self.metadata = Some(CbMetadata {
            ldv,
            b_flags: 0, 
            signature,
            cd_cbb_hash: next_hash,
        });
    }

    pub fn is_decrypted(&self) -> bool {
        if self.data.len() < 0x241 { return false; }
        // globals[0x110] is at Absolute 0x250. 
        // Payload (data) starts at 0x10, so 0x250 - 0x10 = 0x240
        self.data[0x240] == 0x80
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = size_aligned as usize - 0x10;

        if self.data.len() < payload_len { return; }

        // rotsum covers first 0x10 bytes (header)
        // and everything from globals (0x130 rel / 0x140 abs) to the end
        if let Ok(hash) = excrypt::rot_sum_sha(
            &IntoBytes::as_bytes(&self.header)[..0x10],
            &self.data[0x130..payload_len], 
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn verify_signature(&self, rsa_1bl: &ExCryptRsa) -> bool {
        let mut cb_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut cb_hash);

        if self.data.len() < 0x130 { return false; }
        let signature: &[u8; 256] = self.data[0x30..0x130].try_into().unwrap(); // Absolute 0x40

        let expected_salt = b"XBOX_ROM_2\0";
        excrypt::verify_signature(signature, &cb_hash, expected_salt, rsa_1bl).unwrap_or(false)
    }

    pub fn print_info(&self) {
        let magic = self.header.magic.get();
        let mut indicator = if (magic & 0xF000) == 0x5000 {
            "SB"
        } else {
            "CB"
        };

        if (self.header.flags.get() & 0x800) == 0x800 {
            indicator = "CB_A";
        }

        if self.data.len() >= 0x30 && self.data[0x30] == 0 { // absolute 0x40
            indicator = "CB_B";
        }

        info!("[builder] {} version: {}", indicator, self.header.version.get());
        info!("[builder] {} size: 0x{:x}", indicator, self.header.size.get());
        info!(
            "[builder] {} entrypoint: 0x{:x}",
            indicator,
            self.header.entrypoint.get()
        );

        if self.is_decrypted() {
            if let Some(ref meta) = self.metadata {
                info!("[builder] {} LDV: {}", indicator, meta.ldv);
                info!("[builder] {} next hash: {:02x?}", indicator, meta.cd_cbb_hash);
            } else {
                // Fallback to raw indexing if metadata wasn't populated
                info!("[builder] {} LDV: {}", indicator, self.data[0x391]);
                info!("[builder] {} next hash: {:02x?}", indicator, &self.data[0x37C..0x390]);
            }
            if self.data.len() >= 0x30 && self.data[0x30] != 0 {
                info!("[builder] {} signature: (requires keys to verify)", indicator);
            }
        } else {
            info!("[builder] {} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, onebl_key: &[u8; 16]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = size_aligned as usize - 0x10;

        if self.data.len() < payload_len { return; }

        // Derive RC4 key from 1BL key and the bootloader's key field.
        // Matches xenon-bltool's cb_decrypt: writes derived key back into data[0..16] in-place.
        if let Ok(derived_key) = excrypt::hmac_sha(onebl_key, &[&self.data[0..16]]) {
            let mut decrypt_key = [0u8; 16];
            decrypt_key.copy_from_slice(&derived_key[..16]);
            self.data[0..16].copy_from_slice(&decrypt_key);
            info!("[builder] Decrypting CB using derived key: {:02x?}", decrypt_key);
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                let _ = rc4.crypt(&mut self.data[0x10..payload_len]);
            }
        }
    }

    /// Decrypts a CB_B bootloader using MFG (manufacturing) zero-key.
    /// Based on x360Utils Cryptography.DecryptBootloaderCB with BlEncryptionTypes.MfgCbb (0x801).
    /// The "inkey" is all zeros, and the HMAC input combines cb_b_key + cb_a_key.
    ///
    /// # Arguments
    /// * `cb_a_key` - The derived RC4 key from the CB_A bootloader (payload key at offset 0x10)
    pub fn decrypt_mfg(&mut self, cb_a_key: &[u8; 16]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = size_aligned as usize - 0x10;

        if self.data.len() < payload_len { return; }

        // MFG key is all zeros
        let zero_key = [0u8; 16];

        // Build HMAC input: cb_b_key (0x10) + cb_a_key (0x10)
        let mut hmac_input = [0u8; 0x20];
        hmac_input[..0x10].copy_from_slice(&self.data[0..0x10]); // cb_b_hdr.key
        hmac_input[0x10..0x20].copy_from_slice(cb_a_key);         // cb_a derived key

        if let Ok(derived_key) = excrypt::hmac_sha(&zero_key, &[&hmac_input]) {
            let mut decrypt_key = [0u8; 16];
            decrypt_key.copy_from_slice(&derived_key[..16]);
            info!("[builder] Decrypting CB (MFG zero-key) using derived key: {:02x?}", decrypt_key);
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                let _ = rc4.crypt(&mut self.data[0x10..payload_len]);
            }
        }
    }

    /// Verifies that a CB bootloader has been successfully decrypted.
    /// Based on x360Utils Cryptography.VerifyCBDecrypted():
    /// After decryption, bytes 0x270..0x390 (0x120 bytes) should be all zeros.
    /// This region corresponds to `globals[0x128..0x248]` in the decrypted CB payload.
    /// Note: x360Utils offsets are from the full bootloader start (including 16-byte header).
    /// gxBuild's `data` field is the payload AFTER the header, so we subtract 0x10.
    pub fn verify_decrypted(&self) -> bool {
        if self.data.len() < 0x380 { return false; }
        self.data[0x260..0x380].iter().all(|&b| b == 0)
    }

    pub fn decrypt_v1(&mut self, cb_a_key: &[u8; 16], cpu_key: &[u8; 16]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = size_aligned as usize - 0x10;

        if self.data.len() < payload_len { return; }

        // C: ExCryptHmacSha(cb_a_key, cb_b_key, cpu_key, ..., cb_b_key) — writes back in-place.
        if let Ok(derived_key) = excrypt::hmac_sha(cb_a_key, &[&self.data[0..16], cpu_key]) {
            let mut decrypt_key = [0u8; 16];
            decrypt_key.copy_from_slice(&derived_key[..16]);
            self.data[0..16].copy_from_slice(&decrypt_key);
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                let _ = rc4.crypt(&mut self.data[0x10..payload_len]);
            }
        }
    }

    pub fn decrypt_v2(&mut self, cb_a_hdr: &BootloaderHeader, cb_a_key: &[u8; 16], cpu_key: &[u8; 16]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = size_aligned as usize - 0x10;

        if self.data.len() < payload_len { return; }

        // copy cb_a_hdr's BootloaderHeader and nullify flags
        let mut cb_a_hdr_copy = cb_a_hdr.clone();
        cb_a_hdr_copy.flags.set(0);

        if let Ok(derived_key) = excrypt::hmac_sha(
            cb_a_key, 
            &[&self.data[0..16], cpu_key, &IntoBytes::as_bytes(&cb_a_hdr_copy)[..0x10]]
        ) {
            let mut decrypt_key = [0u8; 16];
            decrypt_key.copy_from_slice(&derived_key[..16]);
            
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                let _ = rc4.crypt(&mut self.data[0x10..payload_len]);
            }
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = zerocopy::IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
