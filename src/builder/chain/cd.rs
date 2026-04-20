/*
    cd.rs - Handling for Xbox 360 CD/4BL bootloader stages.
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
use log::info;

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
}

impl BootloaderCd {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let (header, payload) = BootloaderHeader::read_from_prefix(data)
            .map_err(|_| "Failed to parse CD header")?;
        let mut cd = Self {
            header: header.clone(),
            data: payload.to_vec(),
            metadata: None,
        };
        cd.populate_metadata();
        Ok(cd)
    }

    pub fn populate_metadata(&mut self) {
        if !self.is_decrypted() || self.data.len() < 0x250 { return; }

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
            if self.data.len() < 0x250 { return; }

            self.data[0x10..0x110].copy_from_slice(&meta.signature);
            self.data[0x110..0x220].copy_from_slice(&meta.rsa_pub_key);
            self.data[0x220..0x230].copy_from_slice(&meta.nonce_6bl);
            self.data[0x230..0x23A].copy_from_slice(&meta.salt_6bl);
            self.data[0x23C..0x250].copy_from_slice(&meta.digest_5bl);
        }
    }

    pub fn is_decrypted(&self) -> bool {
        if self.data.len() < 0x111 { return false; }
        // Matches xenon-bltool cd_is_decrypted(): hdr->idk_yet[0] == 0x00.
        // The idk_yet field is unnamed in all references; empirically always 0 when decrypted.
        self.data[0x110] == 0x00
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = (size_aligned - 0x10) as usize; // data after header

        if self.data.len() < payload_len { return; }

        if let Ok(hash) = excrypt::rot_sum_sha(
            &IntoBytes::as_bytes(&self.header)[..0x10],
            &self.data[0x110..payload_len], // Skip key and signature, start at idk_yet (0x110 rel)
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn print_info(&self) {
        let indicator = if (self.header.magic.get() & 0xF000) == 0x5000 {
            "SD"
        } else {
            "CD"
        };
        info!("[builder] {} version: {}", indicator, self.header.version.get());
        info!("[builder] {} size: 0x{:x}", indicator, self.header.size.get());
        info!("[builder] {} entrypoint: 0x{:x}", indicator, self.header.entrypoint.get());

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

    pub fn decrypt(&mut self, cbb_key: &[u8; 16], cpu_key: Option<&[u8; 16]>) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = (size_aligned - 0x10) as usize;

        if self.data.len() < payload_size { return; }

        // Derived key starts with CBB key and Absolute 0x10 key.
        // Matches xenon-bltool's cd_decrypt: writes derived key back into data[0..16] in-place.
        if let Ok(derived_key) = excrypt::hmac_sha(cbb_key, &[&self.data[0..16]]) {
            let mut final_key = [0u8; 16];
            final_key.copy_from_slice(&derived_key[..16]);
            info!("[builder] CD Decryption Key Derived: {:02x?}", final_key);

            // Optional CPU Key second-pass HMAC.
            // Present in xenon-bltool cd_decrypt() (source/cd-handler.c:64-65).
            // Currently always called with cpu_key = None for all known retail layouts.
            // Would be needed if a CD variant requiring a CPU-key second pass were encountered.
            if let Some(key) = cpu_key {
                if let Ok(derived_key_cpu) = excrypt::hmac_sha(key, &[&final_key]) {
                    final_key.copy_from_slice(&derived_key_cpu[..16]);
                }
            }

            self.data[0..16].copy_from_slice(&final_key);
            if let Ok(mut rc4) = Rc4::new(&final_key) {
                // Encryption starts at signature, which is 0x10 rel into payload (absolute 0x20)
                let _ = rc4.crypt(&mut self.data[0x10..payload_size]);
            }
        }
    }

    pub fn verify_signature_devkit(&self, pubkey: &ExCryptRsa) -> bool {
        let mut cd_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut cd_hash);

        if self.data.len() < 0x110 { return false; }
        let signature: &[u8; 256] = self.data[0x10..0x110].try_into().unwrap(); // Absolute 0x20

        let expected_salt = b"XBOX_ROM_4\0";
        excrypt::verify_signature(signature, &cd_hash, expected_salt, pubkey).unwrap_or(false)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = zerocopy::IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
