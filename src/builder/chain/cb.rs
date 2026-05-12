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
    // Basic / Legacy
    pub ldv: u8,
    pub b_flags: u16,         
    
    // PerBoxData (Offset 0x10 in payload)
    pub pairing_data: [u8; 3],
    pub lockdown_value: u8,
    pub reserved_per_box: [u8; 0xC],
    pub per_box_digest: [u8; 0x10],

    // Chain Metadata (Decrypted)
    pub signature: [u8; 0x100],
    pub rsa_pub_key: [u8; 0x110],
    pub nonce_3bl: [u8; 0x10],
    pub salt_3bl: [u8; 0xA],
    pub salt_4bl: [u8; 0xA],
    pub digest_4bl: [u8; 0x14],

    // Hardware/Debug Hooks
    pub post_output_addr: u64,
    pub sb_flash_addr: u64,
    pub soc_mmio_addr: u64,
    
    // Security/Policy
    pub console_allow: [u8; 4],
}

#[derive(Clone)]
pub struct BootloaderCb {
    pub header: BootloaderHeader,
    pub data: Vec<u8>,
    pub metadata: Option<CbMetadata>,
    pub derived_key: Option<[u8; 16]>,
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
                    derived_key: None,
                };
            }
        };

        let mut cb = Self {
            header: header.clone(),
            data: payload.to_vec(),
            metadata: None,
            derived_key: None,
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
            derived_key: None,
        };
        // Attempt to populate metadata if the size looks like a decrypted or valid CB
        cb.populate_metadata();
        Ok(cb)
    }

    pub fn populate_metadata(&mut self) {
        // is_decrypted() checks CB_A zero-padding. CB_B never has this, so for
        // post-decrypt_v1 calls use populate_metadata_unchecked directly.
        if !self.is_decrypted() || self.data.len() < 0x3B0 { return; }
        self.populate_metadata_unchecked();
    }

    /// Populates metadata unconditionally (no is_decrypted guard).
    /// Use after decrypt_v1 for CB_B, which lacks CB_A's zero-padding region.
    pub fn populate_metadata_unchecked(&mut self) {
        if self.data.len() < 0x3B0 { return; }

        // Mappings (+0x10 from RGBuild DecryptedData offsets)
        // Absolute 0x20 = self.data[0x10]
        let mut pairing_data: [u8; 3] = self.data[0x10..0x13].try_into().unwrap();
        pairing_data.reverse(); // J-Runner reverses the 3 bytes

        // Absolute 0x23 = self.data[0x13]
        let mut lockdown_value = self.data[0x13];
        
        // J-Runner check: if bootloader starts with specific branch, LDV is 0
        // cb_dec[0x02] and cb_dec[0x03] correspond to the version field in the header.
        if self.header.version.get() == 0x3C48 {
            lockdown_value = 0;
        }

        let reserved_per_box: [u8; 0xC] = self.data[0x14..0x20].try_into().unwrap();
        let per_box_digest: [u8; 0x10] = self.data[0x20..0x30].try_into().unwrap();
        
        let mut signature = [0u8; 0x100];
        signature.copy_from_slice(&self.data[0x30..0x130]); 

        let post_output_addr = u64::from_be_bytes(self.data[0x240..0x248].try_into().unwrap());
        let sb_flash_addr = u64::from_be_bytes(self.data[0x248..0x250].try_into().unwrap());
        let soc_mmio_addr = u64::from_be_bytes(self.data[0x250..0x258].try_into().unwrap());

        let mut rsa_pub_key = [0u8; 0x110];
        rsa_pub_key.copy_from_slice(&self.data[0x258..0x368]);

        let mut nonce_3bl = [0u8; 0x10];
        nonce_3bl.copy_from_slice(&self.data[0x368..0x378]);

        let mut salt_3bl = [0u8; 0xA];
        salt_3bl.copy_from_slice(&self.data[0x378..0x382]);

        let mut salt_4bl = [0u8; 0xA];
        salt_4bl.copy_from_slice(&self.data[0x382..0x38C]);

        let mut digest_4bl = [0u8; 0x14];
        digest_4bl.copy_from_slice(&self.data[0x38C..0x3A0]);

        let mut console_allow = [0u8; 4];
        console_allow.copy_from_slice(&self.data[0x3A0..0x3A4]);

        self.metadata = Some(CbMetadata {
            ldv: lockdown_value,
            b_flags: self.header.flags.get(), 
            pairing_data,
            lockdown_value,
            reserved_per_box,
            per_box_digest,
            signature,
            post_output_addr,
            sb_flash_addr,
            soc_mmio_addr,
            rsa_pub_key,
            nonce_3bl,
            salt_3bl,
            salt_4bl,
            digest_4bl,
            console_allow,
        });
    }

    /// Synchronizes the high-level metadata object back into the raw bootloader payload.
    /// This ensures that any edits made to the metadata are carried over to the final image.
    pub fn sync_metadata(&mut self) {
        if let Some(ref meta) = self.metadata {
            if self.data.len() < 0x3A4 { return; }

            let mut pd_sync = meta.pairing_data;
            pd_sync.reverse(); // Reverse back for storage
            self.data[0x10..0x13].copy_from_slice(&pd_sync);
            self.data[0x13] = meta.lockdown_value;
            self.data[0x3A1] = meta.lockdown_value; // J-Runner display offset
            
            self.data[0x14..0x20].copy_from_slice(&meta.reserved_per_box);
            self.data[0x20..0x30].copy_from_slice(&meta.per_box_digest);
            
            // If this is a combined CB (like CB_6750), it contains an embedded CB_B.
            // External tools like J-Runner-with-Extras will decrypt the payload and read the LDV from CB_B.
            // We must sync the metadata to the embedded CB_B as well.
            if self.data.len() > 0x2400 && self.data[0x1FF0] == 0x43 && self.data[0x1FF1] == 0x42 {
                self.data[0x2010..0x2013].copy_from_slice(&pd_sync);
                self.data[0x2013] = meta.lockdown_value;
                self.data[0x23B1] = meta.lockdown_value;
                self.data[0x2014..0x2020].copy_from_slice(&meta.reserved_per_box);
                self.data[0x2020..0x2030].copy_from_slice(&meta.per_box_digest);
                info!("[pfa] Synchronized embedded CB_B metadata!");
            }

            self.data[0x30..0x130].copy_from_slice(&meta.signature);

            self.data[0x240..0x248].copy_from_slice(&meta.post_output_addr.to_be_bytes());
            self.data[0x248..0x250].copy_from_slice(&meta.sb_flash_addr.to_be_bytes());
            self.data[0x250..0x258].copy_from_slice(&meta.soc_mmio_addr.to_be_bytes());

            self.data[0x258..0x368].copy_from_slice(&meta.rsa_pub_key);
            self.data[0x368..0x378].copy_from_slice(&meta.nonce_3bl);
            self.data[0x378..0x382].copy_from_slice(&meta.salt_3bl);
            self.data[0x382..0x38C].copy_from_slice(&meta.salt_4bl);
            self.data[0x38C..0x3A0].copy_from_slice(&meta.digest_4bl);
            self.data[0x3A0..0x3A4].copy_from_slice(&meta.console_allow);
        }
    }

    pub fn recalculate_per_box_digest(&mut self, cpu_key: &[u8; 16]) {
        if let Some(ref mut meta) = self.metadata {
            let mut data_to_hash = [0u8; 0x10];
            data_to_hash[0..3].copy_from_slice(&meta.pairing_data);
            data_to_hash[3] = meta.lockdown_value;
            data_to_hash[4..16].copy_from_slice(&meta.reserved_per_box);

            if let Ok(digest) = excrypt::hmac_sha(cpu_key, &[&data_to_hash]) {
                meta.per_box_digest.copy_from_slice(&digest[..16]);
                self.sync_metadata();
                info!("[builder] Recalculated CB PerBoxDigest with updated pairing data");
            }
        }
    }

    pub fn is_decrypted(&self) -> bool {
        if self.data.len() < 0x380 { return false; }
        // Use the zero-padding chunk (CB[0x270:0x390] relative to 0x10 header offset) to verify success
        self.data[0x260..0x380].iter().all(|&b| b == 0)
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
                info!("[builder] {} Pairing: {:02x?}", indicator, meta.pairing_data);
                info!("[builder] {} Post Addr: 0x{:08X}", indicator, meta.post_output_addr);
                info!("[builder] {} SB Flash: 0x{:08X}", indicator, meta.sb_flash_addr);
                info!("[builder] {} SOC MMIO: 0x{:08X}", indicator, meta.soc_mmio_addr);
                info!("[builder] {} Nonce 3BL: {:02x?}", indicator, meta.nonce_3bl);
                info!("[builder] {} Allow Mask: {:02x?}", indicator, meta.console_allow);
                info!("[builder] {} Next Digest: {:02x?}", indicator, meta.digest_4bl);
            } else {
                // Fallback to raw indexing if metadata wasn't populated
                info!("[builder] {} LDV: {}", indicator, self.data[0x13]);
                info!("[builder] {} next hash: {:02x?}", indicator, &self.data[0x38C..0x3A0]);
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
            self.derived_key = Some(decrypt_key);
            info!("[builder] Decrypting CB using derived key: {:02x?}", decrypt_key);
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                let _ = rc4.crypt(&mut self.data[0x10..payload_len]);
            }
        }
        self.populate_metadata();
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
            self.derived_key = Some(decrypt_key);
            info!("[builder] Decrypting CB (MFG zero-key) using derived key: {:02x?}", decrypt_key);
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                let _ = rc4.crypt(&mut self.data[0x10..payload_len]);
            }
        }
        self.populate_metadata();
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

        // C: ExCryptHmacSha(cb_a_key, cb_b_key, cpu_key, ..., cb_b_key) - writes back in-place.
        if let Ok(derived_key) = excrypt::hmac_sha(cb_a_key, &[&self.data[0..16], cpu_key]) {
            let mut decrypt_key = [0u8; 16];
            decrypt_key.copy_from_slice(&derived_key[..16]);
            self.derived_key = Some(decrypt_key);
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                let _ = rc4.crypt(&mut self.data[0x10..payload_len]);
            }
        }
        // Note: populate_metadata_unchecked is NOT called here intentionally.
        // RC4 is symmetric so decrypt_v1 is used for both decryption (decrypt_chain)
        // and re-encryption (encrypt_chain). Calling it here on the encrypt path
        // would re-read ciphertext and corrupt the synced metadata.
        // decrypt_chain calls populate_metadata_unchecked explicitly after this.
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
            self.derived_key = Some(decrypt_key);
            
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                let _ = rc4.crypt(&mut self.data[0x10..payload_len]);
            }
        }
        // Same as decrypt_v1: no populate_metadata here (called for both encrypt and decrypt passes).
    }
    /// Returns the 16-byte value at `data[0..16]`.
    /// - In **encrypted** state: this is the original nonce.
    /// - In **decrypted** state (after `decrypt()` / `decrypt_v1()`): the nonce has been
    ///   overwritten in-place by `HMAC(inkey, nonce)`, i.e. the derived chain key.
    ///   CD and CE must be decrypted with this key on split (CB_A+CB_B) and glitch3 layouts.
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

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = zerocopy::IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
