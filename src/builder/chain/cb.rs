/*
    cb.rs - Handling for Xbox 360 CB/2BL bootloader stages.
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
use log::info;
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Error, Debug)]
pub enum CbError {
    #[error("CB data too short: got {got}, need {need}")]
    DataTooShort { got: usize, need: usize },
    #[error("Failed to parse CB header")]
    ParseError,
    #[error("HMAC-SHA key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("RC4 initialization failed: {0}")]
    Rc4Init(String),
    #[error("RC4 decryption failed: {0}")]
    Rc4Crypt(String),
}

pub type Result<T> = std::result::Result<T, CbError>;

impl From<CbError> for String {
    fn from(e: CbError) -> Self {
        e.to_string()
    }
}

#[derive(Clone, Debug)]
pub struct CbMetadata {
    pub b_flags: u16,

    pub pairing_data: [u8; 3],
    pub lockdown_value: u8,
    pub reserved_per_box: [u8; 0xC],
    pub per_box_digest: [u8; 0x10],

    pub signature: [u8; 0x100],
    pub rsa_pub_key: [u8; 0x110],
    pub nonce_3bl: [u8; 0x10],
    pub salt_3bl: [u8; 0xA],
    pub salt_4bl: [u8; 0xA],
    pub digest_4bl: [u8; 0x14],

    pub post_output_addr: u64,
    pub sb_flash_addr: u64,
    pub soc_mmio_addr: u64,

    pub console_allow: [u8; 4],
}

#[derive(Clone)]
pub struct BootloaderCb {
    pub header: BootloaderHeader,
    pub data: Vec<u8>,
    pub metadata: Option<CbMetadata>,
    pub derived_key: Option<[u8; 16]>,
    pub decrypted: bool,
}

impl BootloaderCb {
    pub fn new(bytes: &[u8]) -> Self {
        let (header, payload) = match BootloaderHeader::read_from_prefix(bytes) {
            Ok(result) => result,
            Err(_) => {
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
                    decrypted: false,
                };
            }
        };

        let mut cb = Self {
            header: header.clone(),
            data: payload.to_vec(),
            metadata: None,
            derived_key: None,
            decrypted: false,
        };
        cb.decrypted = cb.verify_decrypted();
        cb.populate_metadata();
        cb
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        let (header, payload) =
            BootloaderHeader::read_from_prefix(data).map_err(|_| CbError::ParseError)?;
        let mut cb = Self {
            header: header.clone(),
            data: payload.to_vec(),
            metadata: None,
            derived_key: None,
            decrypted: false,
        };
        cb.decrypted = cb.verify_decrypted();
        cb.populate_metadata();
        Ok(cb)
    }

    pub fn populate_metadata(&mut self) {
        if !self.is_decrypted() || self.data.len() < 0x3B0 {
            return;
        }
        self.populate_metadata_unchecked();
    }

    pub fn populate_metadata_unchecked(&mut self) {
        if self.data.len() < 0x3B0 {
            return;
        }

        let pd_raw: [u8; 3] = self.data[0x10..0x13].try_into().unwrap();

        info!(
            "[cb] PD raw bytes at self.data[0x10..0x13]: {:02x?}",
            pd_raw
        );

        let mut pairing_data = pd_raw;
        pairing_data.reverse();

        let ldv_raw = self.data.get(0x13).copied().unwrap_or(0);
        let lockdown_value = if ldv_raw <= 16 { ldv_raw } else { 0 };

        info!(
            "[cb] populate_metadata: PD={:02x?} LDV={} (raw={} at self.data[0x13])",
            pairing_data, lockdown_value, ldv_raw
        );

        // 15432 CB_X
        if self.header.version.get() == 0x3C48 {
            // lockdown_value = 0;
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

    pub fn sync_metadata(&mut self) {
        if let Some(ref meta) = self.metadata {
            if self.data.len() < 0x3A4 {
                return;
            }

            let mut pd_sync = meta.pairing_data;
            pd_sync.reverse(); // Reverse back for storage
            self.data[0x10..0x13].copy_from_slice(&pd_sync);
            self.data[0x13] = meta.lockdown_value;

            self.data[0x14..0x20].copy_from_slice(&meta.reserved_per_box);
            self.data[0x20..0x30].copy_from_slice(&meta.per_box_digest);

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

            if self.data.len() > 0x2400 && self.data[0x1FF0] == 0x43 && self.data[0x1FF1] == 0x42 {
                self.data[0x2010..0x2013].copy_from_slice(&pd_sync);
                self.data[0x2013] = meta.lockdown_value;
                self.data[0x2014..0x2020].copy_from_slice(&meta.reserved_per_box);
                self.data[0x2020..0x2030].copy_from_slice(&meta.per_box_digest);
                if self.data.len() >= 0x23A4 {
                    self.data[0x23A0..0x23A4].copy_from_slice(&meta.console_allow);
                }
                if self.data.len() > 0x23B1 {
                    self.data[0x23B1] = meta.lockdown_value;
                }
                info!("[pfa] Synchronized embedded CB_B metadata!");
            }
        }
    }

    pub fn recalculate_per_box_digest(
        &mut self,
        cpu_key: &[u8; 16],
        rc4_key: &[u8; 16],
        smc_hash: &[u8; 16],
    ) {
        if let Some(ref mut meta) = self.metadata {
            let mut data_to_hash = [0u8; 0x30];
            let mut pd_on_disk = meta.pairing_data;
            pd_on_disk.reverse();
            data_to_hash[0x00..0x10].copy_from_slice(rc4_key);
            data_to_hash[0x10..0x13].copy_from_slice(&pd_on_disk);
            data_to_hash[0x13] = meta.lockdown_value;
            data_to_hash[0x14..0x20].copy_from_slice(&meta.reserved_per_box);
            data_to_hash[0x20..0x30].copy_from_slice(smc_hash);

            if let Ok(digest) = hmac_sha(cpu_key, &[&data_to_hash]) {
                meta.per_box_digest.copy_from_slice(&digest[..16]);
                self.sync_metadata();
                info!("[builder] Recalculated CB PerBoxDigest with updated pairing data");
            }
        }
    }

    pub fn is_decrypted(&self) -> bool {
        self.decrypted || self.verify_decrypted()
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = size_aligned as usize - 0x10;

        if self.data.len() < payload_len {
            return;
        }

        // rotsum covers first 0x10 bytes (header) and everything from globals (0x130 rel / 0x140 abs) to the end
        if let Ok(hash) = rot_sum_sha(
            &IntoBytes::as_bytes(&self.header)[..0x10],
            &self.data[0x130..payload_len],
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn verify_signature(&self, rsa_1bl: &ExCryptRsa) -> bool {
        let mut cb_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut cb_hash);

        if self.data.len() < 0x130 {
            return false;
        }
        let signature: &[u8; 256] = self.data[0x30..0x130].try_into().unwrap(); // Absolute 0x40

        let expected_salt = b"XBOX_ROM_2\0";
        verify_signature(signature, &cb_hash, expected_salt, rsa_1bl).unwrap_or(false)
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

        if self.data.len() >= 0x30 && self.data[0x30] == 0 {
            indicator = "CB_B";
        }

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

        if self.is_decrypted() {
            if let Some(ref meta) = self.metadata {
                info!("[builder] {} LDV: {}", indicator, meta.lockdown_value);
                info!(
                    "[builder] {} Pairing: {:02x?}",
                    indicator, meta.pairing_data
                );
                info!(
                    "[builder] {} Post Addr: 0x{:08X}",
                    indicator, meta.post_output_addr
                );
                info!(
                    "[builder] {} SB Flash: 0x{:08X}",
                    indicator, meta.sb_flash_addr
                );
                info!(
                    "[builder] {} SOC MMIO: 0x{:08X}",
                    indicator, meta.soc_mmio_addr
                );
                info!("[builder] {} Nonce 3BL: {:02x?}", indicator, meta.nonce_3bl);
                info!(
                    "[builder] {} Allow Mask: {:02x?}",
                    indicator, meta.console_allow
                );
                info!(
                    "[builder] {} Next Digest: {:02x?}",
                    indicator, meta.digest_4bl
                );
            } else {
                // Fallback to raw indexing if metadata wasn't populated
                info!("[builder] {} LDV: {}", indicator, self.data[0x13]);
                info!(
                    "[builder] {} next hash: {:02x?}",
                    indicator,
                    &self.data[0x38C..0x3A0]
                );
            }
            if self.data.len() >= 0x30 && self.data[0x30] != 0 {
                info!(
                    "[builder] {} signature: (requires keys to verify)",
                    indicator
                );
            }
        } else {
            info!("[builder] {} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, onebl_key: &[u8; 16]) -> Result<()> {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = size_aligned as usize - 0x10;

        if self.data.len() < payload_len {
            return Err(CbError::DataTooShort {
                got: self.data.len(),
                need: payload_len,
            });
        }

        // Derive RC4 key from 1BL key and the bootloader's key field.
        let derived_key = hmac_sha(onebl_key, &[&self.data[0..16]])
            .map_err(|e| CbError::KeyDerivation(e.to_string()))?;
        let mut decrypt_key = [0u8; 16];
        decrypt_key.copy_from_slice(&derived_key[..16]);
        self.derived_key = Some(decrypt_key);
        info!(
            "[builder] Decrypting CB using derived key: {:02x?}",
            decrypt_key
        );

        let mut rc4 = Rc4::new(&decrypt_key).map_err(|e| CbError::Rc4Init(e.to_string()))?;
        rc4.crypt(&mut self.data[0x10..payload_len])
            .map_err(|e| CbError::Rc4Crypt(e.to_string()))?;

        self.decrypted = !self.decrypted;
        if self.decrypted {
            self.populate_metadata();
        }
        Ok(())
    }

    pub fn decrypt_mfg(&mut self, cb_a_key: &[u8; 16]) -> Result<()> {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = size_aligned as usize - 0x10;

        if self.data.len() < payload_len {
            return Err(CbError::DataTooShort {
                got: self.data.len(),
                need: payload_len,
            });
        }

        // MFG key is all zeros
        let zero_key = [0u8; 16];

        // Build HMAC input: cb_b_key (0x10) + cb_a_key (0x10)
        let mut hmac_input = [0u8; 0x20];
        hmac_input[..0x10].copy_from_slice(&self.data[0..0x10]); // cb_b_hdr.key
        hmac_input[0x10..0x20].copy_from_slice(cb_a_key); // cb_a derived key

        let derived_key = hmac_sha(&zero_key, &[&hmac_input])
            .map_err(|e| CbError::KeyDerivation(e.to_string()))?;
        let mut decrypt_key = [0u8; 16];
        decrypt_key.copy_from_slice(&derived_key[..16]);
        self.derived_key = Some(decrypt_key);
        info!(
            "[builder] Decrypting CB (MFG zero-key) using derived key: {:02x?}",
            decrypt_key
        );

        let mut rc4 = Rc4::new(&decrypt_key).map_err(|e| CbError::Rc4Init(e.to_string()))?;
        rc4.crypt(&mut self.data[0x10..payload_len])
            .map_err(|e| CbError::Rc4Crypt(e.to_string()))?;

        self.decrypted = !self.decrypted;
        if self.decrypted {
            self.populate_metadata();
        }
        Ok(())
    }

    pub fn verify_decrypted(&self) -> bool {
        if self.data.len() < 0x380 {
            return false;
        }
        self.data[0x260..0x380].iter().all(|&b| b == 0)
    }

    pub fn decrypt_v1(&mut self, cb_a_key: &[u8; 16], cpu_key: &[u8; 16]) -> Result<()> {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = size_aligned as usize - 0x10;

        if self.data.len() < payload_len {
            return Err(CbError::DataTooShort {
                got: self.data.len(),
                need: payload_len,
            });
        }

        // C: ExCryptHmacSha(cb_a_key, cb_b_key, cpu_key, ..., cb_b_key) - writes back in-place.
        let derived_key = hmac_sha(cb_a_key, &[&self.data[0..16], cpu_key])
            .map_err(|e| CbError::KeyDerivation(e.to_string()))?;
        let mut decrypt_key = [0u8; 16];
        decrypt_key.copy_from_slice(&derived_key[..16]);
        self.derived_key = Some(decrypt_key);

        let mut rc4 = Rc4::new(&decrypt_key).map_err(|e| CbError::Rc4Init(e.to_string()))?;
        rc4.crypt(&mut self.data[0x10..payload_len])
            .map_err(|e| CbError::Rc4Crypt(e.to_string()))?;

        self.decrypted = !self.decrypted;
        if self.decrypted {
            self.populate_metadata();
        }

        Ok(())
    }

    pub fn decrypt_v2(
        &mut self,
        cb_a_hdr: &BootloaderHeader,
        cb_a_key: &[u8; 16],
        cpu_key: &[u8; 16],
    ) -> Result<()> {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = size_aligned as usize - 0x10;

        if self.data.len() < payload_len {
            return Err(CbError::DataTooShort {
                got: self.data.len(),
                need: payload_len,
            });
        }

        // Build HMAC input for v2 crypto
        let mut cb_a_hdr_copy: [u8; 16] =
            zerocopy::IntoBytes::as_bytes(cb_a_hdr).try_into().unwrap();
        cb_a_hdr_copy[0x6] = 0; // Clear wFlags low byte
        cb_a_hdr_copy[0x7] = 0; // Clear wFlags high byte

        let derived_key = hmac_sha(cb_a_key, &[&self.data[0..16], cpu_key, &cb_a_hdr_copy])
            .map_err(|e| CbError::KeyDerivation(e.to_string()))?;
        let mut decrypt_key = [0u8; 16];
        decrypt_key.copy_from_slice(&derived_key[..16]);
        self.derived_key = Some(decrypt_key);
        info!("[cb] CB_B v2 key derived successfully");

        let mut rc4 = Rc4::new(&decrypt_key).map_err(|e| CbError::Rc4Init(e.to_string()))?;
        rc4.crypt(&mut self.data[0x10..payload_len])
            .map_err(|e| CbError::Rc4Crypt(e.to_string()))?;
        info!("[cb] CB_B v2 RC4 decryption successful");

        self.decrypted = !self.decrypted;
        if self.decrypted {
            self.populate_metadata();
        }

        Ok(())
    }

    pub fn derive_key_from_nonce(&self, onebl_key: &[u8; 16]) -> Option<[u8; 16]> {
        let nonce = self.data.get(0..16)?;
        let derived = hmac_sha(onebl_key, &[nonce]).ok()?;
        let mut key = [0u8; 16];
        key.copy_from_slice(&derived[..16]);
        Some(key)
    }

    pub fn derive_split_key_v1(
        &self,
        cb_a_key: &[u8; 16],
        cpu_key: &[u8; 16],
    ) -> Option<[u8; 16]> {
        let nonce = self.data.get(0..16)?;
        let derived = hmac_sha(cb_a_key, &[nonce, cpu_key]).ok()?;
        let mut key = [0u8; 16];
        key.copy_from_slice(&derived[..16]);
        Some(key)
    }

    pub fn derive_split_key_v2(
        &self,
        cb_a_hdr: &BootloaderHeader,
        cb_a_key: &[u8; 16],
        cpu_key: &[u8; 16],
    ) -> Option<[u8; 16]> {
        let nonce = self.data.get(0..16)?;
        let mut cb_a_hdr_copy: [u8; 16] = zerocopy::IntoBytes::as_bytes(cb_a_hdr).try_into().ok()?;
        cb_a_hdr_copy[0x6] = 0;
        cb_a_hdr_copy[0x7] = 0;
        let derived = hmac_sha(cb_a_key, &[nonce, cpu_key, &cb_a_hdr_copy]).ok()?;
        let mut key = [0u8; 16];
        key.copy_from_slice(&derived[..16]);
        Some(key)
    }

    /// Returns the derived RC4 key if decryption has been performed.
    pub fn derived_key(&self) -> Option<[u8; 16]> {
        self.derived_key
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = zerocopy::IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
