/*
  smc.rs - Handling for Xbox 360 SMC.

  Copyright (c) 2026 gxBuild Contributors and Developers

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/

use super::BootloaderHeader;
use crate::crypto::rsa::ExCryptRsa;
use crate::crypto::{rot_sum_sha, verify_signature};
use log::{info, warn};
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

#[derive(Error, Debug)]
pub enum SmcError {
    #[error("SMC data too short: got {got}, need {need}")]
    DataTooShort { got: usize, need: usize },
    #[error("Invalid SMC size in header")]
    InvalidSize,
    #[error("Failed to parse SMC header")]
    ParseError,
    #[error("Signature verification failed")]
    SignatureVerification,
}

pub type Result<T> = std::result::Result<T, SmcError>;

impl From<SmcError> for String {
    fn from(e: SmcError) -> Self {
        e.to_string()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmcType {
    Unknown = -1,
    Retail = 0,
    Glitch = 1,
    Jtag = 2,
    Cygnos = 3,
    RJtag = 4,
}

#[derive(Clone, Debug)]
pub struct SmcMetadata {
    pub smc_type: SmcType,
    pub console_type: u8,
    pub type_byte: u8,
    pub major_version: u8,
    pub minor_version: u8,
    pub lockdown_value: u8,
    pub pairing_data: [u8; 3],
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
pub struct SmcHeader {
    pub header: BootloaderHeader,
    pub signature: [u8; 0x100],
}

#[derive(Clone)]
pub struct Smc {
    pub header: SmcHeader,
    pub data: Vec<u8>,
    pub metadata: Option<SmcMetadata>,
}

impl Smc {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (header, payload) =
            SmcHeader::read_from_prefix(data).map_err(|_| SmcError::ParseError)?;
        let mut smc = Self {
            header: header.clone(),
            data: payload.to_vec(),
            metadata: None,
        };
        smc.populate_metadata();
        Ok(smc)
    }

    pub fn populate_metadata(&mut self) {
        if self.data.len() < 0x103 {
            warn!(
                "[smc] SMC data too short for metadata: got 0x{:x}, need 0x103",
                self.data.len()
            );
            return;
        }

        let type_byte = self.data[0x100];
        let major = self.data[0x101];
        let minor = self.data[0x102];
        let identified_type = self.identify_type();

        let ldv = self.data[0x103];
        let mut pd = [0u8; 3];
        if self.data.len() >= 0x107 {
            pd.copy_from_slice(&self.data[0x104..0x107]);
        }

        self.metadata = Some(SmcMetadata {
            smc_type: identified_type,
            console_type: (type_byte >> 4) & 0xF,
            type_byte,
            major_version: major,
            minor_version: minor,
            lockdown_value: ldv,
            pairing_data: pd,
        });

        if let Some(meta) = &self.metadata {
            info!(
                "[smc] Metadata: [{:?}] Type 0x{:02X}, Ver {}.{:02}",
                meta.smc_type, meta.type_byte, meta.major_version, meta.minor_version
            );
        }
    }

    pub fn identify_type(&self) -> SmcType {
        let mut identified = SmcType::Unknown;
        let mut glitch_patched = false;
        let mut retail_found = false;

        if self.data.len() < 8 {
            return identified;
        }

        for i in 0..self.data.len() - 6 {
            match self.data[i] {
                0x05 => {
                    if self.data[i + 2] == 0xE5
                        && self.data[i + 4] == 0xB4
                        && self.data[i + 5] == 0x05
                    {
                        retail_found = true;
                    }
                }
                0x00 => {
                    if self.data[i + 1] == 0x00
                        && self.data[i + 2] == 0xE5
                        && self.data[i + 4] == 0xB4
                        && self.data[i + 5] == 0x05
                    {
                        glitch_patched = true;
                    }
                }
                0x78 => {
                    if self.data[i + 1] == 0xBA && self.data[i + 2] == 0xB6 {
                        identified = SmcType::Cygnos;
                    }
                }
                0xD0 => {
                    if self.data[i + 1] == 0x00
                        && self.data[i + 2] == 0x00
                        && self.data[i + 3] == 0x1B
                    {
                        identified = SmcType::Jtag;
                    }
                }
                _ => {}
            }
        }

        if glitch_patched && !retail_found {
            return match identified {
                SmcType::Jtag => SmcType::RJtag,
                _ => SmcType::Glitch,
            };
        }

        if identified == SmcType::Unknown && retail_found {
            return SmcType::Retail;
        }

        identified
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) -> Result<()> {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = size_aligned as usize - std::mem::size_of::<SmcHeader>();

        if self.data.len() < payload_len {
            return Err(SmcError::DataTooShort {
                got: self.data.len(),
                need: payload_len,
            });
        }

        let hash = rot_sum_sha(
            &IntoBytes::as_bytes(&self.header.header)[..0x10],
            &self.data[..payload_len],
        )
        .map_err(|_| SmcError::InvalidSize)?;
        sha_out.copy_from_slice(&hash);
        Ok(())
    }

    pub fn verify_sig(&self, pubkey: &ExCryptRsa) -> Result<()> {
        let mut bl_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut bl_hash)?;
        let expected_salt = b"XBOX_ROM_S\0";
        if verify_signature(&self.header.signature, &bl_hash, expected_salt, pubkey)
            .unwrap_or(false)
        {
            Ok(())
        } else {
            Err(SmcError::SignatureVerification)
        }
    }

    pub fn decrypt(&mut self) -> &mut Self {
        smc_crypt(&mut self.data, false);
        self.populate_metadata();
        self
    }

    pub fn encrypt(&mut self) -> &mut Self {
        smc_crypt(&mut self.data, true);
        self
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}

#[derive(Clone)]
pub struct RawSmc {
    pub data: Vec<u8>,
    pub metadata: Option<SmcMetadata>,
}

impl RawSmc {
    pub fn new(data: Vec<u8>) -> Self {
        let mut smc = Self {
            data,
            metadata: None,
        };
        smc.populate_metadata();
        smc
    }

    fn looks_decrypted(&self) -> bool {
        if self.data.is_empty() {
            return false;
        }

        let scan_len = std::cmp::min(self.data.len(), 0x200);
        let pat = b"Microsoft";
        if scan_len >= pat.len() && self.data[..scan_len].windows(pat.len()).any(|w| w == pat) {
            return true;
        }

        false
    }

    pub fn populate_metadata(&mut self) {
        if self.data.len() < 0x103 {
            return;
        }

        let type_byte = self.data[0x100];
        let major = self.data[0x101];
        let minor = self.data[0x102];

        let identified_type = self.identify_type();

        let ldv = self.data[0x103];
        let mut pd = [0u8; 3];
        if self.data.len() >= 0x107 {
            pd.copy_from_slice(&self.data[0x104..0x107]);
        }

        self.metadata = Some(SmcMetadata {
            smc_type: identified_type,
            console_type: (type_byte >> 4) & 0xF,
            type_byte,
            major_version: major,
            minor_version: minor,
            lockdown_value: ldv,
            pairing_data: pd,
        });

        if major != 0 && major != 0xFF {
            info!(
                "[smc] Identified Version: {}.{:02} (Type: 0x{:02X}, Offset: 0x101)",
                major, minor, type_byte
            );
        } else {
            // For debugging garbage versions
            info!(
                "[smc] Raw Version Bytes at 0x100: {:02X} {:02X} {:02X}",
                type_byte, major, minor
            );
        }
    }

    pub fn identify_type(&self) -> SmcType {
        let mut identified = SmcType::Unknown;
        let mut glitch_patched = false;
        let mut retail_found = false;

        if self.data.len() < 8 {
            return identified;
        }

        for i in 0..self.data.len() - 6 {
            match self.data[i] {
                0x05 => {
                    if self.data[i + 2] == 0xE5
                        && self.data[i + 4] == 0xB4
                        && self.data[i + 5] == 0x05
                    {
                        retail_found = true;
                    }
                }
                0x00 => {
                    if self.data[i + 1] == 0x00
                        && self.data[i + 2] == 0xE5
                        && self.data[i + 4] == 0xB4
                        && self.data[i + 5] == 0x05
                    {
                        glitch_patched = true;
                    }
                }
                0x78 => {
                    if self.data[i + 1] == 0xBA && self.data[i + 2] == 0xB6 {
                        identified = SmcType::Cygnos;
                    }
                }
                0xD0 => {
                    if self.data[i + 1] == 0x00
                        && self.data[i + 2] == 0x00
                        && self.data[i + 3] == 0x1B
                    {
                        identified = SmcType::Jtag;
                    }
                }
                _ => {}
            }
        }

        if glitch_patched && !retail_found {
            return match identified {
                SmcType::Jtag => SmcType::RJtag,
                _ => SmcType::Glitch,
            };
        }

        if identified == SmcType::Unknown && retail_found {
            return SmcType::Retail;
        }

        identified
    }

    pub fn is_scrambled(&self) -> bool {
        if self.data.len() < 4 {
            return false;
        }
        self.data[0..4] == [0x04, 0x20, 0x69, 0x69]
    }

    pub fn decrypt(&mut self) {
        self.unscramble();
        smc_crypt(&mut self.data, false);
        self.populate_metadata();
    }

    pub fn ensure_decrypted(&mut self) {
        self.unscramble();
        if self.looks_decrypted() {
            self.populate_metadata();
            return;
        }

        let original = self.data.clone();
        smc_crypt(&mut self.data, false);
        if self.looks_decrypted() {
            self.populate_metadata();
            return;
        }

        self.data = original;
        self.populate_metadata();
    }

    pub fn force_decrypt(&mut self) {
        self.unscramble();
        smc_crypt(&mut self.data, false);
        self.populate_metadata();
    }

    pub fn encrypt(&mut self) {
        self.encrypt_with_scramble(false);
    }

    pub fn encrypt_with_scramble(&mut self, scramble: bool) {
        let mut is_retail = false;
        self.ensure_decrypted();
        if let Some(ref meta) = self.metadata {
            if meta.smc_type == SmcType::Retail {
                is_retail = true;
            }
        }

        smc_crypt(&mut self.data, true);

        if scramble && !is_retail {
            self.scramble();
        }
    }

    pub fn unscramble(&mut self) {
        if self.data.len() < 8 {
            return;
        }
        if !self.is_scrambled() {
            return;
        }
        let len = self.data.len();
        let mut real_header = [0u8; 4];
        real_header.copy_from_slice(&self.data[len - 8..len - 4]);
        self.data[0..4].copy_from_slice(&real_header);
        for i in 0..8 {
            self.data[len - 8 + i] = 0;
        }
        info!("[smc] Unscrambled (RGH3)");
    }

    pub fn scramble(&mut self) {
        if self.data.len() < 8 {
            return;
        }
        if self.is_scrambled() {
            return;
        }
        let len = self.data.len();
        let mut real_header = [0u8; 4];
        real_header.copy_from_slice(&self.data[0..4]);
        self.data[0..4].copy_from_slice(&[0x04, 0x20, 0x69, 0x69]);
        self.data[len - 8..len - 4].copy_from_slice(&real_header);
        for i in 0..4 {
            self.data[len - 4 + i] = 0;
        }
        info!("[smc] Scrambled (RGH3)");
    }
}

pub fn smc_crypt(data: &mut [u8], encrypt: bool) {
    let mut key: [u32; 4] = [0x42, 0x75, 0x4E, 0x79];
    for i in 0..data.len() {
        let ciphertext_byte;
        if encrypt {
            ciphertext_byte = data[i] ^ (key[i & 3] & 0xFF) as u8;
        } else {
            ciphertext_byte = data[i];
        }
        let mod_val = (ciphertext_byte as u32).wrapping_mul(0xFB);
        if !encrypt {
            data[i] ^= (key[i & 3] & 0xFF) as u8;
        } else {
            data[i] = ciphertext_byte;
        }
        key[(i + 1) & 3] = key[(i + 1) & 3].wrapping_add(mod_val);
        key[(i + 2) & 3] = key[(i + 2) & 3].wrapping_add(mod_val >> 8);
    }
}
