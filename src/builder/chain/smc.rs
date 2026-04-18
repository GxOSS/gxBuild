/*
    smc.rs - Handling for Xbox 360 SMC.

    Copyright 2024 Emma https://ipg.gay/
    Modified for GGX by Exposure / Zach
    Some code taken from RGH3 by 15432 / Alexey

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
use crate::builder::deps::excrypt::{self, ExCryptRsa};
use log::info;

#[derive(Clone, Debug)]
pub struct SmcMetadata {
    /// Console type nibble: (SMC[0x100] >> 4) & 0xF
    /// 1=Xenon 2=Zephyr 3=Falcon 4=Jasper 5=Trinity 6=Corona 7=Winchester
    /// (matches J-Runner patch_SMC console_types array)
    pub console_type: u8,
    /// Full SMC[0x100] byte (console type + lower nibble flags)
    pub type_byte: u8,
    pub major_version: u8,   // SMC[0x101]
    pub minor_version: u8,   // SMC[0x102]
}

#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, Clone, Copy)]
#[repr(C)]
pub struct SmcHeader {
    pub header: BootloaderHeader,
    pub signature: [u8; 0x100], // matching EXCRYPT_SIG size
}

#[derive(Clone)]
pub struct Smc {
    pub header: SmcHeader,
    pub data: Vec<u8>,
    pub metadata: Option<SmcMetadata>,
}

impl Smc {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let (header, payload) = SmcHeader::read_from_prefix(data)
            .map_err(|_| "Failed to parse SMC header")?;
        let mut smc = Self {
            header: header.clone(),
            data: payload.to_vec(),
            metadata: None,
        };
        smc.populate_metadata();
        Ok(smc)
    }

    pub fn populate_metadata(&mut self) {
        if self.data.len() < 0x103 { return; }
        // J-Runner patch_SMC: smctype = (SMC[0x100] >> 4) & 0xF
        // SMC[0x101] = major version, SMC[0x102] = minor version
        self.metadata = Some(SmcMetadata {
            console_type: (self.data[0x100] >> 4) & 0xF,
            type_byte: self.data[0x100],
            major_version: self.data[0x101],
            minor_version: self.data[0x102],
        });
        if let Some(meta) = &self.metadata {
            info!("[smc] Metadata: Type 0x{:02X}, Ver {}.{}", meta.type_byte, meta.major_version, meta.minor_version);
        }
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        // Signature is excluded from the hash
        if let Ok(hash) = excrypt::rot_sum_sha(
            &IntoBytes::as_bytes(&self.header.header)[..0x10],
            &self.data[..(size_aligned as usize - std::mem::size_of::<SmcHeader>())],
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn verify_sig(&self, pubkey: &ExCryptRsa) -> bool {
        let mut bl_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut bl_hash);

        let expected_salt = b"XBOX_ROM_S\0"; // Standard SMC salt
        excrypt::verify_signature(&self.header.signature, &bl_hash, expected_salt, pubkey).unwrap_or(false)
    }

    /// Decrypts the SMC payload using the "SMC Hash" rolling-key cipher in-place.
    pub fn decrypt(&mut self) -> &mut Self {
        smc_crypt(&mut self.data, false);
        self.populate_metadata();
        self
    }

    /// Encrypts the SMC payload using the "SMC Hash" rolling-key cipher in-place.
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

/// A "Raw" SMC as found in retail NAND images, which lacks the 0x130 byte signed header.
#[derive(Clone)]
pub struct RawSmc {
    pub data: Vec<u8>,
    pub metadata: Option<SmcMetadata>,
}

impl RawSmc {
    pub fn new(data: Vec<u8>) -> Self {
        let mut smc = Self { data, metadata: None };
        smc.populate_metadata();
        smc
    }

    pub fn populate_metadata(&mut self) {
        if self.data.len() < 0x103 { return; }
        self.metadata = Some(SmcMetadata {
            console_type: (self.data[0x100] >> 4) & 0xF,
            type_byte: self.data[0x100],
            major_version: self.data[0x101],
            minor_version: self.data[0x102],
        });
        if let Some(meta) = &self.metadata {
            if self.data.len() >= 0x11C {
                let copyright = &self.data[0x10C..0x11C];
                if copyright == b"Copyright 2001-2" {
                    info!("[smc] Validated Copyright: {}", String::from_utf8_lossy(copyright));
                }
            }
            info!("[smc] Raw SMC Metadata: Type 0x{:02X}, Ver {}.{}", meta.type_byte, meta.major_version, meta.minor_version);
        }
    }

    /// Decrypts the raw SMC payload in-place using the "BuNy" rolling-key cipher and unscrambles headers.
    pub fn decrypt(&mut self) {
        smc_crypt(&mut self.data, false);
        self.unscramble();
        self.populate_metadata();
    }

    /// Encrypts the raw SMC payload in-place using the "BuNy" rolling-key cipher and scrambles headers.
    pub fn encrypt(&mut self) {
        self.scramble();
        smc_crypt(&mut self.data, true);
    }

    /// Moves the real first four bytes from the footer back to the header (hardware descrambling).
    /// Forensic detail from RGH3/smc.py: res[0:4] = res[-8:-4]
    pub fn unscramble(&mut self) {
        if self.data.len() < 8 { return; }
        let len = self.data.len();
        let mut real_header = [0u8; 4];
        real_header.copy_from_slice(&self.data[len - 8..len - 4]);
        self.data[0..4].copy_from_slice(&real_header);
    }

    /// Scrambles the SMC by moving the first four bytes to the footer (pre-encryption).
    /// Forensic detail from RGH3/smc.py: data = rnd + data[4:-8] + data[0:4] + b"\x00"*4
    pub fn scramble(&mut self) {
        if self.data.len() < 8 { return; }
        let len = self.data.len();
        
        // Save the real first four bytes
        let mut real_header = [0u8; 4];
        real_header.copy_from_slice(&self.data[0..4]);
        
        // Use placeholder identification bytes (RGH3 default: 0x04206969)
        let placeholder = [0x04, 0x20, 0x69, 0x69];
        self.data[0..4].copy_from_slice(&placeholder);
        
        // Move real header to footer (len-8 to len-4)
        self.data[len - 8..len - 4].copy_from_slice(&real_header);
        
        // Ensure final four bytes are zeroed (if they weren't already)
        for i in 0..4 {
            self.data[len - 4 + i] = 0;
        }
    }
}


/// A 64KB SMC Configuration Partition (typically found at logical block 1/sector 0x20).
/// This structure handles the 256-byte settings header and retains the full partition blob.
#[derive(Clone)]
pub struct SmcConfig {
    /// Internal 64KB partition data.
    pub data: Box<[u8; 0x10000]>,
}

impl SmcConfig {
    pub const SIZE: usize = 0x10000;
    pub const SETTINGS_SIZE: usize = 0x100;

    /// Creates a new, empty 64KB configuration partition initialized with 0xFF.
    pub fn new_empty() -> Self {
        Self {
            data: Box::new([0xFF; Self::SIZE]),
        }
    }

    /// Parses a 64KB configuration partition from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() != Self::SIZE {
            return Err(format!("Invalid SMC Config size: expected 0x{:X}, got 0x{:X}", Self::SIZE, data.len()));
        }

        let mut config = Self {
            data: Box::new([0; Self::SIZE]),
        };
        config.data.copy_from_slice(data);

        // Verify checksum of the 256-byte header
        let expected = config.get_checksum();
        let calculated = config.calculate_checksum();
        if expected != calculated {
            return Err(format!("SMC Config Checksum mismatch: expected 0x{:04X}, calculated 0x{:04X}", expected, calculated));
        }

        Ok(config)
    }

    /// Serializes the 64KB partition, ensuring the 16-bit checksum is up to date.
    pub fn serialize(&mut self) -> &[u8; Self::SIZE] {
        let checksum = self.calculate_checksum();
        self.set_checksum(checksum);
        &self.data
    }

    /// Calculates the 16-bit checksum for the 256-byte settings header.
    /// Algorithm: ~Sum(data[0x10..0x100]) & 0xFFFF
    pub fn calculate_checksum(&self) -> u16 {
        let mut sum: u32 = 0;
        for i in 0x10..Self::SETTINGS_SIZE {
            sum = sum.wrapping_add(self.data[i] as u32);
        }
        (!sum & 0xFFFF) as u16
    }

    pub fn get_checksum(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        let bytes = checksum.to_be_bytes();
        self.data[0] = bytes[0];
        self.data[1] = bytes[1];
    }

    // --- High-level Accessors ---

    /// Sets the fan speed and control mode.
    /// speed_pct: 0-100. If mode_manual is false, speed_pct is ignored by the SMC (Auto mode).
    pub fn set_fan_speed(&mut self, is_gpu: bool, mode_manual: bool, speed_pct: u8) {
        let offset = if is_gpu { 0x12 } else { 0x11 };
        let mut val = speed_pct & 0x7F;
        if mode_manual {
            val |= 0x80;
        }
        self.data[offset] = val;
    }

    pub fn set_thermal_targets(&mut self, cpu: u8, gpu: u8, ram: u8) {
        self.data[0x29] = cpu;
        self.data[0x2A] = gpu;
        self.data[0x2B] = ram;
    }

    pub fn set_thermal_limits(&mut self, cpu: u8, gpu: u8, ram: u8) {
        self.data[0x2C] = cpu;
        self.data[0x2D] = gpu;
        self.data[0x2E] = ram;
    }

    pub fn set_mac_address(&mut self, mac: &[u8; 6]) {
        self.data[0x220..0x226].copy_from_slice(mac);
    }

    pub fn set_regions(&mut self, video: u16, game: u16, dvd: u8) {
        let v_bytes = video.to_be_bytes();
        self.data[0x22A] = v_bytes[0];
        self.data[0x22B] = v_bytes[1];

        let g_bytes = game.to_be_bytes();
        self.data[0x22C] = g_bytes[0];
        self.data[0x22D] = g_bytes[1]; 
        
        self.data[0x237] = dvd;
    }

    pub fn set_reset_code(&mut self, code: &[u8; 4]) {
        self.data[0x238..0x23C].copy_from_slice(code);
    }
}

/// Core implementation of the SMC "BuNy" rolling-key cipher.
fn smc_crypt(data: &mut [u8], encrypt: bool) {
    let mut key: [u32; 4] = [0x42, 0x75, 0x4E, 0x79]; // "BuNy"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smc_config_empty() {
        let mut config = SmcConfig::new_empty();
        assert_eq!(config.data.len(), 0x10000);
        assert_eq!(config.data[0x100], 0xFF);
        
        // Calculate expected first, then serialize
        let expected_checksum = config.calculate_checksum();
        let bytes = config.serialize();
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), expected_checksum);
    }

    #[test]
    fn test_smc_config_checksum() {
        let mut config = SmcConfig::new_empty();
        // Zero out the header area for predictable checksum
        for i in 0x10..0x100 {
            config.data[i] = 0;
        }
        // ~0 & 0xFFFF = 0xFFFF
        assert_eq!(config.calculate_checksum(), 0xFFFF);

        // Put one byte
        config.data[0x10] = 0x01;
        // ~1 & 0xFFFF = 0xFFFE
        assert_eq!(config.calculate_checksum(), 0xFFFE);
    }

    #[test]
    fn test_smc_config_accessors() {
        let mut config = SmcConfig::new_empty();
        config.set_fan_speed(false, true, 50); // CPU Manual 50%
        assert_eq!(config.data[0x11], 0x80 | 50);

        config.set_thermal_targets(60, 70, 80);
        assert_eq!(config.data[0x29], 60);
        assert_eq!(config.data[0x2A], 70);
        assert_eq!(config.data[0x2B], 80);

        let mac = [0x00, 0x1D, 0xD8, 0x11, 0x22, 0x33];
        config.set_mac_address(&mac);
        assert_eq!(&config.data[0x220..0x226], &mac);
    }
}