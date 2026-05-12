/*
    smc.rs - Handling for Xbox 360 SMC.

    This file was originally taken from xenon-bltool, but at this point, contains more code from Swizzy's x360Utils
    and the various buildpy scripts floating around.

    Modified in 2026 by Exposure / Zach for GGX
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

use zerocopy::{FromBytes, IntoBytes};
use super::BootloaderHeader;
use crate::builder::deps::excrypt::{self, ExCryptRsa};
use crate::core::images::blocks::NandLayout;
use log::info;

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

#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, Clone, Copy)]
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
            info!("[smc] Metadata: [{:?}] Type 0x{:02X}, Ver {}.{:02}", meta.smc_type, meta.type_byte, meta.major_version, meta.minor_version);
        }
    }

    pub fn identify_type(&self) -> SmcType {
        let mut identified = SmcType::Unknown;
        let mut glitch_patched = false;
        let mut retail_found = false;

        if self.data.len() < 8 { return identified; }

        for i in 0..self.data.len() - 6 {
            match self.data[i] {
                0x05 => {
                    if self.data[i + 2] == 0xE5 && self.data[i + 4] == 0xB4 && self.data[i + 5] == 0x05 {
                        retail_found = true;
                    }
                }
                0x00 => {
                    if self.data[i + 1] == 0x00 && self.data[i + 2] == 0xE5 && self.data[i + 4] == 0xB4 && self.data[i + 5] == 0x05 {
                        glitch_patched = true;
                    }
                }
                0x78 => {
                    if self.data[i + 1] == 0xBA && self.data[i + 2] == 0xB6 {
                        identified = SmcType::Cygnos;
                    }
                }
                0xD0 => {
                    if self.data[i + 1] == 0x00 && self.data[i + 2] == 0x00 && self.data[i + 3] == 0x1B {
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

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

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
        let expected_salt = b"XBOX_ROM_S\0";
        excrypt::verify_signature(&self.header.signature, &bl_hash, expected_salt, pubkey).unwrap_or(false)
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

/// A "Raw" SMC as found in NAND images, which lacks the 0x130 byte signed header.
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
        
        let type_byte = self.data[0x100];
        let major = self.data[0x101];
        let minor = self.data[0x102];
        
        // Use Smc's structural logic for identification if possible
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
            info!("[smc] Identified Version: {}.{:02} (Type: 0x{:02X}, Offset: 0x101)", major, minor, type_byte);
        } else {
            // For debugging garbage versions
            info!("[smc] Raw Version Bytes at 0x100: {:02X} {:02X} {:02X}", type_byte, major, minor);
        }
    }

    pub fn identify_type(&self) -> SmcType {
        let mut identified = SmcType::Unknown;
        let mut glitch_patched = false;
        let mut retail_found = false;

        if self.data.len() < 8 { return identified; }

        for i in 0..self.data.len() - 6 {
            match self.data[i] {
                0x05 => {
                    if self.data[i + 2] == 0xE5 && self.data[i + 4] == 0xB4 && self.data[i + 5] == 0x05 {
                        retail_found = true;
                    }
                }
                0x00 => {
                    if self.data[i + 1] == 0x00 && self.data[i + 2] == 0xE5 && self.data[i + 4] == 0xB4 && self.data[i + 5] == 0x05 {
                        glitch_patched = true;
                    }
                }
                0x78 => {
                    if self.data[i + 1] == 0xBA && self.data[i + 2] == 0xB6 {
                        identified = SmcType::Cygnos;
                    }
                }
                0xD0 => {
                    if self.data[i + 1] == 0x00 && self.data[i + 2] == 0x00 && self.data[i + 3] == 0x1B {
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
        if self.data.len() < 4 { return false; }
        self.data[0..4] == [0x04, 0x20, 0x69, 0x69]
    }

    pub fn decrypt(&mut self) {
        // RGH3 scrambling is applied to the ciphertext in the NAND.
        // We must unscramble BEFORE decryption to keep the rolling key state in sync.
        self.unscramble();
        smc_crypt(&mut self.data, false);
        self.populate_metadata();
    }

    pub fn encrypt(&mut self) {
        let mut is_retail = false;
        self.populate_metadata();
        if let Some(ref meta) = self.metadata {
            if meta.smc_type == SmcType::Retail { is_retail = true; }
        }

        smc_crypt(&mut self.data, true);
        
        // RGH3 scrambling is applied to the ciphertext.
        if !is_retail {
            self.scramble();
        }
    }

    pub fn unscramble(&mut self) {
        if self.data.len() < 8 { return; }
        if !self.is_scrambled() { return; }
        let len = self.data.len();
        let mut real_header = [0u8; 4];
        real_header.copy_from_slice(&self.data[len - 8..len - 4]);
        self.data[0..4].copy_from_slice(&real_header);
        for i in 0..8 { self.data[len - 8 + i] = 0; }
        info!("[smc] Unscrambled (RGH3)");
    }

    pub fn scramble(&mut self) {
        if self.data.len() < 8 { return; }
        if self.is_scrambled() { return; }
        let len = self.data.len();
        let mut real_header = [0u8; 4];
        real_header.copy_from_slice(&self.data[0..4]);
        self.data[0..4].copy_from_slice(&[0x04, 0x20, 0x69, 0x69]);
        self.data[len - 8..len - 4].copy_from_slice(&real_header);
        for i in 0..4 { self.data[len - 4 + i] = 0; }
        info!("[smc] Scrambled (RGH3)");
    }
}


/// 64KB SMC Configuration Partition.
#[derive(Clone)]
pub struct SmcConfig {
    pub data: Box<[u8; 0x10000]>,
}

impl SmcConfig {
    pub const SIZE: usize = 0x10000;
    pub const SETTINGS_SIZE: usize = 0x100;

    /// Physical/logical address used when *scanning* for the SMC config partition.
    /// On eMMC, xeBuild finds this at 0x2FFC000 by scanning the NAND header field.
    /// (smc_config_offset) is 0x0 on all real Corona dumps; the console does not use
    /// the header field to locate config on eMMC.
    /// For SB/BB layouts the header field IS populated and used for booting.
    pub fn get_scan_address(layout: &NandLayout) -> u32 {
        match layout {
            NandLayout::Emmc => 0x02FFC000,
            NandLayout::Bb   => 0x3DF0000,
            _                => 0xF70000,
        }
    }

    /// Value to write into the NAND header's smc_config_offset field.
    /// eMMC: 0x0 (field unused - confirmed from emmc-ksb-rginfo.txt: SMC config addr 0x0)
    /// SB/BB: physical address used by the bootloader to locate the config partition.
    pub fn get_logical_address(layout: &NandLayout) -> u32 {
        match layout {
            NandLayout::Emmc => 0x0,
            NandLayout::Bb   => 0x3DF0000,
            _                => 0xF70000,
        }
    }

    pub fn new_empty() -> Self {
        Self { data: Box::new([0xFF; Self::SIZE]) }
    }

    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() != Self::SIZE {
            return Err(format!("Invalid SMC Config size"));
        }
        let mut config = Self { data: Box::new([0; Self::SIZE]) };
        config.data.copy_from_slice(data);
        Ok(config)
    }

    pub fn serialize(&mut self) -> &[u8; Self::SIZE] {
        let checksum = self.calculate_checksum();
        self.set_checksum(checksum);
        &self.data
    }

    pub fn calculate_checksum(&self) -> u16 {
        let mut sum: u32 = 0;
        for i in 0x10..Self::SETTINGS_SIZE {
            sum = sum.wrapping_add(self.data[i] as u32);
        }
        (!sum & 0xFFFF) as u16
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        let bytes = checksum.to_be_bytes();
        self.data[0] = bytes[0];
        self.data[1] = bytes[1];
    }

    pub fn set_fan_speed(&mut self, is_gpu: bool, mode_manual: bool, speed_pct: u8) {
        let offset = if is_gpu { 0x12 } else { 0x11 };
        let mut val = speed_pct & 0x7F;
        if mode_manual { val |= 0x80; }
        self.data[offset] = val;
    }

    pub fn set_thermal_targets(&mut self, cpu: u8, gpu: u8, ram: u8) {
        self.data[0x29] = cpu; self.data[0x2A] = gpu; self.data[0x2B] = ram;
    }

    pub fn set_thermal_limits(&mut self, cpu: u8, gpu: u8, ram: u8) {
        self.data[0x2C] = cpu; self.data[0x2D] = gpu; self.data[0x2E] = ram;
    }

    pub fn set_mac_address(&mut self, mac: &[u8; 6]) {
        self.data[0x220..0x226].copy_from_slice(mac);
    }

    pub fn set_regions(&mut self, video: u16, game: u16, dvd: u8) {
        let v_bytes = video.to_be_bytes();
        self.data[0x22A] = v_bytes[0]; self.data[0x22B] = v_bytes[1];
        let g_bytes = game.to_be_bytes();
        self.data[0x22C] = g_bytes[0]; self.data[0x22D] = g_bytes[1];
        self.data[0x237] = dvd;
    }

    pub fn set_reset_code(&mut self, code: &[u8; 4]) {
        self.data[0x238..0x23C].copy_from_slice(code);
    }
}

fn smc_crypt(data: &mut [u8], encrypt: bool) {
    let mut key: [u32; 4] = [0x42, 0x75, 0x4E, 0x79];
    for i in 0..data.len() {
        let ciphertext_byte;
        if encrypt { 
            ciphertext_byte = data[i] ^ (key[i & 3] & 0xFF) as u8;
        } else {
            ciphertext_byte = data[i];
        }
        let mod_val = (ciphertext_byte as u32).wrapping_mul(0xFB);
        if !encrypt { data[i] ^= (key[i & 3] & 0xFF) as u8; }
        else { data[i] = ciphertext_byte; }
        key[(i+1)&3] = key[(i+1)&3].wrapping_add(mod_val);
        key[(i+2)&3] = key[(i+2)&3].wrapping_add(mod_val >> 8);
    }
}