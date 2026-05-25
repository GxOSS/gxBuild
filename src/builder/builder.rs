/*
  builder.rs - Core NAND assembly and parsing logic.

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

use log::{debug, error, info, warn};
use zerocopy::byteorder::{BigEndian, I16, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::builder::chain::*;
use crate::builder::filesystem::corona::{self, CoronaFsSlots};
use crate::builder::filesystem::flashfs::FlashFS;
use crate::builder::filesystem::mobile::MobileStore;
use crate::core::images::blocks::*;
use crate::core::images::gxp::{apply_records, GxpBinary, GxpPatchType, PatchRecord};

const NAND_RETAIL_1BL_KEY: [u8; 16] = [0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA];

struct BlDiscovery {
    magic: String,
    version: u16,
    size: u32,
    key_source: String,
}

fn bl_is_valid_magic(magic: u16) -> bool {
    matches!(magic & 0xFFF, 0x342 | 0x343 | 0x344 | 0x345 | 0x346 | 0x347 | 0x341)
}

fn bl_magic_to_str(magic: u16) -> String {
    match magic {
        0x4342 | 0x5342 => "CB",
        0x4343 | 0x5343 => "SC",
        0x4344 | 0x5344 => "CD",
        0x4345 | 0x5345 => "CE",
        0x4346 | 0x5346 => "CF",
        0x4347 | 0x5347 => "CG",
        0x0341 => "1BL",
        _ => "??",
    }
    .to_string()
}

fn bl_try_identify(data: &[u8], parent_key: &[u8; 16]) -> Option<BlDiscovery> {
    use crate::builder::deps::excrypt::{self, Rc4};
    if data.len() < 0x10 {
        return None;
    }

    let magic_val = u16::from_be_bytes([data[0], data[1]]);
    let version = u16::from_be_bytes([data[2], data[3]]);
    let size = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

    if bl_is_valid_magic(magic_val) && version >= 1888 && version < 20000 && size < 0x2000000 {
        return Some(BlDiscovery { magic: bl_magic_to_str(magic_val), version, size, key_source: "Plain".to_string() });
    }

    let devkit_key = [0u8; 16];
    let key_sources: [(&str, &[u8; 16]); 3] = [("Retail", &NAND_RETAIL_1BL_KEY), ("Devkit", &devkit_key), ("Chain", parent_key)];

    for (key_name, key_base) in key_sources {
        if key_name == "Chain" && key_base.iter().all(|&x| x == 0) {
            continue;
        }
        for &salt_off in &[0x10usize, 0x20usize] {
            if data.len() < salt_off + 0x10 {
                continue;
            }
            let dk = match excrypt::hmac_sha(key_base, &[&data[salt_off..salt_off + 0x10]]) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let mut block = data[0..0x10].to_vec();
            if let Ok(mut rc4) = Rc4::new(&dk[..0x10]) {
                let _ = rc4.crypt(&mut block);
            } else {
                continue;
            }

            let dm = u16::from_be_bytes([block[0], block[1]]);
            let dv = u16::from_be_bytes([block[2], block[3]]);
            let ds = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);

            if bl_is_valid_magic(dm) && dv >= 1888 && dv < 20000 && ds < 0x2000000 {
                return Some(BlDiscovery { magic: bl_magic_to_str(dm), version: dv, size: ds, key_source: key_name.to_string() });
            }
        }
    }
    None
}

/// Scans `scan_range` bytes from `start_offset` in 0x10-byte steps for a valid bootloader.
fn bl_scan<F>(read_fn: &mut F, start_offset: usize, scan_range: usize, parent_key: &[u8; 16]) -> Option<(usize, BlDiscovery)>
where
    F: FnMut(usize, usize) -> Option<Vec<u8>>,
{
    for offset in (start_offset..start_offset + scan_range).step_by(0x10) {
        let buf = read_fn(offset, 0x100)?;
        if let Some(r) = bl_try_identify(&buf, parent_key) {
            info!("[builder] bl_scan: found {} v{} at 0x{:08X} via {} key", r.magic, r.version, offset, r.key_source);
            return Some((offset, r));
        }
    }
    None
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!("Hex string has odd length ({}): '{}'", hex.len(), hex));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("Invalid hex byte '{}': {}", &hex[i..i + 2], e)))
        .collect()
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub struct NandHeaderPrefix {
    pub magic: U16<BigEndian>,
    pub version: U16<BigEndian>,
    pub pairing: U16<BigEndian>,
    pub flags: U16<BigEndian>,
    pub entrypoint: U32<BigEndian>, // CB
    pub size: U32<BigEndian>,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub struct NandHeader {
    pub prefix: NandHeaderPrefix,
    pub copyright: [u8; 0x40],
    pub payload_indicator: U16<BigEndian>,
    pub unused: [u8; 0x0E],
    pub kv_size: U32<BigEndian>,
    pub cf_offset: U32<BigEndian>,
    pub patch_slots: I16<BigEndian>,
    pub kv_version: U16<BigEndian>,
    pub kv_addr: U32<BigEndian>,
    pub fs_addr: U32<BigEndian>,
    pub smc_config_offset: U32<BigEndian>,
    pub smc_boot_size: U32<BigEndian>,
    pub smc_boot_offset: U32<BigEndian>,
}

#[derive(Debug, Clone)]
pub struct PayloadEntry {
    pub address: u32,
    pub size: u32,
    pub description: String,
    pub data: Vec<u8>,
    pub fixed_address: Option<u32>,
}

impl PayloadEntry {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.address.to_be_bytes());
        buf.extend_from_slice(&self.size.to_be_bytes());
        let desc_bytes = self.description.as_bytes();
        let desc_len = (desc_bytes.len() as u8).min(0xFF);
        buf.push(desc_len);
        buf.extend_from_slice(&desc_bytes[..desc_len as usize]);
        buf
    }
}

pub struct PayloadList {
    pub entries: Vec<PayloadEntry>,
}

impl PayloadList {
    pub fn new() -> Self {
        PayloadList { entries: Vec::new() }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for entry in &self.entries {
            buf.extend_from_slice(&entry.serialize());
        }
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // Table terminator
        buf
    }
}

impl NandHeader {
    pub const MAGIC: u16 = 0xFF4F;
    const XEBUILD_FLAG_OFFSET: usize = 0x3B;
    const XEBUILD_DUALBOOT_OFFSET: usize = 0x3C;
    const XEBUILD_UART_OFFSET: usize = 0x3D;
    const XEBUILD_XELL_ALT_POC_OFFSET: usize = 0x3E;
    const XEBUILD_XELL_POC_OFFSET: usize = 0x3F;

    pub fn validate(&self) -> Result<(), String> {
        if self.prefix.magic.get() != Self::MAGIC {
            return Err(format!("Invalid NAND magic: 0x{:04X}", self.prefix.magic.get()));
        }
        Ok(())
    }

    pub fn cb_offset(&self) -> u32 {
        self.prefix.entrypoint.get()
    }

    pub fn print_info(&self) {
        info!("[builder] NAND magic:       0x{:04X}", self.prefix.magic.get());
        info!("[builder] NAND build:       {}", self.prefix.version.get());
        info!("[builder] CB offset:        0x{:X}", self.cb_offset());
        info!("[builder] CF offset:        0x{:X}", self.cf_offset.get());
        let copyright = String::from_utf8_lossy(&self.copyright);
        info!("[builder] Copyright:        {}", copyright.trim_matches(char::from(0)));
        info!("[builder] KV offset:        0x{:X}", self.kv_addr.get());
        info!("[builder] KV size:          0x{:X}", self.kv_size.get());
        info!("[builder] SMC boot size:    0x{:X}", self.smc_boot_size.get());
        info!("[builder] SMC boot offset:  0x{:X}", self.smc_boot_offset.get());
    }

    fn apply_xebuild_header_flags(&mut self, options: &BuildOptions, extra: &NandExtra) {
        let profile = options.image_profile.as_str();
        let is_devkit = profile == "devkit" || matches!(options.build_mode, BuildMode::Devkit);
        let is_retail = profile == "retail";
        let is_hacked = profile == "jtag" || profile == "devgl" || profile == "xdkbuild" || profile.contains("glitch");

        if is_retail || is_devkit {
            self.copyright[Self::XEBUILD_FLAG_OFFSET] = 0;
            return;
        }

        if is_hacked {
            self.copyright[Self::XEBUILD_FLAG_OFFSET] = 1;

            let alt = extra.power_on_cause_a;
            let primary = extra.power_on_cause_b;

            self.copyright[Self::XEBUILD_XELL_ALT_POC_OFFSET] = if alt != 0 { alt } else { 0x00 };
            self.copyright[Self::XEBUILD_XELL_POC_OFFSET] = if primary != 0 { primary } else { 0x12 };

            if options.demon {
                self.copyright[Self::XEBUILD_UART_OFFSET] = 2;
            } else if options.cygnos {
                self.copyright[Self::XEBUILD_UART_OFFSET] = 1;
            }

            let _ = Self::XEBUILD_DUALBOOT_OFFSET;
        }
    }
}

use crate::builder::chain::cb::BootloaderCb;
use crate::builder::chain::cd::BootloaderCd;
use crate::builder::chain::ce::BootloaderCe;
use crate::builder::chain::cf::BootloaderCf;
use crate::builder::chain::cg::BootloaderCg;
use crate::builder::chain::sc::BootloaderSc;

#[derive(Clone)]
pub struct NandBootloaders {
    pub cb: Option<BootloaderCb>,
    pub cb_a: Option<BootloaderCb>,
    pub cb_x: Option<BootloaderCb>,
    pub cb_b: Option<BootloaderCb>,
    pub sc: Option<BootloaderSc>,
    pub cd: Option<BootloaderCd>,
    pub ce: Option<BootloaderCe>,
    pub khvpatch: Option<Vec<PatchRecord>>,
    pub xell: Option<crate::builder::chain::xell::Xell>,
}

impl NandBootloaders {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.cb = None;
        self.cb_a = None;
        self.cb_x = None;
        self.cb_b = None;
        self.sc = None;
        self.cd = None;
        self.ce = None;
        self.khvpatch = None;
        self.xell = None;
    }
}

impl Default for NandBootloaders {
    fn default() -> Self {
        NandBootloaders { cb: None, cb_a: None, cb_x: None, cb_b: None, sc: None, cd: None, ce: None, khvpatch: None, xell: None }
    }
}

#[derive(Clone)]
pub struct NandUpdate {
    pub cf_0: Option<BootloaderCf>,
    pub cg_0: Option<BootloaderCg>,
    pub cf_1: Option<BootloaderCf>,
    pub cg_1: Option<BootloaderCg>,
}

impl NandUpdate {
    pub fn clear(&mut self) {
        self.cf_0 = None;
        self.cg_0 = None;
        self.cf_1 = None;
        self.cg_1 = None;
    }
}

impl Default for NandUpdate {
    fn default() -> Self {
        NandUpdate { cf_0: None, cg_0: None, cf_1: None, cg_1: None }
    }
}

#[derive(Clone)]
pub struct NandExtra {
    pub smc: Vec<u8>,
    pub smc_metadata: Option<crate::builder::chain::smc::SmcMetadata>,
    pub smc_config: Vec<u8>,
    pub keyvault: Vec<u8>,
    pub fcrt: Option<Vec<u8>>,
    pub power_on_cause_a: u8,
    pub power_on_cause_b: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum MotherboardType {
    Xenon = 1,
    Zephyr = 2,
    Falcon = 3,
    Jasper = 4,
    Trinity = 5,
    Corona = 6,
    Winchester = 7,
    Unknown = 0xF,
}

impl MotherboardType {
    pub fn from_smc(smc_byte: u8) -> Self {
        match (smc_byte >> 4) & 0xF {
            1 => MotherboardType::Xenon,
            2 => MotherboardType::Zephyr,
            3 => MotherboardType::Falcon,
            4 => MotherboardType::Jasper,
            5 => MotherboardType::Trinity,
            6 => MotherboardType::Corona,
            7 => MotherboardType::Winchester,
            _ => MotherboardType::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SouthbridgeType {
    Xsb,
    Psb,
    Ksb,
    Unknown,
}

impl From<MotherboardType> for SouthbridgeType {
    fn from(m: MotherboardType) -> Self {
        match m {
            MotherboardType::Xenon | MotherboardType::Zephyr | MotherboardType::Falcon => SouthbridgeType::Xsb,
            MotherboardType::Jasper | MotherboardType::Trinity => SouthbridgeType::Psb,
            MotherboardType::Corona | MotherboardType::Winchester => SouthbridgeType::Ksb,
            MotherboardType::Unknown => SouthbridgeType::Unknown,
        }
    }
}

pub struct LayoutCalculator;

impl LayoutCalculator {
    pub fn calculate(sb: SouthbridgeType, image_profile: &str, layout: NandLayout) -> (u32, u32, u32) {
        // Returns (header.fs_addr, header.smc_config_offset, physical_fs_block)
        let smc_config = match layout {
            NandLayout::Xsb | NandLayout::Sb => 0xF70000,
            NandLayout::Bb => 0x3DF0000,
            NandLayout::Emmc => 0x0,
        };

        if matches!(layout, NandLayout::Bb | NandLayout::Emmc) {
            return (0, smc_config, 0);
        }

        // SmallBlock FlashFS relocation based on SB and profile
        let is_split = match image_profile {
            "split" | "devgl" | "devkit" | "xdkbuild" | "glitch2m" | "glitchr" | "glitch2r" => true,
            _ => false,
        };

        match sb {
            SouthbridgeType::Xsb => {
                if is_split {
                    (0xE44000, smc_config, 0x391)
                } else {
                    (0xD84000, smc_config, 0x361)
                }
            }
            SouthbridgeType::Psb => {
                if is_split {
                    (0xDF4000, smc_config, 0x37D)
                } else {
                    (0xD84000, smc_config, 0x361)
                }
            }
            SouthbridgeType::Ksb => {
                // Corona is always split in modern builds (RGH2/3) or handles it same as Split PSB
                (0xE44000, smc_config, 0x391)
            }
            _ => (0, smc_config, 0),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BuildMode {
    Normal,
    Xell,
    Shadowboot,
    Devkit,
}

#[derive(Clone)]
pub struct BuildOptions {
    pub layout: NandLayout,
    pub lba_map: LbaMap,
    pub image_profile: String,
    pub build_mode: BuildMode,
    pub motherboard: MotherboardType,
    pub bigonsmall: bool,
    pub shadowboot: bool,
    pub mfg: bool,
    pub noremap: bool,
    pub khv_apply: bool,
    pub khv_header_size: u32,
    pub jtag_syscall: Option<u16>,
    pub jtag_pairing_2bl: Option<[u8; 3]>,
    pub gxunsafe: bool,
    pub verbose: bool,
    pub cba: Option<String>,
    pub cbb: Option<String>,
    pub full_image: bool,
    pub xsb: bool,
    pub nomobile: bool,
    pub nofcrt: bool,
    pub dualpatchslots: bool,
    pub cygnos: bool,
    pub demon: bool,
}

impl Default for BuildOptions {
    fn default() -> Self {
        BuildOptions {
            layout: NandLayout::Sb,
            lba_map: LbaMap::new(0x400),
            image_profile: "retail".to_string(),
            build_mode: BuildMode::Normal,
            motherboard: MotherboardType::Unknown,
            bigonsmall: false,
            shadowboot: false,
            mfg: false,
            full_image: false,
            xsb: false,
            noremap: false,
            khv_apply: false,
            khv_header_size: 0x4000,
            jtag_syscall: None,
            jtag_pairing_2bl: None,
            gxunsafe: false,
            verbose: false,
            cba: None,
            cbb: None,
            nomobile: false,
            nofcrt: false,
            dualpatchslots: false,
            cygnos: false,
            demon: false,
        }
    }
}

#[derive(Clone)]
pub struct NandSkeleton {
    pub cpukey: Option<[u8; 16]>,
    pub image: Vec<u8>,
    pub lba_map: Option<LbaMap>,
    pub options: BuildOptions,
    pub header: NandHeader,
    pub extra: NandExtra,
    pub kv: Option<crate::builder::chain::kv::Keyvault>,
    pub bootloaders: NandBootloaders,
    pub rebooter: Option<NandBootloaders>,
    pub update: NandUpdate,
    pub rebooter_update: Option<NandUpdate>,
    pub payloads: Vec<PayloadEntry>,
    pub flashfs: FlashFS,
    pub mobile: MobileStore,
    pub corona_fs: CoronaFsSlots,
    pub layout: NandLayout,
    pub total_blocks: usize,
    pub input_ldv_cb: Option<u8>,
    pub input_ldv_cf: Option<u8>,
    pub input_pd: Option<[u8; 3]>,
}

impl NandSkeleton {
    pub fn new_blank(layout: NandLayout) -> Self {
        let size = match layout {
            NandLayout::Xsb | NandLayout::Sb => 0x1000000,
            NandLayout::Bb => 0x4000000,
            NandLayout::Emmc => 0x3000000,
        };
        let mut image = vec![0xFFu8; size];
        image[0] = 0xFF;
        image[1] = 0x4F;
        let total_blocks = size / (layout.logical_pages_per_block() * 0x200);

        Self {
            cpukey: None,
            image,
            lba_map: Some(LbaMap::new(total_blocks)),
            options: BuildOptions {
                layout,
                image_profile: "retail".to_string(),
                build_mode: BuildMode::Normal,
                motherboard: MotherboardType::Unknown,
                gxunsafe: false,
                ..Default::default()
            },
            header: NandHeader {
                prefix: NandHeaderPrefix {
                    magic: U16::new(NandHeader::MAGIC),
                    version: U16::new(0),
                    pairing: U16::new(0),
                    flags: U16::new(0),
                    entrypoint: U32::new(0),
                    size: U32::new(0),
                },
                copyright: [0u8; 0x40],
                payload_indicator: U16::new(0),
                unused: [0u8; 0x0E],
                kv_size: U32::new(0x4000),
                cf_offset: U32::new(match layout {
                    NandLayout::Bb => 0x80000,
                    NandLayout::Emmc => 0xB0000,
                    _ => 0x70000,
                }),
                patch_slots: I16::new(0),
                kv_version: U16::new(0x712),
                kv_addr: U32::new(0x4000),
                fs_addr: U32::new(0x10000),
                smc_config_offset: U32::new(match layout {
                    NandLayout::Bb => 0x3DF0000,
                    NandLayout::Emmc => 0x0,
                    _ => 0xF70000,
                }),
                smc_boot_size: U32::new(match layout {
                    NandLayout::Emmc => 0x3800,
                    _ => 0x3000,
                }),
                smc_boot_offset: U32::new(match layout {
                    NandLayout::Emmc => 0x800,
                    _ => 0x1000,
                }),
            },
            extra: NandExtra { smc: Vec::new(), smc_metadata: None, smc_config: Vec::new(), keyvault: Vec::new(), fcrt: None, power_on_cause_a: 0, power_on_cause_b: 0 },
            kv: None,
            bootloaders: NandBootloaders::default(),
            rebooter: None,
            update: NandUpdate::default(),
            rebooter_update: None,
            payloads: Vec::new(),
            flashfs: FlashFS::new(),
            mobile: MobileStore::new(),
            corona_fs: [Default::default(), Default::default()],
            layout,
            total_blocks,
            input_ldv_cb: None,
            input_ldv_cf: None,
            input_pd: None,
        }
    }

    pub fn clear_bootloaders(&mut self) {
        self.bootloaders.clear();
        if let Some(ref mut r) = self.rebooter {
            r.clear();
        }
    }

    pub fn clear_update(&mut self) {
        self.update.clear();
        if let Some(ref mut r) = self.rebooter_update {
            r.clear();
        }
    }

    pub fn prepare_for_assembly(&mut self) -> Result<(), String> {
        if self.options.verbose {
            info!("[pfa] === prepare_for_assembly START ===");
            info!("[pfa] input_pd: {:02x?}", self.input_pd);
            info!("[pfa] input_ldv_cb: {:?}", self.input_ldv_cb);
            info!("[pfa] input_ldv_cf: {:?}", self.input_ldv_cf);
            info!(
                "[pfa] cb present: {}, cb_a present: {}, cb_b present: {}",
                self.bootloaders.cb.is_some(),
                self.bootloaders.cb_a.is_some(),
                self.bootloaders.cb_b.is_some()
            );
            info!(
                "[pfa] cb meta: {}, cb_a meta: {}, cb_b meta: {}",
                self.bootloaders.cb.as_ref().map_or(false, |b| b.metadata.is_some()),
                self.bootloaders.cb_a.as_ref().map_or(false, |b| b.metadata.is_some()),
                self.bootloaders.cb_b.as_ref().map_or(false, |b| b.metadata.is_some())
            );
            info!("[pfa] cf_0 present: {}, cf_0 meta: {}", self.update.cf_0.is_some(), self.update.cf_0.as_ref().map_or(false, |cf| cf.metadata.is_some()));
        }

        // Decrypt newly assigned bootloaders individually
        if let Some(cpukey) = self.cpukey {
            if let Some(cb_b) = self.bootloaders.cb_b.as_mut() {
                if cb_b.metadata.is_none() {
                    info!("[pfa] CB_B has no metadata — decrypting");
                    if let Some(cb_a) = self.bootloaders.cb_a.as_ref() {
                        if let Some(cb_a_key_slice) = cb_a.data.get(0..16) {
                            let cb_a_key: [u8; 16] = cb_a_key_slice.try_into().unwrap();
                            let uses_new_crypto = (cb_a.header.flags.get() & 0x1000) != 0;
                            if uses_new_crypto {
                                cb_b.decrypt_v2(&cb_a.header, &cb_a_key, &cpukey);
                            } else {
                                cb_b.decrypt_v1(&cb_a_key, &cpukey);
                            }
                            cb_b.populate_metadata_unchecked();
                            if self.options.verbose {
                                info!("[pfa] CB_B decrypted, meta: {:?}", cb_b.metadata.as_ref().map(|m| (m.lockdown_value, &m.pairing_data)));
                            }
                        } else {
                            warn!("[pfa] CB_A is too small to derive CB_B key");
                        }
                    } else {
                        warn!("[pfa] CB_B needs decrypt but CB_A is missing — cannot derive key");
                    }
                }
            }

            if let Some(cb) = self.bootloaders.cb.as_mut() {
                if cb.metadata.is_none() {
                    info!("[pfa] CB (single) has no metadata — decrypting with 1BL key");
                    cb.decrypt(&ONEBL_KEY);
                    cb.populate_metadata_unchecked();
                    info!("[pfa] CB decrypted, meta: {:?}", cb.metadata.as_ref().map(|m| (m.lockdown_value, &m.pairing_data)));
                }
            }

            if let Some(cf) = self.update.cf_0.as_mut() {
                if cf.metadata.is_none() {
                    info!("[pfa] CF_0 has no metadata — decrypting with 1BL key");
                    cf.decrypt(&ONEBL_KEY);
                    cf.populate_metadata_unchecked();
                    info!("[pfa] CF_0 decrypted, meta: {:?}", cf.metadata.as_ref().map(|m| (m.lockdown_value, &m.pairing_data)));
                }
            }

            if let Some(cf) = self.update.cf_1.as_mut() {
                if cf.metadata.is_none() {
                    info!("[pfa] CF_1 has no metadata — decrypting with 1BL key");
                    cf.decrypt(&ONEBL_KEY);
                    cf.populate_metadata_unchecked();
                    info!("[pfa] CF_1 decrypted, meta: {:?}", cf.metadata.as_ref().map(|m| (m.lockdown_value, &m.pairing_data)));
                }
            }
        }

        let pd = self.input_pd;
        let ldv_cb = self.input_ldv_cb;
        let ldv_cf = self.input_ldv_cf;

        if let Some(pd_val) = pd {
            if let Some(ref mut cb_b) = self.bootloaders.cb_b {
                if let Some(ref mut meta) = cb_b.metadata {
                    info!("[pfa] Syncing PD {:02x?} -> CB_B (was {:02x?})", pd_val, meta.pairing_data);
                    meta.pairing_data = pd_val;
                }
            } else if let Some(ref mut cb) = self.bootloaders.cb {
                if let Some(ref mut meta) = cb.metadata {
                    info!("[pfa] Syncing PD {:02x?} -> CB (was {:02x?})", pd_val, meta.pairing_data);
                    meta.pairing_data = pd_val;
                }
            }
            if let Some(ref mut cf) = self.update.cf_0 {
                if let Some(ref mut meta) = cf.metadata {
                    meta.pairing_data = pd_val;
                }
            }
            if let Some(ref mut cf) = self.update.cf_1 {
                if let Some(ref mut meta) = cf.metadata {
                    meta.pairing_data = pd_val;
                }
            }
            if let Some(ref mut meta) = self.extra.smc_metadata {
                meta.pairing_data = pd_val;
            }
        } else {
            warn!("[pfa] input_pd is None — PD will not be synced");
        }

        if let Some(ldv) = ldv_cb {
            if let Some(ref mut cb_b) = self.bootloaders.cb_b {
                if let Some(ref mut meta) = cb_b.metadata {
                    info!("[pfa] Syncing LDV {} -> CB_B (was {})", ldv, meta.lockdown_value);
                    meta.lockdown_value = ldv;
                }
            } else if let Some(ref mut cb) = self.bootloaders.cb {
                if let Some(ref mut meta) = cb.metadata {
                    info!("[pfa] Syncing LDV {} -> CB (was {})", ldv, meta.lockdown_value);
                    meta.lockdown_value = ldv;
                }
            }
        } else {
            warn!("[pfa] input_ldv_cb is None — CB LDV will not be synced");
        }

        if let Some(ldv) = ldv_cf {
            if let Some(ref mut cf) = self.update.cf_0 {
                if let Some(ref mut meta) = cf.metadata {
                    meta.lockdown_value = ldv;
                }
            }
            if let Some(ref mut cf) = self.update.cf_1 {
                if let Some(ref mut meta) = cf.metadata {
                    meta.lockdown_value = ldv;
                }
            }
        }

        // Resize image so FlashFS block allocation succeeds
        let expected_size = self.total_blocks * self.layout.logical_pages_per_block() * 0x200;
        if self.image.len() != expected_size {
            self.image.resize(expected_size, 0xFF);
        }

        // Handle CG splitting for FlashFS
        let patch_slot_len = 0x10000;

        let cf_size_0 = self.update.cf_0.as_ref().map(|cf| cf.header.size.get() as usize).unwrap_or(0);
        let aligned_cf_0 = (cf_size_0 + 0xF) & !0xF;
        if let Some(cg) = self.update.cg_0.as_ref() {
            let cg_size = cg.header.size.get() as usize; // This is the total serialized size including header
            if aligned_cf_0 + cg_size > patch_slot_len {
                let overflow = aligned_cf_0 + cg_size - patch_slot_len;
                let cg_to_slot = cg_size - overflow;

                if cg_to_slot >= 0x10 {
                    let cg_ser = cg.serialize();
                    let overflow_data = cg_ser[cg_to_slot..].to_vec();

                    let mut entry = crate::builder::filesystem::flashfs::FileSystemEntry::new(0);
                    entry.file_name = "sysupdate.xexp1".to_string();
                    self.flashfs.root.set_entry_data(&mut self.image, &self.layout, &mut entry, &overflow_data)?;
                    self.flashfs.root.entries.push(entry.clone());

                    if let Some(cf) = self.update.cf_0.as_mut() {
                        if let Some(meta) = cf.metadata.as_mut() {
                            let chain = self.flashfs.root.get_block_chain(entry.block_number, 223);
                            meta.cg_blocks_used = chain.len() as u16;
                            meta.cg_block_numbers = chain;
                            info!("[pfa] Split CG0: {} blocks overflowed to sysupdate.xexp1", meta.cg_blocks_used);
                        }
                    }
                }
            }
        }

        let cf_size_1 = self.update.cf_1.as_ref().map(|cf| cf.header.size.get() as usize).unwrap_or(0);
        let aligned_cf_1 = (cf_size_1 + 0xF) & !0xF;
        if let Some(cg) = self.update.cg_1.as_ref() {
            let cg_size = cg.header.size.get() as usize;
            if aligned_cf_1 + cg_size > patch_slot_len {
                let overflow = aligned_cf_1 + cg_size - patch_slot_len;
                let cg_to_slot = cg_size - overflow;

                if cg_to_slot >= 0x10 {
                    let cg_ser = cg.serialize();
                    let overflow_data = cg_ser[cg_to_slot..].to_vec();

                    let mut entry = crate::builder::filesystem::flashfs::FileSystemEntry::new(0);
                    entry.file_name = "sysupdate.xexp2".to_string();
                    self.flashfs.root.set_entry_data(&mut self.image, &self.layout, &mut entry, &overflow_data)?;
                    self.flashfs.root.entries.push(entry.clone());

                    if let Some(cf) = self.update.cf_1.as_mut() {
                        if let Some(meta) = cf.metadata.as_mut() {
                            let chain = self.flashfs.root.get_block_chain(entry.block_number, 223);
                            meta.cg_blocks_used = chain.len() as u16;
                            meta.cg_block_numbers = chain;
                            info!("[pfa] Split CG1: {} blocks overflowed to sysupdate.xexp2", meta.cg_blocks_used);
                        }
                    }
                }
            }
        }

        if let Some(ref mut cb) = self.bootloaders.cb {
            cb.sync_metadata();
        }
        if let Some(ref mut cba) = self.bootloaders.cb_a {
            cba.sync_metadata();
        }
        if let Some(ref mut cbx) = self.bootloaders.cb_x {
            cbx.sync_metadata();
        }
        if let Some(ref mut cbb) = self.bootloaders.cb_b {
            cbb.sync_metadata();
        }
        if let Some(ref mut cd) = self.bootloaders.cd {
            cd.sync_metadata();
        }
        if let Some(ref mut ce) = self.bootloaders.ce {
            ce.sync_metadata();
        }
        if let Some(ref mut cf) = self.update.cf_0 {
            cf.sync_metadata();
        }
        if let Some(ref mut cf) = self.update.cf_1 {
            cf.sync_metadata();
        }
        if let Some(ref mut cg) = self.update.cg_0 {
            cg.sync_metadata();
        }
        if let Some(ref mut cg) = self.update.cg_1 {
            cg.sync_metadata();
        }

        if let Some(meta) = &self.extra.smc_metadata {
            if self.extra.smc.len() >= 0x107 {
                self.extra.smc[0x103] = meta.lockdown_value;
                self.extra.smc[0x104..0x107].copy_from_slice(&meta.pairing_data);
            }
        }
        Ok(())
    }

    pub fn parse_clean_encrypted(image: Vec<u8>, layout: NandLayout, flashfs: FlashFS) -> Result<Self, String> {
        let header_sz = std::mem::size_of::<NandHeader>();
        if image.len() < header_sz {
            return Err(format!("Image too small for header: {} bytes (need {})", image.len(), header_sz));
        }
        let header = NandHeader::read_from_prefix(&image[..header_sz])
            .map_err(|e| format!("Failed to parse NAND header: {}", e))?
            .0;
        header.validate()?;
        header.print_info();

        let kv_addr = header.kv_addr.get() as usize;
        let kv_size = header.kv_size.get() as usize;
        if kv_size != 0x4000 {
            return Err(format!("Invalid KV size: 0x{:X} (expected 0x4000)", kv_size));
        }
        if kv_addr.checked_add(kv_size).ok_or("KV offset overflow")? > image.len() {
            return Err(format!("KV out of bounds: offset 0x{:X} + size 0x{:X} > image 0x{:X}", kv_addr, kv_size, image.len()));
        }
        info!("[builder] Extracting Keyvault (encrypted) (Addr: 0x{:X}, Size: 0x{:X})...", kv_addr, kv_size);
        let kv = crate::builder::chain::kv::Keyvault::parse(&image[kv_addr..kv_addr + kv_size])?;

        let smc_offset = header.smc_boot_offset.get() as usize;
        let smc_size = header.smc_boot_size.get() as usize;
        if smc_offset.checked_add(smc_size).ok_or("SMC offset overflow")? > image.len() {
            return Err(format!("SMC out of bounds: offset 0x{:X} + size 0x{:X} > image 0x{:X}", smc_offset, smc_size, image.len()));
        }
        info!("[builder] Extracting SMC (encrypted) (Addr: 0x{:X}, Size: 0x{:X})...", smc_offset, smc_size);
        let smc_data = image[smc_offset..smc_offset + smc_size].to_vec();

        let config_offset = header.smc_config_offset.get() as usize;
        let config_size = 0x10000;
        let config_data = if config_offset > 0 && config_offset + config_size <= image.len() {
            info!("[builder] Extracting SMC Config (Addr: 0x{:X}, Size: 0x{:X})...", config_offset, config_size);
            image[config_offset..config_offset + config_size].to_vec()
        } else {
            Vec::new()
        };

        let mut extra = NandExtra {
            smc: smc_data,
            smc_metadata: None,
            smc_config: config_data,
            keyvault: kv.data.clone(),
            fcrt: None,
            power_on_cause_a: 0,
            power_on_cause_b: 0,
        };

        info!("[builder] Walking bootloader chain (encrypted) starting at offset 0x{:X}...", header.cb_offset());
        let (bootloaders, update) = Self::parse_bootloader_chain(&image, header.cb_offset() as usize, header.cf_offset.get() as usize, &flashfs)?;

        let motherboard = MotherboardType::Unknown;

        let mut final_flashfs = flashfs;
        if matches!(layout, NandLayout::Sb | NandLayout::Xsb) {
            let sb = SouthbridgeType::from(motherboard);
            let chain_profile = if bootloaders.cb_b.is_some() { "split" } else { "single" };
            let (_fs_root_addr, _smc_cfg, phys_fs_block) = LayoutCalculator::calculate(sb, chain_profile, layout);
            if phys_fs_block > 0 {
                final_flashfs.root.block_number = phys_fs_block as i32;
                final_flashfs.root.read(&image, &layout);
            }
        }

        let fcrt_from_nand = final_flashfs
            .root
            .entries
            .iter()
            .find(|e| !e.deleted && e.file_name.eq_ignore_ascii_case("fcrt.bin"))
            .map(|e| e.data.clone());
        if extra.fcrt.is_none() {
            extra.fcrt = fcrt_from_nand;
        }

        let total_blocks = layout.total_blocks(image.len());
        let lba_map = LbaMap::from_layout(layout, total_blocks);
        let corona_fs = if layout == NandLayout::Emmc { corona::load_slots(&image) } else { [Default::default(), Default::default()] };

        Ok(NandSkeleton {
            cpukey: None,
            image,
            lba_map: Some(lba_map),
            options: BuildOptions {
                layout,
                lba_map: LbaMap::from_layout(layout, total_blocks),
                image_profile: (if bootloaders.cb_b.is_some() { "split" } else { "single" }).to_string(),
                build_mode: BuildMode::Normal,
                motherboard,
                gxunsafe: false,
                verbose: false,
                ..Default::default()
            },
            header,
            extra,
            kv: Some(kv),
            bootloaders,
            rebooter: None,
            update,
            rebooter_update: None,
            payloads: Vec::new(),
            flashfs: final_flashfs,
            mobile: MobileStore::new(),
            corona_fs,
            layout,
            total_blocks,
            input_ldv_cb: None,
            input_ldv_cf: None,
            input_pd: None,
        })
    }

    pub fn parse_encrypted_chain(&self) -> Result<(NandBootloaders, NandUpdate), String> {
        Self::parse_bootloader_chain(&self.image, self.header.cb_offset() as usize, self.header.cf_offset.get() as usize, &self.flashfs)
    }

    pub fn parse_clean(image: Vec<u8>, layout: NandLayout, cpukey: [u8; 16], flashfs: FlashFS) -> Result<Self, String> {
        let header_sz = std::mem::size_of::<NandHeader>();
        if image.len() < header_sz {
            return Err(format!("Image too small for header: {} bytes (need {})", image.len(), header_sz));
        }
        let header = NandHeader::read_from_prefix(&image[..header_sz])
            .map_err(|e| format!("Failed to parse NAND header: {}", e))?
            .0;
        header.validate()?;
        header.print_info();

        let kv_addr = header.kv_addr.get() as usize;
        let kv_size = header.kv_size.get() as usize;
        if kv_size != 0x4000 {
            return Err(format!("Invalid KV size: 0x{:X} (expected 0x4000)", kv_size));
        }
        if kv_addr.checked_add(kv_size).ok_or("KV offset overflow")? > image.len() {
            return Err(format!("KV out of bounds: offset 0x{:X} + size 0x{:X} > image 0x{:X}", kv_addr, kv_size, image.len()));
        }
        info!("[builder] Extracting and decrypting Keyvault (Addr: 0x{:X}, Size: 0x{:X})...", kv_addr, kv_size);
        let mut kv = crate::builder::chain::kv::Keyvault::parse(&image[kv_addr..kv_addr + kv_size])?;
        kv.decrypt(&cpukey)?;

        let smc_offset = header.smc_boot_offset.get() as usize;
        let smc_size = header.smc_boot_size.get() as usize;
        if smc_offset.checked_add(smc_size).ok_or("SMC offset overflow")? > image.len() {
            return Err(format!("SMC out of bounds: offset 0x{:X} + size 0x{:X} > image 0x{:X}", smc_offset, smc_size, image.len()));
        }
        info!("[builder] Extracting and decrypting SMC (Addr: 0x{:X}, Size: 0x{:X})...", smc_offset, smc_size);
        let mut smc = crate::builder::chain::smc::RawSmc::new(image[smc_offset..smc_offset + smc_size].to_vec());
        smc.decrypt();

        let config_offset = header.smc_config_offset.get() as usize;
        let config_size = 0x10000;

        let config_data = if config_offset > 0 && config_offset + config_size <= image.len() {
            info!("[builder] Extracting SMC Config (Addr: 0x{:X}, Size: 0x{:X})...", config_offset, config_size);
            image[config_offset..config_offset + config_size].to_vec()
        } else {
            if config_offset > 0 {
                warn!("[builder] SMC Config offset 0x{:X} is out of bounds, using blank config", config_offset);
            }
            Vec::new()
        };

        let mut extra = NandExtra {
            smc: smc.data,
            smc_metadata: smc.metadata.clone(),
            smc_config: config_data,
            keyvault: kv.data.clone(),
            fcrt: None,
            power_on_cause_a: 0,
            power_on_cause_b: 0,
        };

        info!("[builder] Walking bootloader chain starting at offset 0x{:X}...", header.cb_offset());
        let (bl, mut update) = Self::parse_bootloader_chain(&image, header.cb_offset() as usize, header.cf_offset.get() as usize, &flashfs)?;

        info!("[builder] Decrypting bootloader chain...");
        let mut bl_mut = bl;
        if bl_mut.cb_a.is_none() {
            return Err("Missing CB_A bootloader".into());
        }
        if bl_mut.cd.is_none() {
            return Err("Missing CD bootloader".into());
        }
        if bl_mut.ce.is_none() {
            return Err("Missing CE bootloader".into());
        }

        decrypt_chain(
            bl_mut.cb_a.as_mut().unwrap(),
            bl_mut.cb_x.as_mut(),
            bl_mut.cb_b.as_mut(),
            bl_mut.sc.as_mut(),
            bl_mut.cd.as_mut().unwrap(),
            bl_mut.ce.as_mut().unwrap(),
            update.cf_0.as_mut(),
            update.cg_0.as_mut(),
            update.cf_1.as_mut(),
            update.cg_1.as_mut(),
            &cpukey,
        )?;
        info!("[builder] Bootloader chain successfully decrypted.");

        let motherboard = if extra.smc.len() > 0x100 {
            MotherboardType::from_smc(extra.smc[0x100])
        } else {
            MotherboardType::Unknown
        };

        let mut final_flashfs = flashfs;
        if matches!(layout, NandLayout::Sb | NandLayout::Xsb) {
            let sb = SouthbridgeType::from(motherboard);
            let chain_profile = if bl_mut.cb_b.is_some() { "split" } else { "single" };
            let (_fs_root_addr, _smc_cfg, phys_fs_block) = LayoutCalculator::calculate(sb, chain_profile, layout);
            if phys_fs_block > 0 {
                final_flashfs.root.block_number = phys_fs_block as i32;
                final_flashfs.root.read(&image, &layout);
            }
        }

        let fcrt_from_nand = final_flashfs
            .root
            .entries
            .iter()
            .find(|e| !e.deleted && e.file_name.eq_ignore_ascii_case("fcrt.bin"))
            .map(|e| e.data.clone());
        if extra.fcrt.is_none() {
            extra.fcrt = fcrt_from_nand;
        }

        let total_blocks = layout.total_blocks(image.len());
        let lba_map = LbaMap::from_layout(layout, total_blocks);

        let mut input_ldv_cb = None;
        let mut input_pd = None;

        if let Some(cb_b) = bl_mut.cb_b.as_ref() {
            info!("[builder] Input CB_B: data_len={}, metadata={}", cb_b.data.len(), cb_b.metadata.is_some());
            if let Some(meta) = &cb_b.metadata {
                input_ldv_cb = Some(meta.lockdown_value);
                input_pd = Some(meta.pairing_data);
                info!("[builder] Captured input CB_B LDV={}", meta.lockdown_value);
            } else {
                warn!("[builder] Input CB_B metadata is None after decryption!");
            }
        } else if let Some(cb) = bl_mut.cb.as_ref() {
            info!("[builder] Input CB (single): data_len={}, metadata={}", cb.data.len(), cb.metadata.is_some());
            if let Some(meta) = &cb.metadata {
                input_ldv_cb = Some(meta.lockdown_value);
                input_pd = Some(meta.pairing_data);
                info!("[builder] Captured input CB LDV={}", meta.lockdown_value);
            } else {
                warn!("[builder] Input CB metadata is None after decryption!");
            }
        }

        if input_pd.is_none() {
            input_pd = update.cf_0.as_ref().and_then(|cf| cf.metadata.as_ref().map(|m| m.pairing_data));
        }

        let ldv0 = update.cf_0.as_ref().and_then(|cf| cf.metadata.as_ref().map(|m| m.lockdown_value));
        let ldv1 = update.cf_1.as_ref().and_then(|cf| cf.metadata.as_ref().map(|m| m.lockdown_value));
        let input_ldv_cf = match (ldv0, ldv1) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            _ => None,
        };

        let corona_fs = if layout == NandLayout::Emmc {
            corona::load_slots(&image)
        } else {
            [Default::default(), Default::default()]
        };

        Ok(NandSkeleton {
            cpukey: Some(cpukey),
            image,
            lba_map: Some(lba_map),
            layout,
            total_blocks,
            options: BuildOptions {
                layout,
                lba_map: LbaMap::from_layout(layout, total_blocks),
                image_profile: (if bl_mut.cb_b.is_some() { "split" } else { "single" }).to_string(),
                build_mode: BuildMode::Normal,
                motherboard,
                gxunsafe: false,
                verbose: false,
                ..Default::default()
            },
            header,
            extra,
            kv: Some(kv),
            bootloaders: bl_mut,
            rebooter: None,
            update,
            rebooter_update: None,
            payloads: Vec::new(),
            flashfs: final_flashfs,
            mobile: MobileStore::new(),
            corona_fs,
            input_ldv_cb,
            input_ldv_cf,
            input_pd,
        })
    }

    fn parse_bootloader_chain(
        image: &[u8],
        cb_offset: usize,
        cf_ptr: usize,
        flashfs: &crate::builder::filesystem::flashfs::FlashFS,
    ) -> Result<(NandBootloaders, NandUpdate), String> {
        let mut bl = NandBootloaders { cb: None, cb_a: None, cb_x: None, cb_b: None, sc: None, cd: None, ce: None, khvpatch: None, xell: None };
        let mut update = NandUpdate { cf_0: None, cg_0: None, cf_1: None, cg_1: None };

        let mut off = cb_offset;
        let mut cf_count = 0;
        let mut cg_count = 0;
        let mut cb_seen = 0;
        let mut cf0_offset = 0;
        let mut cf1_offset = 0;

        let fetch_cg_data = |off: usize, bl_size: usize, cg_count: usize, cf0_offset: usize, cf1_offset: usize, image: &[u8], flashfs: &FlashFS| -> Vec<u8> {
            let slot_start = if cg_count == 0 { cf0_offset } else { cf1_offset };
            let mut read_size = bl_size;
            if slot_start > 0 {
                let max_slot_end = slot_start + 0x10000;
                if off + read_size > max_slot_end {
                    read_size = max_slot_end - off;
                }
            }
            if off + read_size > image.len() {
                return vec![];
            }
            let mut data = image[off..off + read_size].to_vec();
            if data.len() < bl_size {
                let sysupdate_name = if cg_count == 0 { "sysupdate.xexp1" } else { "sysupdate.xexp2" };
                if let Some(entry) = flashfs.root.entries.iter().find(|e| e.file_name.to_lowercase() == sysupdate_name) {
                    let needed = bl_size - data.len();
                    data.extend_from_slice(&entry.data[..std::cmp::min(needed, entry.data.len())]);
                } else {
                    warn!("[builder] CG{} overflows patch slot but {} not found in FlashFS!", cg_count + 1, sysupdate_name);
                    if off + bl_size <= image.len() {
                        data = image[off..off + bl_size].to_vec();
                    }
                }
            }
            data
        };

        // Primary chain walk
        let mut iteration = 0;
        while iteration < 16 {
            iteration += 1;

            if off + 0x10 > image.len() {
                info!("[builder] End of bootloader chain at offset 0x{:08X}", off);
                break;
            }

            let bl_header = match BootloaderHeader::read_from_prefix(&image[off..off + 0x10]) {
                Ok((h, _)) => h,
                Err(_) => {
                    info!("[builder] Invalid bootloader header at offset 0x{:08X}", off);
                    break;
                }
            };

            let bl_size = bl_header.size.get() as usize;
            let bl_version = bl_header.version.get();

            // Validate size bounds - if invalid, stop the chain walk gracefully
            // and let CF_Ptr bridging handle the gap (common between CE and CF)
            if bl_size < 0x10 || bl_size > 0x2000000 {
                info!("[builder] Invalid bootloader size at 0x{:08X} (0x{:X}), stopping chain walk", off, bl_size);
                break;
            }
            if off + bl_size > image.len() {
                info!("[builder] Bootloader at 0x{:08X} extends past image end (size 0x{:X}), stopping", off, bl_size);
                break;
            }

            let bl_data = image[off..off + bl_size].to_vec();
            let aligned_size = (bl_size + 0xF) & 0xFFFFFFF0;

            match bl_header.get_type() {
                XenonBlType::CB => {
                    cb_seen += 1;
                    let flags = bl_header.flags.get();
                    let has_cba_flag = (flags & 0x800) == 0x800;
                    let is_single = cb_seen == 1 && !has_cba_flag;
                    let is_cba = cb_seen == 1 && has_cba_flag;
                    let is_cbx = cb_seen == 2
                        && has_cba_flag                   // stub still carries 0x800
                        && bl_size <= 0x500               // stub is very small (0x400 on Corona)
                        && bl_header.pairing.get() == 0; // stub pairing word is 0x0000
                                                         // CB_B = anything that doesn't match the above (cb_seen >= 2, or cb_seen == 3)

                    if is_single {
                        info!("[builder] CB (single) at 0x{:08X} (v{}, 0x{:X} bytes)", off, bl_version, bl_size);
                        bl.cb = Some(BootloaderCb::parse(&bl_data)?);
                    } else if is_cba {
                        info!("[builder] CB_A at 0x{:08X} (v{}, 0x{:X} bytes)", off, bl_version, bl_size);
                        bl.cb_a = Some(BootloaderCb::parse(&bl_data)?);
                    } else if is_cbx {
                        info!("[builder] CB_X (RGH3 stub) at 0x{:08X} (v{}, 0x{:X} bytes)", off, bl_version, bl_size);
                        bl.cb_x = Some(BootloaderCb::parse(&bl_data)?);
                    } else {
                        info!("[builder] CB_B at 0x{:08X} (v{}, 0x{:X} bytes)", off, bl_version, bl_size);
                        bl.cb_b = Some(BootloaderCb::parse(&bl_data)?);
                    }
                }
                XenonBlType::SC => {
                    info!("[builder] SC at 0x{:08X} (v{}, 0x{:X} bytes)", off, bl_version, bl_size);
                    bl.sc = Some(BootloaderSc::parse(&bl_data)?);
                }
                XenonBlType::CD => {
                    info!("[builder] CD at 0x{:08X} (v{}, 0x{:X} bytes)", off, bl_version, bl_size);
                    bl.cd = Some(BootloaderCd::parse(&bl_data)?);
                }
                XenonBlType::CE => {
                    info!("[builder] CE at 0x{:08X} (v{}, 0x{:X} bytes)", off, bl_version, bl_size);
                    bl.ce = Some(BootloaderCe::parse(&bl_data)?);
                }
                XenonBlType::CF => {
                    info!("[builder] CF_{} at 0x{:08X} (v{}, 0x{:X} bytes)", cf_count + 1, off, bl_version, bl_size);
                    let cf = BootloaderCf::parse(&bl_data)?;
                    if cf_count == 0 {
                        update.cf_0 = Some(cf);
                        cf0_offset = off;
                    } else {
                        update.cf_1 = Some(cf);
                        cf1_offset = off;
                    }
                    cf_count += 1;
                }
                XenonBlType::CG => {
                    info!("[builder] CG_{} at 0x{:08X} (v{}, 0x{:X} bytes)", cg_count + 1, off, bl_version, bl_size);
                    let actual_data = fetch_cg_data(off, bl_size, cg_count, cf0_offset, cf1_offset, image, &flashfs);
                    if actual_data.is_empty() {
                        info!("[builder] Failed to fetch complete CG data, stopping chain walk");
                        break;
                    }
                    let cg = BootloaderCg::parse(&actual_data)?;
                    if cg_count == 0 {
                        update.cg_0 = Some(cg);
                    } else {
                        update.cg_1 = Some(cg);
                    }
                    cg_count += 1;
                }
                _ => {
                    // For zeropaired or unencryped payloads
                    let zero_key = [0u8; 16];
                    let probe_len = 0x100.min(image.len().saturating_sub(off));
                    if probe_len >= 0x10 {
                        if let Some(disco) = bl_try_identify(&image[off..off + probe_len], &zero_key) {
                            info!(
                                "[builder] Discovery probe at 0x{:08X}: {} v{} (0x{:X} bytes) via {} key — not a standard chain type, stopping",
                                off, disco.magic, disco.version, disco.size, disco.key_source
                            );
                        } else {
                            info!("[builder] Unknown bootloader type at 0x{:08X}, stopping chain walk", off);
                        }
                    } else {
                        info!("[builder] Unknown bootloader type at 0x{:08X}, stopping chain walk", off);
                    }
                    break;
                }
            }

            off += aligned_size;
        }

        // if not found in primary walk, try CF_Ptr
        if update.cf_0.is_none() && cf_ptr > 0 && cf_ptr < image.len() {
            info!("[builder] CF not found after CE, trying CF_Ptr at 0x{:08X}", cf_ptr);
            off = cf_ptr;

            while off + 0x10 <= image.len() && cf_count < 2 {
                let bl_header = match BootloaderHeader::read_from_prefix(&image[off..off + 0x10]) {
                    Ok((h, _)) => h,
                    Err(_) => break,
                };

                let bl_size = bl_header.size.get() as usize;
                if bl_size < 0x10 || bl_size > 0x2000000 {
                    break;
                }
                if off + bl_size > image.len() {
                    break;
                }

                let bl_data = image[off..off + bl_size].to_vec();
                let aligned_size = (bl_size + 0xF) & 0xFFFFFFF0;

                match bl_header.get_type() {
                    XenonBlType::CF => {
                        info!("[builder] CF_{} at 0x{:08X} (v{}, 0x{:X} bytes)", cf_count + 1, off, bl_header.version.get(), bl_size);
                        let cf = BootloaderCf::parse(&bl_data)?;
                        if cf_count == 0 {
                            update.cf_0 = Some(cf);
                            cf0_offset = off;
                        } else {
                            update.cf_1 = Some(cf);
                            cf1_offset = off;
                        }
                        cf_count += 1;
                    }
                    XenonBlType::CG => {
                        info!("[builder] CG_{} at 0x{:08X} (v{}, 0x{:X} bytes)", cg_count + 1, off, bl_header.version.get(), bl_size);
                        let actual_data = fetch_cg_data(off, bl_size, cg_count, cf0_offset, cf1_offset, image, &flashfs);
                        if actual_data.is_empty() {
                            info!("[builder] Failed to fetch complete CG data, stopping CF_Ptr chain walk");
                            break;
                        }
                        let cg = BootloaderCg::parse(&actual_data)?;
                        if cg_count == 0 {
                            update.cg_0 = Some(cg);
                        } else {
                            update.cg_1 = Some(cg);
                        }
                        cg_count += 1;
                    }
                    _ => break,
                }

                off += aligned_size;
            }

            // if CF still not found after direct CF_Ptr read, scan in 0x10-byte steps through a 128KB window
            if update.cf_0.is_none() {
                let zero_key = [0u8; 16];
                let scan_range = 0x20000;
                let image_ref: &[u8] = image;
                let mut read_fn = |offset: usize, len: usize| -> Option<Vec<u8>> {
                    if offset + len <= image_ref.len() {
                        Some(image_ref[offset..offset + len].to_vec())
                    } else {
                        None
                    }
                };
                if let Some((found_off, disco)) = bl_scan(&mut read_fn, cf_ptr, scan_range, &zero_key) {
                    info!("[builder] Discovery scan found {} v{} at 0x{:08X} via {} key", disco.magic, disco.version, found_off, disco.key_source);
                    off = found_off;
                    while off + 0x10 <= image.len() && cf_count < 2 {
                        let bl_header = match BootloaderHeader::read_from_prefix(&image[off..off + 0x10]) {
                            Ok((h, _)) => h,
                            Err(_) => break,
                        };
                        let bl_size = bl_header.size.get() as usize;
                        if bl_size < 0x10 || bl_size > 0x2000000 {
                            break;
                        }
                        if off + bl_size > image.len() {
                            break;
                        }
                        let bl_data = image[off..off + bl_size].to_vec();
                        let aligned_size = (bl_size + 0xF) & 0xFFFFFFF0;
                        match bl_header.get_type() {
                            XenonBlType::CF => {
                                info!("[builder] CF_{} at 0x{:08X} (v{}, 0x{:X} bytes) [discovery]", cf_count + 1, off, bl_header.version.get(), bl_size);
                                let cf = BootloaderCf::parse(&bl_data)?;
                                if cf_count == 0 {
                                    update.cf_0 = Some(cf);
                                    cf0_offset = off;
                                } else {
                                    update.cf_1 = Some(cf);
                                    cf1_offset = off;
                                }
                                cf_count += 1;
                            }
                            XenonBlType::CG => {
                                info!("[builder] CG_{} at 0x{:08X} (v{}, 0x{:X} bytes) [discovery]", cg_count + 1, off, bl_header.version.get(), bl_size);
                                let actual_data = fetch_cg_data(off, bl_size, cg_count, cf0_offset, cf1_offset, image, &flashfs);
                                if actual_data.is_empty() {
                                    info!("[builder] Failed to fetch complete CG data, stopping discovery scan");
                                    break;
                                }
                                let cg = BootloaderCg::parse(&actual_data)?;
                                if cg_count == 0 {
                                    update.cg_0 = Some(cg);
                                } else {
                                    update.cg_1 = Some(cg);
                                }
                                cg_count += 1;
                            }
                            _ => break,
                        }
                        off += aligned_size;
                    }
                } else {
                    info!("[builder] Discovery scan: no CF found in 0x{:08X}..0x{:08X}", cf_ptr, cf_ptr + scan_range);
                }
            }
        }

        Ok((bl, update))
    }

    /// Assembles a JTAG rebooter image with two bootloader chains.
    /// Chain 0 (Base) starts at 0x8000.
    /// Chain 1 (Update) starts at 0x20000.
    pub fn assemble_rebooter(&mut self) -> Result<Vec<u8>, String> {
        let layout = &self.layout;
        let expected_size = self.total_blocks * layout.logical_pages_per_block() * 0x200;

        let mut logical_image = self.image.clone();
        if logical_image.len() != expected_size {
            logical_image.resize(expected_size, 0xFF);
        }

        let mut header = self.header.clone();

        let smc_len = self.extra.smc.len();
        let target_smc_offset = match layout {
            NandLayout::Emmc => 0x800,
            _ => 0x1000,
        };
        if smc_len > 0 {
            if target_smc_offset + smc_len > logical_image.len() {
                return Err(format!("SMC write out of bounds: offset 0x{:X} + size 0x{:X} > image 0x{:X}", target_smc_offset, smc_len, logical_image.len()));
            }
            logical_image[target_smc_offset..target_smc_offset + smc_len].copy_from_slice(&self.extra.smc);
        }

        let kv_offset = 0x4000usize;
        if !self.extra.keyvault.is_empty() {
            if kv_offset + self.extra.keyvault.len() > logical_image.len() {
                return Err(format!(
                    "Keyvault write out of bounds: offset 0x{:X} + size 0x{:X} > image 0x{:X}",
                    kv_offset,
                    self.extra.keyvault.len(),
                    logical_image.len()
                ));
            }
            logical_image[kv_offset..kv_offset + self.extra.keyvault.len()].copy_from_slice(&self.extra.keyvault);
        }

        let mut curr_off = 0x8000;
        let mut bl_stages = Vec::new();
        if let Some(cb) = &self.bootloaders.cb_a {
            bl_stages.push(("CB_A", cb.serialize()));
        } else if let Some(cb) = &self.bootloaders.cb {
            bl_stages.push(("CB", cb.serialize()));
        }

        if let Some(cbb) = &self.bootloaders.cb_b {
            bl_stages.push(("CB_B", cbb.serialize()));
        }
        if let Some(cd) = &self.bootloaders.cd {
            bl_stages.push(("CD", cd.serialize()));
        }

        for (name, mut data) in bl_stages {
            let declared_size = if data.len() >= 16 {
                let h = BootloaderHeader::read_from_prefix(&data).map(|(h, _)| h.size.get()).unwrap_or(0);
                h as usize
            } else {
                0
            };
            let aligned = (declared_size + 0xF) & !0xF;
            if aligned > 0 && data.len() != aligned {
                if data.len() < aligned {
                    data.resize(aligned, 0);
                } else if data.len() >= 0x10 {
                    let new_len = data.len() as u32;
                    data[0x0C..0x10].copy_from_slice(&new_len.to_be_bytes());
                }
            }

            if curr_off + data.len() > logical_image.len() {
                return Err(format!("Chain 0 {} overflow at 0x{:X}", name, curr_off));
            }
            info!("[builder] JTAG Chain 0: Serializing {} at 0x{:08X}", name, curr_off);
            logical_image[curr_off..curr_off + data.len()].copy_from_slice(&data);
            curr_off += data.len();
        }

        let rebooter = self.rebooter.as_ref().ok_or("Rebooter chain (Chain 1) is missing for JTAG build")?;
        curr_off = 0x20000;
        let mut update_stages = Vec::new();
        if let Some(cb) = &rebooter.cb {
            update_stages.push(("CB", cb.serialize()));
        }
        if let Some(cd) = &rebooter.cd {
            update_stages.push(("CD", cd.serialize()));
        }
        if let Some(ce) = &rebooter.ce {
            update_stages.push(("CE", ce.serialize()));
        }

        for (name, mut data) in update_stages {
            let declared_size = if data.len() >= 16 {
                let h = BootloaderHeader::read_from_prefix(&data).map(|(h, _)| h.size.get()).unwrap_or(0);
                h as usize
            } else {
                0
            };
            let aligned = (declared_size + 0xF) & !0xF;
            if aligned > 0 && data.len() != aligned {
                if data.len() < aligned {
                    data.resize(aligned, 0);
                } else if data.len() >= 0x10 {
                    let new_len = data.len() as u32;
                    data[0x0C..0x10].copy_from_slice(&new_len.to_be_bytes());
                }
            }

            if curr_off + data.len() > logical_image.len() {
                return Err(format!("Chain 1 {} overflow at 0x{:X}", name, curr_off));
            }
            info!("[builder] JTAG Chain 1: Serializing {} at 0x{:08X}", name, curr_off);
            logical_image[curr_off..curr_off + data.len()].copy_from_slice(&data);
            curr_off += data.len();
        }

        let target_cf_offset = (curr_off + 0xFFFF) & !0xFFFF; // Align to 64KB for JTAG CF/CG
        header.cf_offset.set(target_cf_offset as u32);
        header.prefix.size.set(target_cf_offset as u32);

        let mut curr_update = target_cf_offset;

        let cf0 = self.update.cf_0.as_ref();
        let cg0 = self.update.cg_0.as_ref();

        if let Some(cf) = cf0.cloned() {
            let data = cf.serialize();
            logical_image[curr_update..curr_update + data.len()].copy_from_slice(&data);
            curr_update += data.len();

            if let Some(cg) = cg0.cloned() {
                let cg_off = (curr_update + 0xF) & !0xF;
                let data = cg.serialize();
                logical_image[cg_off..cg_off + data.len()].copy_from_slice(&data);
            }

            let slot1_start = target_cf_offset + 0x10000;
            let slot1_end = (slot1_start + 0x10000).min(logical_image.len());
            if slot1_start < logical_image.len() {
                logical_image[slot1_start..slot1_end].fill(0xFF);
            }
        }

        let chain_profile = if self.bootloaders.cb_b.is_some() { "split" } else { "single" };
        let (fs_addr_calc, smc_config_offset, phys_fs_block) =
            LayoutCalculator::calculate(SouthbridgeType::from(self.options.motherboard), chain_profile, *layout);
        let mut target_fs_block = phys_fs_block as i32;
        if !self.flashfs.root.entries.is_empty() && matches!(layout, NandLayout::Sb | NandLayout::Xsb | NandLayout::Bb) && target_fs_block >= 0 {
            let page_size = 0x200usize;
            let pages_per_block = layout.logical_pages_per_block();
            let logical_block_size = pages_per_block * page_size;

            let bm_count = page_size / 2;
            let fn_count = page_size / 0x20;

            let non_deleted_count = self.flashfs.root.entries.iter().filter(|e| !e.deleted).count();
            let required_data_blocks: usize = self
                .flashfs
                .root
                .entries
                .iter()
                .filter(|e| !e.deleted)
                .map(|e| {
                    let len = e.data.len().max(1);
                    (len + logical_block_size - 1) / logical_block_size
                })
                .sum();

            let max_entries_per_root_block = ((pages_per_block + 1) / 2) * fn_count;
            let max_bmap_per_root_block = (pages_per_block / 2) * bm_count;
            let total_blocks = layout.total_blocks(logical_image.len());

            let root_blocks_needed_for_entries = (non_deleted_count + max_entries_per_root_block - 1) / max_entries_per_root_block.max(1);
            let root_blocks_needed_for_bmap = (total_blocks + max_bmap_per_root_block - 1) / max_bmap_per_root_block.max(1);
            let root_blocks_needed = root_blocks_needed_for_entries.max(root_blocks_needed_for_bmap).max(1);

            let reserve_start = layout.reserve_start(logical_image.len());
            let config_start = reserve_start.saturating_sub(4);
            let available_blocks = config_start.saturating_sub(target_fs_block as usize);

            let required_total_blocks = required_data_blocks + root_blocks_needed;

            if required_total_blocks > available_blocks {
                let patch_slots = if self.options.dualpatchslots || self.update.cf_1.is_some() { 2usize } else { 1usize };
                let patch_slot_size = patch_slots.saturating_mul(0x10000);
                let sysupdate_end = (target_cf_offset as usize).saturating_add(patch_slot_size);
                let min_fs_block = ((sysupdate_end + logical_block_size - 1) / logical_block_size) as i32;
                let desired_start = (config_start as i32).saturating_sub(required_total_blocks as i32);
                let new_start = desired_start.max(min_fs_block).max(4);

                if new_start < target_fs_block {
                    warn!(
                        "[builder] FlashFS target block {} leaves insufficient space (need {} blocks, have {}); moving start to {}",
                        target_fs_block, required_total_blocks, available_blocks, new_start
                    );
                    target_fs_block = new_start;
                }
            }
        }

        header.smc_config_offset.set(smc_config_offset);

        let patch_slot_size: u32 = 0x10000;
        header.fs_addr.set(patch_slot_size);

        let has_vfuses = self.payloads.iter().any(|p| p.description.eq_ignore_ascii_case("virtual fuses"));
        let patch_stream_start = (header.cf_offset.get() as usize)
            .saturating_add(patch_slot_size as usize)
            .saturating_add(if has_vfuses { 0x60 } else { 0x10 });

        let mut khv_len = 0usize;
        if let Some(records) = &self.bootloaders.khvpatch {
            if !self.options.khv_apply {
                let patch_stream = crate::core::images::gxp::serialize_records(records);
                khv_len = patch_stream.len();
                if patch_stream_start + khv_len > logical_image.len() {
                    return Err(format!("KHV patch stream overflow at 0x{:X}: need 0x{:X} bytes", patch_stream_start, khv_len));
                }
                logical_image[patch_stream_start..patch_stream_start + khv_len].copy_from_slice(&patch_stream);
                info!("[builder] Injected KHV patch stream at 0x{:08X} (Size: 0x{:X})", patch_stream_start, khv_len);

                let logical_block_size = layout.logical_pages_per_block() * 0x200;
                let start_block = patch_stream_start / logical_block_size;
                let end_block = (patch_stream_start + khv_len + logical_block_size - 1) / logical_block_size;
                for b in start_block..end_block {
                    if b < self.flashfs.root.block_map.len() {
                        self.flashfs.root.block_map[b] = 0x1FFB;
                    }
                }
            }
        }

        let mut final_payloads = self.payloads.clone();
        let mut current_payload_offset = (patch_stream_start + khv_len + 0x1F) & !0x1F;
        let mut payload_list = PayloadList::new();

        for payload in &mut final_payloads {
            let addr = if let Some(fixed) = payload.fixed_address {
                fixed as usize
            } else {
                current_payload_offset
            };

            payload.address = addr as u32;
            payload_list.entries.push(payload.clone());

            // Reserve blocks in FlashFS to prevent overwriting
            let logical_block_size = layout.logical_pages_per_block() * 0x200;
            let start_block = addr / logical_block_size;
            let end_block = (addr + payload.data.len() + logical_block_size - 1) / logical_block_size;

            for b in start_block..end_block {
                if b < self.flashfs.root.block_map.len() {
                    self.flashfs.root.block_map[b] = 0x1FFB; // Reserved
                }
            }

            if payload.fixed_address.is_none() {
                current_payload_offset = (current_payload_offset + payload.data.len() + 0x1F) & !0x1F;
            }
        }

        if !payload_list.entries.is_empty() {
            header.payload_indicator.set(0x1337);

            // Write the Payload Table at 0x100
            let table_data = payload_list.serialize();
            if table_data.len() > 0x100 {
                warn!("[builder] Payload Table at 0x100 exceeds 256 bytes! This may overwrite other header data.");
            }
            let table_len = table_data.len().min(0x100);
            logical_image[0x100..0x100 + table_len].copy_from_slice(&table_data[..table_len]);

            // Write payload data
            for payload in &payload_list.entries {
                let addr = payload.address as usize;
                if addr + payload.data.len() > logical_image.len() {
                    logical_image.resize(addr + payload.data.len(), 0xFF);
                }
                logical_image[addr..addr + payload.data.len()].copy_from_slice(&payload.data);
                info!("[builder] Injected payload '{}' at 0x{:08X} (Size: 0x{:X})", payload.description, addr, payload.data.len());
            }
        }

        let fs_addr_effective = if target_fs_block >= 0 {
            (target_fs_block as u32) * (layout.logical_pages_per_block() as u32) * 0x200
        } else {
            fs_addr_calc
        };

        if !self.flashfs.root.entries.is_empty() && fs_addr_effective > 0 {
            let mut root = self.flashfs.root.clone();
            let logical_block_size = layout.logical_pages_per_block() * 0x200;
            root.block_number = (fs_addr_effective as usize / logical_block_size) as i32;
            root.create_defaults(logical_image.len(), layout, root.block_number as u16);
            for e in root.entries.iter_mut() {
                if !e.deleted {
                    e.block_number = 0;
                    e.page_number = 0;
                }
            }
            for payload in &payload_list.entries {
                let addr = payload.address as usize;
                let start_block = addr / logical_block_size;
                let end_block = (addr + payload.data.len() + logical_block_size - 1) / logical_block_size;
                for b in start_block..end_block {
                    if b < root.block_map.len() {
                        root.block_map[b] = 0x1FFB;
                    }
                }
            }

            root.write_logical(&mut logical_image, layout)?;
            let fs_root_block = root.serialize_logical(*layout);
            logical_image[fs_addr_effective as usize..fs_addr_effective as usize + fs_root_block.len()].copy_from_slice(&fs_root_block);
            self.flashfs.root = root;
        }

        header.smc_boot_offset.set(target_smc_offset as u32);
        header.smc_boot_size.set(smc_len as u32);
        header.kv_addr.set(kv_offset as u32);
        header.kv_size.set(self.extra.keyvault.len() as u32);

        // Update prefix entrypoint to CB_A in Chain 0
        header.prefix.entrypoint.set(0x8000);

        header.apply_xebuild_header_flags(&self.options, &self.extra);

        let header_bytes = zerocopy::IntoBytes::as_bytes(&header);
        logical_image[..header_bytes.len()].copy_from_slice(header_bytes);

        if self.options.image_profile == "onef" {
            if let Some(xell) = self.bootloaders.xell.as_ref() {
                let xell_offset = xell
                    .get_target_offset(self.layout, &self.options.image_profile, false, 0, 0x10000)
                    .map_err(|e| e.to_string())? as usize;
                info!("[builder] JTAG Chain 1: Injecting XeLL-1F payload at 0x{:08X}", xell_offset);
                logical_image[xell_offset..xell_offset + xell.data.len()].copy_from_slice(&xell.data);
            }
        } else if let Some(rebooter) = &self.rebooter {
            if let Some(xell) = rebooter.xell.as_ref() {
                let xell_offset = xell
                    .get_target_offset(self.layout, &self.options.image_profile, false, 0, 0x10000)
                    .map_err(|e| e.to_string())? as usize;
                info!("[builder] JTAG Chain 1: Injecting XeLL-2F payload at 0x{:08X}", xell_offset);
                logical_image[xell_offset..xell_offset + xell.data.len()].copy_from_slice(&xell.data);
            }
        }

        Ok(logical_image)
    }

    pub fn assemble_logical(&mut self) -> Result<Vec<u8>, String> {
        let layout = &self.layout;
        let expected_size = self.total_blocks * layout.logical_pages_per_block() * 0x200;

        let mut logical_image = self.image.clone();
        if logical_image.len() != expected_size {
            logical_image.resize(expected_size, 0xFF);
        }

        let mut header = self.header.clone();

        let smc_len = self.extra.smc.len();
        let smc_default_offset = match layout {
            NandLayout::Emmc => 0x800,
            _ => 0x1000,
        };
        let target_smc_offset = if smc_len > 0 {
            0x4000usize.checked_sub(smc_len).ok_or_else(|| format!("SMC too large: 0x{:X} bytes", smc_len))?
        } else {
            smc_default_offset
        };

        let bootchain_start = 0x8000;
        let mut curr_bl = bootchain_start;
        let mut bl_stages = Vec::new();

        if let Some(cb) = &self.bootloaders.cb {
            bl_stages.push(("CB", cb.serialize()));
        }
        if let Some(cba) = &self.bootloaders.cb_a {
            bl_stages.push(("CB_A", cba.serialize()));
        }
        if let Some(cbx) = &self.bootloaders.cb_x {
            bl_stages.push(("CB_X", cbx.serialize()));
        }
        if let Some(cbb) = &self.bootloaders.cb_b {
            bl_stages.push(("CB_B", cbb.serialize()));
        }
        if let Some(sc) = &self.bootloaders.sc {
            bl_stages.push(("SC", sc.serialize()));
        }
        if let Some(cd) = &self.bootloaders.cd {
            bl_stages.push(("CD", cd.serialize()));
        }
        if let Some(ce) = &self.bootloaders.ce {
            bl_stages.push(("CE", ce.serialize()));
        }

        for (i, (name, mut data)) in bl_stages.into_iter().enumerate() {
            let declared_size = if data.len() >= 16 {
                let h = BootloaderHeader::read_from_prefix(&data).map(|(h, _)| h.size.get()).unwrap_or(0);
                h as usize
            } else {
                0
            };

            let aligned_declared = (declared_size + 0xF) & !0xF;
            if aligned_declared > 0 && data.len() != aligned_declared {
                if data.len() < aligned_declared {
                    warn!(
                        "[builder] {} length mismatch: data is 0x{:X}, header says 0x{:X} (aligned 0x{:X}). Padding...",
                        name,
                        data.len(),
                        declared_size,
                        aligned_declared
                    );
                    data.resize(aligned_declared, 0);
                } else {
                    warn!(
                        "[builder] {} length mismatch: data is 0x{:X}, header says 0x{:X} (aligned 0x{:X}). Keeping extra bytes...",
                        name,
                        data.len(),
                        declared_size,
                        aligned_declared
                    );
                    if data.len() >= 0x10 {
                        let new_len = data.len() as u32;
                        data[0x0C..0x10].copy_from_slice(&new_len.to_be_bytes());
                    }
                }
            }

            if curr_bl + data.len() > logical_image.len() {
                return Err(format!("Bootchain stage {} ({}) overflow at 0x{:X}", i, name, curr_bl));
            }
            info!("[builder] Serializing {} at 0x{:08X} (0x{:X} bytes)", name, curr_bl, data.len());
            logical_image[curr_bl..curr_bl + data.len()].copy_from_slice(&data);
            curr_bl += data.len();
        }

        let build_profile = self.options.image_profile.clone();
        let build_profile_l = build_profile.to_ascii_lowercase();

        let forensic_cf_default = match layout {
            NandLayout::Bb => {
                // XeLL GG payloads are typically 0x40000 bytes at 0x70000, so CF/CG must not start at 0x80000
                // (it would be overwritten by the payload). xeBuild uses 0xC0000 for BB glitch builds.
                if build_profile_l.contains("glitch") {
                    0xC0000
                } else {
                    0x80000
                }
            }
            NandLayout::Emmc => 0xB0000,
            NandLayout::Sb | NandLayout::Xsb => {
                if build_profile_l == "glitch2m" || build_profile_l.contains("glitch2m") || build_profile_l == "devgl" || build_profile_l == "xdkbuild" {
                    0xD0000
                } else if build_profile_l.contains("glitch") || build_profile_l.contains("glitchr") || build_profile_l.contains("glitch2r") {
                    0xB0000
                } else {
                    0x70000
                }
            }
        };

        // If the bootchain has realigned/extended into the CF area, shift CF to the next 64KB block
        let target_cf_offset = if curr_bl > forensic_cf_default {
            (curr_bl + 0xFFFF) & 0xFFFF0000
        } else {
            forensic_cf_default
        };

        let chain_profile = if self.bootloaders.cb_b.is_some() { "split" } else { "single" };

        let sb_type = SouthbridgeType::from(self.options.motherboard);
        let (_fs_root_addr, smc_config_offset, phys_fs_block) = LayoutCalculator::calculate(sb_type, chain_profile, self.layout);
        header.smc_config_offset = U32::new(smc_config_offset);


        header.smc_boot_offset.set(target_smc_offset as u32);
        header.smc_boot_size.set(smc_len as u32);
        header.cf_offset.set(target_cf_offset as u32);
        header.prefix.size.set(target_cf_offset as u32);
        header.kv_addr.set(0x4000); // Enforce Block 1 KV

        let mut target_fs_block = if phys_fs_block > 0 { phys_fs_block as i32 } else { self.flashfs.root.block_number };
        let reserve_start = layout.reserve_start(logical_image.len()) as i32;
        if *layout != NandLayout::Emmc && target_fs_block >= reserve_start {
            warn!(
                "[builder] FlashFS target block {} is in/after the reserved remap area (>= 0x{:X}); forcing to 0x110 for compatibility",
                target_fs_block, reserve_start
            );
            target_fs_block = 0x110;
        }

        let cf0 = self.update.cf_0.as_ref().map(|b| b.serialize());
        let cg0 = self.update.cg_0.as_ref().map(|b| b.serialize());
        let cf1 = self.update.cf_1.as_ref().map(|b| b.serialize());
        let cg1 = self.update.cg_1.as_ref().map(|b| b.serialize());

        if !self.flashfs.root.entries.is_empty() && matches!(layout, NandLayout::Sb | NandLayout::Xsb | NandLayout::Bb) && target_fs_block >= 0 {
            let page_size = 0x200usize;
            let pages_per_block = layout.logical_pages_per_block();
            let logical_block_size = pages_per_block * page_size;

            let bm_count = page_size / 2;
            let fn_count = page_size / 0x20;

            let non_deleted_count = self.flashfs.root.entries.iter().filter(|e| !e.deleted).count();
            let required_data_blocks: usize = self
                .flashfs
                .root
                .entries
                .iter()
                .filter(|e| !e.deleted)
                .map(|e| {
                    let len = e.data.len().max(1);
                    (len + logical_block_size - 1) / logical_block_size
                })
                .sum();

            let mut extra_non_deleted = 0usize;
            let mut extra_data_blocks = 0usize;
            if let (Some(cf0d), Some(cg0d)) = (cf0.as_ref(), cg0.as_ref()) {
                let cg0_offset = (target_cf_offset + cf0d.len() + 0xF) & !0xF;
                let slot0_end = target_cf_offset.saturating_add(0x10000);
                if cg0_offset < slot0_end {
                    let cg_to_slot = cg0d.len().min(slot0_end - cg0_offset);
                    if cg_to_slot < cg0d.len() {
                        let overflow_len = cg0d.len() - cg_to_slot;
                        let sys_name = "sysupdate.xexp1";
                        let existing = self
                            .flashfs
                            .root
                            .entries
                            .iter()
                            .find(|e| !e.deleted && e.file_name.eq_ignore_ascii_case(sys_name))
                            .map(|e| e.data.len())
                            .unwrap_or(0);

                        if existing == 0 && overflow_len > 0 {
                            extra_non_deleted = 1;
                            extra_data_blocks = (overflow_len + logical_block_size - 1) / logical_block_size;
                        } else if overflow_len > 0 {
                            let old_blocks = (existing.max(1) + logical_block_size - 1) / logical_block_size;
                            let new_blocks = ((existing + overflow_len).max(1) + logical_block_size - 1) / logical_block_size;
                            extra_data_blocks = new_blocks.saturating_sub(old_blocks);
                        }
                    }
                }
            }

            let max_entries_per_root_block = ((pages_per_block + 1) / 2) * fn_count;
            let max_bmap_per_root_block = (pages_per_block / 2) * bm_count;
            let total_blocks = layout.total_blocks(logical_image.len());

            let root_blocks_needed_for_entries =
                (non_deleted_count + extra_non_deleted + max_entries_per_root_block - 1) / max_entries_per_root_block.max(1);
            let root_blocks_needed_for_bmap = (total_blocks + max_bmap_per_root_block - 1) / max_bmap_per_root_block.max(1);
            let root_blocks_needed = root_blocks_needed_for_entries.max(root_blocks_needed_for_bmap).max(1);

            let reserve_start_u = reserve_start as usize;
            let config_start = reserve_start_u.saturating_sub(4);
            let available_blocks = config_start.saturating_sub(target_fs_block as usize);

            let required_total_blocks = required_data_blocks + extra_data_blocks + root_blocks_needed;

            if required_total_blocks > available_blocks {
                let patch_slots = if self.options.dualpatchslots || self.update.cf_1.is_some() { 2usize } else { 1usize };
                let patch_slot_size = patch_slots.saturating_mul(0x10000);
                let sysupdate_end = (target_cf_offset as usize).saturating_add(patch_slot_size);
                let min_fs_block = ((sysupdate_end + logical_block_size - 1) / logical_block_size) as i32;
                let desired_start = (config_start as i32).saturating_sub(required_total_blocks as i32);
                let new_start = desired_start.max(min_fs_block).max(4);

                if new_start < target_fs_block {
                    warn!(
                        "[builder] FlashFS target block {} leaves insufficient space (need {} blocks, have {}); moving start to {}",
                        target_fs_block, required_total_blocks, available_blocks, new_start
                    );
                    target_fs_block = new_start;
                }
            }
        }

        if !self.flashfs.root.entries.is_empty() && target_fs_block >= 0 {
            let fs_logical_addr = (target_fs_block as u32) * (layout.logical_pages_per_block() as u32) * 0x200;
            info!("[builder] FlashFS root logical addr: 0x{:08X} (Block {})", fs_logical_addr, target_fs_block);
        }

        let kv_offset = header.kv_addr.get() as usize;
        if smc_len > 0 {
            if target_smc_offset + smc_len > logical_image.len() {
                return Err(format!("SMC write out of bounds: offset 0x{:X} + size 0x{:X} > image 0x{:X}", target_smc_offset, smc_len, logical_image.len()));
            }
            logical_image[target_smc_offset..target_smc_offset + smc_len].copy_from_slice(&self.extra.smc);
        }
        if !self.extra.keyvault.is_empty() {
            if kv_offset + self.extra.keyvault.len() > logical_image.len() {
                return Err(format!(
                    "Keyvault write out of bounds: offset 0x{:X} + size 0x{:X} > image 0x{:X}",
                    kv_offset,
                    self.extra.keyvault.len(),
                    logical_image.len()
                ));
            }
            logical_image[kv_offset..kv_offset + self.extra.keyvault.len()].copy_from_slice(&self.extra.keyvault);
        }

        if let Some(cf0d) = cf0 {
            let cf0_offset = target_cf_offset;
            let reserve_two_slots = build_profile_l == "jtag"
                || build_profile_l == "1f"
                || build_profile_l == "2f"
                || build_profile_l == "devgl"
                || build_profile_l == "devkit"
                || build_profile_l == "xdkbuild"
                || build_profile_l.contains("glitch");

            let desired_patch_slots = if reserve_two_slots { 2 } else { if cf1.is_some() { 2 } else { 1 } };

            if self.options.dualpatchslots {
                if cf1.is_none() || cg1.is_none() {
                    return Err("dualpatchslots is enabled but CF1/CG1 is missing".to_string());
                }
                header.patch_slots.set(2);
            } else {
                header.patch_slots.set(desired_patch_slots);
            }

            if cf0_offset + cf0d.len() > logical_image.len() {
                return Err(format!("CF0 overflow at 0x{:X}: need 0x{:X} bytes", cf0_offset, cf0d.len()));
            }
            logical_image[cf0_offset..cf0_offset + cf0d.len()].copy_from_slice(&cf0d);
            if cf0_offset + 2 <= logical_image.len() {
                let magic = u16::from_be_bytes([logical_image[cf0_offset], logical_image[cf0_offset + 1]]);
                info!("[builder] CF0 magic at 0x{:08X}: 0x{:04X}", cf0_offset, magic);
            }

            // If there is no second slot, zero it out so stale CF1/CG1 bytes from
            // the input NAND image are not carried into the output.
            if !self.options.dualpatchslots && cf1.is_none() && header.patch_slots.get() >= 2 {
                let slot1_start = target_cf_offset + 0x10000;
                let slot1_end = (slot1_start + 0x10000).min(logical_image.len());
                if slot1_start < logical_image.len() {
                    logical_image[slot1_start..slot1_end].fill(0xFF);
                    info!("[builder] Cleared second CF/CG slot (0x{:X}..0x{:X}) — no CF1 present", slot1_start, slot1_end);
                }
            }

            let mut next_offset = cf0_offset + cf0d.len();

            if let Some(cg0d) = cg0 {
                // 16-byte align CG after CF
                let cg0_offset = (next_offset + 0xF) & !0xF;
                let max_slot_end = target_cf_offset + 0x10000;
                if cg0_offset >= max_slot_end {
                    warn!("[builder] CG0 starts at 0x{:X} which is past slot end 0x{:X}, skipping", cg0_offset, max_slot_end);
                    // Still advance past this slot so CF1 lands on the next 64KB boundary
                    next_offset = max_slot_end;
                } else {
                    let mut cg_to_slot = cg0d.len();
                    if cg0_offset + cg_to_slot > max_slot_end {
                        // CG overflows — write only the slot portion; overflow is in sysupdate.xexp1
                        cg_to_slot = max_slot_end - cg0_offset;
                    }
                    if cg0_offset + cg_to_slot > logical_image.len() {
                        return Err(format!("CG0 overflow at 0x{:X}: need 0x{:X} bytes", cg0_offset, cg_to_slot));
                    }
                    logical_image[cg0_offset..cg0_offset + cg_to_slot].copy_from_slice(&cg0d[0..cg_to_slot]);
                    if cg_to_slot < cg0d.len() {
                        let overflow = &cg0d[cg_to_slot..];
                        let idx = self
                            .flashfs
                            .root
                            .entries
                            .iter()
                            .position(|e| !e.deleted && e.file_name.eq_ignore_ascii_case("sysupdate.xexp1"));
                        match idx {
                            Some(i) => {
                                let mut new_data = Vec::with_capacity(overflow.len() + self.flashfs.root.entries[i].data.len());
                                new_data.extend_from_slice(overflow);
                                new_data.extend_from_slice(&self.flashfs.root.entries[i].data);
                                self.flashfs.root.entries[i].data = new_data;
                                self.flashfs.root.entries[i].size = self.flashfs.root.entries[i].data.len() as u32;
                                info!("[builder] Prepended 0x{:X} CG0 overflow bytes to sysupdate.xexp1", overflow.len());
                            }
                            None => {
                                let mut entry = crate::builder::filesystem::flashfs::FileSystemEntry::new(0);
                                entry.file_name = "sysupdate.xexp1".to_string();
                                entry.data = overflow.to_vec();
                                entry.size = entry.data.len() as u32;
                                self.flashfs.root.entries.push(entry);
                                info!("[builder] Created sysupdate.xexp1 with 0x{:X} CG0 overflow bytes", overflow.len());
                            }
                        }
                    }
                    if cg0_offset + 2 <= logical_image.len() {
                        let magic = u16::from_be_bytes([logical_image[cg0_offset], logical_image[cg0_offset + 1]]);
                        info!("[builder] CG0 magic at 0x{:08X}: 0x{:04X}", cg0_offset, magic);
                    }
                    // Always advance to slot end so CF1 starts on the next clean 64KB block
                    next_offset = max_slot_end;
                }
            } else {
                // No CG0 — still advance to slot end so CF1 is placed at the next 64KB boundary
                // Should probably error here instead
                next_offset = target_cf_offset + 0x10000;
            }

            if let Some(cf1d) = cf1 {
                // Align CF1 to the next 64KB block after CG0
                let cf1_offset = (next_offset + 0xFFFF) & !0xFFFF;
                if cf1_offset + cf1d.len() > logical_image.len() {
                    return Err(format!("CF1 overflow at 0x{:X}: need 0x{:X} bytes", cf1_offset, cf1d.len()));
                }
                logical_image[cf1_offset..cf1_offset + cf1d.len()].copy_from_slice(&cf1d);

                next_offset = cf1_offset + cf1d.len();

                if let Some(cg1d) = cg1 {
                    let cg1_offset = (next_offset + 0xF) & !0xF;
                    let max_slot_end = cf1_offset + 0x10000;
                    if cg1_offset >= max_slot_end {
                        warn!("[builder] CG1 starts at 0x{:X} which is past slot end 0x{:X}, skipping", cg1_offset, max_slot_end);
                    } else {
                        let mut cg_to_slot = cg1d.len();
                        if cg1_offset + cg_to_slot > max_slot_end {
                            cg_to_slot = max_slot_end - cg1_offset;
                        }
                        if cg1_offset + cg_to_slot > logical_image.len() {
                            return Err(format!("CG1 overflow at 0x{:X}: need 0x{:X} bytes", cg1_offset, cg_to_slot));
                        }
                        logical_image[cg1_offset..cg1_offset + cg_to_slot].copy_from_slice(&cg1d[0..cg_to_slot]);
                        if cg_to_slot < cg1d.len() {
                            let overflow = &cg1d[cg_to_slot..];
                            let idx = self
                                .flashfs
                                .root
                                .entries
                                .iter()
                                .position(|e| !e.deleted && e.file_name.eq_ignore_ascii_case("sysupdate.xexp2"));
                            match idx {
                                Some(i) => {
                                    let mut new_data = Vec::with_capacity(overflow.len() + self.flashfs.root.entries[i].data.len());
                                    new_data.extend_from_slice(overflow);
                                    new_data.extend_from_slice(&self.flashfs.root.entries[i].data);
                                    self.flashfs.root.entries[i].data = new_data;
                                    self.flashfs.root.entries[i].size = self.flashfs.root.entries[i].data.len() as u32;
                                    info!("[builder] Prepended 0x{:X} CG1 overflow bytes to sysupdate.xexp2", overflow.len());
                                }
                                None => {
                                    let mut entry = crate::builder::filesystem::flashfs::FileSystemEntry::new(0);
                                    entry.file_name = "sysupdate.xexp2".to_string();
                                    entry.data = overflow.to_vec();
                                    entry.size = entry.data.len() as u32;
                                    self.flashfs.root.entries.push(entry);
                                    info!("[builder] Created sysupdate.xexp2 with 0x{:X} CG1 overflow bytes", overflow.len());
                                }
                            }
                        }
                    }
                }
            }
        }

        let has_vfuses = self.payloads.iter().any(|p| p.description.eq_ignore_ascii_case("virtual fuses"));
        let patch_slot_size: u32 = 0x10000;

        let xell_payloads = [(self.bootloaders.xell.as_ref(), false), (self.rebooter.as_ref().and_then(|r| r.xell.as_ref()), true)];

        for (xell_opt, _is_rebooter) in xell_payloads {
            if let Some(xell) = xell_opt {
                let x_type = xell.identify();
                let xell_offset = xell
                    .get_target_offset(*layout, &build_profile, has_vfuses, header.cf_offset.get(), patch_slot_size)
                    .map_err(|e| e.to_string())? as usize;
                if xell_offset + xell.data.len() > logical_image.len() {
                    return Err(format!("XeLL ({:?}) overflow at 0x{:X}: need 0x{:X} bytes", x_type, xell_offset, xell.data.len()));
                }
                info!("[builder] Injecting XeLL payload ({:?}) at offset 0x{:08X}", x_type, xell_offset);
                logical_image[xell_offset..xell_offset + xell.data.len()].copy_from_slice(&xell.data);
            }
        }

        header.fs_addr.set(patch_slot_size);

        let patch_stream_start = (header.cf_offset.get() as usize)
            .saturating_add(patch_slot_size as usize)
            .saturating_add(if has_vfuses { 0x60 } else { 0x10 });

        let mut khv_len = 0usize;
        if let Some(records) = &self.bootloaders.khvpatch {
            if !self.options.khv_apply {
                let patch_stream = crate::core::images::gxp::serialize_records(records);
                khv_len = patch_stream.len();
                if patch_stream_start + khv_len > logical_image.len() {
                    return Err(format!("KHV patch stream overflow at 0x{:X}: need 0x{:X} bytes", patch_stream_start, khv_len));
                }
                logical_image[patch_stream_start..patch_stream_start + khv_len].copy_from_slice(&patch_stream);
                info!("[builder] Injected KHV patch stream at 0x{:08X} (Size: 0x{:X})", patch_stream_start, khv_len);

                let logical_block_size = layout.logical_pages_per_block() * 0x200;
                let start_block = patch_stream_start / logical_block_size;
                let end_block = (patch_stream_start + khv_len + logical_block_size - 1) / logical_block_size;
                for b in start_block..end_block {
                    if b < self.flashfs.root.block_map.len() {
                        self.flashfs.root.block_map[b] = 0x1FFB;
                    }
                }
            }
        }

        let mut final_payloads = self.payloads.clone();
        let mut current_payload_offset = (patch_stream_start + khv_len + 0x1F) & !0x1F;
        let mut payload_list = PayloadList::new();

        for payload in &mut final_payloads {
            let addr = if let Some(fixed) = payload.fixed_address {
                fixed as usize
            } else {
                current_payload_offset
            };

            payload.address = addr as u32;
            payload_list.entries.push(payload.clone());

            // Reserve blocks in FlashFS to prevent overwriting
            let logical_block_size = layout.logical_pages_per_block() * 0x200;
            let start_block = addr / logical_block_size;
            let end_block = (addr + payload.data.len() + logical_block_size - 1) / logical_block_size;

            for b in start_block..end_block {
                if b < self.flashfs.root.block_map.len() {
                    self.flashfs.root.block_map[b] = 0x1FFB;
                }
            }

            if payload.fixed_address.is_none() {
                current_payload_offset = (current_payload_offset + payload.data.len() + 0x1F) & !0x1F;
            }
        }

        if !payload_list.entries.is_empty() {
            header.payload_indicator.set(0x1337);

            let table_data = payload_list.serialize();
            if table_data.len() > 0x100 {
                warn!("[builder] Payload Table at 0x100 exceeds 256 bytes! This may overwrite other header data.");
            }
            let table_len = table_data.len().min(0x100);
            logical_image[0x100..0x100 + table_len].copy_from_slice(&table_data[..table_len]);

            for payload in &payload_list.entries {
                let addr = payload.address as usize;
                if addr + payload.data.len() > logical_image.len() {
                    logical_image.resize(addr + payload.data.len(), 0xFF);
                }
                logical_image[addr..addr + payload.data.len()].copy_from_slice(&payload.data);
                info!("[builder] Injected payload '{}' at 0x{:08X} (Size: 0x{:X})", payload.description, addr, payload.data.len());
            }
        }

        header.prefix.entrypoint.set(bootchain_start as u32);
        header.apply_xebuild_header_flags(&self.options, &self.extra);
        let header_bytes = zerocopy::IntoBytes::as_bytes(&header);
        logical_image[..header_bytes.len()].copy_from_slice(header_bytes);

        let mut partitions_to_write = std::collections::HashMap::new();
        if !self.flashfs.root.entries.is_empty() && target_fs_block >= 0 {
            partitions_to_write.insert(self.flashfs.root.partition_type, self.flashfs.root.clone());
        }

        for (btype, mut root) in partitions_to_write {
            if root.entries.is_empty() {
                continue;
            }

            if btype == 0x30 || btype == 0x2C {
                if target_fs_block >= 0 {
                    root.block_number = target_fs_block;
                }
            }

            if root.block_number < 0 {
                warn!("[builder] FlashFS partition 0x{:02X} has no block number assigned, skipping", btype);
                continue;
            }

            root.create_defaults(logical_image.len(), layout, root.block_number as u16);
            for e in root.entries.iter_mut() {
                if !e.deleted {
                    e.block_number = 0;
                    e.page_number = 0;
                }
            }
            let logical_block_size = layout.logical_pages_per_block() * 0x200;
            let protect_range = |start: usize, len: usize, root: &mut crate::builder::filesystem::flashfs::FileSystemRoot| {
                if len == 0 {
                    return;
                }
                let start_block = start / logical_block_size;
                let end_block = (start + len + logical_block_size - 1) / logical_block_size;
                for b in start_block..end_block {
                    if b < root.block_map.len() {
                        root.block_map[b] = 0x1FFB;
                    }
                }
            };
            protect_range(target_smc_offset, smc_len, &mut root);
            protect_range(kv_offset, self.extra.keyvault.len(), &mut root);
            protect_range(bootchain_start, curr_bl.saturating_sub(bootchain_start), &mut root);
            protect_range(target_cf_offset, header.patch_slots.get().max(1) as usize * 0x10000, &mut root);
            if khv_len > 0 {
                protect_range(patch_stream_start, khv_len, &mut root);
            }
            for payload in &payload_list.entries {
                let addr = payload.address as usize;
                let start_block = addr / logical_block_size;
                let end_block = (addr + payload.data.len() + logical_block_size - 1) / logical_block_size;
                for b in start_block..end_block {
                    if b < root.block_map.len() {
                        root.block_map[b] = 0x1FFB;
                    }
                }
            }

            let fs_block = root.block_number as usize;
            let fs_offset = fs_block * layout.logical_pages_per_block() * 0x200;

            info!("[builder] Writing FlashFS partition 0x{:02X} at block {} (offset 0x{:08X})", btype, fs_block, fs_offset);

            root.write_logical(&mut logical_image, layout)?;

            let fs_root_block = root.serialize_logical(*layout);

            if fs_offset + fs_root_block.len() <= logical_image.len() {
                logical_image[fs_offset..fs_offset + fs_root_block.len()].copy_from_slice(&fs_root_block);
            } else {
                error!("[builder] FlashFS partition 0x{:02X} root block exceeds image bounds at block {}", btype, fs_block);
            }

            if btype == self.flashfs.root.partition_type {
                self.flashfs.root = root;
            }
        }

        if !self.options.nomobile && self.mobile.latest.iter().any(|s| s.is_some()) {
            let fs_start: u16 = match layout {
                NandLayout::Bb => std::cmp::max(4u16, self.flashfs.root.block_number.max(0) as u16),
                _ => 0x4E,
            };
            if self.flashfs.root.block_map.is_empty() {
                self.flashfs.root.create_defaults(logical_image.len(), layout, fs_start);
            }
            self.mobile.write_logical(&mut logical_image, layout, &mut self.flashfs.root);
        }

        if *layout == NandLayout::Emmc {
            corona::write_back(&mut logical_image, &mut self.corona_fs, &self.flashfs.root, &self.mobile)?;
        }

        Ok(logical_image)
    }

    pub fn assemble_xell_image(&self) -> Result<Vec<u8>, String> {
        let layout = &self.options.layout;
        let image_size = 0x140000;
        let mut logical_image = vec![0xFFu8; image_size];

        let mut header = self.header.clone();

        let smc_len = self.extra.smc.len();
        let target_smc_offset = match layout {
            NandLayout::Emmc => 0x800,
            _ => 0x1000,
        };
        if smc_len > 0 {
            if target_smc_offset + smc_len > logical_image.len() {
                return Err(format!("SMC write out of bounds: offset 0x{:X} + size 0x{:X} > image 0x{:X}", target_smc_offset, smc_len, logical_image.len()));
            }
            logical_image[target_smc_offset..target_smc_offset + smc_len].copy_from_slice(&self.extra.smc);
        }

        let kv_offset = 0x4000usize;
        if !self.extra.keyvault.is_empty() {
            if kv_offset + self.extra.keyvault.len() > logical_image.len() {
                return Err(format!(
                    "Keyvault write out of bounds: offset 0x{:X} + size 0x{:X} > image 0x{:X}",
                    kv_offset,
                    self.extra.keyvault.len(),
                    logical_image.len()
                ));
            }
            logical_image[kv_offset..kv_offset + self.extra.keyvault.len()].copy_from_slice(&self.extra.keyvault);
        }

        let bootchain_start = 0x8000;
        let mut curr_bl = bootchain_start;
        let mut bl_stages = Vec::new();
        if let Some(cb) = &self.bootloaders.cb {
            bl_stages.push(("CB", cb.serialize()));
        }
        if let Some(cba) = &self.bootloaders.cb_a {
            bl_stages.push(("CB_A", cba.serialize()));
        }
        if let Some(cbx) = &self.bootloaders.cb_x {
            bl_stages.push(("CB_X", cbx.serialize()));
        }
        if let Some(cbb) = &self.bootloaders.cb_b {
            bl_stages.push(("CB_B", cbb.serialize()));
        }
        if let Some(sc) = &self.bootloaders.sc {
            bl_stages.push(("SC", sc.serialize()));
        }
        if let Some(cd) = &self.bootloaders.cd {
            bl_stages.push(("CD", cd.serialize()));
        }

        for (name, mut data) in bl_stages {
            let declared_size = if data.len() >= 16 {
                let h = BootloaderHeader::read_from_prefix(&data).map(|(h, _)| h.size.get()).unwrap_or(0);
                h as usize
            } else {
                0
            };

            let aligned_declared = (declared_size + 0xF) & !0xF;
            if aligned_declared > 0 && data.len() != aligned_declared {
                if data.len() < aligned_declared {
                    data.resize(aligned_declared, 0);
                } else if data.len() >= 0x10 {
                    let new_len = data.len() as u32;
                    data[0x0C..0x10].copy_from_slice(&new_len.to_be_bytes());
                }
            }

            if curr_bl + data.len() > logical_image.len() {
                return Err(format!("Bootchain stage {} overflow at 0x{:X}", name, curr_bl));
            }
            logical_image[curr_bl..curr_bl + data.len()].copy_from_slice(&data);
            curr_bl += data.len();
        }

        if let Some(xell) = &self.bootloaders.xell {
            let xell_backup_offset = 0xC0000;
            let xell_main_offset = 0x100000;

            // Backup
            if xell_backup_offset + xell.data.len() <= logical_image.len() {
                info!("[builder] Injecting XeLL backup at 0x{:08X}", xell_backup_offset);
                logical_image[xell_backup_offset..xell_backup_offset + xell.data.len()].copy_from_slice(&xell.data);
            }

            // Main
            if xell_main_offset + xell.data.len() <= logical_image.len() {
                info!("[builder] Injecting XeLL main at 0x{:08X}", xell_main_offset);
                logical_image[xell_main_offset..xell_main_offset + xell.data.len()].copy_from_slice(&xell.data);
            }
        } else {
            warn!("[builder] Assembling XeLL image WITHOUT a XeLL payload!");
        }

        header.smc_boot_offset.set(target_smc_offset as u32);
        header.smc_boot_size.set(smc_len as u32);
        header.kv_addr.set(kv_offset as u32);
        header.cf_offset.set(((curr_bl + 0x3FFF) & !0x3FFF) as u32); // Point CF pointer to aligned gap after CD
        header.prefix.size.set(header.cf_offset.get());
        header.prefix.entrypoint.set(bootchain_start as u32);
        header.fs_addr.set(0); // No filesystem

        header.apply_xebuild_header_flags(&self.options, &self.extra);

        let header_bytes = zerocopy::IntoBytes::as_bytes(&header);
        logical_image[..header_bytes.len()].copy_from_slice(header_bytes);

        Ok(logical_image)
    }

    pub fn build(&self, cpukey: [u8; 16]) -> Result<Vec<u8>, String> {
        let mut skel = self.clone();
        skel.build_in_place(cpukey)
    }

    pub fn build_in_place(&mut self, cpukey: [u8; 16]) -> Result<Vec<u8>, String> {
        let skel = self;
        skel.cpukey = Some(cpukey);
        info!("[builder] Starting final image build (Profile: {}, Mode: {:?})...", skel.options.image_profile, skel.options.build_mode);

        let target_pd = if let Some(pairing) = skel.options.jtag_pairing_2bl {
            info!("[builder] Using JTAG 2BL pairing override: {:02x?}", pairing);
            Some(pairing)
        } else {
            skel.input_pd
        };

        if let Some(pd) = target_pd {
            info!("[builder] Synchronizing Pairing Data");
            if skel.options.verbose {
                debug!("[builder] Pairing Data: {:02x?}", pd);
            }

            if let Some(cb) = skel.bootloaders.cb_a.as_mut().or(skel.bootloaders.cb.as_mut()) {
                if let Some(meta) = cb.metadata.as_mut() {
                    meta.pairing_data = pd;
                    if let Some(ldv) = skel.input_ldv_cb {
                        meta.lockdown_value = ldv;
                    }
                    cb.recalculate_per_box_digest(&cpukey);
                }
            }

            if let Some(rebooter) = skel.rebooter.as_mut() {
                if let Some(cb) = rebooter.cb.as_mut() {
                    if let Some(meta) = cb.metadata.as_mut() {
                        meta.pairing_data = pd;
                        if let Some(ldv) = skel.input_ldv_cb {
                            meta.lockdown_value = ldv;
                        }
                        cb.recalculate_per_box_digest(&cpukey);
                    }
                }
            }

            if let Some(meta) = skel.update.cf_0.as_mut().and_then(|cf| cf.metadata.as_mut()) {
                meta.pairing_data = pd;
            }
            if let Some(meta) = skel.update.cf_1.as_mut().and_then(|cf| cf.metadata.as_mut()) {
                meta.pairing_data = pd;
            }
        }

        let ldv0 = skel.update.cf_0.as_ref().and_then(|cf| cf.metadata.as_ref().map(|m| m.lockdown_value));
        let ldv1 = skel.update.cf_1.as_ref().and_then(|cf| cf.metadata.as_ref().map(|m| m.lockdown_value));
        let current_max = match (ldv0, ldv1) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            _ => None,
        };

        let target_cf_ldv = skel.input_ldv_cf.or(current_max);

        if let Some(h) = target_cf_ldv {
            if let Some(meta) = skel.update.cf_0.as_mut().and_then(|cf| cf.metadata.as_mut()) {
                if meta.lockdown_value != h {
                    info!("[builder] Syncing CF_0 LDV to target: {}", h);
                    meta.lockdown_value = h;
                }
            }
            if let Some(meta) = skel.update.cf_1.as_mut().and_then(|cf| cf.metadata.as_mut()) {
                if meta.lockdown_value != h {
                    info!("[builder] Syncing CF_1 LDV to target: {}", h);
                    meta.lockdown_value = h;
                }
            }
        }

        if let Some(ref mut kv) = skel.kv {
            info!("[builder] Encrypting Keyvault...");
            kv.encrypt(&cpukey)?;
            skel.extra.keyvault = kv.data.clone();
        } else {
            warn!("[builder] No internal Keyvault object found, using raw bytes from extra.keyvault");
        }

        let mut smc = crate::builder::chain::smc::RawSmc::new(skel.extra.smc.clone());
        smc.ensure_decrypted();

        if let Some(rebooter) = skel.rebooter.as_mut() {
            encrypt_rebooter_chain(
                skel.bootloaders.cb_a.as_mut().or(skel.bootloaders.cb.as_mut()).ok_or("Missing Chain 0 CB")?,
                skel.bootloaders.cd.as_mut().ok_or("Missing Chain 0 CD")?,
                rebooter.cb.as_mut().ok_or("Missing Chain 1 CB")?,
                rebooter.cd.as_mut().ok_or("Missing Chain 1 CD")?,
                rebooter.ce.as_mut().ok_or("Missing Chain 1 CE")?,
                &mut (skel.update.cf_0.as_mut(), skel.update.cg_0.as_mut(), skel.update.cf_1.as_mut(), skel.update.cg_1.as_mut()),
                &mut smc,
                &cpukey,
            )?;
        } else {
            skel.prepare_for_assembly()?;

            info!("[builder] Re-encrypting bootloader chain...");
            let profile_l = skel.options.image_profile.to_ascii_lowercase();
            let profile_base = profile_l.split('_').next().unwrap_or("");
            let keep_cd_plaintext = matches!(profile_base, "glitch" | "glitch1" | "glitch2" | "glitch3");
            encrypt_chain(
                skel.bootloaders
                    .cb_a
                    .as_mut()
                    .or(skel.bootloaders.cb.as_mut())
                    .ok_or("Missing primary CB (CB or CB_A) for encryption")?,
                skel.bootloaders.cb_x.as_mut(),
                skel.bootloaders.cb_b.as_mut(),
                skel.bootloaders.sc.as_mut(),
                skel.bootloaders.cd.as_mut().ok_or("Missing CD for encryption")?,
                skel.bootloaders.ce.as_mut().ok_or("Missing CE for encryption")?,
                skel.update.cf_0.as_mut(),
                skel.update.cg_0.as_mut(),
                skel.update.cf_1.as_mut(),
                skel.update.cg_1.as_mut(),
                &mut smc,
                &cpukey,
                keep_cd_plaintext,
            )?;
        }

        info!("[builder] Re-encrypting SMC...");
        let scramble_smc = skel.options.image_profile.contains("glitch3");
        smc.encrypt_with_scramble(scramble_smc);
        skel.extra.smc = smc.data;

        if skel.rebooter.is_some() {
            skel.assemble_rebooter()
        } else {
            skel.assemble_logical()
        }
    }

    pub fn apply_patch(&mut self, patch: GxpBinary) -> Result<(), String> {
        if let Some(khv) = patch.khv {
            info!("[builder] Routing {} KHV patch records to options slot...", khv.records.len());
            self.bootloaders.khvpatch = Some(
                khv.records
                    .iter()
                    .map(|r| PatchRecord { address: r.address, amount: r.amount, data: r.data.clone() })
                    .collect(),
            );
        }

        if let Some(cb_b) = patch.cb_b {
            if patch.header.patch_type == GxpPatchType::Rgh4Section {
                if let Some(cbb_bl) = &mut self.bootloaders.cb_b {
                    info!("[builder] Applying RGH Section 0 patches to CB_B");
                    apply_records(&cb_b.records, &mut cbb_bl.data).map_err(|e| e.to_string())?;
                }
            }
        }

        if let Some(cb) = patch.cb {
            if self.rebooter.is_some() {
                if let Some(rebooter) = &mut self.rebooter {
                    if let Some(cb_bl) = &mut rebooter.cb {
                        info!("[builder] JTAG: Applying primary patches to Chain 1 CB");
                        apply_records(&cb.records, &mut cb_bl.data).map_err(|e| e.to_string())?;
                    }
                }
            } else {
                if let Some(cbb_bl) = &mut self.bootloaders.cb_b {
                    info!("[builder] Split/Glitch3 CB: Applying primary patch section to CB_B");
                    apply_records(&cb.records, &mut cbb_bl.data).map_err(|e| e.to_string())?;
                } else if let Some(cb_bl) = &mut self.bootloaders.cb {
                    info!("[builder] Single CB: Applying patches to CB");
                    apply_records(&cb.records, &mut cb_bl.data).map_err(|e| e.to_string())?;
                }
            }
        }

        if let Some(cd) = patch.cd {
            if self.rebooter.is_some() {
                if let Some(rebooter) = &mut self.rebooter {
                    if let Some(cd_bl) = &mut rebooter.cd {
                        info!("[builder] JTAG: Applying patches to Chain 1 CD");
                        apply_records(&cd.records, &mut cd_bl.data).map_err(|e| e.to_string())?;
                    }
                }
            } else if let Some(cd_bl) = &mut self.bootloaders.cd {
                info!("[builder] Applying patches to CD (Filesystem Driver)");
                apply_records(&cd.records, &mut cd_bl.data).map_err(|e| e.to_string())?;
            }
        }

        if let Some(smc) = patch.smc {
            info!("[builder] Applying {} records to decrypted SMC buffer", smc.records.len());
            apply_records(&smc.records, &mut self.extra.smc).map_err(|e| e.to_string())?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::chain::BootloaderHeader;

    #[test]
    fn test_nand_layout_defaults_sb() {
        let skeleton = NandSkeleton::new_blank(NandLayout::Sb);
        assert_eq!(skeleton.image.len(), 0x1000000);
        assert_eq!(skeleton.header.kv_addr.get(), 0x4000);
        assert_eq!(skeleton.header.smc_boot_offset.get(), 0x1000); // SB: 0x4000 - 0x3000
        assert_eq!(skeleton.header.smc_boot_size.get(), 0x3000);
        assert_eq!(skeleton.header.fs_addr.get(), 0x10000);
        assert_eq!(skeleton.header.cf_offset.get(), 0x70000);
    }

    #[test]
    fn test_nand_layout_defaults_bb() {
        let skeleton = NandSkeleton::new_blank(NandLayout::Bb);
        assert_eq!(skeleton.image.len(), 0x4000000);
        assert_eq!(skeleton.header.kv_addr.get(), 0x4000);
        assert_eq!(skeleton.header.smc_boot_offset.get(), 0x1000); // BB: 0x4000 - 0x3000
        assert_eq!(skeleton.header.smc_boot_size.get(), 0x3000);
        assert_eq!(skeleton.header.fs_addr.get(), 0x10000);
        assert_eq!(skeleton.header.cf_offset.get(), 0x80000);
    }

    #[test]
    fn test_nand_layout_defaults_emmc() {
        let skeleton = NandSkeleton::new_blank(NandLayout::Emmc);
        assert_eq!(skeleton.image.len(), 0x3000000);
        assert_eq!(skeleton.header.kv_addr.get(), 0x4000);
        assert_eq!(skeleton.header.smc_boot_offset.get(), 0x800); // eMMC: 0x4000 - 0x3800
        assert_eq!(skeleton.header.smc_boot_size.get(), 0x3800); // eMMC SMC is 0x3800 bytes
        assert_eq!(skeleton.header.smc_config_offset.get(), 0x0); // eMMC header field is 0x0
        assert_eq!(skeleton.header.fs_addr.get(), 0x10000); // FileSystemAddress
        assert_eq!(skeleton.header.cf_offset.get(), 0xB0000);
    }

    #[test]
    fn test_dynamic_smc_placement() {
        let mut skeleton = NandSkeleton::new_blank(NandLayout::Sb);
        skeleton.extra.smc = vec![0; 0x3200]; // custom larger SMC

        let logical = skeleton.assemble_logical().unwrap();
        // 0x4000 - 0x3200 = 0x0E00
        let target_offset = 0x0E00;

        // Check header reflects new offset
        let header = NandHeader::read_from_prefix(&logical).unwrap().0;
        assert_eq!(header.smc_boot_offset.get(), target_offset as u32);
        assert_eq!(header.smc_boot_size.get(), 0x3200);
    }

    #[test]
    fn test_xebuild_header_flags() {
        let skeleton = NandSkeleton::new_blank(NandLayout::Sb);

        let mut retail_header = skeleton.header.clone();
        retail_header.copyright[0x3E] = 0xAA;
        retail_header.copyright[0x3F] = 0xBB;
        let mut retail_opts = skeleton.options.clone();
        retail_opts.image_profile = "retail".to_string();
        retail_header.apply_xebuild_header_flags(&retail_opts, &skeleton.extra);
        assert_eq!(retail_header.copyright[0x3B], 0);
        assert_eq!(retail_header.copyright[0x3E], 0xAA);
        assert_eq!(retail_header.copyright[0x3F], 0xBB);

        let mut devkit_header = skeleton.header.clone();
        devkit_header.copyright[0x3E] = 0xAA;
        devkit_header.copyright[0x3F] = 0xBB;
        let mut devkit_opts = skeleton.options.clone();
        devkit_opts.image_profile = "devkit".to_string();
        devkit_header.apply_xebuild_header_flags(&devkit_opts, &skeleton.extra);
        assert_eq!(devkit_header.copyright[0x3B], 0);
        assert_eq!(devkit_header.copyright[0x3E], 0xAA);
        assert_eq!(devkit_header.copyright[0x3F], 0xBB);

        let mut hacked_header = skeleton.header.clone();
        let mut hacked_opts = skeleton.options.clone();
        hacked_opts.image_profile = "glitch2".to_string();
        hacked_header.apply_xebuild_header_flags(&hacked_opts, &skeleton.extra);
        assert_eq!(hacked_header.copyright[0x3B], 1);
        assert_eq!(hacked_header.copyright[0x3E], 0x00);
        assert_eq!(hacked_header.copyright[0x3F], 0x12);

        let mut xdk_header = skeleton.header.clone();
        let mut xdk_opts = skeleton.options.clone();
        xdk_opts.image_profile = "xdkbuild".to_string();
        xdk_header.apply_xebuild_header_flags(&xdk_opts, &skeleton.extra);
        assert_eq!(xdk_header.copyright[0x3B], 1);
        assert_eq!(xdk_header.copyright[0x3E], 0x00);
        assert_eq!(xdk_header.copyright[0x3F], 0x12);
    }

    #[test]
    fn test_bootchain_overflow_realignment() {
        let mut skeleton = NandSkeleton::new_blank(NandLayout::Sb);
        // Create a fake massive CD bootloader to force realignment
        // SB CF 0x70000. 2BL base 0x8000.
        // We need CD to extend past 0x70000.
        let large_cd = vec![0u8; 0x69000]; // 0x8000 + 0x69000 = 0x71000 (overflows standard 0x70000)

        let bl_header = BootloaderHeader {
            magic: U16::new(0x4344), // 'CD'
            version: U16::new(1888),
            pairing: U16::new(0),
            flags: U16::new(0),
            entrypoint: U32::new(0),
            size: U32::new(0x69000),
        };

        skeleton.bootloaders.cd = Some(crate::builder::chain::cd::BootloaderCd { header: bl_header, data: large_cd, derived_key: None, metadata: None });

        let logical = skeleton.assemble_logical().unwrap();
        let header = NandHeader::read_from_prefix(&logical).unwrap().0;

        // Expected realignment to next 64KB block: (0x71000 + 0xFFFF) & 0xFFFF0000 = 0x80000
        assert_eq!(header.cf_offset.get(), 0x80000);
    }
}
