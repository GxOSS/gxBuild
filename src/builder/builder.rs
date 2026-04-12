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


use std::collections::HashMap;
use zerocopy::{FromBytes, IntoBytes, KnownLayout, Immutable};
use zerocopy::byteorder::{U16, U32, I16, BigEndian};

use crate::builder::tools::blocks::*;
use crate::builder::chain::*;
use crate::builder::chain::flashfs::FlashFS;

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex byte: {}", e))
        })
        .collect()
}

/// Xbox 360 NAND header — matches xenon-bltool's `xenon_nand_header` layout.
/// The first field is a `BootloaderHeader` whose `entrypoint` points to CB.
/// Xbox 360 NAND header prefix — the first 16 bytes of the NAND header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub struct NandHeaderPrefix {
    pub magic: U16<BigEndian>,
    pub version: U16<BigEndian>,
    pub pairing: U16<BigEndian>,
    pub flags: U16<BigEndian>,
    pub entrypoint: U32<BigEndian>, // points to CB offset
    pub size: U32<BigEndian>,
}

/// Xbox 360 NAND header — matches xenon-bltool's `xenon_nand_header` layout.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub struct NandHeader {
    pub prefix: NandHeaderPrefix,       // 16 bytes (instead of 32-byte BootloaderHeader)
    pub copyright: [u8; 0x40],         // 64 bytes
    pub unused: [u8; 0x10],            // 16 bytes
    pub kv_size: U32<BigEndian>,       // 4 bytes (offset 16+64+16 = 96 = 0x60)
    pub cf_offset: U32<BigEndian>,     // 4 bytes (offset 0x64)
    pub patch_slots: I16<BigEndian>,    // 0x68
    pub kv_version: U16<BigEndian>,     // 0x6A
    pub kv_addr: U32<BigEndian>,        // 0x6C
    pub patch_size: U32<BigEndian>,     // 0x70
    pub smc_config_offset: U32<BigEndian>, // 0x74
    pub smc_boot_size: U32<BigEndian>,   // 0x78
    pub smc_boot_offset: U32<BigEndian>, // 0x7C
    pub sys_update_addr: U32<BigEndian>, // 0x80
    pub sys_update_count: U16<BigEndian>,
    pub sys_update_version: U16<BigEndian>,
    pub sys_update_size: U32<BigEndian>,
    // Fields used by assemble_logical for in-memory header patching
    pub block_offset: U32<BigEndian>,
    pub smc_start: U32<BigEndian>,
    pub smc_size: U32<BigEndian>,
}

impl NandHeader {
    pub const MAGIC: u16 = 0xFF4F;

    /// Validate the NAND header magic.
    pub fn validate(&self) -> Result<(), String> {
        if self.prefix.magic.get() != Self::MAGIC {
            return Err(format!(
                "Invalid NAND magic: 0x{:04X} (expected 0xFF4F)",
                self.prefix.magic.get()
            ));
        }
        Ok(())
    }

    /// CB offset — the entrypoint field in the embedded bootloader header.
    pub fn cb_offset(&self) -> u32 {
        self.prefix.entrypoint.get()
    }

    pub fn is_modified_copyright(&self) -> bool {
        let ms_copyright = b"\xa9 2004-2011 Microsoft Corporation. All rights reserved.\0";
        // Compare everything EXCEPT the year range (bytes 2..11)
        self.copyright[0] != ms_copyright[0] || self.copyright[11..] != ms_copyright[11..]
    }

    pub fn print_info(&self) {
        println!("NAND magic:       0x{:04X}", self.prefix.magic.get());
        println!("NAND build:       {}", self.prefix.version.get());
        println!("CB offset:        0x{:X}", self.cb_offset());
        println!("CF offset:        0x{:X}", self.cf_offset.get());
        let copyright = String::from_utf8_lossy(&self.copyright);
        println!("Copyright:        {}", copyright.trim_matches(char::from(0)));
        println!("KV offset:        0x{:X}", self.kv_addr.get());
        println!("KV size:          0x{:X}", self.kv_size.get());
        println!("Patch slots:      {}", self.patch_slots.get());
        println!("Patch size:       0x{:X}", self.patch_size.get());
        println!("SMC config:       0x{:X}", self.smc_config_offset.get());
        println!("SMC boot size:    0x{:X}", self.smc_boot_size.get());
        println!("SMC boot offset:  0x{:X}", self.smc_boot_offset.get());
    }
}

use crate::builder::chain::cb::BootloaderCb;
use crate::builder::chain::sc::BootloaderSc;
use crate::builder::chain::cd::BootloaderCd;
use crate::builder::chain::ce::BootloaderCe;
use crate::builder::chain::cf::BootloaderCf;
use crate::builder::chain::cg::BootloaderCg;


// Bootchain will be interpreted from provided bootloaders
#[derive(Clone)]
pub struct NandBootloaders {
    pub cb: Option<BootloaderCb>,
    pub cb_a: Option<BootloaderCb>,
    pub cb_x: Option<BootloaderCb>, // RGH3 Intermediate stage
    pub cb_b: Option<BootloaderCb>,
    pub sc: Option<BootloaderSc>,
    pub cd: Option<BootloaderCd>,
    pub ce: Option<BootloaderCe>,
}

// If only 0, will be treated as full images. If 0 and 1, will be treated as patchslots
#[derive(Clone)]
pub struct NandUpdate {
    pub cf_0: Option<BootloaderCf>,
    pub cg_0: Option<BootloaderCg>,
    pub cf_1: Option<BootloaderCf>,
    pub cg_1: Option<BootloaderCg>,
}

// SMC, Keyvault and Security
#[derive(Clone)]
pub struct NandExtra {
    pub smc: Vec<u8>,
    pub smc_config: Vec<u8>,
    pub keyvault: Vec<u8>,
    pub fcrt: Option<Vec<u8>>,
    // Power-up cause / boot trigger stubs
    pub power_on_cause_a: u8,
    pub power_on_cause_b: u8,
}

// KeyvaultRecord moved to src/builder/chain/kv.rs

/// One patch entry – copy `data` to `address`.
#[derive(Debug, Clone)]
pub struct PatchRecord {
    pub address: u32,
    pub amount: u32,
    pub data: Vec<u32>,
}

#[derive(Clone)]
pub struct NandPatches {
    pub rglp: Option<Vec<u8>>,
    pub xebuild: Option<Vec<u8>>,
    pub khv: Vec<PatchRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum MotherboardType {
    Xenon = 0,
    Zephyr = 1,
    Falcon = 2,
    Jasper = 3,
    Trinity = 4,
    Corona = 5,
    Winchester = 6,
    Unknown = 0xF,
}

impl MotherboardType {
    pub fn from_smc(smc_byte: u8) -> Self {
        match (smc_byte >> 4) & 0xF {
            0 => MotherboardType::Xenon,
            1 => MotherboardType::Zephyr,
            2 => MotherboardType::Falcon,
            3 => MotherboardType::Jasper,
            4 => MotherboardType::Trinity,
            5 => MotherboardType::Corona,
            6 => MotherboardType::Winchester,
            _ => MotherboardType::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ImageType {
    Single,
    Split,
    Devkit,
    Devgl,
    Rgbuild,
    Xdkbuild,
    Onef,
    Twof,
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BuildType { // Custom images
    Retail,     // Regular secure image
    Jtag,       // Dual-boot with reboot chain
    Glitch,     // Patches somewhere after CE
    Conversion, // Load dev kernel on glitch or glitch kernel on dev
}

#[derive(Clone)]
pub struct BuildOptions {
    pub layout: NandLayout,
    pub block_map: BlockMap,
    pub image_type: ImageType,
    pub build_type: BuildType,
    pub motherboard: MotherboardType,
    pub bigonsmall: bool, // Usually false, For RGL/ XDKB systems with nandfs on hdd
    pub shadowboot: bool, // Toggle shadowboot image creation
    pub mfg: bool,
    pub patches: Option<NandPatches>,
}

// RawImage and its implementation moved to blocks.rs

#[derive(Clone)]
pub struct NandSkeleton {
    pub cpukey: Option<[u8; 16]>,
    pub image: Vec<u8>,
    pub block_map: Option<BlockMap>, // Need to retarget
    pub options: BuildOptions,
    pub header: NandHeader,
    pub extra: NandExtra,
    pub bootloaders: NandBootloaders,
    pub update: NandUpdate,
    pub flashfs: FlashFS,
    pub layout: NandLayout,
    pub total_blocks: usize,
}

impl NandSkeleton {
    pub fn new_blank(layout: NandLayout) -> Self {
        let size = match layout {
            NandLayout::Xsb => 0x1080000, // 16MB
            NandLayout::Sb => 0x4200000,  // 64MB
            NandLayout::Bb => 0x4200000,  // Default to 64MB for blank BB
            NandLayout::Emmc => 0x3000000, // 48MB as requested
        };

        let mut image = vec![0u8; size];
        
        // Initialize basic header magic so it's technically valid
        image[0] = 0xFF;
        image[1] = 0x4F;

        Self {
            cpukey: None,
            image,
            block_map: Some(BlockMap { blocks: Vec::new(), layout }),
            options: BuildOptions {
                layout,
                block_map: BlockMap { blocks: Vec::new(), layout },
                image_type: ImageType::Single,
                build_type: BuildType::Retail,
                motherboard: MotherboardType::Unknown,
                bigonsmall: false,
                shadowboot: false,
                mfg: false,
                patches: None,
            },
            header: unsafe { std::mem::zeroed() }, // Will be patched during build
            extra: NandExtra {
                smc: Vec::new(),
                smc_config: Vec::new(),
                keyvault: Vec::new(),
                fcrt: None,
                power_on_cause_a: 0,
                power_on_cause_b: 0,
            },
            bootloaders: NandBootloaders {
                cb: None,
                cb_a: None,
                cb_x: None,
                cb_b: None,
                sc: None,
                cd: None,
                ce: None,
            },
            update: NandUpdate {
                cf_0: None,
                cg_0: None,
                cf_1: None,
                cg_1: None,
            },
            flashfs: FlashFS {
                root: crate::builder::chain::flashfs::FileSystemRoot::new(0, 0),
                partitions: HashMap::new(),
            },
            layout,
            total_blocks: layout.total_blocks(size),
        }
    }
}

impl NandSkeleton {
    // From J-Runner-with-Extras>J-Runner>Nand>PatchParser.cs
    // Thanks Mena
    // TODO: Add crc32 hashing (?)
    /// Parse patches applied to a NandSkeleton
    pub fn get_patches(&self) -> Option<NandPatches> {
        self.options.patches.clone()
    }

    /// Parse nand image into populated NandSkeleton
    pub fn parse_nand(nandimg: &std::path::Path, cpukey: [u8; 16]) -> Result<Self, String> {
        let raw_image = std::fs::read(nandimg)
            .map_err(|e| format!("Failed to read NAND image: {}", e))?;

        // 1. Detect Layout e.g. 16MB vs 64MB+ vs eMMC
        let layout = NandLayout::detect(&raw_image)?;
        let cpukey_bytes = cpukey;

        // 2. Extract and Parse NandHeader (always at 0x0)
        // For physical NANDs, we grab the first 0x4200 (block) and unecc it.
        // For eMMC, we just take the first 0x4000 (standard block size equivalent or just enough).
        let raw_header = if matches!(layout, NandLayout::Emmc) {
            raw_image[..0x200].to_vec()
        } else {
            unecc(&raw_image[..0x4200])
        };
        let header = NandHeader::read_from_prefix(&raw_header[..0x100])
            .map(|(h, _)| h.clone())
            .map_err(|_| "Failed to parse primary NAND header")?;

        // Capture Power-on cause / boot triggers from the hacked header area (0x4E/0x4F)
        let _power_on_cause_a = raw_header[0x4E];
        let _power_on_cause_b = raw_header[0x4F];

        // 3. Extract Bootchain stages individually with their spare data
        let mut bootloaders = NandBootloaders {
            cb: None,
            cb_a: None,
            cb_x: None,
            cb_b: None,
            sc: None,
            cd: None,
            ce: None,
        };

        let cb_offset = header.cb_offset() as usize;
        let p_cb_offset = if matches!(layout, NandLayout::Emmc) { cb_offset } else { (cb_offset / 0x200) * 0x210 };

        // Read CB_A (The first stage in the chain)
        let raw_cb_hdr = &raw_image[p_cb_offset..p_cb_offset + 0x20];
        let (bl_hdr, _) = BootloaderHeader::read_from_prefix(raw_cb_hdr)
            .map_err(|_| "Failed to read CB_A header")?;
        
        let cb_size = bl_hdr.size.get() as usize;
        let p_cb_size = if matches!(layout, NandLayout::Emmc) { 
            cb_size 
        } else { 
            ((cb_size + 0x1FF) / 0x200) * 0x210 
        };
        let p_cb_aligned = (p_cb_size + 0xF) & 0xFFFFFFF0;

        let cb_raw = &raw_image[p_cb_offset..p_cb_offset + p_cb_aligned];
        let cb_clean = if matches!(layout, NandLayout::Emmc) { cb_raw.to_vec() } else { unecc(cb_raw) };
        let cb_a = BootloaderCb::parse(&cb_clean)?;
        
        // Helper to scan subsequent stages sequentially
        let extract_next = |p_offset: &mut usize| -> Result<Vec<u8>, String> {
            if *p_offset + 0x20 > raw_image.len() { return Err("Offset out of bounds".into()); }
            let (hdr, _) = BootloaderHeader::read_from_prefix(&raw_image[*p_offset..*p_offset+0x20])
                .map_err(|_| "Failed to read stage header")?;
            
            let size = hdr.size.get() as usize;
            let p_size = if matches!(layout, NandLayout::Emmc) { size } else { ((size + 0x1FF) / 0x200) * 0x210 };
            let p_aligned = (p_size + 0xF) & 0xFFFFFFF0;
            
            if *p_offset + p_aligned > raw_image.len() { return Err("Stage exceeds image bounds".into()); }
            let raw = &raw_image[*p_offset..*p_offset + p_aligned];
            let clean = if matches!(layout, NandLayout::Emmc) { raw.to_vec() } else { unecc(raw) };
            *p_offset += p_aligned;
            Ok(clean)
        };

        bootloaders.cb_a = Some(cb_a.clone());

        // --- Sequential Chain Walk ---
        let mut p_cur_offset = p_cb_offset + p_cb_aligned;
        let mut cf_0: Option<BootloaderCf> = None;
        let mut cg_0: Option<BootloaderCg> = None;
        let mut cf_1: Option<BootloaderCf> = None;
        let mut cg_1: Option<BootloaderCg> = None;

        // Stable walk: break on first non-header or end of image
        while p_cur_offset + 0x20 < raw_image.len() {
            let next_hdr: BootloaderHeader = match BootloaderHeader::read_from_prefix(&raw_image[p_cur_offset..p_cur_offset+0x20]) {
                Ok((h, _)) => h,
                Err(_) => break,
            };
            
            match next_hdr.get_type() {
                XenonBlType::CB => {
                    let data = extract_next(&mut p_cur_offset)?;
                    if data.len() == 0x400 {
                         println!("[GGX] Discovery: RGH3 Intermediate (CB_X) detected.");
                         bootloaders.cb_x = Some(BootloaderCb::parse(&data)?);
                    } else if bootloaders.cb_x.is_some() || bootloaders.cb_b.is_none() {
                         bootloaders.cb_b = Some(BootloaderCb::parse(&data)?);
                    }
                },
                XenonBlType::SC => {
                    let data = extract_next(&mut p_cur_offset)?;
                    bootloaders.sc = Some(BootloaderSc::parse(&data)?);
                },
                XenonBlType::CD => {
                    let data = extract_next(&mut p_cur_offset)?;
                    bootloaders.cd = Some(BootloaderCd::parse(&data)?);
                },
                XenonBlType::CE => {
                    let data = extract_next(&mut p_cur_offset)?;
                    bootloaders.ce = Some(BootloaderCe::parse(&data)?);
                },
                XenonBlType::CF => {
                    let data = extract_next(&mut p_cur_offset)?;
                    let cf = BootloaderCf::parse(&data)?;
                    println!("[GGX] Discovery: Found CF_{} at physical 0x{:X}", cf.header.version.get(), p_cur_offset - data.len());
                    if cf_0.is_none() { cf_0 = Some(cf); } else { cf_1 = Some(cf); }
                },
                XenonBlType::CG => {
                    let data = extract_next(&mut p_cur_offset)?;
                    let cg = BootloaderCg::parse(&data)?;
                    println!("[GGX] Discovery: Found CG_{} at physical 0x{:X}", cg.header.version.get(), p_cur_offset - data.len());
                    if cg_0.is_none() { cg_0 = Some(cg); } else { cg_1 = Some(cg); }
                },
                _ => break,
            }
        }
        
        // --- Fallback: Jump to cf_offset OR Heuristic Deep Scan ---
        if cf_0.is_none() {
            let cf_logical = header.cf_offset.get() as usize;
            if cf_logical > 0 && cf_logical < raw_image.len() {
                let mut p_cf_offset = if matches!(layout, NandLayout::Emmc) { cf_logical } else { (cf_logical / 0x200) * 0x210 };
                println!("[GGX] Discovery: Header pointer CF jump to 0x{:X} (Physical: 0x{:X})", cf_logical, p_cf_offset);
                
                if let Ok(clean) = extract_next(&mut p_cf_offset) {
                    if let Ok(cf) = BootloaderCf::parse(&clean) {
                        cf_0 = Some(cf);
                        if let Ok(clean_cg) = extract_next(&mut p_cf_offset) {
                            if let Ok(cg) = BootloaderCg::parse(&clean_cg) { cg_0 = Some(cg); }
                        }
                    }
                }
            }
        }

        // Secondary Heuristic: Brute force page starts for CF magic if still missing
        if cf_0.is_none() {
            println!("[GGX] Discovery: CF still missing, performing heuristic deep scan...");
            let page_size = if matches!(layout, NandLayout::Emmc) { 0x200 } else { 0x210 };
            for p_off in (0x70000..0x140000).step_by(page_size) {
                if p_off + 0x10 > raw_image.len() { break; }
                let magic = u16::from_be_bytes([raw_image[p_off], raw_image[p_off+1]]);
                if (magic & 0xFFF) == 0x346 { // CF Magic
                    let mut p_scan_off = p_off;
                    if let Ok(clean) = extract_next(&mut p_scan_off) {
                        if let Ok(cf) = BootloaderCf::parse(&clean) {
                            println!("[GGX] Discovery: Heuristic FOUND CF_{} at physical 0x{:X}", cf.header.version.get(), p_off);
                            cf_0 = Some(cf);
                            if let Ok(clean_cg) = extract_next(&mut p_scan_off) {
                                if let Ok(cg) = BootloaderCg::parse(&clean_cg) { cg_0 = Some(cg); }
                            }
                            break;
                        }
                    }
                }
            }
        }

        // 4. Decrypt mandatory stages
        // CF and CG are now optional during initial parsing to support images where they are injected later
        let mut cf_0_dec: Option<BootloaderCf> = None;
        let mut cg_0_dec: Option<BootloaderCg> = None;
        let mut cf_1_dec: Option<BootloaderCf> = None;
        let mut cg_1_dec: Option<BootloaderCg> = None;

        if let Some(mut cf) = cf_0 {
            if let Some(mut cg) = cg_0 {
                let mut cf1 = cf_1.unwrap_or_else(|| cf.clone());
                let mut cg1 = cg_1.unwrap_or_else(|| cg.clone());

                decrypt_chain(
                    bootloaders.cb_a.as_mut().unwrap(),
                    bootloaders.cb_x.as_mut(),
                    bootloaders.cb_b.as_mut(),
                    bootloaders.sc.as_mut(),
                    bootloaders.cd.as_mut().ok_or("CD stage missing")?,
                    bootloaders.ce.as_mut().ok_or("CE stage missing")?,
                    Some(&mut cf),
                    Some(&mut cg),
                    Some(&mut cf1),
                    Some(&mut cg1),
                    &cpukey_bytes,
                )?;

                cf.populate_metadata();
                cg.populate_metadata();
                cf1.populate_metadata();
                cg1.populate_metadata();

                cf_0_dec = Some(cf);
                cg_0_dec = Some(cg);
                cf_1_dec = Some(cf1);
                cg_1_dec = Some(cg1);
            }
        }

        if cf_0_dec.is_none() {
            // If they weren't found/decrypted, just ensure basic decryption of mandatory stages
            decrypt_chain(
                bootloaders.cb_a.as_mut().unwrap(),
                bootloaders.cb_x.as_mut(),
                bootloaders.cb_b.as_mut(),
                bootloaders.sc.as_mut(),
                bootloaders.cd.as_mut().ok_or("CD stage missing")?,
                bootloaders.ce.as_mut().ok_or("CE stage missing")?,
                None, None, None, None,
                &cpukey_bytes,
            )?;
        }

        let update = NandUpdate {
            cf_0: cf_0_dec,
            cg_0: cg_0_dec,
            cf_1: cf_1_dec,
            cg_1: cg_1_dec,
        };

        // 5. Extra forensic extraction
        let kv_addr = header.kv_addr.get() as usize;
        let kv_size = header.kv_size.get() as usize;
        let p_kv_offset = if matches!(layout, NandLayout::Emmc) { kv_addr } else { (kv_addr / 0x200) * 0x210 };
        let p_kv_size = if matches!(layout, NandLayout::Emmc) { kv_size } else { ((kv_size + 0x1FF) / 0x200) * 0x210 };
        
        let kv_raw = &raw_image[p_kv_offset..p_kv_offset + p_kv_size];
        let kv_clean = if matches!(layout, NandLayout::Emmc) { kv_raw.to_vec() } else { unecc(kv_raw) };
        let mut kv = crate::builder::chain::kv::Keyvault::parse(&kv_clean)?;
        kv.decrypt(&cpukey_bytes)?;

        let smc_offset = header.smc_boot_offset.get() as usize;
        let smc_size = header.smc_boot_size.get() as usize;
        let p_smc_offset = if matches!(layout, NandLayout::Emmc) { smc_offset } else { (smc_offset / 0x200) * 0x210 };
        let p_smc_size = if matches!(layout, NandLayout::Emmc) { smc_size } else { ((smc_size + 0x1FF) / 0x200) * 0x210 };
        
        let smc_raw = &raw_image[p_smc_offset..p_smc_offset + p_smc_size];
        let smc_clean = if matches!(layout, NandLayout::Emmc) { smc_raw.to_vec() } else { unecc(smc_raw) };
        let mut smc = crate::builder::chain::smc::RawSmc::new(smc_clean);
        smc.decrypt();

        let extra = NandExtra {
            smc: smc.data,
            smc_config: Vec::new(), // Raw for now as per user request
            keyvault: kv.data,
            fcrt: None,
            power_on_cause_a: 0,
            power_on_cause_b: 0,
        };

        let motherboard = MotherboardType::from_smc(extra.smc[0x100]);
        let total_blocks = raw_image.len() / layout.physical_block_size();
        let flashfs = FlashFS::scan(&raw_image, &layout);

        Ok(NandSkeleton {
            cpukey: Some(cpukey_bytes),
            image: raw_image,
            block_map: None,
            layout,
            total_blocks,
            options: BuildOptions {
                layout,
                block_map: BlockMap { blocks: Vec::new(), layout },
                image_type: if bootloaders.cb_b.is_some() { ImageType::Split } else { ImageType::Single },
                build_type: BuildType::Retail,
                motherboard,
                bigonsmall: false,
                shadowboot: false,
                mfg: false,
                patches: None,
            },
            header,
            extra,
            bootloaders,
            update,
            flashfs,
        })
    }

    /// Assembles a 'Flat' logical image (0x200 pages) from the skeleton's components.
    /// This is the precursor to applying physical spare data and ECC.
    pub fn assemble_logical(&self) -> Result<Vec<u8>, String> {
        let layout = &self.options.layout;
        let mut logical_image = vec![0xFFu8; self.total_blocks * layout.logical_pages_per_block() * 0x200];
        
        let header_clone = self.header.clone();
        let mut header = header_clone;

        let bootchain_start = 0x8000;
        let smc_offset = header.smc_boot_offset.get() as usize;
        let kv_offset = header.kv_addr.get() as usize;

        // 2. Inject SMC
        if self.extra.smc.len() > 0 {
            let smc_len = self.extra.smc.len();
            logical_image[smc_offset..smc_offset + smc_len].copy_from_slice(&self.extra.smc);
            header.smc_boot_size.set(smc_len as u32);
        }

        // 3. Inject Keyvault
        if self.extra.keyvault.len() > 0 {
            let kv_len = self.extra.keyvault.len();
            logical_image[kv_offset..kv_offset + kv_len].copy_from_slice(&self.extra.keyvault);
            header.kv_addr.set(kv_offset as u32);
            header.kv_size.set(kv_len as u32);
        }

        // 4. Inject Bootchain (Starting at 0x8000)
        let mut current_offset = bootchain_start;
        let bl = &self.bootloaders;

        let mut stages: Vec<Vec<u8>> = Vec::new();

        // Sequential Stages
        if let Some(cb_bl) = bl.cb.as_ref().or(bl.cb_a.as_ref()) {
            stages.push(cb_bl.serialize());
        }
        if let Some(cb_x) = bl.cb_x.as_ref() {
            stages.push(cb_x.serialize());
        }
        if let Some(cb_b) = bl.cb_b.as_ref() {
            stages.push(cb_b.serialize());
        }
        if let Some(sc) = bl.sc.as_ref() {
            stages.push(sc.serialize());
        }
        if let Some(cd) = bl.cd.as_ref() {
            stages.push(cd.serialize());
        }
        if let Some(ce) = bl.ce.as_ref() {
            stages.push(ce.serialize());
        }

        for data in stages {
            let len = data.len();
            if current_offset + len > logical_image.len() { break; }
            logical_image[current_offset..current_offset + len].copy_from_slice(&data);
            current_offset += (len + 0xF) & 0xFFFFFFF0; // 0x10 Alignment
        }

        // 5. Inject Mandated Dual Patch Slots (CF/CG)
        // Auto-mirror Slot 1 if missing for retail compliance
        let cf_0_data = self.update.cf_0.as_ref().map(|b| b.serialize());
        let cg_0_data = self.update.cg_0.as_ref().map(|b| b.serialize());
        let cf_1_data = self.update.cf_1.as_ref().map(|b| b.serialize()).or_else(|| cf_0_data.clone());
        let cg_1_data = self.update.cg_1.as_ref().map(|b| b.serialize()).or_else(|| cg_0_data.clone());

        if let Some(cf_data) = &cf_0_data {
            current_offset = (current_offset + 0x1FF) & 0xFFFFFE00; // Alignment to page boundary
            header.cf_offset.set(current_offset as u32);
            header.sys_update_addr.set(current_offset as u32);
            header.patch_slots.set(2);
            header.sys_update_count.set(2);
            header.sys_update_version.set(self.update.cf_0.as_ref().unwrap().header.version.get());

            let mut total_update_size = 0u32;

            // Slot 0 Injection
            logical_image[current_offset..current_offset + cf_data.len()].copy_from_slice(cf_data);
            total_update_size += cf_data.len() as u32;
            current_offset += (cf_data.len() + 0xF) & 0xFFFFFFF0;

            if let Some(cg_data) = &cg_0_data {
                logical_image[current_offset..current_offset + cg_data.len()].copy_from_slice(cg_data);
                total_update_size += cg_data.len() as u32;
                current_offset += (cg_data.len() + 0xF) & 0xFFFFFFF0;
            }

            // Slot 1 Injection (Mirrored if necessary)
            if let Some(cf1) = &cf_1_data {
                logical_image[current_offset..current_offset + cf1.len()].copy_from_slice(cf1);
                total_update_size += cf1.len() as u32;
                current_offset += (cf1.len() + 0xF) & 0xFFFFFFF0;

                if let Some(cg1) = &cg_1_data {
                    logical_image[current_offset..current_offset + cg1.len()].copy_from_slice(cg1);
                    total_update_size += cg1.len() as u32;
                    // Final offset increment is not needed here
                }
            }
            
            header.sys_update_size.set(total_update_size);
        }

        // 6. Final Header Sync & Write
        header.prefix.entrypoint.set(bootchain_start as u32);
        let header_bytes = zerocopy::IntoBytes::as_bytes(&header);
        logical_image[..header_bytes.len()].copy_from_slice(header_bytes);

        // 7. FlashFS (Usually at 0x100000)
        // Optional for Big Block and eMMC/4G
        let skip_fs = matches!(layout, NandLayout::Bb | NandLayout::Emmc) && self.flashfs.root.entries.is_empty();
        
        if !skip_fs {
            let fs_blob = self.flashfs.root.clone().serialize_logical(layout);
            let fs_anchor = 0x100000;
            if fs_anchor + fs_blob.len() <= logical_image.len() {
                logical_image[fs_anchor..fs_anchor + fs_blob.len()].copy_from_slice(&fs_blob);
            }
        }

        Ok(logical_image)
    }

    /// Reconstructs a full physical NAND image from the skeleton.
    /// This follows the J-Runner logic: Logical Assembly -> Physical Distribution (skipping bad blocks).
    pub fn build(&self, cpukey: [u8; 16]) -> Result<Vec<u8>, String> {
        let cpukey_bytes = cpukey;

        // 1. Prepare an Encrypted Clone
        let mut skeleton = self.clone();
        
        // Encrypt Keyvault
        let mut kv = crate::builder::chain::kv::Keyvault::parse(&skeleton.extra.keyvault)?;
        kv.encrypt(&cpukey_bytes, true)?; // Build defaults to Hashed KV
        skeleton.extra.keyvault = kv.data;

        // Encrypt Chain
        let mut smc = crate::builder::chain::smc::RawSmc::new(skeleton.extra.smc.clone());
        // SMC starts encrypted with BuNy, encrypt_chain will handle FixPerBoxDigest marriage logic
        
        encrypt_chain(
            skeleton.bootloaders.cb_a.as_mut().unwrap(),
            skeleton.bootloaders.cb_x.as_mut(),
            skeleton.bootloaders.cb_b.as_mut(),
            skeleton.bootloaders.sc.as_mut(),
            skeleton.bootloaders.cd.as_mut().unwrap(), // Guaranteed in parse
            skeleton.bootloaders.ce.as_mut().unwrap(), // Guaranteed in parse
            skeleton.update.cf_0.as_mut(),
            skeleton.update.cg_0.as_mut(),
            skeleton.update.cf_1.as_mut(),
            skeleton.update.cg_1.as_mut(),
            &mut smc,
            &cpukey_bytes,
        )?;

        // Re-encrypt SMC with BuNy
        smc.encrypt();
        skeleton.extra.smc = smc.data;

        // 2. Logical Assembly
        let logical_image = skeleton.assemble_logical()?;

        // 3. Physical Distribution & Bad Block Mapping
        let layout = &self.options.layout;
        let mut physical_image = vec![0xFFu8; self.total_blocks * layout.physical_page_size()];
        
        let logical_block_size = layout.logical_pages_per_block() * 0x200;
        let physical_block_size = layout.physical_block_size();
        
        let mut logical_ptr = 0;
        for p_block in 0..self.total_blocks {
            // Bad block skipping
            if let Some(ref map) = self.block_map {
                if map.is_bad(p_block) {
                    continue;
                }
            }

            if logical_ptr + logical_block_size <= logical_image.len() {
                let logical_chunk = &logical_image[logical_ptr..logical_ptr + logical_block_size];
                let profile = if p_block < 0x20 { SpareProfile::Metadata } else { SpareProfile::FileSystem };
                
                let ecc_chunk = addecc(logical_chunk, layout.clone(), profile, p_block * physical_block_size);
                
                let p_offset = p_block * physical_block_size;
                physical_image[p_offset..p_offset + ecc_chunk.len()].copy_from_slice(&ecc_chunk);
                
                logical_ptr += logical_block_size;
            } else {
                break;
            }
        }

        Ok(physical_image)
    }
}