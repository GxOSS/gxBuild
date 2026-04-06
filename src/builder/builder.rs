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


use crate::builder::deps::excrypt::{
    Rc4, ExCryptRsa, ExCryptSig,
};
use zerocopy::{FromBytes, IntoBytes, Immutable};
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
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, Clone, Copy)]
#[repr(C)]
pub struct NandHeader {
    pub header: BootloaderHeader,       // magic 0xFF4F, entrypoint -> CB offset
    pub copyright: [u8; 0x40],
    pub unused: [u8; 0x10],
    pub kv_size: U32<BigEndian>,
    pub cf_offset: U32<BigEndian>,
    pub patch_slots: I16<BigEndian>,
    pub kv_version: U16<BigEndian>,
    pub kv_addr: U32<BigEndian>,
    pub patch_size: U32<BigEndian>,
    pub smc_config_offset: U32<BigEndian>,
    pub smc_boot_size: U32<BigEndian>,
    pub smc_boot_offset: U32<BigEndian>,
    pub sys_update_addr: U32<BigEndian>,
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
        if self.header.magic.get() != Self::MAGIC {
            return Err(format!(
                "Invalid NAND magic: 0x{:04X} (expected 0xFF4F)",
                self.header.magic.get()
            ));
        }
        Ok(())
    }

    /// CB offset — the entrypoint field in the embedded bootloader header.
    pub fn cb_offset(&self) -> u32 {
        self.header.entrypoint.get()
    }

    pub fn is_modified_copyright(&self) -> bool {
        let ms_copyright = b"\xa9 2004-2011 Microsoft Corporation. All rights reserved.\0";
        // Compare everything EXCEPT the year range (bytes 2..11)
        self.copyright[0] != ms_copyright[0] || self.copyright[11..] != ms_copyright[11..]
    }

    pub fn print_info(&self) {
        println!("NAND magic:       0x{:04X}", self.header.magic.get());
        println!("NAND build:       {}", self.header.version.get());
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
    pub cb_b: Option<BootloaderCb>,
    pub sc: Option<BootloaderSc>,
    pub cd: Option<BootloaderCd>,
    pub ce: Option<BootloaderCe>,
}

// If only 0, will be treated as full images. If 0 and 1, will be treated as patchslots
#[derive(Clone)]
pub struct NandUpdate {
    pub cf_0: BootloaderCf,
    pub cg_0: BootloaderCg,
    pub cf_1: BootloaderCf,
    pub cg_1: BootloaderCg,
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

#[derive(Clone)]
pub struct NandPatches {
    pub rglp: Option<Vec<u8>>,
    pub xebuild: Option<Vec<u8>>,
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
pub enum ImageType { // Base image type
    Single, // CB -> CD
    Split,  // CB_A -> CB_B -> CD
    Devkit, // SB (=CB) -> SC -> SD (=CD)
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
    pub cpukey: Option<String>,
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
    // From J-Runner-with-Extras>J-Runner>Nand>PatchParser.cs
    // Thanks Mena
    // TODO: Add crc32 hashing (?)
    /// Parse patches applied to a NandSkeleton
    pub fn get_patches(&self) -> Option<NandPatches> {
        self.options.patches.clone()
    }

    /// Parse nand image into populated NandSkeleton
    pub fn parse_nand(nandimg: &std::path::Path, cpukey: String) -> Result<Self, String> {
        let raw_image = std::fs::read(nandimg)
            .map_err(|e| format!("Failed to read NAND image: {}", e))?;

        // 1. Detect Layout e.g. 16MB vs 64MB+ vs eMMC
        let layout = NandLayout::detect(&raw_image)?;
        let cpukey_bytes: [u8; 16] = hex_to_bytes(&cpukey).map_err(|_| "Invalid CPU Key format")?.try_into().map_err(|_| "CPU Key must be 16 bytes")?;

        // 2. Extract and Parse NandHeader (always at 0x0)
        // Header is raw at the start, we unecc it to be sure
        let raw_header = unecc(&raw_image[..0x4200]); // Grab first block
        let header = NandHeader::read_from_prefix(&raw_header[..0x100])
            .map(|(h, _)| h.clone())
            .map_err(|_| "Failed to parse primary NAND header")?;

        // Capture Power-on cause / boot triggers from the hacked header area (0x4E/0x4F)
        let power_on_cause_a = raw_header[0x4E];
        let power_on_cause_b = raw_header[0x4F];

        // 3. Extract Bootchain stages individually with their spare data
        let mut bootloaders = NandBootloaders {
            cb: None,
            cb_a: None,
            cb_b: None,
            sc: None,
            cd: None,
            ce: None,
        };

        // Extract CB — its offset is the entrypoint in the header
        let cb_offset = header.cb_offset() as usize;
        let p_cb_offset = if matches!(layout, NandLayout::Emmc) {
            cb_offset
        } else {
            // For NANDs with spares, we calculate the physical offset (0x210 steps)
            (cb_offset / 0x200) * 0x210
        };

        // Read CB Header to find total size
        let raw_cb_hdr = &raw_image[p_cb_offset..p_cb_offset + 0x100]; // peek
        let clean_cb_hdr = unecc(raw_cb_hdr);
        let (bl_hdr, _) = BootloaderHeader::read_from_prefix(&clean_cb_hdr[..0x10])
            .map_err(|_| "Failed to read CB bootloader header")?;
        let bl_hdr = bl_hdr.clone();
        
        let cb_size = bl_hdr.size.get() as usize;
        let mut p_cb_size = if matches!(layout, NandLayout::Emmc) {
            cb_size
        } else {
            ((cb_size + 0x1FF) / 0x200) * 0x210
        };
        // Align to 0x10 physically if needed
        p_cb_size = (p_cb_size + 0xF) & 0xFFFFFFF0;

        let cb_raw_data = &raw_image[p_cb_offset..p_cb_offset + p_cb_size];
        let cb_clean_data = unecc(cb_raw_data);
        let cb_extracted = BootloaderCb::parse(&cb_clean_data)?;
        
        let mut image_type = ImageType::Single;

        // Detect Split-CB (flags 0x800)
        if (cb_extracted.header.header.flags.get() & 0x800) == 0x800 {
            image_type = ImageType::Split;
            bootloaders.cb_a = Some(cb_extracted);
        } else {
            bootloaders.cb = Some(cb_extracted);
        }

        // --- Chain Walk (CD / CE) ---
        // CD usually follows the last CB stage directly (or after SC)
        let mut p_next_offset = p_cb_offset + p_cb_size;

        // Helper to peek and slice the next stage
        let mut extract_next = |offset: &mut usize, expected_type: XenonBlType| -> Result<Vec<u8>, String> {
            if *offset + 0x100 > raw_image.len() {
                return Err("Offset out of bounds during chain walk".to_string());
            }
            let peek_raw = &raw_image[*offset..*offset + 0x100];
            let clean_peek = unecc(peek_raw);
            let (hdr, _) = BootloaderHeader::read_from_prefix(&clean_peek[..0x10])
                .map_err(|_| "Failed to read next stage header")?;
            let hdr = hdr.clone();

            let size = hdr.size.get() as usize;
            let p_size = if matches!(layout, NandLayout::Emmc) { size } else { ((size + 0x1FF) / 0x200) * 0x210 };
            let p_aligned_size = (p_size + 0xF) & 0xFFFFFFF0;

            if *offset + p_aligned_size > raw_image.len() {
                 return Err(format!("Stage size (0x{:x}) exceeds image bounds", p_aligned_size));
            }

            let data = unecc(&raw_image[*offset..*offset + p_aligned_size]);
            *offset += p_aligned_size;
            Ok(data)
        };

        // If it was a split image, the next stage SHOULD be CB_B
        if image_type == ImageType::Split {
            let cb_b_data = extract_next(&mut p_next_offset, XenonBlType::CB)?;
            let cb_b_extracted = BootloaderCb::parse(&cb_b_data)?;
            bootloaders.cb_b = Some(cb_b_extracted.clone());
        }

        // --- Sequence Scanner (SC -> CD -> CE / SD -> SE) ---
        while p_next_offset + 0x100 < raw_image.len() {
            let peek_raw = &raw_image[p_next_offset..p_next_offset + 0x100];
            let clean_peek = unecc(peek_raw);
            let bl_hdr = if let Ok((h, _)) = BootloaderHeader::read_from_prefix(&clean_peek[..0x10]) { h.clone() } else { break; };
            
            match bl_hdr.get_type() {
                XenonBlType::SC => {
                    let sc_data = extract_next(&mut p_next_offset, XenonBlType::SC)?;
                    let sc_extracted = BootloaderSc::parse(&sc_data)?;
                    bootloaders.sc = Some(sc_extracted.clone());
                },
                XenonBlType::CD => { // CD or SD (devkit variant)
                    let cd_data = extract_next(&mut p_next_offset, bl_hdr.get_type())?;
                    let cd_extracted = BootloaderCd::parse(&cd_data)?;
                    bootloaders.cd = Some(cd_extracted.clone());
                },
                XenonBlType::CE => { // CE or SE (devkit variant)
                    let ce_data = extract_next(&mut p_next_offset, bl_hdr.get_type())?;
                    let ce_extracted = BootloaderCe::parse(&ce_data)?;
                    bootloaders.ce = Some(ce_extracted.clone());
                },
                XenonBlType::CB if image_type == ImageType::Split && bootloaders.cb_b.is_none() => {
                    // Handle Split CB_B (or devkit SB equivalent)
                    let b_data = extract_next(&mut p_next_offset, bl_hdr.get_type())?;
                    let cb_b_extracted = BootloaderCb::parse(&b_data)?;
                    bootloaders.cb_b = Some(cb_b_extracted.clone());
                },
                _ => break, 
            }
        }

        // 4. Extract CF/CG if offsets are present
        let mut cf_0: Option<BootloaderCf> = None;
        let mut cg_0: Option<BootloaderCg> = None;
        let mut cf_1: Option<BootloaderCf> = None;
        let mut cg_1: Option<BootloaderCg> = None;

        let cf_offset = header.cf_offset.get() as usize;
        if cf_offset != 0 {
            let mut p_cur_offset = if matches!(layout, NandLayout::Emmc) { cf_offset } else { (cf_offset / 0x200) * 0x210 };
            
            for _ in 0..4 { // Search for up to 4 slots (usually 2 CF+CG pairs)
                if p_cur_offset + 0x100 > raw_image.len() { break; }
                
                let peek = unecc(&raw_image[p_cur_offset..p_cur_offset+0x100]);
                let bl_hdr = if let Ok((h, _)) = BootloaderHeader::read_from_prefix(&peek[..0x10]) { h.clone() } else { break; };
                
                let size = bl_hdr.size.get() as usize;
                let p_size = if matches!(layout, NandLayout::Emmc) { size } else { ((size + 0x1FF) / 0x200) * 0x210 };
                let p_aligned = (p_size + 0xF) & 0xFFFFFFF0;
                
                if bl_hdr.get_type() == XenonBlType::CF {
                    let cf_extracted = BootloaderCf::parse(&unecc(&raw_image[p_cur_offset..p_cur_offset+p_aligned]))?;
                    let cf = cf_extracted.clone();
                    if cf_0.is_none() { cf_0 = Some(cf); } else { cf_1 = Some(cf); }
                } else if bl_hdr.get_type() == XenonBlType::CG {
                    let cg_extracted = BootloaderCg::parse(&unecc(&raw_image[p_cur_offset..p_cur_offset+p_aligned]))?;
                    let cg = cg_extracted.clone();
                    if cg_0.is_none() { cg_0 = Some(cg); } else { cg_1 = Some(cg); }
                }
                
                p_cur_offset += p_aligned;
            }
        }

        // 5. Run decryption chain using the mandatory CPU Key
        let mut cf_final = cf_0.as_mut().ok_or("CF_0 stage not found in NAND image")?;
        let mut cg_final = cg_0.as_mut().ok_or("CG_0 stage not found in NAND image")?;

        decrypt_chain(
            bootloaders.cb.as_mut().or(bootloaders.cb_a.as_mut()).ok_or("CB stage missing")?,
            bootloaders.sc.as_mut(),
            bootloaders.cd.as_mut().ok_or("CD stage missing")?,
            bootloaders.ce.as_mut().ok_or("CE stage missing")?,
            cf_final,
            cg_final,
            &cpukey_bytes,
        )?;

        let cf_0_final = cf_0.clone().ok_or("CF_0 stage not found in NAND image")?;
        let cg_0_final = cg_0.clone().ok_or("CG_0 stage not found in NAND image")?;

        let update = NandUpdate {
            cf_0: cf_0_final.clone(),
            cg_0: cg_0_final.clone(),
            cf_1: cf_1.unwrap_or(cf_0_final),
            cg_1: cg_1.unwrap_or(cg_0_final),
        };

        // 6. Extract Extra (SMC / KV)
        let kv_addr = header.kv_addr.get() as usize;
        let kv_size = header.kv_size.get() as usize;
        let smc_offset = header.smc_boot_offset.get() as usize;
        let smc_size = header.smc_boot_size.get() as usize;
        
        let p_smc_offset = if matches!(layout, NandLayout::Emmc) { smc_offset } else { (smc_offset / 0x200) * 0x210 };
        let p_smc_size = if matches!(layout, NandLayout::Emmc) { smc_size } else { ((smc_size + 0x1FF) / 0x200) * 0x210 };
        
        let smc_raw = unecc(&raw_image[p_smc_offset..p_smc_offset + p_smc_size]);
        let mut smc = crate::builder::chain::smc::RawSmc::new(smc_raw);
        smc.decrypt(); // SMC is always encrypted with the BuNy cipher

        let motherboard = MotherboardType::from_smc(smc.data[0x100]);

        let p_kv_offset = if matches!(layout, NandLayout::Emmc) { kv_addr } else { (kv_addr / 0x200) * 0x210 };
        let p_kv_size = if matches!(layout, NandLayout::Emmc) { kv_size } else { ((kv_size + 0x1FF) / 0x200) * 0x210 };
        
        let kv_raw = unecc(&raw_image[p_kv_offset..p_kv_offset + p_kv_size]);
        let mut kv = crate::builder::chain::kv::Keyvault::parse(&kv_raw)?;
        kv.decrypt(&cpukey_bytes)?;

        // Attempt to find SMC Config
        let (p_conf_off, p_conf_size) = match layout {
            NandLayout::Xsb | NandLayout::Sb => (0xFEB800, 0x4200 * 4),
            NandLayout::Bb => (0x3D5C000, 0x21000 * 4),
            NandLayout::Emmc => (0x2FF0000, 0x4000 * 4),
        };
        
        let extra = NandExtra {
            smc: smc.data,
            smc_config: unecc(&raw_image[p_conf_off..p_conf_off + p_conf_size]),
            keyvault: kv.data,
            fcrt: None,
            power_on_cause_a: 0,
            power_on_cause_b: 0,
        };

        let total_blocks = raw_image.len() / layout.physical_block_size();

        // 6. Discover Filesystem
        let flashfs = FlashFS::scan(&raw_image, &layout);

        let skeleton = NandSkeleton {
            cpukey: Some(cpukey),
            image: raw_image,
            block_map: None,
            layout,
            total_blocks,
            options: BuildOptions {
                layout,
                block_map: BlockMap { blocks: Vec::new(), layout },
                image_type, 
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
        };

        Ok(skeleton)
    }


    /// Assembles a 'Flat' logical image (0x200 pages) from the skeleton's components.
    /// This is the precursor to applying physical spare data and ECC.
    pub fn assemble_logical(&self) -> Result<Vec<u8>, String> {
        let layout = &self.options.layout;
        let mut logical_image = vec![0xFFu8; self.total_blocks * layout.logical_pages_per_block() * 0x200];
        
        let mut header = self.header.clone();
        
        // 1. Placement Strategy (Logical Offsets)
        let smc_offset = header.smc_boot_offset.get() as usize;
        let kv_offset = 0x4000;
        let bootchain_start = 0x8000;

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

        if let Some(cb_bl) = bl.cb.as_ref().or(bl.cb_a.as_ref()) {
            stages.push(cb_bl.serialize());
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
            logical_image[current_offset..current_offset + len].copy_from_slice(&data);
            current_offset += (len + 0xF) & 0xFFFFFFF0; // 0x10 Alignment
        }

        // 5. Inject Mandated Dual Patch Slots (CF/CG)
        header.cf_offset.set(current_offset as u32);
        
        // Slot 0
        let cf_0_data = self.update.cf_0.serialize();
        logical_image[current_offset..current_offset + cf_0_data.len()].copy_from_slice(&cf_0_data);
        current_offset += (cf_0_data.len() + 0xF) & 0xFFFFFFF0;

        let cg_0_data = self.update.cg_0.serialize();
        logical_image[current_offset..current_offset + cg_0_data.len()].copy_from_slice(&cg_0_data);
        current_offset += (cg_0_data.len() + 0xF) & 0xFFFFFFF0;

        // Slot 1 (Mandatory)
        let cf_1_data = self.update.cf_1.serialize();
        logical_image[current_offset..current_offset + cf_1_data.len()].copy_from_slice(&cf_1_data);
        current_offset += (cf_1_data.len() + 0xF) & 0xFFFFFFF0;

        let cg_1_data = self.update.cg_1.serialize();
        logical_image[current_offset..current_offset + cg_1_data.len()].copy_from_slice(&cg_1_data);
        current_offset += (cg_1_data.len() + 0xF) & 0xFFFFFFF0;

        // 6. Final Header Sync & Write
        header.header.entrypoint.set(bootchain_start as u32);
        let header_bytes = zerocopy::IntoBytes::as_bytes(&header);
        logical_image[..header_bytes.len()].copy_from_slice(header_bytes);

        // 7. FlashFS (Usually at 0x100000)
        let fs_blob = self.flashfs.root.clone().serialize_logical(layout);
        let fs_anchor = 0x100000;
        if fs_anchor + fs_blob.len() <= logical_image.len() {
            logical_image[fs_anchor..fs_anchor + fs_blob.len()].copy_from_slice(&fs_blob);
        }

        Ok(logical_image)
    }

    /// Reconstructs a full physical NAND image from the skeleton.
    /// This follows the J-Runner logic: Logical Assembly -> Physical Distribution (skipping bad blocks).
    pub fn build(&self, cpukey: String) -> Result<Vec<u8>, String> {
        let cpukey_bytes: [u8; 16] = hex_to_bytes(&cpukey)
            .map_err(|_| "Invalid CPU Key format")?
            .try_into()
            .map_err(|_| "CPU Key must be 16 bytes")?;

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
            skeleton.bootloaders.cb.as_mut().or(skeleton.bootloaders.cb_a.as_mut()).ok_or("CB missing")?,
            skeleton.bootloaders.sc.as_mut(),
            skeleton.bootloaders.cd.as_mut().ok_or("CD missing")?,
            skeleton.bootloaders.ce.as_mut().ok_or("CE missing")?,
            &mut skeleton.update.cf_0, 
            &mut skeleton.update.cg_0,
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