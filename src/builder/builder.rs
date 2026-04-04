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

use bevy_reflect::{Reflect, Struct};
use crate::builder::deps::excrypt::{
    ExCryptBnQwBeSigVerify, ExCryptHmacSha, ExCryptRc4Ecb, ExCryptRc4Key, ExCryptRc4State,
    ExCryptRotSumSha, ExCryptRsa, ExCryptSig,
};
use zerocopy::*;
use zerocopy::byteorder::{U16, U32, U64, I16, I32, BigEndian};

use crate::builder::tools::flashfs::FlashFS;
use crate::builder::deps::compression::*;
use crate::builder::tools::blocks::*;
use crate::builder::chain::*;
use crate::builder::tools::smc_crypto;

/// Xbox 360 NAND header — matches xenon-bltool's `xenon_nand_header` layout.
/// The first field is a `BootloaderHeader` whose `entrypoint` points to CB.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
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
use crate::builder::chain::xell::XeLL;

// Bootchain will be interpreted from provided bootloaders
pub struct NandBootloaders {
    pub cb: Option<BootloaderCb>,
    pub cb_a: Option<BootloaderCb>,
    pub cb_b: Option<BootloaderCb>,
    pub sc: Option<BootloaderSc>,
    pub cd: Option<BootloaderCd>,
    pub ce: Option<BootloaderCe>,
    pub xell: Option<XeLL>,
}

// If only 0, will be treated as full images. If 0 and 1, will be treated as patchslots
pub struct NandUpdate {
    pub cf_0: BootloaderCf,
    pub cg_0: BootloaderCg,
    pub cf_1: Option<BootloaderCf>,
    pub cg_1: Option<BootloaderCg>,
}

// SMC, Keyvault and Security
pub struct NandExtra {
    pub smc: Vec<u8>,
    pub smc_config: Vec<u8>,
    pub keyvault: Vec<u8>,
    pub fcrt: Option<Vec<u8>>,
    // Power-up cause / boot trigger stubs
    pub power_on_cause_a: u8,
    pub power_on_cause_b: u8,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone)]
#[repr(C)]
pub struct KeyvaultRecord {
    pub unused0: [u8; 0xB0],
    pub serial: [u8; 12],
    pub unused1: [u8; 0x6],
    pub console_id: [u8; 5],
    pub unused2: [u8; 0x2B],
    pub dvd_key: [u8; 16],
    pub unused3: [u8; 0x10],
    pub game_region: U16<BigEndian>,
    pub video_region: U16<BigEndian>,
}

pub struct NandPatches {
    pub rglp: Option<Vec<u8>>,
    pub xebuild: Option<Vec<u8>>,
}

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

#[derive(PartialEq)]
pub enum ImageType { // Base image type
    Single, // CB -> CD
    Split,  // CB_A -> CB_B -> CD
    Devkit, // SB (=CB) -> SC -> SD (=CD)
}

#[derive(PartialEq)]
pub enum BuildType { // Custom images
    Retail,     // Regular secure image
    Jtag,       // Dual-boot with reboot chain
    Glitch,     // Patches somewhere after CE
    Conversion, // Load dev kernel on glitch or glitch kernel on dev
}

pub struct BuildOptions {
    pub layout: NandLayout,
    pub image_type: ImageType,
    pub build_type: BuildType,
    pub motherboard: MotherboardType,
    pub bigonsmall: bool, // Usually false, For RGL/ XDKB systems with nandfs on hdd
    pub shadowboot: bool, // Toggle shadowboot image creation
    pub mfg: bool,
    pub patches: Option<NandPatches>,
}

pub struct BlockMap; // Standard placeholder for now

impl BlockMap {
    pub fn is_bad(&self, _block: usize) -> bool {
        false // TODO: implement real bad block tracking
    }
}


pub struct NandSkeleton {
    pub cpukey: Option<String>,
    pub image: Vec<u8>,
    pub block_map: Option<BlockMap>,
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
    /// Discovers and extracts all critical NAND metadata (Header, Bootloaders, Keyvault, SMC) from a raw dump.
    /// A CPU Key is required for successful decryption of the bootloader chain.
    pub fn decrypt_smc(&mut self) -> Result<(), String> {
        if self.extra.smc.is_empty() {
            return Err("SMC binary is empty".to_string());
        }
        self.extra.smc = smc_crypto::decrypt_smc(&self.extra.smc);
        Ok(())
    }

    pub fn decrypt_kv(&mut self, cpukey: [u8; 16]) -> Result<(), String> {
        if self.extra.keyvault.len() < 0x10 {
            return Err("Keyvault is too small".to_string());
        }

        let kv = &mut self.extra.keyvault;
        
        // 1. Extract the HMAC-SHA1 Nonce (first 16 bytes)
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&kv[..0x10]);

        // 2. Derive the RC4 key: HMAC-SHA1(CPUKey, Nonce)
        let mut rc4_key = [0u8; 20];
        unsafe {
            ExCryptHmacSha(
                cpukey.as_ptr(),
                cpukey.len() as u32,
                nonce.as_ptr(),
                nonce.len() as u32,
                std::ptr::null(), 0,
                std::ptr::null(), 0,
                rc4_key.as_mut_ptr(),
                20
            );
        }

        // 3. Decrypt the rest of the KV (0x10 to end) using RC4
        let mut state = ExCryptRc4State { S: [0u8; 256], i: 0, j: 0 };
        unsafe {
            ExCryptRc4Key(&mut state, rc4_key.as_ptr(), 16);
            ExCryptRc4Ecb(&mut state, kv[0x10..].as_mut_ptr(), (kv.len() - 0x10) as u32);
        }

        Ok(())
    }

    /// Retrieve critical console metadata (DVD Key, Region, Serial) from a decrypted Keyvault.
    pub fn get_kv_info(&self) -> Result<KeyvaultRecord, String> {
        if self.extra.keyvault.len() < 0x130 {
            return Err("Keyvault not decrypted or too small".to_string());
        }
        KeyvaultRecord::read_from_bytes(&self.extra.keyvault[..std::mem::size_of::<KeyvaultRecord>()])
            .ok().ok_or_else(|| "Failed to map KeyvaultRecord structure".to_string())
    }

    pub fn parse_nand(nandimg: &std::path::Path, cpukey: String) -> Result<Self, String> {
        let raw_image = std::fs::read(nandimg)
            .map_err(|e| format!("Failed to read NAND image: {}", e))?;

        // 1. Detect Layout e.g. 16MB vs 64MB+ vs eMMC
        let layout = NandLayout::detect(&raw_image)?;

        // 2. Extract and Parse NandHeader (always at 0x0)
        // Header is raw at the start, we unecc it to be sure
        let raw_header = unecc(&raw_image[..0x4200]); // Grab first block
        let header = NandHeader::read_from_bytes(&raw_header[..0x100])
            .ok().ok_or("Failed to parse primary NAND header")?;

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
            xell: None,
        };

        let extra = NandExtra {
            smc: Vec::new(),
            smc_config: Vec::new(),
            keyvault: Vec::new(),
            fcrt: None,
            power_on_cause_a,
            power_on_cause_b,
        };

        // Extract CB — its offset is the entrypoint in the header
        let cb_offset = header.cb_offset() as usize;
        let p_cb_offset = if matches!(layout, NandLayout::Layout3) {
            cb_offset
        } else {
            // For NANDs with spares, we calculate the physical offset (0x210 steps)
            (cb_offset / 0x200) * 0x210
        };

        // Read CB Header to find total size
        let raw_cb_hdr = &raw_image[p_cb_offset..p_cb_offset + 0x100]; // peek
        let clean_cb_hdr = unecc(raw_cb_hdr);
        let bl_hdr = BootloaderHeader::read_from_bytes(&clean_cb_hdr[..0x10])
            .ok().ok_or("Failed to read CB bootloader header")?;
        
        let cb_size = bl_hdr.size.get() as usize;
        let mut p_cb_size = if matches!(layout, NandLayout::Layout3) {
            cb_size
        } else {
            ((cb_size + 0x1FF) / 0x200) * 0x210
        };
        // Align to 0x10 physically if needed
        p_cb_size = (p_cb_size + 0xF) & 0xFFFFFFF0;

        let cb_raw_data = &raw_image[p_cb_offset..p_cb_offset + p_cb_size];
        let cb_clean_data = unecc(cb_raw_data);
        let cb_extracted = BootloaderCb::from_bytes(&cb_clean_data)?;
        
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
            let hdr = BootloaderHeader::read_from_bytes(&clean_peek[..0x10])
            .ok().ok_or("Failed to read next stage header")?;

            let size = hdr.size.get() as usize;
            let p_size = if matches!(layout, NandLayout::Layout3) { size } else { ((size + 0x1FF) / 0x200) * 0x210 };
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
            bootloaders.cb_b = Some(BootloaderCb::from_bytes(&cb_b_data)?);
        }

        // --- Sequence Scanner (SC -> CD -> CE / SD -> SE) ---
        while p_next_offset + 0x100 < raw_image.len() {
            let peek_raw = &raw_image[p_next_offset..p_next_offset + 0x100];
            let clean_peek = unecc(peek_raw);
            let bl_hdr = if let Some(h) = BootloaderHeader::read_from_bytes(&clean_peek[..0x10]).ok() { h } else { break; };
            
            match bl_hdr.get_type() {
                XenonBlType::SC => {
                    let sc_data = extract_next(&mut p_next_offset, XenonBlType::SC)?;
                    bootloaders.sc = Some(BootloaderSc::from_bytes(&sc_data)?);
                },
                XenonBlType::CD => { // CD or SD (devkit variant)
                    let cd_data = extract_next(&mut p_next_offset, bl_hdr.get_type())?;
                    bootloaders.cd = Some(BootloaderCd::from_bytes(&cd_data)?);
                },
                XenonBlType::CE => { // CE or SE (devkit variant)
                    let ce_data = extract_next(&mut p_next_offset, bl_hdr.get_type())?;
                    bootloaders.ce = Some(BootloaderCe::from_bytes(&ce_data)?);
                },
                XenonBlType::CB if image_type == ImageType::Split && bootloaders.cb_b.is_none() => {
                    // Handle Split CB_B (or devkit SB equivalent)
                    let b_data = extract_next(&mut p_next_offset, bl_hdr.get_type())?;
                    bootloaders.cb_b = Some(BootloaderCb::from_bytes(&b_data)?);
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
            let mut p_cur_offset = if matches!(layout, NandLayout::Layout3) { cf_offset } else { (cf_offset / 0x200) * 0x210 };
            
            for _ in 0..4 { // Search for up to 4 slots (usually 2 CF+CG pairs)
                if p_cur_offset + 0x100 > raw_image.len() { break; }
                
                let peek = unecc(&raw_image[p_cur_offset..p_cur_offset+0x100]);
                let bl_hdr = if let Some(h) = BootloaderHeader::read_from_bytes(&peek[..0x10]).ok() { h } else { break; };
                
                let size = bl_hdr.size.get() as usize;
                let p_size = if matches!(layout, NandLayout::Layout3) { size } else { ((size + 0x1FF) / 0x200) * 0x210 };
                let p_aligned = (p_size + 0xF) & 0xFFFFFFF0;
                
                if bl_hdr.get_type() == XenonBlType::CF {
                    let cf = BootloaderCf::from_bytes(&unecc(&raw_image[p_cur_offset..p_cur_offset+p_aligned]))?;
                    if cf_0.is_none() { cf_0 = Some(cf); } else { cf_1 = Some(cf); }
                } else if bl_hdr.get_type() == XenonBlType::CG {
                    let cg = BootloaderCg::from_bytes(&unecc(&raw_image[p_cur_offset..p_cur_offset+p_aligned]))?;
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
            bootloaders.cb_b.as_mut(),
            bootloaders.sc.as_mut(),
            bootloaders.cd.as_mut().ok_or("CD stage missing")?,
            bootloaders.ce.as_mut().ok_or("CE stage missing")?,
            cf_final,
            cg_final,
            &cpukey,
        )?;

        let update = NandUpdate {
            cf_0: cf_0.ok_or("CF_0 stage not found in NAND image")?,
            cg_0: cg_0.ok_or("CG_0 stage not found in NAND image")?,
            cf_1,
            cg_1,
        };

        // 6. Extract Extra (SMC / KV)
        let kv_addr = header.kv_addr.get() as usize;
        let kv_size = header.kv_size.get() as usize;
        let smc_offset = header.smc_boot_offset.get() as usize;
        let smc_size = header.smc_boot_size.get() as usize;
        
        let p_kv_offset = if matches!(layout, NandLayout::Layout3) { kv_addr } else { (kv_addr / 0x200) * 0x210 };
        let p_kv_size = if matches!(layout, NandLayout::Layout3) { kv_size } else { ((kv_size + 0x1FF) / 0x200) * 0x210 };
        let p_smc_offset = if matches!(layout, NandLayout::Layout3) { smc_offset } else { (smc_offset / 0x200) * 0x210 };
        let p_smc_size = if matches!(layout, NandLayout::Layout3) { smc_size } else { ((smc_size + 0x1FF) / 0x200) * 0x210 };
        
        let mut smc_data = unecc(&raw_image[p_smc_offset..p_smc_offset + p_smc_size]);
        // TODO: SMC Decryption should happen here
        let motherboard = MotherboardType::from_smc(smc_data[0x100]);

        // Attempt to find SMC Config
        let (p_conf_off, p_conf_size) = match layout {
            NandLayout::Layout0 | NandLayout::Layout1 => (0xFEB800, 0x4200 * 4),
            NandLayout::Layout2 => (0x3D5C000, 0x21000 * 4),
            NandLayout::Layout3 => (0x2FF0000, 0x4000 * 4),
        };
        
        let extra = NandExtra {
            smc: smc_data,
            smc_config: unecc(&raw_image[p_conf_off..p_conf_off + p_conf_size]),
            keyvault: unecc(&raw_image[p_kv_offset..p_kv_offset + p_kv_size]),
            fcrt: None,
            power_on_cause_a,
            power_on_cause_b,
        };

        let total_blocks = raw_image.len() / layout.physical_block_size();

        let mut skeleton = NandSkeleton {
            cpukey: Some(cpukey),
            image: raw_image,
            block_map: None,
            layout,
            total_blocks,
            options: BuildOptions {
                layout,  // NandLayout is Copy
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
            flashfs: FlashFS::new(),
        };

        // 6. Discover Filesystem
        skeleton.scan_flashfs();

        Ok(skeleton)
    }


    /// Assembles a 'Flat' logical image (0x200 pages) from the skeleton's components.
    /// This is the precursor to applying physical spare data and ECC.
    pub fn assemble_logical(&self, xell_mode: bool) -> Result<Vec<u8>, String> {
        let mut logical_image = vec![0xFFu8; self.total_blocks * 0x200];

        // 1. Header (0x0)
        let mut header = self.header;
        
        // 2. Map SMC and KV (Logical offsets)
        if let Some(smc) = self.extra.smc.as_slice().get(..) {
            // Re-encrypt SMC before mapping (Round-Trip)
            let encrypted_smc = smc_crypto::encrypt_smc(smc);
            let smc_offset = 0x4000 - encrypted_smc.len();
            logical_image[smc_offset..smc_offset + encrypted_smc.len()].copy_from_slice(&encrypted_smc);
            header.smc_start.set(smc_offset as u32);
            header.smc_size.set(encrypted_smc.len() as u32);
        }

        if let Some(kv) = self.extra.keyvault.as_slice().get(..) {
            logical_image[0x4000..0x4000 + kv.len()].copy_from_slice(kv);
        }

        // 3. Assemble the Bootchain (starting at 0x8000 usually)
        let mut current_offset = 0x8000;
        let bl = &self.bootloaders;

        // Sequence: CB (A+B or Single) -> SC -> CD -> CE
        if let Some(cb_primary) = bl.cb_a.as_ref().or(bl.cb.as_ref()) {
            let cb_primary_data = cb_primary.serialize(); 
            logical_image[current_offset..current_offset + cb_primary_data.len()].copy_from_slice(&cb_primary_data);
            header.block_offset.set(current_offset as u32);
            current_offset += (cb_primary_data.len() + 0xF) & 0xFFFFFFF0;
        }

        if let Some(ref cb_b) = bl.cb_b {
            let cb_b_data = cb_b.serialize();
            logical_image[current_offset..current_offset + cb_b_data.len()].copy_from_slice(&cb_b_data);
            current_offset += (cb_b_data.len() + 0xF) & 0xFFFFFFF0;
        }

        if let Some(ref sc) = bl.sc {
            let sc_data = sc.serialize();
            logical_image[current_offset..current_offset + sc_data.len()].copy_from_slice(&sc_data);
            current_offset += (sc_data.len() + 0xF) & 0xFFFFFFF0;
        }

        if let Some(ref cd) = bl.cd {
            let cd_data = cd.serialize();
            logical_image[current_offset..current_offset + cd_data.len()].copy_from_slice(&cd_data);
            current_offset += (cd_data.len() + 0xF) & 0xFFFFFFF0;
        }

        if let Some(ref ce) = bl.ce {
            let ce_data = ce.serialize();
            logical_image[current_offset..current_offset + ce_data.len()].copy_from_slice(&ce_data);
            current_offset += (ce_data.len() + 0xF) & 0xFFFFFFF0;
        }

        let bootchain_end = current_offset;

        // 4. Inject in-memory KHV patches (CDXell)
        // Patches are appended directly after the bootchain end
        // CD engine looks at: Header[0x64] + Header[0x70] + 0x5C
        if let Some(ref patches) = self.options.patches {
            if let Some(ref xebuild) = patches.xebuild {
                // Header Synchronization for the patch engine
                header.cf_offset.set(0x8000);
                header.patch_size.set((bootchain_end - 0x8000) as u32);

                // Add 0x5C padding for 'Virtual Fuses' as used by the search pointer
                let patch_start = bootchain_end + 0x5C;
                if patch_start + xebuild.len() <= logical_image.len() {
                    logical_image[patch_start..patch_start + xebuild.len()].copy_from_slice(xebuild);
                }
            }
        }

        // 5. Handle XeLL (Logical 0xC0000)
        if xell_mode {
            if let Some(ref xell) = bl.xell {
                let xell_data = xell.serialize_for_nand(256 * 1024);
                let xell_offset = 0xC0000;
                if xell_offset + xell_data.len() <= logical_image.len() {
                    logical_image[xell_offset..xell_offset + xell_data.len()].copy_from_slice(&xell_data);
                }
            }
        }

        // 5. Handle FlashFS (NandFS)
        // Usually anchored at logical 0x100000 for standard RGH images
        let fs_blob = self.flashfs.root.clone().serialize_logical(&self.layout);
        let fs_offset = 0x100000;
        if fs_offset + fs_blob.len() <= logical_image.len() {
            logical_image[fs_offset..fs_offset + fs_blob.len()].copy_from_slice(&fs_blob);
        }

        // 6. Inject SMC Config (Config.bin)
        if let Some(config) = self.extra.smc_config.as_slice().get(..) {
            let config_offset = match self.layout {
                NandLayout::Layout0 | NandLayout::Layout1 => 0x3DC * self.layout.logical_pages_per_block() * 0x200,
                NandLayout::Layout2 => 0x1F0 * self.layout.logical_pages_per_block() * 0x200,
                NandLayout::Layout3 => 0x2FF0000, // eMMC fixed offset
            };
            if config_offset + config.len() <= logical_image.len() {
                logical_image[config_offset..config_offset + config.len()].copy_from_slice(config);
            }
        }

        // 7. Final Header Sync
        let header_bytes = header.as_bytes();
        logical_image[..header_bytes.len()].copy_from_slice(header_bytes);

        Ok(logical_image)
    }

    /// Reconstructs a full physical NAND image from the skeleton.
    /// This follows the J-Runner logic: Logical Assembly -> Physical Distribution (skipping bad blocks).
    pub fn build(&self) -> Result<Vec<u8>, String> {
        use crate::builder::tools::blocks::{addecc, SpareProfile};

        // 1. Logical Assembly (XeLL vs Retail)
        let xell_mode = self.bootloaders.xell.is_some();
        let logical_image = self.assemble_logical(xell_mode)?;

        // 2. Physical Distribution & Bad Block Mapping
        let layout = &self.options.layout;
        let mut physical_image = vec![0xFFu8; self.total_blocks * layout.physical_page_size()];
        
        let logical_block_size = layout.logical_pages_per_block() * 0x200;
        let physical_block_size = layout.physical_block_size();
        
        let mut logical_ptr = 0;
        for p_block in 0..self.total_blocks {
            // Check if this physical block is bad
            // If it is, we leave it as 0xFF and move to the next physical slot
            if let Some(ref map) = self.block_map {
                if map.is_bad(p_block) {
                    continue;
                }
            }

            // Pull the next logical chunk
            if logical_ptr + logical_block_size <= logical_image.len() {
                let logical_chunk = &logical_image[logical_ptr..logical_ptr + logical_block_size];
                
                // Identify the profile for this block (Metadata for start of NAND, FileSystem for the rest)
                let profile = if p_block < 0x8 { SpareProfile::Metadata } else { SpareProfile::FileSystem };
                
                // Physical conversion (0x210 pages)
                let ecc_chunk = addecc(logical_chunk, layout.clone(), profile, p_block * physical_block_size);
                
                // Copy to final image
                let p_offset = p_block * physical_block_size;
                physical_image[p_offset..p_offset + ecc_chunk.len()].copy_from_slice(&ecc_chunk);
                
                logical_ptr += logical_block_size;
            } else {
                // No more logical data to write
                break;
            }
        }

        Ok(physical_image)
    }

    /// High-level scan that populates the skeleton's filesystem state automatically from the attached image.
    pub fn scan_flashfs(&mut self) {
        self.flashfs = FlashFS::scan(&self.image, &self.options.layout);
    }
}