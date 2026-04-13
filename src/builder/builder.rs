/*
    builder.rs - Core NAND assembly and parsing logic.

    Modified in 2026 by Exposure / Zach for GGX
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

use std::collections::HashMap;
use zerocopy::{FromBytes, IntoBytes, KnownLayout, Immutable};
use zerocopy::byteorder::{U16, U32, I16, BigEndian};
use log::{info, error};

use crate::core::data::blocks::*;
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

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub struct NandHeader {
    pub prefix: NandHeaderPrefix,
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
}

impl NandHeader {
    pub const MAGIC: u16 = 0xFF4F;

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
        info!("NAND magic:       0x{:04X}", self.prefix.magic.get());
        info!("NAND build:       {}", self.prefix.version.get());
        info!("CB offset:        0x{:X}", self.cb_offset());
        info!("CF offset:        0x{:X}", self.cf_offset.get());
        let copyright = String::from_utf8_lossy(&self.copyright);
        info!("Copyright:        {}", copyright.trim_matches(char::from(0)));
        info!("KV offset:        0x{:X}", self.kv_addr.get());
        info!("KV size:          0x{:X}", self.kv_size.get());
        info!("SMC boot size:    0x{:X}", self.smc_boot_size.get());
        info!("SMC boot offset:  0x{:X}", self.smc_boot_offset.get());
    }
}

use crate::builder::chain::cb::BootloaderCb;
use crate::builder::chain::sc::BootloaderSc;
use crate::builder::chain::cd::BootloaderCd;
use crate::builder::chain::ce::BootloaderCe;
use crate::builder::chain::cf::BootloaderCf;
use crate::builder::chain::cg::BootloaderCg;

#[derive(Clone)]
pub struct NandBootloaders {
    pub cb: Option<BootloaderCb>,
    pub cb_a: Option<BootloaderCb>,
    pub cb_x: Option<BootloaderCb>,
    pub cb_b: Option<BootloaderCb>,
    pub sc: Option<BootloaderSc>,
    pub cd: Option<BootloaderCd>,
    pub ce: Option<BootloaderCe>,
}

#[derive(Clone)]
pub struct NandUpdate {
    pub cf_0: Option<BootloaderCf>,
    pub cg_0: Option<BootloaderCg>,
    pub cf_1: Option<BootloaderCf>,
    pub cg_1: Option<BootloaderCg>,
}

#[derive(Clone)]
pub struct NandExtra {
    pub smc: Vec<u8>,
    pub smc_config: Vec<u8>,
    pub keyvault: Vec<u8>,
    pub fcrt: Option<Vec<u8>>,
    pub power_on_cause_a: u8,
    pub power_on_cause_b: u8,
}

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
    Xenon = 0, Zephyr = 1, Falcon = 2, Jasper = 3, Trinity = 4, Corona = 5, Winchester = 6, Unknown = 0xF,
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
    Single, Split, Devkit, Devgl, Rgbuild, Xdkbuild, Onef, Twof,
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BuildType {
    Retail, Jtag, Glitch, Conversion,
}

#[derive(Clone)]
pub struct BuildOptions {
    pub layout: NandLayout,
    pub block_map: BlockMap,
    pub image_type: ImageType,
    pub build_type: BuildType,
    pub motherboard: MotherboardType,
    pub bigonsmall: bool,
    pub shadowboot: bool,
    pub mfg: bool,
    pub patches: Option<NandPatches>,
}

#[derive(Clone)]
pub struct NandSkeleton {
    pub cpukey: Option<[u8; 16]>,
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
    /// Create a blank NandSkeleton for building from scratch.
    pub fn new_blank(layout: NandLayout) -> Self {
        let size = match layout {
            NandLayout::Xsb | NandLayout::Sb => 0x1000000,
            NandLayout::Bb => 0x4000000,
            NandLayout::Emmc => 0x3000000,
        };
        let mut image = vec![0xFFu8; size];
        image[0] = 0xFF; image[1] = 0x4F;
        let total_blocks = size / (layout.logical_pages_per_block() * 0x200);

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
                bigonsmall: false, shadowboot: false, mfg: false, patches: None,
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
                unused: [0u8; 0x10],
                kv_size: U32::new(0x4000),
                cf_offset: U32::new(0),
                patch_slots: I16::new(0),
                kv_version: U16::new(0),
                kv_addr: U32::new(0x4000),
                patch_size: U32::new(0),
                smc_config_offset: U32::new(0),
                smc_boot_size: U32::new(0x2000),
                smc_boot_offset: U32::new(0x2000),
            },
            extra: NandExtra { smc: Vec::new(), smc_config: Vec::new(), keyvault: Vec::new(), fcrt: None, power_on_cause_a: 0, power_on_cause_b: 0 },
            bootloaders: NandBootloaders { cb: None, cb_a: None, cb_x: None, cb_b: None, sc: None, cd: None, ce: None },
            update: NandUpdate { cf_0: None, cg_0: None, cf_1: None, cg_1: None },
            flashfs: FlashFS { root: crate::builder::chain::flashfs::FileSystemRoot::new(0, 0), partitions: HashMap::new() },
            layout,
            total_blocks,
        }
    }

    /// Parses a clean logical NAND image (no ECC/Spare) into a skeleton.
    /// Based on x360Utils NANDReader + J-Runner Nand.cs parsing:
    /// 1. Validate header magic and bounds
    /// 2. Extract KV and SMC using header offset pointers
    /// 3. Walk bootloader chain: CB_A → [CB_X] → CB_B → CD → CE → CF/CG
    /// 4. Handle CF_Ptr bridging when CF isn't contiguous after CE
    /// 5. Decrypt full chain with verification
    pub fn parse_clean(image: Vec<u8>, layout: NandLayout, cpukey: [u8; 16], flashfs: FlashFS) -> Result<Self, String> {
        // 1. Validate header
        let header_sz = std::mem::size_of::<NandHeader>();
        if image.len() < header_sz {
            return Err(format!("Image too small for header: {} bytes (need {})", image.len(), header_sz));
        }
        let header = NandHeader::read_from_prefix(&image[..header_sz])
            .map_err(|e| format!("Failed to parse NAND header: {}", e))?
            .0;
        header.validate()?;
        header.print_info();

        // 2. Extract and decrypt Keyvault
        let kv_addr = header.kv_addr.get() as usize;
        let kv_size = header.kv_size.get() as usize;
        if kv_size != 0x4000 {
            return Err(format!("Invalid KV size: 0x{:X} (expected 0x4000)", kv_size));
        }
        if kv_addr.checked_add(kv_size).ok_or("KV offset overflow")? > image.len() {
            return Err(format!("KV out of bounds: offset 0x{:X} + size 0x{:X} > image 0x{:X}",
                               kv_addr, kv_size, image.len()));
        }
        info!(" -> Extracting and decrypting Keyvault (Addr: 0x{:X}, Size: 0x{:X})...", kv_addr, kv_size);
        let mut kv = crate::builder::chain::kv::Keyvault::parse(&image[kv_addr..kv_addr + kv_size])?;
        kv.decrypt(&cpukey)?;

        // 3. Extract and decrypt SMC
        let smc_offset = header.smc_boot_offset.get() as usize;
        let smc_size = header.smc_boot_size.get() as usize;
        if smc_offset.checked_add(smc_size).ok_or("SMC offset overflow")? > image.len() {
            return Err(format!("SMC out of bounds: offset 0x{:X} + size 0x{:X} > image 0x{:X}",
                               smc_offset, smc_size, image.len()));
        }
        info!(" -> Extracting and decrypting SMC (Addr: 0x{:X}, Size: 0x{:X})...", smc_offset, smc_size);
        let mut smc = crate::builder::chain::smc::RawSmc::new(image[smc_offset..smc_offset + smc_size].to_vec());
        smc.decrypt();

        let extra = NandExtra {
            smc: smc.data,
            smc_config: Vec::new(),
            keyvault: kv.data,
            fcrt: None,
            power_on_cause_a: 0,
            power_on_cause_b: 0,
        };

        // 4. Walk bootloader chain
        info!(" -> Walking bootloader chain starting at offset 0x{:X}...", header.cb_offset());
        let (bl, mut update) = Self::parse_bootloader_chain(&image, header.cb_offset() as usize, header.cf_offset.get() as usize)?;

        // 5. Decrypt chain — fail early if critical bootloaders are missing
        info!(" -> Decrypting bootloader chain...");
        let mut bl_mut = bl;
        if bl_mut.cb_a.is_none() { return Err("Missing CB_A bootloader".into()); }
        if bl_mut.cd.is_none() { return Err("Missing CD bootloader".into()); }
        if bl_mut.ce.is_none() { return Err("Missing CE bootloader".into()); }

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
        info!(" -> Bootloader chain successfully decrypted.");

        // 6. Build skeleton
        let motherboard = if extra.smc.len() > 0x100 {
            MotherboardType::from_smc(extra.smc[0x100])
        } else {
            MotherboardType::Unknown
        };
        let total_blocks = image.len() / (layout.logical_pages_per_block() * 0x200);
        let image_type = if bl_mut.cb_b.is_some() { ImageType::Split } else { ImageType::Single };

        Ok(NandSkeleton {
            cpukey: Some(cpukey),
            image,
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
            bootloaders: bl_mut,
            update,
            flashfs,
        })
    }

    /// Parses the bootloader chain from a clean NAND image.
    /// Based on x360Utils Bootloader + J-Runner sequential parsing:
    /// CB_A → [CB_X] → CB_B → CD → CE → [CF_Ptr jump] → CF/CG pairs
    fn parse_bootloader_chain(
        image: &[u8],
        cb_offset: usize,
        cf_ptr: usize,
    ) -> Result<(NandBootloaders, NandUpdate), String> {
        let mut bl = NandBootloaders {
            cb: None, cb_a: None, cb_x: None, cb_b: None,
            sc: None, cd: None, ce: None,
        };
        let mut update = NandUpdate {
            cf_0: None, cg_0: None, cf_1: None, cg_1: None,
        };

        let mut off = cb_offset;
        let mut cf_count = 0;
        let mut cg_count = 0;
        let mut cb_seen = 0;

        // Primary chain walk: CB_A → [CB_X] → CB_B → CD → CE
        let mut iteration = 0;
        while iteration < 16 {
            iteration += 1;

            if off + 0x10 > image.len() {
                info!(" -> End of bootloader chain at offset 0x{:08X}", off);
                break;
            }

            let bl_header = match BootloaderHeader::read_from_prefix(&image[off..off + 0x10]) {
                Ok((h, _)) => h,
                Err(_) => {
                    info!(" -> Invalid bootloader header at offset 0x{:08X}", off);
                    break;
                }
            };

            let bl_size = bl_header.size.get() as usize;
            let bl_version = bl_header.version.get();

            // Validate size bounds — if invalid, stop the chain walk gracefully
            // and let CF_Ptr bridging handle the gap (common between CE and CF)
            if bl_size < 0x10 || bl_size > 0x2000000 {
                info!(" -> Invalid bootloader size at 0x{:08X} (0x{:X}), stopping chain walk", off, bl_size);
                break;
            }
            if off + bl_size > image.len() {
                info!(" -> Bootloader at 0x{:08X} extends past image end (size 0x{:X}), stopping", off, bl_size);
                break;
            }

            let bl_data = image[off..off + bl_size].to_vec();
            let aligned_size = (bl_size + 0xF) & 0xFFFFFFF0;

            match bl_header.get_type() {
                XenonBlType::CB => {
                    cb_seen += 1;
                    let is_cba = (bl_header.flags.get() & 0x800) == 0x800 || cb_seen == 1;
                    let is_cbx = bl_size == 0x400 && cb_seen > 1;

                    if is_cba {
                        info!(" -> CB_A at 0x{:08X} (v{}, 0x{:X} bytes)", off, bl_version, bl_size);
                        bl.cb_a = Some(BootloaderCb::parse(&bl_data)?);
                    } else if is_cbx {
                        info!(" -> CB_X at 0x{:08X} (v{}, 0x{:X} bytes)", off, bl_version, bl_size);
                        bl.cb_x = Some(BootloaderCb::parse(&bl_data)?);
                    } else {
                        info!(" -> CB_B at 0x{:08X} (v{}, 0x{:X} bytes)", off, bl_version, bl_size);
                        bl.cb_b = Some(BootloaderCb::parse(&bl_data)?);
                    }
                }
                XenonBlType::SC => {
                    info!(" -> SC at 0x{:08X} (v{}, 0x{:X} bytes)", off, bl_version, bl_size);
                    bl.sc = Some(BootloaderSc::parse(&bl_data)?);
                }
                XenonBlType::CD => {
                    info!(" -> CD at 0x{:08X} (v{}, 0x{:X} bytes)", off, bl_version, bl_size);
                    bl.cd = Some(BootloaderCd::parse(&bl_data)?);
                }
                XenonBlType::CE => {
                    info!(" -> CE at 0x{:08X} (v{}, 0x{:X} bytes)", off, bl_version, bl_size);
                    bl.ce = Some(BootloaderCe::parse(&bl_data)?);
                }
                XenonBlType::CF => {
                    cf_count += 1;
                    info!(" -> CF_{} at 0x{:08X} (v{}, 0x{:X} bytes)", cf_count, off, bl_version, bl_size);
                    let cf = BootloaderCf::parse(&bl_data)?;
                    if cf_count == 1 { update.cf_0 = Some(cf); }
                    else { update.cf_1 = Some(cf); }
                }
                XenonBlType::CG => {
                    cg_count += 1;
                    info!(" -> CG_{} at 0x{:08X} (v{}, 0x{:X} bytes)", cg_count, off, bl_version, bl_size);
                    let cg = BootloaderCg::parse(&bl_data)?;
                    if cg_count == 1 { update.cg_0 = Some(cg); }
                    else { update.cg_1 = Some(cg); }
                }
                _ => {
                    info!(" -> Unknown bootloader type at 0x{:08X}, stopping chain walk", off);
                    break;
                }
            }

            off += aligned_size;
        }

        // CF/CG secondary: if not found in primary walk, try CF_Ptr
        // This handles big-block NANDs where CF is at a non-contiguous offset
        if update.cf_0.is_none() && cf_ptr > 0 && cf_ptr < image.len() {
            info!(" -> CF not found after CE, trying CF_Ptr at 0x{:08X}", cf_ptr);
            off = cf_ptr;

            while off + 0x10 <= image.len() && cf_count < 2 {
                let bl_header = match BootloaderHeader::read_from_prefix(&image[off..off + 0x10]) {
                    Ok((h, _)) => h,
                    Err(_) => break,
                };

                let bl_size = bl_header.size.get() as usize;
                if bl_size < 0x10 || bl_size > 0x2000000 { break; }
                if off + bl_size > image.len() { break; }

                let bl_data = image[off..off + bl_size].to_vec();
                let aligned_size = (bl_size + 0xF) & 0xFFFFFFF0;

                match bl_header.get_type() {
                    XenonBlType::CF => {
                        cf_count += 1;
                        info!(" -> CF_{} at 0x{:08X} (v{}, 0x{:X} bytes)", cf_count, off, bl_header.version.get(), bl_size);
                        let cf = BootloaderCf::parse(&bl_data)?;
                        if cf_count == 1 { update.cf_0 = Some(cf); }
                        else { update.cf_1 = Some(cf); }
                    }
                    XenonBlType::CG => {
                        cg_count += 1;
                        info!(" -> CG_{} at 0x{:08X} (v{}, 0x{:X} bytes)", cg_count, off, bl_header.version.get(), bl_size);
                        let cg = BootloaderCg::parse(&bl_data)?;
                        if cg_count == 1 { update.cg_0 = Some(cg); }
                        else { update.cg_1 = Some(cg); }
                    }
                    _ => break,
                }

                off += aligned_size;
            }
        }

        Ok((bl, update))
    }

    pub fn assemble_logical(&self) -> Result<Vec<u8>, String> {
        let layout = &self.options.layout;
        let mut logical_image = vec![0xFFu8; self.total_blocks * layout.logical_pages_per_block() * 0x200];
        let mut header = self.header.clone();

        let bootchain_start = 0x8000;
        let smc_offset = header.smc_boot_offset.get() as usize;
        let kv_offset = header.kv_addr.get() as usize;

        if !self.extra.smc.is_empty() {
            logical_image[smc_offset..smc_offset + self.extra.smc.len()].copy_from_slice(&self.extra.smc);
        }
        if !self.extra.keyvault.is_empty() {
            logical_image[kv_offset..kv_offset + self.extra.keyvault.len()].copy_from_slice(&self.extra.keyvault);
        }

        let mut curr = bootchain_start;
        let mut stages = Vec::new();
        if let Some(cba) = &self.bootloaders.cb_a { stages.push(cba.serialize()); }
        if let Some(cbx) = &self.bootloaders.cb_x { stages.push(cbx.serialize()); }
        if let Some(cbb) = &self.bootloaders.cb_b { stages.push(cbb.serialize()); }
        if let Some(sc) = &self.bootloaders.sc { stages.push(sc.serialize()); }
        if let Some(cd) = &self.bootloaders.cd { stages.push(cd.serialize()); }
        if let Some(ce) = &self.bootloaders.ce { stages.push(ce.serialize()); }

        for data in stages {
            if curr + data.len() > logical_image.len() {
                return Err(format!("Bootchain overflow at 0x{:X}: need 0x{:X} bytes", curr, data.len()));
            }
            logical_image[curr..curr+data.len()].copy_from_slice(&data);
            curr += (data.len() + 0xF) & 0xFFFFFFF0;
        }

        // CF/CG always start at 0x70000 (standard CF offset for small-block NAND).
        // CF_0/CG_0 go at 0x70000, CF_1/CG_1 go at 0x80000 (exactly 64KB later).
        // This matches x360Utils GetBootLoaders() which seeks to CF_Ptr + 0x10000 for CF_1/CG_1.
        let cf0 = self.update.cf_0.as_ref().map(|b| b.serialize());
        let cg0 = self.update.cg_0.as_ref().map(|b| b.serialize());
        let cf1 = self.update.cf_1.as_ref().map(|b| b.serialize()).or_else(|| cf0.clone());
        let cg1 = self.update.cg_1.as_ref().map(|b| b.serialize()).or_else(|| cg0.clone());

        if let Some(cf0d) = cf0 {
            let cf0_offset = match layout {
                NandLayout::Bb => 0x80000,
                _ => 0x70000,
            };
            let cf1_offset = cf0_offset + 0x10000; // 64KB gap between CF_0 and CF_1

            header.cf_offset.set(cf0_offset as u32);
            header.patch_slots.set(if cf1.is_some() { 2 } else { 1 });

            if cf0_offset + cf0d.len() > logical_image.len() {
                return Err(format!("CF0 overflow at 0x{:X}: need 0x{:X} bytes", cf0_offset, cf0d.len()));
            }
            logical_image[cf0_offset..cf0_offset+cf0d.len()].copy_from_slice(&cf0d);
            if let Some(cg0d) = cg0 {
                let cg0_offset = cf0_offset + cf0d.len();
                if cg0_offset + cg0d.len() > logical_image.len() {
                    return Err(format!("CG0 overflow at 0x{:X}: need 0x{:X} bytes", cg0_offset, cg0d.len()));
                }
                logical_image[cg0_offset..cg0_offset+cg0d.len()].copy_from_slice(&cg0d);
            }
            if let Some(cf1d) = cf1 {
                if cf1_offset + cf1d.len() > logical_image.len() {
                    return Err(format!("CF1 overflow at 0x{:X}: need 0x{:X} bytes", cf1_offset, cf1d.len()));
                }
                logical_image[cf1_offset..cf1_offset+cf1d.len()].copy_from_slice(&cf1d);
                if let Some(cg1d) = cg1 {
                    let cg1_offset = cf1_offset + cf1d.len();
                    if cg1_offset + cg1d.len() > logical_image.len() {
                        return Err(format!("CG1 overflow at 0x{:X}: need 0x{:X} bytes", cg1_offset, cg1d.len()));
                    }
                    logical_image[cg1_offset..cg1_offset+cg1d.len()].copy_from_slice(&cg1d);
                }
            }
        }

        header.prefix.entrypoint.set(bootchain_start as u32);
        let header_bytes = zerocopy::IntoBytes::as_bytes(&header);
        logical_image[..header_bytes.len()].copy_from_slice(header_bytes);

        if !self.flashfs.root.entries.is_empty() && self.flashfs.root.block_number >= 0 {
            let fs_block = self.flashfs.root.block_number as usize;
            let fs_offset = fs_block * layout.logical_pages_per_block() * 0x200;
            let fs = self.flashfs.root.clone().serialize_logical(*layout);
            if fs_offset + fs.len() <= logical_image.len() {
                logical_image[fs_offset..fs_offset + fs.len()].copy_from_slice(&fs);
            } else {
                error!("[NandSkeleton] FlashFS block {} (offset 0x{:X}) exceeds image bounds", fs_block, fs_offset);
            }
        }

        Ok(logical_image)
    }

    pub fn build(&self, cpukey: [u8; 16]) -> Result<Vec<u8>, String> {
        let mut skel = self.clone();
        info!(" -> Starting final image build...");
        let mut kv = crate::builder::chain::kv::Keyvault::parse(&skel.extra.keyvault)?;
        info!(" -> Encrypting Keyvault...");
        kv.encrypt(&cpukey, true)?;
        skel.extra.keyvault = kv.data;

        let mut smc = crate::builder::chain::smc::RawSmc::new(skel.extra.smc.clone());
        info!(" -> Re-encrypting bootloader chain...");
        encrypt_chain(
            skel.bootloaders.cb_a.as_mut().ok_or("Missing CB_A for encryption")?,
            skel.bootloaders.cb_x.as_mut(),
            skel.bootloaders.cb_b.as_mut(),
            skel.bootloaders.sc.as_mut(),
            skel.bootloaders.cd.as_mut().ok_or("Missing CD for encryption")?,
            skel.bootloaders.ce.as_mut().ok_or("Missing CE for encryption")?,
            skel.update.cf_0.as_mut(),
            skel.update.cg_0.as_mut(),
            skel.update.cf_1.as_mut(),
            skel.update.cg_1.as_mut(),
            &mut smc, &cpukey,
        )?;
        info!(" -> Re-encrypting SMC...");
        smc.encrypt();
        skel.extra.smc = smc.data;
        skel.assemble_logical()
    }
}
