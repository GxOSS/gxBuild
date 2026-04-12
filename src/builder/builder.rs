/*
    builder.rs - Core NAND assembly and parsing logic.
    
    Modified in 2026 by Exposure / Zach for GGX
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

use std::collections::HashMap;
use zerocopy::{FromBytes, IntoBytes, KnownLayout, Immutable};
use zerocopy::byteorder::{U16, U32, I16, BigEndian};

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
        println!("NAND magic:       0x{:04X}", self.prefix.magic.get());
        println!("NAND build:       {}", self.prefix.version.get());
        println!("CB offset:        0x{:X}", self.cb_offset());
        println!("CF offset:        0x{:X}", self.cf_offset.get());
        let copyright = String::from_utf8_lossy(&self.copyright);
        println!("Copyright:        {}", copyright.trim_matches(char::from(0)));
        println!("KV offset:        0x{:X}", self.kv_addr.get());
        println!("KV size:          0x{:X}", self.kv_size.get());
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
    /// Create a blank NandSkeleton for building from scratch
    pub fn new_blank(layout: NandLayout) -> Self {
        let size = match layout {
            NandLayout::Xsb | NandLayout::Sb => 0x1000000, // 16 MB small block
            NandLayout::Bb => 0x4000000,                    // 64 MB big block (default blank)
            NandLayout::Emmc => 0x3000000,                  // 48 MB eMMC
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
            header: unsafe { std::mem::zeroed() },
            extra: NandExtra { smc: Vec::new(), smc_config: Vec::new(), keyvault: Vec::new(), fcrt: None, power_on_cause_a: 0, power_on_cause_b: 0 },
            bootloaders: NandBootloaders { cb: None, cb_a: None, cb_x: None, cb_b: None, sc: None, cd: None, ce: None },
            update: NandUpdate { cf_0: None, cg_0: None, cf_1: None, cg_1: None },
            flashfs: FlashFS { root: crate::builder::chain::flashfs::FileSystemRoot::new(0, 0), partitions: HashMap::new() },
            layout,
            total_blocks,
        }
    }

    /// Parses a clean logical NAND image (no ECC/Spare) into a skeleton.
    pub fn parse_clean(image: Vec<u8>, layout: NandLayout, cpukey: [u8; 16], flashfs: FlashFS) -> Result<Self, String> {
        let cpukey_bytes = cpukey;

        // 1. Read Header
        let header_sz = std::mem::size_of::<NandHeader>();
        if image.len() < header_sz { return Err("Clean image too small to contain header".into()); }
        let header = NandHeader::read_from_prefix(&image[..header_sz]).map_err(|e| e.to_string())?.0;
        header.validate()?;

        // 2. Extract Keyvault and SMC
        let kv_addr = header.kv_addr.get() as usize;
        let kv_size = header.kv_size.get() as usize;
        if kv_addr + kv_size > image.len() {
            return Err(format!("Keyvault offset (0x{:X}) or size (0x{:X}) exceeds image bounds", kv_addr, kv_size));
        }
        let kv_clean = image[kv_addr..kv_addr + kv_size].to_vec();
        let mut kv = crate::builder::chain::kv::Keyvault::parse(&kv_clean)?;
        kv.decrypt(&cpukey_bytes)?;

        let smc_offset = header.smc_boot_offset.get() as usize;
        let smc_size = header.smc_boot_size.get() as usize;
        if smc_offset + smc_size > image.len() {
             return Err(format!("SMC offset (0x{:X}) or size (0x{:X}) exceeds image bounds", smc_offset, smc_size));
        }
        let smc_clean = image[smc_offset..smc_offset + smc_size].to_vec();
        let mut smc = crate::builder::chain::smc::RawSmc::new(smc_clean);
        smc.decrypt();

        let extra = NandExtra {
            smc: smc.data, smc_config: Vec::new(), keyvault: kv.data,
            fcrt: None, power_on_cause_a: 0, power_on_cause_b: 0,
        };

        // 3. Extract Bootloaders
        let mut bl = NandBootloaders { cb: None, cb_a: None, cb_x: None, cb_b: None, sc: None, cd: None, ce: None };
        let mut off = header.cb_offset() as usize;
        
        let extract_next = |o: &mut usize| -> Result<Vec<u8>, String> {
            if *o + 0x10 > image.len() { return Err("EOF in clean walk".into()); }
            let h = BootloaderHeader::read_from_prefix(&image[*o..*o+0x10]).map_err(|e| e.to_string())?.0;
            let sz = h.size.get() as usize;
            let d = image[*o..*o+sz].to_vec();
            *o += (sz + 0xF) & 0xFFFFFFF0;
            Ok(d)
        };

        let cb_a_bytes = extract_next(&mut off)?;
        bl.cb_a = Some(BootloaderCb::parse(&cb_a_bytes)?);

        let mut cf_0: Option<BootloaderCf> = None;
        let mut cg_0: Option<BootloaderCg> = None;
        let mut cf_1: Option<BootloaderCf> = None;
        let mut cg_1: Option<BootloaderCg> = None;

        while off + 0x10 < image.len() {
            let h = match BootloaderHeader::read_from_prefix(&image[off..off+0x10]) {
                Ok((h, _)) => h,
                Err(_) => break,
            };
            match h.get_type() {
                XenonBlType::CB => {
                    let d = extract_next(&mut off)?;
                    if d.len() == 0x400 { bl.cb_x = Some(BootloaderCb::parse(&d)?); }
                    else { bl.cb_b = Some(BootloaderCb::parse(&d)?); }
                },
                XenonBlType::SC => { bl.sc = Some(BootloaderSc::parse(&extract_next(&mut off)?)?); },
                XenonBlType::CD => { bl.cd = Some(BootloaderCd::parse(&extract_next(&mut off)?)?); },
                XenonBlType::CE => { bl.ce = Some(BootloaderCe::parse(&extract_next(&mut off)?)?); },
                XenonBlType::CF => {
                    let d = extract_next(&mut off)?;
                    let cf = BootloaderCf::parse(&d)?;
                    if cf_0.is_none() { cf_0 = Some(cf); } else { cf_1 = Some(cf); }
                },
                XenonBlType::CG => {
                    let d = extract_next(&mut off)?;
                    let cg = BootloaderCg::parse(&d)?;
                    if cg_0.is_none() { cg_0 = Some(cg); } else { cg_1 = Some(cg); }
                },
                _ => break,
            }
        }

        decrypt_chain(
            bl.cb_a.as_mut().unwrap(), bl.cb_x.as_mut(), bl.cb_b.as_mut(), bl.sc.as_mut(),
            bl.cd.as_mut().ok_or("CD missing")?, bl.ce.as_mut().ok_or("CE missing")?,
            cf_0.as_mut(), cg_0.as_mut(), cf_1.as_mut(), cg_1.as_mut(), &cpukey_bytes,
        )?;

        let motherboard = MotherboardType::from_smc(extra.smc[0x100]);
        let total_blocks = image.len() / (layout.logical_pages_per_block() * 0x200);

        Ok(NandSkeleton {
            cpukey: Some(cpukey_bytes), image, block_map: None, layout,
            total_blocks,
            options: BuildOptions {
                layout, block_map: BlockMap { blocks: Vec::new(), layout },
                image_type: if bl.cb_b.is_some() { ImageType::Split } else { ImageType::Single },
                build_type: BuildType::Retail, motherboard, bigonsmall: false, shadowboot: false, mfg: false, patches: None,
            },
            header, extra, bootloaders: bl, update: NandUpdate { cf_0, cg_0, cf_1, cg_1 }, flashfs,
        })
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
            logical_image[curr..curr+data.len()].copy_from_slice(&data);
            curr += (data.len() + 0xF) & 0xFFFFFFF0;
        }

        let cf0 = self.update.cf_0.as_ref().map(|b| b.serialize());
        let cg0 = self.update.cg_0.as_ref().map(|b| b.serialize());
        let cf1 = self.update.cf_1.as_ref().map(|b| b.serialize()).or_else(|| cf0.clone());
        let cg1 = self.update.cg_1.as_ref().map(|b| b.serialize()).or_else(|| cg0.clone());

        if let Some(cf0d) = cf0 {
            curr = (curr + 0x1FF) & 0xFFFFFE00;
            header.cf_offset.set(curr as u32);
            header.patch_slots.set(2);

            logical_image[curr..curr+cf0d.len()].copy_from_slice(&cf0d); curr += (cf0d.len() + 0xF) & 0xFFFFFFF0;
            if let Some(cg0d) = cg0 { logical_image[curr..curr+cg0d.len()].copy_from_slice(&cg0d); curr += (cg0d.len() + 0xF) & 0xFFFFFFF0; }
            if let Some(cf1d) = cf1 { logical_image[curr..curr+cf1d.len()].copy_from_slice(&cf1d); curr += (cf1d.len() + 0xF) & 0xFFFFFFF0; }
            if let Some(cg1d) = cg1 { logical_image[curr..curr+cg1d.len()].copy_from_slice(&cg1d); }
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
                eprintln!("[NandSkeleton] FlashFS block {} (offset 0x{:X}) exceeds image bounds", fs_block, fs_offset);
            }
        }

        Ok(logical_image)
    }

    pub fn build(&self, cpukey: [u8; 16]) -> Result<Vec<u8>, String> {
        let mut skel = self.clone();
        let mut kv = crate::builder::chain::kv::Keyvault::parse(&skel.extra.keyvault)?;
        kv.encrypt(&cpukey, true)?;
        skel.extra.keyvault = kv.data;

        let mut smc = crate::builder::chain::smc::RawSmc::new(skel.extra.smc.clone());
        encrypt_chain(
            skel.bootloaders.cb_a.as_mut().unwrap(), skel.bootloaders.cb_x.as_mut(), skel.bootloaders.cb_b.as_mut(),
            skel.bootloaders.sc.as_mut(), skel.bootloaders.cd.as_mut().unwrap(), skel.bootloaders.ce.as_mut().unwrap(),
            skel.update.cf_0.as_mut(), skel.update.cg_0.as_mut(), skel.update.cf_1.as_mut(), skel.update.cg_1.as_mut(),
            &mut smc, &cpukey,
        )?;
        smc.encrypt();
        skel.extra.smc = smc.data;
        skel.assemble_logical()
    }
}