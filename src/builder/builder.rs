/*
    builder.rs - Core NAND assembly and parsing logic.

    Modified in 2026 by Exposure / Zach for GGX
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

use std::collections::HashMap;
use zerocopy::{FromBytes, IntoBytes, KnownLayout, Immutable};
use zerocopy::byteorder::{U16, U32, I16, BigEndian};
use log::{info, error, warn};

use crate::core::data::blocks::*;
use crate::builder::chain::*;
use crate::builder::chain::flashfs::FlashFS;
use crate::core::data::gxp::{GxpBinary, GxpPatchType, apply_records, PatchRecord};

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!("Hex string has odd length ({}): '{}'", hex.len(), hex));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex byte '{}': {}", &hex[i..i + 2], e))
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
    /// Maps to `FileSystemAddress` in RGBuild/xeBuild. Real eMMC dumps show 0x10000.
    /// Not used for booting; do not overwrite unless managing a full FS root.
    pub fs_addr: U32<BigEndian>,
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
    pub khvpatch: Option<Vec<PatchRecord>>,
    pub xell: Option<crate::builder::chain::xell::Xell>,
}

impl NandBootloaders {
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

#[derive(Clone)]
pub struct NandExtra {
    pub smc: Vec<u8>,
    pub smc_config: Vec<u8>,
    pub keyvault: Vec<u8>,
    pub fcrt: Option<Vec<u8>>,
    pub power_on_cause_a: u8,
    pub power_on_cause_b: u8,
}

// Legacy local PatchRecord removed in favor of crate::core::data::gxp::PatchRecord

#[derive(Clone)]
pub struct NandPatches {
    pub rglp: Option<Vec<u8>>,
    pub xebuild: Option<Vec<u8>>,
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
    pub noremap: bool,
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
    pub rebooter: Option<NandBootloaders>,
    pub update: NandUpdate,
    pub rebooter_update: Option<NandUpdate>,
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
            NandLayout::Emmc => 0x3000000, // 48MB standard EMMC corona dump
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
                bigonsmall: false, shadowboot: false, mfg: false, noremap: false, patches: None,
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
                cf_offset: U32::new(match layout {
                    NandLayout::Bb   => 0x80000,
                    NandLayout::Emmc => 0xB0000,
                    _                => 0x70000,
                }),
                patch_slots: I16::new(0),
                kv_version: U16::new(0x712), // v1 retail - matches real dump (emmc-ksb-rginfo.txt)
                kv_addr: U32::new(0x4000), // Standard retail KV offset for all layouts
                // FileSystemAddress - 0x10000 on all real dumps (emmc-ksb-rginfo.txt: FileSystem addr 0x10000)
                fs_addr: U32::new(0x10000),
                // eMMC header field is 0x0; console scans for config at 0x2FFC000 independently
                smc_config_offset: U32::new(match layout {
                    NandLayout::Emmc => 0x0,
                    _                => crate::builder::chain::smc::SmcConfig::get_logical_address(&layout),
                }),
                // Corona eMMC SMC is 0x3800 bytes at 0x800; SB/BB is 0x3000 bytes at 0x1000
                // Confirmed from extract-ksb-emmc.log: SMC at 0x800 size 0x3800
                smc_boot_size: U32::new(match layout {
                    NandLayout::Emmc => 0x3800,
                    _                => 0x3000,
                }),
                smc_boot_offset: U32::new(match layout {
                    NandLayout::Emmc => 0x800,  // 0x4000 - 0x3800
                    _                => 0x1000, // 0x4000 - 0x3000
                }),
            },
            extra: NandExtra { smc: Vec::new(), smc_config: Vec::new(), keyvault: Vec::new(), fcrt: None, power_on_cause_a: 0, power_on_cause_b: 0 },
            bootloaders: NandBootloaders { cb: None, cb_a: None, cb_x: None, cb_b: None, sc: None, cd: None, ce: None, khvpatch: None, xell: None },
            rebooter: None,
            update: NandUpdate { cf_0: None, cg_0: None, cf_1: None, cg_1: None },
            rebooter_update: None,
            flashfs: FlashFS { root: crate::builder::chain::flashfs::FileSystemRoot::new(0, 0), partitions: HashMap::new() },
            layout,
            total_blocks,
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
        info!("[builder] Extracting and decrypting Keyvault (Addr: 0x{:X}, Size: 0x{:X})...", kv_addr, kv_size);
        let mut kv = crate::builder::chain::kv::Keyvault::parse(&image[kv_addr..kv_addr + kv_size])?;
        // KV version 0x712 = v1 retail (RC4 only, no HMAC outer wrap).
        // Any other non-zero value = v2+ = hashed (HMAC-SHA1 outer).
        // Reference: RGBuild BootloaderFlashHeader uses KeyVaultVersion == 0x712 as the v1 sentinel.
        let kv_version = header.kv_version.get();
        let hashed = kv_version != 0 && kv_version != 0x712;
        kv.decrypt(&cpukey, hashed)?;

        // 3. Extract and decrypt SMC
        let smc_offset = header.smc_boot_offset.get() as usize;
        let smc_size = header.smc_boot_size.get() as usize;
        if smc_offset.checked_add(smc_size).ok_or("SMC offset overflow")? > image.len() {
            return Err(format!("SMC out of bounds: offset 0x{:X} + size 0x{:X} > image 0x{:X}",
                               smc_offset, smc_size, image.len()));
        }
        info!("[builder] Extracting and decrypting SMC (Addr: 0x{:X}, Size: 0x{:X})...", smc_offset, smc_size);
        let mut smc = crate::builder::chain::smc::RawSmc::new(image[smc_offset..smc_offset + smc_size].to_vec());
        smc.decrypt();

        // 3b. Extract SMC Config (usually 0x10000 bytes)
        let config_offset = header.smc_config_offset.get() as usize;
        let config_size = 0x10000; // standard config partition size
        
        let config_data = if config_offset > 0 && config_offset + config_size <= image.len() {
            info!("[builder] Extracting SMC Config (Addr: 0x{:X}, Size: 0x{:X})...", config_offset, config_size);
            image[config_offset..config_offset + config_size].to_vec()
        } else {
            if config_offset > 0 {
                warn!("[builder] SMC Config offset 0x{:X} is out of bounds, using blank config", config_offset);
            }
            Vec::new()
        };

        let extra = NandExtra {
            smc: smc.data,
            smc_config: config_data,
            keyvault: kv.data,
            fcrt: None,
            power_on_cause_a: 0,
            power_on_cause_b: 0,
        };

        // 4. Walk bootloader chain
        info!("[builder] Walking bootloader chain starting at offset 0x{:X}...", header.cb_offset());
        let (bl, mut update) = Self::parse_bootloader_chain(&image, header.cb_offset() as usize, header.cf_offset.get() as usize)?;

        // 5. Decrypt chain - fail early if critical bootloaders are missing
        info!("[builder] Decrypting bootloader chain...");
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
        info!("[builder] Bootloader chain successfully decrypted.");

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
                noremap: false,
                patches: None,
            },
            header,
            extra,
            bootloaders: bl_mut,
            rebooter: None,
            update,
            rebooter_update: None,
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
            sc: None, cd: None, ce: None, khvpatch: None,
            xell: None,
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

                    // Layout taxonomy:
                    //   Single:  CB (cb_seen=1, no 0x800 flag)  → bl.cb
                    //   Split:   CB_A (cb_seen=1) + CB_B         → bl.cb_a, bl.cb_b
                    //   Glitch3: CB_A (cb_seen=1) + CB_X (cb_seen=2, small, 0x800, zero pairing)
                    //            + CB_B (cb_seen=3)              → bl.cb_a, bl.cb_x, bl.cb_b
                    // CB_A always accompanies CB_B; a lone CB_A does not exist.
                    // Confirmed from emmc-ksb-rginfo.txt:
                    //   CB_A flags=0x801 size=0x1AF0 cb_seen=1
                    //   CB_X flags=0x800 size=0x400  cb_seen=2  pairing=0x0000
                    let is_single = cb_seen == 1 && !has_cba_flag;
                    let is_cba   = cb_seen == 1 && has_cba_flag;
                    let is_cbx   = cb_seen == 2
                        && has_cba_flag                   // stub still carries 0x800
                        && bl_size <= 0x500               // stub is very small (0x400 on Corona)
                        && bl_header.pairing.get() == 0;  // stub pairing word is 0x0000
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
                    cf_count += 1;
                    info!("[builder] CF_{} at 0x{:08X} (v{}, 0x{:X} bytes)", cf_count, off, bl_version, bl_size);
                    let cf = BootloaderCf::parse(&bl_data)?;
                    if cf_count == 1 { update.cf_0 = Some(cf); }
                    else { update.cf_1 = Some(cf); }
                }
                XenonBlType::CG => {
                    cg_count += 1;
                    info!("[builder] CG_{} at 0x{:08X} (v{}, 0x{:X} bytes)", cg_count, off, bl_version, bl_size);
                    let cg = BootloaderCg::parse(&bl_data)?;
                    if cg_count == 1 { update.cg_0 = Some(cg); }
                    else { update.cg_1 = Some(cg); }
                }
                _ => {
                    info!("[builder] Unknown bootloader type at 0x{:08X}, stopping chain walk", off);
                    break;
                }
            }

            off += aligned_size;
        }

        // CF/CG secondary: if not found in primary walk, try CF_Ptr
        // This handles big-block NANDs where CF is at a non-contiguous offset
        if update.cf_0.is_none() && cf_ptr > 0 && cf_ptr < image.len() {
            info!("[builder] CF not found after CE, trying CF_Ptr at 0x{:08X}", cf_ptr);
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
                        info!("[builder] CF_{} at 0x{:08X} (v{}, 0x{:X} bytes)", cf_count, off, bl_header.version.get(), bl_size);
                        let cf = BootloaderCf::parse(&bl_data)?;
                        if cf_count == 1 { update.cf_0 = Some(cf); }
                        else { update.cf_1 = Some(cf); }
                    }
                    XenonBlType::CG => {
                        cg_count += 1;
                        info!("[builder] CG_{} at 0x{:08X} (v{}, 0x{:X} bytes)", cg_count, off, bl_header.version.get(), bl_size);
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
        let expected_size = self.total_blocks * layout.logical_pages_per_block() * 0x200;
        
        let mut logical_image = self.image.clone();
        if logical_image.len() != expected_size {
            logical_image.resize(expected_size, 0);
        }
        
        let mut header = self.header.clone();

        // Dynamic forensic offset logic:
        // 1. SMC is flush against the end of Block 0 (Sector 32)
        //    eMMC: 0x4000 - 0x3800 = 0x800   (confirmed extract-ksb-emmc.log)
        //    SB/BB: 0x4000 - 0x3000 = 0x1000
        let smc_len = self.extra.smc.len();
        let smc_default_offset = match layout {
            NandLayout::Emmc => 0x800,
            _                => 0x1000,
        };
        let target_smc_offset = if smc_len > 0 { 0x4000 - smc_len } else { smc_default_offset };
        
        // 2. Bootloaders start at 0x8000
        let bootchain_start = 0x8000;
        let mut curr_bl = bootchain_start;
        let mut bl_stages = Vec::new();
        if let Some(cb) = &self.bootloaders.cb { bl_stages.push(("CB", cb.serialize())); }
        if let Some(cba) = &self.bootloaders.cb_a { bl_stages.push(("CB_A", cba.serialize())); }
        if let Some(cbx) = &self.bootloaders.cb_x { bl_stages.push(("CB_X", cbx.serialize())); }
        if let Some(cbb) = &self.bootloaders.cb_b { bl_stages.push(("CB_B", cbb.serialize())); }
        if let Some(sc) = &self.bootloaders.sc { bl_stages.push(("SC", sc.serialize())); }
        if let Some(cd) = &self.bootloaders.cd { bl_stages.push(("CD", cd.serialize())); }
        if let Some(ce) = &self.bootloaders.ce { bl_stages.push(("CE", ce.serialize())); }

        for (i, (name, mut data)) in bl_stages.into_iter().enumerate() {
            // Read header to get declared size
            let declared_size = if data.len() >= 16 {
                let h = BootloaderHeader::read_from_prefix(&data).map(|(h,_)| h.size.get()).unwrap_or(0);
                h as usize
            } else { 0 };

            let aligned_declared = (declared_size + 0xF) & !0xF;
            if aligned_declared > 0 && data.len() != aligned_declared {
                warn!("[builder] {} length mismatch: data is 0x{:X}, header says 0x{:X} (aligned 0x{:X}). Adjusting...", 
                    name, data.len(), declared_size, aligned_declared);
                data.resize(aligned_declared, 0);
            }

            if curr_bl + data.len() > logical_image.len() {
                return Err(format!("Bootchain stage {} ({}) overflow at 0x{:X}", i, name, curr_bl));
            }
            info!("[builder] Serializing {} at 0x{:08X} (0x{:X} bytes)", name, curr_bl, data.len());
            logical_image[curr_bl..curr_bl+data.len()].copy_from_slice(&data);
            curr_bl += data.len(); // already aligned via resize
        }

        // 3. CF/CG placement: Ensure safe gap after bootchain
        let forensic_cf_default = match layout {
            NandLayout::Bb => 0x80000,
            NandLayout::Emmc => 0xB0000,
            _ => 0x70000,
        };

        // If the bootchain has realigned/extended into the CF area, shift CF to the next 64KB block
        let target_cf_offset = if curr_bl > forensic_cf_default {
            (curr_bl + 0xFFFF) & 0xFFFF0000
        } else {
            forensic_cf_default
        };

        // Update header with the realigned offsets
        header.smc_boot_offset.set(target_smc_offset as u32);
        header.smc_boot_size.set(smc_len as u32);
        header.cf_offset.set(target_cf_offset as u32);
        header.kv_addr.set(0x4000); // Enforce Block 1 KV

        // User-provided SMC Config offsets
        let smc_config_offset = match layout {
            NandLayout::Emmc => 0x2FFC000,
            _ => 0xF7C000,
        };
        header.smc_config_offset.set(smc_config_offset as u32);

        // FlashFS Address: Logical byte address of the root block
        if !self.flashfs.root.entries.is_empty() && self.flashfs.root.block_number >= 0 {
            let fs_logical_addr = (self.flashfs.root.block_number as u32) * (layout.logical_pages_per_block() as u32) * 0x200;
            header.fs_addr.set(fs_logical_addr);
            info!("[builder] Updated FlashFS root address in header: 0x{:08X} (Block {})", fs_logical_addr, self.flashfs.root.block_number);
        }

        // Actually place components into the image
        let kv_offset = header.kv_addr.get() as usize;
        if !self.extra.smc.is_empty() {
            logical_image[target_smc_offset..target_smc_offset + smc_len].copy_from_slice(&self.extra.smc);
        }
        if !self.extra.keyvault.is_empty() {
            logical_image[kv_offset..kv_offset + self.extra.keyvault.len()].copy_from_slice(&self.extra.keyvault);
        }

        let cf0 = self.update.cf_0.as_ref().map(|b| b.serialize());
        let cg0 = self.update.cg_0.as_ref().map(|b| b.serialize());
        let cf1 = self.update.cf_1.as_ref().map(|b| b.serialize()).or_else(|| cf0.clone());
        let cg1 = self.update.cg_1.as_ref().map(|b| b.serialize()).or_else(|| cg0.clone());

        if let Some(cf0d) = cf0 {
            let cf0_offset = target_cf_offset;
            let cf1_offset = cf0_offset + 0x10000; // 64KB gap between CF_0 and CF_1
            
            header.patch_slots.set(if cf1.is_some() { 2 } else { 1 });

            if cf0_offset + cf0d.len() > logical_image.len() {
                return Err(format!("CF0 overflow at 0x{:X}: need 0x{:X} bytes", cf0_offset, cf0d.len()));
            }
            logical_image[cf0_offset..cf0_offset+cf0d.len()].copy_from_slice(&cf0d);
            if let Some(cg0d) = cg0 {
                // 16-byte align CG after CF - parser advances by (size + 0xF) & !0xF between loaders
                let cg0_offset = (cf0_offset + cf0d.len() + 0xF) & !0xF;
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
                    // 16-byte align CG after CF - parser advances by (size + 0xF) & !0xF between loaders
                    let cg1_offset = (cf1_offset + cf1d.len() + 0xF) & !0xF;
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
                error!("[builder] FlashFS block {} (offset 0x{:X}) exceeds image bounds", fs_block, fs_offset);
            }
        }

        Ok(logical_image)
    }

    pub fn build(&self, cpukey: [u8; 16]) -> Result<Vec<u8>, String> {
        let mut skel = self.clone();
        info!("[builder] Starting final image build...");
        let mut kv = crate::builder::chain::kv::Keyvault::parse(&skel.extra.keyvault)?;
        info!("[builder] Encrypting Keyvault...");
        let hashed = skel.header.kv_version.get() >= 2;
        kv.encrypt(&cpukey, hashed)?;
        skel.extra.keyvault = kv.data;

        let mut smc = crate::builder::chain::smc::RawSmc::new(skel.extra.smc.clone());
        info!("[builder] Re-encrypting bootloader chain...");
        encrypt_chain(
            skel.bootloaders.cb_a.as_mut().or(skel.bootloaders.cb.as_mut()).ok_or("Missing primary CB (CB or CB_A) for encryption")?,
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
        info!("[builder] Re-encrypting SMC...");
        smc.encrypt();
        skel.extra.smc = smc.data;
        skel.assemble_logical()
    }

    /// Appplies a GXP or legacy patchset to the relevant sections of this NAND skeleton.
    pub fn apply_patch(&mut self, patch: GxpBinary) -> Result<(), String> {
        if let Some(khv) = patch.khv {
            info!("[builder] Routing {} KHV patch records to options slot...", khv.records.len());
            self.bootloaders.khvpatch = Some(khv.records.iter().map(|r| PatchRecord {
                address: r.address,
                amount: r.amount,
                data: r.data.clone(),
            }).collect());
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
            // CB_A always accompanies CB_B (Split / Glitch3 layouts).
            // CB_A-only is not a valid layout - checking cb_b.is_some() covers both cases.
            if matches!(patch.header.patch_type, GxpPatchType::Jtag4Section | GxpPatchType::Jtag5Section | GxpPatchType::Rgh3Section) {
                if let Some(cbb_bl) = &mut self.bootloaders.cb_b {
                    // Split or Glitch3 layout: patch always targets CB_B
                    info!("[builder] Split/Glitch3 CB: Applying primary patch section to CB_B");
                    apply_records(&cb.records, &mut cbb_bl.data).map_err(|e| e.to_string())?;
                } else if let Some(cb_bl) = &mut self.bootloaders.cb {
                    // Single layout: patch targets bare CB
                    info!("[builder] Single CB: Applying patches to CB");
                    apply_records(&cb.records, &mut cb_bl.data).map_err(|e| e.to_string())?;
                }
            }
        }

        if let Some(cd) = patch.cd {
            if let Some(cd_bl) = &mut self.bootloaders.cd {
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
        assert_eq!(skeleton.header.smc_boot_offset.get(), 0x800);   // eMMC: 0x4000 - 0x3800
        assert_eq!(skeleton.header.smc_boot_size.get(), 0x3800);    // eMMC SMC is 0x3800 bytes
        assert_eq!(skeleton.header.smc_config_offset.get(), 0x0);   // eMMC header field is 0x0
        assert_eq!(skeleton.header.fs_addr.get(), 0x10000);          // FileSystemAddress
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

        skeleton.bootloaders.cd = Some(crate::builder::chain::cd::BootloaderCd {
            header: bl_header,
            data: large_cd,
            metadata: None,
        });

        let logical = skeleton.assemble_logical().unwrap();
        let header = NandHeader::read_from_prefix(&logical).unwrap().0;
        
        // Expected realignment to next 64KB block: (0x71000 + 0xFFFF) & 0xFFFF0000 = 0x80000
        assert_eq!(header.cf_offset.get(), 0x80000);
    }
}
