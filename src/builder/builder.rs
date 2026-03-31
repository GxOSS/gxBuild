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
use crate::deps::excrypt::{
    ExCryptBnQwBeSigVerify, ExCryptHmacSha, ExCryptRc4Ecb, ExCryptRc4Key, ExCryptRc4State,
    ExCryptRotSumSha, ExCryptRsa, ExCryptSig,
};
use zerocopy::{AsBytes, FromBytes, byteorder::big_endian};

use crate::builder::tools::blocks::*;
use crate::builder::chain::*;

/// Xbox 360 NAND header — matches xenon-bltool's `xenon_nand_header` layout.
/// The first field is a `BootloaderHeader` whose `entrypoint` points to CB.
#[derive(FromBytes, AsBytes, Clone)]
#[repr(C)]
pub struct NandHeader {
    pub header: BootloaderHeader,       // magic 0xFF4F, entrypoint -> CB offset
    pub copyright: [u8; 0x40],
    pub unused: [u8; 0x10],
    pub kv_size: u32<big_endian>,
    pub cf_offset: u32<big_endian>,
    pub patch_slots: i16<big_endian>,
    pub kv_version: u16<big_endian>,
    pub kv_addr: u32<big_endian>,
    pub patch_size: u32<big_endian>,
    pub smc_config_offset: u32<big_endian>,
    pub smc_boot_size: u32<big_endian>,
    pub smc_boot_offset: u32<big_endian>,
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
use crate::builder::chain::cd::BootloaderCd;
use crate::builder::chain::ce::BootloaderCe;
use crate::builder::chain::cf::BootloaderCf;
use crate::builder::chain::cg::BootloaderCg;

// Bootchain will be interpreted from provided bootloaders
pub struct NandBootloaders {
    pub cb: Option<BootloaderCb>,
    pub cb_a: Option<BootloaderCb>,
    pub cb_b: Option<BootloaderCb>,
    pub cd: Option<BootloaderCd>,
    pub ce: Option<BootloaderCe>,
    pub sb: Option<Vec<u8>>,
    pub sc: Option<Vec<u8>>,
    pub sd: Option<Vec<u8>>,
    pub se: Option<Vec<u8>>,
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
    smc: Vec<u8>,
    smc_config: Vec<u8>,
    keyvault: Vec<u8>,
    fcrt: Option<Vec<u8>>,
}

pub struct NandPatches {
    rglp: Option<Vec<u8>>,
    xebuild: Option<Vec<u8>>,
}

pub enum MotherboardType {
    Xenon,
    Zephyr,
    Falcon,
    Jasper,
    Trinity,
    Corona,
    Winchester,
}

pub enum ImageType { // Base image type
    Single, // CB -> CD
    Split, // CB_A -> CB_B -> CD
    Devkit, // SB -> SC -> SD
}

pub enum BuildType { // Custom images
    Retail, // Regular secure image
    Jtag, // Some sort of rebooting shit where theres like a double boot chain? fml
    Glitch, // Patches somewhere after CE
    Conversion, // Load dev kernel on glitch or glitch kernel on dev
}

pub struct BuildOptions {
    layout: NandLayout,
    image_type: ImageType,
    build_type: BuildType,
    motherboard: MotherboardType,
    bigonsmall: bool = false, // Usually false, For RGL/ XDKB systems with nandfs on hdd
    shadowboot: bool = false, // Toggle shadowboot image creation
    mfg: bool = false,
    patches: Option<NandPatches>,
}

pub struct BlockMap // (?)

pub struct NandSkeleton {
    pub cpukey: Option<String>,
    pub image: Vec<u8>,
    pub blockmap: Option<Blockmap>,
    pub options: BuildOptions,
    pub header: NandHeader,
    pub extra: NandExtra,
    pub bootloaders: NandBootloaders,
    pub update: NandUpdate,
    pub flashfs: FlashFS,
}

impl NandSkeleton {
    pub fn new(nandimg: AsRef<Path>, cpukey: Option<String>) -> Result<Self, String> {
        // Read image
        // Check block type
        // Check bad blocks
        // Mark in block map
        // Get data and output to NandHeader
        // Remove spare data
        // Extract to Bootloader structs and NandBootloaders struct
        // Extract to NandUpdate and NandExtra
        // Extract to FlashFS struct
        // Run decryption chain(s)
        // Read detailed info
        // Populate ImageType, BuildType, and BuildOptions
        // Build NandSkeleton
    }
    pub fn build() -> Result<Vec<u8>, String> {
        // Read NandSkeleton
        // Rehash and resign (?)
        // Run encryption chain
        // Construct final image
        // Inject patches
        // Calculate ECC and inject
        // Remap bad blocks from blockmap

    }
}