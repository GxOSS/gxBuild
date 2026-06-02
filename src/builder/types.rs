use crate::core::images::blocks::{LbaMap, NandLayout};
use zerocopy::byteorder::{BigEndian, I16, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const NAND_RETAIL_1BL_KEY: [u8; 16] = [
    0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA,
];

pub struct BlDiscovery {
    pub magic: String,
    pub version: u16,
    pub size: u32,
    pub key_source: String,
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
        PayloadList {
            entries: Vec::new(),
        }
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

impl NandHeader {
    pub const MAGIC: u16 = 0xFF4F;
    const XEBUILD_FLAG_OFFSET: usize = 0x3B;
    const XEBUILD_DUALBOOT_OFFSET: usize = 0x3C;
    const XEBUILD_UART_OFFSET: usize = 0x3D;
    const XEBUILD_XELL_ALT_POC_OFFSET: usize = 0x3E;
    const XEBUILD_XELL_POC_OFFSET: usize = 0x3F;

    pub fn validate(&self) -> Result<(), crate::builder::parser::BuilderError> {
        if self.prefix.magic.get() != Self::MAGIC {
            return Err(crate::builder::parser::BuilderError::InvalidMagic {
                magic: self.prefix.magic.get(),
            });
        }
        Ok(())
    }

    pub fn cb_offset(&self) -> u32 {
        self.prefix.entrypoint.get()
    }

    /*
    pub fn print_info(&self) {
        info!(
            "[builder] NAND magic:       0x{:04X}",
            self.prefix.magic.get()
        );
        info!("[builder] NAND build:       {}", self.prefix.version.get());
        info!("[builder] CB offset:        0x{:X}", self.cb_offset());
        info!("[builder] CF offset:        0x{:X}", self.cf_offset.get());
        let copyright = String::from_utf8_lossy(&self.copyright);
        info!(
            "[builder] Copyright:        {}",
            copyright.trim_matches(char::from(0))
        );
        info!("[builder] KV offset:        0x{:X}", self.kv_addr.get());
        info!("[builder] KV size:          0x{:X}", self.kv_size.get());
        info!(
            "[builder] SMC boot size:    0x{:X}",
            self.smc_boot_size.get()
        );
        info!(
            "[builder] SMC boot offset:  0x{:X}",
            self.smc_boot_offset.get()
        );
    }
    */
    pub fn apply_xebuild_header_flags(&mut self, options: &BuildOptions) {
        let profile = options.image_profile.as_str();
        let is_devkit = profile == "devkit" || matches!(options.build_mode, BuildMode::Devkit);
        let is_retail = profile == "retail";
        let is_hacked = profile == "jtag"
            || profile == "devgl"
            || profile == "xdkbuild"
            || profile.contains("glitch");

        if is_retail || is_devkit {
            self.copyright[Self::XEBUILD_FLAG_OFFSET] = 0;
            return;
        }

        if is_hacked {
            self.copyright[Self::XEBUILD_FLAG_OFFSET] = 1;

            /*
            let alt = extra.power_on_cause_a;
            let primary = extra.power_on_cause_b;

            self.copyright[Self::XEBUILD_XELL_ALT_POC_OFFSET] = if alt != 0 { alt } else { 0x00 };
            self.copyright[Self::XEBUILD_XELL_POC_OFFSET] =
                if primary != 0 { primary } else { 0x12 };

            if options.demon {
                self.copyright[Self::XEBUILD_UART_OFFSET] = 2;
            } else if options.cygnos {
                self.copyright[Self::XEBUILD_UART_OFFSET] = 1;
            }
            */
            let _ = Self::XEBUILD_DUALBOOT_OFFSET;
        }
    }
}

#[derive(Clone)]
pub struct NandBootloaders {
    pub cb: Option<crate::builder::chain::cb::BootloaderCb>,
    pub cb_a: Option<crate::builder::chain::cb::BootloaderCb>,
    pub cb_x: Option<crate::builder::chain::cb::BootloaderCb>,
    pub cb_b: Option<crate::builder::chain::cb::BootloaderCb>,
    pub sc: Option<crate::builder::chain::sc::BootloaderSc>,
    pub cd: Option<crate::builder::chain::cd::BootloaderCd>,
    pub ce: Option<crate::builder::chain::ce::BootloaderCe>,
    //  pub khvpatch: Option<Vec<PatchRecord>>,
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
        //      self.khvpatch = None;
        self.xell = None;
    }
}

impl Default for NandBootloaders {
    fn default() -> Self {
        NandBootloaders {
            cb: None,
            cb_a: None,
            cb_x: None,
            cb_b: None,
            sc: None,
            cd: None,
            ce: None,
            //          khvpatch: None,
            xell: None,
        }
    }
}

#[derive(Clone)]
pub struct NandUpdate {
    pub cf_0: Option<crate::builder::chain::cf::BootloaderCf>,
    pub cg_0: Option<crate::builder::chain::cg::BootloaderCg>,
    pub cf_1: Option<crate::builder::chain::cf::BootloaderCf>,
    pub cg_1: Option<crate::builder::chain::cg::BootloaderCg>,
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
        NandUpdate {
            cf_0: None,
            cg_0: None,
            cf_1: None,
            cg_1: None,
        }
    }
}

#[derive(Clone, Default)]
pub struct NandExtra {
    pub smc: Vec<u8>,
    pub smc_metadata: Option<crate::builder::chain::smc::SmcMetadata>,
    pub smc_config: Vec<u8>,
    pub keyvault: Vec<u8>,
    pub fcrt: Option<Vec<u8>>,
    //  pub power_on_cause_a: u8,
    //  pub power_on_cause_b: u8,
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
            MotherboardType::Xenon | MotherboardType::Zephyr | MotherboardType::Falcon => {
                SouthbridgeType::Xsb
            }
            MotherboardType::Jasper | MotherboardType::Trinity => SouthbridgeType::Psb,
            MotherboardType::Corona | MotherboardType::Winchester => SouthbridgeType::Ksb,
            MotherboardType::Unknown => SouthbridgeType::Unknown,
        }
    }
}

pub fn layout_calculator(
    sb: SouthbridgeType,
    image_profile: &str,
    layout: NandLayout,
) -> (u32, u32, u32) {
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
        "split" | "devgl" | "devkit" | "xdkbuild" | "glitch2m" | "glitch2" | "glitch3" => true,
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
    pub khv_header_size: u32,
    pub gxunsafe: bool,
    pub verbose: bool,
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
            khv_header_size: 0x4000,
            gxunsafe: false,
            verbose: false,
        }
    }
}
