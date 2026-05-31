/*
  session.rs - Session management and command queue

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

use crate::builder::builder::NandSkeleton;
use crate::core::data::filesearch::IniSearch;
use log::{error, info, warn};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("[session] IO error: {0}")]
    Io(String),

    #[error("[session] Failed to parse options INI: {0}")]
    OptionsIniParse(String),

    #[error("[session] Failed to parse INI: {0}")]
    IniParse(String),

    #[error("[session] INI discovery failed: {0}")]
    IniDiscovery(String),

    #[error("[session] Failed to apply INI data: {0}")]
    IniApply(String),

    #[error("[session] prepare_build: build_type not set")]
    BuildTypeNotSet,

    #[error("[session] prepare_build: console_type not set")]
    ConsoleTypeNotSet,

    #[error("[session] prepare_build: cannot read INI at {path:?}")]
    IniRead { path: PathBuf },

    #[error("[session] SMC autopatching failed ({error}): {path:?}")]
    SmcAutopatch { error: String, path: PathBuf },

    #[error("[session] SMC config error: {0}")]
    SmcConfig(String),

    #[error("[session] Keyvault error: {0}")]
    Keyvault(String),

    #[error("[session] Invalid hex u8 '{value}': {error}")]
    InvalidHexU8 { value: String, error: String },

    #[error("[session] Invalid decimal u8 '{value}': {error}")]
    InvalidDecimalU8 { value: String, error: String },

    #[error("[session] Invalid hex u16 '{value}': {error}")]
    InvalidHexU16 { value: String, error: String },

    #[error("[session] Invalid decimal u16 '{value}': {error}")]
    InvalidDecimalU16 { value: String, error: String },

    #[error("[session] No active NAND loaded to patch")]
    NoActiveNand,

    #[error("[session] {0}")]
    Other(String),
}

impl From<String> for SessionError {
    fn from(s: String) -> Self {
        SessionError::Other(s)
    }
}

impl From<io::Error> for SessionError {
    fn from(e: io::Error) -> Self {
        SessionError::Io(e.to_string())
    }
}

#[derive(Debug)]
pub enum InternalCommand {
    ParseIni {
        path: PathBuf,
        target: String,
        ini_base: PathBuf,
        common: PathBuf,
        data: PathBuf,
        payloads: PathBuf,
        smc: PathBuf,
    },
    ParseImage {
        path: PathBuf,
        key: Option<[u8; 16]>,
    },
    ParseKey {
        key: [u8; 16],
    },
    ParseKeybin {
        key: Option<[u8; 16]>,
    },
    ParseFlashfs {
        path: PathBuf,
    },
    ParsePatch {
        path: PathBuf,
    },
    ApplyPatch {
        path: PathBuf,
        ptype: u8,
        target: Option<u8>,
    },
    ApplyEcc {
        path: PathBuf,
    },
    ExtractAll {
        output_dir: PathBuf,
        all: bool,
        include_decrypted: bool,
    },
    Replace {
        id: u8,
        path: PathBuf,
    },
    List,
    Delete {
        id: u8,
    },
    Clear,
    Compress,
    // Decompress,
    Update {
        path: PathBuf,
    },
    Build {
        output: PathBuf,
        target: u8,
    },
    FinalizeFlashfs,
    FinalizeMobile,
    SessionInit {
        base: Option<PathBuf>,
        common: Option<PathBuf>,
    },
    SessionList,
    SessionDelete {
        id: u8,
    },
    SessionRun,
    CreateImage {
        layout: crate::core::images::blocks::NandLayout,
    },
    ExtractStfs {
        path: PathBuf,
        target_dir: PathBuf,
    },
    SwapBootloader {
        bl_type: String,
        path: PathBuf,
        is_rebooter: bool,
    },
    ApplyOptions,
    ApplySmcSignature {
        json: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::chain::cb::{BootloaderCb, CbMetadata};
    use crate::builder::chain::cf::{BootloaderCf, CfMetadata};
    use crate::builder::chain::BootloaderHeader;
    use crate::core::images::blocks::NandLayout;
    use zerocopy::byteorder::{U16, U32};

    fn test_header(magic: u16, size: u32) -> BootloaderHeader {
        BootloaderHeader {
            magic: U16::new(magic),
            version: U16::new(0),
            pairing: U16::new(0),
            flags: U16::new(0),
            entrypoint: U32::new(0),
            size: U32::new(size),
        }
    }

    fn test_cb(pairing: [u8; 3], ldv: u8) -> BootloaderCb {
        BootloaderCb {
            header: test_header(0x4342, 0x3C0),
            data: vec![0; 0x3B0],
            derived_key: None,
            metadata: Some(CbMetadata {
                b_flags: 0,
                pairing_data: pairing,
                lockdown_value: ldv,
                reserved_per_box: [0; 0xC],
                per_box_digest: [0; 0x10],
                signature: [0; 0x100],
                rsa_pub_key: [0; 0x110],
                nonce_3bl: [0; 0x10],
                salt_3bl: [0; 0xA],
                salt_4bl: [0; 0xA],
                digest_4bl: [0; 0x14],
                post_output_addr: 0,
                sb_flash_addr: 0,
                soc_mmio_addr: 0,
                console_allow: [0; 4],
            }),
        }
    }

    fn test_cf(pairing: [u8; 3], ldv: u8) -> BootloaderCf {
        BootloaderCf {
            header: test_header(0x4346, 0x354),
            data: vec![0; 0x344],
            metadata: Some(CfMetadata {
                source_version: 0,
                target_version: 0,
                reserved_prefix: 0,
                cg_size: 0,
                hmac_salt: [0; 16],
                cg_blocks_used: 0,
                cg_block_numbers: vec![0; 223],
                reserved_per_box: [0; 0x2B],
                update_slot: 0,
                pairing_data: pairing,
                lockdown_value: ldv,
                per_box_digest: [0; 0x10],
                signature: [0; 0x100],
                cg_nonce: [0; 0x10],
                cg_digest: [0; 0x14],
            }),
        }
    }

    #[test]
    fn sync_per_box_settings_cb_and_cf_ldv_are_independent() {
        let session = Session::new();
        let mut nand = NandSkeleton::new_blank(NandLayout::Sb);

        // CB has ldv=7, CF has ldv=2 they must NOT bleed into each other
        nand.bootloaders.cb_a = Some(test_cb([0x12, 0x34, 0x56], 7));
        nand.update.cf_0 = Some(test_cf([0xAA, 0xBB, 0xCC], 2));

        let pairing = Session::resolve_pairing(&session.options, &nand);
        let cb_ldv = Session::resolve_cb_ldv(&session.options, &nand).unwrap();
        let cf_ldv = Session::resolve_cf_ldv(&session.options, &nand).unwrap();
        Session::sync_per_box_settings(&mut nand, pairing, cb_ldv, cf_ldv);

        let cb_meta = nand
            .bootloaders
            .cb_a
            .as_ref()
            .unwrap()
            .metadata
            .as_ref()
            .unwrap();
        let cf_meta = nand
            .update
            .cf_0
            .as_ref()
            .unwrap()
            .metadata
            .as_ref()
            .unwrap();

        assert_eq!(cb_meta.pairing_data, [0x12, 0x34, 0x56]);
        assert_eq!(cb_meta.lockdown_value, 7);

        assert_eq!(cf_meta.pairing_data, [0x12, 0x34, 0x56]);
        assert_eq!(cf_meta.lockdown_value, 2);
    }

    #[test]
    fn test_nofcrt_option_handling() {
        let mut session = Session::new();
        // 1. Verify Default state
        assert_eq!(session.options.nofcrt, None);

        // 2. Set "nofcrt" option
        session.set_option("nofcrt", "true");
        assert_eq!(session.options.nofcrt, Some(true));

        // 3. Test merging options
        let mut other_opt = crate::core::data::optini::OptionsIni::new();
        other_opt.nofcrt = Some(false);
        session.options.merge(other_opt);
        assert_eq!(session.options.nofcrt, Some(false));
    }

    #[test]
    fn finalize_flashfs_resets_empty_source_map() {
        let mut session = Session::new();
        let mut nand = NandSkeleton::new_blank(NandLayout::Sb);
        nand.flashfs.root.block_number = 1000;
        nand.flashfs.root.block_map = vec![0x1FFB; 1024];
        for block in 1000..1024 {
            nand.flashfs.root.block_map[block] = 0x1FFE;
        }
        session.active_nand = Some(nand);

        session.run_once(InternalCommand::FinalizeFlashfs).unwrap();

        let root = &session.active_nand.as_ref().unwrap().flashfs.root;
        assert_eq!(root.block_number, 0x4E);
        assert_eq!(root.block_map[0x4E], 0x1FFF);
        assert_eq!(root.block_map[0], 0x1FFB);
        assert_eq!(root.block_map[4], 0x1FFB);
    }
}

impl InternalCommand {
    pub(crate) fn priority_score(&self) -> u8 {
        match self {
            Self::ParseKey { .. } => 160,
            Self::ParseKeybin { .. } => 160,
            Self::ParseImage { .. } => 150,
            Self::CreateImage { .. } => 150,
            Self::ApplyEcc { .. } => 149,
            Self::ExtractStfs { .. } => 110,
            Self::Update { .. } => 110,
            Self::SessionInit { .. } => 100,
            Self::SessionList => 100,
            Self::SessionDelete { .. } => 100,
            Self::ParseIni { .. } => 100,
            Self::ParseFlashfs { .. } => 100,
            Self::ParsePatch { .. } => 100,
            // Self::Decompress => 99,
            Self::FinalizeFlashfs => 90,
            Self::FinalizeMobile => 89,
            Self::ExtractAll { .. } => 88,
            Self::Replace { .. } => 87,
            Self::List => 86,
            Self::Delete { .. } => 85,
            Self::Clear => 84,
            Self::ApplyPatch { .. } => 79,
            Self::ApplySmcSignature { .. } => 79,
            Self::Compress => 78,
            Self::SessionRun => 50,
            Self::Build { .. } => 0,
            Self::SwapBootloader { .. } => 140,
            Self::ApplyOptions => 80,
        }
    }
}

#[derive(Debug)]
pub struct QueuedCommand {
    pub(crate) sequence_id: usize,
    pub(crate) command: InternalCommand,
}

impl Ord for QueuedCommand {
    fn cmp(&self, other: &Self) -> Ordering {
        let p_cmp = self
            .command
            .priority_score()
            .cmp(&other.command.priority_score());
        if p_cmp != Ordering::Equal {
            return p_cmp;
        }
        // tie breaker based on when queued from id
        other.sequence_id.cmp(&self.sequence_id)
    }
}

impl PartialOrd for QueuedCommand {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for QueuedCommand {
    fn eq(&self, other: &Self) -> bool {
        self.command.priority_score() == other.command.priority_score()
            && self.sequence_id == other.sequence_id
    }
}

impl Eq for QueuedCommand {}

pub struct Session {
    pub(crate) queue: BinaryHeap<QueuedCommand>,
    next_seq_id: usize,
    // Legacy single-asset pool used by the Update command
    pub pending_assets: HashMap<String, Vec<u8>>,
    pub bootloader_assets: HashMap<String, Vec<u8>>,
    pub security_assets: HashMap<String, Vec<u8>>,
    pub flashfs_assets: HashMap<String, Vec<u8>>,
    pub flashfs_allowlist: Option<std::collections::HashSet<String>>,
    pub active_nand: Option<NandSkeleton>,
    pub options: crate::core::data::optini::OptionsIni,
    pub pending_key: Option<[u8; 16]>,
    // Last error message for FFI reporting
    pub last_error: Option<String>,

    // Build config
    pub build_type: Option<String>,
    pub console_type: Option<String>,
    pub ini_dir: Option<std::path::PathBuf>,
    pub common_dir: Option<std::path::PathBuf>,
    pub data_dir: Option<std::path::PathBuf>,
    pub output_path: Option<std::path::PathBuf>,
    pub ini_ext: Option<String>,
    pub bl_ext: Option<String>,
    pub addons: Vec<String>,
    pub build_ini_loaded: bool,
}

impl Session {
    fn fallback_pairing_data() -> [u8; 3] {
        [0, 0, 1]
    }

    fn fallback_lockdown_value() -> u8 {
        1
    }

    /// Resolves the pairing data: CB-priority, CF fallback, then [0,0,1].
    fn resolve_pairing(
        _options: &crate::core::data::optini::OptionsIni,
        nand: &NandSkeleton,
    ) -> [u8; 3] {
        nand.bootloaders
            .cb_a
            .as_ref()
            .or(nand.bootloaders.cb.as_ref())
            .and_then(|cb| cb.metadata.as_ref().map(|meta| meta.pairing_data))
            .or_else(|| {
                nand.update
                    .cf_0
                    .as_ref()
                    .and_then(|cf| cf.metadata.as_ref().map(|meta| meta.pairing_data))
            })
            .filter(|p| *p != [0, 0, 0])
            .unwrap_or_else(Self::fallback_pairing_data)
    }

    fn resolve_cb_ldv(
        _options: &crate::core::data::optini::OptionsIni,
        nand: &NandSkeleton,
    ) -> Result<u8, SessionError> {
        let from_nand = nand
            .bootloaders
            .cb_a
            .as_ref()
            .or(nand.bootloaders.cb.as_ref())
            .and_then(|cb| cb.metadata.as_ref().map(|meta| meta.lockdown_value))
            .filter(|v| *v != 0);

        Ok(from_nand.unwrap_or_else(Self::fallback_lockdown_value))
    }

    fn resolve_cf_ldv(
        options: &crate::core::data::optini::OptionsIni,
        nand: &NandSkeleton,
    ) -> Result<u8, SessionError> {
        if let Some(cfldv_option) = &options.cfldv {
            return Self::parse_u8_hex_or_dec(cfldv_option);
        }

        let from_nand = nand
            .update
            .cf_0
            .as_ref()
            .and_then(|cf| cf.metadata.as_ref().map(|meta| meta.lockdown_value))
            .filter(|v| *v != 0);

        Ok(from_nand.unwrap_or_else(Self::fallback_lockdown_value))
    }

    fn sync_per_box_settings(nand: &mut NandSkeleton, pairing: [u8; 3], cb_ldv: u8, cf_ldv: u8) {
        if let Some(ref mut cb) = nand.bootloaders.cb {
            if let Some(ref mut meta) = cb.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = cb_ldv;
                cb.sync_metadata();
            }
        }

        if let Some(ref mut cb) = nand.bootloaders.cb_a {
            if let Some(ref mut meta) = cb.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = cb_ldv;
                cb.sync_metadata();
            }
        }

        if let Some(ref mut cb) = nand.bootloaders.cb_b {
            if let Some(ref mut meta) = cb.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = cb_ldv;
                cb.sync_metadata();
            }
        }

        if let Some(ref mut cf) = nand.update.cf_0 {
            if let Some(ref mut meta) = cf.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = cf_ldv;
                cf.sync_metadata();
            } else {
                if cf.data.len() > 0x20E {
                    cf.data[0x20C..0x20F].copy_from_slice(&pairing);
                }
                if cf.data.len() > 0x20F {
                    cf.data[0x20F] = cf_ldv;
                }
            }
        }

        if let Some(ref mut cf) = nand.update.cf_1 {
            if let Some(ref mut meta) = cf.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = cf_ldv;
                cf.sync_metadata();
            } else {
                if cf.data.len() > 0x20E {
                    cf.data[0x20C..0x20F].copy_from_slice(&pairing);
                }
                if cf.data.len() > 0x20F {
                    cf.data[0x20F] = cf_ldv;
                }
            }
        }
    }

    pub fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
            next_seq_id: 0,
            pending_assets: HashMap::new(),
            bootloader_assets: HashMap::new(),
            security_assets: HashMap::new(),
            flashfs_assets: HashMap::new(),
            flashfs_allowlist: None,
            active_nand: None,
            options: crate::core::data::optini::OptionsIni::new(),
            pending_key: None,
            last_error: None,
            build_type: None,
            console_type: None,
            ini_dir: None,
            common_dir: None,
            data_dir: None,
            output_path: None,
            ini_ext: None,
            bl_ext: None,
            addons: Vec::new(),
            build_ini_loaded: false,
        }
    }

    pub fn enqueue(&mut self, command: InternalCommand) {
        self.queue.push(QueuedCommand {
            sequence_id: self.next_seq_id,
            command,
        });
        self.next_seq_id += 1;
    }

    pub fn extract_all(&mut self, output_dir: PathBuf, all: bool, include_decrypted: bool) {
        self.enqueue(InternalCommand::ExtractAll {
            output_dir,
            all,
            include_decrypted,
        });
    }

    pub fn build(&mut self, output: PathBuf, target: u8) {
        self.enqueue(InternalCommand::Build { output, target });
    }

    pub fn update(&mut self, path: PathBuf) {
        self.enqueue(InternalCommand::Update { path });
    }

    pub fn parse_image(&mut self, path: PathBuf, key: Option<[u8; 16]>) {
        self.enqueue(InternalCommand::ParseImage { path, key });
    }

    pub fn parse_key(&mut self, key: [u8; 16]) {
        self.enqueue(InternalCommand::ParseKey { key });
    }

    pub fn parse_keybin(&mut self, key: Option<[u8; 16]>) {
        self.enqueue(InternalCommand::ParseKeybin { key });
    }

    pub fn parse_flashfs(&mut self, path: PathBuf) {
        self.enqueue(InternalCommand::ParseFlashfs { path });
    }

    pub fn parse_patch(&mut self, path: PathBuf) {
        self.enqueue(InternalCommand::ParsePatch { path });
    }

    pub fn apply_ecc(&mut self, path: PathBuf) {
        self.enqueue(InternalCommand::ApplyEcc { path });
    }

    pub fn apply_patch(&mut self, path: PathBuf, ptype: u8, target: Option<u8>) {
        self.enqueue(InternalCommand::ApplyPatch {
            path,
            ptype,
            target,
        });
    }

    pub fn replace(&mut self, id: u8, path: PathBuf) {
        self.enqueue(InternalCommand::Replace { id, path });
    }

    pub fn list(&mut self) {
        self.enqueue(InternalCommand::List);
    }

    pub fn delete(&mut self, id: u8) {
        self.enqueue(InternalCommand::Delete { id });
    }

    pub fn clear(&mut self) {
        self.enqueue(InternalCommand::Clear);
    }

    pub fn compress(&mut self) {
        self.enqueue(InternalCommand::Compress);
    }

    /*
    pub fn decompress(&mut self) {
        self.enqueue(InternalCommand::Decompress);
    }
    */

    pub fn session_init(&mut self, base: Option<PathBuf>, common: Option<PathBuf>) {
        self.enqueue(InternalCommand::SessionInit { base, common });
    }

    pub fn session_list(&mut self) {
        self.enqueue(InternalCommand::SessionList);
    }

    pub fn session_delete(&mut self, id: u8) {
        self.enqueue(InternalCommand::SessionDelete { id });
    }

    pub fn session_clear(&mut self) {
        self.queue.clear();
        self.active_nand = None;
        self.pending_assets.clear();
        self.bootloader_assets.clear();
        self.security_assets.clear();
        self.flashfs_assets.clear();
        self.next_seq_id = 0;
    }

    pub fn session_run(&mut self) {
        self.enqueue(InternalCommand::SessionRun);
    }

    pub fn set_build_type(&mut self, build_type: String) {
        self.build_type = Some(build_type);
    }

    pub fn set_console(&mut self, console: String) {
        self.console_type = Some(console.clone());
        self.options.ctype = Some(console);
    }

    pub fn set_ini_dir(&mut self, path: PathBuf) {
        self.ini_dir = Some(path);
    }

    pub fn set_common_dir(&mut self, path: PathBuf) {
        self.common_dir = Some(path);
    }

    pub fn set_data_dir(&mut self, path: PathBuf) {
        self.data_dir = Some(path);
    }

    pub fn set_output(&mut self, path: PathBuf) {
        self.output_path = Some(path);
    }

    pub fn set_ini_ext(&mut self, ext: String) {
        self.ini_ext = Some(ext);
    }

    pub fn set_bl_ext(&mut self, ext: String) {
        self.bl_ext = Some(ext);
    }

    pub fn add_addon(&mut self, addon: String) {
        self.addons.push(addon);
    }

    pub fn clear_addons(&mut self) {
        self.addons.clear();
    }

    /// Parses a 32-character hex CPU key string and enqueues a ParseKey command.
    pub fn set_cpukey(&mut self, key: String) {
        if let Ok(bytes) = crate::builder::builder::hex_to_bytes(&key) {
            if let Ok(arr) = bytes.try_into() {
                self.parse_key(arr);
            } else {
                error!("[session] CPU Key must be 32 hex chars / 16 bytes");
            }
        } else {
            error!("[session] Invalid formatting for CPU Key: {}", key);
        }
    }

    pub fn set_option(&mut self, key: &str, value: &str) {
        let mut o = crate::core::data::optini::OptionsIni::new();
        let v = value;
        let is_true = v.eq_ignore_ascii_case("true");
        match key.to_lowercase().as_str() {
            "region" | "avregion" => o.avregion = Some(v.to_string()),
            "gameregion" => o.gameregion = Some(v.to_string()),
            "dvdregion" => o.dvdregion = Some(v.to_string()),
            "unsafe" | "gxunsafe" => o.gxunsafe = Some(is_true),
            "verbose" => {
                o.verbose = Some(is_true);
                let _ = crate::core::logger::init_logger("build", is_true);
            }
            "cba" => o.cba = Some(v.to_string()),
            "cbb" => o.cbb = Some(v.to_string()),
            "nomobile" => o.nomobile = Some(is_true),
            "noremap" => o.noremap = Some(is_true),
            "nandmu" => o.nandmu = Some(is_true),
            "cputemp" => o.cputemp = Some(v.to_string()),
            "gputemp" => o.gputemp = Some(v.to_string()),
            "edramtemp" => o.edramtemp = Some(v.to_string()),
            "overcputemp" => o.overcputemp = Some(v.to_string()),
            "overgputemp" => o.overgputemp = Some(v.to_string()),
            "overedramtemp" => o.overedramtemp = Some(v.to_string()),
            "cpufan" => o.cpufan = Some(v.to_string()),
            "gpufan" => o.gpufan = Some(v.to_string()),
            "macid" | "mac" => o.macid = Some(v.to_string()),
            "dvdkey" => o.dvdkey = Some(v.to_string()),
            "cfldv" => o.cfldv = Some(v.to_string()),
            "serial" => o.serial = Some(v.to_string()),
            "consoleid" => o.consoleid = Some(v.to_string()),
            "osig" => o.osig = Some(v.to_string()),
            "mfdate" => o.mfdate = Some(v.to_string()),
            "fcrt" => o.fcrt = Some(is_true),
            "nofcrt" => o.nofcrt = Some(is_true),
            "xellbutton" => o.xellbutton = Some(v.to_string()),
            "xellbutton2" => o.xellbutton2 = Some(v.to_string()),
            "cygnos" => o.cygnos = Some(is_true),
            "demon" => o.demon = Some(is_true),
            "smcnoeject" => o.smcnoeject = Some(is_true),
            "smcnoblink" => o.smcnoblink = Some(is_true),
            "patchsmc" => o.patchsmc = Some(is_true),
            "olddvd" => o.olddvd = Some(is_true),
            "nodvd" => o.nodvd = Some(is_true),
            "dualboot" => o.dualboot = Some(is_true),
            "dualpatchslots" => o.dualpatchslots = Some(is_true),
            "nolog" => o.nolog = Some(is_true),
            "noinfo" => o.noinfo = Some(is_true),
            "noenter" => o.noenter = Some(is_true),
            "noecc" => o.noecc = Some(is_true),
            "nosecurity" => o.nosecurity = Some(is_true),
            "nosusecurity" => o.nosusecurity = Some(is_true),
            "nochainpatch" => o.nochainpatch = Some(is_true),
            _ => warn!("[session] set_option: unknown key '{}'", key),
        }
        self.options.merge(o);
    }

    pub fn load_options_ini(&mut self, content: &str) -> Result<(), SessionError> {
        match crate::core::data::optini::parse_options_ini(content) {
            Ok(new_opts) => {
                self.options.merge(new_opts);
                info!("[session] Merged options from INI content string.");
                Ok(())
            }
            Err(e) => Err(SessionError::OptionsIniParse(e.to_string())),
        }
    }

    pub fn load_ini(&mut self, content: &str, target: &str) -> Result<(), SessionError> {
        let is_verbose = self.options.verbose.unwrap_or(false);
        let _ = crate::core::logger::init_logger("build", is_verbose);

        info!(
            "[session] Loading build INI from string for target: {}",
            target
        );
        self.build_ini_loaded = true;

        let ini_dir = self.ini_dir.clone().unwrap_or_else(|| PathBuf::from("."));
        let common_dir = self
            .common_dir
            .clone()
            .unwrap_or_else(|| ini_dir.join("../common"));
        let data_dir = self
            .data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("mydata"));
        let payloads_dir = ini_dir.join("../payloads");
        let smc_dir = ini_dir.join("../smc");

        let hint = self.build_type.as_ref().map(|t| format!("_{}.ini", t));

        match crate::core::data::xeini::parse_xe_ini_str(content, target, hint.as_deref()) {
            Ok(ini) => match IniSearch::new(
                ini.clone(),
                &ini_dir,
                &common_dir,
                &data_dir,
                &payloads_dir,
                &smc_dir,
                &self.active_nand,
                self.options.gxunsafe,
                self.options.nofcrt,
                self.options.nosecurity,
                self.options.nosusecurity,
                self.options.nochainpatch,
            ) {
                Ok(search) => {
                    self.bootloader_assets
                        .extend(search.result.bootloader_assets);
                    self.security_assets.extend(search.result.security_assets);
                    self.flashfs_assets.extend(search.result.flashfs_assets);

                    // Security files that live in the FlashFS (not at fixed offsets).
                    for name in &[
                        "fcrt.bin",
                        "crl.bin",
                        "dae.bin",
                        "extended.bin",
                        "secdata.bin",
                        "odd.bin",
                    ] {
                        if let Some(data) = self.security_assets.get(*name).cloned() {
                            self.flashfs_assets.entry(name.to_string()).or_insert(data);
                        }
                    }

                    let nand = self.active_nand.take().unwrap_or_else(|| {
                        let console = self.console_type.clone().unwrap_or("Jasper".to_string());
                        let layout = match console.to_lowercase().as_str() {
                            "trinity" | "corona" | "winchester" => {
                                crate::core::images::blocks::NandLayout::Sb
                            }
                            _ => crate::core::images::blocks::NandLayout::Sb,
                        };
                        crate::builder::builder::NandSkeleton::new_blank(layout)
                    });

                    let pending = crate::core::data::xeini::PendingAssets {
                        bootloaders: &self.bootloader_assets,
                        security: &self.security_assets,
                    };
                    match crate::core::data::xeini::apply_xe_ini(nand, ini, pending) {
                        Ok(updated_nand) => {
                            self.active_nand = Some(updated_nand);
                            self.build_ini_loaded = true;
                            info!("[session] INI assets applied to NAND skeleton");
                        }
                        Err(e) => return Err(SessionError::IniApply(e.to_string())),
                    }
                    Ok(())
                }
                Err(e) => Err(SessionError::IniDiscovery(e.to_string())),
            },
            Err(e) => Err(SessionError::IniParse(e.to_string())),
        }
    }

    /// Loads an options.ini file from the specified path and merges it into the session options.
    pub fn load_options_ini_file(&mut self, path: impl AsRef<Path>) -> Result<(), SessionError> {
        let content = fs::read_to_string(path)?;
        self.load_options_ini(&content)
    }

    /// Resets queue and config for fresh build.
    pub fn reset_build(&mut self) {
        self.queue.clear();
        self.next_seq_id = 0;
        self.pending_assets.clear();
        self.bootloader_assets.clear();
        self.security_assets.clear();
        self.flashfs_assets.clear();
        self.addons.clear();
        self.options = crate::core::data::optini::OptionsIni::new();
        self.last_error = None;
        self.build_ini_loaded = false;
    }

    /// Resolves build configuration and enqueues assets.
    pub fn prepare_build(&mut self) -> Result<(), SessionError> {
        use std::collections::HashSet;

        let ini_dir = self.ini_dir.clone().unwrap_or_else(|| PathBuf::from("."));
        let data_dir = self
            .data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("mydata"));
        let common_dir = self
            .common_dir
            .clone()
            .unwrap_or_else(|| ini_dir.join("../common"));
        let payloads_dir = ini_dir.join("../payloads");
        let smc_dir = ini_dir.join("../smc");
        let output_path = self
            .output_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("updflash.bin"));

        // Load options.ini from the data dir FIRST, then merge user overrides
        let options_path = data_dir.join("options.ini");
        if options_path.exists() {
            if let Ok(content) = fs::read_to_string(&options_path) {
                match crate::core::data::optini::parse_options_ini(&content) {
                    Ok(disk_opts) => {
                        let user_opts = self.options.clone();
                        self.options = disk_opts;
                        self.options.merge(user_opts);
                    }
                    Err(e) => warn!(
                        "[session] prepare_build: failed to parse options.ini: {}",
                        e
                    ),
                }
            }
        }

        // Initialize or update logger level based on FINAL merged options
        let is_verbose = self.options.verbose.unwrap_or(false);
        let _ = crate::core::logger::init_logger("build", is_verbose);

        if let Some(nand) = &mut self.active_nand {
            nand.options.gxunsafe = self.options.gxunsafe.unwrap_or(false);
            nand.options.verbose = self.options.verbose.unwrap_or(false);
        }

        let build_type = self
            .build_type
            .clone()
            .ok_or(SessionError::BuildTypeNotSet)?;
        let console = self
            .console_type
            .clone()
            .ok_or(SessionError::ConsoleTypeNotSet)?;

        // Resolve INI filename: _<type>[_<ext>].ini
        let ini_suffix = self
            .ini_ext
            .as_ref()
            .map(|e| format!("_{}", e))
            .unwrap_or_default();
        let ini_filename = format!("_{}{}.ini", build_type, ini_suffix);
        let ini_path = ini_dir.join(&ini_filename);

        // Console section, e.g. "trinity" or "trinity_ext"
        let console_section = match &self.bl_ext {
            Some(ext) => format!("{}_{}", console, ext),
            None => console.clone(),
        };

        // Pre-parse INI to know which asset filenames we need
        let mut target_filenames: HashSet<String> = HashSet::new();
        if !self.build_ini_loaded {
            match crate::core::data::xeini::parse_xe_ini(&ini_path, &console_section) {
                Ok(ini) => {
                    for e in ini.main {
                        target_filenames.insert(e.filename.to_lowercase());
                    }
                    for e in ini.security {
                        target_filenames.insert(e.filename.to_lowercase());
                    }
                    for e in ini.flashfs {
                        target_filenames.insert(e.filename.to_lowercase());
                    }
                }
                Err(_) => return Err(SessionError::IniRead { path: ini_path }),
            }
        }

        info!(
            "[session] prepare_build | type={} console={} section={}",
            build_type, console, console_section
        );
        info!(
            "[session] prepare_build | ini_dir={:?}  data_dir={:?}  common={:?}",
            ini_dir, data_dir, common_dir
        );

        // Enqueue FinalizeFlashfs / FinalizeMobile early (priority ordering handles sequencing)
        self.enqueue(InternalCommand::FinalizeFlashfs);
        self.enqueue(InternalCommand::FinalizeMobile);

        // Build the search path list: ini â†’ ini/flashfs â†’ ini/data â†’ common
        let ini_flashfs = ini_dir.join("flashfs");
        let ini_data = ini_dir.join("data");
        let mut search_dirs: Vec<PathBuf> = vec![ini_dir.clone()];
        if ini_flashfs.is_dir() {
            search_dirs.push(ini_flashfs);
        }
        if ini_data.is_dir() {
            search_dirs.push(ini_data);
        }
        if common_dir.is_dir() {
            search_dirs.push(common_dir.clone());
        }

        // Discover INI assets
        let mut cf_found = false;
        let mut cg_found = false;
        for filename in &target_filenames {
            for dir in &search_dirs {
                let candidate = dir.join(filename);
                if candidate.exists() {
                    self.enqueue(InternalCommand::Update { path: candidate });
                    if filename.starts_with("cf_") {
                        cf_found = true;
                    }
                    if filename.starts_with("cg_") {
                        cg_found = true;
                    }
                    break;
                }
            }
        }

        // CF/CG fallback: xboxupd.bin or su*** containers
        if !cf_found || !cg_found {
            let xboxupd = ini_dir.join("xboxupd.bin");
            if xboxupd.exists() {
                self.enqueue(InternalCommand::Update { path: xboxupd });
            } else if let Ok(entries) = fs::read_dir(&ini_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        let name = p
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_lowercase();
                        if name.starts_with("su") {
                            self.enqueue(InternalCommand::Update { path: p });
                        }
                    }
                }
            }
        }

        // NAND image (data dir)
        let nand_needed = self.active_nand.is_none();

        if nand_needed {
            let nand_candidates = [
                data_dir.join("nanddump.bin"),
                data_dir.join("nanddump1.bin"),
                data_dir.join("nanddump2.bin"),
                data_dir.join("nanddump.ecc"),
                data_dir.join("nanddump1.ecc"),
                data_dir.join("nanddump2.ecc"),
                data_dir.join("updflash.bin"),
                data_dir.join("updflash.ecc"),
            ];
            let mut nand_found = false;
            for p in &nand_candidates {
                if p.exists() {
                    self.enqueue(InternalCommand::ParseImage {
                        path: p.clone(),
                        key: None,
                    });
                    nand_found = true;
                    break;
                }
            }
            if !nand_found {
                // No source NAND: create a blank image based on console layout
                let layout = match console.as_str() {
                    "xenon" => crate::core::images::blocks::NandLayout::Xsb,
                    "jasper256" | "jasper512" | "jasperbb" | "jasperbigffs" | "trinitybigffs" => {
                        crate::core::images::blocks::NandLayout::Bb
                    }
                    "corona4g" | "winchester" => crate::core::images::blocks::NandLayout::Emmc,
                    _ => crate::core::images::blocks::NandLayout::Sb,
                };
                self.enqueue(InternalCommand::CreateImage { layout });
            }
        }

        // CPU key (cpukey.txt / cpukey.bin in data dir)
        if self.pending_key.is_none() && self.options.cpukey.is_none() {
            let key_txt = data_dir.join("cpukey.txt");
            let key_bin = data_dir.join("cpukey.bin");
            if key_bin.exists() {
                if let Ok(bytes) = fs::read(&key_bin) {
                    if bytes.len() >= 16 {
                        let mut k = [0u8; 16];
                        k.copy_from_slice(&bytes[..16]);
                        self.parse_keybin(Some(k));
                    }
                }
            } else if key_txt.exists() {
                if let Ok(text) = fs::read_to_string(&key_txt) {
                    let clean = text.trim();
                    if clean.len() >= 32 {
                        self.set_cpukey(clean.to_string());
                    }
                }
            }
        }

        // Security assets from data dir
        for name in &[
            "smc.bin",
            "smc_config.bin",
            "fcrt.bin",
            "kv.bin",
            "keyvault.bin",
        ] {
            if name == &"fcrt.bin" && self.options.nofcrt.unwrap_or(false) {
                continue;
            }
            let p = data_dir.join(name);
            if p.exists() {
                if let Ok(data) = fs::read(&p) {
                    self.pending_assets.insert(name.to_string(), data);
                }
            }
        }

        // Enqueue INI parsing (Only if not already loaded via string)
        if !self.build_ini_loaded {
            self.parse_ini(
                &ini_path,
                console_section,
                &ini_dir,
                &common_dir,
                &data_dir,
                &payloads_dir,
                &smc_dir,
            );
        }

        // Addon patches
        let addons = self.addons.clone();
        for addon in &addons {
            let addon_path = if PathBuf::from(addon).is_absolute() {
                PathBuf::from(addon)
            } else {
                let p = ini_dir.join(addon);
                if p.exists() {
                    p
                } else {
                    data_dir.join(addon)
                }
            };
            if addon_path.exists() {
                self.enqueue(InternalCommand::ApplyPatch {
                    path: addon_path,
                    ptype: 2,
                    target: None,
                });
            } else {
                warn!("[session] prepare_build: addon not found: {}", addon);
            }
        }

        // Final build command
        self.build(output_path, 0);

        Ok(())
    }

    /// Pulls defaults from NAND into session options.
    pub fn extract_options_from_nand(&mut self) {
        if let Some(nand) = &mut self.active_nand {
            info!("[session] Extracting hardware defaults from active NAND image...");

            // CPU Key
            if self.options.cpukey.is_none() {
                if let Some(key) = nand.cpukey {
                    self.options.cpukey = Some(key.iter().map(|b| format!("{:02x}", b)).collect());
                }
            }

            // Motherboard / Console Type mapping
            if self.options.ctype.is_none() {
                self.options.ctype = Some(format!("{:?}", nand.options.motherboard).to_lowercase());
            }

            if self.options.cfldv.is_none() {
                if let Ok(ldv) = Self::resolve_cf_ldv(&self.options, nand) {
                    self.options.cfldv = Some(ldv.to_string());
                }
            }

            // Keyvault Metadata
            if let Some(ref mut kv) = nand.kv {
                if !kv.is_decrypted {
                    let cpukey = nand.cpukey.unwrap_or([0u8; 16]);
                    if let Err(e) = kv.decrypt(&cpukey) {
                        warn!(
                            "[session] Failed to decrypt Keyvault for metadata extraction: {}",
                            e
                        );
                    }
                }

                if let Some(meta) = &kv.metadata {
                    if self.options.gameregion.is_none() {
                        self.options.gameregion = Some(format!("0x{:04X}", meta.region));
                    }
                    if self.options.dvdkey.is_none() {
                        self.options.dvdkey =
                            Some(meta.dvd_key.iter().map(|b| format!("{:02x}", b)).collect());
                    }
                }
            }
        }
    }

    /// Pushes the final merged session options back into the NAND skeleton's
    /// Keyvault and SMC buffers before a build.
    pub fn sync_options_to_nand(&mut self) -> Result<(), SessionError> {
        if let Some(nand) = &mut self.active_nand {
            info!("[session] Syncing merged options to NAND components...");

            //  Standard/Core Overrides
            if let Some(noremap) = self.options.noremap {
                nand.options.noremap = noremap;
            }
            if let Some(cba) = &self.options.cba {
                nand.options.cba = Some(cba.clone());
            }
            if let Some(cbb) = &self.options.cbb {
                nand.options.cbb = Some(cbb.clone());
            }

            nand.options.gxunsafe = self.options.gxunsafe.unwrap_or(false);
            nand.options.verbose = self.options.verbose.unwrap_or(false);
            nand.options.nomobile = self.options.nomobile.unwrap_or(false);
            nand.options.nofcrt = self.options.nofcrt.unwrap_or(false);
            nand.options.dualpatchslots = self.options.dualpatchslots.unwrap_or(false);
            nand.options.cygnos = self.options.cygnos.unwrap_or(false);
            nand.options.demon = self.options.demon.unwrap_or(false);

            //  CPU Key
            if let Some(key_str) = &self.options.cpukey {
                if let Ok(key_bytes) = crate::builder::builder::hex_to_bytes(key_str) {
                    if key_bytes.len() == 16 {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&key_bytes);
                        nand.cpukey = Some(arr);
                    }
                }
            }

            let cpukey = nand.cpukey.unwrap_or([0u8; 16]);

            //  Per-box LDV / Pairing Sync for CB + CF (independent)
            let pairing = Self::resolve_pairing(&self.options, nand);
            let cb_ldv = Self::resolve_cb_ldv(&self.options, nand)?;
            let cf_ldv = Self::resolve_cf_ldv(&self.options, nand)?;
            Self::sync_per_box_settings(nand, pairing, cb_ldv, cf_ldv);

            //  Keyvault Overrides (Region, DVD Key)
            if let Some(ref mut kv) = nand.kv {
                // Decrypt with current session key if possible
                if !kv.is_decrypted {
                    if let Err(e) = kv.decrypt(&cpukey) {
                        warn!(
                            "[session] Failed to decrypt Keyvault for option patching: {}",
                            e
                        );
                    }
                }

                if kv.is_decrypted {
                    if let Some(dvdkey_str) = &self.options.dvdkey {
                        if let Ok(key_bytes) = crate::builder::builder::hex_to_bytes(dvdkey_str) {
                            if key_bytes.len() == 16 {
                                let mut arr = [0u8; 16];
                                arr.copy_from_slice(&key_bytes);
                                kv.set_dvd_key(&arr)?;
                            }
                        }
                    }

                    if let Some(region_str) = &self.options.gameregion {
                        let region = Self::parse_u16_hex_or_dec(region_str)?;
                        kv.set_region(region)?;
                    }

                    if let Some(serial) = &self.options.serial {
                        kv.set_serial(serial)?;
                    }

                    if let Some(osig) = &self.options.osig {
                        kv.set_osig(osig)?;
                    }

                    if let Some(mfdate) = &self.options.mfdate {
                        kv.set_mf_date(mfdate)?;
                    }

                    if let Some(fcrt) = self.options.fcrt {
                        kv.apply_fcrt_patch(fcrt)?;
                    }

                    if let Some(cid_str) = &self.options.consoleid {
                        if let Ok(bytes) = crate::builder::builder::hex_to_bytes(cid_str) {
                            if bytes.len() == 5 {
                                let mut arr = [0u8; 5];
                                arr.copy_from_slice(&bytes);
                                kv.set_console_id(&arr)?;
                            }
                        }
                    }

                    // Re-encrypt and store Keyvault
                    kv.encrypt(&cpukey)
                        .map_err(|e| SessionError::Keyvault(e.to_string()))?;
                    nand.extra.keyvault = kv.data.clone();
                }
            }

            // SMC Configuration Patching
            let mut smc_config = if nand.extra.smc_config.is_empty() {
                info!("[session] No SMC Config found in skeleton, initializing clean defaults.");
                crate::builder::chain::smc::SmcConfig::new_empty()
            } else {
                crate::builder::chain::smc::SmcConfig::parse(&nand.extra.smc_config)
                    .map_err(|e| SessionError::SmcConfig(e.to_string()))?
            };

            // MAC Address
            if let Some(mac_str) = &self.options.macid {
                let clean_mac = mac_str.replace(":", "");
                if let Ok(bytes) = crate::builder::builder::hex_to_bytes(&clean_mac) {
                    if bytes.len() == 6 {
                        let mut arr = [0u8; 6];
                        arr.copy_from_slice(&bytes);
                        smc_config.set_mac_address(&arr);
                    }
                }
            }

            // Regions (SMC sync)
            let video = if let Some(s) = &self.options.avregion {
                Self::parse_u16_hex_or_dec(s)?
            } else {
                (smc_config.data[0x22A] as u16) << 8 | smc_config.data[0x22B] as u16
            };
            let game = if let Some(s) = &self.options.gameregion {
                Self::parse_u16_hex_or_dec(s)?
            } else {
                (smc_config.data[0x22C] as u16) << 8 | smc_config.data[0x22D] as u16
            };
            let dvd = if let Some(s) = &self.options.dvdregion {
                s.parse::<u8>().unwrap_or(0xFF)
            } else {
                smc_config.data[0x237]
            };
            smc_config.set_regions(video, game, dvd);

            // Thermals (Targets)
            let cpu_t = if let Some(s) = &self.options.cputemp {
                Self::parse_u8_hex_or_dec(s)?
            } else {
                smc_config.data[0x29]
            };
            let gpu_t = if let Some(s) = &self.options.gputemp {
                Self::parse_u8_hex_or_dec(s)?
            } else {
                smc_config.data[0x2A]
            };
            let ram_t = if let Some(s) = &self.options.edramtemp {
                Self::parse_u8_hex_or_dec(s)?
            } else {
                smc_config.data[0x2B]
            };
            smc_config.set_thermal_targets(cpu_t, gpu_t, ram_t);

            // Thermals (Max/Limits)
            let cpu_m = if let Some(s) = &self.options.overcputemp {
                Self::parse_u8_hex_or_dec(s)?
            } else {
                smc_config.data[0x2C]
            };
            let gpu_m = if let Some(s) = &self.options.overgputemp {
                Self::parse_u8_hex_or_dec(s)?
            } else {
                smc_config.data[0x2D]
            };
            let ram_m = if let Some(s) = &self.options.overedramtemp {
                Self::parse_u8_hex_or_dec(s)?
            } else {
                smc_config.data[0x2E]
            };
            smc_config.set_thermal_limits(cpu_m, gpu_m, ram_m);

            //  Fans
            if let Some(s) = &self.options.cpufan {
                let speed = Self::parse_u8_hex_or_dec(s)?;
                smc_config.set_fan_speed(false, speed != 0, speed);
            }
            if let Some(s) = &self.options.gpufan {
                let speed = Self::parse_u8_hex_or_dec(s)?;
                smc_config.set_fan_speed(true, speed != 0, speed);
            }

            // 3f. Reset/XeLL Buttons
            if let Some(s) = &self.options.xellbutton {
                if s.len() == 4 {
                    smc_config.set_reset_code(s.as_bytes().try_into().unwrap());
                }
            }

            // Finalize and store SMC Config
            nand.extra.smc_config = smc_config.serialize().clone().to_vec();

            // SMC image
            let mut smc = crate::builder::chain::smc::RawSmc::new(nand.extra.smc.clone());
            smc.ensure_decrypted();

            let profile_l = nand.options.image_profile.to_ascii_lowercase();
            let auto_patch_smc = matches!(profile_l.as_str(), "glitch" | "glitch1" | "glitch2");
            if auto_patch_smc {
                let ini_dir = self.ini_dir.clone().unwrap_or_else(|| PathBuf::from("."));
                let patch_path = ini_dir.join("../smc/bin/glitch.json");
                match fs::read_to_string(&patch_path) {
                    Ok(json) => {
                        let mut count = crate::core::images::signature::Signature::apply_batch(
                            &mut smc.data,
                            &json,
                        )
                        .map_err(|e| SessionError::SmcAutopatch {
                            error: e.to_string(),
                            path: patch_path.clone(),
                        })?;
                        if count == 0 {
                            let mut retry =
                                crate::builder::chain::smc::RawSmc::new(smc.data.clone());
                            retry.force_decrypt();
                            let retry_count =
                                crate::core::images::signature::Signature::apply_batch(
                                    &mut retry.data,
                                    &json,
                                )
                                .map_err(|e| {
                                    SessionError::SmcAutopatch {
                                        error: e.to_string(),
                                        path: patch_path.clone(),
                                    }
                                })?;
                            if retry_count > 0 {
                                smc.data = retry.data;
                                count = retry_count;
                            }
                        }
                        if count > 0 {
                            info!(
                                "[session] SMC autopatching applied: {} match(es) from {:?}",
                                count, patch_path
                            );
                        } else {
                            info!(
                                "[session] SMC autopatching: 0 matches from {:?}",
                                patch_path
                            );
                        }
                    }
                    Err(_) => warn!(
                        "[session] SMC autopatching patch file missing: {:?}",
                        patch_path
                    ),
                }
            }
            nand.extra.smc = smc.data;
        }
        Ok(())
    }

    /// Applies a batch of signature patches (JSON format) to the active NAND's decrypted SMC.
    /// Returns the total number of patches applied.
    pub fn apply_smc_signature_batch(&mut self, json_str: &str) -> Result<usize, SessionError> {
        if let Some(nand) = &mut self.active_nand {
            info!("[session] Applying signature batch to SMC...");
            let mut smc = crate::builder::chain::smc::RawSmc::new(nand.extra.smc.clone());
            smc.ensure_decrypted();

            let count =
                crate::core::images::signature::Signature::apply_batch(&mut smc.data, json_str)?;

            nand.extra.smc = smc.data;
            info!(
                "[session] SMC signature batch applied: {} match(es) patched.",
                count
            );
            Ok(count)
        } else {
            Err(SessionError::NoActiveNand)
        }
    }

    fn parse_u16_hex_or_dec(s: &str) -> Result<u16, SessionError> {
        if s.starts_with("0x") {
            u16::from_str_radix(&s[2..], 16).map_err(|e| SessionError::InvalidHexU16 {
                value: s.to_string(),
                error: e.to_string(),
            })
        } else {
            s.parse::<u16>()
                .map_err(|e| SessionError::InvalidDecimalU16 {
                    value: s.to_string(),
                    error: e.to_string(),
                })
        }
    }

    fn parse_u8_hex_or_dec(s: &str) -> Result<u8, SessionError> {
        if s.starts_with("0x") {
            u8::from_str_radix(&s[2..], 16).map_err(|e| SessionError::InvalidHexU8 {
                value: s.to_string(),
                error: e.to_string(),
            })
        } else {
            s.parse::<u8>().map_err(|e| SessionError::InvalidDecimalU8 {
                value: s.to_string(),
                error: e.to_string(),
            })
        }
    }

    /// Execute a command by ID and remove it.
    pub fn session_run_once(&mut self, id: usize) -> Result<bool, SessionError> {
        let mut remaining = Vec::new();
        let mut result: Result<bool, SessionError> = Ok(false);
        while let Some(q) = self.queue.pop() {
            if q.sequence_id == id {
                result = self.execute_command(q.command).map(|_| true);
            } else {
                remaining.push(q);
            }
        }
        for q in remaining {
            self.queue.push(q);
        }
        result
    }

    pub fn parse_ini(
        &mut self,
        path: impl AsRef<Path>,
        target: String,
        ini_base: impl AsRef<Path>,
        common: impl AsRef<Path>,
        data: impl AsRef<Path>,
        payloads: impl AsRef<Path>,
        smc: impl AsRef<Path>,
    ) {
        self.enqueue(InternalCommand::ParseIni {
            path: path.as_ref().to_path_buf(),
            target,
            ini_base: ini_base.as_ref().to_path_buf(),
            common: common.as_ref().to_path_buf(),
            data: data.as_ref().to_path_buf(),
            payloads: payloads.as_ref().to_path_buf(),
            smc: smc.as_ref().to_path_buf(),
        });
    }

    pub fn extract_stfs(&mut self, path: PathBuf, target_dir: PathBuf) {
        self.enqueue(InternalCommand::ExtractStfs { path, target_dir });
    }

    pub fn create_image(&mut self, layout: crate::core::images::blocks::NandLayout) {
        self.enqueue(InternalCommand::CreateImage { layout });
    }

    pub fn finalize_flashfs(&mut self) {
        self.enqueue(InternalCommand::FinalizeFlashfs);
    }

    pub fn run(&mut self) -> Result<(), SessionError> {
        info!("[session] Running {} queued commands...", self.queue.len());

        while let Some(queued_cmd) = self.queue.pop() {
            let priority = queued_cmd.command.priority_score();
            match &queued_cmd.command {
                InternalCommand::ParseIni { path, target, .. } => {
                    info!("[session] Executing (PriorityScore: {}, Seq: {}): ParseIni {{ path: {:?}, target: {:?} }}", priority, queued_cmd.sequence_id, path, target);
                }
                cmd => {
                    info!(
                        "[session] Executing (PriorityScore: {}, Seq: {}): {:?}",
                        priority, queued_cmd.sequence_id, cmd
                    );
                }
            }

            self.execute_command(queued_cmd.command)?;
        }
        info!("[session] Finished priority queue batch.");
        Ok(())
    }

    /// Execute a command immediately, bypassing the priority queue entirely.
    pub fn swap_bootloader(&mut self, bl_type: String, path: PathBuf, is_rebooter: bool) {
        self.enqueue(InternalCommand::SwapBootloader {
            bl_type,
            path,
            is_rebooter,
        });
    }

    pub fn run_once(&mut self, command: InternalCommand) -> Result<(), SessionError> {
        info!(
            "[session] Executing command directly (queue bypassed): {:?}",
            command
        );
        self.execute_command(command)
    }

    pub fn execute_command(&mut self, command: InternalCommand) -> Result<(), SessionError> {
        use crate::core::commands;
        match command {
            InternalCommand::ExtractAll {
                output_dir,
                all,
                include_decrypted,
            } => commands::handle_extract_all(self, output_dir, all, include_decrypted),
            InternalCommand::Build { output, target } => {
                commands::handle_build(self, output, target)
            }
            InternalCommand::ParseIni {
                path,
                target,
                ini_base,
                common,
                data,
                payloads,
                smc,
            } => commands::handle_parse_ini(
                self, path, target, ini_base, common, data, payloads, smc,
            ),
            InternalCommand::ParseImage { path, key } => {
                commands::handle_parse_image(self, path, key)
            }
            InternalCommand::ApplyEcc { path } => commands::handle_apply_ecc(self, path),
            InternalCommand::ParseKey { key } => {
                commands::handle_parse_key(self, key);
                Ok(())
            }
            InternalCommand::ParseKeybin { key } => {
                commands::handle_parse_keybin(self, key);
                Ok(())
            }
            InternalCommand::ParseFlashfs { path } => commands::handle_parse_flashfs(self, path),
            InternalCommand::ParsePatch { path } => commands::handle_parse_patch(self, path),
            InternalCommand::ApplyPatch {
                path,
                ptype,
                target,
            } => commands::handle_apply_patch(self, path, ptype, target),
            InternalCommand::ApplySmcSignature { json } => {
                commands::handle_apply_smc_signature(self, json).map(|_| ())
            }
            InternalCommand::SwapBootloader {
                bl_type,
                path,
                is_rebooter,
            } => commands::handle_swap_bootloader(self, bl_type, path, is_rebooter),
            InternalCommand::Replace { id, path } => {
                commands::handle_replace(self, id, path);
                Ok(())
            }
            InternalCommand::List => {
                commands::handle_list(self);
                Ok(())
            }
            InternalCommand::Delete { id } => {
                commands::handle_delete(self, id);
                Ok(())
            }
            InternalCommand::Clear => {
                commands::handle_clear(self);
                Ok(())
            }
            InternalCommand::Compress => {
                commands::handle_compress();
                Ok(())
            }
            InternalCommand::ApplyOptions => commands::handle_apply_options(self),
            InternalCommand::SessionInit { base, common } => {
                commands::handle_session_init(base, common);
                Ok(())
            }
            InternalCommand::SessionList => {
                commands::handle_session_list(self);
                Ok(())
            }
            InternalCommand::SessionDelete { id } => {
                commands::handle_session_delete(self, id);
                Ok(())
            }
            InternalCommand::SessionRun => commands::handle_session_run(self),
            InternalCommand::CreateImage { layout } => {
                commands::handle_create_image(self, layout);
                Ok(())
            }
            InternalCommand::Update { path } => commands::handle_update(self, path),
            InternalCommand::FinalizeMobile => {
                commands::handle_finalize_mobile(self);
                Ok(())
            }
            InternalCommand::FinalizeFlashfs => {
                commands::handle_finalize_flashfs(self);
                Ok(())
            }
            InternalCommand::ExtractStfs { path, target_dir } => {
                commands::handle_extract_stfs(self, path, target_dir)?;
                Ok(())
            }
        }
    }

    // Internal helper methods used by commands
    pub(crate) fn finalize_flashfs_internal(&mut self) {
        if let Some(nand) = &mut self.active_nand {
            let fs_start: u16 = match nand.layout {
                crate::core::images::blocks::NandLayout::Bb => {
                    let image_len = nand.image.len();
                    let reserve_start = nand.layout.reserve_start(image_len);
                    let scanned = nand.flashfs.root.block_number;
                    if scanned > 0 && (scanned as usize) < reserve_start {
                        scanned as u16
                    } else {
                        let fallback = reserve_start.saturating_sub(0x80);
                        std::cmp::max(4u16, fallback as u16)
                    }
                }
                crate::core::images::blocks::NandLayout::Emmc => {
                    crate::builder::filesystem::corona::default_emmc_fs_block(
                        nand.header.fs_addr.get(),
                        &nand.corona_fs,
                    )
                }
                _ => {
                    let sb: crate::builder::types::SouthbridgeType =
                        nand.options.motherboard.into();
                    let chain_profile = if nand.bootloaders.cb_b.is_some() {
                        "split"
                    } else {
                        "single"
                    };
                    let (_, _, phys_fs_block) = crate::builder::types::LayoutCalculator::calculate(
                        sb,
                        chain_profile,
                        nand.layout,
                    );
                    if phys_fs_block != 0 {
                        phys_fs_block as u16
                    } else {
                        0x4E
                    }
                }
            };

            if nand.flashfs.root.block_number > 0 {
                let new_fs = crate::builder::filesystem::flashfs::FlashFS::scan_physical(
                    &nand.image,
                    &nand.layout,
                );
                if new_fs.root.block_number >= 0 {
                    nand.flashfs.root = new_fs.root;
                } else {
                    let mut root = crate::builder::filesystem::flashfs::FileSystemRoot::new(
                        fs_start as i32,
                        0,
                        0x30,
                    );
                    root.create_defaults(nand.image.len(), &nand.layout, fs_start);
                    nand.flashfs.root = root;
                }
            }

            let sec_files = [
                "fcrt.bin",
                "crl.bin",
                "dae.bin",
                "extended.bin",
                "secdata.bin",
                "odd.bin",
            ];
            for name in &sec_files {
                if let Some(data) = self.security_assets.get(*name).cloned() {
                    nand.inject_security_file(name, &data, fs_start);
                }
            }
        }
    }

    pub(crate) fn finalize_mobile_internal(&mut self) {
        if self.options.nomobile.unwrap_or(false) {
            return;
        }
        let data_dir = self
            .data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("mydata"));
        if let Some(nand) = &mut self.active_nand {
            nand.mobile.apply_data_folder_tier(&data_dir);
        }
    }
}
