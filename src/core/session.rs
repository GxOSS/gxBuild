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
use crate::core::handler::Executor;
use log::{error, info};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::fs;
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

impl InternalCommand {
    pub fn priority_score(&self) -> u8 {
        match self {
            Self::ParseKey { .. } => 160,
            Self::ParseKeybin { .. } => 160,
            Self::ParseImage { .. } => 150,
            Self::CreateImage { .. } => 150,
            Self::ApplyEcc { .. } => 149,
            Self::SwapBootloader { .. } => 140,
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
            Self::ApplyOptions => 80,
            Self::ApplyPatch { .. } => 79,
            Self::ApplySmcSignature { .. } => 79,
            Self::Compress => 78,
            Self::SessionRun => 50,
            Self::Build { .. } => 0,
        }
    }
}

#[derive(Debug)]
pub struct QueuedCommand {
    pub sequence_id: usize,
    pub command: InternalCommand,
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
    pub queue: BinaryHeap<QueuedCommand>,
    pub next_seq_id: usize,
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
        if let Ok(bytes) = crate::builder::parser::hex_to_bytes(&key) {
            if let Ok(arr) = bytes.try_into() {
                self.parse_key(arr);
            } else {
                error!("[session] CPU Key must be 32 hex chars / 16 bytes");
            }
        } else {
            error!("[session] Invalid formatting for CPU Key: {}", key);
        }
    }

    pub fn load_options_ini(&mut self, content: &str) -> Result<(), String> {
        match crate::core::data::optini::parse_options_ini(content) {
            Ok(new_opts) => {
                self.options.merge(new_opts);
                info!("[session] Merged options from INI content string.");
                Ok(())
            }
            Err(e) => Err(format!("Failed to parse options INI: {}", e)),
        }
    }

    pub fn load_ini(&mut self, content: &str, target: &str) -> Result<(), String> {
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
                        Err(e) => return Err(format!("Failed to apply INI data: {}", e)),
                    }
                    Ok(())
                }
                Err(e) => Err(format!("INI discovery failed: {}", e)),
            },
            Err(e) => Err(format!("Failed to parse INI string: {}", e)),
        }
    }

    /// Loads an options.ini file from the specified path and merges it into the session options.
    pub fn load_options_ini_file(&mut self, path: impl AsRef<Path>) -> Result<(), String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read options INI file: {}", e))?;
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

    /// Execute a command by ID and remove it.
    pub fn session_run_once(&mut self, id: usize) -> Result<bool, String> {
        let mut remaining = Vec::new();
        let mut result: Result<bool, String> = Ok(false);
        while let Some(q) = self.queue.pop() {
            if q.sequence_id == id {
                result = Executor::execute_command(self, q.command).map(|_| true);
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

    pub fn run(&mut self) -> Result<(), String> {
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

            Executor::execute_command(self, queued_cmd.command)?;
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

    pub fn run_once(&mut self, command: InternalCommand) -> Result<(), String> {
        info!(
            "[session] Executing command directly (queue bypassed): {:?}",
            command
        );
        Executor::execute_command(self, command)
    }

    pub fn prepare_build(&mut self) -> Result<(), String> {
        Executor::prepare_build(self)
    }
}

/*
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
*/
