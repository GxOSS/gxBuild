/*
    session.rs - Session management and command queue

    Created in 2026 by Exposure / Zach for gxBuild.
    Modified/Contributed by erorn (2026)
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::path::{Path, PathBuf};

use crate::builder::builder::NandSkeleton;
use std::fs;
use crate::builder::builder::{SouthbridgeType, LayoutCalculator};
use crate::core::data::gxp::parse_patch_binary;
use crate::core::data::filesearch::IniSearch;
use log::{info, error, warn};
use crate::core::data::blocks::NandLayout;
#[derive(Debug)]
pub enum InternalCommand { 
    ParseIni { path: PathBuf, target: String, ini_base: PathBuf, common: PathBuf, data: PathBuf },
    ParseImage { path: PathBuf, key: Option<[u8; 16]> },
    ParseKey { key: [u8; 16] },
    ParseKeybin { key: Option<[u8; 16]> },
    ParseFlashfs { path: PathBuf },
    ParsePatch { path: PathBuf },
    ApplyPatch { path: PathBuf, ptype: u8, target: Option<u8> },
    Extract { id: String },
    ExtractAll,
    Replace { id: u8, path: PathBuf },
    List,
    Delete { id: u8 },
    Clear,
    Compress,
    Decompress,
    Update { path: PathBuf },
    Build { output: PathBuf, target: u8 },
    FinalizeFlashfs,
    SessionInit { base: Option<PathBuf>, common: Option<PathBuf> },
    SessionList,
    SessionDelete { id: u8 },
    SessionRun,
    CreateImage { layout: crate::core::data::blocks::NandLayout },
    ExtractStfs { path: PathBuf, target_dir: PathBuf },
    SwapBootloader { bl_type: String, path: PathBuf, is_rebooter: bool },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::chain::cb::{BootloaderCb, CbMetadata};
    use crate::builder::chain::cf::{BootloaderCf, CfMetadata};
    use crate::builder::chain::BootloaderHeader;
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
            metadata: Some(CbMetadata {
                ldv,
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
    fn sync_per_box_settings_keeps_cb_and_cf_values_in_sync() {
        let session = Session::new();
        let mut nand = NandSkeleton::new_blank(NandLayout::Sb);

        // start with mismatched values to mirror the original bug
        nand.bootloaders.cb_a = Some(test_cb([0x12, 0x34, 0x56], 7));
        nand.update.cf_0 = Some(test_cf([0xAA, 0xBB, 0xCC], 2));

        let (pairing, ldv) = Session::resolve_per_box_settings(&session.options, &nand).unwrap();
        Session::sync_per_box_settings(&mut nand, pairing, ldv);

        let cb_meta = nand.bootloaders.cb_a.as_ref().unwrap().metadata.as_ref().unwrap();
        let cf_meta = nand.update.cf_0.as_ref().unwrap().metadata.as_ref().unwrap();

        assert_eq!(cb_meta.pairing_data, [0x12, 0x34, 0x56]);
        assert_eq!(cb_meta.lockdown_value, 7);
        assert_eq!(cb_meta.ldv, 7);
        assert_eq!(cf_meta.pairing_data, [0x12, 0x34, 0x56]);
        assert_eq!(cf_meta.lockdown_value, 7);
    }
}

impl InternalCommand {
    /// Priority score - higher value runs first.
    ///
    /// Tiers:
    ///   150 - Foundation: Load/create the NAND image (ParseImage, CreateImage)
    ///   145 - Key assignment: must run after NAND is loaded (ParseKey, ParseKeybin)
    ///   110 - Standalone ops: no NAND dependency (ExtractStfs, Update)
    ///   100 - Session admin: immediate teardown/inspection ops (SessionInit, SessionList, SessionDelete)
    ///   100 - Post-load mutations: ParseIni, ParseFlashfs, ParsePatch (safe; 150 runs first)
    ///    99 - Decompress: inspection op, after NAND load + INI apply
    ///    90 - FinalizeFlashfs: consumes pending_assets gathered by ParseIni
    ///    89 - Extract (single component)
    ///    88 - ExtractAll
    ///    87 - Replace
    ///    86 - List
    ///    85 - Delete
    ///    84 - Clear
    ///    79 - ApplyPatch
    ///    78 - Compress
    ///    50 - SessionRun: drains and re-executes queue; must fire after all real work is dispatched
    ///     0 - Build: always the final step
    fn priority_score(&self) -> u8 {
        match self {
            // ── Key assignment (Must happen before ParseImage) ───────────
            Self::ParseKey { .. }     => 160,
            Self::ParseKeybin { .. }  => 160,
            // ── Foundation ────────────────────────────────────────────────
            Self::ParseImage { .. }   => 150,
            Self::CreateImage { .. }  => 150,
            // ── Standalone ops (no active-NAND dependency) ────────────────
            Self::ExtractStfs { .. }  => 110,
            Self::Update { .. }       => 110,
            // ── Session admin (immediate, before queue processing) ────────
            Self::SessionInit { .. }  => 100,
            Self::SessionList         => 100,
            Self::SessionDelete { .. }=> 100,
            // ── Post-load mutations ────────────────────────────────────────
            Self::ParseIni { .. }     => 100,
            Self::ParseFlashfs { .. } => 100,
            Self::ParsePatch { .. }   => 100,
            // ── Inspection / decompression ─────────────────────────────────
            Self::Decompress          => 99,
            // ── FlashFS finalization ───────────────────────────────────────
            Self::FinalizeFlashfs     => 90,
            // ── Extraction ────────────────────────────────────────────────
            Self::Extract { .. }      => 89,
            Self::ExtractAll          => 88,
            // ── Modification ──────────────────────────────────────────────
            Self::Replace { .. }      => 87,
            Self::List                => 86,
            Self::Delete { .. }       => 85,
            Self::Clear               => 84,
            Self::ApplyPatch { .. }   => 79,
            Self::Compress            => 78,
            // ── SessionRun: drains queue; must follow all real work ───────
            Self::SessionRun          => 50,
            // ── Build: always last ────────────────────────────────────────
            Self::Build { .. }        => 0,
            Self::SwapBootloader { .. } => 140,
        }
    }
}

#[derive(Debug)]
pub struct QueuedCommand {
    sequence_id: usize,
    command: InternalCommand,
}

impl Ord for QueuedCommand {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare priority score (higher score = runs sooner = Should be ordered as 'Greater')
        let p_cmp = self.command.priority_score().cmp(&other.command.priority_score());
        if p_cmp != Ordering::Equal {
            return p_cmp;
        }
        // Then sequence_id tie breaker (lower ID = enqueued earlier = Should be chosen sooner)
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
    queue: BinaryHeap<QueuedCommand>,
    next_seq_id: usize,
    /// Legacy single-asset pool (used by the Update command for ad-hoc file loading).
    pub pending_assets: HashMap<String, Vec<u8>>,
    /// Assets resolved from the INI [main] section (bootloader binaries, CF/CG).
    pub bootloader_assets: HashMap<String, Vec<u8>>,
    /// Assets resolved from the INI [security] section (smc.bin, kv.bin, fcrt.bin).
    pub security_assets: HashMap<String, Vec<u8>>,
    /// Assets resolved from the INI [flashfs] section (XEX/dat files for FlashFS).
    pub flashfs_assets: HashMap<String, Vec<u8>>,
    /// Dummy state object for passing over to extract commands
    pub active_nand: Option<NandSkeleton>,
    /// Global xeBuild options / preferences
    pub options: crate::core::data::xeini::OptionsIni,
    /// CPU Key buffer if provided before NAND is loaded
    pub pending_key: Option<[u8; 16]>,
    /// Last error message for FFI reporting
    pub last_error: Option<String>,

    // ── Build configuration (set via FFI setters, consumed by prepare_build) ──
    pub build_type: Option<String>,
    pub console_type: Option<String>,
    pub ini_dir: Option<std::path::PathBuf>,
    pub common_dir: Option<std::path::PathBuf>,
    pub data_dir: Option<std::path::PathBuf>,
    pub output_path: Option<std::path::PathBuf>,
    pub ini_ext: Option<String>,
    pub bl_ext: Option<String>,
    pub addons: Vec<String>,
}

impl Session {
    // fallback pairing if nothing usable comes from the nand
    fn fallback_pairing_data() -> [u8; 3] {
        [0, 0, 1]
    }

    // fallback ldv if the nand and options do not provide one
    fn fallback_lockdown_value() -> u8 {
        1
    }

    fn resolve_per_box_settings(
        options: &crate::core::data::xeini::OptionsIni,
        nand: &NandSkeleton,
    ) -> Result<([u8; 3], u8), String> {
        let fallback_pairing = Self::fallback_pairing_data();
        let fallback_ldv = Self::fallback_lockdown_value();

        let pairing_from_nand = nand
            .bootloaders
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
            .filter(|pairing| *pairing != [0, 0, 0]);

        let ldv_from_nand = nand
            .bootloaders
            .cb_a
            .as_ref()
            .or(nand.bootloaders.cb.as_ref())
            .and_then(|cb| cb.metadata.as_ref().map(|meta| meta.lockdown_value))
            .or_else(|| {
                nand.update
                    .cf_0
                    .as_ref()
                    .and_then(|cf| cf.metadata.as_ref().map(|meta| meta.lockdown_value))
            })
            .filter(|ldv| *ldv != 0);

        // prefer values already on the nand, then fall back
        let pairing = pairing_from_nand.unwrap_or(fallback_pairing);
        let ldv = if let Some(cfldv_option) = &options.cfldv {
            Self::parse_u8_hex_or_dec(cfldv_option)?
        } else {
            ldv_from_nand.unwrap_or(fallback_ldv)
        };

        Ok((pairing, ldv))
    }

    fn sync_per_box_settings(nand: &mut NandSkeleton, pairing: [u8; 3], ldv: u8) {
        // keep the cb side in sync
        if let Some(ref mut cb) = nand.bootloaders.cb {
            if let Some(ref mut meta) = cb.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = ldv;
                meta.ldv = ldv;
                cb.sync_metadata();
            }
        }

        if let Some(ref mut cb) = nand.bootloaders.cb_a {
            if let Some(ref mut meta) = cb.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = ldv;
                meta.ldv = ldv;
                cb.sync_metadata();
            }
        }

        if let Some(ref mut cb) = nand.bootloaders.cb_b {
            if let Some(ref mut meta) = cb.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = ldv;
                meta.ldv = ldv;
                cb.sync_metadata();
            }
        }

        // keep the cf side in sync too
        if let Some(ref mut cf) = nand.update.cf_0 {
            if let Some(ref mut meta) = cf.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = ldv;
                cf.sync_metadata();
            } else {
                if cf.data.len() > 0x20E {
                    cf.data[0x20C..0x20F].copy_from_slice(&pairing);
                }
                if cf.data.len() > 0x20F {
                    cf.data[0x20F] = ldv;
                }
            }
        }

        if let Some(ref mut cf) = nand.update.cf_1 {
            if let Some(ref mut meta) = cf.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = ldv;
                cf.sync_metadata();
            } else {
                if cf.data.len() > 0x20E {
                    cf.data[0x20C..0x20F].copy_from_slice(&pairing);
                }
                if cf.data.len() > 0x20F {
                    cf.data[0x20F] = ldv;
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
            active_nand: None,
            options: crate::core::data::xeini::OptionsIni::new(),
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
        }
    }

    pub fn enqueue(&mut self, command: InternalCommand) {
        self.queue.push(QueuedCommand {
            sequence_id: self.next_seq_id,
            command,
        });
        self.next_seq_id += 1;
    }

    // ------------------------------------
    // Fixed public methods (Interface API)
    // ------------------------------------

    pub fn extract(&mut self, id: String) {
        self.enqueue(InternalCommand::Extract { id });
    }

    pub fn extract_all(&mut self) {
        self.enqueue(InternalCommand::ExtractAll);
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

    pub fn apply_patch(&mut self, path: PathBuf, ptype: u8, target: Option<u8>) {
        self.enqueue(InternalCommand::ApplyPatch { path, ptype, target });
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

    pub fn decompress(&mut self) {
        self.enqueue(InternalCommand::Decompress);
    }

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
        // Full teardown: clear queue, active NAND, all asset pools, and reset sequence counter.
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

    // ── Build configuration setters ─────────────────────────────────────────

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
                error!("[session] CPU Key must be 32 hex characters (16 bytes).");
            }
        } else {
            error!("[session] Invalid hex format for CPU Key: {}", key);
        }
    }

    pub fn set_option(&mut self, key: &str, value: &str) {
        let mut o = crate::core::data::xeini::OptionsIni::new();
        let v = value;
        let is_true = v.eq_ignore_ascii_case("true");
        match key.to_lowercase().as_str() {
            "region" | "avregion" => o.avregion = Some(v.to_string()),
            "gameregion"          => o.gameregion = Some(v.to_string()),
            "dvdregion"           => o.dvdregion = Some(v.to_string()),
            "unsafe" | "gxunsafe" => o.gxunsafe = Some(is_true),
            "verbose"             => {
                o.verbose = Some(is_true);
                // Update logger level immediately if verbose is toggled
                let _ = crate::core::logger::init_logger("build", is_true);
            },
            "cba"                 => o.cba = Some(v.to_string()),
            "cbb"                 => o.cbb = Some(v.to_string()),
            "nomobile"            => o.nomobile = Some(is_true),
            "noremap"             => o.noremap = Some(is_true),
            "nandmu"              => o.nandmu = Some(is_true),
            "cputemp"             => o.cputemp = Some(v.to_string()),
            "gputemp"             => o.gputemp = Some(v.to_string()),
            "edramtemp"           => o.edramtemp = Some(v.to_string()),
            "overcputemp"         => o.overcputemp = Some(v.to_string()),
            "overgputemp"         => o.overgputemp = Some(v.to_string()),
            "overedramtemp"       => o.overedramtemp = Some(v.to_string()),
            "cpufan"              => o.cpufan = Some(v.to_string()),
            "gpufan"              => o.gpufan = Some(v.to_string()),
            "macid" | "mac"       => o.macid = Some(v.to_string()),
            "dvdkey"              => o.dvdkey = Some(v.to_string()),
            "cfldv"               => o.cfldv = Some(v.to_string()),
            "xellbutton"          => o.xellbutton = Some(v.to_string()),
            "xellbutton2"         => o.xellbutton2 = Some(v.to_string()),
            "cygnos"              => o.cygnos = Some(is_true),
            "demon"               => o.demon = Some(is_true),
            "smcnoeject"          => o.smcnoeject = Some(is_true),
            "smcnoblink"          => o.smcnoblink = Some(is_true),
            "patchsmc"            => o.patchsmc = Some(is_true),
            "olddvd"              => o.olddvd = Some(is_true),
            "nodvd"               => o.nodvd = Some(is_true),
            "dualboot"            => o.dualboot = Some(is_true),
            "nolog"               => o.nolog = Some(is_true),
            "noinfo"              => o.noinfo = Some(is_true),
            "noenter"             => o.noenter = Some(is_true),
            _ => warn!("[session] set_option: unknown key '{}'", key),
        }
        self.options.merge(o);
    }

    /// Parses an options.ini content string and merges it into the session options.
    pub fn load_options_ini(&mut self, content: &str) -> Result<(), String> {
        match crate::core::data::xeini::parse_options_ini(content) {
            Ok(new_opts) => {
                self.options.merge(new_opts);
                info!("[session] Merged options from INI content string.");
                Ok(())
            }
            Err(e) => Err(format!("Failed to parse options INI: {}", e)),
        }
    }

    /// Loads an options.ini file from the specified path and merges it into the session options.
    pub fn load_options_ini_file(&mut self, path: impl AsRef<Path>) -> Result<(), String> {
        let content = fs::read_to_string(path).map_err(|e| format!("Failed to read options INI file: {}", e))?;
        self.load_options_ini(&content)
    }

    /// Resets the command queue and build config for a fresh build,
    /// while keeping the active NAND and CPU key in place.
    pub fn reset_build(&mut self) {
        self.queue.clear();
        self.next_seq_id = 0;
        self.pending_assets.clear();
        self.bootloader_assets.clear();
        self.security_assets.clear();
        self.flashfs_assets.clear();
        self.addons.clear();
        self.last_error = None;
    }

    /// Resolves all build configuration set via the setter methods, discovers
    /// assets, and enqueues everything ready for `run()`. This is the FFI-facing
    /// equivalent of `handle_build()` in `cli.rs`.
    pub fn prepare_build(&mut self) -> Result<(), String> {
        use std::collections::HashSet;

        let ini_dir = self.ini_dir.clone()
            .unwrap_or_else(|| PathBuf::from("."));
        let data_dir = self.data_dir.clone()
            .unwrap_or_else(|| PathBuf::from("data"));
        let common_dir = self.common_dir.clone()
            .unwrap_or_else(|| ini_dir.join("../common"));
        let output_path = self.output_path.clone()
            .unwrap_or_else(|| PathBuf::from("updflash.bin"));

        // 1. Load options.ini from the data dir FIRST, then merge user overrides
        let options_path = data_dir.join("options.ini");
        if options_path.exists() {
            if let Ok(content) = fs::read_to_string(&options_path) {
                match crate::core::data::xeini::parse_options_ini(&content) {
                    Ok(disk_opts) => {
                        let user_opts = self.options.clone();
                        self.options = disk_opts;
                        self.options.merge(user_opts);
                    }
                    Err(e) => warn!("[session] prepare_build: failed to parse options.ini: {}", e),
                }
            }
        }

        // 2. Initialize or update logger level based on FINAL merged options
        let is_verbose = self.options.verbose.unwrap_or(false);
        let _ = crate::core::logger::init_logger("build", is_verbose);

        if let Some(nand) = &mut self.active_nand {
            nand.options.gxunsafe = self.options.gxunsafe.unwrap_or(false);
            nand.options.verbose = self.options.verbose.unwrap_or(false);
        }

        let build_type = self.build_type.clone()
            .ok_or("prepare_build: build_type not set")?;
        let console = self.console_type.clone()
            .ok_or("prepare_build: console_type not set")?;

        // Resolve INI filename: _<type>[_<ext>].ini
        let ini_suffix = self.ini_ext.as_ref()
            .map(|e| format!("_{}", e)).unwrap_or_default();
        let ini_filename = format!("_{}{}.ini", build_type, ini_suffix);
        let ini_path = ini_dir.join(&ini_filename);

        // Console section, e.g. "trinity" or "trinity_ext"
        let console_section = match &self.bl_ext {
            Some(ext) => format!("{}_{}", console, ext),
            None      => console.clone(),
        };

        // Pre-parse INI to know which asset filenames we need
        let mut target_filenames: HashSet<String> = HashSet::new();
        match crate::core::data::xeini::parse_xe_ini(&ini_path, &console_section) {
            Ok(ini) => {
                for e in ini.main    { target_filenames.insert(e.filename.to_lowercase()); }
                for e in ini.security { target_filenames.insert(e.filename.to_lowercase()); }
                for e in ini.flashfs  { target_filenames.insert(e.filename.to_lowercase()); }
            }
            Err(_) => return Err(format!("prepare_build: cannot read INI at {:?}", ini_path)),
        }

        info!("[session] prepare_build | type={} console={} section={}", build_type, console, console_section);
        info!("[session] prepare_build | ini_dir={:?}  data_dir={:?}  common={:?}", ini_dir, data_dir, common_dir);

        // Enqueue FinalizeFlashfs early (priority ordering handles sequencing)
        self.enqueue(InternalCommand::FinalizeFlashfs);

        // Build the search path list: ini → ini/flashfs → ini/data → common
        let ini_flashfs = ini_dir.join("flashfs");
        let ini_data    = ini_dir.join("data");
        let mut search_dirs: Vec<PathBuf> = vec![ini_dir.clone()];
        if ini_flashfs.is_dir() { search_dirs.push(ini_flashfs); }
        if ini_data.is_dir()    { search_dirs.push(ini_data); }
        if common_dir.is_dir()  { search_dirs.push(common_dir.clone()); }

        // Discover INI assets
        let mut cf_found = false;
        let mut cg_found = false;
        for filename in &target_filenames {
            for dir in &search_dirs {
                let candidate = dir.join(filename);
                if candidate.exists() {
                    self.enqueue(InternalCommand::Update { path: candidate });
                    if filename.starts_with("cf_") { cf_found = true; }
                    if filename.starts_with("cg_") { cg_found = true; }
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
                        let name = p.file_name().unwrap_or_default()
                            .to_string_lossy().to_lowercase();
                        if name.starts_with("su") {
                            self.enqueue(InternalCommand::Update { path: p });
                        }
                    }
                }
            }
        }

        // NAND image (data dir)
        let nand_candidates = [
            data_dir.join("nanddump.bin"),
            data_dir.join("nanddump1.bin"),
            data_dir.join("nanddump2.bin"),
            data_dir.join("updflash.bin"),
        ];
        let mut nand_found = false;
        for p in &nand_candidates {
            if p.exists() {
                self.enqueue(InternalCommand::ParseImage { path: p.clone(), key: None });
                nand_found = true;
                break;
            }
        }
        if !nand_found {
            // No source NAND: create a blank image based on console layout
            let layout = match console.as_str() {
                "xenon"                        => crate::core::data::blocks::NandLayout::Xsb,
                "jasper256" | "jasper512" |
                "jasperbb"  | "jasperbigffs" |
                "trinitybigffs"                => crate::core::data::blocks::NandLayout::Bb,
                "corona4g"  | "winchester"     => crate::core::data::blocks::NandLayout::Emmc,
                _                              => crate::core::data::blocks::NandLayout::Sb,
            };
            self.enqueue(InternalCommand::CreateImage { layout });
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
        for name in &["smc.bin", "smc_config.bin", "fcrt.bin", "kv.bin", "keyvault.bin"] {
            let p = data_dir.join(name);
            if p.exists() {
                if let Ok(data) = fs::read(&p) {
                    self.pending_assets.insert(name.to_string(), data);
                }
            }
        }

        // Enqueue INI parsing
        self.parse_ini(&ini_path, console_section, &ini_dir, &common_dir, &data_dir);

        // Addon patches
        let addons = self.addons.clone();
        for addon in &addons {
            let addon_path = if PathBuf::from(addon).is_absolute() {
                PathBuf::from(addon)
            } else {
                let p = ini_dir.join(addon);
                if p.exists() { p } else { data_dir.join(addon) }
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

    /// Pulls hardware/image defaults from the active NAND into the session options.
    /// Only populates options that are currently None.
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
                if let Ok((_, ldv)) = Self::resolve_per_box_settings(&self.options, nand) {
                    self.options.cfldv = Some(ldv.to_string());
                }
            }

            // Keyvault Metadata (Region, DVD Key, etc.)
            if let Some(ref mut kv) = nand.kv {
                // If it was decrypted in the skeleton, we can read it
                if !kv.is_decrypted {
                    let cpukey = nand.cpukey.unwrap_or([0u8; 16]);
                    if let Err(e) = kv.decrypt(&cpukey) {
                        warn!("[session] Failed to decrypt Keyvault for metadata extraction: {}", e);
                    }
                }

                if let Some(meta) = &kv.metadata {
                    if self.options.avregion.is_none() {
                        self.options.avregion = Some(format!("0x{:04X}", meta.region));
                    }
                    if self.options.dvdkey.is_none() {
                        self.options.dvdkey = Some(meta.dvd_key.iter().map(|b| format!("{:02x}", b)).collect());
                    }
                }
            }
        }
    }

    /// Pushes the final merged session options back into the NAND skeleton's 
    /// Keyvault and SMC buffers before a build.
    pub fn sync_options_to_nand(&mut self) -> Result<(), String> {
        if let Some(nand) = &mut self.active_nand {
            info!("[session] Syncing merged options to NAND components...");

            // --- 0. Standard/Core Overrides ---
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

            // --- 1. CPU Key ---
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

            // --- 2. Per-box LDV / Pairing Sync for CB + CF ---
            let (pairing, ldv) = Self::resolve_per_box_settings(&self.options, nand)?;
            Self::sync_per_box_settings(nand, pairing, ldv);

            // --- 3. Keyvault Overrides (Region, DVD Key) ---
            if let Some(ref mut kv) = nand.kv {
                // Decrypt with current session key if possible
                if !kv.is_decrypted {
                    if let Err(e) = kv.decrypt(&cpukey) {
                        warn!("[session] Failed to decrypt Keyvault for option patching: {}", e);
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

                    // AV Region sync to KV
                    if let Some(region_str) = &self.options.avregion {
                        let region = Self::parse_u16_hex_or_dec(region_str)?;
                        kv.set_region(region)?;
                    }
                    
                    // Re-encrypt and store Keyvault
                    kv.encrypt(&cpukey)?;
                    nand.extra.keyvault = kv.data.clone();
                }
            }

            // --- 3. SMC Configuration Patching ---
            let mut smc_config = if nand.extra.smc_config.is_empty() {
                info!("[session] No SMC Config found in skeleton, initializing clean defaults.");
                crate::builder::chain::smc::SmcConfig::new_empty()
            } else {
                crate::builder::chain::smc::SmcConfig::parse(&nand.extra.smc_config)?
            };

            // 3a. MAC Address
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

            // 3b. Regions (SMC sync)
            let video = if let Some(s) = &self.options.avregion { Self::parse_u16_hex_or_dec(s)? } else { (smc_config.data[0x22A] as u16) << 8 | smc_config.data[0x22B] as u16 };
            let game = if let Some(s) = &self.options.gameregion { Self::parse_u16_hex_or_dec(s)? } else { (smc_config.data[0x22C] as u16) << 8 | smc_config.data[0x22D] as u16 };
            let dvd = if let Some(s) = &self.options.dvdregion { s.parse::<u8>().unwrap_or(0xFF) } else { smc_config.data[0x237] };
            smc_config.set_regions(video, game, dvd);

            // 3c. Thermals (Targets)
            let cpu_t = if let Some(s) = &self.options.cputemp { Self::parse_u8_hex_or_dec(s)? } else { smc_config.data[0x29] };
            let gpu_t = if let Some(s) = &self.options.gputemp { Self::parse_u8_hex_or_dec(s)? } else { smc_config.data[0x2A] };
            let ram_t = if let Some(s) = &self.options.edramtemp { Self::parse_u8_hex_or_dec(s)? } else { smc_config.data[0x2B] };
            smc_config.set_thermal_targets(cpu_t, gpu_t, ram_t);

            // 3d. Thermals (Max/Limits)
            let cpu_m = if let Some(s) = &self.options.overcputemp { Self::parse_u8_hex_or_dec(s)? } else { smc_config.data[0x2C] };
            let gpu_m = if let Some(s) = &self.options.overgputemp { Self::parse_u8_hex_or_dec(s)? } else { smc_config.data[0x2D] };
            let ram_m = if let Some(s) = &self.options.overedramtemp { Self::parse_u8_hex_or_dec(s)? } else { smc_config.data[0x2E] };
            smc_config.set_thermal_limits(cpu_m, gpu_m, ram_m);

            // 3e. Fans
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

            // --- 4. SMC Code Patching ---
            let mut smc = crate::builder::chain::smc::RawSmc::new(nand.extra.smc.clone());
            smc.decrypt(); // Decrypt using "BuNy"

            // Generic signature patching can be invoked here or via session APIs
            // using the new signature engine.

            smc.encrypt();
            nand.extra.smc = smc.data;
        }
        Ok(())
    }

    /// Applies a batch of signature patches (JSON format) to the active NAND's decrypted SMC.
    /// Returns the total number of patches applied.
    pub fn apply_smc_signature_batch(&mut self, json_str: &str) -> Result<usize, String> {
        if let Some(nand) = &mut self.active_nand {
            info!("[session] Applying signature batch to SMC...");
            let mut smc = crate::builder::chain::smc::RawSmc::new(nand.extra.smc.clone());
            smc.decrypt();
            
            let count = crate::core::data::signature::Signature::apply_batch(&mut smc.data, json_str)?;
            
            smc.encrypt();
            nand.extra.smc = smc.data;
            info!("[session] SMC signature batch applied: {} match(es) patched.", count);
            Ok(count)
        } else {
            Err("No active NAND loaded to patch.".to_string())
        }
    }

    fn parse_u16_hex_or_dec(s: &str) -> Result<u16, String> {
        if s.starts_with("0x") {
            u16::from_str_radix(&s[2..], 16).map_err(|e| format!("Invalid hex u16 '{}': {}", s, e))
        } else {
            s.parse::<u16>().map_err(|e| format!("Invalid decimal u16 '{}': {}", s, e))
        }
    }

    fn parse_u8_hex_or_dec(s: &str) -> Result<u8, String> {
        if s.starts_with("0x") {
            u8::from_str_radix(&s[2..], 16).map_err(|e| format!("Invalid hex u8 '{}': {}", s, e))
        } else {
            s.parse::<u8>().map_err(|e| format!("Invalid decimal u8 '{}': {}", s, e))
        }
    }

    /// Execute a specific queued command by its sequence_id, then remove it from the queue.
    /// Returns `Ok(true)` if found and executed successfully, `Ok(false)` if not found,
    /// or `Err` if the command was found but failed during execution.
    pub fn session_run_once(&mut self, id: usize) -> Result<bool, String> {
        let mut remaining = Vec::new();
        let mut result: Result<bool, String> = Ok(false);
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

    pub fn parse_ini(&mut self, path: impl AsRef<Path>, target: String, ini_base: impl AsRef<Path>, common: impl AsRef<Path>, data: impl AsRef<Path>) {
        self.enqueue(InternalCommand::ParseIni { 
            path: path.as_ref().to_path_buf(), 
            target, 
            ini_base: ini_base.as_ref().to_path_buf(), 
            common: common.as_ref().to_path_buf(),
            data: data.as_ref().to_path_buf() 
        });
    }


    pub fn extract_stfs(&mut self, path: PathBuf, target_dir: PathBuf) {
        self.enqueue(InternalCommand::ExtractStfs { path, target_dir });
    }

    pub fn create_image(&mut self, layout: crate::core::data::blocks::NandLayout) {
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
                    info!("[session] Executing (PriorityScore: {}, Seq: {}): ParseIni {{ path: {:?}, target: {:?} }}", 
                             priority, queued_cmd.sequence_id, path, target);
                }
                cmd => {
                    info!("[session] Executing (PriorityScore: {}, Seq: {}): {:?}", 
                             priority, queued_cmd.sequence_id, cmd);
                }
            }
                     
            self.execute_command(queued_cmd.command)?;
        }
        info!("[session] Finished priority queue batch.");
        Ok(())
    }

    /// Execute a command immediately, bypassing the priority queue entirely.
    pub fn swap_bootloader(&mut self, bl_type: String, path: PathBuf, is_rebooter: bool) {
        self.enqueue(InternalCommand::SwapBootloader { bl_type, path, is_rebooter });
    }

    pub fn run_once(&mut self, command: InternalCommand) -> Result<(), String> {
        info!("[session] Executing command directly (queue bypassed): {:?}", command);
        self.execute_command(command)
    }

    pub fn execute_command(&mut self, command: InternalCommand) -> Result<(), String> {
        match command {
                InternalCommand::ExtractAll => {
                    info!("[session] Extracting all components...");
                    let ids = vec!["smc", "smcc", "kv", "fcrt", "cb", "cba", "cbb", "sc", "cd", "ce", "cf0", "cg0", "cf1", "cg1", "header"];
                    for id in ids {
                        let _ = self.execute_command(InternalCommand::Extract { id: id.to_string() });
                    }
                    info!("[session] Extraction complete.");
                }
                InternalCommand::Extract { id } => {
                    if let Some(nand) = &self.active_nand {
                        let (filename, data) = match id.to_lowercase().as_str() {
                            "smc" => ("SMC.bin", Some(nand.extra.smc.clone())),
                            "smcc" | "smc_config" => ("SMC_Config.bin", Some(nand.extra.smc_config.clone())),
                            "kv" => ("KV.bin", Some(nand.extra.keyvault.clone())),
                            "fcrt" => ("FCRT.bin", nand.extra.fcrt.clone()),
                            "cb" => ("CB.bin", nand.bootloaders.cb.as_ref().map(|b| b.serialize())),
                            "cba" | "cb_a" => ("CBA.bin", nand.bootloaders.cb_a.as_ref().map(|b| b.serialize())),
                            "cbb" | "cb_b" => ("CBB.bin", nand.bootloaders.cb_b.as_ref().map(|b| b.serialize())),
                            "sc" => ("SC.bin", nand.bootloaders.sc.as_ref().map(|b| b.serialize())),
                            "cd" => ("CD.bin", nand.bootloaders.cd.as_ref().map(|b| b.serialize())),
                            "ce" => ("CE.bin", nand.bootloaders.ce.as_ref().map(|b| b.serialize())),
                            "cf0" | "cf_0" => ("CF_0.bin", nand.update.cf_0.as_ref().map(|b| b.serialize())),
                            "cg0" | "cg_0" => ("CG_0.bin", nand.update.cg_0.as_ref().map(|b| b.serialize())),
                            "cf1" | "cf_1" => ("CF_1.bin", nand.update.cf_1.as_ref().map(|b| b.serialize())),
                            "cg1" | "cg_1" => ("CG_1.bin", nand.update.cg_1.as_ref().map(|b| b.serialize())),
                            "header" | "nandhdr" => ("NandHeader.bin", Some(zerocopy::IntoBytes::as_bytes(&nand.header).to_vec())),
                            _ => {
                                error!("[session] Unknown component ID '{}': cannot extract.", id);
                                return Ok(());
                            }
                        };

                        if let Some(bytes) = data {
                            if let Err(e) = fs::write(filename, bytes) {
                                error!("[session] Failed to extract {}: {}", id, e);
                            } else {
                                info!("[session] Extracted {} to {}", id, filename);
                            }
                        }
                    } else {
                        error!("[session] No active NAND loaded. Cannot extract {}.", id);
                    }
                }
                InternalCommand::Build { output, target: _target } => {
                    info!("[session] Building NAND image to '{}'...", output.display());
                    // Sync options before build
                    self.sync_options_to_nand()?;
                    
                    if let Some(nand) = &self.active_nand {
                        let cpukey = nand.cpukey.unwrap_or([0u8; 16]);
                        let layout = nand.layout;
                        
                        let sb_type = SouthbridgeType::from(nand.options.motherboard);
                        let _ = LayoutCalculator::calculate(sb_type, &nand.options.image_profile, layout);

                        let meta_type = match nand.options.motherboard {
                            crate::builder::builder::MotherboardType::Xenon |
                            crate::builder::builder::MotherboardType::Zephyr |
                            crate::builder::builder::MotherboardType::Falcon => crate::core::data::blocks::SpareMetaType::MetaType0,
                            _ => crate::core::data::blocks::SpareMetaType::MetaType1,
                        };

                        match nand.build(cpukey) {
                            Ok(clean_bytes) => {
                                let mut fs_meta = std::collections::HashMap::new();
                                let page_count_encoded = if layout == crate::core::data::blocks::NandLayout::Bb {
                                    match nand.layout {
                                        crate::core::data::blocks::NandLayout::Bb => 0x00,
                                        _ => 0x01,
                                    }
                                } else { 0x01 };

                                let mut all_partitions = std::collections::HashMap::new();
                                if !nand.flashfs.root.entries.is_empty() {
                                    all_partitions.insert(nand.flashfs.root.partition_type, nand.flashfs.root.clone());
                                }

                                for (btype, root) in all_partitions {
                                    if root.block_number < 0 { continue; }
                                    
                                    // Branding strategy: Every block in the FlashFS partition must have 
                                    // the correct partition type (e.g. 0x30) and version sequence in its spare area.
                                    for (val, &block) in root.block_map.iter().enumerate() {
                                        // 0x1FFE is the only marker for a truly 'free' block in the block map.
                                        // All other values (including 0 and 0x1FFF) represent occupied space.
                                        let is_free = (block & 0x7FFF) == 0x1FFE;
                                        
                                        if !is_free {
                                            let absolute_block = val + (root.block_number as usize);
                                            let is_root = val == 0;
                                            
                                            // Branding: Root block gets the partition type (0x30, 0x31, etc.)
                                            // Data blocks technically can also carry the partition type for better discovery.
                                            // RGBuild and others advanced by partition type scanning.
                                            let block_type = if is_root { btype } else { 0x01 };
                                            
                                            fs_meta.insert(absolute_block, crate::core::data::blocks::FsSpareInfo {
                                                sequence: root.version as u32,
                                                size: 0x4000, // Standard 16KB block size (physical)
                                                page_count: page_count_encoded,
                                                block_type,
                                            });
                                        }
                                    }
                                }
                                
                                let jtag_syscall = self.active_nand.as_ref().and_then(|n| n.options.jtag_syscall);
                                let finalized_bytes = crate::core::data::blocks::NandProcessor::finalize_nand(&clean_bytes, layout, meta_type, Some(&fs_meta), jtag_syscall);
                                let final_size = finalized_bytes.len();
                                if let Err(e) = std::fs::write(&output, finalized_bytes) {
                                    error!("[session] Failed to write build output to '{}': {}", output.display(), e);
                                } else {
                                    info!("[session] Build complete: '{}' written ({} bytes, layout {:?})",
                                        output.display(), final_size, layout);
                                }
                            }
                            Err(e) => error!("[session] Build failed: {}", e),
                        }
                    } else {
                        error!("[session] No active NAND loaded to build!");
                    }
                }
                InternalCommand::ParseIni { path, target, ini_base, common, data } => {
                    info!("[session] Parsing INI for target {}...", target);
                    if let Some(nand) = self.active_nand.take() {
                        match crate::core::data::xeini::parse_xe_ini(&path, &target) {
                            Ok(ini) => {
                                match IniSearch::new(ini.clone(), &ini_base, &common, &data, &self.active_nand, self.options.gxunsafe) {
                                    Ok(search) => {
                                        // Route each pool to its typed session pool
                                        self.bootloader_assets.extend(search.result.bootloader_assets);
                                        self.security_assets.extend(search.result.security_assets);
                                        self.flashfs_assets.extend(search.result.flashfs_assets);

                                        // Apply bootloaders using the improved apply_xe_ini
                                        let pending = crate::core::data::xeini::PendingAssets {
                                            bootloaders: &self.bootloader_assets,
                                            security: &self.security_assets,
                                        };
                                        match crate::core::data::xeini::apply_xe_ini(nand, ini, pending) {
                                            Ok(updated_nand) => {
                                                self.active_nand = Some(updated_nand);
                                                info!("[session] INI bootloaders and assets applied to NAND skeleton.");
                                            }
                                            Err(e) => {
                                                error!("[session] Failed to apply INI data: {}", e);
                                                return Err(format!("Applied INI data failed: {}", e));
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("[session] Configuration discovery failed: {}", e);
                                        return Err(format!("Discovery failed: {}", e));
                                    }
                                }
                            }
                            Err(e) => {
                                self.active_nand = Some(nand);
                                return Err(format!("Failed parsing INI descriptors: {}", e));
                            }
                        }
                    } else {
                        return Err("No active NAND skeleton active to apply INI map onto!".to_string());
                    }
                }
                InternalCommand::ParseImage { path, key } => {
                    info!("[session] Parsing image {:?}...", path);
                    match fs::read(&path) {
                        Ok(raw_data) => {
                            // Use preprocess_nand_with_lba to track bad block remapping
                            match crate::core::data::blocks::NandProcessor::preprocess_nand_with_lba(&raw_data) {
                                Ok((clean_data, layout, lba_map)) => {
                                    info!("[session] Detected {} bad block(s) during preprocessing", lba_map.bad_blocks.len());
                                    // Use provided key or buffered pending key
                                    let active_key = key.or(self.pending_key).unwrap_or([0u8; 16]);
                                    
                                    // Scan FlashFS with LBA map for accurate block mapping
                                    let flashfs = crate::builder::chain::flashfs::FlashFS::scan_physical_with_lba(&raw_data, &layout, &lba_map);
                                    match NandSkeleton::parse_clean(clean_data, layout, active_key, flashfs) {
                                        Ok(nand) => {
                                            // Verify bootloader decryption using zero-region checks
                                            if let Some(cb) = &nand.bootloaders.cb_a {
                                                if cb.verify_decrypted() {
                                                    info!("[session] CB_A decryption verified (zero-region check passed).");
                                                } else {
                                                    log::warn!("[session] CB_A decryption verification failed - data may be corrupted.");
                                                }
                                            }
                                            for (i, cf_opt) in [&nand.update.cf_0, &nand.update.cf_1].iter().enumerate() {
                                                if let Some(cf) = cf_opt {
                                                    if cf.verify_decrypted() {
                                                        info!("[session] CF_{} decryption verified.", i);
                                                    } else {
                                                        log::warn!("[session] CF_{} decryption verification failed.", i);
                                                    }
                                                }
                                            }
                                            // Store LBA map in session for later use
                                            info!("[session] LBA Map: {} total blocks, {} bad blocks remapped",
                                                lba_map.logical_to_physical.len(), lba_map.bad_blocks.len());
                                            self.active_nand = Some(nand);
                                            self.extract_options_from_nand();
                                            info!("[session] Successfully parsed NAND from {:?} (Layout: {:?})", path, layout);
                                        }
                                        Err(e) => return Err(format!("Failed to interpret clean NAND: {}", e)),
                                    }
                                }
                                Err(e) => return Err(format!("Failed to pre-process NAND image: {}", e)),
                            }
                        }
                        Err(e) => return Err(format!("Failed to read image file '{}': {}", path.display(), e)),
                    }
                }
                InternalCommand::ParseKey { key } => {
                    self.pending_key = Some(key);
                    if let Some(nand) = &mut self.active_nand {
                        nand.cpukey = Some(key);
                        info!("[session] CPU Key assigned to active NAND.");
                    } else {
                        info!("[session] CPU Key buffered (awaiting NAND image).");
                    }
                }
                InternalCommand::ParseKeybin { key } => {
                    if let Some(k) = key {
                        self.pending_key = Some(k);
                        if let Some(nand) = &mut self.active_nand {
                            nand.cpukey = Some(k);
                            info!("[session] CPU Keybin assigned to active NAND.");
                        } else {
                            info!("[session] CPU Keybin buffered (awaiting NAND image).");
                        }
                    } else {
                        error!("[session] No key provided in keybin.");
                    }
                }
                InternalCommand::ParseFlashfs { path } => {
                    info!("[session] Preparing to build flashfs from folder {:?}...", path);
                    if let Some(nand) = &mut self.active_nand {
                        if matches!(nand.layout, crate::core::data::blocks::NandLayout::Emmc) {
                            return Err("eMMC FlashFS building/injection is not yet implemented (different metadata structure).".to_string());
                        }
                        // Use layout-specific defaults for FlashFS start block, not the parsed NAND's root block.
                        let fs_start: u16 = match nand.layout {
                            crate::core::data::blocks::NandLayout::Bb => 0x1E0,
                            _ => 0x4E,  // Small block default: block 78
                        };
                        match crate::builder::chain::flashfs::FileSystemRoot::build_from_folder(&mut nand.image, &nand.layout, &path, fs_start, 0x30) {
                            Ok(new_root) => {
                                nand.flashfs.root = new_root;
                                info!("[session] FlashFS constructed and injected successfully.");
                            }
                            Err(e) => error!("[session] Failed to build FlashFS from folder: {}", e),
                        }
                    } else {
                        error!("[session] No active NAND loaded to parse FlashFS into.");
                    }
                }
                InternalCommand::ParsePatch { path } => {
                    info!("[session] Parsing patch binary from {:?}...", path);
                    match parse_patch_binary(path) {
                        Ok(patch) => {
                            info!("[session] Successfully parsed patch: Type {:?}, Legacy: {}", 
                                     patch.header.patch_type, patch.is_legacy);
                        }
                        Err(e) => return Err(format!("Failed to parse patch binary: {}", e)),
                    }
                }
                InternalCommand::ApplyPatch { path, .. } => {
                    info!("[session] Applying patch {:?} (GXP Logic)...", path);
                    if let Some(nand) = &mut self.active_nand {
                        match parse_patch_binary(path) {
                            Ok(patch) => {
                                if let Err(e) = nand.apply_patch(patch) {
                                    return Err(format!("Failed to apply patch: {}", e));
                                } else {
                                    info!("[session] Successfully applied patch and routed components.");
                                }
                            }
                            Err(e) => error!("[session] Failed to parse patch binary: {}", e),
                        }
                    } else {
                        error!("[session] No active NAND loaded to patch.");
                    }
                }
                InternalCommand::SwapBootloader { bl_type, path, is_rebooter } => {
                    info!("[session] Swapping bootloader {} with {:?} (Rebooter: {})...", bl_type, path, is_rebooter);
                    if let Some(nand) = &mut self.active_nand {
                        let target = if is_rebooter {
                            if nand.rebooter.is_none() {
                                nand.rebooter = Some(crate::builder::builder::NandBootloaders::new());
                            }
                            nand.rebooter.as_mut().unwrap()
                        } else {
                            &mut nand.bootloaders
                        };

                        let data = fs::read(&path).map_err(|e| format!("Failed to read swap bootloader: {}", e))?;
                        match bl_type.to_lowercase().as_str() {
                            "cb" | "cba" | "cbb" | "cbx" => {
                                let bl = crate::builder::chain::cb::BootloaderCb::parse(&data)?;
                                match bl_type.to_lowercase().as_str() {
                                    "cb"  => target.cb = Some(bl),
                                    "cba" => target.cb_a = Some(bl),
                                    "cbb" => target.cb_b = Some(bl),
                                    "cbx" => target.cb_x = Some(bl),
                                    _ => unreachable!(),
                                }
                            }
                            "cd" => {
                                let bl = crate::builder::chain::cd::BootloaderCd::parse(&data)?;
                                target.cd = Some(bl);
                            }
                            "ce" => {
                                let bl = crate::builder::chain::ce::BootloaderCe::parse(&data)?;
                                target.ce = Some(bl);
                            }
                            "cf" => {
                                let bl = crate::builder::chain::cf::BootloaderCf::parse(&data)?;
                                if is_rebooter {
                                    if nand.rebooter_update.is_none() { nand.rebooter_update = Some(Default::default()); }
                                    nand.rebooter_update.as_mut().unwrap().cf_0 = Some(bl);
                                } else {
                                    nand.update.cf_0 = Some(bl);
                                }
                            }
                            "cg" => {
                                let bl = crate::builder::chain::cg::BootloaderCg::parse(&data)?;
                                if is_rebooter {
                                    if nand.rebooter_update.is_none() { nand.rebooter_update = Some(Default::default()); }
                                    nand.rebooter_update.as_mut().unwrap().cg_0 = Some(bl);
                                } else {
                                    nand.update.cg_0 = Some(bl);
                                }
                            }
                            "smc" => {
                                nand.extra.smc = data;
                            }
                            _ => return Err(format!("Unknown bootloader type: {}", bl_type)),
                        }
                        info!("[session] Bootloader {} swapped successfully.", bl_type);
                    } else {
                        return Err("No active NAND loaded. Cannot swap bootloader.".to_string());
                    }
                }
                InternalCommand::Replace { id, path } => {
                    println!(" -> Replacing element {} with {:?}...", id, path);
                    if let Some(nand) = &mut self.active_nand {
                        if let Ok(data) = fs::read(&path) {
                            match id {
                                1 => nand.extra.smc = data,
                                2 => nand.extra.keyvault = data,
                                _ => eprintln!(" -> Unhandled Replace ID {}", id),
                            }
                        } else {
                            eprintln!(" -> Failed to read replace payload.");
                        }
                    }
                }
                InternalCommand::List => {
                    if let Some(nand) = &self.active_nand {
                        nand.header.print_info();
                        info!("[session] Bootloaders Present: CB: {} | CD: {} | CE: {}", 
                            nand.bootloaders.cb.is_some(), 
                            nand.bootloaders.cd.is_some(), 
                            nand.bootloaders.ce.is_some()
                        );
                    } else {
                        info!("[session] Active NAND is empty.");
                    }
                }
                InternalCommand::Delete { id } => {
                    info!("[session] Deleting element {}...", id);
                    if let Some(nand) = &mut self.active_nand {
                        match id {
                            1 => nand.extra.smc = Vec::new(),
                            3 => nand.bootloaders.cb = None,
                            _ => error!("[session] Unhandled Delete ID {}", id),
                        }
                    }
                }
                InternalCommand::Clear => {
                    self.active_nand = None;
                    self.pending_assets.clear();
                    self.bootloader_assets.clear();
                    self.security_assets.clear();
                    self.flashfs_assets.clear();
                    info!("[session] Active NAND and all asset pools cleared.");
                }
                InternalCommand::Compress => {
                    info!("[session] Compress logic hooks to mspack / xenia (Not Yet Invoked)");
                }
                InternalCommand::Decompress => {
                    info!("[session] Decompressing CE Base Kernel payload...");
                    if let Some(nand) = &mut self.active_nand {
                        if let Some(ce) = &mut nand.bootloaders.ce {
                            match ce.decompress() {
                                Ok(kernel_payload) => {
                                    ce.data_kernel = Some(kernel_payload.clone());
                                    // Optionally dump to verification file locally
                                    let _ = std::fs::write("Kernel-Decompressed.bin", &kernel_payload);
                                    info!("[session] CE Base Kernel successfully decompressed! (0x{:X} bytes)", kernel_payload.len());
                                }
                                Err(e) => error!("[session] CE decompression failed: {}", e),
                            }
                        } else {
                            error!("[session] Active NAND does not contain a CE bootloader to decompress.");
                        }
                    } else {
                        error!("[session] No active NAND loaded. Cannot run Decompress.");
                    }
                }
                InternalCommand::SessionInit { base, common } => {
                    info!("[session] Initializing session with base {:?} and common {:?}", base, common);
                }
                InternalCommand::SessionList => {
                    info!("[session] Queue:");
                    for q in self.queue.iter() {
                        info!("[session]   [Priority {}] Seq {}: {:?}", q.command.priority_score(), q.sequence_id, q.command);
                    }
                }
                InternalCommand::SessionDelete { id } => {
                    let mut temp = Vec::new();
                    let mut found = false;
                    while let Some(q) = self.queue.pop() {
                        if q.sequence_id != id as usize {
                            temp.push(q);
                        } else {
                            found = true;
                            info!("[session] Deleted sequence {}.", id);
                        }
                    }
                    if !found {
                        error!("[session] Sequence {} not found in queue.", id);
                    }
                    for q in temp {
                        self.queue.push(q);
                    }
                }
                InternalCommand::SessionRun => {
                    // Execute all queued commands in priority order, clearing the queue.
                    // Swap out the queue so the while-let loop in run() is naturally empty
                    // after we return, preventing re-entry issues.
                    let commands: Vec<QueuedCommand> = self.queue.drain().collect();
                    info!("[session] SessionRun: executing {} queued commands in priority order.", commands.len());
                    for queued_cmd in commands {
                        let priority = queued_cmd.command.priority_score();
                        match &queued_cmd.command {
                            InternalCommand::ParseIni { path, target, .. } => {
                                info!("[session] SessionRun Executing (PriorityScore: {}, Seq: {}): ParseIni {{ path: {:?}, target: {:?} }}",
                                         priority, queued_cmd.sequence_id, path, target);
                            }
                            cmd => {
                                info!("[session] SessionRun Executing (PriorityScore: {}, Seq: {}): {:?}",
                                         priority, queued_cmd.sequence_id, cmd);
                            }
                        }
                        self.execute_command(queued_cmd.command)?;
                    }
                    info!("[session] SessionRun: queue cleared.");
                }
                InternalCommand::CreateImage { layout } => {
                    let blank = NandSkeleton::new_blank(layout);
                    info!("[session] Created blank NAND skeleton: layout {:?}, {} blocks ({} MB)",
                        layout,
                        blank.total_blocks,
                        blank.image.len() / (1024 * 1024));
                    self.active_nand = Some(blank);
                }
                InternalCommand::Update { path } => {
                    info!("[session] Loading asset discovery from {:?}...", path);
                    match fs::read(&path) {
                        Ok(data) => {
                            let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                            self.pending_assets.insert(name.clone(), data);
                            info!("[session] Discovered asset '{}' added to session pool.", name);
                        }
                        Err(e) => return Err(format!("Failed to read asset at {:?}: {}", path, e)),
                    }
                }
                InternalCommand::FinalizeFlashfs => {
                    if !self.flashfs_assets.is_empty() {
                        info!("[session] Finalizing FlashFS with {} collected assets...", self.flashfs_assets.len());
                        if let Some(nand) = &mut self.active_nand {
                            // Use layout-specific defaults for FlashFS start block, NOT the parsed
                            // NAND's root block. The original NAND's FlashFS root was placed based
                            // on its own file content and growth pattern. A new build should start
                            // fresh at the standard location.
                            let fs_start: u16 = match nand.layout {
                                crate::core::data::blocks::NandLayout::Bb => 0x1E0,
                                _ => 0x4E,  // Small block default: block 78
                            };
                            info!("[session] FlashFS start block: 0x{:X} ({})", fs_start, fs_start);
                            match crate::builder::chain::flashfs::FileSystemRoot::build_from_memory(&mut nand.image, &nand.layout, &self.flashfs_assets, fs_start, 0x30) {
                                Ok(new_root) => {
                                    nand.flashfs.root = new_root;
                                    info!(" -> FlashFS generation complete.");
                                },
                                Err(e) => return Err(format!("FlashFS Build Error: {}", e)),
                            }
                        }
                    }
                }
                InternalCommand::ExtractStfs { path, target_dir } => {
                    info!("[session] Extracting STFS container from {:?} to {:?}...", path, target_dir);
                    match fs::read(&path) {
                        Ok(data) => {
                            match crate::core::data::stfs::StfsContainer::new(&data) {
                                Ok(container) => {
                                    if let Err(e) = container.extract_all(&target_dir) {
                                        return Err(format!("STFS Extraction Error: {}", e));
                                    }
                                    println!(" -> STFS extraction complete.");
                                }
                                Err(e) => return Err(format!("STFS Format Error: {}", e)),
                            }
                        }
                        Err(e) => return Err(format!("Failed to read STFS file: {}", e)),
                    }
                }
            }
        
        Ok(())
    }
}
