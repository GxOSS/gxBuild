/*
    session.rs - Session management and command queue

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::path::{Path, PathBuf};

use crate::builder::builder::NandSkeleton;
use std::fs;
#[cfg(feature = "python")]
use crate::core::interface::python::{python_interpreter, python_shell, python_script};
use crate::core::data::gxp::parse_patch_binary;
use crate::core::data::filesearch::IniSearch;
use log::{info, error, warn};
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
    #[cfg(feature = "python")]
    PythonShell,
    #[cfg(feature = "python")]
    RunPythonScript { path: PathBuf },
    CreateImage { layout: crate::core::data::blocks::NandLayout },
    ExtractStfs { path: PathBuf, target_dir: PathBuf },
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
    ///     2 - RunPythonScript
    ///     1 - PythonShell
    ///     0 - Build: always the final step
    fn priority_score(&self) -> u8 {
        match self {
            // ── Foundation ────────────────────────────────────────────────
            Self::ParseImage { .. }   => 150,
            Self::CreateImage { .. }  => 150,
            // ── Key assignment (must follow ParseImage) ───────────────────
            Self::ParseKey { .. }     => 145,
            Self::ParseKeybin { .. }  => 145,
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
            // ── Scripting ─────────────────────────────────────────────────
            #[cfg(feature = "python")]
            Self::RunPythonScript { .. } => 2,
            #[cfg(feature = "python")]
            Self::PythonShell            => 1,
            // ── Build: always last ────────────────────────────────────────
            Self::Build { .. }        => 0,
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
            active_nand: None,
            options: crate::core::data::xeini::OptionsIni::new(),
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

    /// Pulls hardware/image defaults from the active NAND into the session options.
    /// Only populates options that are currently None.
    pub fn extract_options_from_nand(&mut self) {
        if let Some(nand) = &self.active_nand {
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

            // Keyvault Metadata (Region, DVD Key, etc.)
            // We can re-parse the KV to get the latest info
            if let Ok(mut kv) = crate::builder::chain::kv::Keyvault::parse(&nand.extra.keyvault) {
                // If it was decrypted in the skeleton, we can read it
                let cpukey = nand.cpukey.unwrap_or([0u8; 16]);
                if let Ok(_) = kv.decrypt(&cpukey, nand.header.kv_version.get() >= 2) {
                    if let Some(meta) = kv.metadata {
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

            // --- 2. CF/CG LDV Overrides ---
            if let Some(cfldv_str) = &self.options.cfldv {
                let ldv = Self::parse_u8_hex_or_dec(cfldv_str)?;
                
                // Update primary CF (slot 0) if it exists
                if let Some(ref mut cf) = nand.update.cf_0 {
                    if let Some(ref mut meta) = cf.metadata {
                        meta.lockdown_value = ldv;
                        cf.sync_metadata();
                    } else {
                        // Patch direct offset if metadata wasn't parsed (plain/encrypted fallback)
                        if cf.data.len() > 0x20F {
                            cf.data[0x20F] = ldv;
                        }
                    }
                }
                
                // Update secondary CF (slot 1) if it exists
                if let Some(ref mut cf) = nand.update.cf_1 {
                    if let Some(ref mut meta) = cf.metadata {
                        meta.lockdown_value = ldv;
                        cf.sync_metadata();
                    } else {
                        if cf.data.len() > 0x20F {
                            cf.data[0x20F] = ldv;
                        }
                    }
                }
            }

            // --- 3. Keyvault Overrides (Region, DVD Key) ---
            let mut kv = crate::builder::chain::kv::Keyvault::parse(&nand.extra.keyvault)?;
            
            // Decrypt with current session key if possible
            if let Err(e) = kv.decrypt(&cpukey, nand.header.kv_version.get() >= 2) {
                warn!("[session] Failed to decrypt Keyvault for option patching: {}", e);
            } else {
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
                kv.encrypt(&cpukey, nand.header.kv_version.get() >= 2)?;
                nand.extra.keyvault = kv.data;
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

    #[cfg(feature = "python")]
    pub fn run_python_script(&mut self, path: impl AsRef<Path>) {
        self.enqueue(InternalCommand::RunPythonScript { path: path.as_ref().to_path_buf() });
    }

    #[cfg(feature = "python")]
    pub fn open_python_shell(&mut self) {
        self.enqueue(InternalCommand::PythonShell);
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

    // ------------------------------------
    // Execution core
    // ------------------------------------
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
                        match nand.build(cpukey) {
                            Ok(clean_bytes) => {
                                let mut fs_meta = std::collections::HashMap::new();
                                let page_count_encoded = if layout == crate::core::data::blocks::NandLayout::Bb {
                                    (layout.logical_pages_per_block() / 4) as u8
                                } else {
                                    layout.logical_pages_per_block() as u8
                                };
                                
                                for (val, &block) in nand.flashfs.root.block_map.iter().enumerate() {
                                    if block != 0 && block != 0x1FFE {
                                        let is_root = val == nand.flashfs.root.block_number as usize;
                                        let btype = if is_root { 0x30 } else { 0x01 };
                                        let fs_size = if is_root { (layout.logical_pages_per_block() * 0x200) as u16 } else { 0 };
                                        
                                        fs_meta.insert(val, crate::core::data::blocks::FsSpareInfo {
                                            sequence: nand.flashfs.root.version as u32,
                                            size: fs_size,
                                            page_count: page_count_encoded,
                                            block_type: btype,
                                        });
                                    }
                                }
                                
                                let finalized_bytes = crate::core::data::blocks::NandProcessor::finalize_nand(&clean_bytes, layout, Some(&fs_meta));
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
                #[cfg(feature = "python")]
                InternalCommand::RunPythonScript { path } => {
                    let interp = python_interpreter();
                    if let Err(e) = python_script(&interp, &path) {
                        error!("[session] Python script execution failed: {}", e);
                    }
                }
                #[cfg(feature = "python")]
                InternalCommand::PythonShell => {
                    let interp = python_interpreter();
                    if let Err(e) = python_shell(&interp) {
                        error!("[session] Python shell exited with error: {}", e);
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
                                    // Scan FlashFS with LBA map for accurate block mapping
                                    let flashfs = crate::builder::chain::flashfs::FlashFS::scan_physical_with_lba(&raw_data, &layout, &lba_map);
                                    match NandSkeleton::parse_clean(clean_data, layout, key.unwrap_or([0u8; 16]), flashfs) {
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
                                        Err(e) => error!("[session] Failed to interpret clean NAND: {}", e),
                                    }
                                }
                                Err(e) => error!("[session] Failed to pre-process NAND image: {}", e),
                            }
                        }
                        Err(e) => error!("[session] Failed to read image file '{}': {}", path.display(), e),
                    }
                }
                InternalCommand::ParseKey { key } => {
                    if let Some(nand) = &mut self.active_nand {
                        nand.cpukey = Some(key);
                        info!("[session] CPU Key set (16 bytes).");
                    } else {
                        error!("[session] No active NAND image to assign key to.");
                    }
                }
                InternalCommand::ParseKeybin { key } => {
                    if let Some(k) = key {
                        if let Some(nand) = &mut self.active_nand {
                            nand.cpukey = Some(k);
                            info!("[session] CPU Keybin assigned.");
                        } else {
                            error!("[session] No active NAND image to assign keybin to.");
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
                        match crate::builder::chain::flashfs::FileSystemRoot::build_from_folder(&mut nand.image, &nand.layout, &path, fs_start) {
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
                        Err(e) => error!("[session] Failed to parse patch binary: {}", e),
                    }
                }
                InternalCommand::ApplyPatch { path, .. } => {
                    info!("[session] Applying patch {:?} (GXP Logic)...", path);
                    if let Some(nand) = &mut self.active_nand {
                        match parse_patch_binary(path) {
                            Ok(patch) => {
                                if let Err(e) = nand.apply_patch(patch) {
                                    error!("[session] Failed to apply patch: {}", e);
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
                        Err(e) => error!("[session] Failed to read asset at {:?}: {}", path, e),
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
                            match crate::builder::chain::flashfs::FileSystemRoot::build_from_memory(&mut nand.image, &nand.layout, &self.flashfs_assets, fs_start) {
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