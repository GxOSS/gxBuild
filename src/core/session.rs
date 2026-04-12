/*
    session.rs
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::path::{Path, PathBuf};

use crate::builder::builder::NandSkeleton;
use std::fs;
#[cfg(feature = "python")]
use crate::core::interface::python::{python_interpreter, python_shell, python_script};
use crate::builder::tools::xebuild::{parse_xe_binary, apply_xe_patch};
#[derive(Debug)]
pub enum InternalCommand { 
    ParseIni { content: String, target: String, ini_base: PathBuf, common: PathBuf },
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
    SessionClear,
    SessionRun,
    #[cfg(feature = "python")]
    PythonShell,
    #[cfg(feature = "python")]
    RunPythonScript { path: PathBuf },
    CreateImage { layout: crate::builder::tools::blocks::NandLayout },
    ExtractStfs { path: PathBuf, target_dir: PathBuf },
}

impl InternalCommand {
    /// Higher first, 100 run immediately.
    fn priority_score(&self) -> u8 {
        match self {
            Self::SessionInit { .. } => 100,
            Self::SessionList => 100,
            Self::SessionDelete { .. } => 100,
            Self::SessionClear => 100,
            Self::SessionRun => 100,
            Self::CreateImage { .. } => 150,
            Self::ExtractStfs { .. } => 110,
            Self::Update { .. } => 110,
            Self::ParseIni { .. } => 100,
            Self::ParseImage { .. } => 150,
            Self::ParseKey { .. } => 150,
            Self::ParseKeybin { .. } => 150,
            Self::ParseFlashfs { .. } => 100,
            Self::ParsePatch { .. } => 100,
            Self::Decompress => 99,
            Self::FinalizeFlashfs => 90,
            Self::Extract { .. } => 89,
            Self::ExtractAll => 88,
            Self::Replace { .. } => 87,
            Self::List => 86,
            Self::Delete { .. } => 85,
            Self::Clear => 84,
            Self::ApplyPatch { .. } => 79,
            Self::Compress => 78,
            #[cfg(feature = "python")]
            Self::RunPythonScript { .. } => 2,
            #[cfg(feature = "python")]
            Self::PythonShell => 1,
            Self::Build { .. } => 0,
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
    /// Assets gathered during discovery (Base Dir, flashfs/, STFS)
    pub pending_assets: HashMap<String, Vec<u8>>,
    /// Dummy state object for passing over to extract commands
    pub active_nand: Option<NandSkeleton>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
            next_seq_id: 0,
            pending_assets: HashMap::new(),
            active_nand: None,
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
        self.enqueue(InternalCommand::SessionClear);
    }

    pub fn session_run(&mut self) {
        self.enqueue(InternalCommand::SessionRun);
    }

    pub fn session_run_once(&mut self, _id: u8) {
        self.enqueue(InternalCommand::SessionRun);
    }

    pub fn session_close(&mut self) {
        self.enqueue(InternalCommand::SessionClear);
    }

    pub fn parse_ini(&mut self, content: String, target: String, ini_base: impl AsRef<Path>, common: impl AsRef<Path>) {
        self.enqueue(InternalCommand::ParseIni { 
            content, 
            target, 
            ini_base: ini_base.as_ref().to_path_buf(), 
            common: common.as_ref().to_path_buf() 
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

    // ------------------------------------
    // Execution core
    // ------------------------------------
    pub fn run(&mut self) -> Result<(), String> {
        println!("[Session] Running {} queued commands...", self.queue.len());
        
        while let Some(queued_cmd) = self.queue.pop() {
            let priority = queued_cmd.command.priority_score();
            println!("[Session] Executing (PriorityScore: {}, Seq: {}): {:?}", 
                     priority, queued_cmd.sequence_id, queued_cmd.command);
                     
            self.execute_command(queued_cmd.command)?;
        }
        println!("[Session] Finished priority queue batch.");
        Ok(())
    }

    pub fn run_once(&mut self, command: InternalCommand) -> Result<(), String> {
        println!("[Session] Running executed command actively out of queue...");
        self.execute_command(command)
    }

    pub fn execute_command(&mut self, command: InternalCommand) -> Result<(), String> {
        match command {
                InternalCommand::ExtractAll => {
                    println!(" -> Extracting all components...");
                    let ids = vec!["smc", "kv", "fcrt", "cb", "cba", "cbb", "sc", "cd", "ce", "cf0", "cg0", "cf1", "cg1"];
                    for id in ids {
                        let _ = self.execute_command(InternalCommand::Extract { id: id.to_string() });
                    }
                    println!(" -> Extraction complete.");
                }
                InternalCommand::Extract { id } => {
                    if let Some(nand) = &self.active_nand {
                        let (filename, data) = match id.to_lowercase().as_str() {
                            "smc" => ("SMC.bin", Some(nand.extra.smc.clone())),
                            "smcc" => ("SMCC.bin", Some(nand.extra.smc_config.clone())),
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
                                eprintln!(" -> Unknown component ID to extract: {}", id);
                                return Ok(());
                            }
                        };

                        if let Some(bytes) = data {
                            if let Err(e) = fs::write(filename, bytes) {
                                eprintln!(" -> Failed to extract {}: {}", id, e);
                            } else {
                                println!(" -> Extracted {} to {}", id, filename);
                            }
                        }
                    } else {
                        eprintln!(" -> No active NAND loaded. Cannot extract {}.", id);
                    }
                }
                InternalCommand::Build { output, target: _target } => {
                    println!(" -> Building image to {:?}...", output);
                    if let Some(nand) = &self.active_nand {
                        let cpukey = nand.cpukey.unwrap_or([0u8; 16]);
                        match nand.build(cpukey) {
                            Ok(bytes) => {
                                if let Err(e) = std::fs::write(&output, bytes) {
                                    eprintln!(" -> Failed to write build output: {}", e);
                                } else {
                                    println!(" -> Build completed successfully.");
                                }
                            }
                            Err(e) => eprintln!(" -> Build failed: {}", e),
                        }
                    } else {
                        eprintln!(" -> No active NAND loaded to build!");
                    }
                }
                InternalCommand::ParseIni { content, target, ini_base, common } => {
                    println!(" -> Parsing INI for target {}...", target);
                    if let Some(nand) = self.active_nand.take() {
                        match crate::core::data::xeini::parse_xe_ini(&content, &target, &ini_base, &common) {
                            Ok(parsed_cfg) => {
                                // 1. Collect FlashFS/Security assets from INI
                                let mut file_entries = parsed_cfg.security.clone();
                                file_entries.extend(parsed_cfg.flashfs.clone());
                                for entry in file_entries {
                                    if let Ok(data) = fs::read(&entry.path) {
                                        let name = entry.path.file_name().unwrap_or_default().to_string_lossy().to_string();
                                        println!(" -> INI Discovery: Asset {} from {:?}", name, entry.path);
                                        self.pending_assets.entry(name).or_insert(data);
                                    }
                                }

                                // 2. Apply bootloaders
                                match crate::core::data::xeini::apply_xe_ini(nand, parsed_cfg, &self.pending_assets) {
                                    Ok(updated_nand) => {
                                        self.active_nand = Some(updated_nand);
                                        println!(" -> INI Bootloaders applied natively!");
                                    }
                                    Err(e) => {
                                        return Err(format!("Applied INI data failed due to bindings error: {}", e));
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
                        eprintln!(" -> Python Execution Error: {}", e);
                    }
                }
                #[cfg(feature = "python")]
                InternalCommand::PythonShell => {
                    let interp = python_interpreter();
                    if let Err(e) = python_shell(&interp) {
                        eprintln!(" -> Python Shell Error: {}", e);
                    }
                }
                InternalCommand::ParseImage { path, key } => {
                    println!(" -> Parsing image {:?}...", path);
                    match NandSkeleton::parse_nand(&path, key.unwrap_or([0u8; 16])) {
                        Ok(nand) => {
                            self.active_nand = Some(nand);
                            println!(" -> Successfully parsed NAND from {:?}", path);
                        }
                        Err(e) => eprintln!(" -> Failed to parse NAND: {}", e),
                    }
                }
                InternalCommand::ParseKey { key } => {
                    if let Some(nand) = &mut self.active_nand {
                        nand.cpukey = Some(key);
                        println!(" -> CPU Key set (16 bytes).");
                    } else {
                        eprintln!(" -> No active NAND image to assign key to.");
                    }
                }
                InternalCommand::ParseKeybin { key } => {
                    if let Some(k) = key {
                        if let Some(nand) = &mut self.active_nand {
                            nand.cpukey = Some(k);
                            println!(" -> CPU Keybin assigned.");
                        } else {
                            eprintln!(" -> No active NAND image to assign keybin to.");
                        }
                    } else {
                        eprintln!(" -> No key provided in keybin.");
                    }
                }
                InternalCommand::ParseFlashfs { path } => {
                    println!(" -> Preparing to build flashfs from folder {:?}...", path);
                    if let Some(nand) = &mut self.active_nand {
                        if matches!(nand.layout, crate::builder::tools::blocks::NandLayout::Emmc) {
                            return Err("eMMC FlashFS building/injection is not yet implemented (different metadata structure).".to_string());
                        }
                        let fs_start = match nand.layout { crate::builder::tools::blocks::NandLayout::Bb => 0x1E0, _ => 0x4E };
                        match crate::builder::chain::flashfs::FileSystemRoot::build_from_folder(&mut nand.image, &nand.layout, &path, fs_start) {
                            Ok(new_root) => {
                                nand.flashfs.root = new_root;
                                println!(" -> FlashFS constructed and injected successfully.");
                            }
                            Err(e) => eprintln!(" -> Failed to build FlashFS from folder: {}", e),
                        }
                    } else {
                        eprintln!(" -> No active NAND loaded to parse FlashFS into.");
                    }
                }
                InternalCommand::ParsePatch { path } => {
                    println!(" -> Parsing patch binary from {:?}...", path);
                    match parse_xe_binary(path.to_str().unwrap_or_default()) {
                        Ok(xe_patch) => {
                            println!(" -> Successfully parsed patch: Type {:?}, {} KHV records", 
                                     xe_patch.xetype, 
                                     xe_patch.khv.as_ref().map(|k| k.records.len()).unwrap_or(0));
                        }
                        Err(e) => eprintln!(" -> Failed to parse patch binary: {}", e),
                    }
                }
                InternalCommand::ApplyPatch { path, ptype, target } => {
                    println!(" -> Applying patch {:?} (type {}, target {:?})...", path, ptype, target);
                    if let Some(nand) = &mut self.active_nand {
                        match parse_xe_binary(path.to_str().unwrap_or_default()) {
                            Ok(xe_patch) => {
                                if let Err(e) = apply_xe_patch(xe_patch, nand) {
                                    eprintln!(" -> Failed to apply patch: {}", e);
                                } else {
                                    println!(" -> Successfully applied patch and routed KHV to NAND options.");
                                }
                            }
                            Err(e) => eprintln!(" -> Failed to parse xePatch binary: {}", e),
                        }
                    } else {
                        eprintln!(" -> No active NAND loaded to patch.");
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
                        println!(" -> Bootloaders Present: CB: {} | CD: {} | CE: {}", 
                            nand.bootloaders.cb.is_some(), 
                            nand.bootloaders.cd.is_some(), 
                            nand.bootloaders.ce.is_some()
                        );
                    } else {
                        println!(" -> Active NAND is empty.");
                    }
                }
                InternalCommand::Delete { id } => {
                    println!(" -> Deleting element {}...", id);
                    if let Some(nand) = &mut self.active_nand {
                        match id {
                            1 => nand.extra.smc = Vec::new(),
                            3 => nand.bootloaders.cb = None,
                            _ => eprintln!(" -> Unhandled Delete ID {}", id),
                        }
                    }
                }
                InternalCommand::Clear => {
                    self.active_nand = None;
                    println!(" -> Active NAND cleared.");
                }
                InternalCommand::Compress => {
                    println!(" -> Compress logic hooks to mspack / xenia (Not Yet Invoked)");
                }
                InternalCommand::Decompress => {
                    println!(" -> Decompressing CE Base Kernel payload...");
                    if let Some(nand) = &mut self.active_nand {
                        if let Some(ce) = &mut nand.bootloaders.ce {
                            match ce.decompress() {
                                Ok(kernel_payload) => {
                                    ce.data_kernel = Some(kernel_payload.clone());
                                    // Optionally dump to verification file locally
                                    let _ = std::fs::write("Kernel-Decompressed.bin", &kernel_payload);
                                    println!(" -> CE Base Kernel successfully decompressed! (0x{:X} bytes)", kernel_payload.len());
                                }
                                Err(e) => eprintln!(" -> CE decompression failed: {}", e),
                            }
                        } else {
                            eprintln!(" -> Active NAND does not contain a CE bootloader to decompress.");
                        }
                    } else {
                        eprintln!(" -> No active NAND loaded. Cannot run Decompress.");
                    }
                }
                InternalCommand::SessionInit { base, common } => {
                    println!(" -> Initializing session with base {:?} and common {:?}", base, common);
                }
                InternalCommand::SessionList => {
                    println!(" -> Session Queue:");
                    for q in self.queue.iter() {
                        println!("   [Priority {}] Seq {}: {:?}", q.command.priority_score(), q.sequence_id, q.command);
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
                            println!(" -> Deleted Session sequence {}.", id);
                        }
                    }
                    if !found {
                        eprintln!(" -> Sequence {} not found in session queue.", id);
                    }
                    for q in temp {
                        self.queue.push(q);
                    }
                }
                InternalCommand::SessionClear => {
                    self.queue.clear();
                    println!(" -> Session queue cleared.");
                }
                InternalCommand::SessionRun => {
                    // This is inherently a no-op loop trigger since `run()` is already running.
                    println!(" -> SessionRun triggered.");
                }
                InternalCommand::CreateImage { layout } => {
                    println!(" -> Creating blank NAND image with layout {:?}...", layout);
                    self.active_nand = Some(NandSkeleton::new_blank(layout));
                }
                InternalCommand::Update { path } => {
                    let data = fs::read(&path).map_err(|e| format!("Failed to read update file: {}", e))?;
                    
                    if crate::builder::tools::stfs::StfsContainer::new(&data).is_ok() {
                        // 1. Process as STFS/PIRS container
                        println!(" -> Discovery: System Update container detected at {:?}", path);
                        let container = crate::builder::tools::stfs::StfsContainer::new(&data).unwrap();
                        let files = container.extract_to_memory()?;
                        
                        // Process internal xboxupd.bin if present for CF/CG
                        if let Some(upd_data) = files.get("xboxupd.bin") {
                            println!(" -> Internal xboxupd.bin discovered. Parsing bootloaders...");
                            match crate::builder::tools::stfs::parse_xboxupd(upd_data) {
                                Ok((cf, cg)) => {
                                    let cf_ver = cf.header.version.get();
                                    let cg_ver = cg.header.version.get();
                                    println!(" -> Discovery: Identified CF_{} and CG_{} in xboxupd.bin", cf_ver, cg_ver);

                                    // Register versioned names in pending_assets to satisfy INI lookup
                                    self.pending_assets.insert(format!("cf_{}.bin", cf_ver), cf.serialize());
                                    self.pending_assets.insert(format!("cg_{}.bin", cg_ver), cg.serialize());
                                    
                                    if let Some(nand) = &mut self.active_nand {
                                        nand.update.cf_0 = Some(cf);
                                        nand.update.cg_0 = Some(cg);
                                        
                                        if let Some(ce) = &mut nand.bootloaders.ce {
                                            if let (Some(cf), Some(cg)) = (&nand.update.cf_0, &nand.update.cg_0) {
                                                let _ = ce.apply_update(cf, cg);
                                            }
                                        }
                                        println!(" -> Discovery: Injected CF/CG from internal xboxupd.bin into active NAND");
                                    }
                                }
                                Err(e) => eprintln!(" -> Warning: Failed to parse internal xboxupd: {}", e),
                            }
                        }

                        // Add FlashFS assets
                        for (name, content) in files {
                            self.pending_assets.insert(name.to_lowercase(), content);
                        }
                    } else if path.file_name().and_then(|n| n.to_str()).map(|s| s.to_lowercase() == "xboxupd.bin").unwrap_or(false) {
                        // 2. Process as standalone xboxupd.bin binary
                        println!(" -> Discovery: Standalone update binary detected at {:?}", path);
                        match crate::builder::tools::stfs::parse_xboxupd(&data) {
                            Ok((cf, cg)) => {
                                let cf_ver = cf.header.version.get();
                                let cg_ver = cg.header.version.get();
                                println!(" -> Discovery: Identified CF_{} and CG_{} in standalone xboxupd.bin", cf_ver, cg_ver);

                                // Register versioned names in pending_assets to satisfy INI lookup
                                self.pending_assets.insert(format!("cf_{}.bin", cf_ver).to_lowercase(), cf.serialize());
                                self.pending_assets.insert(format!("cg_{}.bin", cg_ver).to_lowercase(), cg.serialize());

                                if let Some(nand) = &mut self.active_nand {
                                    nand.update.cf_0 = Some(cf);
                                    nand.update.cg_0 = Some(cg);
                                    
                                    if let Some(ce) = &mut nand.bootloaders.ce {
                                        if let (Some(cf), Some(cg)) = (&nand.update.cf_0, &nand.update.cg_0) {
                                            let _ = ce.apply_update(cf, cg);
                                        }
                                    }
                                    println!(" -> Discovery: Injected CF/CG from standalone xboxupd.bin into active NAND");
                                }
                            }
                            Err(e) => return Err(format!("Update Parse Error: {}", e)),
                        }
                    } else {
                        // 3. Process as loose FlashFS asset
                        let filename = path.file_name().unwrap().to_string_lossy().to_string();
                        let lower = filename.to_lowercase();
                        if lower.ends_with(".xex") || lower.ends_with(".dll") || lower == "fcrt.bin" || lower == "xeconfig.bin" {
                            println!(" -> Discovery: Loose FlashFS asset detected: {}", filename);
                            self.pending_assets.entry(filename).or_insert(data);
                        }
                    }
                }
                InternalCommand::FinalizeFlashfs => {
                    if !self.pending_assets.is_empty() {
                        println!(" -> Finalizing FlashFS with {} collected assets...", self.pending_assets.len());
                        if let Some(nand) = &mut self.active_nand {
                            let fs_start = match nand.layout { crate::builder::tools::blocks::NandLayout::Bb => 0x1E0, _ => 0x4E };
                            match crate::builder::chain::flashfs::FileSystemRoot::build_from_memory(&mut nand.image, &nand.layout, &self.pending_assets, fs_start) {
                                Ok(new_root) => {
                                    nand.flashfs.root = new_root;
                                    println!(" -> FlashFS generation complete.");
                                },
                                Err(e) => return Err(format!("FlashFS Build Error: {}", e)),
                            }
                        }
                    }
                }
                InternalCommand::ExtractStfs { path, target_dir } => {
                    println!(" -> Extracting STFS container from {:?} to {:?}...", path, target_dir);
                    match fs::read(&path) {
                        Ok(data) => {
                            match crate::builder::tools::stfs::StfsContainer::new(&data) {
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