/*
    xebuild.rs
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/

#![cfg(feature = "cli")]

use clap::{Parser, Subcommand, ValueEnum, CommandFactory};
use std::path::PathBuf;
use crate::core::session::{Session, InternalCommand};
use crate::core::logger;
use log::{info, error};

/// xeBuild v1.21.810 clone - System image builder
#[derive(Parser, Debug)]
#[command(name = "gxBuild", about = "Rust Xbox 360 Nand Manipulation Utility", version)]
pub struct GgxArgs {
    /// Operation mode (defaults to build)
    #[command(subcommand)]
    pub mode: Option<GgxMode>,

    /// Target image type
    #[arg(short = 't', long = "type")]
    pub build_type: Option<CliBuildType>,

    /// 32 character CPU hex key (override, can be elsewhere)
    #[arg(short = 'p', long = "cpukey")]
    pub cpu_key: Option<String>,

    /// 32 character 1BL hex key (override, can be elsewhere)
    #[arg(short = 'b', long = "blkey")]
    pub bl_key: Option<String>,

    /// Console motherboard type
    #[arg(short = 'c', long = "console")]
    pub console: Option<CliConsoleType>,

    /// INI directory — contains _retail.ini, bootloaders, flashfs/ (defaults to .)
    #[arg(short = 'd', long = "datadir")]
    pub data_dir: Option<PathBuf>,

    /// Folder for shared bootloaders (defaults to <ini_dir>/../common)
    #[arg(short = 'm', long = "common")]
    pub common_dir: Option<PathBuf>,

    /// Data directory — nand dump, cpu key, smc, fcrt, keyvault (defaults to ./data)
    #[arg(short = 'f', long = "fwdir")]
    pub fw_dir: Option<PathBuf>,

    /// Outputs SHA-1 of final image to <file>
    #[arg(short = 's', long = "sha")]
    pub sha_file: Option<PathBuf>,

    /// Set xeBuild options (e.g. -o nomobile;cputemp=80)
    #[arg(short = 'o', long = "option", value_parser = parse_key_val)]
    pub options: Vec<(String, String)>,

    /// Append addon patches or RGLP (.bin file name)
    #[arg(short = 'a', long = "addon")]
    pub addons: Vec<String>,

    /// Adds _<ext> into firmware ini and patches file names
    #[arg(short = 'i', long = "iniext")]
    pub ini_ext: Option<String>,

    /// Adds _<ext> into ini bl section name and patches file names
    #[arg(short = 'r', long = "blext")]
    pub bl_ext: Option<String>,

    /// Adds raw patch to NAND (format: file,offset)
    #[arg(short = '8', long = "rawpatch")]
    pub raw_patches: Vec<String>,

    /// Shows more info during build process
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Optional source NAND image
    #[arg(short = 'n', long = "nand")]
    pub source_nand: Option<PathBuf>,

    /// Optional system update file (e.g. xboxupd.bin)
    #[arg(short = 'u', long = "update")]
    pub xboxupd: Option<PathBuf>,

    /// Set preset for build
    #[arg(short = 'e', long = "preset")]
    pub preset: Option<String>,

    /// Run python script
    #[arg(short = 'M', long = "script")]
    pub script: Option<PathBuf>,

    /// Apply CDXeLL / RGLP patches directly (toggle)
    #[arg(short = 'x', long = "xell")]
    pub apply_xell: bool,

    /// Format of output image (system, full, xell, shadow)
    #[arg(short = 'h', long = "format")]
    pub format: Option<String>,

    /// Output directory / location of file
    #[arg(short = 'g', long = "output-dir")]
    pub output_dir: Option<PathBuf>,

    /// Optional output image name
    pub output: Option<PathBuf>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GgxMode {
    /// Image Build Mode (Default)
    Build {
        #[arg(from_global)]
        build_type: Option<CliBuildType>,
    },
    /// Perform dump loading and verification
    Extract,
    /// Client mode - flash over network
    Client,
    /// Update mode - update patches over network
    Update,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]
pub enum CliBuildType {
    retail,
    jtag,
    glitch,
    glitch2,
    glitch2m,
    devkit,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]
pub enum CliConsoleType {
    xenon,
    zephyr,
    falcon,
    jasper,
    jasper256,
    jasper512,
    jasperbb,
    jasperbigffs,
    trinity,
    trinitybigffs,
    corona,
    corona4g,
    winchester,
}

/// Custom parser for the -o options flag.
/// Supports both `key=value` and `key` (boolean true).
/// Semicolons are handled by splitting before parsing.
fn parse_key_val(s: &str) -> Result<(String, String), String> {
    let pos = s.find('=');
    match pos {
        Some(pos) => Ok((s[..pos].to_string(), s[pos + 1..].to_string())),
        None => Ok((s.to_string(), "true".to_string())),
    }
}

const LICENSE_TEXT: &str = r#"
=============================================================
gxBuild - Rust Xbox 360 Nand Manipulation Utility
by ExposureMG

This program is distributed under the GPL v2 License
This program has NO WARRANTY
=============================================================
"#;

pub fn ggx_cli() {
    if std::env::args().count() == 1 {
        println!("{}", LICENSE_TEXT);
        let mut cmd = GgxArgs::command();
        cmd.print_help().unwrap();
        
        println!("\nPress Enter to exit...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        return;
    }

    let args = GgxArgs::parse();

    // Initialize logger
    let mode_str = match &args.mode {
        Some(GgxMode::Build { .. }) | None => "build",
        Some(GgxMode::Extract) => "extract",
        Some(GgxMode::Client) => "client",
        Some(GgxMode::Update) => "update",
    };

    if let Err(e) = logger::init_logger(mode_str, args.verbose) {
        eprintln!("[GGX] Failed to initialize logger: {}", e);
    }

    info!("{}", LICENSE_TEXT);
    
    let mut session = Session::new();

    match args.mode.clone() {
        Some(GgxMode::Build { .. }) | None => {
            if let Err(e) = handle_build(&args, &mut session) {
                error!("\n[GGX] Build Setup Failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(GgxMode::Extract) => {
            session.extract_all();
        }
        Some(GgxMode::Client) => {
            info!("Client mode selected.");
        }
        Some(GgxMode::Update) => {
            info!("Update mode not fully implemented yet.");
        }
    }

    if let Err(e) = session.run() {
        error!("\n[GGX] Session failed: {}", e);
    } else if let Some(GgxMode::Build { .. }) | None = args.mode {
        // Build succeeded, calculate SHA-1 if requested
        let output_path = args.output.clone()
            .unwrap_or_else(|| args.output_dir.clone().unwrap_or_else(|| PathBuf::from("updflash.bin")));
        if output_path.exists() {
            if let Ok(data) = std::fs::read(&output_path) {
                if let Ok(hash) = crate::builder::deps::excrypt::sha(&[&data]) {
                    let sha_str = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                    info!(" -> Image SHA-1: {}", sha_str);

                    if let Some(sha_p) = args.sha_file.clone() {
                        if let Err(e) = std::fs::write(&sha_p, &sha_str) {
                            error!("[GGX] Warning: Failed to write SHA-1 to {:?}: {}", sha_p, e);
                        } else {
                            info!(" -> SHA-1 written to {:?}", sha_p);
                        }
                    }
                }
            }
        }
    }
    // Enter prompt is handled in handle_build via -o noenter
}

fn handle_build(args: &GgxArgs, session: &mut Session) -> anyhow::Result<()> {
    let build_type = args.build_type.as_ref().ok_or_else(|| anyhow::anyhow!("Missing required argument: --type (-t)"))?;
    let console_type = args.console.as_ref().ok_or_else(|| anyhow::anyhow!("Missing required argument: --console (-c)"))?;

    // --- Path Resolution ---
    // -d = INI directory (contains _retail.ini, bootloaders, flashfs/)
    let ini_dir = args.data_dir.clone()
        .unwrap_or_else(|| PathBuf::from("."));

    // -f = data directory (nand dump, cpu key, smc, fcrt, keyvault)
    let data_dir = args.fw_dir.clone()
        .unwrap_or_else(|| PathBuf::from("data"));

    // -m = common directory (shared bootloaders, defaults to <ini_dir>/../common)
    let resolved_common_dir = args.common_dir.clone()
        .unwrap_or_else(|| ini_dir.join("../common"));

    // Resolve INI file path: <ini_dir>/_<type>.ini
    let build_type_str = format!("{:?}", build_type).to_lowercase();
    let ini_suffix = args.ini_ext.as_ref().map(|ext| format!("_{}", ext)).unwrap_or_default();
    let ini_filename = format!("_{}{}.ini", build_type_str, ini_suffix);
    let ini_path = ini_dir.join(&ini_filename);

    let console_base = format!("{:?}", console_type).to_lowercase();
    let bl_suffix = args.bl_ext.as_ref().map(|ext| format!("_{}", ext)).unwrap_or_default();
    let console_section = format!("{}bl{}", console_base, bl_suffix);

    // --- INI Pre-Parsing ---
    let mut target_filenames = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string(&ini_path) {
        if let Ok(ini) = crate::core::data::xeini::parse_xe_ini(&content, &console_section, &ini_dir, &resolved_common_dir) {
            for entry in ini.main { target_filenames.insert(entry.filename.to_lowercase()); }
            for entry in ini.security { target_filenames.insert(entry.path.file_name().unwrap().to_string_lossy().to_lowercase()); }
            for entry in ini.flashfs { target_filenames.insert(entry.path.file_name().unwrap().to_string_lossy().to_lowercase()); }
        }
    } else {
        anyhow::bail!("Could not find or read INI at {:?}", ini_path);
    }

    info!("\n--- GGX Build Configuration ---");
    info!("Type:      {:?}", build_type);
    info!("Console:   {}", console_base);
    info!("Section:   {}", console_section);
    info!("INI Dir:   {:?}", ini_dir);
    info!("Data Dir:  {:?}", data_dir);
    info!("Common:    {:?}", resolved_common_dir);
    info!("INI File:  {:?}", ini_path);
    info!("-------------------------------\n");

    // --- Discovery Phase ---
    // Enqueue FinalizeFlashfs to run after all asset discovery
    session.enqueue(InternalCommand::FinalizeFlashfs);

    // ============================================================
    // BOOTLOADER & FLASHFS DISCOVERY
    // 1. Parse INI to get target filenames (relative paths)
    // 2. Search INI dir first, then INI subfolders (flashfs/, data/), then common
    // 3. If CF/CG not found, fall back to xboxupd.bin then su*** in INI dir
    // ============================================================

    // Helper: try to find and enqueue a file by name across search paths
    // Returns true if the file was actually found and enqueued
    let enqueue_if_found = |session: &mut Session, name: &str, search_paths: &[&std::path::PathBuf]| {
        let lower = name.to_lowercase();
        for dir in search_paths {
            let candidate = dir.join(name);
            if candidate.exists() {
                session.enqueue(InternalCommand::Update { path: candidate });
                return true;
            }
            // Also try lowercase variant
            let candidate_lower = dir.join(&lower);
            if candidate_lower.exists() {
                session.enqueue(InternalCommand::Update { path: candidate_lower });
                return true;
            }
        }
        false
    };

    // Build search path list: INI dir → INI subfolders → common
    let ini_flashfs = ini_dir.join("flashfs");
    let ini_data = ini_dir.join("data");
    let mut search_paths: Vec<&std::path::PathBuf> = vec![&ini_dir];
    if ini_flashfs.exists() && ini_flashfs.is_dir() { search_paths.push(&ini_flashfs); }
    if ini_data.exists() && ini_data.is_dir() { search_paths.push(&ini_data); }
    if resolved_common_dir.exists() && resolved_common_dir.is_dir() { search_paths.push(&resolved_common_dir); }

    // Enqueue files from INI target filenames, track which CF/CG were actually found
    let mut cf_on_disk = false;
    let mut cg_on_disk = false;
    info!("[GGX] Discovering {} assets from INI targets...", target_filenames.len());
    for filename in &target_filenames {
        let found = enqueue_if_found(session, filename, &search_paths);
        if filename.starts_with("cf_") && filename.ends_with(".bin") && found { cf_on_disk = true; }
        if filename.starts_with("cg_") && filename.ends_with(".bin") && found { cg_on_disk = true; }
    }

    // --- CF/CG Fallback: if not found on disk, search update containers ---
    if !cf_on_disk || !cg_on_disk {
        info!("[GGX] CF/CG not found on disk, searching update containers...");

        // Priority 1: xboxupd.bin in INI dir
        let xboxupd_path = ini_dir.join("xboxupd.bin");
        if xboxupd_path.exists() {
            info!("[GGX] Found xboxupd.bin in INI dir: {:?}", xboxupd_path);
            session.enqueue(InternalCommand::Update { path: xboxupd_path });
        } else {
            // Priority 2: su*** files in INI dir
            if let Ok(entries) = std::fs::read_dir(&ini_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                        if name.starts_with("su") {
                            info!("[GGX] Found STFS container in INI dir: {:?}", path);
                            session.enqueue(InternalCommand::Update { path });
                        }
                    }
                }
            }
        }
    }

    // ============================================================
    // DATA DIR DISCOVERY (-f) — NAND, CPU Key, Security, SMC, FCRT, KV
    // ============================================================
    info!("[GGX] Scanning Data Dir (nand/key/smc/fcrt/kv): {:?}", data_dir);

    // --- NAND Image Discovery (data dir only) ---
    let mut nand_found = false;
    let mut parsed_nand_path = None;

    if let Some(nand) = &args.source_nand {
        parsed_nand_path = Some(nand.clone());
        nand_found = true;
    } else {
        let nand_candidates = [
            data_dir.join("nanddump.bin"),
            data_dir.join("nanddump1.bin"),
            data_dir.join("nanddump2.bin"),
            data_dir.join("nanddump"),
            data_dir.join("updflash.bin"),
        ];

        for p in &nand_candidates {
            if p.exists() {
                parsed_nand_path = Some(p.clone());
                nand_found = true;
                break;
            }
        }
    }

    if nand_found {
        let path = parsed_nand_path.unwrap();
        info!("[GGX] Auto-discovered source NAND image from {:?}", path);
        session.enqueue(InternalCommand::ParseImage { path, key: None });
    } else {
        let layout = match console_type {
            CliConsoleType::xenon => crate::core::data::blocks::NandLayout::Xsb,
            CliConsoleType::zephyr | CliConsoleType::falcon | CliConsoleType::jasper => {
                crate::core::data::blocks::NandLayout::Sb
            }
            CliConsoleType::jasper256 | CliConsoleType::jasper512 | CliConsoleType::jasperbb | CliConsoleType::jasperbigffs => {
                crate::core::data::blocks::NandLayout::Bb
            }
            CliConsoleType::trinity => crate::core::data::blocks::NandLayout::Sb,
            CliConsoleType::trinitybigffs => crate::core::data::blocks::NandLayout::Bb,
            CliConsoleType::corona => crate::core::data::blocks::NandLayout::Sb,
            CliConsoleType::corona4g | CliConsoleType::winchester => crate::core::data::blocks::NandLayout::Emmc,
        };
        info!("[GGX] Synthesizing blank image from scratch (Layout: {:?}).", layout);
        session.enqueue(InternalCommand::CreateImage { layout });
    }

    // --- CPU Key Discovery (data dir only) ---
    if let Some(key) = &args.cpu_key {
        session.set_cpukey(key.clone());
    } else {
        let mut key_found = false;
        let key_candidates = [
            (data_dir.join("cpukey.bin"), true),
            (data_dir.join("cpukey.txt"), false),
        ];

        for (p, is_bin) in &key_candidates {
            if p.exists() {
                if *is_bin {
                    if let Ok(bytes) = std::fs::read(p) {
                        if bytes.len() >= 16 {
                            let mut key = [0u8; 16];
                            key.copy_from_slice(&bytes[..16]);
                            session.parse_keybin(Some(key));
                            info!("[GGX] Auto-discovered CPU Key binary from {:?}", p);
                            key_found = true;
                            break;
                        }
                    }
                } else {
                    if let Ok(text) = std::fs::read_to_string(p) {
                        let clean_key = text.trim();
                        if clean_key.len() >= 32 {
                            session.set_cpukey(clean_key.to_string());
                            info!("[GGX] Auto-discovered CPU Key string from {:?}", p);
                            key_found = true;
                            break;
                        }
                    }
                }
            }
        }

        if !key_found {
            anyhow::bail!("No CPU Key provided. A CPU key is strictly required to build.");
        }
    }

    // --- Security Assets (SMC, SMC config, FCRT, KV) from data dir ---
    let security_candidates = [
        data_dir.join("smc.bin"),
        data_dir.join("smc_config.bin"),
        data_dir.join("fcrt.bin"),
        data_dir.join("kv.bin"),
        data_dir.join("keyvault.bin"),
    ];

    for p in &security_candidates {
        if p.exists() {
            if let Ok(data) = std::fs::read(p) {
                let name = p.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                info!("[GGX] Discovered security asset: {:?} ({} bytes)", p, data.len());
                session.pending_assets.insert(name, data);
            }
        }
    }

    // --- Enqueue INI Parsing ---
    let ini_content = std::fs::read_to_string(&ini_path)
        .map_err(|e| anyhow::anyhow!("Failed to read INI at {:?}: {}", ini_path, e))?;
    session.parse_ini(ini_content.clone(), ini_filename.clone(), console_section.clone(), &ini_dir, &resolved_common_dir);

    // --- System Update Discovery (STFS / xboxupd.bin) ---
    // Searched in INI dir (-d) first, then data dir (-f)
    let mut update_path = None;
    if let Some(upd) = &args.xboxupd {
        if upd.exists() { update_path = Some(upd.clone()); }
    } else {
        let update_candidates = [
            ini_dir.join("xboxupd.bin"),
            ini_dir.join("system_update.xsu"),
            ini_dir.join("system_update.bin"),
            data_dir.join("xboxupd.bin"),
            data_dir.join("system_update.xsu"),
        ];

        for target in &update_candidates {
            if target.exists() {
                update_path = Some(target.clone());
                break;
            }
        }
    }

    if let Some(p) = update_path {
        info!("[GGX] Auto-discovered system update from {:?}", p);
        session.update(p);
    }

    // --- 1BL Key Warning ---
    if args.bl_key.is_some() {
        info!("[GGX] Warning: Overriding the 1BL key (-b) is currently not implemented. Using default retail key.");
    }

    // --- Addon Patches ---
    for addon in &args.addons {
        let addon_path = if PathBuf::from(addon).is_absolute() {
            PathBuf::from(addon)
        } else {
            let ini_path = ini_dir.join(addon);
            if ini_path.exists() {
                ini_path
            } else {
                data_dir.join(addon)
            }
        };

        if addon_path.exists() {
            session.enqueue(InternalCommand::ApplyPatch {
                path: addon_path,
                ptype: 2, // Addon
                target: None
            });
        } else {
            error!("[GGX] Warning: Addon patch not found: {}", addon);
        }
    }

    // --- Raw Patches (-8) ---
    for raw_patch in &args.raw_patches {
        // Parse format: filename.ext,offset
        let parts: Vec<&str> = raw_patch.split(',').collect();
        if parts.len() == 2 {
            let filename = parts[0];
            let offset_str = parts[1];

            let patch_path = if PathBuf::from(filename).is_absolute() {
                PathBuf::from(filename)
            } else {
                let p = data_dir.join(filename);
                if p.exists() { p } else { ini_dir.join(filename) }
            };

            let offset = if offset_str.starts_with("0x") {
                u64::from_str_radix(&offset_str[2..], 16).ok()
            } else {
                offset_str.parse::<u64>().ok()
            };

            if patch_path.exists() && offset.is_some() {
                info!("[GGX] Raw patch: {:?} at offset 0x{:X}", patch_path, offset.unwrap());
                // Enqueue raw patch command
                session.enqueue(InternalCommand::ApplyPatch {
                    path: patch_path,
                    ptype: 3, // Raw patch
                    target: None
                });
            }
        }
    }

    // --- Output Path Resolution ---
    let output_path = args.output.clone()
        .unwrap_or_else(|| args.output_dir.clone()
            .unwrap_or_else(|| PathBuf::from("updflash.bin")));
    session.build(output_path.clone(), 0); // Target 0 for now

    // --- Options Processing ---
    let mut no_enter = false;
    for (key, _val) in &args.options {
        match key.as_str() {
            "noenter" => no_enter = true,
            "noinfo" => {},
            "nolog" => {},
            "unsafe" => {},
            _ => {}
        }
    }

    if !no_enter {
        println!("\nPress Enter to exit...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
    }

    Ok(())
}

impl Session {
    // Helper to set session state from CLI
    pub fn set_cpukey(&mut self, key: String) {
        if let Ok(bytes) = crate::builder::builder::hex_to_bytes(&key) {
            if let Ok(arr) = bytes.try_into() {
                self.parse_key(arr);
            } else {
                error!("[Session] Error: CPU Key must be 32 hex characters (16 bytes).");
            }
        } else {
            error!("[Session] Error: Invalid hex format for CPU Key.");
        }
    }
    pub fn set_verbose(&mut self, _v: bool) {
        // session verbosity logic
    }
}