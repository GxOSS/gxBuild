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

    /// 32 character CPU hex key
    #[arg(short = 'p', long = "cpukey")]
    pub cpu_key: Option<String>,

    /// 32 character 1BL hex key
    #[arg(short = 'b', long = "blkey")]
    pub bl_key: Option<String>,

    /// Console motherboard type
    #[arg(short = 'c', long = "console")]
    pub console: Option<CliConsoleType>,

    /// Per build files directory
    #[arg(short = 'd', long = "datadir")]
    pub data_dir: Option<PathBuf>,

    /// Folder for shared bootloaders (defaults to <ini_dir>/../common)
    #[arg(short = 'm', long = "common")]
    pub common_dir: Option<PathBuf>,

    /// Use different firmware dir
    #[arg(short = 'f', long = "fwdir")]
    pub fw_dir: Option<PathBuf>,

    /// Outputs SHA-1 of final image to file
    #[arg(short = 's', long = "sha")]
    pub sha_file: Option<PathBuf>,

    /// Set xeBuild options (e.g. -o nomobile;cputemp=80)
    #[arg(short = 'o', long = "option", value_parser = parse_key_val)]
    pub options: Vec<(String, String)>,

    /// Append patches (.bin file name)
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

    /// Suppresses prompt for enter key when finished
    #[arg(long = "noenter")]
    pub no_enter: bool,
    
    /// Optional source NAND image
    #[arg(short = 'n', long = "nand")]
    pub source_nand: Option<PathBuf>,

    /// Optional system update file (e.g. xboxupd.bin)
    #[arg(short = 'u', long = "update")]
    pub xboxupd: Option<PathBuf>,

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
    println!("{}", LICENSE_TEXT);
    if std::env::args().count() == 1 {
        let mut cmd = GgxArgs::command();
        cmd.print_help().unwrap();
        
        println!("\nPress Enter to exit...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        return;
    }

    let args = GgxArgs::parse();
    let mut session = Session::new();

    match args.mode.clone() {
        Some(GgxMode::Build { .. }) | None => {
            if let Err(e) = handle_build(&args, &mut session) {
                eprintln!("\n[GGX] Build Setup Failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(GgxMode::Extract) => {
            session.extract_all();
        }
        Some(GgxMode::Client) => {
            println!("Client mode selected.");
        }
        Some(GgxMode::Update) => {
            println!("Update mode not fully implemented yet.");
        }
    }

    if let Err(e) = session.run() {
        eprintln!("\n[GGX] Session failed: {}", e);
    } else if let Some(GgxMode::Build { .. }) | None = args.mode {
        // Build succeeded, calculate SHA-1 if requested
        let output_path = args.output.clone().unwrap_or_else(|| PathBuf::from("updflash.bin"));
        if output_path.exists() {
            if let Ok(data) = std::fs::read(&output_path) {
                if let Ok(hash) = crate::builder::deps::excrypt::sha(&[&data]) {
                    let sha_str = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                    println!(" -> Image SHA-1: {}", sha_str);
                    
                    if let Some(sha_p) = args.sha_file {
                        if let Err(e) = std::fs::write(&sha_p, &sha_str) {
                            eprintln!("[GGX] Warning: Failed to write SHA-1 to {:?}: {}", sha_p, e);
                        } else {
                            println!(" -> SHA-1 written to {:?}", sha_p);
                        }
                    }
                }
            }
        }
    }

    if !args.no_enter {
        println!("\nPress Enter to exit...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
    }
}

fn handle_build(args: &GgxArgs, session: &mut Session) -> anyhow::Result<()> {
    let build_type = args.build_type.as_ref().ok_or_else(|| anyhow::anyhow!("Missing required argument: --type (-t)"))?;
    let console_type = args.console.as_ref().ok_or_else(|| anyhow::anyhow!("Missing required argument: --console (-c)"))?;

    // 1. Determine common and data paths
    let data_dir = args.data_dir.clone().unwrap_or_else(|| PathBuf::from("./data"));
    let fw_dir = args.fw_dir.clone().unwrap_or_else(|| PathBuf::from("./"));

    // 2. Resolve the correct INI file
    let build_type_str = format!("{:?}", build_type).to_lowercase();
    let ini_suffix = args.ini_ext.as_ref().map(|ext| format!("_{}", ext)).unwrap_or_default();
    let ini_filename = format!("_{}{}.ini", build_type_str, ini_suffix);
    let ini_path = data_dir.join(ini_filename);

    let resolved_common_dir = if let Some(common) = &args.common_dir {
        common.clone()
    } else {
        // Default to adjacency: <ini_parent>/../common
        ini_path.parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("common"))
            .unwrap_or_else(|| data_dir.join("common"))
    };

    let console_base = format!("{:?}", console_type).to_lowercase();
    let bl_suffix = args.bl_ext.as_ref().map(|ext| format!("_{}", ext)).unwrap_or_default();
    let console_section = format!("{}bl{}", console_base, bl_suffix);

    // 2.3 Pre-parse INI to identify TARGET filenames for discovery
    let mut target_filenames = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string(&ini_path) {
        if let Ok(ini) = crate::core::data::xeini::parse_xe_ini(&content, &console_section, &ini_path.parent().unwrap(), &resolved_common_dir) {
            for entry in ini.main { target_filenames.insert(entry.filename.to_lowercase()); }
            for entry in ini.security { target_filenames.insert(entry.path.file_name().unwrap().to_string_lossy().to_lowercase()); }
            for entry in ini.flashfs { target_filenames.insert(entry.path.file_name().unwrap().to_string_lossy().to_lowercase()); }
        }
    }

    // 2.5 Tiered Discovery Orchestration
    // Enqueue 'Finalize' to run after all discoveries
    session.enqueue(InternalCommand::FinalizeFlashfs);

    // TIER 1: Base Directory Scan (Highest Priority)
    println!("[GGX] TIER 1 Scanning Base Directory: {:?}", fw_dir);
    if let Ok(entries) = std::fs::read_dir(&fw_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                // ONLY pick up if it is a target or a discovery donor
                if target_filenames.contains(&name) || name.contains("su") || name.contains("update") || name == "xboxupd.bin" {
                    if name != "updflash.bin" {
                        session.enqueue(InternalCommand::Update { path });
                    }
                }
            }
        }
    }

    // TIER 2: Specialized Subfolders (flashfs/ and the INI parent directory)
    let ini_dir = ini_path.parent().unwrap_or(&fw_dir);
    let flashfs_dir = fw_dir.join("flashfs");
    
    for dir in &[Some(ini_dir), Some(&flashfs_dir)] {
        if let Some(d) = dir {
            if d.exists() && d.is_dir() {
                println!("[GGX] TIER 2 Scanning Folder: {:?}", d);
                if let Ok(entries) = std::fs::read_dir(d) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                            if target_filenames.contains(&name) || name.contains("su") || name.contains("update") || name == "xboxupd.bin" {
                                session.enqueue(InternalCommand::Update { path });
                            }
                        }
                    }
                }
            }
        }
    }

    // TIER 3: Common Directory
    println!("[GGX] TIER 3 Scanning Common Directory: {:?}", resolved_common_dir);
    if resolved_common_dir.exists() && resolved_common_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&resolved_common_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                    if target_filenames.contains(&name) {
                        session.enqueue(InternalCommand::Update { path });
                    }
                }
            }
        }
    }

    // TIER 4: Update Containers (Lowest Priority)
    let discovery_paths = vec![Some(&fw_dir), Some(&resolved_common_dir)];
    for dir in discovery_paths.into_iter().flatten() {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                    if name.contains("su") || name.contains("update") || name == "xboxupd.bin" {
                        session.enqueue(InternalCommand::Update { path });
                    }
                }
            }
        }
    }

    println!("\n--- GGX Build Configuration ---");
    println!("Type:      {:?}", build_type);
    println!("Console:   {}", console_base);
    println!("Section:   {}", console_section);
    println!("INI Path:  {:?}", ini_path);
    println!("Common:    {:?}", resolved_common_dir);
    println!("-------------------------------\n");

    // Determine layout from console type
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

    // 3. Initialize NAND (Parse from source or create blank)
    let mut nand_found = false;
    let mut parsed_nand_path = None;

    if let Some(nand) = &args.source_nand {
        parsed_nand_path = Some(nand.clone());
        nand_found = true;
    } else {
        // Fallback search for source NAND
        let discovery_targets = [
            data_dir.join("nanddump.bin"),
            fw_dir.join("nanddump.bin"),
            data_dir.join("nanddump1.bin"),
            fw_dir.join("nanddump1.bin"),
            data_dir.join("nanddump2.bin"),
            fw_dir.join("nanddump2.bin"),
            data_dir.join("nanddump"),
            fw_dir.join("nanddump"),
            data_dir.join("updflash.bin"),
            fw_dir.join("updflash.bin"),
        ];
        
        for p in &discovery_targets {
            if p.exists() {
                parsed_nand_path = Some(p.clone());
                nand_found = true;
                break;
            }
        }
    }

    if nand_found {
        let path = parsed_nand_path.unwrap();
        println!("[GGX] Auto-discovered source NAND image from {:?}", path);
        session.enqueue(crate::core::session::InternalCommand::ParseImage { path, key: None });
    } else {
        println!("[GGX] Synthesizing blank image from scratch.");
        session.enqueue(crate::core::session::InternalCommand::CreateImage { layout });
    }

    if let Ok(content) = std::fs::read_to_string(&ini_path) {
        session.parse_ini(content, console_section, ini_path.parent().unwrap(), resolved_common_dir.clone());
    } else {
        anyhow::bail!("Could not find or read INI at {:?}", ini_path);
    }

    if let Some(key) = &args.cpu_key {
        session.set_cpukey(key.clone());
    } else {
        // Look for cpukey.bin (binary) or cpukey.txt (text) in data_dir OR fw_dir
        let mut key_found = false;
        
        let discovery_targets = [
            (data_dir.join("cpukey.bin"), true),
            (fw_dir.join("cpukey.bin"), true),
            (data_dir.join("cpukey.txt"), false),
            (fw_dir.join("cpukey.txt"), false),
        ];

        for (p, is_bin) in discovery_targets {
            if p.exists() {
                if is_bin {
                    if let Ok(bytes) = std::fs::read(&p) {
                        if bytes.len() >= 16 {
                            let mut key = [0u8; 16];
                            key.copy_from_slice(&bytes[..16]);
                            session.parse_keybin(Some(key));
                            println!("[GGX] Auto-discovered CPU Key binary from {:?}", p);
                            key_found = true;
                            break;
                        }
                    }
                } else {
                    if let Ok(text) = std::fs::read_to_string(&p) {
                        let clean_key = text.trim();
                        if clean_key.len() >= 32 {
                            session.set_cpukey(clean_key.to_string());
                            println!("[GGX] Auto-discovered CPU Key string from {:?}", p);
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

    if args.bl_key.is_some() {
        println!("[GGX] Warning: Overriding the 1BL key (-b) is currently not implemented. Using default retail key.");
    }
    
    if args.verbose {
        session.set_verbose(true);
    }
    
    // 4. Update Discovery (xboxupd.bin)
    let mut update_path = None;
    if let Some(upd) = &args.xboxupd {
        if upd.exists() { update_path = Some(upd.clone()); }
    } else {
        // Search priority: INI dir, Common dir, Data dir, FW dir
        let search_targets = [
            ini_path.parent().map(|p| p.join("xboxupd.bin")),
            Some(resolved_common_dir.join("xboxupd.bin")),
            Some(data_dir.join("xboxupd.bin")),
            Some(fw_dir.join("xboxupd.bin")),
            Some(PathBuf::from("xboxupd.bin")),
        ];
        
        for target in search_targets.into_iter().flatten() {
            if target.exists() {
                update_path = Some(target);
                break;
            }
        }
    }

    if let Some(p) = update_path {
        println!("[GGX] Auto-discovered system update from {:?}", p);
        session.update(p);
    }

    // 5. Addon patches
    for addon in &args.addons {
        let addon_path = if PathBuf::from(addon).is_absolute() {
            PathBuf::from(addon)
        } else {
            let fw_path = fw_dir.join(addon);
            if fw_path.exists() {
                fw_path
            } else {
                data_dir.join(addon)
            }
        };
        
        if addon_path.exists() {
            session.enqueue(crate::core::session::InternalCommand::ApplyPatch { 
                path: addon_path, 
                ptype: 2, // Addon
                target: None 
            });
        } else {
            eprintln!("[GGX] Warning: Addon patch not found: {}", addon);
        }
    }

    let output_path = args.output.clone().unwrap_or_else(|| PathBuf::from("updflash.bin"));
    session.build(output_path, 0); // Target 0 for now
    
    Ok(())
}

impl Session {
    // Helper to set session state from CLI
    pub fn set_cpukey(&mut self, key: String) {
        if let Ok(bytes) = crate::builder::builder::hex_to_bytes(&key) {
            if let Ok(arr) = bytes.try_into() {
                self.parse_key(arr);
            } else {
                eprintln!("[Session] Error: CPU Key must be 32 hex characters (16 bytes).");
            }
        } else {
            eprintln!("[Session] Error: Invalid hex format for CPU Key.");
        }
    }
    pub fn set_verbose(&mut self, _v: bool) {
        // session verbosity logic
    }
}