/*
    xebuild.rs
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/

#![cfg(feature = "cli")]

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use crate::core::session::Session;

/// xeBuild v1.21.810 clone - System image builder
#[derive(Parser, Debug)]
#[command(name = "ggxbuild", about = "xeBuild clone for Xbox 360 image building", version)]
pub struct GgxArgs {
    /// Operation mode (defaults to build)
    #[command(subcommand)]
    pub mode: Option<GgxMode>,

    /// Image type: retail, jtag, glitch, glitch2, glitch2m, devkit
    #[arg(short = 't', long = "type", default_value = "retail")]
    pub build_type: CliBuildType,

    /// 32 character CPU hex key
    #[arg(short = 'p', long = "cpukey")]
    pub cpu_key: Option<String>,

    /// 32 character 1BL hex key
    #[arg(short = 'b', long = "blkey")]
    pub bl_key: Option<String>,

    /// Console/Motherboard type (e.g., xenon, jasper, trinity...)
    #[arg(short = 'c', long = "console")]
    pub console: Option<CliConsoleType>,

    /// Per build files directory
    #[arg(short = 'd', long = "datadir")]
    pub data_dir: Option<PathBuf>,

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

    /// Optional output image name
    pub output: Option<PathBuf>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GgxMode {
    /// Image Build Mode (Default)
    Build {
        #[arg(from_global)]
        build_type: CliBuildType,
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

pub fn ggx_cli() {
    if std::env::args().count() == 1 {
        let help_path = "c:\\Users\\Exposure\\Documents\\References\\xeBuild\\help.txt";
        if let Ok(content) = std::fs::read_to_string(help_path) {
            println!("{}", content);
        } else {
            // Fallback if the reference file is missing
            println!("gxbuild [mode] -t <type> [<switch> [<switch>...]] <out.bin>");
            println!("(Help reference missing at {})", help_path);
        }
        
        println!("\nPress Enter to exit...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        return;
    }

    let args = GgxArgs::parse();
    let mut session = Session::new();

    match args.mode.clone() {
        Some(GgxMode::Build { .. }) | None => {
            handle_build(&args, &mut session);
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
}

fn handle_build(args: &GgxArgs, session: &mut Session) {
    // 1. Determine common and data paths
    let data_dir = args.data_dir.clone().unwrap_or_else(|| PathBuf::from("./data"));
    let fw_dir = args.fw_dir.clone().unwrap_or_else(|| PathBuf::from("./"));

    // 2. Resolve the correct INI file
    let build_type_str = format!("{:?}", args.build_type).to_lowercase();
    let ini_suffix = args.ini_ext.as_ref().map(|ext| format!("_{}", ext)).unwrap_or_default();
    let ini_filename = format!("_{}{}.ini", build_type_str, ini_suffix);
    let ini_path = data_dir.join(ini_filename);

    let console_type = args.console.unwrap_or(CliConsoleType::xenon);
    let console_base = format!("{:?}", console_type).to_lowercase();
    let bl_suffix = args.bl_ext.as_ref().map(|ext| format!("_{}", ext)).unwrap_or_default();
    let console_section = format!("{}bl{}", console_base, bl_suffix);

    println!("\n--- GGX Build Configuration ---");
    println!("Type:      {:?}", args.build_type);
    println!("Console:   {}", console_base);
    println!("Section:   {}", console_section);
    println!("INI Path:  {:?}", ini_path);
    println!("-------------------------------\n");

    // Determine layout from console type
    let layout = match console_type {
        CliConsoleType::xenon => crate::builder::tools::blocks::NandLayout::Xsb,
        CliConsoleType::zephyr | CliConsoleType::falcon | CliConsoleType::jasper => {
            crate::builder::tools::blocks::NandLayout::Sb
        }
        CliConsoleType::jasper256 | CliConsoleType::jasper512 | CliConsoleType::jasperbb | CliConsoleType::jasperbigffs => {
            crate::builder::tools::blocks::NandLayout::Bb
        }
        CliConsoleType::trinity => crate::builder::tools::blocks::NandLayout::Sb,
        CliConsoleType::trinitybigffs => crate::builder::tools::blocks::NandLayout::Bb,
        CliConsoleType::corona => crate::builder::tools::blocks::NandLayout::Sb,
        CliConsoleType::corona4g | CliConsoleType::winchester => crate::builder::tools::blocks::NandLayout::Emmc,
    };

    // 3. Initialize NAND (Blank synthesis)
    session.enqueue(crate::core::session::InternalCommand::CreateImage { layout });

    if let Ok(content) = std::fs::read_to_string(&ini_path) {
        session.parse_ini(content, console_section, ini_path.parent().unwrap(), data_dir.join("common"));
    } else {
        eprintln!("[GGX] Warning: Could not find or read INI at {:?}", ini_path);
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
            println!("[GGX] Warning: No CPU Key provided and no cpukey.bin/txt found.");
        }
    }

    if args.bl_key.is_some() {
        println!("[GGX] Warning: Overriding the 1BL key (-b) is currently not implemented. Using default retail key.");
    }
    
    if args.verbose {
        session.set_verbose(true);
    }
    
    // 4. Addon patches
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
    
    if !args.no_enter {
        println!("\nPress Enter to exit...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
    }
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