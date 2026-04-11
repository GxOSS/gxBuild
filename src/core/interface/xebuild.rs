/*
    xebuild.rs
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/

use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashMap;
use std::path::PathBuf;
use crate::core::session::Session;
use crate::builder::builder::{BuildType, ImageType, MotherboardType};

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

    /// Use different data dir and file lists
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
    let args = GgxArgs::parse();
    let mut session = Session::new();

    // Map options to HashMap for the session
    let mut _opts_map = HashMap::new();
    for (k, v) in &args.options {
        _opts_map.insert(k.clone(), v.clone());
    }

    match args.mode.clone() {
        Some(GgxMode::Build { .. }) | None => {
            handle_build(args, &mut session);
        }
        Some(GgxMode::Extract) => {
            session.extract_all();
        }
        Some(GgxMode::Client) => {
            println!("Client mode selected.");
        }
        Some(GgxMode::Update) => {
            session.update();
        }
    }

    if let Err(e) = session.run() {
        eprintln!("\n[GGX] Session failed: {}", e);
    }
}

fn handle_build(args: GgxArgs, session: &mut Session) {
    // 1. Determine common and data paths
    let data_dir = args.data_dir.unwrap_or_else(|| PathBuf::from("./data"));
    let fw_dir = args.fw_dir.unwrap_or_else(|| PathBuf::from("./")); // Default to current dir or reference

    // 2. Resolve the correct INI file
    // xeBuild logic: <fw_dir>/<version>/_<type>.ini
    // For now we'll assume a default version '17559' if not specified, 
    // but in a real scenario we'd look in all subfolders or a config.
    let version = "17559"; // TODO: make this configurable or scanned
    let build_type_str = format!("{:?}", args.build_type).to_lowercase();
    let console_type = args.console.unwrap_or(CliConsoleType::xenon);
    let console_str = format!("{:?}", console_type).to_lowercase();

    let ini_filename = format!("_{}.ini", build_type_str);
    let ini_path = fw_dir.join(version).join(ini_filename);

    println!("\n--- GGX Build Configuration ---");
    println!("Type:      {:?}", args.build_type);
    println!("Console:   {}", console_str);
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
        _ => crate::builder::tools::blocks::NandLayout::Sb,
    };

    // 3. Initialize NAND (Blank synthesis)
    session.enqueue(crate::core::session::InternalCommand::CreateImage { layout });

    if let Ok(content) = std::fs::read_to_string(&ini_path) {
        // We use the console string as the target section in the INI
        session.parse_ini(content, console_str, ini_path.parent().unwrap(), fw_dir.join("common"));
    } else {
        eprintln!("[GGX] Warning: Could not find or read INI at {:?}", ini_path);
    }

    if let Some(key) = args.cpu_key {
        session.set_cpukey(key);
    }
    
    if args.verbose {
        session.set_verbose(true);
    }

    session.build();
    
    if !args.no_enter {
        println!("\nPress Enter to exit...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
    }
}

impl Session {
    // Helper to set session state from CLI
    pub fn set_cpukey(&mut self, _key: String) {
        // self.active_nand.cpukey = Some(key);
    }
    pub fn set_verbose(&mut self, _v: bool) {
        // session verbosity logic
    }
}