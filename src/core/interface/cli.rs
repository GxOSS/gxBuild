/*
  cli.rs - xeBuild style command line interface

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

use crate::builder::nand::ecc::handle_extract_ecc;
#[cfg(feature = "rhai")]
use crate::core::interface::rhai::GxScriptEngine;
use crate::core::interface::handler::{execute_internal_commands, Executor, InternalCommand};
use crate::core::interface::data::options::{parse_options_ini, OptionsIni};
use crate::core::interface::data::{BuildAssets, BuildConfig, Session};
use crate::core::logger;
use clap::ValueEnum;
use clap::{CommandFactory, Parser, Subcommand};
use log::{error, info, warn};
use std::path::PathBuf;
#[cfg(feature = "rhai")]
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("Missing required build type argument: --type (-t)")]
    MissingBuildType,

    #[error("Missing required console argument: --console (-c)")]
    MissingConsole,

    #[error("Could not find or read INI at {path:?}")]
    IniRead { path: PathBuf },

    #[error("No CPU Key provided. A CPU key is strictly required to build.")]
    MissingCpuKey,

    #[error("Provide either -l/--image (NAND) or --ecc (ECC image), not both.")]
    InvalidExtractSource,

    #[error("No NAND/ECC image found. Provide one via -l/--image or --ecc, or place it in the data dir (-f/--data).")]
    ExtractSourceNotFound,

    #[error("Build asset discovery error: {0}")]
    BuildAssets(#[from] crate::core::interface::data::BuildAssetsError),

    #[error("Handler error: {0}")]
    Handler(#[from] crate::core::interface::handler::HandlerError),

    #[error("Builder error: {0}")]
    Builder(#[from] crate::builder::nand::types::BuilderError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Message(String),
}

#[derive(Parser, Debug)]
#[command(
    name = "gxBuild",
    about = "Rust Xbox 360 Nand Manipulation Utility",
    version,
    disable_help_flag = true
)]
pub struct GgxArgs {
    /// Operation mode (defaults to build)
    #[command(subcommand)]
    pub mode: Option<GgxMode>,

    /// Target image type
    #[arg(short = 't', long = "type", global = true)]
    pub build_type: Option<CliBuildType>,

    /// 32 character CPU hex key (override, can be elsewhere)
    #[arg(short = 'p', long = "cpukey", global = true)]
    pub cpu_key: Option<String>,

    /// 32 character 1BL hex key (override, can be elsewhere)
    #[arg(short = 'b', long = "1blkey", global = true)]
    pub bl_key: Option<String>,

    /// Console motherboard type
    #[arg(short = 'c', long = "console", global = true)]
    pub console: Option<CliConsoleType>,

    /// INI directory - contains _retail.ini, bootloaders, flashfs/ (defaults to .)
    #[arg(short = 'd', long = "build", global = true)]
    pub data_dir: Option<PathBuf>,

    /// Folder for shared bootloaders (defaults to <ini_dir>/../common)
    #[arg(short = 'm', long = "common", global = true)]
    pub common_dir: Option<PathBuf>,

    /// Data directory - nand dump, cpu key, smc, fcrt, keyvault (defaults to ./data)
    #[arg(short = 'f', long = "data", global = true)]
    pub fw_dir: Option<PathBuf>,

    /// Outputs SHA-1 of final image to <file>
    #[arg(short = 's', long = "sha", global = true)]
    pub sha_file: Option<PathBuf>,

    /// Set xeBuild options (e.g. -o nomobile;cputemp=80)
    #[arg(short = 'o', long = "options", value_parser = parse_key_val, global = true)]
    pub options: Vec<Vec<(String, String)>>,

    /// Append addon patches or RGLP (.bin file name)
    #[arg(short = 'a', long = "addon", global = true)]
    pub addons: Vec<String>,

    /// Adds _<ext> into firmware ini and patches file names
    #[arg(short = 'i', long = "fwext", global = true)]
    pub ini_ext: Option<String>,

    /// Adds _<ext> into ini bl section name and patches file names
    #[arg(short = 'r', long = "iniext", global = true)]
    pub bl_ext: Option<String>,

    /// Adds raw patch to NAND (format: file,offset)
    #[arg(short = '8', long = "raw", global = true)]
    pub raw_patches: Vec<String>,

    /// Optional source NAND image
    #[arg(short = 'l', long = "image", global = true)]
    pub source_nand: Option<PathBuf>,

    /// Optional ECC image to overlay onto the loaded NAND (typically a XeLL ECC)
    #[arg(long = "ecc", global = true)]
    pub ecc: Option<PathBuf>,

    /// Optional system update file (e.g. xboxupd.bin)
    #[arg(short = 'u', long = "update", global = true)]
    pub xboxupd: Option<PathBuf>,

    /// Set preset for build
    #[arg(short = 'e', long = "preset", global = true)]
    pub preset: Option<String>,

    /// Direct session access
    #[arg(short = 'n', long = "cmd", global = true)]
    pub cmd: Option<String>,

    /// Format of output image (system, full, xell, shadow)
    #[arg(short = 'h', long = "format", global = true)]
    pub format: Option<String>,

    /// Output directory / location of file
    #[arg(short = 'g', long = "output-dir", global = true)]
    pub output_dir: Option<PathBuf>,

    /// Optional output image name
    pub output: Option<PathBuf>,

    /// Force XSB layout
    #[arg(short = 'x', long = "xsb", global = true)]
    pub xsb: bool,

    /// Build full NAND image (not just system portion)
    #[arg(long = "fullimage", global = true)]
    pub full_image: bool,

    #[arg(long = "bigblock", global = true, help = "Force Big Block layout for the final skeleton")]
    pub bigblock: bool,

    /// Run a Rhai script file
    #[cfg(feature = "rhai")]
    #[arg(long = "script")]
    pub script: Option<PathBuf>,

    /// Launch interactive Rhai shell
    #[cfg(feature = "rhai")]
    #[arg(long = "shell")]
    pub shell: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GgxMode {
    /// Image Build Mode (Default)
    Build {
        #[arg(from_global)]
        build_type: Option<CliBuildType>,
    },
    /// Perform dump loading and verification
    Extract {
        #[arg(long = "all")]
        all: bool,
    },
}

/// Custom parser for the -o options flag.
/// Supports semicolon-separated values: e.g. "noenter;noinfo;nomobile;cputemp=80"
/// Each part supports both `key=value` and `key` (boolean true).
fn parse_key_val(s: &str) -> Result<Vec<(String, String)>, String> {
    s.split(';')
        .filter(|part| !part.is_empty())
        .map(|part| match part.find('=') {
            Some(pos) => Ok((part[..pos].to_string(), part[pos + 1..].to_string())),
            None => Ok((part.to_string(), "true".to_string())),
        })
        .collect()
}

const LICENSE_TEXT: &str = r#"
=============================================================
gxBuild - Rust Xbox 360 Nand Manipulation Utility
by ExposureMG

This program is distributed under the GPL v2 License
This program has NO WARRANTY
=============================================================
"#;

fn parse_cpu_key_hex(text: &str) -> Result<([u8; 16], String), CliError> {
    let clean = text.trim();
    let bytes = crate::builder::nand::parser::hex_to_bytes(clean)
        .map_err(|e| CliError::Message(format!("Invalid formatting for CPU Key '{}': {}", clean, e)))?;
    let key: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CliError::Message("CPU Key must be 32 hex chars / 16 bytes".to_string()))?;
    let normalized = key.iter().map(|b| format!("{:02x}", b)).collect();
    Ok((key, normalized))
}

fn load_cpu_key(args: &GgxArgs, data_dir: &PathBuf) -> Result<Option<([u8; 16], String)>, CliError> {
    if let Some(key) = &args.cpu_key {
        return parse_cpu_key_hex(key).map(Some);
    }

    let key_bin = data_dir.join("cpukey.bin");
    if key_bin.exists() {
        let bytes = std::fs::read(&key_bin)?;
        if bytes.len() >= 16 {
            let mut key = [0u8; 16];
            key.copy_from_slice(&bytes[..16]);
            let normalized = key.iter().map(|b| format!("{:02x}", b)).collect();
            return Ok(Some((key, normalized)));
        }
    }

    let key_txt = data_dir.join("cpukey.txt");
    if key_txt.exists() {
        let text = std::fs::read_to_string(&key_txt)?;
        return parse_cpu_key_hex(text.trim()).map(Some);
    }

    Ok(None)
}

fn apply_cli_option_override(options: &mut OptionsIni, key: &str, value: &str) {
    match key.to_lowercase().as_str() {
        "region" | "avregion" => options.keyvault.avregion = Some(value.to_string()),
        "gameregion" => options.keyvault.gameregion = Some(value.to_string()),
        "dvdregion" => options.keyvault.dvdregion = Some(value.to_string()),
        "unsafe" => {
            options.core.gxunsafe = Some(value.eq_ignore_ascii_case("true"));
            if options.core.gxunsafe.unwrap_or(false) {
                warn!("[cli] Unsafe Mode enabled via CLI override.");
            }
        }
        "nomobile" => options.core_builder.nomobile = Some(value.eq_ignore_ascii_case("true")),
        "nofcrt" => options.core_builder.nofcrt = Some(value.eq_ignore_ascii_case("true")),
        "noenter" => options.core.noenter = Some(value.eq_ignore_ascii_case("true")),
        "noremap" => options.core_builder.noremap = Some(value.eq_ignore_ascii_case("true")),
        "nandmu" => options.core_builder.nandmu = Some(value.eq_ignore_ascii_case("true")),
        "nochainpatch" => options.core_builder.nochainpatch = Some(value.eq_ignore_ascii_case("true")),
        "bigblock" => options.core_builder.bigblock = Some(value.eq_ignore_ascii_case("true")),
        "cputemp" => options.smc_config.cputemp = Some(value.to_string()),
        "gputemp" => options.smc_config.gputemp = Some(value.to_string()),
        "edramtemp" => options.smc_config.edramtemp = Some(value.to_string()),
        "overcputemp" => options.smc_config.overcputemp = Some(value.to_string()),
        "overgputemp" => options.smc_config.overgputemp = Some(value.to_string()),
        "overedramtemp" => options.smc_config.overedramtemp = Some(value.to_string()),
        "cpufan" => options.smc_config.cpufan = Some(value.to_string()),
        "gpufan" => options.smc_config.gpufan = Some(value.to_string()),
        "macid" | "mac" => options.keyvault.macid = Some(value.to_string()),
        "dvdkey" => options.keyvault.dvdkey = Some(value.to_string()),
        "cfldv" => options.keys.cfldv = Some(value.to_string()),
        "xellbutton" => options.builder.xellbutton = Some(value.to_string()),
        "xellbutton2" => options.builder.xellbutton2 = Some(value.to_string()),
        "cygnos" => options.jtag.cygnos = Some(value.eq_ignore_ascii_case("true")),
        "demon" => options.jtag.demon = Some(value.eq_ignore_ascii_case("true")),
        "smcnoeject" => options.jtag.smcnoeject = Some(value.eq_ignore_ascii_case("true")),
        "smcnoblink" => options.jtag.smcnoblink = Some(value.eq_ignore_ascii_case("true")),
        "patchsmc" => options.jtag.patchsmc = Some(value.eq_ignore_ascii_case("true")),
        "olddvd" => options.jtag.olddvd = Some(value.eq_ignore_ascii_case("true")),
        "nodvd" => options.jtag.nodvd = Some(value.eq_ignore_ascii_case("true")),
        "dualboot" => options.jtag.dualboot = Some(value.eq_ignore_ascii_case("true")),
        "nolog" => options.core.nolog = Some(value.eq_ignore_ascii_case("true")),
        "noinfo" => options.core.noinfo = Some(value.eq_ignore_ascii_case("true")),
        "verbose" => {}
        _ => warn!("[cli] Unhandled generic option override: {}", key),
    }
}

fn resolve_ini_target(
    build_type: &str,
    console: &str,
    ini_ext: Option<&String>,
    bl_ext: Option<&String>,
    ini_dir: &PathBuf,
) -> (PathBuf, String) {
    let ini_suffix = ini_ext
        .map(|ext| format!("_{}", ext))
        .unwrap_or_default();
    let ini_filename = format!("_{}{}.ini", build_type, ini_suffix);
    let ini_path = ini_dir.join(&ini_filename);

    let console_section_base = match console {
        "jasper256" | "jasper512" | "jasperbb" | "jasperbigffs" => "jasper".to_string(),
        "trinitybb" | "trinitybigffs" => "trinity".to_string(),
        "corona4g" => "corona".to_string(),
        "winchester4g" => "winchester".to_string(),
        _ => console.to_string(),
    };
    let console_section = match bl_ext {
        Some(ext) => format!("{}_{}", console_section_base, ext),
        None => console_section_base,
    };

    (ini_path, console_section)
}

fn build_config_from_args(args: &GgxArgs) -> Result<BuildConfig, CliError> {
    let build_type = args.build_type.as_ref().ok_or(CliError::MissingBuildType)?;
    let console_type = args.console.as_ref().ok_or(CliError::MissingConsole)?;
    let build_type_str = format!("{:?}", build_type).to_lowercase();
    let console_base = format!("{:?}", console_type).to_lowercase();

    let ini_dir = args.data_dir.clone().unwrap_or_else(|| PathBuf::from("."));
    let data_dir = args.fw_dir.clone().unwrap_or_else(|| PathBuf::from("mydata"));
    let common_dir = args
        .common_dir
        .clone()
        .unwrap_or_else(|| ini_dir.join("../common"));
    let output_path = args.output.clone().unwrap_or_else(|| {
        args.output_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("updflash.bin"))
    });

    let mut options = OptionsIni::new();
    let options_path = data_dir.join("options.ini");
    if options_path.exists() {
        let content = std::fs::read_to_string(&options_path)?;
        let parsed = parse_options_ini(&content)
            .map_err(|e| CliError::Message(format!("Failed to parse options.ini: {}", e)))?;
        options.merge(parsed);
        info!("[cli] Merged defaults from {:?}", options_path);
    }

    options.keys.ctype = Some(console_base.clone());
    if args.full_image {
        options.core_builder.full_image = Some(true);
    }
    if args.xsb {
        options.core_builder.xsb = Some(true);
    }
    if args.bigblock {
        options.core_builder.bigblock = Some(true);
    }

    for group in &args.options {
        for (key, value) in group {
            apply_cli_option_override(&mut options, key, value);
        }
    }

    let pending_key = load_cpu_key(args, &data_dir)?;
    if let Some((_, normalized)) = &pending_key {
        options.keys.cpukey = Some(normalized.clone());
    } else {
        return Err(CliError::MissingCpuKey);
    }

    let (ini_path, console_section) = resolve_ini_target(
        &build_type_str,
        &console_base,
        args.ini_ext.as_ref(),
        args.bl_ext.as_ref(),
        &ini_dir,
    );
    let xe_ini = crate::core::interface::data::xeini::parse_xe_ini(&ini_path, &console_section)
        .map_err(|_| CliError::IniRead {
            path: ini_path.clone(),
        })?;

    if options.core.gxunsafe.unwrap_or(false) {
        warn!("[cli] Unsafe Mode Enabled");
    }

    Ok(BuildConfig {
        pending_key: pending_key.map(|(key, _)| key),
        build_type: Some(build_type_str),
        console_type: Some(console_base),
        xe_ini: Some(xe_ini),
        options,
        ini_dir: Some(ini_dir),
        common_dir: Some(common_dir),
        data_dir: Some(data_dir),
        output_path: Some(output_path),
        ini_ext: args.ini_ext.clone(),
        bl_ext: args.bl_ext.clone(),
        addons: args.addons.clone(),
    })
}

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
        Some(GgxMode::Extract { .. }) => "extract",
    };

    let mut is_verbose = false;
    let mut no_enter = false;
    for group in &args.options {
        for (k, _) in group {
            if k.eq_ignore_ascii_case("verbose") {
                is_verbose = true;
            } else if k.eq_ignore_ascii_case("noenter") {
                no_enter = true;
            }
        }
    }

    if let Err(e) = logger::init_logger(mode_str, is_verbose) {
        error!("[cli] Failed to initialize logger: {}", e);
    }

    info!("{}", LICENSE_TEXT);

    let mut session = Session::default();

    let mut session_prepared = true;
    match args.mode.clone() {
        Some(GgxMode::Build { .. }) | None => {
            match create_build(&args) {
                Ok(built_session) => {
                    session = built_session;
                }
                Err(e) => {
                    error!("[cli] Build Setup Failed: {}", e);
                    session_prepared = false;
                }
            }
        }
        Some(GgxMode::Extract { .. }) => {
            if let Err(e) = handle_extract(&args, &mut session) {
                error!("[cli] Extract Setup Failed: {}", e);
                session_prepared = false;
            }
        }
    }

    if session_prepared {
        // --- Scripting & Shell Handlers ---
        #[cfg(feature = "rhai")]
        if args.shell || args.script.is_some() {
            let session_ptr = Arc::new(Mutex::new(session));
            let mut script_engine = GxScriptEngine::new(session_ptr);

            if args.shell {
                script_engine.repl();
            } else if let Some(path) = &args.script {
                if let Err(e) = script_engine.run_file(&path.to_string_lossy()) {
                    error!("[cli] Script error: {}", e);
                }
            }
            return;
        }

        if let Some(GgxMode::Build { .. }) | None = args.mode {
            // Build succeeded, calculate SHA-1 if requested
            let output_path = args.output.clone().unwrap_or_else(|| {
                args.output_dir
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("updflash.bin"))
            });
            if output_path.exists() {
                if let Ok(data) = std::fs::read(&output_path) {
                    if let Ok(hash) = crate::crypto::sha(&[&data]) {
                        let sha_str = hash
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<String>();
                        info!("[cli] Image SHA-1: {}", sha_str);

                        if let Some(sha_p) = args.sha_file.clone() {
                            if let Err(e) = std::fs::write(&sha_p, &sha_str) {
                                error!("[cli] Failed to write SHA-1 to {:?}: {}", sha_p, e);
                            } else {
                                info!("[cli] SHA-1 written to {:?}", sha_p);
                            }
                        }
                    }
                }
            }
        }
    }

    if !no_enter {
        println!("\nPress Enter to exit...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]
pub enum CliBuildType {
    retail,
    jtag,
    glitch,
    glitch2,
    glitch2m,
    glitch3,
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
    trinitybb,
    trinitybigffs,
    corona,
    corona4g,
    winchester,
    winchester4g,
}

fn create_build(args: &GgxArgs) -> Result<Session, CliError> {
    let build_config = build_config_from_args(args)?;
    let build_type = build_config
        .build_type
        .clone()
        .ok_or(CliError::MissingBuildType)?;
    let console = build_config
        .console_type
        .clone()
        .ok_or(CliError::MissingConsole)?;
    let ini_dir = build_config
        .ini_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    let data_dir = build_config
        .data_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("mydata"));
    let common_dir = build_config
        .common_dir
        .clone()
        .unwrap_or_else(|| ini_dir.join("../common"));
    let payloads_dir = ini_dir.join("../payloads");
    let smc_dir = ini_dir.join("../smc");
    let output_path = build_config
        .output_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("updflash.bin"));
    let (ini_path, console_section) = resolve_ini_target(
        &build_type,
        &console,
        build_config.ini_ext.as_ref(),
        build_config.bl_ext.as_ref(),
        &ini_dir,
    );

    info!("[cli] Build Configuration");
    info!("[cli]   Type:      {}", build_type);
    info!("[cli]   Console:   {}", console);
    info!("[cli]   Section:   {}", console_section);
    info!("[cli]   INI Dir:   {:?}", ini_dir);
    info!("[cli]   Data Dir:  {:?}", data_dir);
    info!("[cli]   Common:    {:?}", common_dir);
    info!("[cli]   INI File:  {:?}", ini_path);

    let build_assets = BuildAssets::new(&build_config)?;
    let mut session = Session::new(build_config, build_assets);
    let mut commands = vec![
        InternalCommand::FinalizeFlashfs,
        InternalCommand::FinalizeMobile,
    ];

    let source_nand = if let Some(path) = &args.source_nand {
        Some(path.clone())
    } else {
        [
            data_dir.join("nanddump.bin"),
            data_dir.join("nanddump1.bin"),
            data_dir.join("nanddump2.bin"),
            data_dir.join("nanddump.ecc"),
            data_dir.join("nanddump1.ecc"),
            data_dir.join("nanddump2.ecc"),
            data_dir.join("nanddump"),
            data_dir.join("updflash.bin"),
            data_dir.join("updflash.ecc"),
        ]
        .into_iter()
        .find(|path| path.exists())
    };

    if let Some(path) = source_nand {
        info!("[cli] Using source NAND image from {:?}", path);
        commands.push(InternalCommand::ParseImage { path, key: None });
        if let Some(ecc) = &args.ecc {
            commands.push(InternalCommand::ApplyEcc { path: ecc.clone() });
        }
    } else {
        let layout = match args.console.as_ref().ok_or(CliError::MissingConsole)? {
            CliConsoleType::xenon => crate::core::images::blocks::NandLayout::Xsb,
            CliConsoleType::zephyr | CliConsoleType::falcon | CliConsoleType::jasper => {
                crate::core::images::blocks::NandLayout::Sb
            }
            CliConsoleType::jasper256
            | CliConsoleType::jasper512
            | CliConsoleType::jasperbb
            | CliConsoleType::jasperbigffs => crate::core::images::blocks::NandLayout::Bb,
            CliConsoleType::trinity => crate::core::images::blocks::NandLayout::Sb,
            CliConsoleType::trinitybb | CliConsoleType::trinitybigffs => {
                crate::core::images::blocks::NandLayout::Bb
            }
            CliConsoleType::corona => crate::core::images::blocks::NandLayout::Sb,
            CliConsoleType::corona4g
            | CliConsoleType::winchester
            | CliConsoleType::winchester4g => crate::core::images::blocks::NandLayout::Emmc,
        };
        info!(
            "[cli] Synthesizing blank image from scratch (Layout: {:?}).",
            layout
        );
        commands.push(InternalCommand::CreateImage { layout });
    }

    commands.push(InternalCommand::ParseIni {
        path: ini_path,
        target: console_section,
        ini_base: ini_dir.clone(),
        common: common_dir.clone(),
        data: data_dir.clone(),
        payloads: payloads_dir,
        smc: smc_dir,
    });

    if args.bl_key.is_some() {
        info!("[cli] Warning: Overriding the 1BL key (-b) is currently not implemented. Using default retail key.");
    }

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
            commands.push(InternalCommand::ApplyPatch {
                path: addon_path,
                ptype: 2,
                target: None,
            });
        } else {
            error!("[cli] Warning: Addon patch not found: {}", addon);
        }
    }

    for raw_patch in &args.raw_patches {
        for patch_str in raw_patch.split(';').filter(|s| !s.is_empty()) {
            let parts: Vec<&str> = patch_str.split(',').collect();
            if parts.len() != 2 {
                error!(
                    "[cli] Malformed raw patch entry (expected filename,offset): {}",
                    patch_str
                );
                continue;
            }

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

            if !patch_path.exists() {
                error!("[cli] Raw patch file not found: {}", filename);
                continue;
            }
            if let Some(off) = offset {
                info!("[cli] Raw patch: {:?} at offset 0x{:X}", patch_path, off);
                commands.push(InternalCommand::ApplyPatch {
                    path: patch_path,
                    ptype: 3,
                    target: None,
                });
            } else {
                error!(
                    "[cli] Invalid offset value '{}' in raw patch: {}",
                    offset_str, patch_str
                );
            }
        }
    }

    commands.push(InternalCommand::Build {
        output: output_path,
        target: 0,
    });

    execute_internal_commands(&mut session, commands)?;
    Ok(session)
}

fn handle_extract(args: &GgxArgs, session: &mut Session) -> Result<(), CliError> {
    let data_dir = args
        .fw_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("mydata"));
    let all = matches!(args.mode, Some(GgxMode::Extract { all: true }));

    if args.ecc.is_some() && args.source_nand.is_some() {
        return Err(CliError::InvalidExtractSource);
    }

    session.build_config.data_dir = Some(data_dir.clone());
    for group in &args.options {
        for (k, v) in group {
            if k.eq_ignore_ascii_case("nomobile") {
                session.build_config.options.core_builder.nomobile =
                    Some(v.eq_ignore_ascii_case("true"));
            }
        }
    }

    let base_output_dir = args.output_dir.clone().unwrap_or_else(|| data_dir.clone());
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let output_dir = base_output_dir.join(format!("extract-{}", timestamp));

    if let Some(ecc_path) = &args.ecc {
        handle_extract_ecc(ecc_path, &output_dir)?;
        return Ok(());
    }

    // -l = NAND image, else auto-discover from data dir
    let image_path = if let Some(p) = &args.source_nand {
        p.clone()
    } else {
        let candidates = [
            data_dir.join("nanddump.bin"),
            data_dir.join("nanddump1.bin"),
            data_dir.join("nanddump2.bin"),
            data_dir.join("nanddump.ecc"),
            data_dir.join("nanddump1.ecc"),
            data_dir.join("nanddump2.ecc"),
            data_dir.join("nanddump"),
            data_dir.join("updflash.bin"),
            data_dir.join("updflash.ecc"),
        ];
        candidates
            .into_iter()
            .find(|p| p.exists())
            .ok_or(CliError::ExtractSourceNotFound)?
    };

    if image_path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("ecc"))
    {
        handle_extract_ecc(&image_path, &output_dir)?;
        return Ok(());
    }

    let has_cpukey = if let Some((key, normalized)) = load_cpu_key(args, &data_dir)? {
        session.build_config.pending_key = Some(key);
        session.build_config.options.keys.cpukey = Some(normalized);
        true
    } else {
        false
    };

    if has_cpukey {
        if let Some(cpukey) = &session.build_config.options.keys.cpukey {
            info!("[cli] Extract: loaded CPU key {}", cpukey);
        }
    }

    info!(
        "[cli] Extract: IMAGE={:?}, Output={:?} ({}{}, {})",
        image_path,
        output_dir,
        if all { "all" } else { "minimal" },
        if has_cpukey { "" } else { ", encrypted-only" },
        if has_cpukey {
            "encrypted+decrypted"
        } else {
            "encrypted"
        }
    );

    execute_internal_commands(
        session,
        vec![
            InternalCommand::ParseImage {
                path: image_path,
                key: None,
            },
            InternalCommand::ExtractAll {
                output_dir,
                all,
                include_decrypted: has_cpukey,
            },
        ],
    )?;

    Ok(())
}
