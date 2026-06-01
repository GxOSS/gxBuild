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

#![cfg(feature = "cli")]

use crate::builder::ecc::handle_extract_ecc;
#[cfg(feature = "rhai")]
use crate::core::interface::gxscript::GxScriptEngine;
use crate::core::logger;
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

    #[error("Session error: {0}")]
    Session(#[from] crate::core::session::SessionError),

    #[error("Builder error: {0}")]
    Builder(#[from] crate::builder::builder::BuilderError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
use crate::core::session::{InternalCommand, Session};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use log::{error, info, warn};
use std::path::PathBuf;
#[cfg(feature = "rhai")]
use std::sync::{Arc, Mutex};

/// xeBuild v1.21.810 clone - System image builder
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

    /// Show version mapped natively by clap.

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
    trinitybigffs,
    corona,
    corona4g,
    winchester,
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

    let session = Session::new();

    let mut session = session;

    let mut session_prepared = true;
    match args.mode.clone() {
        Some(GgxMode::Build { .. }) | None => {
            if let Err(e) = handle_build(&args, &mut session) {
                error!("[cli] Build Setup Failed: {}", e);
                session_prepared = false;
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

        if let Err(e) = session.run() {
            error!("[cli] Session failed: {}", e);
        } else if let Some(GgxMode::Build { .. }) | None = args.mode {
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

impl Session {
    pub fn set_verbose(&mut self, _v: bool) {
        // session verbosity logic
    }
}
