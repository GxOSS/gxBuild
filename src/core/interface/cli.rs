/*
    cli.rs - xeBuild style command line interface

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under the GNU General Public License Version 2.0
*/

#![cfg(feature = "cli")]

use crate::core::interface::gxscript::GxScriptEngine;
use crate::core::logger;
use crate::core::session::{InternalCommand, Session};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use log::{error, info, warn};
use std::path::PathBuf;
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
    #[arg(short = 't', long = "type")]
    pub build_type: Option<CliBuildType>,

    /// 32 character CPU hex key (override, can be elsewhere)
    #[arg(short = 'p', long = "cpukey")]
    pub cpu_key: Option<String>,

    /// 32 character 1BL hex key (override, can be elsewhere)
    #[arg(short = 'b', long = "1blkey")]
    pub bl_key: Option<String>,

    /// Console motherboard type
    #[arg(short = 'c', long = "console")]
    pub console: Option<CliConsoleType>,

    /// INI directory - contains _retail.ini, bootloaders, flashfs/ (defaults to .)
    #[arg(short = 'd', long = "build")]
    pub data_dir: Option<PathBuf>,

    /// Folder for shared bootloaders (defaults to <ini_dir>/../common)
    #[arg(short = 'm', long = "common")]
    pub common_dir: Option<PathBuf>,

    /// Data directory - nand dump, cpu key, smc, fcrt, keyvault (defaults to ./data)
    #[arg(short = 'f', long = "data")]
    pub fw_dir: Option<PathBuf>,

    /// Outputs SHA-1 of final image to <file>
    #[arg(short = 's', long = "sha")]
    pub sha_file: Option<PathBuf>,

    /// Set xeBuild options (e.g. -o nomobile;cputemp=80)
    #[arg(short = 'o', long = "options", value_parser = parse_key_val)]
    pub options: Vec<Vec<(String, String)>>,

    /// Append addon patches or RGLP (.bin file name)
    #[arg(short = 'a', long = "addon")]
    pub addons: Vec<String>,

    /// Adds _<ext> into firmware ini and patches file names
    #[arg(short = 'i', long = "fwext")]
    pub ini_ext: Option<String>,

    /// Adds _<ext> into ini bl section name and patches file names
    #[arg(short = 'r', long = "iniext")]
    pub bl_ext: Option<String>,

    /// Adds raw patch to NAND (format: file,offset)
    #[arg(short = '8', long = "raw")]
    pub raw_patches: Vec<String>,

    /// Show version mapped natively by clap.

    /// Optional source NAND image
    #[arg(short = 'l', long = "image")]
    pub source_nand: Option<PathBuf>,

    /// Optional system update file (e.g. xboxupd.bin)
    #[arg(short = 'u', long = "update")]
    pub xboxupd: Option<PathBuf>,

    /// Set preset for build
    #[arg(short = 'e', long = "preset")]
    pub preset: Option<String>,

    /// Direct session access
    #[arg(short = 'n', long = "cmd")]
    pub cmd: Option<String>,

    /// Format of output image (system, full, xell, shadow)
    #[arg(short = 'h', long = "format")]
    pub format: Option<String>,

    /// Output directory / location of file
    #[arg(short = 'g', long = "output-dir")]
    pub output_dir: Option<PathBuf>,

    /// Optional output image name
    pub output: Option<PathBuf>,

    /// Force XSB layout
    #[arg(short = 'x', long = "xsb")]
    pub xsb: bool,

    /// Build full NAND image (not just system portion)
    #[arg(long = "fullimage")]
    pub full_image: bool,

    /// Run a Rhai script file
    #[arg(long = "script")]
    pub script: Option<PathBuf>,

    /// Launch interactive Rhai shell
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
        Some(GgxMode::Extract) => "extract",
        Some(GgxMode::Client) => "client",
        Some(GgxMode::Update) => "update",
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
        Some(GgxMode::Extract) => {
            session.extract_all(
                args.output_dir
                    .clone()
                    .unwrap_or_else(|| std::path::PathBuf::from(".")),
            );
        }
        Some(GgxMode::Client) => {
            info!("[cli] Client mode selected.");
        }
        Some(GgxMode::Update) => {
            info!("[cli] Update mode not fully implemented yet.");
        }
    }

    if session_prepared {
        // --- Scripting & Shell Handlers ---
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
                    if let Ok(hash) = crate::builder::deps::excrypt::sha(&[&data]) {
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

fn handle_build(args: &GgxArgs, session: &mut Session) -> anyhow::Result<()> {
    let build_type = args
        .build_type
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing required argument: --type (-t)"))?;
    let console_type = args
        .console
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing required argument: --console (-c)"))?;

    // --- Path Resolution ---
    // -d = INI directory (contains _retail.ini, bootloaders, flashfs/)
    let ini_dir = args.data_dir.clone().unwrap_or_else(|| PathBuf::from("."));

    // -f = data directory (nand dump, cpu key, smc, fcrt, keyvault)
    let data_dir = args.fw_dir.clone().unwrap_or_else(|| PathBuf::from("data"));

    // -m = common directory (shared bootloaders, defaults to <ini_dir>/../common)
    let resolved_common_dir = args
        .common_dir
        .clone()
        .unwrap_or_else(|| ini_dir.join("../common"));

    // --- Options INI Loading (<data>/options.ini) ---
    let options_path = data_dir.join("options.ini");
    if options_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&options_path) {
            match crate::core::data::optini::parse_options_ini(&content) {
                Ok(opts) => {
                    session.options.merge(opts);
                    info!("[cli] Merged defaults from {:?}", options_path);
                }
                Err(e) => warn!("[cli] Failed to parse options.ini: {}", e),
            }
        }
    }

    // --- CLI Command-Line Specific Overrides ---
    let mut cli_overrides = crate::core::data::optini::OptionsIni::new();
    if let Some(key) = &args.cpu_key {
        cli_overrides.cpukey = Some(key.clone());
    }
    if args.full_image {
        cli_overrides.full_image = Some(true);
    }
    if args.xsb {
        cli_overrides.xsb = Some(true);
    }
    session.options.merge(cli_overrides);

    // --- CLI Generic Options Overrides (-o) ---
    for group in &args.options {
        for (k, v) in group {
            let mut o = crate::core::data::optini::OptionsIni::new();
            match k.to_lowercase().as_str() {
                "region" | "avregion" => o.avregion = Some(v.clone()),
                "gameregion" => o.gameregion = Some(v.clone()),
                "dvdregion" => o.dvdregion = Some(v.clone()),
                "unsafe" => {
                    o.gxunsafe = Some(v.eq_ignore_ascii_case("true"));
                    if o.gxunsafe.unwrap_or(false) {
                        warn!("[cli] Unsafe Mode enabled via CLI override.");
                    }
                }
                "nomobile" => o.nomobile = Some(v.eq_ignore_ascii_case("true")),
                "noenter" => o.noenter = Some(v.eq_ignore_ascii_case("true")),
                "noremap" => o.noremap = Some(v.eq_ignore_ascii_case("true")),
                "nandmu" => o.nandmu = Some(v.eq_ignore_ascii_case("true")),
                "cputemp" => o.cputemp = Some(v.clone()),
                "gputemp" => o.gputemp = Some(v.clone()),
                "edramtemp" => o.edramtemp = Some(v.clone()),
                "overcputemp" => o.overcputemp = Some(v.clone()),
                "overgputemp" => o.overgputemp = Some(v.clone()),
                "overedramtemp" => o.overedramtemp = Some(v.clone()),
                "cpufan" => o.cpufan = Some(v.clone()),
                "gpufan" => o.gpufan = Some(v.clone()),
                "macid" | "mac" => o.macid = Some(v.clone()),
                "dvdkey" => o.dvdkey = Some(v.clone()),
                "cfldv" => o.cfldv = Some(v.clone()),
                "xellbutton" => o.xellbutton = Some(v.clone()),
                "xellbutton2" => o.xellbutton2 = Some(v.clone()),
                "cygnos" => o.cygnos = Some(v.eq_ignore_ascii_case("true")),
                "demon" => o.demon = Some(v.eq_ignore_ascii_case("true")),
                "smcnoeject" => o.smcnoeject = Some(v.eq_ignore_ascii_case("true")),
                "smcnoblink" => o.smcnoblink = Some(v.eq_ignore_ascii_case("true")),
                "patchsmc" => o.patchsmc = Some(v.eq_ignore_ascii_case("true")),
                "olddvd" => o.olddvd = Some(v.eq_ignore_ascii_case("true")),
                "nodvd" => o.nodvd = Some(v.eq_ignore_ascii_case("true")),
                "dualboot" => o.dualboot = Some(v.eq_ignore_ascii_case("true")),
                "nolog" => o.nolog = Some(v.eq_ignore_ascii_case("true")),
                "noinfo" => o.noinfo = Some(v.eq_ignore_ascii_case("true")),
                "verbose" => {} // Handled during logger init
                _ => warn!("[cli] Unhandled generic option override: {}", k),
            }
            session.options.merge(o);
        }
    }

    if session.options.gxunsafe.unwrap_or(false) {
        warn!("[cli] UNEXPECTED BEHAVIOR ENABLED: Unsafe Mode is active. CRC32 mismatches will be bypassed.");
    }

    // Resolve INI file path: <ini_dir>/_<type>.ini
    let build_type_str = format!("{:?}", build_type).to_lowercase();
    let ini_suffix = args
        .ini_ext
        .as_ref()
        .map(|ext| format!("_{}", ext))
        .unwrap_or_default();
    let ini_filename = format!("_{}{}.ini", build_type_str, ini_suffix);
    let ini_path = ini_dir.join(&ini_filename);

    let console_base = format!("{:?}", console_type).to_lowercase();
    let console_section = if let Some(ext) = &args.bl_ext {
        format!("{}_{}", console_base, ext)
    } else {
        console_base.clone()
    };

    // --- INI Pre-Parsing ---
    let mut target_filenames = std::collections::HashSet::new();
    if let Ok(ini) = crate::core::data::xeini::parse_xe_ini(&ini_path, &console_section) {
        for entry in ini.main {
            target_filenames.insert(entry.filename.to_lowercase());
        }
        for entry in ini.security {
            target_filenames.insert(entry.filename.to_lowercase());
        }
        for entry in ini.flashfs {
            target_filenames.insert(entry.filename.to_lowercase());
        }
    } else {
        anyhow::bail!("Could not find or read INI at {:?}", ini_path);
    }

    info!("[cli] Build Configuration");
    info!("[cli]   Type:      {:?}", build_type);
    info!("[cli]   Console:   {}", console_base);
    info!("[cli]   Section:   {}", console_section);
    info!("[cli]   INI Dir:   {:?}", ini_dir);
    info!("[cli]   Data Dir:  {:?}", data_dir);
    info!("[cli]   Common:    {:?}", resolved_common_dir);
    info!("[cli]   INI File:  {:?}", ini_path);

    // Discovery Phase
    // Enqueue FinalizeFlashfs to run after all asset discovery
    session.enqueue(InternalCommand::FinalizeFlashfs);

    // Try to find and enqueue a file by name across search paths
    let enqueue_if_found =
        |session: &mut Session, name: &str, search_paths: &[&std::path::PathBuf]| {
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
                    session.enqueue(InternalCommand::Update {
                        path: candidate_lower,
                    });
                    return true;
                }
            }
            false
        };

    // Build search path list: INI dir, INI subfolders, common
    let ini_flashfs = ini_dir.join("flashfs");
    let ini_data = ini_dir.join("data");
    let mut search_paths: Vec<&std::path::PathBuf> = vec![&ini_dir];
    if ini_flashfs.exists() && ini_flashfs.is_dir() {
        search_paths.push(&ini_flashfs);
    }
    if ini_data.exists() && ini_data.is_dir() {
        search_paths.push(&ini_data);
    }
    if resolved_common_dir.exists() && resolved_common_dir.is_dir() {
        search_paths.push(&resolved_common_dir);
    }

    // Enqueue files from INI target filenames, track which CF/CG were actually found
    let mut cf_on_disk = false;
    let mut cg_on_disk = false;
    info!(
        "[cli] Discovering {} assets from INI targets...",
        target_filenames.len()
    );
    for filename in &target_filenames {
        let found = enqueue_if_found(session, filename, &search_paths);
        if filename.starts_with("cf_") && filename.ends_with(".bin") && found {
            cf_on_disk = true;
        }
        if filename.starts_with("cg_") && filename.ends_with(".bin") && found {
            cg_on_disk = true;
        }
    }

    // CF/CG Fallback: if not found on disk, search update containers
    if !cf_on_disk || !cg_on_disk {
        info!("[cli] CF/CG not found on disk, searching update containers...");

        // Priority 1: xboxupd.bin in INI dir
        let xboxupd_path = ini_dir.join("xboxupd.bin");
        if xboxupd_path.exists() {
            info!("[cli] Found xboxupd.bin in INI dir: {:?}", xboxupd_path);
            session.enqueue(InternalCommand::Update { path: xboxupd_path });
        } else {
            // Priority 2: su*** files in INI dir
            if let Ok(entries) = std::fs::read_dir(&ini_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let name = path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_lowercase();
                        if name.starts_with("su") {
                            info!("[cli] Found STFS container in INI dir: {:?}", path);
                            session.enqueue(InternalCommand::Update { path });
                        }
                    }
                }
            }
        }
    }

    // Data Dir Discovery (-f) - NAND, CPU Key, Security, SMC, FCRT, KV
    info!(
        "[cli] Scanning Data Dir (nand/key/smc/fcrt/kv): {:?}",
        data_dir
    );

    // NAND Image Discovery (data dir only)
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
        info!("[cli] Auto-discovered source NAND image from {:?}", path);
        session.enqueue(InternalCommand::ParseImage { path, key: None });
    } else {
        // Block type selection here needs a CLI arg override
        warn!("[cli] No NAND image found in data dir or specified via -f");
        info!("[cli] Attempting Donor Image");
        let layout = match console_type {
            CliConsoleType::xenon => crate::core::images::blocks::NandLayout::Xsb,
            CliConsoleType::zephyr | CliConsoleType::falcon | CliConsoleType::jasper => {
                crate::core::images::blocks::NandLayout::Sb
            }
            CliConsoleType::jasper256
            | CliConsoleType::jasper512
            | CliConsoleType::jasperbb
            | CliConsoleType::jasperbigffs => crate::core::images::blocks::NandLayout::Bb,
            CliConsoleType::trinity => crate::core::images::blocks::NandLayout::Sb,
            CliConsoleType::trinitybigffs => crate::core::images::blocks::NandLayout::Bb,
            CliConsoleType::corona => crate::core::images::blocks::NandLayout::Sb,
            CliConsoleType::corona4g | CliConsoleType::winchester => {
                crate::core::images::blocks::NandLayout::Emmc
            }
        };
        info!(
            "[cli] Synthesizing blank image from scratch (Layout: {:?}).",
            layout
        );
        session.enqueue(InternalCommand::CreateImage { layout });
    }

    // CPU Key Discovery (data dir only)
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
                            info!("[cli] Auto-discovered CPU Key binary from {:?}", p);
                            key_found = true;
                            break;
                        }
                    }
                } else {
                    if let Ok(text) = std::fs::read_to_string(p) {
                        let clean_key = text.trim();
                        if clean_key.len() >= 32 {
                            session.set_cpukey(clean_key.to_string());
                            info!("[cli] Auto-discovered CPU Key string from {:?}", p);
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

    // Security Assets (SMC, SMC config, FCRT, KV) from data dir
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
                let name = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase();
                info!(
                    "[cli] Discovered security asset: {:?} ({} bytes)",
                    p,
                    data.len()
                );
                session.pending_assets.insert(name, data);
            }
        }
    }

    // Enqueue INI Parsing
    session.parse_ini(
        &ini_path,
        console_section,
        &ini_dir,
        &resolved_common_dir,
        &data_dir,
    );

    // 1BL Key Warning
    if args.bl_key.is_some() {
        info!("[cli] Warning: Overriding the 1BL key (-b) is currently not implemented. Using default retail key.");
    }

    // Addon Patches
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
                target: None,
            });
        } else {
            error!("[cli] Warning: Addon patch not found: {}", addon);
        }
    }

    // Raw Patches (-8)
    for raw_patch in &args.raw_patches {
        // Support semicolon-separated patches: "file1.bin,0x1234;file2.bin,0x5678"
        for patch_str in raw_patch.split(';').filter(|s| !s.is_empty()) {
            // Parse format: filename.ext,offset
            let parts: Vec<&str> = patch_str.split(',').collect();
            if parts.len() == 2 {
                let filename = parts[0];
                let offset_str = parts[1];

                let patch_path = if PathBuf::from(filename).is_absolute() {
                    PathBuf::from(filename)
                } else {
                    let p = data_dir.join(filename);
                    if p.exists() {
                        p
                    } else {
                        ini_dir.join(filename)
                    }
                };

                let offset = if offset_str.starts_with("0x") {
                    u64::from_str_radix(&offset_str[2..], 16).ok()
                } else {
                    offset_str.parse::<u64>().ok()
                };

                if patch_path.exists() {
                    if let Some(off) = offset {
                        info!("[cli] Raw patch: {:?} at offset 0x{:X}", patch_path, off);
                        session.enqueue(InternalCommand::ApplyPatch {
                            path: patch_path,
                            ptype: 3, // Raw patch
                            target: None,
                        });
                    } else {
                        error!(
                            "[cli] Invalid offset value '{}' in raw patch: {}",
                            offset_str, patch_str
                        );
                    }
                } else {
                    error!("[cli] Raw patch file not found: {}", filename);
                }
            } else {
                error!(
                    "[cli] Malformed raw patch entry (expected filename,offset): {}",
                    patch_str
                );
            }
        }
    }

    // Output Path Resolution
    let output_path = args.output.clone().unwrap_or_else(|| {
        args.output_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("updflash.bin"))
    });
    session.build(output_path.clone(), 0); // Target 0 for now

    Ok(())
}

impl Session {
    pub fn set_verbose(&mut self, _v: bool) {
        // session verbosity logic
    }
}
