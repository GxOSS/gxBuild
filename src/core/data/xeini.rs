/*
    xeini.rs
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/



// xeBuild CSV-Style INI parser

// Input .ini file and section
// Check and verify ini file
// Check and verify the data is present
// Check the data against the provided hashes
// Return the section, security and flashfs as a struct

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use crc32fast::Hasher;
use thiserror::Error;
use crate::builder::builder::NandSkeleton;
use log::{info, warn};

#[derive(Error, Debug)]
pub enum IniError {
    #[error("[ini] Ini section not found: {0}")]
    SectionNotFound(String),
    #[error("[ini] File not found: {0}")]
    FileNotFound(String),
    #[error("[ini] INI CRC32 mismatch for {0}: expected {1}, got {2}")]
    HashMismatch(String, String, String),
    #[error("[ini] INI IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("[ini] No version string in INI")]
    NoVersion(),
    #[error("[ini] Incorrect formatting in options.ini")]
    BadOptionsFormat(),
    #[error("[ini] Incorrect formatting in {0}"),]
    BadBuildFormat(String),
}

#[derive(Debug, Clone)]
pub struct BuildIniEntry {
    pub filename: String,
    pub path: PathBuf,
    pub hash: Option<String>,
}

pub struct BuildIniPatch {
    pub enabled: bool,
    pub path: Option<PathBuf>,
}

pub struct XeBuildIni {
    pub name: String,
    pub buildtype: String,
    pub main: Vec<BuildIniEntry>,
    pub security: Vec<BuildIniEntry>,
    pub flashfs: Vec<BuildIniEntry>,
    pub patch: BuildIniPatch,
}

pub struct OptionsIni {
    pub ctype: String,
    pub _1blkey: String,
    pub cpukey: String,
    pub cfldv: String,
    pub dvdkey: String,
    pub xellbutton: String,
    pub xellbutton2: String,
    pub cygnos: bool,
    pub demon: bool,
    pub smcnoeject: bool,
    pub smcnoblink: bool,
    pub patchsmc: bool,
    pub olddvd: bool,
    pub nodvd: bool,
    pub dualboot: bool,
    pub nomobile: bool,
    pub noremap: bool,
    pub noecdremap: bool,
    pub nandmu: bool,
    pub nosecurity: bool,
    pub nosusecurity: bool,
    pub smcnocheck: bool,
    pub cputemp: String,
    pub gputemp: String,
    pub edramtemp: String,
    pub overcputemp: String,
    pub overgputemp: String,
    pub overedramtemp: String,
    pub cpufan: String,
    pub gpufan: String,
    pub avregion: String,
    pub gameregion: String,
    pub dvdregion: String,
    pub macid: String,
}

impl OptionsIni {
    pub fn new() -> Self {
        OptionsIni {
            _type: String::new("options"),
            _1blkey: String::new("00000000000000000000000000000000"),
            cpukey: String::new("00000000000000000000000000000000"),
            cfldv: String::new("0"),
            dvdkey: String::new("00000000000000000000000000000000"),
            xellbutton: String::new("0"),
            xellbutton2: String::new("0"),
            cygnos: false,
            demon: false,
            smcnoeject: false,
            smcnoblink: false,
            patchsmc: false,
            olddvd: false,
            nodvd: false,
            dualboot: false,
            nomobile: false,
            noremap: false,
            noecdremap: false,
            nandmu: false,
            nosecurity: false,
            nosusecurity: false,
            smcnocheck: false,
            cputemp: String::new("0"),
            gputemp: String::new("0"),
            edramtemp: String::new("0"),
            overcputemp: String::new("0"),
            overgputemp: String::new("0"),
            overedramtemp: String::new("0"),
            cpufan: String::new("0"),
            gpufan: String::new("0"),
            avregion: String::new("0"),
            gameregion: String::new("0"),
            dvdregion: String::new("0"),
            macid: String::new("00000000000000000000000000000000"),
            noenter: false,
            nolog: false,
            noinfo: false,
            gxunsafe: false,
        }
    }
}

fn get_hash(path: impl AsRef<Path>) -> std::io::Result<String> {
    let data = fs::read(path)?;
    let mut hasher = Hasher::new();
    hasher.update(&data);
    Ok(format!("{:08x}", hasher.finalize()))
}

/// Parses xeBuild INI, validates files, and checks hashes.
/// - `ini_base_path`: Folder where the INI and its security/flashfs files are.
/// - `common_path`: Folder where the core bootloaders (main section) are.

pub fn parse_options_ini(
    content: &str,
) -> Result<OptionsIni, IniError> {
    info!("[ini] Parsing options.ini");
    
    let mut sections: HashMap<String, String> = HashMap::new();
    let mut option = String::new();

    let mut options = OptionsIni::new();
    // 1. Initial Parse into raw sections
    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            return Err(IniError::BadOptionsFormat());
        } else {
            let part: Vec<String> = line.split(' = ')
                .map(|s| s.trim_end_matches(';').trim().to_string())
                .collect();
                .as_slice();
            match part.as_slice() {
                [key, value] => {
                    match key.to_lowercase().as_str() {
                        "type" => options._type = value.clone(),
                        "1blkey" => options._1blkey = value.clone(),
                        "cpukey" => options.cpukey = value.clone(),
                        "cfldv" => options.cfldv = value.clone(),
                        "dvdkey" => options.dvdkey = value.clone(),
                        "xellbutton" => options.xellbutton = value.clone(),
                        "xellbutton2" => options.xellbutton2 = value.clone(),
                        "cygnos" => options.cygnos = value.eq_ignore_ascii_case("true"),
                        "demon" => options.demon = value.eq_ignore_ascii_case("true"),
                        "smcnoeject" => options.smcnoeject = value.eq_ignore_ascii_case("true"),
                        "smcnoblink" => options.smcnoblink = value.eq_ignore_ascii_case("true"),
                        "patchsmc" => options.patchsmc = value.eq_ignore_ascii_case("true"),
                        "olddvd" => options.olddvd = value.eq_ignore_ascii_case("true"),
                        "nodvd" => options.nodvd = value.eq_ignore_ascii_case("true"),
                        "dualboot" => options.dualboot = value.eq_ignore_ascii_case("true"),
                        "nomobile" => options.nomobile = value.eq_ignore_ascii_case("true"),
                        "noremap" => options.noremap = value.eq_ignore_ascii_case("true"),
                        "noecdremap" => options.noecdremap = value.eq_ignore_ascii_case("true"),
                        "nandmu" => options.nandmu = value.eq_ignore_ascii_case("true"),
                        "nosecurity" => options.nosecurity = value.eq_ignore_ascii_case("true"),
                        "nosusecurity" => options.nosusecurity = value.eq_ignore_ascii_case("true"),
                        "smcnocheck" => options.smcnocheck = value.eq_ignore_ascii_case("true"),
                        "noenter" => options.noenter = value.eq_ignore_ascii_case("true"),
                        "nolog" => options.nolog = value.eq_ignore_ascii_case("true"),
                        "noinfo" => options.noinfo = value.eq_ignore_ascii_case("true"),
                        "gxunsafe" => options.gxunsafe = value.eq_ignore_ascii_case("true"),
                        "cputemp" => options.cputemp = value.clone(),
                        "gputemp" => options.gputemp = value.clone(),
                        "edramtemp" => options.edramtemp = value.clone(),
                        "overcputemp" => options.overcputemp = value.clone(),
                        "overgputemp" => options.overgputemp = value.clone(),
                        "overedramtemp" => options.overedramtemp = value.clone(),
                        "cpufan" => options.cpufan = value.clone(),
                        "gpufan" => options.gpufan = value.clone(),
                        "avregion" => options.avregion = value.clone(),
                        "gameregion" => options.gameregion = value.clone(),
                        "dvdregion" => options.dvdregion = value.clone(),
                        "macid" => options.macid = value.clone(),
                        _ => warn!("[ini] Unknown option: {}", key),
                    }
                }
                _ => {} // Skip malformed lines
            }
        }
    }
    Ok(options)
}

pub fn parse_xe_ini(
    content: &str,
    target_section: &str,
    ini_base_path: impl AsRef<Path>,
    common_path: impl AsRef<Path>,
    data_path: impl AsRef<Path>,
) -> Result<XeBuildIni, IniError> {
    
    info!("[ini] Parsing section '{}' from INI (base: {:?})", target_section, ini_base_path.as_ref());
    
    let ini_base = ini_base_path.as_ref(); 
    let common_base = common_path.as_ref();
    let data_base = data_path.as_ref();
    
    let patches_dir = ini_base.join("data");

    let mut sections: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    let mut current_section = String::new();

    let mut patch_path = None;

    let build_type = ini_base_path
        .file_stem()
        .and_then(|n| n.to_str())
        .map(|s| s.trim_start_matches('_').to_string())
        .unwrap_or_default();
        .to_lowercase()

    let console_type = target_section
        .split('_')
        .next()
        .unwrap_or("")
        .trim_end_matches("bl")
        .to_lowercase();

    let main_section_name = target_section
        .split_once('_')
        .map(|(prefix, suffix)| format!("{}_{}", prefix.trim_end_matches("bl"), suffix))
        .unwrap_or_else(|| target_section.trim_end_matches("bl").to_string());
    
    let validate_and_resolve = |search_paths: &[&Path], filename: &str, expected_hash: Option<&str>| -> Result<IniEntry, IniError> {
        let mut full_path = None;

        for base in search_paths {
            let p = if filename.starts_with("..\\") || filename.starts_with("../") {
                base.parent().unwrap_or(base).join(&filename[3..])
            } else {
                base.join(filename)
            };
            
            if p.exists() {
                full_path = Some(p);
                break;
            }
        }

        if (!full_path.exists()) {
            warn!("[ini] File not found: {}", filename);
        } else {
            info!("[ini] File {} found at path: {}", filename, full_path.display());
        }
        
        // If not found on disk, we revert to a best-guess path in the first search directory
        // but mark it for targeted discovery.
        let full_path = full_path.unwrap_or_else(|| search_paths[0].join(filename));

        Ok(IniEntry {
            filename: filename.to_string(),
            path: full_path,
            hash: expected_hash,
            require_patch: require_patch,
        })
    };
    
    // xeBuild auto patching
    match build_type {
        "retail" => {
            info!("[ini] Retail build type selected"),
        },
        "glitch1" | "glitch2" | "glitch2m" | "glitch3" | "jtag" | "1f" | "2f" | "devgl" | "devkit" | "xdkbuild" | "rgbuild" => {
            info!("[ini] {0} build type selected", build_type),
            match build_type {
                "glitch1" => {
                    let patch_path = match console_type {
                        "trinity" | "corona" => Some(patches_dir.join("patches_trinity.bin")),
                        "zephyr" | "jasper" | "falcon" => Some(patches_dir.join("patches_fat.bin")),
                        "xenon" => None,
                        _ => None,
                    };
                    if (!patch_path.exists() || patch_path.is_none()) { 
                        error!("[ini] Glitch1 Patches for platform {} not found at path: {}", main_section_name, patch_path.display());
                    } else {
                        info!("[ini] Glitch1 Patches for platform {} found at path: {}", main_section_name, patch_path.display());
                    }
                }
                "glitch2" => {
                    let patch_path = patches_dir.join(format!("patches_g2{}.bin", main_section_name));
                    if (!patch_path.exists()) { 
                        error!("[ini] Glitch2 Patches for platform {} not found at path: {}", main_section_name, patch_path.display());
                    } else {
                        info!("[ini] Glitch2 Patches for platform {} found at path: {}", main_section_name, patch_path.display());
                    }
                }
                "glitch2m" | "devgl" | "xdkbuild" => {
                    let patch_path = patches_dir.join(format!("patches_g2m{}.bin", main_section_name));
                    if (!patch_path.exists()) { 
                        error!("[ini] {} Patches for platform {} not found at path: {}", build_type, main_section_name, patch_path.display());
                    } else {
                        info!("[ini] {} Patches for platform {} found at path: {}", build_type, main_section_name, patch_path.display());
                    }
                }
                "glitch3" => {
                    let patch_path = patches_dir.join(format!("patches_g3{}.bin", main_section_name));
                    let patch_path2 = patches_dir.join(format!("patches_g2{}.bin", main_section_name));
                    if (!patch_path.exists()) {
                        if (patch_path2.exists()) {
                            warn!("[ini] Glitch3 Patches for platform {} not found at path: {}", main_section_name, patch_path.display());
                            info!("[ini] Falling back to Glitch2 Patches for platform {} found at path: {}", main_section_name, patch_path2.display());
                            patch_path = patch_path2;
                        } else {
                            warn!("[ini] Glitch3 Patches for platform {} not found at path: {}", main_section_name, patch_path.display());
                            error!("[ini] Fallback Glitch2 Patches for platform {} not found at path: {}", main_section_name, patch_path2.display());
                        }
                    } else {
                        info!("[ini] Glitch3 Patches for platform {} found at path: {}", main_section_name, patch_path.display());
                    }
                }
                "devkit" => {
                    let patch_path = patches_dir.join(format!("patches_dev{}.bin", main_section_name));
                    if (!patch_path.exists()) { 
                        error!("[ini] Devkit Patches for platform {} not found at path: {}", main_section_name, patch_path.display());
                    } else {
                        info!("[ini] Devkit Patches for platform {} found at path: {}", main_section_name, patch_path.display());
                    }
                }
                "rgbuild" => {
                    let patch_path = patches_dir.join(format!("patches_rg{}.bin", main_section_name));
                    if (!patch_path.exists()) { 
                        error!("[ini] RGBuild Patches for platform {} not found at path: {}", main_section_name, patch_path.display());
                    } else {
                        info!("[ini] RGBuild Patches for platform {} found at path: {}", main_section_name, patch_path.display());
                    }
                }
                "1f" => {
                    // ???           
                }
                "jtag" | "2f" => {
                    // Need payload or smc
                    // Need 4532 cf/cg
                }
            }
        },
        _ => return Err(IniError::BadBuildType(build_type)),
    }

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].to_lowercase();
        } else if !current_section.is_empty() {
            let parts: Vec<String> = line.split(',')
                .map(|s| s.trim_end_matches(';').trim().to_string())
                .collect();
            sections.entry(current_section.clone()).or_default().push(parts);
        }
    }

    let main_data_raw = sections.get(&target_section.to_lowercase())
        .ok_or_else(|| IniError::SectionNotFound(target_section.to_string()))?;

    let version_raw = sections.get("version")
        .cloned()
        .unwrap_or_default();

    let security_data_raw = sections.get("security")
        .cloned()
        .unwrap_or_default();

    let flashfs_data_raw = sections.get("flashfs")
        .cloned()
        .unwrap_or_default();

    let mut main_entries = Vec::new();
    for entry in main_data_raw {
        main_entries.push(validate_and_resolve(&[ini_base, common_base], &entry[0], entry.get(1).map(|s| s.as_str()))?);
    }

    let mut security_entries = Vec::new();
    for entry in security_data_raw {
        if !entry.is_empty() {
            security_entries.push(validate_and_resolve(&[ini_base], &entry[0], None)?);
        }
    }

    let mut flashfs_entries = Vec::new();
    let flashfs_subfolder = ini_base.join("flashfs");
    let flashfs_paths = if flashfs_subfolder.exists() {
        vec![ini_base, &flashfs_subfolder]
    } else {
        vec![ini_base]
    };

    for entry in flashfs_data_raw {
        if entry.len() >= 2 {
            flashfs_entries.push(validate_and_resolve(&flashfs_paths, &entry[0], Some(&entry[1]))?);
        } else if entry.len() == 1 {
            flashfs_entries.push(validate_and_resolve(&flashfs_paths, &entry[0], None)?);
        }
    }

    let mut patches_needed = BuildIniPatch {
        enabled: !matches!(build_type, "retail"),
        path: None,
    };

    if (patch_path.exists()) {
        patches_needed.path = Some(patch_path);
    }

    let ini = XeBuildIni {
        name: target_section.to_string(),
        buildtype: build_type,
        main: main_entries,
        security: security_entries,
        flashfs: flashfs_entries,
        patch: patches_needed,
    };

    info!("[ini] Parsed section '{}': {} main bootloader(s), {} security file(s), {} FlashFS asset(s)",
        target_section, ini.main.len(), ini.security.len(), ini.flashfs.len());
    Ok(ini)
}

pub fn apply_xe_ini(
    mut nand: NandSkeleton,
    ini: XeBuildIni,
    pending_assets: &HashMap<String, Vec<u8>>,
    expected_hash: Option<&str>)
    -> anyhow::Result<NandSkeleton> {
    
    // DIAGNOSTIC: Print all pending assets
    if !pending_assets.is_empty() {
        info!("[ini] Discovered assets in memory: {:?}", pending_assets.keys().collect::<Vec<_>>());
    }

    // 1. Process [main] bootloaders
    for entry in &ini.main {
        let filename = &entry.filename;
        let lower = filename.to_lowercase();

        // Load the data (In-memory discovery assets > Disk files)
        let data = if let Some(mem_data) = pending_assets.get(&lower) {
            mem_data.clone()
        } else if let Ok(disk_data) = std::fs::read(&entry.path) {
            disk_data
        } else {
            // If not in memory and not on disk, we only error if it's NOT already in the NAND.
            // This allows us to keep baseline bootloaders if no replacement was found.
            info!("[ini] Note: '{}' not found in memory or at '{}', keeping baseline bootloader if present.",
                filename, entry.path.display());
            continue;
        };
        
        if lower.starts_with("cb_") || lower.starts_with("cba_") || lower.starts_with("sb_") {
            nand.bootloaders.cb = Some(crate::builder::chain::cb::BootloaderCb::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CB_A from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("cbx_") {
            nand.bootloaders.cb_x = &data;
            info!("[ini] Assigned CB_X from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("cbb_") {
            nand.bootloaders.cb_b = Some(crate::builder::chain::cb::BootloaderCb::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CB_B from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("sc_") {
            nand.bootloaders.sc = Some(crate::builder::chain::sc::BootloaderSc::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned SC from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("cd_") || if lower.starts_with("sd_") {
            nand.bootloaders.cd = Some(crate::builder::chain::cd::BootloaderCd::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CD from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("ce_") || lower.starts_with("se_") {
            nand.bootloaders.ce = Some(crate::builder::chain::ce::BootloaderCe::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CE from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("cf_") || lower.starts_with("sf_") {
            nand.update.cf_0 = Some(crate::builder::chain::cf::BootloaderCf::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CF_0 (update slot 0) from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("cg_") || lower.starts_with("sg_") {
            nand.update.cg_0 = Some(crate::builder::chain::cg::BootloaderCg::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CG_0 (update slot 0) from '{}' ({} bytes)", filename, data.len());
        } else {
            warn!("[ini] '{}' did not match any known bootloader prefix, skipping.", filename);
        }
    }

    let mut final_hash = None;
        if let Some(expected) = expected_hash {
            if !expected.is_empty() && full_path.exists() {
                let actual = get_hash(&full_path)?;
                if actual.to_lowercase() != expected.to_lowercase() {
                    return Err(IniError::HashMismatch(filename.to_string(), expected.to_string(), actual));
                }
                final_hash = Some(actual);
            }
        }
    }

    // Process File Entries (Security & FlashFS)
    let mut file_entries = ini.security.clone();
    file_entries.extend(ini.flashfs.clone());

    for entry in &file_entries {
        let basen = entry.path.file_name().unwrap_or_default().to_string_lossy().to_string();
        if basen.to_lowercase() == "fcrt.bin" {
            if let Ok(file_content) = std::fs::read(&entry.path) {
                nand.extra.fcrt = Some(file_content);
            }
        }
    }

    Ok(nand)
}