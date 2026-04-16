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
    #[error("[ini] Incorrect formatting in {0}")]
    BadBuildFormat(String),
    #[error("[ini] Rebooter bootloader chain requested in INI but not initialized in NAND skeleton")]
    RebooterNotInitialized,
    #[error("[ini] Rebooter update chain requested in INI but not initialized in NAND skeleton")]
    RebooterUpdateNotInitialized,
    #[error("[ini] Bootloader parse error: {0}")]
    BootloaderError(String),
    #[error("[ini] {0} Patches for platform {1} not found at path {2}")]
    NoAutoPatches(String, String, String),
    #[error("[ini] No security files found in INI")]
    NoSecurityFiles,
    #[error("[ini] No FlashFS files found in INI")]
    NoFlashFSFiles,
    #[error("[ini] No patches found in INI")]
    NoPatches,
}

#[derive(Debug, Clone)]
pub struct BuildIniEntry {
    pub filename: String,
    pub path: PathBuf,
    pub hash: Option<String>,
    pub chain: u8,
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
    pub rebooter: bool,
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
    pub noenter: bool,
    pub nolog: bool,
    pub noinfo: bool,
    pub gxunsafe: bool,
}

impl OptionsIni {
    pub fn new() -> Self {
        OptionsIni {
            ctype: String::from("options"),
            _1blkey: String::from("00000000000000000000000000000000"),
            cpukey: String::from("00000000000000000000000000000000"),
            cfldv: String::from("0"),
            dvdkey: String::from("00000000000000000000000000000000"),
            xellbutton: String::from("0"),
            xellbutton2: String::from("0"),
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
            noenter: false,
            nolog: false,
            noinfo: false,
            gxunsafe: false,
            cputemp: String::from("0"),
            gputemp: String::from("0"),
            edramtemp: String::from("0"),
            overcputemp: String::from("0"),
            overgputemp: String::from("0"),
            overedramtemp: String::from("0"),
            cpufan: String::from("0"),
            gpufan: String::from("0"),
            avregion: String::from("0"),
            gameregion: String::from("0"),
            dvdregion: String::from("0"),
            macid: String::from("00000000000000000000000000000000"),
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
            let parts: Vec<String> = line.split(" = ")
                .map(|s| s.trim_end_matches(';').trim().to_string())
                .collect();
            match parts.as_slice() {
                [key, value] => {
                    match key.to_lowercase().as_str() {
                        "type" => options.ctype = value.clone(),
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
) -> Result<XeBuildIni, IniError> {
    
    info!("[ini] Parsing section '{}' from INI (base: {:?})", target_section, ini_base_path.as_ref());
    
    let ini_base = ini_base_path.as_ref(); 
    let common_base = common_path.as_ref();
    
    let patches_dir = ini_base.join("data");

    let mut sections: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    let mut current_section = String::new();

    let mut patch_path = None;

    let build_type = ini_base_path.as_ref()
        .file_stem()
        .and_then(|n| n.to_str())
        .map(|s| s.trim_start_matches('_').to_lowercase())
        .unwrap_or_default();

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
    
    let validate_and_resolve = |search_paths: &[&Path], filename: &str, expected_hash: Option<&str>, chain: u8| -> Result<BuildIniEntry, IniError> {
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

        let full_path = full_path.ok_or_else(|| {
             warn!("[ini] File not found: {}", filename);
             IniError::FileNotFound(filename.to_string())
        })?;

        info!("[ini] File {} found at path: {}", filename, full_path.display());

        if let Some(expected) = expected_hash {
            if !expected.is_empty() {
                let actual = get_hash(&full_path).map_err(IniError::IoError)?;
                if actual.to_lowercase() != expected.to_lowercase() {
                    return Err(IniError::HashMismatch(filename.to_string(), expected.to_string(), actual));
                }
            }
        }
        
        Ok(BuildIniEntry {
            filename: filename.to_string(),
            path: full_path,
            hash: expected_hash.map(|s| s.to_string()),
            chain,
        })
    };
    
    // xeBuild auto patching
    match build_type.as_str() {
        "retail" => {
            info!("[ini] Retail build type selected");
        },
    "glitch1" | "glitch2" | "glitch2m" | "glitch3" | "jtag" | "1f" | "2f" | "devgl" | "devkit" | "xdkbuild" | "rgbuild" => {
            info!("[ini] {} build type selected", build_type);
            match build_type.as_str() {
                "glitch1" => {
                    let p_path = match console_type.as_str() {
                        "trinity" | "corona" => Some(patches_dir.join("patches_trinity.bin")),
                        "zephyr" | "jasper" | "falcon" => Some(patches_dir.join("patches_fat.bin")),
                        "xenon" => None,
                        _ => None,
                    };
                    if let Some(ref p) = p_path {
                        if !p.exists() {
                            return Err(IniError::NoAutoPatches("Glitch1".to_string(), main_section_name, p.display().to_string()));
                        } else {
                            info!("[ini] Glitch1 Patches for platform {} found at path: {}", main_section_name, p.display());
                        }
                    }
                    patch_path = p_path;
                }
                "glitch2" => {
                    let p = patches_dir.join(format!("patches_g2{}.bin", main_section_name));
                    if !p.exists() { 
                        return Err(IniError::NoAutoPatches("Glitch2".to_string(), main_section_name, p.display().to_string()));
                    } else {
                        info!("[ini] Glitch2 Patches for platform {} found at path: {}", main_section_name, p.display());
                        patch_path = Some(p);
                    }
                }
                "glitch2m" | "devgl" | "xdkbuild" => {
                    let p = patches_dir.join(format!("patches_g2m{}.bin", main_section_name));
                    if !p.exists() { 
                        return Err(IniError::NoAutoPatches(build_type.clone(), main_section_name, p.display().to_string()));
                    } else {
                        info!("[ini] {} Patches for platform {} found at path: {}", build_type, main_section_name, p.display());
                        patch_path = Some(p);
                    }
                }
                "glitch3" => {
                    let p_g3 = patches_dir.join(format!("patches_g3{}.bin", main_section_name));
                    let p_g2 = patches_dir.join(format!("patches_g2{}.bin", main_section_name));
                    if !p_g3.exists() {
                        if p_g2.exists() {
                            warn!("[ini] Glitch3 Patches for platform {} not found at path: {}", main_section_name, p_g3.display());
                            info!("[ini] Falling back to Glitch2 Patches for platform {} found at path: {}", main_section_name, p_g2.display());
                            patch_path = Some(p_g2);
                        } else {
                            return Err(IniError::NoAutoPatches("Glitch3".to_string(), main_section_name, p_g3.display().to_string()));
                        }
                    } else {
                        info!("[ini] Glitch3 Patches for platform {} found at path: {}", main_section_name, p_g3.display());
                        patch_path = Some(p_g3);
                    }
                }
                "devkit" => {
                    let p = patches_dir.join(format!("patches_dev{}.bin", main_section_name));
                    if !p.exists() { 
                        return Err(IniError::NoAutoPatches("Devkit".to_string(), main_section_name, p.display().to_string()));
                    } else {
                        info!("[ini] Devkit Patches for platform {} found at path: {}", main_section_name, p.display());
                        patch_path = Some(p);
                    }
                }
                "rgbuild" => {
                    let p = patches_dir.join(format!("patches_rg{}.bin", main_section_name));
                    if !p.exists() { 
                        return Err(IniError::NoAutoPatches("RGBuild".to_string(), main_section_name, p.display().to_string()));
                    } else {
                        info!("[ini] RGBuild Patches for platform {} found at path: {}", main_section_name, p.display());
                        patch_path = Some(p);
                    }
                }
                _ => {}
            }
        },
        _ => return Err(IniError::BadBuildFormat(build_type)),
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

    let security_data_raw = sections.get("security")
        .cloned()
        .unwrap_or_default();

    let flashfs_data_raw = sections.get("flashfs")
        .cloned()
        .unwrap_or_default();

    let mut main_entries = Vec::new();
    let mut counts = HashMap::new();
    for entry in main_data_raw {
        let original_name = &entry[0];
        let prefix = original_name.split('_').next().unwrap_or(original_name).to_lowercase();
        let count = counts.entry(prefix.clone()).or_insert(0);
        *count += 1;

        main_entries.push(validate_and_resolve(&[ini_base, common_base], original_name, entry.get(1).map(|s| s.as_str()), *count - 1)?);
    }


    let mut security_entries = Vec::new();
    for entry in security_data_raw {
        if !entry.is_empty() {
            security_entries.push(validate_and_resolve(&[ini_base], &entry[0], None, 0)?);
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
            flashfs_entries.push(validate_and_resolve(&flashfs_paths, &entry[0], Some(&entry[1]), 0)?);
        } else if entry.len() == 1 {
            flashfs_entries.push(validate_and_resolve(&flashfs_paths, &entry[0], None, 0)?);
        }
    }

    let mut patches_needed = BuildIniPatch {
        enabled: build_type != "retail",
        path: None,
    };

    if let Some(p) = patch_path {
        patches_needed.path = Some(p);
    }

    // Validation for non-retail builds
    if build_type != "retail" {
        if security_entries.is_empty() {
             return Err(IniError::NoSecurityFiles);
        }
        if flashfs_entries.is_empty() {
             return Err(IniError::NoFlashFSFiles);
        }
        if patches_needed.path.is_none() {
             return Err(IniError::NoPatches);
        }
    }

    let ini = XeBuildIni {
        name: target_section.to_string(),
        buildtype: build_type,
        main: main_entries,
        security: security_entries,
        flashfs: flashfs_entries,
        patch: patches_needed,
        rebooter: counts.values().any(|&c| c > 1),
    };

    info!("[ini] Parsed section '{}': {} main bootloader(s), {} security file(s), {} FlashFS asset(s)",
        target_section, ini.main.len(), ini.security.len(), ini.flashfs.len());
    Ok(ini)
}

pub fn apply_xe_ini(
    mut nand: NandSkeleton,
    ini: XeBuildIni,
    pending_assets: &HashMap<String, Vec<u8>>,
    _expected_hash: Option<&str>)
    -> Result<NandSkeleton, IniError> {
    
    // DIAGNOSTIC: Print all pending assets
    if !pending_assets.is_empty() {
        info!("[ini] Discovered assets in memory: {:?}", pending_assets.keys().collect::<Vec<_>>());
    }

    // rebooter sanity check
    let mut notified = false;

    // process [main] bootloaders
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

        let is_rebooter = entry.chain == 1;
        let chain_id = entry.chain;

        let target_bl = if is_rebooter {
            nand.rebooter.as_mut().ok_or(IniError::RebooterNotInitialized)?
        } else {
            &mut nand.bootloaders
        };

        let target_update = if is_rebooter {
            nand.rebooter_update.as_mut().ok_or(IniError::RebooterUpdateNotInitialized)?
        } else {
            &mut nand.update
        };
        
        let prefix = &lower;

        if is_rebooter && notified == false {
            info!("[ini] Rebooter chain detected");
            notified = true;
        }

        if prefix.starts_with("cb_") || prefix.starts_with("cba_") || prefix.starts_with("sb_") {
            target_bl.cb = Some(crate::builder::chain::cb::BootloaderCb::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] Assigned CB from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
        } else if prefix.starts_with("cbx_") {
            target_bl.cb_x = Some(crate::builder::chain::cb::BootloaderCb::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] Assigned CB_X from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
        } else if prefix.starts_with("cbb_") {
            target_bl.cb_b = Some(crate::builder::chain::cb::BootloaderCb::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] Assigned CB_B from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
        } else if prefix.starts_with("sc_") {
            target_bl.sc = Some(crate::builder::chain::sc::BootloaderSc::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] Assigned SC from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
        } else if prefix.starts_with("cd_") || prefix.starts_with("sd_") {
            target_bl.cd = Some(crate::builder::chain::cd::BootloaderCd::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] Assigned CD from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
        } else if prefix.starts_with("ce_") || prefix.starts_with("se_") {
            target_bl.ce = Some(crate::builder::chain::ce::BootloaderCe::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] Assigned CE from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
        } else if prefix.starts_with("cf_") || prefix.starts_with("sf_") {
            target_update.cf_0 = Some(crate::builder::chain::cf::BootloaderCf::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] Assigned CF from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
        } else if prefix.starts_with("cg_") || prefix.starts_with("sg_") {
            target_update.cg_0 = Some(crate::builder::chain::cg::BootloaderCg::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] Assigned CG from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
        } else {
            warn!("[ini] '{}' did not match any known bootloader prefix, skipping.", filename);
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