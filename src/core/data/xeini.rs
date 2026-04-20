/*
    xeini.rs - xeBuild style INI parser

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

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
    pub hash: Option<String>,
    pub chain: u8,
}

#[derive(Debug, Clone)]
pub struct BuildIniPatch {
    pub enabled: bool,
    pub path: Option<PathBuf>,
    pub khv: Option<Vec<crate::core::data::gxp::PatchRecord>>,
}

#[derive(Debug, Clone)]
pub struct XeBuildIni {
    pub name: String,
    pub buildtype: String,
    pub main: Vec<BuildIniEntry>,
    pub security: Vec<BuildIniEntry>,
    pub flashfs: Vec<BuildIniEntry>,
    pub patch: BuildIniPatch,
    pub rebooter: bool,
}

#[derive(Debug, Clone)]
pub struct OptionsIni {
    pub ctype: Option<String>,
    pub _1blkey: Option<String>,
    pub cpukey: Option<String>,
    pub cfldv: Option<String>,
    pub dvdkey: Option<String>,
    pub xellbutton: Option<String>,
    pub xellbutton2: Option<String>,
    pub cygnos: Option<bool>,
    pub demon: Option<bool>,
    pub smcnoeject: Option<bool>,
    pub smcnoblink: Option<bool>,
    pub patchsmc: Option<bool>,
    pub olddvd: Option<bool>,
    pub nodvd: Option<bool>,
    pub dualboot: Option<bool>,
    pub nomobile: Option<bool>,
    pub noremap: Option<bool>,
    pub noecdremap: Option<bool>,
    pub nandmu: Option<bool>,
    pub nosecurity: Option<bool>,
    pub nosusecurity: Option<bool>,
    pub smcnocheck: Option<bool>,
    pub cputemp: Option<String>,
    pub gputemp: Option<String>,
    pub edramtemp: Option<String>,
    pub overcputemp: Option<String>,
    pub overgputemp: Option<String>,
    pub overedramtemp: Option<String>,
    pub cpufan: Option<String>,
    pub gpufan: Option<String>,
    pub avregion: Option<String>,
    pub gameregion: Option<String>,
    pub dvdregion: Option<String>,
    pub macid: Option<String>,
    pub noenter: Option<bool>,
    pub nolog: Option<bool>,
    pub noinfo: Option<bool>,
    pub gxunsafe: Option<bool>,
}

impl OptionsIni {
    pub fn new() -> Self {
        OptionsIni {
            ctype: None,
            _1blkey: None,
            cpukey: None,
            cfldv: None,
            dvdkey: None,
            xellbutton: None,
            xellbutton2: None,
            cygnos: None,
            demon: None,
            smcnoeject: None,
            smcnoblink: None,
            patchsmc: None,
            olddvd: None,
            nodvd: None,
            dualboot: None,
            nomobile: None,
            noremap: None,
            noecdremap: None,
            nandmu: None,
            nosecurity: None,
            nosusecurity: None,
            smcnocheck: None,
            noenter: None,
            nolog: None,
            noinfo: None,
            gxunsafe: None,
            cputemp: None,
            gputemp: None,
            edramtemp: None,
            overcputemp: None,
            overgputemp: None,
            overedramtemp: None,
            cpufan: None,
            gpufan: None,
            avregion: None,
            gameregion: None,
            dvdregion: None,
            macid: None,
        }
    }

    /// Merges values from another OptionsIni, overwriting only if the other field is Some.
    pub fn merge(&mut self, other: OptionsIni) {
        if let Some(v) = other.ctype { self.ctype = Some(v); }
        if let Some(v) = other._1blkey { self._1blkey = Some(v); }
        if let Some(v) = other.cpukey { self.cpukey = Some(v); }
        if let Some(v) = other.cfldv { self.cfldv = Some(v); }
        if let Some(v) = other.dvdkey { self.dvdkey = Some(v); }
        if let Some(v) = other.xellbutton { self.xellbutton = Some(v); }
        if let Some(v) = other.xellbutton2 { self.xellbutton2 = Some(v); }
        if let Some(v) = other.cygnos { self.cygnos = Some(v); }
        if let Some(v) = other.demon { self.demon = Some(v); }
        if let Some(v) = other.smcnoeject { self.smcnoeject = Some(v); }
        if let Some(v) = other.smcnoblink { self.smcnoblink = Some(v); }
        if let Some(v) = other.patchsmc { self.patchsmc = Some(v); }
        if let Some(v) = other.olddvd { self.olddvd = Some(v); }
        if let Some(v) = other.nodvd { self.nodvd = Some(v); }
        if let Some(v) = other.dualboot { self.dualboot = Some(v); }
        if let Some(v) = other.nomobile { self.nomobile = Some(v); }
        if let Some(v) = other.noremap { self.noremap = Some(v); }
        if let Some(v) = other.noecdremap { self.noecdremap = Some(v); }
        if let Some(v) = other.nandmu { self.nandmu = Some(v); }
        if let Some(v) = other.nosecurity { self.nosecurity = Some(v); }
        if let Some(v) = other.nosusecurity { self.nosusecurity = Some(v); }
        if let Some(v) = other.smcnocheck { self.smcnocheck = Some(v); }
        if let Some(v) = other.noenter { self.noenter = Some(v); }
        if let Some(v) = other.nolog { self.nolog = Some(v); }
        if let Some(v) = other.noinfo { self.noinfo = Some(v); }
        if let Some(v) = other.gxunsafe { self.gxunsafe = Some(v); }
        if let Some(v) = other.cputemp { self.cputemp = Some(v); }
        if let Some(v) = other.gputemp { self.gputemp = Some(v); }
        if let Some(v) = other.edramtemp { self.edramtemp = Some(v); }
        if let Some(v) = other.overcputemp { self.overcputemp = Some(v); }
        if let Some(v) = other.overgputemp { self.overgputemp = Some(v); }
        if let Some(v) = other.overedramtemp { self.overedramtemp = Some(v); }
        if let Some(v) = other.cpufan { self.cpufan = Some(v); }
        if let Some(v) = other.gpufan { self.gpufan = Some(v); }
        if let Some(v) = other.avregion { self.avregion = Some(v); }
        if let Some(v) = other.gameregion { self.gameregion = Some(v); }
        if let Some(v) = other.dvdregion { self.dvdregion = Some(v); }
        if let Some(v) = other.macid { self.macid = Some(v); }
    }
}

pub fn get_hash(path: impl AsRef<Path>) -> std::io::Result<String> {
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
                        "type" => options.ctype = Some(value.clone()),
                        "1blkey" => options._1blkey = Some(value.clone()),
                        "cpukey" => options.cpukey = Some(value.clone()),
                        "cfldv" => options.cfldv = Some(value.clone()),
                        "dvdkey" => options.dvdkey = Some(value.clone()),
                        "xellbutton" => options.xellbutton = Some(value.clone()),
                        "xellbutton2" => options.xellbutton2 = Some(value.clone()),
                        "cygnos" => options.cygnos = Some(value.eq_ignore_ascii_case("true")),
                        "demon" => options.demon = Some(value.eq_ignore_ascii_case("true")),
                        "smcnoeject" => options.smcnoeject = Some(value.eq_ignore_ascii_case("true")),
                        "smcnoblink" => options.smcnoblink = Some(value.eq_ignore_ascii_case("true")),
                        "patchsmc" => options.patchsmc = Some(value.eq_ignore_ascii_case("true")),
                        "olddvd" => options.olddvd = Some(value.eq_ignore_ascii_case("true")),
                        "nodvd" => options.nodvd = Some(value.eq_ignore_ascii_case("true")),
                        "dualboot" => options.dualboot = Some(value.eq_ignore_ascii_case("true")),
                        "nomobile" => options.nomobile = Some(value.eq_ignore_ascii_case("true")),
                        "noremap" => options.noremap = Some(value.eq_ignore_ascii_case("true")),
                        "noecdremap" => options.noecdremap = Some(value.eq_ignore_ascii_case("true")),
                        "nandmu" => options.nandmu = Some(value.eq_ignore_ascii_case("true")),
                        "nosecurity" => options.nosecurity = Some(value.eq_ignore_ascii_case("true")),
                        "nosusecurity" => options.nosusecurity = Some(value.eq_ignore_ascii_case("true")),
                        "smcnocheck" => options.smcnocheck = Some(value.eq_ignore_ascii_case("true")),
                        "noenter" => options.noenter = Some(value.eq_ignore_ascii_case("true")),
                        "nolog" => options.nolog = Some(value.eq_ignore_ascii_case("true")),
                        "noinfo" => options.noinfo = Some(value.eq_ignore_ascii_case("true")),
                        "gxunsafe" => options.gxunsafe = Some(value.eq_ignore_ascii_case("true")),
                        "cputemp" => options.cputemp = Some(value.clone()),
                        "gputemp" => options.gputemp = Some(value.clone()),
                        "edramtemp" => options.edramtemp = Some(value.clone()),
                        "overcputemp" => options.overcputemp = Some(value.clone()),
                        "overgputemp" => options.overgputemp = Some(value.clone()),
                        "overedramtemp" => options.overedramtemp = Some(value.clone()),
                        "cpufan" => options.cpufan = Some(value.clone()),
                        "gpufan" => options.gpufan = Some(value.clone()),
                        "avregion" => options.avregion = Some(value.clone()),
                        "gameregion" => options.gameregion = Some(value.clone()),
                        "dvdregion" => options.dvdregion = Some(value.clone()),
                        "macid" => options.macid = Some(value.clone()),
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
    ini_path: impl AsRef<Path>,
    target_section: &str,
) -> Result<XeBuildIni, IniError> {
    let ini_path = ini_path.as_ref();
    info!("[ini] Parsing section '{}' from INI: {:?}", target_section, ini_path);

    let content = fs::read_to_string(ini_path).map_err(|e| IniError::IoError(e))?;
    
    let mut sections: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    let mut current_section = String::new();

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

    // Determine the internal section name (insert "bl")
    let main_section = if let Some((prefix, suffix)) = target_section.split_once('_') {
        format!("{}bl_{}", prefix, suffix)
    } else {
        format!("{}bl", target_section)
    };

    // Determine the build type from filename
    let mut build_type = ini_path.file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.trim_start_matches('_').to_lowercase())
        .unwrap_or_else(|| "retail".to_string());
    
    if build_type == "glitch" {
        build_type = "glitch1".to_string();
    }

    let main_data_raw = sections.get(&main_section.to_lowercase())
        .ok_or_else(|| IniError::SectionNotFound(main_section.to_string()))?;

    let security_data_raw = sections.get("security")
        .cloned()
        .unwrap_or_default();

    let flashfs_data_raw = sections.get("flashfs")
        .cloned()
        .unwrap_or_default();

    let resolve = |filename: &str, expected_hash: Option<&str>, chain: u8| -> Result<BuildIniEntry, IniError> {        
        Ok(BuildIniEntry {
            filename: filename.to_string(),
            hash: expected_hash.map(|s| s.to_string()),
            chain,
        })
    };

    let mut main_entries = Vec::new();
    let mut counts = HashMap::new();
    for entry in main_data_raw {
        let original_name = &entry[0];
        let prefix = original_name.split('_').next().unwrap_or(original_name).to_lowercase();
        let count = counts.entry(prefix.clone()).or_insert(0);
        *count += 1;

        main_entries.push(resolve(original_name, entry.get(1).map(|s| s.as_str()), *count - 1)?);
    }

    let mut security_entries = Vec::new();
    for entry in security_data_raw {
        if !entry.is_empty() {
            security_entries.push(resolve(&entry[0], None, 0)?);
        }
    }

    let mut flashfs_entries = Vec::new();
    for entry in flashfs_data_raw {
        if entry.len() >= 2 {
            flashfs_entries.push(resolve(&entry[0], Some(&entry[1]), 0)?);
        } else if entry.len() == 1 {
            flashfs_entries.push(resolve(&entry[0], None, 0)?);
        }
    }

    let ini = XeBuildIni {
        name: target_section.to_string(),
        buildtype: build_type.clone(),
        main: main_entries,
        security: security_entries,
        flashfs: flashfs_entries,
        patch: BuildIniPatch { enabled: build_type != "retail", path: None, khv: None },
        rebooter: counts.values().any(|&c| c > 1),
    };

    Ok(ini)
}

/// Typed asset maps passed to `apply_xe_ini`.
/// Keeps bootloader binaries and security files in separate pools so
/// they cannot be confused with each other or FlashFS content.
pub struct PendingAssets<'a> {
    /// Assets from the [main] INI section (CB, CD, CE, CF, CG, ...).
    pub bootloaders: &'a HashMap<String, Vec<u8>>,
    /// Assets from the [security] INI section (smc.bin, kv.bin, fcrt.bin).
    pub security: &'a HashMap<String, Vec<u8>>,
}

pub fn apply_xe_ini(
    mut nand: NandSkeleton,
    ini: XeBuildIni,
    pending: PendingAssets<'_>)
    -> Result<NandSkeleton, IniError> {
    
    nand.clear_bootloaders();
    nand.clear_update();

    if !pending.bootloaders.is_empty() {
        info!("[ini] Applying {} discovered bootloader assets from memory...", pending.bootloaders.len());
    }

    let mut notified = false;

    // process [main] bootloaders
    for entry in &ini.main {
        let filename = &entry.filename;
        let lower = filename.to_lowercase();

        // Load the data (Only from memory in this new architecture)
        let data = if let Some(mem_data) = pending.bootloaders.get(&lower) {
            mem_data.clone()
        } else {
            // In the new modular discovery architecture, filesearch.rs should have already
            // placed these in the pending_assets map.
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

        if is_rebooter && !notified {
            info!("[ini] Rebooter chain detected");
            notified = true;
        }

        if prefix.starts_with("cba_") {
            target_bl.cb_a = Some(crate::builder::chain::cb::BootloaderCb::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] Assigned CB_A from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
        } else if prefix.starts_with("cbb_") {
            target_bl.cb_b = Some(crate::builder::chain::cb::BootloaderCb::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] Assigned CB_B from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
        } else if prefix.starts_with("cbx_") {
            target_bl.cb_x = Some(crate::builder::chain::cb::BootloaderCb::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] Assigned CB_X from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
        } else if prefix.starts_with("cb_") || prefix.starts_with("sb_") {
            target_bl.cb = Some(crate::builder::chain::cb::BootloaderCb::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] Assigned CB from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
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
            let parsed = Some(crate::builder::chain::cf::BootloaderCf::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            if target_update.cf_0.is_none() {
                target_update.cf_0 = parsed;
                info!("[ini] Assigned CF to slot 0 from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
            } else if target_update.cf_1.is_none() {
                target_update.cf_1 = parsed;
                info!("[ini] Assigned CF to slot 1 from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
            } else {
                target_update.cf_0 = parsed;
                warn!("[ini] Automatically overwriting CF slot 0 from '{}' (no free slots left)", filename);
            }
        } else if prefix.starts_with("cg_") || prefix.starts_with("sg_") {
            let parsed = Some(crate::builder::chain::cg::BootloaderCg::parse(&data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            if target_update.cg_0.is_none() {
                target_update.cg_0 = parsed;
                info!("[ini] Assigned CG to slot 0 from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
            } else if target_update.cg_1.is_none() {
                target_update.cg_1 = parsed;
                info!("[ini] Assigned CG to slot 1 from '{}' ({} bytes, chain {})", filename, data.len(), chain_id);
            } else {
                target_update.cg_0 = parsed;
                warn!("[ini] Automatically overwriting CG slot 0 from '{}' (no free slots left)", filename);
            }
        } else {
            warn!("[ini] '{}' did not match any known bootloader prefix, skipping.", filename);
        }
    }

    // Process File Entries (Security & FlashFS)
    // In the new architecture, FlashFS entries are added directly to the FlashFS struct 
    // by filesearch.rs. Security and Extra files are merged here.
    if let Some(smc_data) = pending.security.get("smc.bin") {
        nand.extra.smc = smc_data.clone();
        info!("[ini] Assigned SMC.bin from memory");
    }

    if let Some(kv_data) = pending.security.get("keyvault.bin").or_else(|| pending.security.get("kv.bin")) {
        nand.extra.keyvault = kv_data.clone();
        info!("[ini] Assigned Keyvault from memory");
    }

    if let Some(fcrt_data) = pending.security.get("fcrt.bin") {
        nand.extra.fcrt = Some(fcrt_data.clone());
        info!("[ini] Assigned FCRT.bin from memory");
    }

    nand.bootloaders.khvpatch = ini.patch.khv.clone();

    Ok(nand)
}