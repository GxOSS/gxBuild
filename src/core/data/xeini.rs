/*
  xeini.rs - xeBuild style build INI parser

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

use crate::builder::builder::NandSkeleton;
use crate::core::images::gxp::PatchRecord;
use crc32fast::Hasher;
use log::{info, warn};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

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

/// Strips leading relative-path indicators (`..\`, `../`, `.\`, `./`) and any
/// directory components from a FlashFS asset name. xeBuild INIs commonly
/// prefix flashfs assets with `..\` to point at the build folder; that hint
/// must not be persisted into the on-NAND 0x16-byte filename field.
pub fn strip_flashfs_path_indicator(name: &str) -> String {
    let trimmed = name.trim();
    // Take the last component after splitting on both Windows and Unix separators.
    trimmed.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(trimmed).to_string()
}

#[derive(Debug, Clone, Default)]
pub struct JtagConfig {
    pub syscall: Option<u16>,
    pub pairing_2bl: Option<[u8; 3]>,
}

#[derive(Debug, Clone)]
pub struct BuildIniPatch {
    pub enabled: bool,
    pub path: Option<PathBuf>,
    pub khv: Option<Vec<PatchRecord>>,
}

#[derive(Debug, Clone)]
pub struct XeBuildIni {
    pub name: String,
    pub buildtype: String,
    pub main: Vec<BuildIniEntry>,
    pub security: Vec<BuildIniEntry>,
    pub flashfs: Vec<BuildIniEntry>,
    pub payloads: Vec<BuildIniEntry>,
    pub patch: BuildIniPatch,
    pub rebooter: bool,
    pub jtag: JtagConfig,
}

pub fn get_hash(path: impl AsRef<Path>) -> std::io::Result<String> {
    let data = fs::read(path)?;
    let mut hasher = Hasher::new();
    hasher.update(&data);
    Ok(format!("{:08x}", hasher.finalize()))
}

pub fn parse_xe_ini(ini_path: impl AsRef<Path>, target_section: &str) -> Result<XeBuildIni, IniError> {
    let ini_path = ini_path.as_ref();
    let content = fs::read_to_string(ini_path).map_err(IniError::IoError)?;
    let filename_hint = ini_path.file_name().and_then(|s| s.to_str());

    parse_xe_ini_str(&content, target_section, filename_hint)
}

pub fn parse_xe_ini_str(content: &str, target_section: &str, filename_hint: Option<&str>) -> Result<XeBuildIni, IniError> {
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
            let parts: Vec<String> = line.split(',').map(|s| s.trim_end_matches(';').trim().to_string()).collect();
            sections.entry(current_section.clone()).or_default().push(parts);
        }
    }

    // Determine the internal section name (insert "bl")
    let main_section = if let Some((prefix, suffix)) = target_section.split_once('_') {
        format!("{}bl_{}", prefix, suffix)
    } else {
        format!("{}bl", target_section)
    };

    // Determine the build type from filename hint or default
    let mut build_type = filename_hint
        .map(|s| s.trim_start_matches('_').to_lowercase())
        .map(|s| s.replace(".ini", ""))
        .unwrap_or_else(|| "retail".to_string());

    if build_type == "glitch" {
        build_type = "glitch1".to_string();
    }

    let main_data_raw = sections
        .get(&main_section.to_lowercase())
        .ok_or_else(|| IniError::SectionNotFound(main_section.to_string()))?;

    let security_data_raw = sections.get("security").cloned().unwrap_or_default();

    let flashfs_data_raw = sections.get("flashfs").cloned().unwrap_or_default();

    let payloads_data_raw = sections.get("payloads").cloned().unwrap_or_default();

    let resolve = |filename: &str, expected_hash: Option<&str>, chain: u8| -> Result<BuildIniEntry, IniError> {
        let hash = expected_hash.map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string());
        Ok(BuildIniEntry { filename: filename.to_string(), hash, chain })
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
        if !entry.is_empty() {
            let mut filename = entry[0].clone();
            let mut hash_storage: Option<String> = None;
            let mut expected_hash = entry.get(1).map(|s| s.as_str());

            if filename.contains('=') {
                let parts: Vec<String> = filename.split('=').map(|s| s.trim().to_string()).collect();
                filename = parts[0].clone();
                if parts.len() > 1 && !parts[1].is_empty() {
                    hash_storage = Some(parts[1].clone());
                }
            }

            if hash_storage.is_some() {
                expected_hash = hash_storage.as_deref();
            }

            flashfs_entries.push(resolve(&filename, expected_hash, 0)?);
        }
    }

    let mut payloads_entries = Vec::new();
    for entry in payloads_data_raw {
        if !entry.is_empty() {
            let line = &entry[0];
            // Format: [offset:]filename [= description]
            let parts: Vec<&str> = line.split('=').collect();
            let file_part = parts[0].trim();
            let subparts: Vec<&str> = file_part.split(':').collect();
            let filename = if subparts.len() > 1 { subparts[1].trim() } else { subparts[0].trim() };

            payloads_entries.push(resolve(filename, entry.get(1).map(|s| s.as_str()), 0)?);
        }
    }

    let mut jtag = JtagConfig::default();
    if let Some(jtag_data) = sections.get("jtag") {
        for entry in jtag_data {
            if entry.len() >= 2 {
                let key = entry[0].to_lowercase();
                let val = &entry[1];
                if key == "syscall" {
                    jtag.syscall = u16::from_str_radix(val.trim_start_matches("0x"), 16).ok();
                } else if key == "2blpairing" {
                    // format: 0x11,0x22,0x33
                    let parts: Vec<u8> = val
                        .split(',')
                        .filter_map(|s: &str| u8::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
                        .collect();
                    if parts.len() == 3 {
                        jtag.pairing_2bl = Some([parts[0], parts[1], parts[2]]);
                    }
                }
            }
        }
    }

    let ini = XeBuildIni {
        name: target_section.to_string(),
        buildtype: build_type.clone(),
        main: main_entries,
        security: security_entries,
        flashfs: flashfs_entries,
        payloads: payloads_entries,
        patch: BuildIniPatch { enabled: build_type != "retail", path: None, khv: None },
        rebooter: counts.values().any(|&c| c > 1),
        jtag,
    };

    Ok(ini)
}

/// Typed asset maps passed to apply_xe_ini
pub struct PendingAssets<'a> {
    pub bootloaders: &'a HashMap<String, Vec<u8>>,
    pub security: &'a HashMap<String, Vec<u8>>,
}

pub fn apply_xe_ini(mut nand: NandSkeleton, ini: XeBuildIni, pending: PendingAssets<'_>) -> Result<NandSkeleton, IniError> {
    nand.bootloaders.clear();
    nand.update.clear();

    if !pending.bootloaders.is_empty() {
        info!("[ini] Applying {} discovered bootloader assets from memory...", pending.bootloaders.len());
    }

    let mut notified = false;

    for entry in &ini.main {
        let filename = &entry.filename;
        let lower = filename.to_lowercase();

        // Load the data from memory
        let data = if let Some(mem_data) = pending.bootloaders.get(&lower) {
            mem_data.clone()
        } else {
            // filesearch.rs should have already placed these in the pending_assets map
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

    for entry in &ini.payloads {
        let filename = &entry.filename;
        let lower = filename.to_lowercase();

        if let Some(data) = pending.bootloaders.get(&lower) {
            if lower.contains("xell") {
                let xell = crate::builder::chain::xell::Xell::parse(data, Some(filename)).map_err(|e| IniError::BootloaderError(e.to_string()))?;
                let x_type = xell.identify();

                match x_type {
                    crate::builder::chain::xell::XellType::XellGg => {
                        nand.bootloaders.xell = Some(xell);
                        info!("[ini] Assigned xell-gggggg to primary slot");
                    }
                    crate::builder::chain::xell::XellType::Xell1f => {
                        info!("[ini] Detected xell-1f: Switching to Onef profile (XeLL-only rebooter)");
                        nand.options.image_profile = "onef".to_string();
                        nand.bootloaders.xell = Some(xell);
                    }
                    crate::builder::chain::xell::XellType::Xell2f => {
                        if let Some(rebooter) = nand.rebooter.as_mut() {
                            rebooter.xell = Some(xell);
                        }
                        info!("[ini] Assigned xell-2f to Full Rebooter secondary slot");
                    }
                    _ => {
                        warn!("[ini] Unknown XeLL type, assigning to primary slot");
                        nand.bootloaders.xell = Some(xell);
                    }
                }
            } else {
                let mut p_entry = crate::builder::builder::PayloadEntry {
                    address: 0, // Dynamic
                    size: data.len() as u32,
                    description: filename.clone(),
                    data: data.clone(),
                    fixed_address: None,
                };

                if nand.options.image_profile == "jtag" {
                    if lower == "jtag_payload.bin" {
                        p_entry.fixed_address = Some(0x200);
                        p_entry.description = "JTAG Exploit Payload".to_string();
                        info!("[ini] Detected JTAG Exploit Payload, assigning to fixed address 0x200");
                    } else if lower == "fuses.bin" {
                        p_entry.description = "Virtual Fuses".to_string();
                    } else if lower == "freeboot.bin" {
                        p_entry.description = "Freeboot Kernel".to_string();
                    }
                }

                nand.payloads.push(p_entry);
                info!("[ini] Assigned payload '{}' ({} bytes)", filename, data.len());
            }
        }
    }

    nand.options.jtag_syscall = ini.jtag.syscall;
    nand.options.jtag_pairing_2bl = ini.jtag.pairing_2bl;

    // Security and Extra files merged here
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

    // 1f with JTAG ini
    if nand.options.image_profile == "onef" {
        info!("[ini] Enforcing Onef profile: Clearing second-chain kernel and FlashFS");
        nand.update = crate::builder::builder::NandUpdate::default();
        let total_blocks = nand.flashfs.root.block_map.len();
        nand.flashfs = crate::builder::filesystem::flashfs::FlashFS::new();
        nand.flashfs.root.block_map = vec![0; total_blocks];
    }

    // Overrides
    if let Some(cba_file) = &nand.options.cba {
        if let Some(data) = pending.bootloaders.get(&cba_file.to_lowercase()) {
            nand.bootloaders.cb_a = Some(crate::builder::chain::cb::BootloaderCb::parse(data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] OVERRIDE: Assigned CB_A from '{}'", cba_file);
        }
    }
    if let Some(cbb_file) = &nand.options.cbb {
        if let Some(data) = pending.bootloaders.get(&cbb_file.to_lowercase()) {
            nand.bootloaders.cb_b = Some(crate::builder::chain::cb::BootloaderCb::parse(data).map_err(|e| IniError::BootloaderError(e.to_string()))?);
            info!("[ini] OVERRIDE: Assigned CB_B from '{}'", cbb_file);
        }
    }

    Ok(nand)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_xe_ini_empty_crc_section() {
        let content = "
[trinitybl]
cba_9188.bin = 00000000

[flashfs]
..\\launch.xex ,
..\\lhelper.xex,  
..\\launch.ini = 
        ";
        let parsed = parse_xe_ini_str(content, "trinity", None).unwrap();
        assert_eq!(parsed.flashfs.len(), 3);
        // BuildIniEntry retains the original path so filesearch can use it for
        // disk discovery; stripping to basename happens later in filesearch.
        assert_eq!(parsed.flashfs[0].filename, "..\\launch.xex");
        assert_eq!(parsed.flashfs[0].hash, None);
        assert_eq!(parsed.flashfs[1].filename, "..\\lhelper.xex");
        assert_eq!(parsed.flashfs[1].hash, None);
        assert_eq!(parsed.flashfs[2].filename, "..\\launch.ini");
        assert_eq!(parsed.flashfs[2].hash, None);
    }

    #[test]
    fn strip_flashfs_path_indicator_handles_common_forms() {
        assert_eq!(strip_flashfs_path_indicator("..\\launch.xex"), "launch.xex");
        assert_eq!(strip_flashfs_path_indicator("../launch.xex"), "launch.xex");
        assert_eq!(strip_flashfs_path_indicator(".\\launch.xex"), "launch.xex");
        assert_eq!(strip_flashfs_path_indicator("./launch.xex"), "launch.xex");
        assert_eq!(strip_flashfs_path_indicator("foo\\bar\\launch.xex"), "launch.xex");
        assert_eq!(strip_flashfs_path_indicator("launch.xex"), "launch.xex");
        assert_eq!(strip_flashfs_path_indicator("  ..\\launch.xex  "), "launch.xex");
    }
}
