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
    #[error("[GGX] Ini section not found: {0}")]
    SectionNotFound(String),
    #[error("[GGX] File not found: {0}")]
    FileNotFound(String),
    #[error("[GGX] Ini CRC32 mismatch for {0}: expected {1}, got {2}")]
    HashMismatch(String, String, String),
    #[error("[GGX] Ini IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct IniEntry {
    pub filename: String,
    pub path: PathBuf,
    pub hash: Option<String>,
}

pub struct XeBuildIni {
    pub name: String,
    pub main: Vec<IniEntry>,
    pub security: Vec<IniEntry>,
    pub flashfs: Vec<IniEntry>,
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
pub fn parse_xe_ini(
    content: &str,
    target_section: &str,
    ini_base_path: impl AsRef<Path>,
    common_path: impl AsRef<Path>,
) -> Result<XeBuildIni, IniError> {
    info!("[ini] Parsing section '{}' from INI (base: {:?})", target_section, ini_base_path.as_ref());
    let ini_base = ini_base_path.as_ref();
    let common_base = common_path.as_ref();
    
    let mut sections: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    let mut current_section = String::new();

    // 1. Initial Parse into raw sections
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

    // 2. Extract specific data
    let main_data_raw = sections.get(&target_section.to_lowercase())
        .ok_or_else(|| IniError::SectionNotFound(target_section.to_string()))?;

    let security_data_raw = sections.get("security")
        .cloned()
        .unwrap_or_default();

    let flashfs_data_raw = sections.get("flashfs")
        .cloned()
        .unwrap_or_default();

    // Helper for validation and path resolution: searches multiple paths in order
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
        
        // If not found on disk, we revert to a best-guess path in the first search directory
        // but mark it for targeted discovery.
        let full_path = full_path.unwrap_or_else(|| search_paths[0].join(filename));

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
        Ok(IniEntry {
            filename: filename.to_string(),
            path: full_path,
            hash: final_hash,
        })
    };

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

    let ini = XeBuildIni {
        name: target_section.to_string(),
        main: main_entries,
        security: security_entries,
        flashfs: flashfs_entries,
    };

    info!("[ini] Parsed section '{}': {} main bootloader(s), {} security file(s), {} FlashFS asset(s)",
        target_section, ini.main.len(), ini.security.len(), ini.flashfs.len());
    Ok(ini)
}

pub fn apply_xe_ini(
    mut nand: NandSkeleton,
    ini: XeBuildIni,
    pending_assets: &HashMap<String, Vec<u8>>,
) -> anyhow::Result<NandSkeleton> {
    
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
        
        if lower.starts_with("cba_") {
            nand.bootloaders.cb_a = Some(crate::builder::chain::cb::BootloaderCb::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CB_A from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("cb_x_") || lower.starts_with("cbx_") {
            nand.bootloaders.cb_x = Some(crate::builder::chain::cb::BootloaderCb::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CB_X from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("cbb_") {
            nand.bootloaders.cb_b = Some(crate::builder::chain::cb::BootloaderCb::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CB_B from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("cb_") {
            nand.bootloaders.cb = Some(crate::builder::chain::cb::BootloaderCb::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CB from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("cd_") {
            nand.bootloaders.cd = Some(crate::builder::chain::cd::BootloaderCd::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CD from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("ce_") {
            nand.bootloaders.ce = Some(crate::builder::chain::ce::BootloaderCe::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CE from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("cf_") {
            nand.update.cf_0 = Some(crate::builder::chain::cf::BootloaderCf::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CF_0 (update slot 0) from '{}' ({} bytes)", filename, data.len());
        } else if lower.starts_with("cg_") {
            nand.update.cg_0 = Some(crate::builder::chain::cg::BootloaderCg::parse(&data).map_err(|e| anyhow::anyhow!("{}", e))?);
            info!("[ini] Assigned CG_0 (update slot 0) from '{}' ({} bytes)", filename, data.len());
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