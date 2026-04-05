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
use std::path::Path;
use std::fs;
use crc32fast::Hasher;
use thiserror::Error;
use crate::core::commands::NandSkeleton;

#[derive(Error, Debug)]
pub enum IniError {
    #[error("[GGX] Ini section not found: {0}")]
    SectionNotFound(String),
    #[error("[GGX] Ini file not found: {0}")]
    FileNotFound(String),
    #[error("[GGX] Ini CRC32 mismatch for {0}: expected {1}, got {2}")]
    HashMismatch(String, String, String),
    #[error("[GGX] Ini IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub struct XeBuildIni {
    pub name: String,
    pub main: Vec<Vec<String>>,
    pub security: Vec<String>,
    pub flashfs: HashMap<String, String>,
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
    let main_data = sections.get(&target_section.to_lowercase())
        .ok_or_else(|| IniError::SectionNotFound(target_section.to_string()))?;

    let security_data = sections.get("security")
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|p| p[0].clone())
        .collect();

    let flashfs_data: HashMap<String, String> = sections.get("flashfs")
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p.len() >= 2)
        .map(|p| (p[0].clone(), p[1].clone()))
        .collect();

    // 3. Validation
    let ini = XeBuildIni {
        name: target_section.to_string(),
        main: main_data.clone(),
        security: security_data,
        flashfs: flashfs_data,
    };

    // Helper for validation
    let validate = |search_path: &Path, filename: &str, expected_hash: Option<&str>| -> Result<(), IniError> {
        let full_path = search_path.join(filename);
        if !full_path.exists() {
            return Err(IniError::FileNotFound(filename.to_string()));
        }
        if let Some(expected) = expected_hash {
            if !expected.is_empty() {
                let actual = get_hash(&full_path)?;
                if actual.to_lowercase() != expected.to_lowercase() {
                    return Err(IniError::HashMismatch(filename.to_string(), expected.to_string(), actual));
                }
            }
        }
        Ok(())
    };

    // Validate Main section (from /common/)
    for entry in &ini.main {
        validate(common_base, &entry[0], entry.get(1).map(|s| s.as_str()))?;
    }

    // Validate Security section (from INI folder)
    for filename in &ini.security {
        validate(ini_base, filename, None)?;
    }

    // Validate FlashFS section (from INI folder)
    for (filename, hash) in &ini.flashfs {
        validate(ini_base, filename, Some(hash))?;
    }

    Ok(ini)
}

pub fn apply_xe_ini(nand: NandSkeleton, _ini: XeBuildIni) -> anyhow::Result<NandSkeleton> {
    Ok(nand)
}