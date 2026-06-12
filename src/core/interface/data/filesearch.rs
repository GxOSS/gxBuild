/*
  filesearch.rs - xeBuild style file searching engine

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
use crate::builder::nand::builder::NandSkeleton;
use crate::builder::filesystem::flashfs::{FileSystemEntry, FlashFS};
use crate::core::interface::data::xeini::{
    bootloader_matches_expected_name, strip_flashfs_path_indicator, XeBuildIni,
};
use log::{info, warn};
use gxcrypt::crc::{bls_crc32_hex, crc32_hex};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::core::images::gxpatch::{apply_records, parse_patch_binary};

#[derive(Error, Debug)]
pub enum FilesearchError {
    #[error("[filesearch] File not found: {0}")]
    FileNotFound(String),
    #[error("[filesearch] Incorrect formatting in {0}")]
    BadBuildFormat(String),
    #[error("[filesearch] Rebooter bootloader chain requested in INI but not initialized in NAND skeleton")]
    RebooterNotInitialized,
    #[error("[filesearch] {0} Patches for platform {1} not found at path {2}")]
    NoAutoPatches(String, String, String),
    #[error("[filesearch] No security files found in INI")]
    NoSecurityFiles,
    #[error("[ini] Hash mismatch for {0}")]
    HashMismatch(String),
    #[error("[ini] No SMC.bin or {0}_CLEAN.bin found")]
    NoSmcOrCleanBin(String),
    #[error("[ini] Payload {0} has broken hash")]
    PayloadBrokenHash(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn resolve_robust(base: &Path, cand: &str) -> PathBuf {
    let mut p = base.to_path_buf();
    for component in cand.split(['/', '\\']) {
        if component == ".." {
            p.pop();
        } else if component == "." || component.is_empty() {
            continue;
        } else {
            p.push(component);
        }
    }
    p
}

fn select_flashfs_candidate(
    candidates: &[Vec<u8>],
    filename: &str,
    expected: &Option<String>,
    unsafe_mode: bool,
) -> Option<Vec<u8>> {
    for candidate in candidates {
        if expected.is_none()
            || check_crc32_simple(candidate, filename, expected, "Build STFS", unsafe_mode).is_some()
        {
            return Some(candidate.clone());
        }
    }
    None
}

fn check_crc32_simple(
    data: &[u8],
    filename: &str,
    expected: &Option<String>,
    tier: &str,
    unsafe_mode: bool,
) -> Option<bool> {
    if let Some(exp) = expected {
        let actual = crc32_hex(data);
        if actual.to_lowercase() == exp.to_lowercase() {
            Some(true)
        } else if unsafe_mode {
            warn!("[ini] Unsafe Bypass: {} CRC32 mismatch (Expected: {}, Got: {} in {} Tier). Continuing...", filename, exp, actual, tier);
            Some(true)
        } else {
            info!(
                "[ini] Hash mismatch for {} in {} Tier, trying next tier...",
                filename, tier
            );
            None
        }
    } else {
        Some(true)
    }
}

fn check_bootloader_candidate(
    data: &[u8],
    filename: &str,
    expected: &Option<String>,
    tier: &str,
    unsafe_mode: bool,
) -> Option<bool> {
    if let Err(reason) = bootloader_matches_expected_name(filename, data) {
        info!(
            "[ini] Rejecting {} from {} Tier: {}",
            filename, tier, reason
        );
        return None;
    }

    if let Some(exp) = expected {
        let actual = get_xebuild_crc32(data, filename);
        if actual.eq_ignore_ascii_case(exp) {
            Some(true)
        } else if unsafe_mode {
            warn!("[ini] Unsafe Bypass: {} CRC32 mismatch (Expected: {}, Found: {} in {} Tier). Continuing...", filename, exp, actual, tier);
            Some(true)
        } else {
            info!(
                "[ini] Hash mismatch for {} in {} Tier, trying next tier...",
                filename, tier
            );
            None
        }
    } else {
        Some(true)
    }
}

fn check_stfs_bootloader_candidate(
    raw_data: &[u8],
    filename: &str,
    expected: &Option<String>,
    tier: &str,
    unsafe_mode: bool,
) -> Option<bool> {
    check_bootloader_candidate(raw_data, filename, expected, tier, unsafe_mode)
}

pub struct DiscoveredBootloaders {
    pub cb: Option<PathBuf>,
    pub cb_a: Option<PathBuf>,
    pub cb_b: Option<PathBuf>,
    pub cb_x: Option<PathBuf>,
    pub sc: Option<PathBuf>,
    pub cd: Option<PathBuf>,
    pub ce: Option<PathBuf>,
}

impl DiscoveredBootloaders {
    pub fn new() -> Self {
        Self {
            cb: None,
            cb_a: None,
            cb_b: None,
            cb_x: None,
            sc: None,
            cd: None,
            ce: None,
        }
    }
}

pub struct DiscoveredUpdate {
    pub cf_0: Option<PathBuf>,
    pub cg_0: Option<PathBuf>,
    pub cf_1: Option<PathBuf>,
    pub cg_1: Option<PathBuf>,
}

impl DiscoveredUpdate {
    pub fn new() -> Self {
        Self {
            cf_0: None,
            cg_0: None,
            cf_1: None,
            cg_1: None,
        }
    }
}

pub(crate) fn get_xebuild_crc32(data: &[u8], filename: &str) -> String {
    bls_crc32_hex(data, filename)
}

pub struct IniSearchResult {
    pub bootloaders: Option<DiscoveredBootloaders>,
    pub rebooter: Option<DiscoveredBootloaders>,
    pub security: Option<Vec<PathBuf>>,
    pub update: Option<DiscoveredUpdate>,
    pub rebooter_update: Option<DiscoveredUpdate>,
    pub flashfs: Option<FlashFS>,
    pub bootloader_assets: HashMap<String, Vec<u8>>,
    pub security_assets: HashMap<String, Vec<u8>>,
    pub flashfs_assets: HashMap<String, Vec<u8>>,
}

pub struct IniSearch {
    pub ini: XeBuildIni,
    pub build: PathBuf,
    pub common: PathBuf,
    pub mydata: PathBuf,
    pub payloads: PathBuf,
    pub smc: PathBuf,
    pub unsafe_mode: Option<bool>,
    pub result: IniSearchResult,
}

impl IniSearch {
    pub fn new(
        ini: XeBuildIni,
        build: impl AsRef<Path>,
        common: impl AsRef<Path>,
        mydata: impl AsRef<Path>,
        payloads: impl AsRef<Path>,
        smc: impl AsRef<Path>,
        nand: &Option<NandSkeleton>,
        unsafe_mode: Option<bool>,
        nofcrt: Option<bool>,
        nosecurity: Option<bool>,
        nosusecurity: Option<bool>,
        nochainpatch: Option<bool>,
    ) -> Result<Self, FilesearchError> {
        let unsafe_mode = unsafe_mode.unwrap_or(false);
        let nofcrt = nofcrt.unwrap_or(false);
        let nosecurity = nosecurity.unwrap_or(false);
        let nosusecurity = nosusecurity.unwrap_or(false);
        let nochainpatch = nochainpatch.unwrap_or(false);
        let mut ini = ini;
        let mut result = IniSearchResult {
            bootloaders: None,
            rebooter: None,
            security: None,
            update: None,
            rebooter_update: None,
            flashfs: None,
            bootloader_assets: HashMap::new(),
            security_assets: HashMap::new(),
            flashfs_assets: HashMap::new(),
        };

        let build = build.as_ref().to_path_buf();
        let common = common.as_ref().to_path_buf();
        let mydata = mydata.as_ref().to_path_buf();
        let payloads = payloads.as_ref().to_path_buf();
        let smc_dir = smc.as_ref().to_path_buf();
        let flashfs_folder = build.join("flashfs");
        // Auto Patcher
        // Patches Priority: 1. Build/bin Folder, 2. Build/../bin Folder
        let platform = ini
            .name
            .split('_')
            .next()
            .unwrap_or(&ini.name)
            .to_lowercase();
        let mut patch_path: Option<PathBuf> = None;

        let find_patch = |name: &str| -> Option<PathBuf> {
            let p1 = build.join("bin").join(name);
            let p2 = build.parent().unwrap_or(&build).join("bin").join(name);
            if p1.exists() {
                Some(p1)
            } else if p2.exists() {
                Some(p2)
            } else {
                None
            }
        };

        // could probably be improved
        match ini.buildtype.as_str() {
            "retail" => {
                info!("[ini] Retail build type selected");
            }
            "glitch1" | "glitch2" | "glitch2m" | "glitch3" | "jtag" | "1f" | "2f" | "devgl"
            | "devkit" | "xdkbuild" | "rgbuild" => {
                info!("[ini] {} build type selected", ini.buildtype);
                match ini.buildtype.as_str() {
                    "glitch1" => {
                        let name = match platform.as_str() {
                            "trinity" | "corona" => Some("patches_trinity.bin"),
                            "zephyr" | "jasper" | "falcon" => Some("patches_fat.bin"),
                            _ => None,
                        };
                        if let Some(n) = name {
                            if let Some(p) = find_patch(n) {
                                info!(
                                    "[ini] Glitch1 Patches for platform {} found at path: {}",
                                    platform,
                                    p.display()
                                );
                                patch_path = Some(p);
                            } else {
                                return Err(FilesearchError::NoAutoPatches(
                                    "Glitch1".to_string(),
                                    ini.name.clone(),
                                    format!("<build>/bin/{}", n),
                                ));
                            }
                        }
                    }
                    "glitch2" => {
                        let n = format!("patches_g2{}.bin", platform);
                        if let Some(p) = find_patch(&n) {
                            info!(
                                "[ini] Glitch2 Patches for platform {} found at path: {}",
                                platform,
                                p.display()
                            );
                            patch_path = Some(p);
                        } else {
                            return Err(FilesearchError::NoAutoPatches(
                                "Glitch2".to_string(),
                                ini.name.clone(),
                                format!("<build>/bin/{}", n),
                            ));
                        }
                    }
                    "glitch2m" | "devgl" | "xdkbuild" => {
                        let n = format!("patches_g2m{}.bin", platform);
                        if let Some(p) = find_patch(&n) {
                            info!(
                                "[ini] {} Patches for platform {} found at path: {}",
                                ini.buildtype,
                                platform,
                                p.display()
                            );
                            patch_path = Some(p);
                        } else {
                            return Err(FilesearchError::NoAutoPatches(
                                ini.buildtype.clone(),
                                ini.name.clone(),
                                format!("<build>/bin/{}", n),
                            ));
                        }
                    }
                    "glitch3" => {
                        let n3 = format!("patches_g3{}.bin", platform);
                        let n2 = format!("patches_g2{}.bin", platform);
                        if let Some(p3) = find_patch(&n3) {
                            info!(
                                "[ini] Glitch3 Patches for platform {} found at path: {}",
                                platform,
                                p3.display()
                            );
                            patch_path = Some(p3);
                        } else if let Some(p2) = find_patch(&n2) {
                            warn!("[ini] Glitch3 Patches for platform {} not found, using fallback: {}", platform, p2.display());
                            patch_path = Some(p2);
                        } else {
                            return Err(FilesearchError::NoAutoPatches(
                                "Glitch3".to_string(),
                                ini.name.clone(),
                                format!("<build>/bin/{}", n3),
                            ));
                        }
                    }
                    "devkit" => {
                        let n = format!("patches_dev{}.bin", platform);
                        if let Some(p) = find_patch(&n) {
                            info!(
                                "[ini] Devkit Patches for platform {} found at path: {}",
                                platform,
                                p.display()
                            );
                            patch_path = Some(p);
                        } else {
                            return Err(FilesearchError::NoAutoPatches(
                                "Devkit".to_string(),
                                ini.name.clone(),
                                format!("<build>/bin/{}", n),
                            ));
                        }
                    }
                    "rgbuild" => {
                        let n = format!("patches_rg{}.bin", platform);
                        if let Some(p) = find_patch(&n) {
                            info!(
                                "[ini] RGBuild Patches for platform {} found at path: {}",
                                platform,
                                p.display()
                            );
                            patch_path = Some(p);
                        } else {
                            return Err(FilesearchError::NoAutoPatches(
                                "RGBuild".to_string(),
                                ini.name.clone(),
                                format!("<build>/bin/{}", n),
                            ));
                        }
                    }
                    _ => {}
                }
            }
            _ => return Err(FilesearchError::BadBuildFormat(ini.buildtype.clone())),
        }
        ini.patch.path = patch_path.clone();

        // security and extra
        if !ini.security.is_empty() {
            let mut sec_paths = Vec::new();
            for entry in &ini.security {
                let filename = &entry.filename;
                let lower_name = filename.to_lowercase();
                if lower_name == "fcrt.bin" && nofcrt {
                    warn!("[ini] fcrt.bin bypassed due to nofcrt option.");
                    continue;
                }
                let mut found_content: Option<Vec<u8>> = None;
                let mut found_path: Option<PathBuf> = None;

                // Tier 0: NAND Image
                if found_content.is_none() && !nosecurity {
                    if let Some(n) = nand {
                        let nand_data = match lower_name.as_str() {
                            "keyvault.bin" | "kv.bin" => Some(n.extra.keyvault.clone()),
                            "fcrt.bin" => n.extra.fcrt.clone(),
                            _ => None,
                        };
                        if let Some(c) = nand_data {
                            if check_crc32_simple(
                                &c,
                                filename,
                                &entry.hash,
                                "NAND Image",
                                unsafe_mode,
                            )
                            .is_some()
                            {
                                found_content = Some(c);
                                found_path = Some(PathBuf::from("NAND_IMAGE"));
                            }
                        }
                    }
                }

                // Tier 1: mydata folder
                if found_content.is_none() {
                    let cand = resolve_robust(&mydata, filename);
                    if cand.exists() {
                        let c = std::fs::read(&cand)?;
                        if check_crc32_simple(&c, filename, &entry.hash, "mydata", unsafe_mode)
                            .is_some()
                        {
                            found_content = Some(c);
                            found_path = Some(cand);
                        }
                    }
                }

                // Tier 2: Build folder
                if found_content.is_none() {
                    let cand = resolve_robust(&build, filename);
                    if cand.exists() {
                        let c = std::fs::read(&cand)?;
                        if check_crc32_simple(&c, filename, &entry.hash, "Build", unsafe_mode)
                            .is_some()
                        {
                            found_content = Some(c);
                            found_path = Some(cand);
                        }
                    }
                }

                // Tier 3: Build folder STFS
                if found_content.is_none() && !nosusecurity {
                    if let Ok(entries) = std::fs::read_dir(&build) {
                        'stfs: for stfs_entry in entries.flatten() {
                            let p = stfs_entry.path();
                            if !p.is_file() {
                                continue;
                            }
                            let ext_ok = p
                                .extension()
                                .and_then(|e| e.to_str())
                                .map(|e| e.eq_ignore_ascii_case("bin"))
                                .unwrap_or(false);
                            if !ext_ok {
                                continue;
                            }
                            if let Ok(data_stfs) = std::fs::read(&p) {
                                if let Ok(stfs) =
                                    crate::core::images::stfs::StfsContainer::new(&data_stfs)
                                {
                                    if let Ok(mem) = stfs.extract_to_memory() {
                                        for (k, v) in mem {
                                            if k.to_lowercase() == lower_name {
                                                if check_crc32_simple(
                                                    &v,
                                                    filename,
                                                    &entry.hash,
                                                    "Build STFS",
                                                    unsafe_mode,
                                                )
                                                .is_some()
                                                {
                                                    found_content = Some(v);
                                                    found_path = Some(p.clone());
                                                    break 'stfs;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Tier 6: Common folder
                if found_content.is_none() {
                    let cand = resolve_robust(&common, filename);
                    if cand.exists() {
                        let c = std::fs::read(&cand)?;
                        if check_crc32_simple(&c, filename, &entry.hash, "Common", unsafe_mode)
                            .is_some()
                        {
                            found_content = Some(c);
                            found_path = Some(cand);
                        }
                    }
                }

                if let Some(c) = found_content {
                    result.security_assets.insert(lower_name, c);
                    if let Some(p) = found_path {
                        sec_paths.push(p);
                    }
                } else {
                    if lower_name == "odd.bin" {
                        warn!("[ini] odd.bin not found during discovery, skipping with warning.");
                        continue;
                    }
                    warn!("[ini] All tiers failed for security asset: {}", filename);
                    return Err(FilesearchError::FileNotFound(filename.to_string()));
                }
            }
            result.security = Some(sec_paths);
        }

        // SMC: Tier 1 = mydata, Tier 2 = smc folder
        let section_base = ini.name.split('_').next().unwrap_or(&ini.name);
        let platform_token = if section_base.ends_with("bl") {
            &section_base[..section_base.len() - 2]
        } else {
            section_base
        };
        let platform_clean = platform_token.to_uppercase();

        {
            let p = mydata.join("smc_config.bin");
            if p.exists() {
                if let Ok(c) = std::fs::read(&p) {
                    info!("[ini] Discovered SMC Config: {}", p.display());
                    result.security_assets.insert("smc_config.bin".to_string(), c);
                }
            } else {
                let p = common.join(format!("smc_config_{}.bin", platform_token.to_lowercase()));
                if p.exists() {
                    if let Ok(c) = std::fs::read(&p) {
                        info!("[ini] Discovered SMC Config: {}", p.display());
                        result.security_assets.insert("smc_config.bin".to_string(), c);
                    }
                }
            }
        }

        {
            let smc_names = [
                "SMC.bin".to_string(),
                format!("{}_CLEAN.bin", platform_clean),
            ];
            let smc_search_dirs = [mydata.clone(), smc_dir.clone()];
            let mut smc_found = false;
            'smc: for dir in &smc_search_dirs {
                for name in &smc_names {
                    let p = dir.join(name);
                    if p.exists() {
                        if let Ok(c) = std::fs::read(&p) {
                            info!("[ini] Discovered SMC: {}", p.display());
                            result.security_assets.insert("smc.bin".to_string(), c);
                            smc_found = true;
                            break 'smc;
                        }
                    }
                }
            }
            if !smc_found {
                return Err(FilesearchError::NoSmcOrCleanBin(platform_clean));
            }
        }

        // Payloads: Tier 5 = payloads folder ONLY
        for entry in &ini.payloads {
            let filename = &entry.filename;
            let lower_name = filename.to_lowercase();
            let cand = payloads.join(filename);
            if cand.exists() {
                if let Ok(c) = std::fs::read(&cand) {
                    let skip_crc = entry
                        .hash
                        .as_deref()
                        .map(|h| {
                            h.eq_ignore_ascii_case("skip")
                                || h.eq_ignore_ascii_case("none")
                                || h == "0"
                                || h == "00000000"
                        })
                        .unwrap_or(true);

                    if skip_crc {
                        warn!("[ini] Payload {} CRC32 check skipped", filename);
                        result.bootloader_assets.insert(lower_name, c);
                    } else if let Some(expected) = &entry.hash {
                        let actual = get_xebuild_crc32(&c, filename);
                        if actual.to_lowercase() != expected.to_lowercase() {
                            if unsafe_mode {
                                warn!("[ini] Unsafe Bypass: payload {} CRC32 mismatch (Expected: {}, Found: {}). Continuing...", filename, expected, actual);
                                result.bootloader_assets.insert(lower_name, c);
                            } else {
                                return Err(FilesearchError::HashMismatch(filename.to_string()));
                            }
                        } else {
                            info!(
                                "[ini] Discovered payload in payloads folder: {}",
                                cand.display()
                            );
                            info!("[ini] Payload {} passed CRC32: {}", filename, actual);
                            result.bootloader_assets.insert(lower_name, c);
                        }
                    }
                }
            } else {
                return Err(FilesearchError::FileNotFound(filename.to_string()));
            }
        }

        let mut stfs_flashfs_candidates: HashMap<String, Vec<Vec<u8>>> = HashMap::new();

        if !ini.main.is_empty() {
            result.bootloaders = Some(DiscoveredBootloaders::new());
            if ini.rebooter {
                result.rebooter = Some(DiscoveredBootloaders::new());
            }

            let mut allowed_flashfs_from_ini: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            if !ini.flashfs.is_empty() {
                for fs_entry in &ini.flashfs {
                    let basename = strip_flashfs_path_indicator(&fs_entry.filename);
                    let lower = basename.to_lowercase();
                    allowed_flashfs_from_ini.insert(lower.clone());
                    allowed_flashfs_from_ini.insert(format!("{}1", lower));
                    allowed_flashfs_from_ini.insert(format!("{}2", lower));
                }
            }

            let mut expected_cf = "cf_0.bin".to_string();
            let mut expected_cg = "cg_0.bin".to_string();
            let mut target_cb = None;

            for entry in &ini.main {
                let lower = entry.filename.to_lowercase();
                if lower.starts_with("cf_") || lower.starts_with("sf_") {
                    expected_cf = lower.clone();
                } else if lower.starts_with("cg_") || lower.starts_with("sg_") {
                    expected_cg = lower.clone();
                }

                if lower.starts_with("cbb_") {
                    target_cb = Some(lower.clone());
                } else if target_cb.is_none()
                    && (lower.starts_with("cb_") || lower.starts_with("sb_"))
                {
                    target_cb = Some(lower.clone());
                }
            }

            // Parse Auto Patch into Memory
            let mut xe_patch = None;
            if let Some(ref p) = patch_path {
                if let Ok(parsed) = parse_patch_binary(p) {
                    if let Some(khv) = parsed.khv.as_ref() {
                        ini.patch.khv = Some(khv.records.clone());
                    }
                    xe_patch = Some(parsed);
                }
            }

            for entry in &ini.main {
                let filename = &entry.filename;
                let lower_name = filename.to_lowercase();
                if lower_name == "none" {
                    continue;
                }
                let mut found_content: Option<Vec<u8>> = None;
                let mut found_path: Option<PathBuf> = None;

                let is_update = lower_name.starts_with("cf_")
                    || lower_name.starts_with("sf_")
                    || lower_name.starts_with("cg_")
                    || lower_name.starts_with("sg_");
                let is_cbx = lower_name == "cbx.bin" || lower_name.starts_with("cbx_");

                macro_rules! check_hash {
                    ($c:expr, $name:expr, $tier:expr) => {
                        check_bootloader_candidate(&$c, $name, &entry.hash, $tier, unsafe_mode)
                            .is_some()
                    };
                }

                if is_cbx {
                    for (dir, tier) in [(&build, "Build"), (&mydata, "mydata"), (&common, "Common")]
                    {
                        let cand = resolve_robust(dir, filename);
                        if cand.exists() {
                            let c = std::fs::read(&cand)?;
                            if check_hash!(c, filename, tier) {
                                found_content = Some(c);
                                found_path = Some(cand);
                                break;
                            }
                        }
                    }
                }

                // Tier 1: mydata folder
                if found_content.is_none() {
                    let cand = resolve_robust(&mydata, filename);
                    if cand.exists() {
                        let c = std::fs::read(&cand)?;
                        if check_hash!(c, filename, "mydata") {
                            found_content = Some(c);
                            found_path = Some(cand);
                        }
                    }
                }

                // Tier 2: Build folder
                if found_content.is_none() {
                    let cand = resolve_robust(&build, filename);
                    if cand.exists() {
                        let c = std::fs::read(&cand)?;
                        if check_hash!(c, filename, "Build") {
                            found_content = Some(c);
                            found_path = Some(cand);
                        }
                    }
                }

                // Tier 4: Build folder STFS (CF, CG only)
                if is_update && found_content.is_none() {
                    let p_xboxupd = build.join("xboxupd.bin");
                    if p_xboxupd.exists() {
                        if let Ok(data_upd) = std::fs::read(&p_xboxupd) {
                            if let Ok(parts) = crate::core::images::stfs::split_xboxupd_raw(&data_upd)
                            {
                                let stfs_match = if lower_name == expected_cf {
                                    check_stfs_bootloader_candidate(
                                        &parts.cf_raw,
                                        filename,
                                        &entry.hash,
                                        "Build STFS (xboxupd.bin)",
                                        unsafe_mode,
                                    )
                                    .map(|_| parts.cf_raw.clone())
                                } else if lower_name == expected_cg {
                                    check_stfs_bootloader_candidate(
                                        &parts.cg_raw,
                                        filename,
                                        &entry.hash,
                                        "Build STFS (xboxupd.bin)",
                                        unsafe_mode,
                                    )
                                    .map(|_| parts.cg_raw.clone())
                                } else {
                                    None
                                };

                                if let Some(c) = stfs_match {
                                    found_content = Some(c);
                                    found_path = Some(p_xboxupd.clone());
                                }
                            }

                            if let Err(e) = crate::core::images::stfs::parse_xboxupd(&data_upd) {
                                info!(
                                    "[ini] Failed to fully validate xboxupd.bin for {} in Build STFS tier: {}",
                                    filename, e
                                );
                            }
                        }
                    }

                    if found_content.is_none() {
                        if let Ok(entries) = std::fs::read_dir(&build) {
                            for stfs_entry in entries.flatten() {
                                if let Some(name) = stfs_entry.file_name().to_str() {
                                    if name.starts_with("su") && !name.contains('.') {
                                        if let Ok(data_stfs) = std::fs::read(stfs_entry.path()) {
                                            if let Ok(stfs) =
                                                crate::core::images::stfs::StfsContainer::new(
                                                    &data_stfs,
                                                )
                                            {
                                                if let Ok(mem) = stfs.extract_to_memory() {
                                                    for (k, v) in mem {
                                                        let k_lower = k.to_lowercase();
                                                        if k_lower == "xboxupd.bin"
                                                            || (k_lower.starts_with("su")
                                                                && !k_lower.contains('.'))
                                                        {
                                                            if let Ok(parts) =
                                                                crate::core::images::stfs::split_xboxupd_raw(&v)
                                                            {
                                                                let stfs_match = if lower_name == expected_cf {
                                                                    check_stfs_bootloader_candidate(
                                                                        &parts.cf_raw,
                                                                        filename,
                                                                        &entry.hash,
                                                                        "STFS",
                                                                        unsafe_mode,
                                                                    )
                                                                    .map(|_| parts.cf_raw.clone())
                                                                } else if lower_name == expected_cg {
                                                                    check_stfs_bootloader_candidate(
                                                                        &parts.cg_raw,
                                                                        filename,
                                                                        &entry.hash,
                                                                        "STFS",
                                                                        unsafe_mode,
                                                                    )
                                                                    .map(|_| parts.cg_raw.clone())
                                                                } else {
                                                                    None
                                                                };
                                                                if let Some(c) = stfs_match {
                                                                    found_content = Some(c);
                                                                    found_path = Some(stfs_entry.path());
                                                                }
                                                            }

                                                            if let Err(e) = crate::core::images::stfs::parse_xboxupd(&v) {
                                                                info!(
                                                                    "[ini] Failed to fully validate STFS xboxupd candidate '{}' for {}: {}",
                                                                    k,
                                                                    filename,
                                                                    e
                                                                );
                                                            }
                                                        } else if allowed_flashfs_from_ini
                                                            .contains(&k_lower)
                                                        {
                                                            stfs_flashfs_candidates
                                                                .entry(k_lower)
                                                                .or_default()
                                                                .push(v);
                                                        }
                                                    }
                                                }
                                            }
                                            if found_content.is_some() {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Tier 6: Common folder
                if found_content.is_none() {
                    let cand = common.join(filename);
                    if cand.exists() {
                        let c = std::fs::read(&cand)?;
                        if check_hash!(c, filename, "Common") {
                            found_content = Some(c);
                            found_path = Some(cand);
                        }
                    }
                }

                // Tier 7: NAND Image
                if found_content.is_none() {
                    if let Some(n) = nand {
                        let bl = Some(&n.bootloaders);
                        let upd = n.update.as_ref();

                        let mut nand_data = None;
                        if lower_name.starts_with("cb") {
                            if lower_name.starts_with("cba") {
                                nand_data = bl.and_then(|b| b.cb_a.as_ref()).map(|b| b.serialize());
                            } else if lower_name.starts_with("cbb") {
                                nand_data = bl.and_then(|b| b.cb_b.as_ref()).map(|b| b.serialize());
                            } else if lower_name.starts_with("cbx") {
                                nand_data = bl.and_then(|b| b.cb_x.as_ref()).map(|b| b.serialize());
                            } else {
                                nand_data = bl.and_then(|b| b.cb.as_ref()).map(|b| b.serialize());
                            }
                        } else if lower_name.starts_with("cd") || lower_name.starts_with("sd") {
                            nand_data = bl.and_then(|b| b.cd.as_ref()).map(|b| b.serialize());
                        } else if lower_name.starts_with("ce") || lower_name.starts_with("se") {
                            nand_data = bl.and_then(|b| b.ce.as_ref()).map(|b| b.serialize());
                        } else if lower_name.starts_with("sc") {
                            nand_data = bl.and_then(|b| b.sc.as_ref()).map(|b| b.serialize());
                        } else if lower_name.starts_with("cf") || lower_name.starts_with("sf") {
                            let slot = lower_name
                                .split('_')
                                .nth(1)
                                .and_then(|s| s.split('.').next())
                                .and_then(|s| s.parse::<usize>().ok())
                                .unwrap_or(0);
                            nand_data = match slot {
                                1 => upd.and_then(|u| u.cf_1.as_ref()).map(|b| b.serialize()),
                                _ => upd.and_then(|u| u.cf_0.as_ref()).map(|b| b.serialize()),
                            };
                        } else if lower_name.starts_with("cg") || lower_name.starts_with("sg") {
                            let slot = lower_name
                                .split('_')
                                .nth(1)
                                .and_then(|s| s.split('.').next())
                                .and_then(|s| s.parse::<usize>().ok())
                                .unwrap_or(0);
                            nand_data = match slot {
                                1 => upd.and_then(|u| u.cg_1.as_ref()).map(|b| b.serialize()),
                                _ => upd.and_then(|u| u.cg_0.as_ref()).map(|b| b.serialize()),
                            };
                        }

                        if let Some(c) = nand_data {
                            if check_hash!(c, filename, "NAND Image") {
                                found_content = Some(c);
                                found_path = Some(PathBuf::from("NAND_IMAGE"));
                            }
                        }
                    }
                }

                // Need to add rebooter patching
                if let Some(mut c) = found_content {
                    if let Some(ref parsed_patch) = xe_patch {
                        if !nochainpatch {
                            if Some(&lower_name) == target_cb.as_ref() {
                                if let Some(ref cb_patch) = parsed_patch.cb {
                                    let _ = apply_records(&cb_patch.records, &mut c);
                                } else if let Some(ref cbb_patch) = parsed_patch.cb_b {
                                    let _ = apply_records(&cbb_patch.records, &mut c);
                                }
                            } else if lower_name.starts_with("cd_") || lower_name.starts_with("sd_")
                            {
                                if let Some(ref cd_patch) = parsed_patch.cd {
                                    let _ = apply_records(&cd_patch.records, &mut c);
                                }
                            }
                        }
                    }

                    result.bootloader_assets.insert(lower_name.clone(), c);
                    if entry.chain > 0 {
                        warn!("[ini] Rebooter chain assets are not supported by the current NAND skeleton structure; recording as primary chain assets.");
                    }
                    let target_bl = result.bootloaders.as_mut().unwrap();

                    let fp = found_path.unwrap_or_else(|| PathBuf::from("MEMORY"));
                    if lower_name.starts_with("cb") {
                        if lower_name.starts_with("cba") {
                            target_bl.cb_a = Some(fp);
                        } else if lower_name.starts_with("cbb") {
                            target_bl.cb_b = Some(fp);
                        } else if lower_name.starts_with("cbx") {
                            target_bl.cb_x = Some(fp);
                        } else {
                            target_bl.cb = Some(fp);
                        }
                    } else if lower_name.starts_with("cd") || lower_name.starts_with("sd") {
                        target_bl.cd = Some(fp);
                    } else if lower_name.starts_with("ce") || lower_name.starts_with("se") {
                        target_bl.ce = Some(fp);
                    } else if lower_name.starts_with("sc") {
                        target_bl.sc = Some(fp);
                    }
                } else {
                    return Err(FilesearchError::FileNotFound(filename.to_string()));
                }
            }
        }

        if !ini.flashfs.is_empty() {
            let mut flashfs = FlashFS::new();
            for entry in &ini.flashfs {
                let filename = &entry.filename;
                let basename = strip_flashfs_path_indicator(filename);
                let lower_basename = basename.to_lowercase();
                if lower_basename == "sysupdate.xexp1" || lower_basename == "sysupdate.xexp2" {
                    info!(
                        "[ini] Unconditionally bypassing file discovery for {}",
                        filename
                    );
                    continue;
                }
                let mut found_content: Option<Vec<u8>> = None;

                // Probe candidates: exact basename, then basename+"1", basename+"2"
                let disk_candidates = [
                    basename.clone(),
                    format!("{}1", basename),
                    format!("{}2", basename),
                ];

                // Tier 1: mydata folder
                if found_content.is_none() {
                    // Try the original hint path first (handles "..\launch.xex" style entries)
                    let hint_path = resolve_robust(&mydata, filename);
                    let paths: Vec<std::path::PathBuf> = std::iter::once(hint_path)
                        .chain(disk_candidates.iter().skip(1).map(|c| mydata.join(c)))
                        .collect();
                    for p in paths {
                        if p.exists() {
                            let c = std::fs::read(&p)?;
                            if check_crc32_simple(&c, &basename, &entry.hash, "mydata", unsafe_mode)
                                .is_some()
                            {
                                found_content = Some(c);
                                break;
                            }
                        }
                    }
                }

                // Tier 2: Build folder
                if found_content.is_none() {
                    let hint_path = resolve_robust(&build, filename);
                    let paths: Vec<std::path::PathBuf> = std::iter::once(hint_path)
                        .chain(disk_candidates.iter().skip(1).map(|c| build.join(c)))
                        .collect();
                    for p in paths {
                        if p.exists() {
                            let c = std::fs::read(&p)?;
                            if check_crc32_simple(&c, &basename, &entry.hash, "Build", unsafe_mode)
                                .is_some()
                            {
                                found_content = Some(c);
                                break;
                            }
                        }
                    }
                }

                // Tier 3: build/flashfs subfolder
                if found_content.is_none() && flashfs_folder.is_dir() {
                    for cand in &disk_candidates {
                        let p = flashfs_folder.join(cand);
                        if p.exists() {
                            let c = std::fs::read(&p)?;
                            if check_crc32_simple(
                                &c,
                                &basename,
                                &entry.hash,
                                "Build/flashfs",
                                unsafe_mode,
                            )
                            .is_some()
                            {
                                found_content = Some(c);
                                break;
                            }
                        }
                    }
                }

                // Tier 4: Build folder STFS (FlashFS assets extracted during bootloader discovery)
                if found_content.is_none() {
                    let cand_names = [
                        lower_basename.clone(),
                        format!("{}1", lower_basename),
                        format!("{}2", lower_basename),
                    ];
                    for cand in &cand_names {
                        if let Some(candidates) = stfs_flashfs_candidates.get(cand) {
                            found_content = select_flashfs_candidate(
                                candidates,
                                &basename,
                                &entry.hash,
                                unsafe_mode,
                            );
                            if found_content.is_some() {
                                break;
                            }
                        }
                    }
                }

                // Tier 5: Common folder
                if found_content.is_none() {
                    for cand in &disk_candidates {
                        let p = common.join(cand);
                        if p.exists() {
                            let c = std::fs::read(&p)?;
                            if check_crc32_simple(&c, &basename, &entry.hash, "Common", unsafe_mode)
                                .is_some()
                            {
                                found_content = Some(c);
                                break;
                            }
                        }
                    }
                }

                // Tier 6: NAND FlashFS
                if found_content.is_none() {
                    if let Some(n) = nand {
                        if let Some(flashfs) = n.flashfs.as_ref() {
                            if let Some(n_entry) = flashfs
                                .root
                                .entries
                                .iter()
                                .find(|e| e.file_name.to_lowercase() == lower_basename)
                            {
                                let c = n_entry.data.clone();
                                if check_crc32_simple(
                                    &c,
                                    &basename,
                                    &entry.hash,
                                    "NAND FlashFS",
                                    unsafe_mode,
                                )
                                .is_some()
                                {
                                    found_content = Some(c);
                                }
                            }
                        }
                    }
                }

                if let Some(c) = found_content {
                    let mut fs_entry = FileSystemEntry::new(0);
                    fs_entry.file_name = basename.clone();
                    fs_entry.source_path = Some(filename.to_string());
                    fs_entry.data = c.clone();
                    flashfs.root.entries.push(fs_entry);
                    result.flashfs_assets.insert(lower_basename, c);
                } else {
                    return Err(FilesearchError::FileNotFound(filename.to_string()));
                }
            }
            result.flashfs = Some(flashfs);
        }

        Ok(IniSearch {
            ini,
            build,
            common,
            mydata,
            payloads,
            smc: smc_dir,
            unsafe_mode: Some(unsafe_mode),
            result,
        })
    }
}

// Search for NAND / Shadowboot / XeLL image / CPU Key / SB Priv Key

pub struct ImageSearchResult {
    pub nand: Option<PathBuf>,
    pub key_string: Option<String>,
    pub key_bin: Option<PathBuf>,
    pub keyvault: Option<PathBuf>,
    pub smc: Option<PathBuf>,
}

pub struct ImageSearch {
    pub result: ImageSearchResult,
}

impl ImageSearch {
    pub fn new(nand: impl AsRef<Path>) -> Self {
        let nand = nand.as_ref().to_path_buf();
        let nand = nand.canonicalize().unwrap_or_else(|_| nand.clone());

        let result = ImageSearchResult {
            nand: Some(nand),
            key_string: None,
            key_bin: None,
            keyvault: None,
            smc: None,
        };

        ImageSearch { result }
    }
}

// Search and return vector of available patches

pub struct PatchSearchResult {
    pub name: String,
    pub path: PathBuf,
}

pub struct PatchSearch {
    pub build: Option<PathBuf>,
    pub data: Option<PathBuf>,
    pub result: Vec<PatchSearchResult>,
}

impl PatchSearch {
    pub fn new(build: impl AsRef<Path>, data: Option<impl AsRef<Path>>) -> Self {
        let build = Some(build.as_ref().to_path_buf());
        let data = data.map(|p| p.as_ref().to_path_buf());

        PatchSearch {
            build,
            data,
            result: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gxcrypt::crc::{bls_crc32_hex, crc32_hex};

    #[test]
    fn flashfs_hashes_use_raw_crc32() {
        let mut data = vec![0u8; 0x260];
        let declared_len = data.len() as u32;
        data[0x0C..0x10].copy_from_slice(&declared_len.to_be_bytes());
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }

        let flashfs_hash = crc32_hex(&data);
        let bootloader_hash = get_xebuild_crc32(&data, "cf_5772.bin");

        assert_eq!(flashfs_hash, crc32_hex(&data));
        assert_eq!(bootloader_hash, bls_crc32_hex(&data, "cf_5772.bin"));
        assert_ne!(flashfs_hash, bootloader_hash);
    }

    #[test]
    fn select_flashfs_candidate_tries_all_candidates_by_crc() {
        let first = b"wrong".to_vec();
        let second = b"right".to_vec();
        let expected = Some(crc32_hex(&second));

        let selected = select_flashfs_candidate(
            &[first.clone(), second.clone()],
            "dash.xex",
            &expected,
            false,
        );

        assert_eq!(selected, Some(second));
    }

    // Verifies that get_xebuild_crc32 produces a hash matching a real xeBuild INI entry for CF.
    //
    // Requires a CF binary and its expected hash from a matching xeBuild INI.
    // Set GXBUILD_TEST_CF to the path of your CF binary, and GXBUILD_TEST_CF_HASH to
    // the expected hash from the INI (e.g. "f19cf13f").
    //
    // Example:
    //   GXBUILD_TEST_CF=/path/to/xeBuild/9199/cf_9199.bin GXBUILD_TEST_CF_HASH=f19cf13f cargo test -- --ignored
    #[test]
    #[ignore = "requires GXBUILD_TEST_CF env var pointing to a CF binary"]
    fn test_cf_crc32_matches_xebuild() {
        let cf_path = std::path::PathBuf::from(
            std::env::var("GXBUILD_TEST_CF").expect("GXBUILD_TEST_CF must be set"),
        );

        let expected = std::env::var("GXBUILD_TEST_CF_HASH")
            .expect("GXBUILD_TEST_CF_HASH must be set to the CRC32 from the xeBuild INI")
            .to_lowercase();

        let data = std::fs::read(&cf_path).expect("Failed to read CF binary");
        let actual = get_xebuild_crc32(&data, &cf_path.file_name().unwrap().to_string_lossy());
        assert_eq!(
            actual, expected,
            "CF CRC32 mismatch: got {}, expected {}",
            actual, expected
        );
    }
}
