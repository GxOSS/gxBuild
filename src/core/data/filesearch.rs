/*
    filesearch.rs - xeBuild style file searching engine

    Created in 2026 by Exposure / Zach for gxBuild.
    Modified in 2026 by M4ttW00d
    Licensed under the GNU General Public License Version 2.0
*/
use crate::builder::builder::NandSkeleton;
use crate::builder::chain::flashfs::{FileSystemEntry, FlashFS};
use crate::core::data::xeini::XeBuildIni;
use log::{info, warn};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

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

fn get_xebuild_crc32(data: &[u8], filename: &str) -> String {
    let lower_name = filename.to_lowercase();

    if data.len() < 0x10 {
        return format!("{:08x}", crc32fast::hash(data));
    }

    // Determine the actual checksum length from the loader header (offset 0xC)
    // xeBuild truncates all bootloaders to the size explicitly declared in the header.
    let mut xe_len = u32::from_be_bytes([data[0x0C], data[0x0D], data[0x0E], data[0x0F]]) as usize;
    if xe_len == 0 || xe_len > data.len() {
        xe_len = data.len();
    }

    let mut working = data[..xe_len].to_vec();

    // Zero out sensitive/nonce fields per xeBuild rules:
    if lower_name.starts_with("cb") || lower_name.starts_with("sb") {
        // CB/CB_A/CB_B/CB_X: Zero 0x30 bytes starting at 0x10 (0x10..0x40)
        let start = 0x10;
        let end = std::cmp::min(0x40, working.len());
        if working.len() > start {
            for i in start..end {
                working[i] = 0;
            }
        }
    } else if lower_name.starts_with("cf") || lower_name.starts_with("sf") {
        // CF: Zero 0x210 bytes starting at 0x20 (0x20..0x230)
        let start = 0x20;
        let end = std::cmp::min(0x230, working.len());
        if working.len() > start {
            for i in start..end {
                working[i] = 0;
            }
        }
    } else if lower_name.starts_with("cd")
        || lower_name.starts_with("sd")
        || lower_name.starts_with("ce")
        || lower_name.starts_with("se")
        || lower_name.starts_with("cg")
        || lower_name.starts_with("sg")
    {
        // CD, CE, CG: Zero 0x10 bytes starting at 0x10 (0x10..0x20)
        let start = 0x10;
        let end = std::cmp::min(0x20, working.len());
        if working.len() > start {
            for i in start..end {
                working[i] = 0;
            }
        }
    }

    format!("{:08x}", crc32fast::hash(&working))
}

pub struct IniSearchResult {
    pub bootloaders: Option<DiscoveredBootloaders>,
    pub rebooter: Option<DiscoveredBootloaders>,
    pub security: Option<Vec<PathBuf>>,
    pub update: Option<DiscoveredUpdate>,
    pub rebooter_update: Option<DiscoveredUpdate>,
    pub flashfs: Option<FlashFS>,
    /// Assets from the [main] section: bootloader binaries + CF/CG update loaders.
    pub bootloader_assets: HashMap<String, Vec<u8>>,
    /// Assets from the [security] section: smc.bin, kv.bin, fcrt.bin, odd.bin.
    pub security_assets: HashMap<String, Vec<u8>>,
    /// Assets from the [flashfs] section: XEX/XEX2/dat files to pack into FlashFS.
    /// Never contains bootloader binaries - routing is enforced by section membership.
    pub flashfs_assets: HashMap<String, Vec<u8>>,
}

pub struct IniSearch {
    pub ini: XeBuildIni,
    pub build: PathBuf,
    pub common: PathBuf,
    pub data: PathBuf,
    pub unsafe_mode: Option<bool>,
    pub result: IniSearchResult,
}

impl IniSearch {
    pub fn new(
        ini: XeBuildIni,
        build: impl AsRef<Path>,
        common: impl AsRef<Path>,
        data: impl AsRef<Path>,
        nand: &Option<NandSkeleton>,
        unsafe_mode: Option<bool>,
    ) -> Result<Self, FilesearchError> {
        let unsafe_mode = unsafe_mode.unwrap_or(false);
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
        let data = data.as_ref().to_path_buf();
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
                let mut found_content: Option<Vec<u8>> = None;
                let mut found_path: Option<PathBuf> = None;

                // NAND Image
                if let Some(n) = nand {
                    let nand_data = match lower_name.as_str() {
                        "keyvault.bin" | "kv.bin" => Some(n.extra.keyvault.clone()),
                        "fcrt.bin" => n.extra.fcrt.clone(),
                        _ => None,
                    };
                    if let Some(c) = nand_data {
                        if let Some(expected) = &entry.hash {
                            let mut hasher = crc32fast::Hasher::new();
                            hasher.update(&c);
                            let actual = format!("{:08x}", hasher.finalize());
                            if actual.to_lowercase() == expected.to_lowercase() {
                                found_content = Some(c);
                                found_path = Some(PathBuf::from("NAND_IMAGE"));
                            } else if unsafe_mode {
                                warn!("[ini] Unsafe Bypass: {} CRC32 mismatch (Expected: {}, Found: {} in NAND Image Tier). Continuing...", filename, expected, actual);
                                found_content = Some(c);
                                found_path = Some(PathBuf::from("NAND_IMAGE"));
                            } else {
                                info!("[ini] Hash mismatch for {} in NAND Image Tier, seeking fallback...", filename);
                            }
                        } else {
                            found_content = Some(c);
                            found_path = Some(PathBuf::from("NAND_IMAGE"));
                        }
                    }
                }

                // Data Folder
                if found_content.is_none() {
                    let cand = resolve_robust(&data, filename);
                    if cand.exists() {
                        let c = std::fs::read(&cand)?;
                        if let Some(expected) = &entry.hash {
                            let mut hasher = crc32fast::Hasher::new();
                            hasher.update(&c);
                            let actual = format!("{:08x}", hasher.finalize());
                            if actual.to_lowercase() == expected.to_lowercase() {
                                found_content = Some(c.clone());
                                found_path = Some(cand);
                            } else if unsafe_mode {
                                warn!("[ini] Unsafe Bypass: {} CRC32 mismatch (Expected: {}, Found: {} in Data Folder Tier). Continuing...", filename, expected, actual);
                                found_content = Some(c.clone());
                                found_path = Some(cand);
                            } else {
                                info!("[ini] Hash mismatch for {} in Data Folder Tier, seeking fallback...", filename);
                            }
                        } else {
                            found_content = Some(c);
                            found_path = Some(cand);
                        }
                    }
                }

                // Common Folder (Security only)
                if found_content.is_none() {
                    let cand = resolve_robust(&common, filename);
                    if cand.exists() {
                        let c = std::fs::read(&cand)?;
                        if let Some(expected) = &entry.hash {
                            let mut hasher = crc32fast::Hasher::new();
                            hasher.update(&c);
                            let actual = format!("{:08x}", hasher.finalize());
                            if actual.to_lowercase() == expected.to_lowercase() {
                                found_content = Some(c);
                                found_path = Some(cand);
                            } else if unsafe_mode {
                                warn!("[ini] Unsafe Bypass: {} CRC32 mismatch (Expected: {}, Found: {} in Common Folder Tier). Continuing...", filename, expected, actual);
                                found_content = Some(c);
                                found_path = Some(cand);
                            } else {
                                return Err(FilesearchError::HashMismatch(filename.to_string()));
                            }
                        } else {
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
                    warn!("[ini] All tiers failed for priority asset: {}", filename);
                    return Err(FilesearchError::FileNotFound(filename.clone()));
                }
            }
            result.security = Some(sec_paths);
        }

        // SMC and Payloads
        let section_base = ini.name.split('_').next().unwrap_or(&ini.name);
        let platform_clean = if section_base.ends_with("bl") {
            &section_base[..section_base.len() - 2]
        } else {
            section_base
        }
        .to_uppercase();

        let smc_path = data.join("SMC.bin");

        let smc_filename2 = format!("{}_CLEAN.bin", platform_clean);
        let smc_path2 = data.join(&smc_filename2);

        if smc_path.exists() {
            if let Ok(c) = std::fs::read(&smc_path) {
                info!("[ini] Discovered SMC.bin");
                result.security_assets.insert("smc.bin".to_string(), c);
            }
        } else if smc_path2.exists() {
            if let Ok(c) = std::fs::read(&smc_path2) {
                info!("[ini] Discovered clean SMC for platform {}", platform_clean);
                result.security_assets.insert("smc.bin".to_string(), c);
            }
        } else {
            return Err(FilesearchError::NoSmcOrCleanBin(platform_clean));
        }

        for entry in &ini.payloads {
            let filename = &entry.filename;
            let lower_name = filename.to_lowercase();
            let cand = data.join(filename);
            if cand.exists() {
                if let Ok(c) = std::fs::read(&cand) {
                    if let Some(expected) = &entry.hash {
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
                                "[ini] Discovered payload in data folder: {}",
                                cand.display()
                            );
                            info!("[ini] Payload {} passed CRC32: {}", filename, actual);
                            result.bootloader_assets.insert(lower_name, c);
                        }
                    } else {
                        return Err(FilesearchError::PayloadBrokenHash(filename.to_string()));
                    }
                }
            } else {
                return Err(FilesearchError::FileNotFound(filename.to_string()));
            }
        }

        // Bootloaders and Update Discovery
        if !ini.main.is_empty() {
            result.bootloaders = Some(DiscoveredBootloaders::new());
            if ini.rebooter {
                result.rebooter = Some(DiscoveredBootloaders::new());
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
                if let Ok(parsed) = crate::core::images::gxp::parse_patch_binary(p) {
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

                // crc32
                macro_rules! check_hash {
                    ($c:expr, $name:expr, $tier:expr) => {
                        if let Some(expected) = &entry.hash {
                            let actual = get_xebuild_crc32(&$c, $name);
                            if actual.to_lowercase() == expected.to_lowercase() { true }
                            else {
                                if unsafe_mode {
                                    warn!("[ini] Unsafe Bypass: {} CRC32 mismatch (Expected: {}, Found: {} in {} Tier). Continuing...", $name, expected, actual, $tier);
                                    true
                                } else {
                                    return Err(FilesearchError::HashMismatch($name.to_string()));
                                }
                            }
                        } else { true }
                    };
                }

                // NAND Image
                if let Some(n) = nand {
                    let mut nand_data = None;
                    if lower_name.starts_with("cb") {
                        if lower_name.starts_with("cba") {
                            nand_data = n.bootloaders.cb_a.as_ref().map(|b| b.serialize());
                        } else if lower_name.starts_with("cbb") {
                            nand_data = n.bootloaders.cb_b.as_ref().map(|b| b.serialize());
                        } else if lower_name.starts_with("cbx") {
                            nand_data = n.bootloaders.cb_x.as_ref().map(|b| b.serialize());
                        } else {
                            nand_data = n.bootloaders.cb.as_ref().map(|b| b.serialize());
                        }
                    } else if lower_name.starts_with("cd") || lower_name.starts_with("sd") {
                        nand_data = n.bootloaders.cd.as_ref().map(|b| b.serialize());
                    } else if lower_name.starts_with("ce") || lower_name.starts_with("se") {
                        nand_data = n.bootloaders.ce.as_ref().map(|b| b.serialize());
                    } else if lower_name.starts_with("sc") {
                        nand_data = n.bootloaders.sc.as_ref().map(|b| b.serialize());
                    } else if lower_name.starts_with("cf") || lower_name.starts_with("sf") {
                        nand_data = n.update.cf_0.as_ref().map(|b| b.serialize());
                    } else if lower_name.starts_with("cg") || lower_name.starts_with("sg") {
                        nand_data = n.update.cg_0.as_ref().map(|b| b.serialize());
                    }

                    if let Some(c) = nand_data {
                        if check_hash!(c, filename, "NAND Image") {
                            found_content = Some(c);
                            found_path = Some(PathBuf::from("NAND_IMAGE"));
                        }
                    }
                }

                // Build Folder (direct)
                if found_content.is_none() {
                    let cand = resolve_robust(&build, filename);
                    if cand.exists() {
                        let c = std::fs::read(&cand)?;
                        if check_hash!(c, filename, "Build Folder") {
                            found_content = Some(c);
                            found_path = Some(cand);
                        }
                    }
                }

                // Common Folder
                if found_content.is_none() {
                    let cand = common.join(filename);
                    if cand.exists() {
                        let c = std::fs::read(&cand)?;
                        if check_hash!(c, filename, "Common Folder") {
                            found_content = Some(c);
                            found_path = Some(cand);
                        }
                    }
                }

                // xboxupd.bin / STFS - Update only
                if is_update && found_content.is_none() {
                    let p_xboxupd = build.join("xboxupd.bin");
                    if p_xboxupd.exists() {
                        if let Ok(data_upd) = std::fs::read(&p_xboxupd) {
                            if let Ok(cf) =
                                crate::builder::chain::cf::BootloaderCf::parse(&data_upd)
                            {
                                let cf_size = cf.header.size.get() as usize;
                                result
                                    .bootloader_assets
                                    .insert(expected_cf.clone(), data_upd[0..cf_size].to_vec());
                                result
                                    .bootloader_assets
                                    .insert(expected_cg.clone(), data_upd[cf_size..].to_vec());
                                if let Some(c) = result.bootloader_assets.get(&lower_name).cloned()
                                {
                                    if check_hash!(c, filename, "xboxupd.bin") {
                                        found_content = Some(c);
                                        found_path = Some(p_xboxupd);
                                    }
                                }
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
                                                            if let Ok(cf) = crate::builder::chain::cf::BootloaderCf::parse(&v) {
                                                                let cf_size = cf.header.size.get() as usize;
                                                                result.bootloader_assets.insert(expected_cf.clone(), v[0..cf_size].to_vec());
                                                                result.bootloader_assets.insert(expected_cg.clone(), v[cf_size..].to_vec());
                                                            }
                                                        } else {
                                                            result
                                                                .flashfs_assets
                                                                .insert(k_lower, v);
                                                        }
                                                    }
                                                    if let Some(c) = result
                                                        .bootloader_assets
                                                        .get(&lower_name)
                                                        .cloned()
                                                    {
                                                        if check_hash!(c, filename, "STFS") {
                                                            found_content = Some(c);
                                                            found_path = Some(stfs_entry.path());
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


                // Need to add rebooter patching
                if let Some(mut c) = found_content {
                    // Apply Patch after confirmation
                    if let Some(ref parsed_patch) = xe_patch {
                        if Some(&lower_name) == target_cb.as_ref() {
                            if let Some(ref cb_patch) = parsed_patch.cb {
                                let _ = crate::core::images::gxp::apply_records(
                                    &cb_patch.records,
                                    &mut c,
                                );
                            } else if let Some(ref cbb_patch) = parsed_patch.cb_b {
                                let _ = crate::core::images::gxp::apply_records(
                                    &cbb_patch.records,
                                    &mut c,
                                );
                            }
                        } else if lower_name.starts_with("cd_") || lower_name.starts_with("sd_") {
                            if let Some(ref cd_patch) = parsed_patch.cd {
                                let _ = crate::core::images::gxp::apply_records(
                                    &cd_patch.records,
                                    &mut c,
                                );
                            }
                        }
                    }

                    result.bootloader_assets.insert(lower_name.clone(), c);
                    let target_bl = if entry.chain > 0 {
                        result
                            .rebooter
                            .as_mut()
                            .ok_or(FilesearchError::RebooterNotInitialized)?
                    } else {
                        result.bootloaders.as_mut().unwrap()
                    };

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

        // FlashFS Tiered Discovery
        if !ini.flashfs.is_empty() {
            let mut flashfs = FlashFS::new();
            for entry in &ini.flashfs {
                let filename = &entry.filename;
                let mut found_content: Option<Vec<u8>> = None;

                // NAND Image
                if let Some(n) = nand {
                    if let Some(n_entry) = n
                        .flashfs
                        .root
                        .entries
                        .iter()
                        .find(|e| e.file_name.to_lowercase() == filename.to_lowercase())
                    {
                        let c = n_entry.data.clone();
                        if let Some(expected) = &entry.hash {
                            let mut hasher = crc32fast::Hasher::new();
                            hasher.update(&c);
                            let actual = format!("{:08x}", hasher.finalize());
                            if actual.to_lowercase() == expected.to_lowercase() {
                                found_content = Some(c);
                            } else if unsafe_mode {
                                warn!("[ini] Unsafe Bypass: {} CRC32 mismatch (Expected: {}, Found: {} in NAND FlashFS Tier). Continuing...", filename, expected, actual);
                                found_content = Some(c);
                            } else {
                                info!("[ini] Hash mismatch for {} in NAND FlashFS Tier", filename);
                            }
                        } else {
                            found_content = Some(c);
                        }
                    }
                }

                // Local Folder
                if found_content.is_none() {
                    let candidates = [
                        filename.clone(),
                        format!("{}1", filename),
                        format!("{}2", filename),
                    ];
                    let paths = [flashfs_folder.clone(), build.clone(), data.clone()];
                    for p_base in &paths {
                        for cand in &candidates {
                            let p = resolve_robust(p_base, cand);
                            if p.exists() {
                                let c = std::fs::read(&p)?;
                                if let Some(expected) = &entry.hash {
                                    let mut hasher = crc32fast::Hasher::new();
                                    hasher.update(&c);
                                    let actual = format!("{:08x}", hasher.finalize());
                                    if actual.to_lowercase() == expected.to_lowercase() {
                                        found_content = Some(c);
                                        break;
                                    } else if unsafe_mode {
                                        warn!("[ini] Unsafe Bypass: {} CRC32 mismatch (Expected: {}, Found: {} in Folder Tier). Continuing...", filename, expected, actual);
                                        found_content = Some(c);
                                        break;
                                    } else {
                                        info!(
                                            "[ini] Hash mismatch for {} ({}) in Folder Tier",
                                            filename, cand
                                        );
                                    }
                                } else {
                                    found_content = Some(c);
                                    break;
                                }
                            }
                        }
                        if found_content.is_some() {
                            break;
                        }
                    }
                }

                // Memory / STFS
                if found_content.is_none() {
                    let cand_names = [
                        filename.to_lowercase(),
                        format!("{}1", filename.to_lowercase()),
                        format!("{}2", filename.to_lowercase()),
                    ];
                    for cand in &cand_names {
                        if let Some(c) = result.flashfs_assets.get(cand).cloned() {
                            if let Some(expected) = &entry.hash {
                                let mut hasher = crc32fast::Hasher::new();
                                hasher.update(&c);
                                let actual = format!("{:08x}", hasher.finalize());
                                if actual.to_lowercase() == expected.to_lowercase() {
                                    found_content = Some(c);
                                    break;
                                } else if unsafe_mode {
                                    warn!("[ini] Unsafe Bypass: {} CRC32 mismatch (Expected: {}, Found: {} in Memory/STFS Tier). Continuing...", filename, expected, actual);
                                    found_content = Some(c);
                                    break;
                                } else {
                                    info!(
                                        "[ini] Hash mismatch for {} in Memory/STFS Tier",
                                        filename
                                    );
                                }
                            } else {
                                found_content = Some(c);
                                break;
                            }
                        }
                    }
                }

                if let Some(c) = found_content {
                    let lower = filename.to_lowercase();
                    // No bootloader filter needed here: the [flashfs] INI section only names
                    // filesystem assets. Routing is enforced by section membership, not by prefix.
                    let mut fs_entry = FileSystemEntry::new(0);
                    fs_entry.file_name = filename.clone();
                    fs_entry.data = c.clone();
                    flashfs.root.entries.push(fs_entry);
                    result.flashfs_assets.insert(lower, c);
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
            data,
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
