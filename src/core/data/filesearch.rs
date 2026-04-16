use std::collections::HashMap;
use std::path::{Path, PathBuf};
use crate::builder::chain::flashfs::{FlashFS, FileSystemEntry};
use crate::core::data::xeini::{XeBuildIni, IniError};
use log::{info, warn};


// Search for files listed in INI

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
        Self { cb: None, cb_a: None, cb_b: None, cb_x: None, sc: None, cd: None, ce: None }
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
        Self { cf_0: None, cg_0: None, cf_1: None, cg_1: None }
    }
}

pub struct IniSearchResult {
    pub bootloaders: Option<DiscoveredBootloaders>,
    pub rebooter: Option<DiscoveredBootloaders>,
    pub security: Option<Vec<PathBuf>>,
    pub update: Option<DiscoveredUpdate>,
    pub rebooter_update: Option<DiscoveredUpdate>,
    pub flashfs: Option<FlashFS>,
    pub extracted_assets: HashMap<String, Vec<u8>>,
}

pub struct IniSearch {
    pub ini: XeBuildIni,
    pub build: PathBuf,
    pub common: PathBuf,
    pub data: PathBuf,
    pub result: IniSearchResult,
}

impl IniSearch {
    pub fn new(ini: XeBuildIni, build: impl AsRef<Path>, common: impl AsRef<Path>, data: impl AsRef<Path>) -> Result<Self, IniError> {
        let mut ini = ini;
        let mut result = IniSearchResult {
            bootloaders: None,
            rebooter: None,
            security: None,
            update: None,
            rebooter_update: None,
            flashfs: None,
            extracted_assets: HashMap::new(),
        };

        let build = build.as_ref().to_path_buf();
        let common = common.as_ref().to_path_buf();
        let data = data.as_ref().to_path_buf();
        
        let flashfs_folder = build.join("flashfs");
        
        // --- Auto Patcher Integration ---
        // Patches Priority: 1. Build/bin Folder, 2. Build/../bin Folder
        let platform = ini.name.split('_').next().unwrap_or(&ini.name).to_lowercase();
        let mut patch_path: Option<PathBuf> = None;

        let find_patch = |name: &str| -> Option<PathBuf> {
            let p1 = build.join("bin").join(name);
            let p2 = build.parent().unwrap_or(&build).join("bin").join(name);
            if p1.exists() { Some(p1) }
            else if p2.exists() { Some(p2) }
            else { None }
        };

        match ini.buildtype.as_str() {
            "retail" => {
                info!("[ini] Retail build type selected");
            },
            "glitch1" | "glitch2" | "glitch2m" | "glitch3" | "jtag" | "1f" | "2f" | "devgl" | "devkit" | "xdkbuild" | "rgbuild" => {
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
                                info!("[ini] Glitch1 Patches for platform {} found at path: {}", platform, p.display());
                                patch_path = Some(p);
                            } else {
                                return Err(IniError::NoAutoPatches("Glitch1".to_string(), ini.name.clone(), format!("Build/bin/{}", n)));
                            }
                        }
                    }
                    "glitch2" => {
                        let n = format!("patches_g2{}.bin", platform);
                        if let Some(p) = find_patch(&n) {
                            info!("[ini] Glitch2 Patches for platform {} found at path: {}", platform, p.display());
                            patch_path = Some(p);
                        } else {
                            return Err(IniError::NoAutoPatches("Glitch2".to_string(), ini.name.clone(), format!("Build/bin/{}", n)));
                        }
                    }
                    "glitch2m" | "devgl" | "xdkbuild" => {
                        let n = format!("patches_g2m{}.bin", platform);
                        if let Some(p) = find_patch(&n) {
                            info!("[ini] {} Patches for platform {} found at path: {}", ini.buildtype, platform, p.display());
                            patch_path = Some(p);
                        } else {
                            return Err(IniError::NoAutoPatches(ini.buildtype.clone(), ini.name.clone(), format!("Build/bin/{}", n)));
                        }
                    }
                    "glitch3" => {
                        let n3 = format!("patches_g3{}.bin", platform);
                        let n2 = format!("patches_g2{}.bin", platform);
                        if let Some(p3) = find_patch(&n3) {
                            info!("[ini] Glitch3 Patches for platform {} found at path: {}", platform, p3.display());
                            patch_path = Some(p3);
                        } else if let Some(p2) = find_patch(&n2) {
                            warn!("[ini] Glitch3 Patches for platform {} not found, using fallback: {}", platform, p2.display());
                            patch_path = Some(p2);
                        } else {
                            return Err(IniError::NoAutoPatches("Glitch3".to_string(), ini.name.clone(), format!("Build/bin/{}", n3)));
                        }
                    }
                    "devkit" => {
                        let n = format!("patches_dev{}.bin", platform);
                        if let Some(p) = find_patch(&n) {
                            info!("[ini] Devkit Patches for platform {} found at path: {}", platform, p.display());
                            patch_path = Some(p);
                        } else {
                            return Err(IniError::NoAutoPatches("Devkit".to_string(), ini.name.clone(), format!("Build/bin/{}", n)));
                        }
                    }
                    "rgbuild" => {
                        let n = format!("patches_rg{}.bin", platform);
                        if let Some(p) = find_patch(&n) {
                            info!("[ini] RGBuild Patches for platform {} found at path: {}", platform, p.display());
                            patch_path = Some(p);
                        } else {
                            return Err(IniError::NoAutoPatches("RGBuild".to_string(), ini.name.clone(), format!("Build/bin/{}", n)));
                        }
                    }
                    _ => {}
                }
            },
            _ => return Err(IniError::BadBuildFormat(ini.buildtype.clone())),
        }
        ini.patch.path = patch_path;

        // --- Security / Extra Discovery ---
        // Priority: 1. Data Folder
        if !ini.security.is_empty() {
            let mut sec_paths = Vec::new();
            for entry in &ini.security {
                let filename = &entry.filename;
                let candidate = data.join(filename);
                if candidate.exists() {
                    let content = std::fs::read(&candidate)?;
                    if let Some(expected) = &entry.hash {
                        let mut hasher = crc32fast::Hasher::new();
                        hasher.update(&content);
                        let actual = format!("{:08x}", hasher.finalize());
                        if actual.to_lowercase() != expected.to_lowercase() {
                            return Err(IniError::HashMismatch(filename.clone(), expected.clone(), actual));
                        }
                    }
                    result.extracted_assets.insert(filename.to_lowercase(), content);
                    sec_paths.push(candidate);
                } else {
                    return Err(IniError::FileNotFound(filename.clone()));
                }
            }
            result.security = Some(sec_paths);
        }

        // --- Bootloaders (Main and Update) Discovery ---
        if !ini.main.is_empty() {
            result.bootloaders = Some(DiscoveredBootloaders::new());
            if ini.rebooter {
                result.rebooter = Some(DiscoveredBootloaders::new());
            }

            let mut expected_cf = "cf_0.bin".to_string();
            let mut expected_cg = "cg_0.bin".to_string();
            for entry in &ini.main {
                let lower = entry.filename.to_lowercase();
                if lower.starts_with("cf_") || lower.starts_with("sf_") { expected_cf = lower; }
                else if lower.starts_with("cg_") || lower.starts_with("sg_") { expected_cg = lower; }
            }

            for entry in &ini.main {
                let filename = &entry.filename;
                let lower_name = filename.to_lowercase();
                let mut found_path = None;
                let mut content = None;

                let is_update = lower_name.starts_with("cf_") || lower_name.starts_with("sf_") || lower_name.starts_with("cg_") || lower_name.starts_with("sg_");

                if is_update {
                    let p_build = build.join(filename);
                    let p_common = common.join(filename);
                    let p_xboxupd = build.join("xboxupd.bin");

                    if p_build.exists() {
                        found_path = Some(p_build.clone());
                        content = Some(std::fs::read(&p_build)?);
                    } else if let Some(mem) = result.extracted_assets.get(&lower_name) {
                        content = Some(mem.clone());
                    } else {
                        if p_xboxupd.exists() {
                            if let Ok(data_upd) = std::fs::read(&p_xboxupd) {
                                info!("[ini] Found generic xboxupd.bin, slicing CF/CG payloads...");
                                if let Ok(cf) = crate::builder::chain::cf::BootloaderCf::parse(&data_upd) {
                                    let cf_size = cf.header.size.get() as usize;
                                    if data_upd.len() >= cf_size {
                                        result.extracted_assets.insert(expected_cf.clone(), data_upd[0..cf_size].to_vec());
                                        result.extracted_assets.insert(expected_cg.clone(), data_upd[cf_size..].to_vec());
                                        content = result.extracted_assets.get(&lower_name).cloned();
                                    }
                                }
                            }
                        }
                        
                        if content.is_none() {
                            if let Ok(entries) = std::fs::read_dir(&build) {
                                for stfs_entry in entries.flatten() {
                                    if let Some(name) = stfs_entry.file_name().to_str() {
                                        if name.starts_with("su") && !name.contains('.') {
                                            if let Ok(data_stfs) = std::fs::read(stfs_entry.path()) {
                                                info!("[ini] Found STFS update container: {}, extracting to memory...", name);
                                                if let Ok(stfs) = crate::core::data::stfs::StfsContainer::new(&data_stfs) {
                                                    if let Ok(mem) = stfs.extract_to_memory() {
                                                        for (k, v) in mem {
                                                            if k == "xboxupd.bin" || (k.starts_with("su") && !k.contains('.')) {
                                                                if let Ok(cf) = crate::builder::chain::cf::BootloaderCf::parse(&v) {
                                                                    let cf_size = cf.header.size.get() as usize;
                                                                    if v.len() >= cf_size {
                                                                        result.extracted_assets.insert(expected_cf.clone(), v[0..cf_size].to_vec());
                                                                        result.extracted_assets.insert(expected_cg.clone(), v[cf_size..].to_vec());
                                                                    }
                                                                }
                                                            } else {
                                                                result.extracted_assets.insert(k.to_lowercase(), v);
                                                            }
                                                        }
                                                        content = result.extracted_assets.get(&lower_name).cloned();
                                                    }
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if content.is_none() && p_common.exists() {
                            found_path = Some(p_common.clone());
                            content = Some(std::fs::read(&p_common)?);
                        }
                    }
                } else {
                    let p_build = build.join(filename);
                    let p_common = common.join(filename);
                    if p_build.exists() {
                        found_path = Some(p_build.clone());
                        content = Some(std::fs::read(&p_build)?);
                    } else if p_common.exists() {
                        found_path = Some(p_common.clone());
                        content = Some(std::fs::read(&p_common)?);
                    }
                }

                if let Some(c) = content {
                    if let Some(expected) = &entry.hash {
                        let mut hasher = crc32fast::Hasher::new();
                        hasher.update(&c);
                        let actual = format!("{:08x}", hasher.finalize());
                        if actual.to_lowercase() != expected.to_lowercase() {
                            return Err(IniError::HashMismatch(filename.clone(), expected.clone(), actual));
                        }
                    }
                    result.extracted_assets.insert(lower_name.clone(), c);

                    let is_rebooter = entry.chain > 0;
                    let target_bl = if is_rebooter {
                        result.rebooter.as_mut().ok_or(IniError::RebooterNotInitialized)?
                    } else {
                        result.bootloaders.as_mut().unwrap()
                    };

                    let fp = found_path.unwrap_or_else(|| std::path::PathBuf::from(filename));
                    if lower_name.starts_with("cb") {
                        if lower_name.starts_with("cba") { target_bl.cb_a = Some(fp); }
                        else if lower_name.starts_with("cbb") { target_bl.cb_b = Some(fp); }
                        else if lower_name.starts_with("cbx") { target_bl.cb_x = Some(fp); }
                        else { target_bl.cb = Some(fp); }
                    } else if lower_name.starts_with("cd") || lower_name.starts_with("sd") {
                        target_bl.cd = Some(fp);
                    } else if lower_name.starts_with("ce") || lower_name.starts_with("se") {
                        target_bl.ce = Some(fp);
                    } else if lower_name.starts_with("sc") {
                        target_bl.sc = Some(fp);
                    }
                } else {
                    warn!("[ini] Bootloader not found: {}", filename);
                    return Err(IniError::FileNotFound(filename.to_string()));
                }
            }
        }

        // --- FlashFS Discovery ---
        if !ini.flashfs.is_empty() {
            let mut flashfs = FlashFS::new();
            for entry in &ini.flashfs {
                let filename = &entry.filename;
                let lower_name = filename.to_lowercase();
                
                let p_flashfs = flashfs_folder.join(filename);
                let p_build = build.join(filename);

                let mut content = None;

                if p_flashfs.exists() {
                    content = Some(std::fs::read(&p_flashfs)?);
                } else if p_build.exists() {
                    content = Some(std::fs::read(&p_build)?);
                } else if let Some(mem) = result.extracted_assets.get(&lower_name) {
                    content = Some(mem.clone());
                } else {
                    if let Ok(entries) = std::fs::read_dir(&build) {
                        for stfs_entry in entries.flatten() {
                            if let Some(name) = stfs_entry.file_name().to_str() {
                                if name.starts_with("su") && !name.contains('.') {
                                    if let Ok(data_stfs) = std::fs::read(stfs_entry.path()) {
                                        if let Ok(stfs) = crate::core::data::stfs::StfsContainer::new(&data_stfs) {
                                            if let Ok(mem) = stfs.extract_to_memory() {
                                                for (k, v) in mem {
                                                    result.extracted_assets.insert(k.to_lowercase(), v);
                                                }
                                                content = result.extracted_assets.get(&lower_name).cloned();
                                            }
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                if let Some(c) = content {
                    if let Some(expected) = &entry.hash {
                        let mut hasher = crc32fast::Hasher::new();
                        hasher.update(&c);
                        let actual = format!("{:08x}", hasher.finalize());
                        if actual.to_lowercase() != expected.to_lowercase() {
                            return Err(IniError::HashMismatch(filename.clone(), expected.clone(), actual));
                        }
                    }
                    
                    let mut fs_entry = FileSystemEntry::new(0);
                    fs_entry.file_name = filename.clone();
                    fs_entry.data = c.clone();
                    flashfs.root.entries.push(fs_entry);
                    
                    result.extracted_assets.insert(lower_name, c);
                } else {
                    warn!("[ini] FlashFS file not found: {}", filename);
                    return Err(IniError::FileNotFound(filename.to_string()));
                }
            }
            result.flashfs = Some(flashfs);
        }

        Ok(IniSearch {
            ini,
            build,
            common,
            data,
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
        
        ImageSearch {
            result,
        }
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
