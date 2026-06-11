use crate::builder::nand::builder::NandSkeleton;
use crate::builder::nand::parser::hex_to_bytes;
use self::filesearch::{FilesearchError, IniSearch};
use self::nandsearch::{NandSearch, NandSearchError};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;

pub mod filesearch;
pub mod nandsearch;
pub mod xeini;
pub mod options;

#[derive(Error, Debug)]
pub enum BuildAssetsError {
    #[error("build config missing build type")]
    MissingBuildType,
    #[error("build config missing console type")]
    MissingConsoleType,
    #[error("could not find or read INI at {path:?}")]
    IniRead { path: PathBuf },
    #[error("no CPU key found in build config or data directory")]
    MissingCpuKey,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Filesearch(#[from] FilesearchError),
    #[error(transparent)]
    NandSearch(#[from] NandSearchError),
}



pub struct BuildConfig {
    pub pending_key: Option<[u8; 16]>,
    pub build_type: Option<String>, // INI name
    pub console_type: Option<String>, // INI section
    pub xe_ini: Option<xeini::XeBuildIni>,
    pub options: options::OptionsIni,
    pub ini_dir: Option<std::path::PathBuf>,
    pub common_dir: Option<std::path::PathBuf>,
    pub data_dir: Option<std::path::PathBuf>,
    pub output_path: Option<std::path::PathBuf>,
    pub ini_ext: Option<String>, // INI name extension
    pub bl_ext: Option<String>, // INI section extension
    pub addons: Vec<String>,
}
impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            pending_key: None,
            build_type: None,
            console_type: None,
            xe_ini: None,
            options: options::OptionsIni::new(),
            ini_dir: None,
            common_dir: None,
            data_dir: None,
            output_path: None,
            ini_ext: None,
            bl_ext: None,
            addons: Vec::new(),
        }
    }
}

pub struct BuildAssets {
    pub pending_assets: HashMap<String, Vec<u8>>, // Legacy
    pub bootloader_assets: HashMap<String, Vec<u8>>,
    pub security_assets: HashMap<String, Vec<u8>>,
    pub flashfs_assets: HashMap<String, Vec<u8>>,
    pub extra_assets: HashMap<String, Vec<u8>>, // SMC, STFS, Xboxupd
    pub flashfs_allowlist: Option<std::collections::HashSet<String>>,
}
impl BuildAssets {
    pub fn new(config: &BuildConfig) -> Result<Self, BuildAssetsError> {
        let build_type = config
            .build_type
            .clone()
            .ok_or(BuildAssetsError::MissingBuildType)?;
        let console = config
            .console_type
            .clone()
            .ok_or(BuildAssetsError::MissingConsoleType)?;

        let ini_dir = config.ini_dir.clone().unwrap_or_else(|| PathBuf::from("."));
        let data_dir = config
            .data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("mydata"));
        let common_dir = config
            .common_dir
            .clone()
            .unwrap_or_else(|| ini_dir.join("../common"));
        let payloads_dir = ini_dir.join("../payloads");
        let smc_dir = ini_dir.join("../smc");
        let options = config.options.clone();

        let ini_suffix = config
            .ini_ext
            .as_ref()
            .map(|ext| format!("_{}", ext))
            .unwrap_or_default();
        let ini_filename = format!("_{}{}.ini", build_type, ini_suffix);
        let ini_path = ini_dir.join(&ini_filename);

        let console_section_base = match console.as_str() {
            "jasper256" | "jasper512" | "jasperbb" | "jasperbigffs" => "jasper".to_string(),
            "trinitybb" | "trinitybigffs" => "trinity".to_string(),
            "corona4g" => "corona".to_string(),
            "winchester4g" => "winchester".to_string(),
            _ => console,
        };
        let console_section = match &config.bl_ext {
            Some(ext) => format!("{}_{}", console_section_base, ext),
            None => console_section_base,
        };

        let ini = if let Some(ini) = config.xe_ini.clone() {
            ini
        } else {
            xeini::parse_xe_ini(&ini_path, &console_section)
                .map_err(|_| BuildAssetsError::IniRead { path: ini_path })?
        };

        let nand_path = [
            data_dir.join("nanddump.bin"),
            data_dir.join("nanddump1.bin"),
            data_dir.join("nanddump2.bin"),
            data_dir.join("nanddump.ecc"),
            data_dir.join("nanddump1.ecc"),
            data_dir.join("nanddump2.ecc"),
            data_dir.join("nanddump"),
            data_dir.join("updflash.bin"),
            data_dir.join("updflash.ecc"),
        ]
        .into_iter()
        .find(|path| path.exists());

        let cpukey = if let Some(key) = config.pending_key {
            Some(key)
        } else if let Some(key) = &options.keys.cpukey {
            match hex_to_bytes(key) {
                Ok(bytes) => <[u8; 16]>::try_from(bytes.as_slice()).ok(),
                Err(_) => None,
            }
        } else {
            let key_bin = data_dir.join("cpukey.bin");
            let key_txt = data_dir.join("cpukey.txt");
            if key_bin.exists() {
                let bytes = std::fs::read(&key_bin)?;
                if bytes.len() >= 16 {
                    let mut key = [0u8; 16];
                    key.copy_from_slice(&bytes[..16]);
                    Some(key)
                } else {
                    None
                }
            } else if key_txt.exists() {
                let text = std::fs::read_to_string(&key_txt)?;
                let clean = text.trim();
                match hex_to_bytes(clean) {
                    Ok(bytes) => <[u8; 16]>::try_from(bytes.as_slice()).ok(),
                    Err(_) => None,
                }
            } else {
                None
            }
        };

        let nand_search = match (nand_path.as_ref(), cpukey) {
            (Some(path), Some(key)) => {
                let nand_bytes = std::fs::read(path)?;
                Some(NandSearch::new(ini.clone(), &nand_bytes, key)?)
            }
            (Some(_), None) => return Err(BuildAssetsError::MissingCpuKey),
            (None, _) => None,
        };

        let nand = nand_search.as_ref().map(|search| search.skeleton.clone());
        let ini_search = IniSearch::new(
            ini.clone(),
            &ini_dir,
            &common_dir,
            &data_dir,
            &payloads_dir,
            &smc_dir,
            &nand,
            options.core.gxunsafe,
            options.core_builder.nofcrt,
            options.core_builder.nosecurity,
            options.core_builder.nosusecurity,
            options.core_builder.nochainpatch,
        )?;

        let mut flashfs_allowlist = std::collections::HashSet::new();
        for entry in &ini.flashfs {
            let basename = xeini::strip_flashfs_path_indicator(&entry.filename);
            flashfs_allowlist.insert(basename.to_lowercase());
        }
        for name in &[
            "fcrt.bin",
            "crl.bin",
            "dae.bin",
            "extended.bin",
            "secdata.bin",
            "odd.bin",
        ] {
            flashfs_allowlist.insert((*name).to_string());
        }

        let mut assets = Self::default();
        assets.bootloader_assets = ini_search.result.bootloader_assets;
        assets.security_assets = ini_search.result.security_assets;
        assets.flashfs_assets = ini_search.result.flashfs_assets;
        assets.flashfs_allowlist = if flashfs_allowlist.is_empty() {
            None
        } else {
            Some(flashfs_allowlist)
        };

        if let Some(search) = nand_search {
            for (name, data) in search.bootloaders {
                assets.bootloader_assets.entry(name).or_insert(data);
            }
            if !search.keyvault.is_empty() {
                assets
                    .security_assets
                    .entry("keyvault.bin".to_string())
                    .or_insert(search.keyvault);
            }
            if !search.smc_config.is_empty() {
                assets
                    .security_assets
                    .entry("smc_config.bin".to_string())
                    .or_insert(search.smc_config);
            }
            if let Some(fcrt) = search.fcrt {
                assets.security_assets.entry("fcrt.bin".to_string()).or_insert(fcrt);
            }
            for (name, data) in search.flashfs_assets {
                assets.flashfs_assets.entry(name).or_insert(data);
            }
        }

        for (name, data) in &assets.bootloader_assets {
            assets.pending_assets.insert(name.clone(), data.clone());
        }
        for (name, data) in &assets.security_assets {
            assets.pending_assets.insert(name.clone(), data.clone());
        }
        for (name, data) in &assets.flashfs_assets {
            assets.pending_assets.insert(name.clone(), data.clone());
        }

        Ok(assets)
    }
}

impl Default for BuildAssets {
    fn default() -> Self {
        Self {
            pending_assets: HashMap::new(),
            bootloader_assets: HashMap::new(),
            security_assets: HashMap::new(),
            flashfs_assets: HashMap::new(),
            extra_assets: HashMap::new(),
            flashfs_allowlist: None,
        }
    }
}

pub struct Session {
    pub build_config: BuildConfig,
    pub build_assets: BuildAssets,
    pub active_nand: Option<NandSkeleton>,
}
impl Default for Session {
    fn default() -> Self {
        Self {
            build_config: BuildConfig::default(),
            build_assets: BuildAssets::default(),
            active_nand: None,
        }
    }
}

impl Session {
    pub fn new(build_config: BuildConfig, build_assets: BuildAssets) -> Self {
        Self {
            build_config,
            build_assets,
            active_nand: None,
        }
    }
}
