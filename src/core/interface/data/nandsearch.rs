use crate::builder::filesystem::flashfs::FlashFS;
use crate::builder::filesystem::mobile::MobileStore;
use crate::builder::nand::builder::NandSkeleton;
use crate::core::interface::data::filesearch::get_xebuild_crc32;
use crate::core::interface::data::xeini::{
    bootloader_matches_expected_name, strip_flashfs_path_indicator, XeBuildIni,
};
use crate::core::images::blocks::{BlocksError, NandProcessor};
use gxcrypt::crc::crc32_hex;
use log::info;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NandSearchError {
    #[error(transparent)]
    Blocks(#[from] BlocksError),
    #[error(transparent)]
    Builder(#[from] crate::builder::nand::types::BuilderError),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PdLdv {
    pub pd: [u8; 3],
    pub ldv: u8,
    pub stage: String,
}

pub struct NandSearch {
    pub ini: XeBuildIni,
    pub skeleton: NandSkeleton,

    pub bootloaders: HashMap<String, Vec<u8>>,
    pub keyvault: Vec<u8>,
    pub fcrt: Option<Vec<u8>>,
    pub smc_config: Vec<u8>,
    pub flashfs_assets: HashMap<String, Vec<u8>>,
    pub mobile: MobileStore,

    pub cf_0: Option<PdLdv>,
    pub cf_1: Option<PdLdv>,
    pub cb: Option<PdLdv>,
}

fn normalize_optional_hash(hash: &Option<String>) -> Option<&str> {
    hash.as_deref().and_then(|h| {
        let s = h.trim();
        if s.is_empty()
            || s.eq_ignore_ascii_case("skip")
            || s.eq_ignore_ascii_case("none")
            || s == "0"
            || s == "00000000"
        {
            None
        } else {
            Some(s)
        }
    })
}

fn hash_match_xebuild_style(data: &[u8], filename: &str, expected: &Option<String>) -> bool {
    if bootloader_matches_expected_name(filename, data).is_err() {
        return false;
    }
    let Some(exp) = normalize_optional_hash(expected) else {
        return true;
    };
    let actual = get_xebuild_crc32(data, filename);
    actual.eq_ignore_ascii_case(exp)
}

fn hash_match_simple(data: &[u8], expected: &Option<String>) -> bool {
    let Some(exp) = normalize_optional_hash(expected) else {
        return true;
    };
    let actual = crc32_hex(data);
    actual.eq_ignore_ascii_case(exp)
}

impl NandSearch {
    pub fn new(ini: XeBuildIni, nand_image: &[u8], cpukey: [u8; 16]) -> Result<Self, NandSearchError> {
        let (clean_data, layout, lba_map) = NandProcessor::preprocess_nand_with_lba_options(nand_image, true)?;

        let flashfs = FlashFS::scan_physical_with_lba(nand_image, &layout, &lba_map);
        let mobile = MobileStore::scan_physical(nand_image, &layout);

        let mut skeleton = NandSkeleton::parse_clean(clean_data, layout, cpukey, flashfs)?;
        skeleton.mobile = Some(mobile.clone());
        skeleton.extra.lba_map = lba_map;

        let mut bootloaders: HashMap<String, Vec<u8>> = HashMap::new();

        for entry in &ini.main {
            let filename = &entry.filename;
            let lower = filename.to_lowercase();
            if lower == "none" {
                continue;
            }

            let data_opt: Option<Vec<u8>> = if lower.starts_with("cba") {
                skeleton.bootloaders.cb_a.as_ref().map(|b| b.serialize())
            } else if lower.starts_with("cbb") {
                skeleton.bootloaders.cb_b.as_ref().map(|b| b.serialize())
            } else if lower.starts_with("cbx") {
                skeleton.bootloaders.cb_x.as_ref().map(|b| b.serialize())
            } else if lower.starts_with("cb") || lower.starts_with("sb") {
                if skeleton.bootloaders.cb_a.is_some() {
                    skeleton.bootloaders.cb_a.as_ref().map(|b| b.serialize())
                } else {
                    skeleton.bootloaders.cb.as_ref().map(|b| b.serialize())
                }
            } else if lower.starts_with("sc") {
                skeleton.bootloaders.sc.as_ref().map(|b| b.serialize())
            } else if lower.starts_with("cd") || lower.starts_with("sd") {
                skeleton.bootloaders.cd.as_ref().map(|b| b.serialize())
            } else if lower.starts_with("ce") || lower.starts_with("se") {
                skeleton.bootloaders.ce.as_ref().map(|b| b.serialize())
            } else if lower.starts_with("cf_") || lower.starts_with("sf_") {
                let upd = skeleton.update.as_ref();
                if entry.chain == 0 {
                    upd.and_then(|u| u.cf_0.as_ref()).map(|b| b.serialize())
                } else {
                    upd.and_then(|u| u.cf_1.as_ref()).map(|b| b.serialize())
                }
            } else if lower.starts_with("cg_") || lower.starts_with("sg_") {
                let upd = skeleton.update.as_ref();
                if entry.chain == 0 {
                    upd.and_then(|u| u.cg_0.as_ref()).map(|b| b.serialize())
                } else {
                    upd.and_then(|u| u.cg_1.as_ref()).map(|b| b.serialize())
                }
            } else {
                None
            };

            if let Some(data) = data_opt {
                if hash_match_xebuild_style(&data, filename, &entry.hash) {
                    bootloaders.insert(lower, data);
                }
            }
        }

        let mut flashfs_assets: HashMap<String, Vec<u8>> = HashMap::new();
        if !ini.flashfs.is_empty() {
            if let Some(flashfs) = skeleton.flashfs.as_ref() {
                for entry in &ini.flashfs {
                    let basename = strip_flashfs_path_indicator(&entry.filename);
                    let lower_basename = basename.to_lowercase();
                    if lower_basename == "sysupdate.xexp1" || lower_basename == "sysupdate.xexp2" {
                        continue;
                    }

                    let candidates = [
                        lower_basename.clone(),
                        format!("{}1", lower_basename),
                        format!("{}2", lower_basename),
                    ];

                    let mut matched: Option<Vec<u8>> = None;
                    for cand in &candidates {
                        if let Some(n_entry) = flashfs
                            .root
                            .entries
                            .iter()
                            .find(|e| !e.deleted && e.file_name.eq_ignore_ascii_case(cand))
                        {
                            let data = n_entry.data.clone();
                            if hash_match_simple(&data, &entry.hash) {
                                matched = Some(data);
                                break;
                            }
                        }
                    }

                    if let Some(data) = matched {
                        flashfs_assets.insert(lower_basename, data);
                    }
                }
            }
        }

        let keyvault = skeleton.extra.keyvault.clone();
        let fcrt = skeleton
            .flashfs
            .as_ref()
            .and_then(|f| {
                f.root
                    .entries
                    .iter()
                    .find(|e| !e.deleted && e.file_name.eq_ignore_ascii_case("fcrt.bin"))
                    .map(|e| e.data.clone())
            });
        let smc_config = skeleton.extra.smc_config.clone();

        let cb = {
            if let Some(cb_b) = skeleton.bootloaders.cb_b.as_mut() {
                cb_b.populate_metadata_unchecked();
                cb_b.metadata.as_ref().map(|m| PdLdv {
                    pd: m.pairing_data,
                    ldv: m.lockdown_value,
                    stage: "CB_B".to_string(),
                })
            } else if let Some(cb_a) = skeleton.bootloaders.cb_a.as_mut() {
                cb_a.populate_metadata_unchecked();
                cb_a.metadata.as_ref().map(|m| PdLdv {
                    pd: m.pairing_data,
                    ldv: m.lockdown_value,
                    stage: "CB_A".to_string(),
                })
            } else if let Some(cb) = skeleton.bootloaders.cb.as_mut() {
                cb.populate_metadata_unchecked();
                cb.metadata.as_ref().map(|m| PdLdv {
                    pd: m.pairing_data,
                    ldv: m.lockdown_value,
                    stage: "CB".to_string(),
                })
            } else {
                None
            }
        };

        let (cf_0, cf_1) = {
            let upd = skeleton.update.as_mut();
            let mut slot0: Option<PdLdv> = None;
            let mut slot1: Option<PdLdv> = None;

            if let Some(u) = upd {
                if let Some(cf0) = u.cf_0.as_mut() {
                    cf0.populate_metadata_unchecked();
                    slot0 = cf0.metadata.as_ref().map(|m| PdLdv {
                        pd: m.pairing_data,
                        ldv: m.lockdown_value,
                        stage: "CF_0".to_string(),
                    });
                }
                if let Some(cf1) = u.cf_1.as_mut() {
                    cf1.populate_metadata_unchecked();
                    slot1 = cf1.metadata.as_ref().map(|m| PdLdv {
                        pd: m.pairing_data,
                        ldv: m.lockdown_value,
                        stage: "CF_1".to_string(),
                    });
                }
            }

            (slot0, slot1)
        };

        info!(
            "[nand] Search complete: {} bootloader asset(s), {} flashfs asset(s)",
            bootloaders.len(),
            flashfs_assets.len()
        );

        Ok(Self {
            ini,
            skeleton,
            bootloaders,
            keyvault,
            fcrt,
            smc_config,
            flashfs_assets,
            mobile,
            cf_0,
            cf_1,
            cb,
        })
    }
}
