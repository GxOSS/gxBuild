use crate::builder::builder::NandSkeleton;
use crate::builder::parser::hex_to_bytes;
use crate::builder::types::{layout_calculator, SouthbridgeType};
use crate::core::data::filesearch::IniSearch;
use crate::core::images::gxpatch::parse_patch_binary;
use crate::core::session::InternalCommand;
use crate::core::session::{QueuedCommand, Session};
use log::{error, info, warn};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BuildMode {
    Normal,
    Xell,
    Shadowboot,
    Devkit,
}

pub struct Executor {}

impl Executor {
    fn fallback_pairing_data() -> [u8; 3] {
        [0, 0, 1]
    }

    fn fallback_lockdown_value() -> u8 {
        1
    }

    /// Resolves the pairing data: CB-priority, CF fallback, then [0,0,1].
    fn resolve_pairing(
        _options: &crate::core::data::optini::OptionsIni,
        nand: &NandSkeleton,
    ) -> [u8; 3] {
        nand.bootloaders
            .cb_a
            .as_ref()
            .or(nand.bootloaders.cb.as_ref())
            .and_then(|cb| cb.metadata.as_ref().map(|meta| meta.pairing_data))
            .or_else(|| {
                nand.update
                    .cf_0
                    .as_ref()
                    .and_then(|cf| cf.metadata.as_ref().map(|meta| meta.pairing_data))
            })
            .filter(|p| *p != [0, 0, 0])
            .unwrap_or_else(Self::fallback_pairing_data)
    }

    fn resolve_cb_ldv(
        _options: &crate::core::data::optini::OptionsIni,
        nand: &NandSkeleton,
    ) -> Result<u8, String> {
        let from_nand = nand
            .bootloaders
            .cb_a
            .as_ref()
            .or(nand.bootloaders.cb.as_ref())
            .and_then(|cb| cb.metadata.as_ref().map(|meta| meta.lockdown_value))
            .filter(|v| *v != 0);

        Ok(from_nand.unwrap_or_else(Self::fallback_lockdown_value))
    }

    fn resolve_cf_ldv(
        options: &crate::core::data::optini::OptionsIni,
        nand: &NandSkeleton,
    ) -> Result<u8, String> {
        if let Some(cfldv_option) = &options.keys.cfldv {
            return Self::parse_u8_hex_or_dec(cfldv_option);
        }

        let from_nand = nand
            .update
            .cf_0
            .as_ref()
            .and_then(|cf| cf.metadata.as_ref().map(|meta| meta.lockdown_value))
            .filter(|v| *v != 0);

        Ok(from_nand.unwrap_or_else(Self::fallback_lockdown_value))
    }

    fn sync_per_box_settings(nand: &mut NandSkeleton, pairing: [u8; 3], cb_ldv: u8, cf_ldv: u8) {
        if let Some(ref mut cb) = nand.bootloaders.cb {
            if let Some(ref mut meta) = cb.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = cb_ldv;
                cb.sync_metadata();
            }
        }

        if let Some(ref mut cb) = nand.bootloaders.cb_a {
            if let Some(ref mut meta) = cb.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = cb_ldv;
                cb.sync_metadata();
            }
        }

        if let Some(ref mut cb) = nand.bootloaders.cb_b {
            if let Some(ref mut meta) = cb.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = cb_ldv;
                cb.sync_metadata();
            }
        }

        if let Some(ref mut cf) = nand.update.cf_0 {
            if let Some(ref mut meta) = cf.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = cf_ldv;
                cf.sync_metadata();
            } else {
                if cf.data.len() > 0x20E {
                    cf.data[0x20C..0x20F].copy_from_slice(&pairing);
                }
                if cf.data.len() > 0x20F {
                    cf.data[0x20F] = cf_ldv;
                }
            }
        }

        if let Some(ref mut cf) = nand.update.cf_1 {
            if let Some(ref mut meta) = cf.metadata {
                meta.pairing_data = pairing;
                meta.lockdown_value = cf_ldv;
                cf.sync_metadata();
            } else {
                if cf.data.len() > 0x20E {
                    cf.data[0x20C..0x20F].copy_from_slice(&pairing);
                }
                if cf.data.len() > 0x20F {
                    cf.data[0x20F] = cf_ldv;
                }
            }
        }
    }

    pub fn prepare_build(session: &mut crate::core::session::Session) -> Result<(), String> {
        use std::collections::HashSet;

        let ini_dir = session
            .ini_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        let data_dir = session
            .data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("mydata"));
        let common_dir = session
            .common_dir
            .clone()
            .unwrap_or_else(|| ini_dir.join("../common"));
        let payloads_dir = ini_dir.join("../payloads");
        let smc_dir = ini_dir.join("../smc");
        let output_path = session
            .output_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("updflash.bin"));

        // Load options.ini from the data dir FIRST, then merge user overrides
        let options_path = data_dir.join("options.ini");
        if options_path.exists() {
            if let Ok(content) = fs::read_to_string(&options_path) {
                match crate::core::data::optini::parse_options_ini(&content) {
                    Ok(disk_opts) => {
                        let user_opts = session.options.clone();
                        session.options = disk_opts;
                        session.options.merge(user_opts);
                    }
                    Err(e) => warn!(
                        "[session] prepare_build: failed to parse options.ini: {}",
                        e
                    ),
                }
            }
        }

        // Initialize or update logger level based on FINAL merged options
        let is_verbose = session.options.core.verbose.unwrap_or(false);
        let _ = crate::core::logger::init_logger("build", is_verbose);

        if let Some(nand) = &mut session.active_nand {
            nand.options.gxunsafe = session.options.core.gxunsafe.unwrap_or(false);
            nand.options.verbose = session.options.core.verbose.unwrap_or(false);
        }

        let build_type = session
            .build_type
            .clone()
            .ok_or("prepare_build: build_type not set")?;
        let console = session
            .console_type
            .clone()
            .ok_or("prepare_build: console_type not set")?;

        // Resolve INI filename: _<type>[_<ext>].ini
        let ini_suffix = session
            .ini_ext
            .as_ref()
            .map(|e| format!("_{}", e))
            .unwrap_or_default();
        let ini_filename = format!("_{}{}.ini", build_type, ini_suffix);
        let ini_path = ini_dir.join(&ini_filename);

        // Console section, e.g. "trinity" or "trinity_ext"
        let console_section = match &session.bl_ext {
            Some(ext) => format!("{}_{}", console, ext),
            None => console.clone(),
        };

        // Pre-parse INI to know which asset filenames we need
        let mut target_filenames: HashSet<String> = HashSet::new();
        if !session.build_ini_loaded {
            match crate::core::data::xeini::parse_xe_ini(&ini_path, &console_section) {
                Ok(ini) => {
                    for e in ini.main {
                        target_filenames.insert(e.filename.to_lowercase());
                    }
                    for e in ini.security {
                        target_filenames.insert(e.filename.to_lowercase());
                    }
                    for e in ini.flashfs {
                        target_filenames.insert(e.filename.to_lowercase());
                    }
                }
                Err(_) => return Err(format!("prepare_build: cannot read INI at {:?}", ini_path)),
            }
        }

        info!(
            "[session] prepare_build | type={} console={} section={}",
            build_type, console, console_section
        );
        info!(
            "[session] prepare_build | ini_dir={:?}  data_dir={:?}  common={:?}",
            ini_dir, data_dir, common_dir
        );

        // Enqueue FinalizeFlashfs / FinalizeMobile early (priority ordering handles sequencing)
        session.enqueue(InternalCommand::FinalizeFlashfs);
        session.enqueue(InternalCommand::FinalizeMobile);

        // Build the search path list: ini â†’ ini/flashfs â†’ ini/data â†’ common
        let ini_flashfs = ini_dir.join("flashfs");
        let ini_data = ini_dir.join("data");
        let mut search_dirs: Vec<PathBuf> = vec![ini_dir.clone()];
        if ini_flashfs.is_dir() {
            search_dirs.push(ini_flashfs);
        }
        if ini_data.is_dir() {
            search_dirs.push(ini_data);
        }
        if common_dir.is_dir() {
            search_dirs.push(common_dir.clone());
        }

        // Discover INI assets
        let mut cf_found = false;
        let mut cg_found = false;
        for filename in &target_filenames {
            for dir in &search_dirs {
                let candidate = dir.join(filename);
                if candidate.exists() {
                    session.enqueue(InternalCommand::Update { path: candidate });
                    if filename.starts_with("cf_") {
                        cf_found = true;
                    }
                    if filename.starts_with("cg_") {
                        cg_found = true;
                    }
                    break;
                }
            }
        }

        // CF/CG fallback: xboxupd.bin or su*** containers
        if !cf_found || !cg_found {
            let xboxupd = ini_dir.join("xboxupd.bin");
            if xboxupd.exists() {
                session.enqueue(InternalCommand::Update { path: xboxupd });
            } else if let Ok(entries) = fs::read_dir(&ini_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        let name = p
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_lowercase();
                        if name.starts_with("su") {
                            session.enqueue(InternalCommand::Update { path: p });
                        }
                    }
                }
            }
        }

        // NAND image (data dir)
        let nand_needed = session.active_nand.is_none();

        if nand_needed {
            let nand_candidates = [
                data_dir.join("nanddump.bin"),
                data_dir.join("nanddump1.bin"),
                data_dir.join("nanddump2.bin"),
                data_dir.join("nanddump.ecc"),
                data_dir.join("nanddump1.ecc"),
                data_dir.join("nanddump2.ecc"),
                data_dir.join("updflash.bin"),
                data_dir.join("updflash.ecc"),
            ];
            let mut nand_found = false;
            for p in &nand_candidates {
                if p.exists() {
                    session.enqueue(InternalCommand::ParseImage {
                        path: p.clone(),
                        key: None,
                    });
                    nand_found = true;
                    break;
                }
            }
            if !nand_found {
                // No source NAND: create a blank image based on console layout
                let layout = match console.as_str() {
                    "xenon" => crate::core::images::blocks::NandLayout::Xsb,
                    "jasper256" | "jasper512" | "jasperbb" | "jasperbigffs" | "trinitybigffs" => {
                        crate::core::images::blocks::NandLayout::Bb
                    }
                    "corona4g" | "winchester" => crate::core::images::blocks::NandLayout::Emmc,
                    _ => crate::core::images::blocks::NandLayout::Sb,
                };
                session.enqueue(InternalCommand::CreateImage { layout });
            }
        }

        // CPU key (cpukey.txt / cpukey.bin in data dir)
        if session.pending_key.is_none() && session.options.keys.cpukey.is_none() {
            let key_txt = data_dir.join("cpukey.txt");
            let key_bin = data_dir.join("cpukey.bin");
            if key_bin.exists() {
                if let Ok(bytes) = fs::read(&key_bin) {
                    if bytes.len() >= 16 {
                        let mut k = [0u8; 16];
                        k.copy_from_slice(&bytes[..16]);
                        session.parse_keybin(Some(k));
                    }
                }
            } else if key_txt.exists() {
                if let Ok(text) = fs::read_to_string(&key_txt) {
                    let clean = text.trim();
                    if clean.len() >= 32 {
                        session.set_cpukey(clean.to_string());
                    }
                }
            }
        }

        // Security assets from data dir
        for name in &[
            "smc.bin",
            "smc_config.bin",
            "fcrt.bin",
            "kv.bin",
            "keyvault.bin",
        ] {
            if name == &"fcrt.bin" && session.options.core_builder.nofcrt.unwrap_or(false) {
                continue;
            }
            let p = data_dir.join(name);
            if p.exists() {
                if let Ok(data) = fs::read(&p) {
                    session.pending_assets.insert(name.to_string(), data);
                }
            }
        }

        // Enqueue INI parsing (Only if not already loaded via string)
        if !session.build_ini_loaded {
            session.parse_ini(
                &ini_path,
                console_section,
                &ini_dir,
                &common_dir,
                &data_dir,
                &payloads_dir,
                &smc_dir,
            );
        }

        // Addon patches
        let addons = session.addons.clone();
        for addon in &addons {
            let addon_path = if PathBuf::from(addon).is_absolute() {
                PathBuf::from(addon)
            } else {
                let p = ini_dir.join(addon);
                if p.exists() {
                    p
                } else {
                    data_dir.join(addon)
                }
            };
            if addon_path.exists() {
                session.enqueue(InternalCommand::ApplyPatch {
                    path: addon_path,
                    ptype: 2,
                    target: None,
                });
            } else {
                warn!("[session] prepare_build: addon not found: {}", addon);
            }
        }

        // Final build command
        session.build(output_path, 0);

        Ok(())
    }

    /// Pulls defaults from NAND into session options.
    pub fn extract_options_from_nand(session: &mut Session) {
        if let Some(nand) = &mut session.active_nand {
            info!("[session] Extracting hardware defaults from active NAND image...");

            // CPU Key
            if session.options.keys.cpukey.is_none() {
                if let Some(key) = nand.cpukey {
                    session.options.keys.cpukey =
                        Some(key.iter().map(|b| format!("{:02x}", b)).collect());
                }
            }

            // Motherboard / Console Type mapping
            if session.options.keys.ctype.is_none() {
                session.options.keys.ctype =
                    Some(format!("{:?}", nand.options.motherboard).to_lowercase());
            }

            if session.options.keys.cfldv.is_none() {
                if let Ok(ldv) = Self::resolve_cf_ldv(&session.options, nand) {
                    session.options.keys.cfldv = Some(ldv.to_string());
                }
            }

            // Keyvault Metadata
            if let Some(ref mut kv) = nand.kv {
                if !kv.is_decrypted {
                    let cpukey = nand.cpukey.unwrap_or([0u8; 16]);
                    if let Err(e) = kv.decrypt(&cpukey) {
                        warn!(
                            "[session] Failed to decrypt Keyvault for metadata extraction: {}",
                            e
                        );
                    }
                }

                if let Some(meta) = &kv.metadata {
                    if session.options.keyvault.gameregion.is_none() {
                        session.options.keyvault.gameregion = Some(format!("0x{:04X}", meta.region));
                    }
                    if session.options.keyvault.dvdkey.is_none() {
                        session.options.keyvault.dvdkey =
                            Some(meta.dvd_key.iter().map(|b| format!("{:02x}", b)).collect());
                    }
                }
            }
        }
    }

    /// Pushes the final merged session options back into the NAND skeleton's
    /// Keyvault and SMC buffers before a build.
    pub fn sync_options_to_nand(session: &mut Session) -> Result<(), String> {
        if let Some(nand) = &mut session.active_nand {
            info!("[session] Syncing merged options to NAND components...");

            if let Some(noremap) = session.options.core_builder.noremap {
                nand.options.noremap = noremap;
            }

            nand.options.core.gxunsafe = session.options.core.gxunsafe.unwrap_or(false);
            nand.options.core.verbose = session.options.core.verbose.unwrap_or(false);
            nand.options.core_builder.nomobile = session.options.core_builder.nomobile.unwrap_or(false);
            nand.options.core_builder.nofcrt = session.options.core_builder.nofcrt.unwrap_or(false);
            nand.options.core_builder.dualpatchslots = session.options.core_builder.dualpatchslots.unwrap_or(false);
            nand.options.jtag.cygnos = session.options.jtag.cygnos.unwrap_or(false);
            nand.options.jtag.demon = session.options.jtag.demon.unwrap_or(false);

            //  CPU Key
            if let Some(key_str) = &session.options.keys.cpukey {
                if let Ok(key_bytes) = hex_to_bytes(key_str) {
                    if key_bytes.len() == 16 {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&key_bytes);
                        nand.cpukey = Some(arr);
                    }
                }
            }

            let cpukey = nand.cpukey.unwrap_or([0u8; 16]);

            //  Per-box LDV / Pairing Sync for CB + CF (independent)
            let pairing = Self::resolve_pairing(&session.options, nand);
            let cb_ldv = Self::resolve_cb_ldv(&session.options, nand)?;
            let cf_ldv = Self::resolve_cf_ldv(&session.options, nand)?;
            Self::sync_per_box_settings(nand, pairing, cb_ldv, cf_ldv);

            //  Keyvault Overrides (Region, DVD Key)
            if let Some(ref mut kv) = nand.kv {
                // Decrypt with current session key if possible
                if !kv.is_decrypted {
                    if let Err(e) = kv.decrypt(&cpukey) {
                        warn!(
                            "[session] Failed to decrypt Keyvault for option patching: {}",
                            e
                        );
                    }
                }

                if kv.is_decrypted {
                    if let Some(dvdkey_str) = &session.options.dvdkey {
                        if let Ok(key_bytes) = hex_to_bytes(dvdkey_str) {
                            if key_bytes.len() == 16 {
                                let mut arr = [0u8; 16];
                                arr.copy_from_slice(&key_bytes);
                                kv.set_dvd_key(&arr)?;
                            }
                        }
                    }

                    if let Some(region_str) = &session.options.gameregion {
                        let region = Self::parse_u16_hex_or_dec(region_str)?;
                        kv.set_region(region)?;
                    }

                    if let Some(serial) = &session.options.serial {
                        kv.set_serial(serial)?;
                    }

                    if let Some(osig) = &session.options.osig {
                        kv.set_osig(osig)?;
                    }

                    if let Some(mfdate) = &session.options.mfdate {
                        kv.set_mf_date(mfdate)?;
                    }

                    if let Some(cid_str) = &session.options.consoleid {
                        if let Ok(bytes) = hex_to_bytes(cid_str) {
                            if bytes.len() == 5 {
                                let mut arr = [0u8; 5];
                                arr.copy_from_slice(&bytes);
                                kv.set_console_id(&arr)?;
                            }
                        }
                    }

                    // Re-encrypt and store Keyvault
                    kv.encrypt(&cpukey)?;
                    nand.extra.keyvault = kv.data.clone();
                }
            }

            // SMC Configuration Patching
            let mut smc_config = if nand.extra.smc_config.is_empty() {
                info!("[session] No SMC Config found in skeleton, initializing clean defaults.");
                crate::builder::chain::smc::SmcConfig::new_empty()
            } else {
                crate::builder::chain::smc::SmcConfig::parse(&nand.extra.smc_config)?
            };

            // MAC Address
            if let Some(mac_str) = &session.options.macid {
                let clean_mac = mac_str.replace(":", "");
                if let Ok(bytes) = hex_to_bytes(&clean_mac) {
                    if bytes.len() == 6 {
                        let mut arr = [0u8; 6];
                        arr.copy_from_slice(&bytes);
                        smc_config.set_mac_address(&arr);
                    }
                }
            }

            // Regions (SMC sync)
            let video = if let Some(s) = &session.options.avregion {
                Self::parse_u16_hex_or_dec(s)?
            } else {
                (smc_config.data[0x22A] as u16) << 8 | smc_config.data[0x22B] as u16
            };
            let game = if let Some(s) = &session.options.gameregion {
                Self::parse_u16_hex_or_dec(s)?
            } else {
                (smc_config.data[0x22C] as u16) << 8 | smc_config.data[0x22D] as u16
            };
            let dvd = if let Some(s) = &session.options.dvdregion {
                s.parse::<u8>().unwrap_or(0xFF)
            } else {
                smc_config.data[0x237]
            };
            smc_config.set_regions(video, game, dvd);

            // Thermals (Targets)
            let cpu_t = if let Some(s) = &session.options.cputemp {
                Self::parse_u8_hex_or_dec(s)?
            } else {
                smc_config.data[0x29]
            };
            let gpu_t = if let Some(s) = &session.options.gputemp {
                Self::parse_u8_hex_or_dec(s)?
            } else {
                smc_config.data[0x2A]
            };
            let ram_t = if let Some(s) = &session.options.edramtemp {
                Self::parse_u8_hex_or_dec(s)?
            } else {
                smc_config.data[0x2B]
            };
            smc_config.set_thermal_targets(cpu_t, gpu_t, ram_t);

            // Thermals (Max/Limits)
            let cpu_m = if let Some(s) = &session.options.overcputemp {
                Self::parse_u8_hex_or_dec(s)?
            } else {
                smc_config.data[0x2C]
            };
            let gpu_m = if let Some(s) = &session.options.overgputemp {
                Self::parse_u8_hex_or_dec(s)?
            } else {
                smc_config.data[0x2D]
            };
            let ram_m = if let Some(s) = &session.options.overedramtemp {
                Self::parse_u8_hex_or_dec(s)?
            } else {
                smc_config.data[0x2E]
            };
            smc_config.set_thermal_limits(cpu_m, gpu_m, ram_m);

            //  Fans
            if let Some(s) = &session.options.cpufan {
                let speed = Self::parse_u8_hex_or_dec(s)?;
                smc_config.set_fan_speed(false, speed != 0, speed);
            }
            if let Some(s) = &session.options.gpufan {
                let speed = Self::parse_u8_hex_or_dec(s)?;
                smc_config.set_fan_speed(true, speed != 0, speed);
            }

            // 3f. Reset/XeLL Buttons
            if let Some(s) = &session.options.xellbutton {
                if s.len() == 4 {
                    smc_config.set_reset_code(s.as_bytes().try_into().unwrap());
                }
            }

            // Finalize and store SMC Config
            nand.extra.smc_config = smc_config.serialize().clone().to_vec();

            // SMC image
            let mut smc = crate::builder::chain::smc::RawSmc::new(nand.extra.smc.clone());
            smc.ensure_decrypted();

            let profile_l = nand.options.image_profile.to_ascii_lowercase();
            let auto_patch_smc = matches!(profile_l.as_str(), "glitch" | "glitch1" | "glitch2");
            if auto_patch_smc {
                let ini_dir = session
                    .ini_dir
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("."));
                let patch_path = ini_dir.join("../smc/bin/glitch.json");
                match fs::read_to_string(&patch_path) {
                    Ok(json) => {
                        let mut count = crate::core::images::signature::Signature::apply_batch(
                            &mut smc.data,
                            &json,
                        )
                        .map_err(|e| {
                            format!("SMC autopatching failed ({}): {:?}", e, patch_path)
                        })?;
                        if count == 0 {
                            let mut retry =
                                crate::builder::chain::smc::RawSmc::new(smc.data.clone());
                            retry.force_decrypt();
                            let retry_count =
                                crate::core::images::signature::Signature::apply_batch(
                                    &mut retry.data,
                                    &json,
                                )
                                .map_err(|e| {
                                    format!("SMC autopatching failed ({}): {:?}", e, patch_path)
                                })?;
                            if retry_count > 0 {
                                smc.data = retry.data;
                                count = retry_count;
                            }
                        }
                        if count > 0 {
                            info!(
                                "[session] SMC autopatching applied: {} match(es) from {:?}",
                                count, patch_path
                            );
                        } else {
                            info!(
                                "[session] SMC autopatching: 0 matches from {:?}",
                                patch_path
                            );
                        }
                    }
                    Err(_) => warn!(
                        "[session] SMC autopatching patch file missing: {:?}",
                        patch_path
                    ),
                }
            }
            nand.extra.smc = smc.data;
        }
        Ok(())
    }

    /// Applies a batch of signature patches (JSON format) to the active NAND's decrypted SMC.
    /// Returns the total number of patches applied.
    pub fn apply_smc_signature_batch(
        session: &mut crate::core::session::Session,
        json_str: &str,
    ) -> Result<usize, String> {
        if let Some(nand) = &mut session.active_nand {
            info!("[session] Applying signature batch to SMC...");
            let mut smc = crate::builder::chain::smc::RawSmc::new(nand.extra.smc.clone());
            smc.ensure_decrypted();

            let count =
                crate::core::images::signature::Signature::apply_batch(&mut smc.data, json_str)?;

            nand.extra.smc = smc.data;
            info!(
                "[session] SMC signature batch applied: {} match(es) patched.",
                count
            );
            Ok(count)
        } else {
            Err("No active NAND loaded to patch.".to_string())
        }
    }

    fn parse_u16_hex_or_dec(s: &str) -> Result<u16, String> {
        if s.starts_with("0x") {
            u16::from_str_radix(&s[2..], 16).map_err(|e| format!("Invalid hex u16 '{}': {}", s, e))
        } else {
            s.parse::<u16>()
                .map_err(|e| format!("Invalid decimal u16 '{}': {}", s, e))
        }
    }

    fn parse_u8_hex_or_dec(s: &str) -> Result<u8, String> {
        if s.starts_with("0x") {
            u8::from_str_radix(&s[2..], 16).map_err(|e| format!("Invalid hex u8 '{}': {}", s, e))
        } else {
            s.parse::<u8>()
                .map_err(|e| format!("Invalid decimal u8 '{}': {}", s, e))
        }
    }

    pub fn execute_command(
        session: &mut crate::core::session::Session,
        command: InternalCommand,
    ) -> Result<(), String> {
        match command {
            InternalCommand::ExtractAll {
                output_dir,
                all,
                include_decrypted,
            } => {
                let Some(nand) = &session.active_nand else {
                    error!("[session] No active NAND loaded. Cannot extract.");
                    return Ok(());
                };

                let encrypted_dir = output_dir.join("encrypted");
                let decrypted_dir = output_dir.join("decrypted");
                let _ = fs::create_dir_all(&encrypted_dir);
                if include_decrypted {
                    let _ = fs::create_dir_all(&decrypted_dir);
                }

                let mut ids: Vec<&str> = vec!["kv", "fcrt"];
                if all {
                    ids = vec![
                        "smc", "smcc", "kv", "fcrt", "cb", "cba", "cbx", "cbb", "sc", "cd", "ce",
                        "cf0", "cg0", "cf1", "cg1", "header",
                    ];
                }

                let encrypted_chain = if all {
                    match nand.parse_encrypted_chain() {
                        Ok(v) => Some(v),
                        Err(e) => {
                            error!(
                                "[session] Failed to parse encrypted bootloader chain: {}",
                                e
                            );
                            None
                        }
                    }
                } else {
                    None
                };

                let write_bytes = |dir: &PathBuf, filename: &str, bytes: Vec<u8>| {
                    let full_path = dir.join(filename);
                    if let Some(parent) = full_path.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    if let Err(e) = fs::write(&full_path, bytes) {
                        error!("[session] Failed to write {}: {}", full_path.display(), e);
                    } else {
                        info!("[session] Wrote {}", full_path.display());
                    }
                };

                let extract_encrypted = |id: &str| -> Option<(&'static str, Vec<u8>)> {
                    match id {
                        "smc" => {
                            let off = nand.header.smc_boot_offset.get() as usize;
                            let sz = nand.header.smc_boot_size.get() as usize;
                            if off.checked_add(sz)? <= nand.image.len() {
                                Some(("SMC.bin", nand.image[off..off + sz].to_vec()))
                            } else {
                                None
                            }
                        }
                        "smcc" => {
                            let off = nand.header.smc_config_offset.get() as usize;
                            if off > 0 && off.checked_add(0x10000)? <= nand.image.len() {
                                Some(("SMC_Config.bin", nand.image[off..off + 0x10000].to_vec()))
                            } else if !nand.extra.smc_config.is_empty() {
                                Some(("SMC_Config.bin", nand.extra.smc_config.clone()))
                            } else {
                                None
                            }
                        }
                        "kv" => {
                            let off = nand.header.kv_addr.get() as usize;
                            let sz = nand.header.kv_size.get() as usize;
                            if off.checked_add(sz)? <= nand.image.len() {
                                Some(("KV.bin", nand.image[off..off + sz].to_vec()))
                            } else {
                                None
                            }
                        }
                        "fcrt" => nand.extra.fcrt.clone().map(|b| ("FCRT.bin", b)),
                        "header" => Some((
                            "NandHeader.bin",
                            zerocopy::IntoBytes::as_bytes(&nand.header).to_vec(),
                        )),
                        "cb" => encrypted_chain
                            .as_ref()
                            .and_then(|(bl, _)| bl.cb.as_ref().map(|b| ("CB.bin", b.serialize()))),
                        "cba" => encrypted_chain.as_ref().and_then(|(bl, _)| {
                            bl.cb_a.as_ref().map(|b| ("CBA.bin", b.serialize()))
                        }),
                        "cbx" => encrypted_chain.as_ref().and_then(|(bl, _)| {
                            bl.cb_x.as_ref().map(|b| ("CBX.bin", b.serialize()))
                        }),
                        "cbb" => encrypted_chain.as_ref().and_then(|(bl, _)| {
                            bl.cb_b.as_ref().map(|b| ("CBB.bin", b.serialize()))
                        }),
                        "sc" => encrypted_chain
                            .as_ref()
                            .and_then(|(bl, _)| bl.sc.as_ref().map(|b| ("SC.bin", b.serialize()))),
                        "cd" => encrypted_chain
                            .as_ref()
                            .and_then(|(bl, _)| bl.cd.as_ref().map(|b| ("CD.bin", b.serialize()))),
                        "ce" => encrypted_chain
                            .as_ref()
                            .and_then(|(bl, _)| bl.ce.as_ref().map(|b| ("CE.bin", b.serialize()))),
                        "cf0" => encrypted_chain.as_ref().and_then(|(_, up)| {
                            up.cf_0.as_ref().map(|b| ("CF_0.bin", b.serialize()))
                        }),
                        "cg0" => encrypted_chain.as_ref().and_then(|(_, up)| {
                            up.cg_0.as_ref().map(|b| ("CG_0.bin", b.serialize()))
                        }),
                        "cf1" => encrypted_chain.as_ref().and_then(|(_, up)| {
                            up.cf_1.as_ref().map(|b| ("CF_1.bin", b.serialize()))
                        }),
                        "cg1" => encrypted_chain.as_ref().and_then(|(_, up)| {
                            up.cg_1.as_ref().map(|b| ("CG_1.bin", b.serialize()))
                        }),
                        _ => None,
                    }
                };

                let extract_decrypted = |id: &str| -> Option<(&'static str, Vec<u8>)> {
                    match id {
                        "smc" => Some(("SMC.bin", nand.extra.smc.clone())),
                        "smcc" => Some(("SMC_Config.bin", nand.extra.smc_config.clone())),
                        "kv" => Some(("KV.bin", nand.extra.keyvault.clone())),
                        "fcrt" => nand.extra.fcrt.clone().map(|b| ("FCRT.bin", b)),
                        "header" => Some((
                            "NandHeader.bin",
                            zerocopy::IntoBytes::as_bytes(&nand.header).to_vec(),
                        )),
                        "cb" => nand
                            .bootloaders
                            .cb
                            .as_ref()
                            .map(|b| ("CB.bin", b.serialize())),
                        "cba" => nand
                            .bootloaders
                            .cb_a
                            .as_ref()
                            .map(|b| ("CBA.bin", b.serialize())),
                        "cbx" => nand
                            .bootloaders
                            .cb_x
                            .as_ref()
                            .map(|b| ("CBX.bin", b.serialize())),
                        "cbb" => nand
                            .bootloaders
                            .cb_b
                            .as_ref()
                            .map(|b| ("CBB.bin", b.serialize())),
                        "sc" => nand
                            .bootloaders
                            .sc
                            .as_ref()
                            .map(|b| ("SC.bin", b.serialize())),
                        "cd" => nand
                            .bootloaders
                            .cd
                            .as_ref()
                            .map(|b| ("CD.bin", b.serialize())),
                        "ce" => nand
                            .bootloaders
                            .ce
                            .as_ref()
                            .map(|b| ("CE.bin", b.serialize())),
                        "cf0" => nand
                            .update
                            .cf_0
                            .as_ref()
                            .map(|b| ("CF_0.bin", b.serialize())),
                        "cg0" => nand
                            .update
                            .cg_0
                            .as_ref()
                            .map(|b| ("CG_0.bin", b.serialize())),
                        "cf1" => nand
                            .update
                            .cf_1
                            .as_ref()
                            .map(|b| ("CF_1.bin", b.serialize())),
                        "cg1" => nand
                            .update
                            .cg_1
                            .as_ref()
                            .map(|b| ("CG_1.bin", b.serialize())),
                        _ => None,
                    }
                };

                info!(
                    "[session] Extracting {} set to '{}' (encrypted{}, decrypted={})...",
                    if all { "full" } else { "minimal" },
                    output_dir.display(),
                    if include_decrypted { "" } else { " only" },
                    include_decrypted
                );

                for id in ids {
                    if let Some((name, bytes)) = extract_encrypted(id) {
                        write_bytes(&encrypted_dir, name, bytes);
                    }
                    if include_decrypted {
                        if let Some((name, bytes)) = extract_decrypted(id) {
                            write_bytes(&decrypted_dir, name, bytes);
                        }
                    }
                }

                info!("[session] Extraction complete.");
            }
            InternalCommand::Build { output, .. } => {
                info!("[session] Building NAND image to '{}'...", output.display());
                // Sync options before build
                Self::sync_options_to_nand(session)?;

                if let Some(nand) = &session.active_nand {
                    let cpukey = nand.cpukey.unwrap_or([0u8; 16]);
                    let layout = nand.layout;

                    let sb_type = SouthbridgeType::from(nand.options.motherboard);
                    let chain_profile = if nand.bootloaders.cb_b.is_some() {
                        "split"
                    } else {
                        "single"
                    };
                    let _ = layout_calculator(sb_type, chain_profile, layout);

                    let meta_type = match nand.options.motherboard {
                        crate::builder::types::MotherboardType::Xenon
                        | crate::builder::types::MotherboardType::Zephyr
                        | crate::builder::types::MotherboardType::Falcon => {
                            crate::core::images::blocks::SpareMetaType::MetaType0
                        }
                        _ => crate::core::images::blocks::SpareMetaType::MetaType1,
                    };

                    if let Some(parent) = output.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }

                    let mut built_nand = nand.clone();
                    match built_nand.build_in_place(cpukey) {
                        Ok(clean_bytes) => {
                            if session.options.noecc.unwrap_or(false) {
                                if let Err(e) = std::fs::write(&output, &clean_bytes) {
                                    error!(
                                        "[session] Failed to write build output to '{}': {}",
                                        output.display(),
                                        e
                                    );
                                    return Err(format!("Failed to write output: {}", e));
                                }
                                info!("[session] Build complete: wrote logical image (noecc) to '{}' (Size: 0x{:X})", output.display(), clean_bytes.len());
                                return Ok(());
                            }

                            let mut fs_meta = std::collections::HashMap::new();
                            let page_count_encoded =
                                if layout == crate::core::images::blocks::NandLayout::Bb {
                                    match nand.layout {
                                        crate::core::images::blocks::NandLayout::Bb => 0x00,
                                        _ => 0x01,
                                    }
                                } else {
                                    0x01
                                };

                            let mut all_partitions = std::collections::HashMap::new();
                            if !built_nand.flashfs.root.entries.is_empty() {
                                all_partitions.insert(
                                    built_nand.flashfs.root.partition_type,
                                    built_nand.flashfs.root.clone(),
                                );
                            }

                            for (btype, root) in all_partitions {
                                if root.block_number < 0 {
                                    continue;
                                }

                                // Branding strategy: Every block in the FlashFS partition must have
                                // the correct partition type (e.g. 0x30) and version sequence in its spare area.
                                let fs_start = root.block_number as usize;
                                let reserve_start = layout.reserve_start(clean_bytes.len());
                                for (val, &block) in root.block_map.iter().enumerate() {
                                    if val < fs_start || val >= reserve_start {
                                        continue;
                                    }
                                    // 0x1FFE is the only marker for a truly 'free' block in the block map.
                                    // All other values (including 0 and 0x1FFF) represent occupied space.
                                    let is_free = (block & 0x7FFF) == 0x1FFE;

                                    if !is_free {
                                        let absolute_block = val;
                                        let is_root =
                                            absolute_block == (root.block_number as usize);

                                        // Branding: Root block gets the partition type (0x30, 0x31, etc.)
                                        // Data blocks technically can also carry the partition type for better discovery.
                                        // RGBuild and others advanced by partition type scanning.
                                        let block_type = if is_root { btype } else { 0x01 };

                                        fs_meta.insert(
                                            absolute_block,
                                            crate::core::images::blocks::FsSpareInfo {
                                                sequence: root.version as u32,
                                                size: 0x4000, // Standard 16KB block size (physical)
                                                page_count: page_count_encoded,
                                                block_type,
                                            },
                                        );
                                    }
                                }
                            }

                            let mobile_meta = if session.options.nomobile.unwrap_or(false) {
                                std::collections::HashMap::new()
                            } else {
                                nand.mobile.collect_spare_meta(&layout)
                            };
                            let finalized_bytes =
                                crate::core::images::blocks::NandProcessor::finalize_nand(
                                    &clean_bytes,
                                    layout,
                                    meta_type,
                                    Some(&fs_meta),
                                    if mobile_meta.is_empty() {
                                        None
                                    } else {
                                        Some(&mobile_meta)
                                    },
                                    None,
                                );
                            let final_size = finalized_bytes.len();
                            if let Err(e) = std::fs::write(&output, finalized_bytes) {
                                error!(
                                    "[session] Failed to write build output to '{}': {}",
                                    output.display(),
                                    e
                                );
                                return Err(format!("Failed to write output: {}", e));
                            } else {
                                info!("[session] Build complete: '{}' written ({} bytes, layout {:?})", output.display(), final_size, layout);
                            }
                        }
                        Err(e) => return Err(format!("Build failed: {}", e)),
                    }
                } else {
                    error!("[session] No active NAND loaded to build!");
                }
            }
            InternalCommand::ParseIni {
                path,
                target,
                ini_base,
                common,
                data,
                payloads,
                smc,
            } => {
                info!("[session] Parsing INI for target {}...", target);
                let mut nand_ref = session.active_nand.take();
                if nand_ref.is_none() {
                    return Err("No active NAND skeleton active to apply INI map onto!".to_string());
                }
                match crate::core::data::xeini::parse_xe_ini(&path, &target) {
                    Ok(ini) => {
                        let mut allow: std::collections::HashSet<String> =
                            std::collections::HashSet::new();
                        for fs_entry in &ini.flashfs {
                            let basename = crate::core::data::xeini::strip_flashfs_path_indicator(
                                &fs_entry.filename,
                            );
                            allow.insert(basename.to_lowercase());
                        }
                        for name in &[
                            "fcrt.bin",
                            "crl.bin",
                            "dae.bin",
                            "extended.bin",
                            "secdata.bin",
                            "odd.bin",
                        ] {
                            allow.insert((*name).to_string());
                        }
                        session.flashfs_allowlist =
                            if allow.is_empty() { None } else { Some(allow) };

                        match IniSearch::new(
                            ini.clone(),
                            &ini_base,
                            &common,
                            &data,
                            &payloads,
                            &smc,
                            &nand_ref,
                            session.options.gxunsafe,
                            session.options.nofcrt,
                            session.options.nosecurity,
                            session.options.nosusecurity,
                            session.options.nochainpatch,
                        ) {
                            Ok(search) => {
                                // Route each pool to its typed session pool
                                session
                                    .bootloader_assets
                                    .extend(search.result.bootloader_assets);
                                session
                                    .security_assets
                                    .extend(search.result.security_assets);
                                session.flashfs_assets.extend(search.result.flashfs_assets);

                                // Security files that live in the FlashFS (not at fixed offsets).
                                // Promote them into flashfs_assets so FinalizeFlashfs/build_from_memory
                                // packs them in after a valid block_map exists.
                                for name in &[
                                    "fcrt.bin",
                                    "crl.bin",
                                    "dae.bin",
                                    "extended.bin",
                                    "secdata.bin",
                                    "odd.bin",
                                ] {
                                    if let Some(data) = session.security_assets.get(*name).cloned()
                                    {
                                        session
                                            .flashfs_assets
                                            .entry(name.to_string())
                                            .or_insert(data);
                                    }
                                }

                                // Apply bootloaders using the improved apply_xe_ini
                                let nand = nand_ref.take().unwrap();
                                let pending = crate::core::data::xeini::PendingAssets {
                                    bootloaders: &session.bootloader_assets,
                                    security: &session.security_assets,
                                };
                                match crate::core::data::xeini::apply_xe_ini(nand, ini, pending) {
                                    Ok(updated_nand) => {
                                        session.active_nand = Some(updated_nand);
                                        info!("[session] INI bootloaders and assets applied to NAND skeleton.");
                                    }
                                    Err(e) => {
                                        error!("[session] Failed to apply INI data: {}", e);
                                        return Err(format!("Applied INI data failed: {}", e));
                                    }
                                }
                            }
                            Err(e) => {
                                session.active_nand = nand_ref;
                                error!("[session] Configuration discovery failed: {}", e);
                                return Err(format!("Discovery failed: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        session.active_nand = nand_ref;
                        return Err(format!("Failed parsing INI descriptors: {}", e));
                    }
                }
            }
            InternalCommand::ParseImage { path, key } => {
                info!("[session] Parsing image {:?}...", path);
                match fs::read(&path) {
                    Ok(raw_data) => {
                        // Use preprocess_nand_with_lba to track bad block remapping
                        let remap_bad_blocks = !session.options.noremap.unwrap_or(false);
                        match crate::core::images::blocks::NandProcessor::preprocess_nand_with_lba_options(&raw_data, remap_bad_blocks) {
                            Ok((clean_data, layout, lba_map)) => {
                                info!("[session] Detected {} bad block(s) during preprocessing", lba_map.bad_blocks.len());
                                let active_key = key.or(session.pending_key);

                                // Scan FlashFS with LBA map for accurate block mapping
                                let flashfs = crate::builder::filesystem::flashfs::FlashFS::scan_physical_with_lba(&raw_data, &layout, &lba_map);
                                let mobile = if session.options.nomobile.unwrap_or(false) {
                                    crate::builder::filesystem::mobile::MobileStore::new()
                                } else {
                                    crate::builder::filesystem::mobile::MobileStore::scan_physical(&raw_data, &layout)
                                };
                                let parse_result = match active_key {
                                    Some(k) => NandSkeleton::parse_clean(clean_data, layout, k, flashfs),
                                    None => NandSkeleton::parse_clean_encrypted(clean_data, layout, flashfs),
                                };
                                match parse_result {
                                    Ok(mut nand) => {
                                        nand.mobile = mobile;
                                        // Verify bootloader decryption using zero-region checks
                                        if let Some(cb) = &nand.bootloaders.cb_a {
                                            if cb.verify_decrypted() {
                                                info!("[session] CB_A decryption verified (zero-region check passed).");
                                            } else {
                                                log::warn!("[session] CB_A decryption verification failed - data may be corrupted.");
                                            }
                                        }
                                        for (i, cf_opt) in [&nand.update.cf_0, &nand.update.cf_1].iter().enumerate() {
                                            if let Some(cf) = cf_opt {
                                                if cf.verify_decrypted() {
                                                    info!("[session] CF_{} decryption verified.", i);
                                                } else {
                                                    log::warn!("[session] CF_{} decryption verification failed.", i);
                                                }
                                            }
                                        }
                                        info!("[session] LBA Map: {} total blocks, {} bad blocks remapped", lba_map.logical_to_physical.len(), lba_map.bad_blocks.len());
                                        nand.lba_map = Some(lba_map);
                                        session.active_nand = Some(nand);
                                        Self::extract_options_from_nand(session);
                                        info!("[session] Successfully parsed NAND from {:?} (Layout: {:?})", path, layout);
                                    }
                                    Err(e) => return Err(format!("Failed to interpret clean NAND: {}", e)),
                                }
                            }
                            Err(e) => return Err(format!("Failed to pre-process NAND image: {}", e)),
                        }
                    }
                    Err(e) => {
                        return Err(format!(
                            "Failed to read image file '{}': {}",
                            path.display(),
                            e
                        ))
                    }
                }
            }
            InternalCommand::ApplyEcc { path } => {
                let Some(old) = session.active_nand.take() else {
                    error!("[session] No active NAND loaded. Cannot apply ECC.");
                    return Ok(());
                };

                let ecc_raw = fs::read(&path)
                    .map_err(|e| format!("Failed to read ECC file '{}': {}", path.display(), e))?;

                let (ecc_clean, ecc_layout, _ecc_lba) =
                    crate::core::images::blocks::NandProcessor::preprocess_nand_with_lba_options(
                        &ecc_raw, false,
                    )
                    .map_err(|e| format!("Failed to pre-process ECC image: {}", e))?;

                let nand_layout = old.layout;
                if ecc_layout != nand_layout {
                    session.active_nand = Some(old);
                    return Err(format!("ECC layout mismatch: ECC={:?}, NAND={:?}. Provide a matching ECC for this NAND type.", ecc_layout, nand_layout));
                }

                let mut image = old.image;
                let write_len = std::cmp::min(image.len(), ecc_clean.len());
                image[..write_len].copy_from_slice(&ecc_clean[..write_len]);

                let flashfs = old.flashfs.clone();
                let layout = old.layout;
                let cpukey = old.cpukey;
                let lba_map = old.lba_map;
                let options = old.options;
                let mobile = old.mobile;
                let corona_fs = old.corona_fs;

                let parse_result = match cpukey {
                    Some(k) => NandSkeleton::parse_clean(image, layout, k, flashfs),
                    None => NandSkeleton::parse_clean_encrypted(image, layout, flashfs),
                };

                match parse_result {
                    Ok(mut nand) => {
                        nand.cpukey = cpukey;
                        nand.lba_map = lba_map;
                        nand.options = options;
                        nand.mobile = mobile;
                        nand.corona_fs = corona_fs;
                        session.active_nand = Some(nand);
                        info!(
                            "[session] Applied ECC from '{}' over {} bytes.",
                            path.display(),
                            write_len
                        );
                    }
                    Err(e) => {
                        return Err(format!("Applied ECC but failed to re-parse NAND: {}", e));
                    }
                }
            }
            InternalCommand::ParseKey { key } => {
                session.pending_key = Some(key);
                if let Some(nand) = &mut session.active_nand {
                    nand.cpukey = Some(key);
                    info!("[session] CPU Key assigned to active NAND.");
                } else {
                    info!("[session] CPU Key buffered (awaiting NAND image).");
                }
            }
            InternalCommand::ParseKeybin { key } => {
                if let Some(k) = key {
                    session.pending_key = Some(k);
                    if let Some(nand) = &mut session.active_nand {
                        nand.cpukey = Some(k);
                        info!("[session] CPU Keybin assigned to active NAND.");
                    } else {
                        info!("[session] CPU Keybin buffered (awaiting NAND image).");
                    }
                } else {
                    error!("[session] No key provided in keybin.");
                }
            }
            InternalCommand::ParseFlashfs { path } => {
                info!(
                    "[session] Preparing to build flashfs from folder {:?}...",
                    path
                );
                if let Some(nand) = &mut session.active_nand {
                    let fs_start: u16 = match nand.layout {
                        crate::core::images::blocks::NandLayout::Bb => 0x1E0,
                        crate::core::images::blocks::NandLayout::Emmc => {
                            crate::builder::filesystem::corona::default_emmc_fs_block(
                                nand.header.fs_addr.get(),
                                &nand.corona_fs,
                            )
                        }
                        _ => {
                            let sb: crate::builder::types::SouthbridgeType =
                                nand.options.motherboard.into();
                            let chain_profile = if nand.bootloaders.cb_b.is_some() {
                                "split"
                            } else {
                                "single"
                            };
                            let (_, _, phys_fs_block) = crate::builder::types::layout_calculator(
                                sb,
                                chain_profile,
                                nand.layout,
                            );
                            if phys_fs_block != 0 {
                                phys_fs_block as u16
                            } else {
                                0x4E
                            }
                        }
                    };
                    match crate::builder::filesystem::flashfs::FileSystemRoot::build_from_folder(
                        &mut nand.image,
                        &nand.layout,
                        &path,
                        fs_start,
                        0x30,
                    ) {
                        Ok(new_root) => {
                            nand.flashfs.root = new_root;
                            if matches!(nand.layout, crate::core::images::blocks::NandLayout::Emmc)
                            {
                                if let Err(e) = crate::builder::filesystem::corona::write_back(
                                    &mut nand.image,
                                    &mut nand.corona_fs,
                                    &nand.flashfs.root,
                                    &nand.mobile,
                                ) {
                                    return Err(format!("Corona metadata write failed: {}", e));
                                }
                                if nand.flashfs.root.block_number >= 0 {
                                    nand.header
                                        .fs_addr
                                        .set((nand.flashfs.root.block_number as u32) * 0x200);
                                }
                            }
                            info!("[session] FlashFS constructed and injected successfully.");
                        }
                        Err(e) => error!("[session] Failed to build FlashFS from folder: {}", e),
                    }
                } else {
                    error!("[session] No active NAND loaded to parse FlashFS into.");
                }
            }
            InternalCommand::ParsePatch { path } => {
                info!("[session] Parsing patch binary from {:?}...", path);
                match parse_patch_binary(path) {
                    Ok(patch) => {
                        info!(
                            "[session] Successfully parsed patch: Type {:?}, Legacy: {}",
                            patch.header.patch_type, patch.is_legacy
                        );
                    }
                    Err(e) => return Err(format!("Failed to parse patch binary: {}", e)),
                }
            }
            InternalCommand::ApplyPatch { path, .. } => {
                info!("[session] Applying patch {:?} (GXP Logic)...", path);
                if let Some(nand) = &mut session.active_nand {
                    match parse_patch_binary(path) {
                        Ok(patch) => {
                            if let Err(e) = nand.apply_patch(patch) {
                                return Err(format!("Failed to apply patch: {}", e));
                            } else {
                                info!(
                                    "[session] Successfully applied patch and routed components."
                                );
                            }
                        }
                        Err(e) => error!("[session] Failed to parse patch binary: {}", e),
                    }
                } else {
                    error!("[session] No active NAND loaded to patch.");
                }
            }
            InternalCommand::ApplySmcSignature { json } => {
                if let Err(e) = Self::apply_smc_signature_batch(session, &json) {
                    return Err(format!("Failed to apply SMC signature patch: {}", e));
                }
            }
            InternalCommand::SwapBootloader {
                bl_type,
                path,
                is_rebooter,
            } => {
                info!(
                    "[session] Swapping bootloader {} with {:?} (Rebooter: {})...",
                    bl_type, path, is_rebooter
                );
                if let Some(nand) = &mut session.active_nand {
                    let target = if is_rebooter {
                        if nand.rebooter.is_none() {
                            nand.rebooter = Some(crate::builder::types::NandBootloaders::new());
                        }
                        nand.rebooter.as_mut().unwrap()
                    } else {
                        &mut nand.bootloaders
                    };

                    let data = fs::read(&path)
                        .map_err(|e| format!("Failed to read swap bootloader: {}", e))?;
                    match bl_type.to_lowercase().as_str() {
                        "cb" | "cba" | "cbb" | "cbx" => {
                            let bl = crate::builder::chain::cb::BootloaderCb::parse(&data)?;
                            match bl_type.to_lowercase().as_str() {
                                "cb" => target.cb = Some(bl),
                                "cba" => target.cb_a = Some(bl),
                                "cbb" => target.cb_b = Some(bl),
                                "cbx" => target.cb_x = Some(bl),
                                _ => unreachable!(),
                            }
                        }
                        "cd" => {
                            let bl = crate::builder::chain::cd::BootloaderCd::parse(&data)?;
                            target.cd = Some(bl);
                        }
                        "ce" => {
                            let bl = crate::builder::chain::ce::BootloaderCe::parse(&data)?;
                            target.ce = Some(bl);
                        }
                        "cf" => {
                            let bl = crate::builder::chain::cf::BootloaderCf::parse(&data)?;
                            if is_rebooter {
                                if nand.rebooter_update.is_none() {
                                    nand.rebooter_update = Some(Default::default());
                                }
                                nand.rebooter_update.as_mut().unwrap().cf_0 = Some(bl);
                            } else {
                                nand.update.cf_0 = Some(bl);
                            }
                        }
                        "cg" => {
                            let bl = crate::builder::chain::cg::BootloaderCg::parse(&data)?;
                            if is_rebooter {
                                if nand.rebooter_update.is_none() {
                                    nand.rebooter_update = Some(Default::default());
                                }
                                nand.rebooter_update.as_mut().unwrap().cg_0 = Some(bl);
                            } else {
                                nand.update.cg_0 = Some(bl);
                            }
                        }
                        "smc" => {
                            nand.extra.smc = data;
                        }
                        _ => return Err(format!("Unknown bootloader type: {}", bl_type)),
                    }
                    info!("[session] Bootloader {} swapped successfully.", bl_type);
                } else {
                    return Err("No active NAND loaded. Cannot swap bootloader.".to_string());
                }
            }
            InternalCommand::Replace { id, path } => {
                println!(" -> Replacing element {} with {:?}...", id, path);
                if let Some(nand) = &mut session.active_nand {
                    if let Ok(data) = fs::read(&path) {
                        match id {
                            1 => nand.extra.smc = data,
                            2 => nand.extra.keyvault = data,
                            _ => eprintln!(" -> Unhandled Replace ID {}", id),
                        }
                    } else {
                        eprintln!(" -> Failed to read replace payload.");
                    }
                }
            }
            InternalCommand::List => {
                if let Some(nand) = &session.active_nand {
                    // nand.header.print_info();
                    info!(
                        "[session] Bootloaders Present: CB: {} | CD: {} | CE: {}",
                        nand.bootloaders.cb.is_some(),
                        nand.bootloaders.cd.is_some(),
                        nand.bootloaders.ce.is_some()
                    );
                } else {
                    info!("[session] Active NAND is empty.");
                }
            }
            InternalCommand::Delete { id } => {
                info!("[session] Deleting element {}...", id);
                if let Some(nand) = &mut session.active_nand {
                    match id {
                        1 => nand.extra.smc = Vec::new(),
                        3 => nand.bootloaders.cb = None,
                        _ => error!("[session] Unhandled Delete ID {}", id),
                    }
                }
            }
            InternalCommand::Clear => {
                session.active_nand = None;
                session.pending_assets.clear();
                session.bootloader_assets.clear();
                session.security_assets.clear();
                session.flashfs_assets.clear();
                info!("[session] Active NAND and all asset pools cleared.");
            }
            InternalCommand::Compress => {
                info!("[session] Compress logic hooks to mspack / xenia (Not Yet Invoked)");
            }
            /*
            InternalCommand::Decompress => {
                info!("[session] Decompressing CE Base Kernel payload...");
                if let Some(nand) = &mut session.active_nand {
                    if let Some(ce) = &mut nand.bootloaders.ce {
                        match ce.decompress() {
                            Ok(kernel_payload) => {
                                ce.data_kernel = Some(kernel_payload.clone());
                                // Optionally dump to verification file locally
                                let _ = std::fs::write("Kernel-Decompressed.bin", &kernel_payload);
                                info!("[session] CE Base Kernel successfully decompressed! (0x{:X} bytes)", kernel_payload.len());
                            }
                            Err(e) => error!("[session] CE decompression failed: {}", e),
                        }
                    } else {
                        error!(
                            "[session] Active NAND does not contain a CE bootloader to decompress."
                        );
                    }
                } else {
                    error!("[session] No active NAND loaded. Cannot run Decompress.");
                }
            }
            */
            InternalCommand::ApplyOptions => {
                info!("[session] Applying session options to active NAND...");
                Self::sync_options_to_nand(session)?;
            }
            InternalCommand::SessionInit { base, common } => {
                info!(
                    "[session] Initializing session with base {:?} and common {:?}",
                    base, common
                );
            }
            InternalCommand::SessionList => {
                info!("[session] Queue:");
                for q in session.queue.iter() {
                    info!(
                        "[session]   [Priority {}] Seq {}: {:?}",
                        q.command.priority_score(),
                        q.sequence_id,
                        q.command
                    );
                }
            }
            InternalCommand::SessionDelete { id } => {
                let mut temp = Vec::new();
                let mut found = false;
                while let Some(q) = session.queue.pop() {
                    if q.sequence_id != id as usize {
                        temp.push(q);
                    } else {
                        found = true;
                        info!("[session] Deleted sequence {}.", id);
                    }
                }
                if !found {
                    error!("[session] Sequence {} not found in queue.", id);
                }
                for q in temp {
                    session.queue.push(q);
                }
            }
            InternalCommand::SessionRun => {
                // Execute all queued commands in priority order, clearing the queue.
                // Swap out the queue so the while-let loop in run() is naturally empty
                // after we return, preventing re-entry issues.
                let commands: Vec<QueuedCommand> = session.queue.drain().collect();
                info!(
                    "[session] SessionRun: executing {} queued commands in priority order.",
                    commands.len()
                );
                for queued_cmd in commands {
                    let priority = queued_cmd.command.priority_score();
                    match &queued_cmd.command {
                        InternalCommand::ParseIni { path, target, .. } => {
                            info!(
                                "[session] SessionRun Executing (PriorityScore: {}, Seq: {}): ParseIni {{ path: {:?}, target: {:?} }}",
                                priority, queued_cmd.sequence_id, path, target
                            );
                        }
                        cmd => {
                            info!(
                                "[session] SessionRun Executing (PriorityScore: {}, Seq: {}): {:?}",
                                priority, queued_cmd.sequence_id, cmd
                            );
                        }
                    }
                    Self::execute_command(session, queued_cmd.command)?;
                }
                info!("[session] SessionRun: queue cleared.");
            }
            InternalCommand::CreateImage { layout } => {
                let blank = NandSkeleton::new_blank(layout);
                info!(
                    "[session] Created blank NAND skeleton: layout {:?}, {} blocks ({} MB)",
                    layout,
                    blank.total_blocks,
                    blank.image.len() / (1024 * 1024)
                );
                session.active_nand = Some(blank);
            }
            InternalCommand::Update { path } => {
                info!("[session] Loading asset discovery from {:?}...", path);
                match fs::read(&path) {
                    Ok(data) => {
                        let name = path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_lowercase();
                        session.pending_assets.insert(name.clone(), data);
                        info!(
                            "[session] Discovered asset '{}' added to session pool.",
                            name
                        );
                    }
                    Err(e) => return Err(format!("Failed to read asset at {:?}: {}", path, e)),
                }
            }
            InternalCommand::FinalizeMobile => {
                if session.options.nomobile.unwrap_or(false) {
                    return Ok(());
                }
                let data_dir = session
                    .data_dir
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("mydata"));
                if let Some(nand) = &mut session.active_nand {
                    nand.mobile.apply_data_folder_tier(&data_dir);
                }
            }
            InternalCommand::FinalizeFlashfs => {
                if let Some(nand) = &mut session.active_nand {
                    let fs_start: u16 = match nand.layout {
                        crate::core::images::blocks::NandLayout::Bb => {
                            let image_len = nand.image.len();
                            let reserve_start = nand.layout.reserve_start(image_len);
                            let scanned = nand.flashfs.root.block_number;
                            if scanned > 0 && (scanned as usize) < reserve_start {
                                scanned as u16
                            } else {
                                let fallback = reserve_start.saturating_sub(0x80);
                                std::cmp::max(4u16, fallback as u16)
                            }
                        }
                        crate::core::images::blocks::NandLayout::Emmc => {
                            crate::builder::filesystem::corona::default_emmc_fs_block(
                                nand.header.fs_addr.get(),
                                &nand.corona_fs,
                            )
                        }
                        _ => {
                            let sb: crate::builder::types::SouthbridgeType =
                                nand.options.motherboard.into();
                            let chain_profile = if nand.bootloaders.cb_b.is_some() {
                                "split"
                            } else {
                                "single"
                            };
                            let (_, _, phys_fs_block) = crate::builder::types::layout_calculator(
                                sb,
                                chain_profile,
                                nand.layout,
                            );
                            if phys_fs_block != 0 {
                                phys_fs_block as u16
                            } else {
                                0x4E
                            }
                        }
                    };

                    info!(
                        "[session] FlashFS start block: 0x{:X} ({})",
                        fs_start, fs_start
                    );

                    let mut merged_flashfs_assets: HashMap<String, Vec<u8>> = HashMap::new();
                    let mut dropped_assets: Vec<String> = Vec::new();
                    let mut dropped_count: usize = 0;
                    for (k, v) in &session.flashfs_assets {
                        let key = k.to_lowercase();
                        if let Some(allow) = &session.flashfs_allowlist {
                            if !allow.contains(&key) {
                                dropped_count += 1;
                                if dropped_assets.len() < 6 {
                                    dropped_assets.push(key);
                                }
                                continue;
                            }
                        }
                        merged_flashfs_assets.insert(key, v.clone());
                    }

                    if !merged_flashfs_assets.is_empty() {
                        if dropped_count > 0 {
                            warn!("[session] Dropped {} FlashFS asset(s) not present in INI FlashFS allowlist (e.g. {:?})", dropped_count, dropped_assets);
                        }
                        info!(
                            "[session] Prepared FlashFS with {} INI-discovered assets...",
                            merged_flashfs_assets.len()
                        );
                        let mut root = crate::builder::filesystem::flashfs::FileSystemRoot::new(
                            fs_start as i32,
                            3,
                            0x30,
                        );
                        root.create_defaults(nand.image.len(), &nand.layout, fs_start);
                        for (name, content) in merged_flashfs_assets {
                            let mut entry =
                                crate::builder::filesystem::flashfs::FileSystemEntry::new(0);
                            entry.file_name = name;
                            entry.data = content;
                            entry.size = entry.data.len() as u32;
                            root.entries.push(entry);
                        }
                        nand.flashfs.root = root;
                    } else {
                        let mut root = crate::builder::filesystem::flashfs::FileSystemRoot::new(
                            fs_start as i32,
                            3,
                            0x30,
                        );
                        root.create_defaults(nand.image.len(), &nand.layout, fs_start);
                        nand.flashfs.root = root;
                        info!(
                            "[session] Initialized empty FlashFS map for generated build assets."
                        );
                    }
                }
            }
            InternalCommand::ExtractStfs { path, target_dir } => {
                info!(
                    "[session] Extracting STFS container from {:?} to {:?}...",
                    path, target_dir
                );
                match fs::read(&path) {
                    Ok(data) => match crate::core::images::stfs::StfsContainer::new(&data) {
                        Ok(container) => {
                            if let Err(e) = container.extract_all(&target_dir) {
                                return Err(format!("STFS Extraction Error: {}", e));
                            }
                            println!(" -> STFS extraction complete.");
                        }
                        Err(e) => return Err(format!("STFS Format Error: {}", e)),
                    },
                    Err(e) => return Err(format!("Failed to read STFS file: {}", e)),
                }
            }
        }

        Ok(())
    }
}
