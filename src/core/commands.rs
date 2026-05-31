/*
  commands.rs - Command implementations for session execution

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
use crate::core::images::gxp::parse_patch_binary;
use crate::core::session::{Session, SessionError};
use log::{error, info, warn};
use std::fs;
use std::path::PathBuf;

/// Extract all components from the active NAND
pub fn handle_extract_all(
    session: &mut Session,
    output_dir: PathBuf,
    all: bool,
    include_decrypted: bool,
) -> Result<(), SessionError> {
    let nand = session.active_nand.as_mut().ok_or(SessionError::Other(
        "No active NAND to extract from".to_string(),
    ))?;

    let _ = std::fs::create_dir_all(&output_dir);

    // Helper to write a file
    let write_file = |name: &str, data: &[u8]| -> Result<(), SessionError> {
        let path = output_dir.join(name);
        std::fs::write(&path, data)
            .map_err(|e| SessionError::Other(format!("Failed to write {}: {}", name, e)))?;
        info!("[extract] Wrote {} ({} bytes)", name, data.len());
        Ok(())
    };

    // Extract header
    let header_bytes = zerocopy::IntoBytes::as_bytes(&nand.header);
    write_file("NandHeader.bin", header_bytes)?;

    // Extract bootloaders (encrypted)
    if all || !include_decrypted {
        // CB_A
        if let Some(cb) = &nand.bootloaders.cb_a {
            let data = cb.serialize();
            write_file("CB_A.bin", &data)?;
        }
        // CB_B
        if let Some(cb) = &nand.bootloaders.cb_b {
            let data = cb.serialize();
            write_file("CB_B.bin", &data)?;
        }
        // SC
        if let Some(sc) = &nand.bootloaders.sc {
            let data = sc.serialize();
            write_file("SC.bin", &data)?;
        }
        // CD
        if let Some(cd) = &nand.bootloaders.cd {
            let data = cd.serialize();
            write_file("CD.bin", &data)?;
        }
        // CE
        if let Some(ce) = &nand.bootloaders.ce {
            let data = ce.serialize();
            write_file("CE.bin", &data)?;
        }
        // CF slots
        if let Some(cf) = &nand.update.cf_0 {
            let data = cf.serialize();
            write_file("CF_0.bin", &data)?;
        }
        if let Some(cf) = &nand.update.cf_1 {
            let data = cf.serialize();
            write_file("CF_1.bin", &data)?;
        }
        // CG slots
        if let Some(cg) = &nand.update.cg_0 {
            let data = cg.serialize();
            write_file("CG_0.bin", &data)?;
        }
        if let Some(cg) = &nand.update.cg_1 {
            let data = cg.serialize();
            write_file("CG_1.bin", &data)?;
        }
    }

    // Extract decrypted versions if requested
    if include_decrypted {
        // SMC
        if !nand.extra.smc.is_empty() {
            write_file("SMC_en.bin", &nand.extra.smc)?;
            // Try to decrypt
            let mut smc = crate::builder::chain::smc::RawSmc::new(nand.extra.smc.clone());
            smc.ensure_decrypted();
            if smc
                .data
                .windows(b"Microsoft".len())
                .any(|w| w == b"Microsoft")
            {
                write_file("SMC_dec.bin", &smc.data)?;
            }
        }

        // Keyvault
        if !nand.extra.keyvault.is_empty() {
            write_file("Keyvault.bin", &nand.extra.keyvault)?;
            // Try to decrypt if CPU key available
            if let Some(key) = nand.cpukey {
                let kv_data = nand.extra.keyvault.clone();
                let mut kv = crate::builder::chain::kv::Keyvault {
                    data: kv_data,
                    is_decrypted: false,
                    hashed: false,
                    metadata: None,
                };
                if let Err(e) = kv.decrypt(&key) {
                    warn!("[extract] Failed to decrypt keyvault: {}", e);
                } else {
                    write_file("Keyvault_dec.bin", &kv.data)?;
                }
            }
        }

        // FCRT
        if let Some(fcrt) = &nand.extra.fcrt {
            write_file("FCRT.bin", fcrt)?;
        }
    }

    // Extract full image
    if all {
        let image_path = output_dir.join("nandimage.bin");
        match std::fs::write(&image_path, &nand.image) {
            Ok(_) => info!(
                "[extract] Wrote full NAND image ({} bytes)",
                nand.image.len()
            ),
            Err(e) => warn!("[extract] Failed to write full image: {}", e),
        }
    }

    // Extract FlashFS contents
    if all {
        let flashfs_dir = output_dir.join("flashfs");
        let _ = std::fs::create_dir_all(&flashfs_dir);
        // TODO: Implement FlashFS extraction
        info!("[extract] FlashFS extraction stub");
    }

    info!("[session] Extraction complete.");
    Ok(())
}

/// Build the NAND image
pub fn handle_build(
    session: &mut Session,
    output: PathBuf,
    _target: u8,
) -> Result<(), SessionError> {
    // Get key before borrowing active_nand
    let key = session.pending_key.ok_or(SessionError::Other(
        "No CPU key available for build".to_string(),
    ))?;

    // Sync and finalize before building
    session.sync_options_to_nand()?;
    session.finalize_flashfs_internal();
    session.finalize_mobile_internal();

    if let Some(nand) = &mut session.active_nand {
        info!("[session] Building NAND image to {:?}...", output);

        // Build in place
        match nand.build_in_place(key) {
            Ok(clean_bytes) => {
                // Add spare if needed
                let final_bytes = if session.options.noecc.unwrap_or(false) {
                    clean_bytes
                } else {
                    crate::core::images::blocks::add_spare(
                        &clean_bytes,
                        nand.layout,
                        crate::core::images::blocks::detect_meta_type(&clean_bytes, nand.layout),
                        0, // blockstart
                        None,
                        None,
                        None,
                    )
                };

                // Write output
                std::fs::write(&output, &final_bytes)
                    .map_err(|e| SessionError::Other(format!("Failed to write output: {}", e)))?;

                info!(
                    "[session] Build complete: {} bytes written to {:?}",
                    final_bytes.len(),
                    output
                );
                Ok(())
            }
            Err(e) => Err(SessionError::Other(format!("Build failed: {}", e))),
        }
    } else {
        Err(SessionError::Other(
            "No active NAND loaded to build!".to_string(),
        ))
    }
}

/// Parse an INI file
pub fn handle_parse_ini(
    session: &mut Session,
    path: PathBuf,
    target: String,
    _ini_base: PathBuf,
    _common: PathBuf,
    data: PathBuf,
    _payloads: PathBuf,
    _smc: PathBuf,
) -> Result<(), SessionError> {
    info!(
        "[session] Parsing INI {:?} for target '{}'...",
        path, target
    );

    match crate::core::data::xeini::parse_xe_ini(&path, &target) {
        Ok(ini) => {
            // Process INI entries
            for entry in &ini.main {
                let filename = entry.filename.to_lowercase();
                let asset_path = data.join(&filename);
                if asset_path.exists() {
                    session.enqueue(crate::core::session::InternalCommand::Update {
                        path: asset_path,
                    });
                }
            }
            Ok(())
        }
        Err(e) => Err(SessionError::Other(format!("Failed to parse INI: {}", e))),
    }
}

/// Parse a NAND image file
pub fn handle_parse_image(
    session: &mut Session,
    path: PathBuf,
    key: Option<[u8; 16]>,
) -> Result<(), SessionError> {
    info!("[session] Parsing image {:?}...", path);
    match fs::read(&path) {
        Ok(raw_data) => {
            let remap_bad_blocks = !session.options.noremap.unwrap_or(false);
            match crate::core::images::blocks::NandProcessor::preprocess_nand_with_lba_options(
                &raw_data,
                remap_bad_blocks,
            ) {
                Ok((clean_data, layout, lba_map)) => {
                    info!(
                        "[session] Detected {} bad block(s) during preprocessing",
                        lba_map.bad_blocks.len()
                    );
                    let active_key = key.or(session.pending_key);

                    let flashfs =
                        crate::builder::filesystem::flashfs::FlashFS::scan_physical_with_lba(
                            &raw_data, &layout, &lba_map,
                        );
                    let mobile = if session.options.nomobile.unwrap_or(false) {
                        crate::builder::filesystem::mobile::MobileStore::new()
                    } else {
                        crate::builder::filesystem::mobile::MobileStore::scan_physical(
                            &raw_data, &layout,
                        )
                    };

                    let parse_result = match active_key {
                        Some(k) => NandSkeleton::parse_clean(clean_data, layout, k, flashfs),
                        None => NandSkeleton::parse_clean_encrypted(clean_data, layout, flashfs),
                    };

                    match parse_result {
                        Ok(mut nand) => {
                            nand.mobile = mobile;
                            nand.lba_map = Some(lba_map);
                            session.active_nand = Some(nand);
                            session.extract_options_from_nand();
                            info!("[session] Successfully parsed NAND from {:?}", path);
                            Ok(())
                        }
                        Err(e) => Err(SessionError::Other(format!(
                            "Failed to interpret clean NAND: {}",
                            e
                        ))),
                    }
                }
                Err(e) => Err(SessionError::Other(format!(
                    "Failed to pre-process NAND image: {}",
                    e
                ))),
            }
        }
        Err(e) => Err(SessionError::Other(format!(
            "Failed to read image file '{}': {}",
            path.display(),
            e
        ))),
    }
}

/// Apply ECC file to active NAND
pub fn handle_apply_ecc(session: &mut Session, path: PathBuf) -> Result<(), SessionError> {
    let Some(old) = session.active_nand.take() else {
        error!("[session] No active NAND loaded. Cannot apply ECC.");
        return Ok(());
    };

    let ecc_raw = fs::read(&path).map_err(|e| {
        SessionError::Other(format!(
            "Failed to read ECC file '{}': {}",
            path.display(),
            e
        ))
    })?;

    let (ecc_clean, ecc_layout, _ecc_lba) =
        crate::core::images::blocks::NandProcessor::preprocess_nand_with_lba_options(
            &ecc_raw, false,
        )
        .map_err(|e| SessionError::Other(format!("Failed to pre-process ECC image: {}", e)))?;

    let nand_layout = old.layout;
    if ecc_layout != nand_layout {
        session.active_nand = Some(old);
        return Err(SessionError::Other(format!(
            "ECC layout mismatch: ECC={:?}, NAND={:?}. Provide a matching ECC for this NAND type.",
            ecc_layout, nand_layout
        )));
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
            Ok(())
        }
        Err(e) => Err(SessionError::Other(format!(
            "Applied ECC but failed to re-parse NAND: {}",
            e
        ))),
    }
}

/// Parse CPU key
pub fn handle_parse_key(session: &mut Session, key: [u8; 16]) {
    session.pending_key = Some(key);
    if let Some(nand) = &mut session.active_nand {
        nand.cpukey = Some(key);
        info!("[session] CPU Key assigned to active NAND.");
    } else {
        info!("[session] CPU Key buffered (awaiting NAND image).");
    }
}

/// Parse CPU key from keybin
pub fn handle_parse_keybin(session: &mut Session, key: Option<[u8; 16]>) {
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

/// Parse FlashFS from folder
pub fn handle_parse_flashfs(session: &mut Session, path: PathBuf) -> Result<(), SessionError> {
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
                let sb: crate::builder::types::SouthbridgeType = nand.options.motherboard.into();
                let chain_profile = if nand.bootloaders.cb_b.is_some() {
                    "split"
                } else {
                    "single"
                };
                let (_, _, phys_fs_block) = crate::builder::types::LayoutCalculator::calculate(
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
                if matches!(nand.layout, crate::core::images::blocks::NandLayout::Emmc) {
                    if let Err(e) = crate::builder::filesystem::corona::write_back(
                        &mut nand.image,
                        &mut nand.corona_fs,
                        &nand.flashfs.root,
                        &nand.mobile,
                    ) {
                        return Err(SessionError::Other(format!(
                            "Corona metadata write failed: {}",
                            e
                        )));
                    }
                    if nand.flashfs.root.block_number >= 0 {
                        nand.header
                            .fs_addr
                            .set((nand.flashfs.root.block_number as u32) * 0x200);
                    }
                }
                info!("[session] FlashFS constructed and injected successfully.");
                Ok(())
            }
            Err(e) => {
                error!("[session] Failed to build FlashFS from folder: {}", e);
                Ok(())
            }
        }
    } else {
        error!("[session] No active NAND loaded to parse FlashFS into.");
        Ok(())
    }
}

/// Parse patch binary
pub fn handle_parse_patch(_session: &mut Session, path: PathBuf) -> Result<(), SessionError> {
    info!("[session] Parsing patch binary from {:?}...", path);
    match parse_patch_binary(&path) {
        Ok(patch) => {
            info!(
                "[session] Successfully parsed patch: Type {:?}, Legacy: {}",
                patch.header.patch_type, patch.is_legacy
            );
            Ok(())
        }
        Err(e) => Err(SessionError::Other(format!(
            "Failed to parse patch binary: {}",
            e
        ))),
    }
}

/// Apply patch to active NAND
pub fn handle_apply_patch(
    session: &mut Session,
    path: PathBuf,
    _ptype: u8,
    _target: Option<u8>,
) -> Result<(), SessionError> {
    info!("[session] Applying patch {:?} (GXP Logic)...", path);
    if let Some(nand) = &mut session.active_nand {
        match parse_patch_binary(&path) {
            Ok(patch) => {
                if let Err(e) = nand.apply_patch(patch) {
                    Err(SessionError::Other(format!("Failed to apply patch: {}", e)))
                } else {
                    info!("[session] Successfully applied patch and routed components.");
                    Ok(())
                }
            }
            Err(e) => {
                error!("[session] Failed to parse patch binary: {}", e);
                Ok(())
            }
        }
    } else {
        error!("[session] No active NAND loaded to patch.");
        Ok(())
    }
}

/// Swap bootloader
pub fn handle_swap_bootloader(
    session: &mut Session,
    bl_type: String,
    path: PathBuf,
    is_rebooter: bool,
) -> Result<(), SessionError> {
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
            .map_err(|e| SessionError::Other(format!("Failed to read swap bootloader: {}", e)))?;

        match bl_type.to_lowercase().as_str() {
            "cb" | "cba" | "cbb" | "cbx" => {
                let bl = crate::builder::chain::cb::BootloaderCb::parse(&data)
                    .map_err(|e| SessionError::Other(format!("Failed to parse CB: {}", e)))?;
                match bl_type.to_lowercase().as_str() {
                    "cb" => target.cb = Some(bl),
                    "cba" => target.cb_a = Some(bl),
                    "cbb" => target.cb_b = Some(bl),
                    "cbx" => target.cb_x = Some(bl),
                    _ => unreachable!(),
                }
            }
            "cd" => {
                let bl = crate::builder::chain::cd::BootloaderCd::parse(&data)
                    .map_err(|e| SessionError::Other(format!("Failed to parse CD: {}", e)))?;
                target.cd = Some(bl);
            }
            "ce" => {
                let bl = crate::builder::chain::ce::BootloaderCe::parse(&data)
                    .map_err(|e| SessionError::Other(format!("Failed to parse CE: {}", e)))?;
                target.ce = Some(bl);
            }
            "cf" => {
                let bl = crate::builder::chain::cf::BootloaderCf::parse(&data)
                    .map_err(|e| SessionError::Other(format!("Failed to parse CF: {}", e)))?;
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
                let bl = crate::builder::chain::cg::BootloaderCg::parse(&data)
                    .map_err(|e| SessionError::Other(format!("Failed to parse CG: {}", e)))?;
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
            _ => {
                return Err(SessionError::Other(format!(
                    "Unknown bootloader type: {}",
                    bl_type
                )))
            }
        }
        info!("[session] Bootloader {} swapped successfully.", bl_type);
        Ok(())
    } else {
        Err(SessionError::Other(
            "No active NAND loaded. Cannot swap bootloader.".to_string(),
        ))
    }
}

/// Replace component by ID
pub fn handle_replace(session: &mut Session, id: u8, path: PathBuf) {
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

/// List active NAND contents
pub fn handle_list(session: &Session) {
    if let Some(nand) = &session.active_nand {
        nand.header.print_info();
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

/// Delete component by ID
pub fn handle_delete(session: &mut Session, id: u8) {
    info!("[session] Deleting element {}...", id);
    if let Some(nand) = &mut session.active_nand {
        match id {
            1 => nand.extra.smc = Vec::new(),
            3 => nand.bootloaders.cb = None,
            _ => error!("[session] Unhandled Delete ID {}", id),
        }
    }
}

/// Clear all session state
pub fn handle_clear(session: &mut Session) {
    session.active_nand = None;
    session.pending_assets.clear();
    session.bootloader_assets.clear();
    session.security_assets.clear();
    session.flashfs_assets.clear();
    info!("[session] Active NAND and all asset pools cleared.");
}

/// Compress (stub)
pub fn handle_compress() {
    info!("[session] Compress logic hooks to mspack / xenia (Not Yet Invoked)");
}

/// Apply SMC signature batch
pub fn handle_apply_smc_signature(
    session: &mut Session,
    json: String,
) -> Result<usize, SessionError> {
    session.apply_smc_signature_batch(&json)
}

/// Session init
pub fn handle_session_init(base: Option<PathBuf>, common: Option<PathBuf>) {
    info!(
        "[session] Initializing session with base {:?} and common {:?}",
        base, common
    );
}

/// Session list queue
pub fn handle_session_list(session: &Session) {
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

/// Session delete command from queue
pub fn handle_session_delete(session: &mut Session, id: u8) {
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

/// Session run - execute all queued commands
pub fn handle_session_run(session: &mut Session) -> Result<(), SessionError> {
    let commands: Vec<_> = session.queue.drain().collect();
    info!(
        "[session] SessionRun: executing {} queued commands in priority order.",
        commands.len()
    );
    for queued_cmd in commands {
        let priority = queued_cmd.command.priority_score();
        match &queued_cmd.command {
            crate::core::session::InternalCommand::ParseIni { path, target, .. } => {
                info!(
                    "[session] SessionRun Executing (Priority {}): ParseIni {{ path: {:?}, target: {:?} }}",
                    priority, path, target
                );
            }
            cmd => {
                info!(
                    "[session] SessionRun Executing (Priority {}): {:?}",
                    priority, cmd
                );
            }
        }
        session.execute_command(queued_cmd.command)?;
    }
    info!("[session] SessionRun: queue cleared.");
    Ok(())
}

/// Create blank image
pub fn handle_create_image(session: &mut Session, layout: crate::core::images::blocks::NandLayout) {
    let blank = NandSkeleton::new_blank(layout);
    info!(
        "[session] Created blank NAND skeleton: layout {:?}, {} blocks ({} MB)",
        layout,
        blank.total_blocks,
        blank.image.len() / (1024 * 1024)
    );
    session.active_nand = Some(blank);
}

/// Update - load asset
pub fn handle_update(session: &mut Session, path: PathBuf) -> Result<(), SessionError> {
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
            Ok(())
        }
        Err(e) => Err(SessionError::Other(format!(
            "Failed to read asset at {:?}: {}",
            path, e
        ))),
    }
}

/// Finalize mobile
pub fn handle_finalize_mobile(session: &mut Session) {
    if session.options.nomobile.unwrap_or(false) {
        return;
    }
    let data_dir = session
        .data_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("mydata"));
    if let Some(nand) = &mut session.active_nand {
        nand.mobile.apply_data_folder_tier(&data_dir);
    }
}

/// Finalize FlashFS
pub fn handle_finalize_flashfs(session: &mut Session) {
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
                let sb: crate::builder::types::SouthbridgeType = nand.options.motherboard.into();
                let chain_profile = if nand.bootloaders.cb_b.is_some() {
                    "split"
                } else {
                    "single"
                };
                let (_, _, phys_fs_block) = crate::builder::types::LayoutCalculator::calculate(
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

        // Re-scan filesystem to ensure we have latest state
        if nand.flashfs.root.block_number > 0 {
            let new_fs = crate::builder::filesystem::flashfs::FlashFS::scan_physical(
                &nand.image,
                &nand.layout,
            );
            if new_fs.root.block_number >= 0 {
                nand.flashfs.root = new_fs.root;
            } else {
                // Re-scan found nothing — create a fresh root at fs_start
                let mut root = crate::builder::filesystem::flashfs::FileSystemRoot::new(
                    fs_start as i32,
                    0,
                    0x30,
                );
                root.create_defaults(nand.image.len(), &nand.layout, fs_start);
                nand.flashfs.root = root;
            }
        }

        // Apply security assets if needed
        let sec_files = [
            "fcrt.bin",
            "crl.bin",
            "dae.bin",
            "extended.bin",
            "secdata.bin",
            "odd.bin",
        ];
        for name in &sec_files {
            if let Some(data) = session.security_assets.get(*name).cloned() {
                nand.inject_security_file(name, &data, fs_start);
            }
        }
    }
}

/// Apply options to NAND
pub fn handle_apply_options(session: &mut Session) -> Result<(), SessionError> {
    info!("[session] Applying session options to active NAND...");
    session.sync_options_to_nand()
}

/// Extract STFS package
pub fn handle_extract_stfs(
    _session: &mut Session,
    path: PathBuf,
    target_dir: PathBuf,
) -> Result<(), SessionError> {
    info!(
        "[extract] Extracting STFS package from {:?} to {:?}...",
        path, target_dir
    );

    let _ = std::fs::create_dir_all(&target_dir);

    // For now, this is a placeholder implementation
    // In a full implementation, this would extract the STFS package
    warn!("[extract] STFS extraction not yet implemented");

    Ok(())
}
