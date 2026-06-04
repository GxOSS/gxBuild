/*
  builder.rs - Core NAND assembly and parsing logic.

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

use log::{error, info, warn};
use zerocopy::byteorder::{I16, U16, U32};
use zerocopy::FromBytes;

use crate::builder::chain::smc::smc_crypt;
use crate::builder::chain::*;
use crate::builder::filesystem::corona;
use crate::builder::filesystem::flashfs::FlashFS;
use crate::builder::filesystem::mobile::MobileStore;
pub use crate::builder::nand::types::*;
use crate::core::images::blocks::*;
use crate::core::images::gxpatch::{apply_records, GxpBinary, GxpPatchType};
use crate::crypto::calculate_smc_hash;

impl NandSkeleton {
    pub fn new_blank(layout: NandLayout) -> Self {
        let size = match layout {
            NandLayout::Xsb | NandLayout::Sb => 0x1000000,
            NandLayout::Bb => 0x4000000,
            NandLayout::Emmc => 0x3000000,
        };
        let mut image = vec![0xFFu8; size];
        image[0] = 0xFF;
        image[1] = 0x4F;
        let total_blocks = size / (layout.logical_pages_per_block() * 0x200);

        Self {
            cpukey: None,
            build_options: BuildOptions::default(),
            options: NandConfig {
                layout,
                image_profile: "retail".to_string(),
                build_mode: BuildMode::Normal,
                motherboard: MotherboardType::Unknown,
                khv_header_size: 0x4000,
                total_blocks,
            },
            header: NandHeader {
                prefix: NandHeaderPrefix {
                    magic: U16::new(NandHeader::MAGIC),
                    version: U16::new(0),
                    pairing: U16::new(0),
                    flags: U16::new(0),
                    entrypoint: U32::new(0),
                    size: U32::new(0),
                },
                copyright: [0u8; 0x40],
                payload_indicator: U16::new(0),
                unused: [0u8; 0x0E],
                kv_size: U32::new(0x4000),
                cf_offset: U32::new(match layout {
                    NandLayout::Bb => 0x80000,
                    NandLayout::Emmc => 0xB0000,
                    _ => 0x70000,
                }),
                patch_slots: I16::new(0),
                kv_version: U16::new(0x712),
                kv_addr: U32::new(0x4000),
                fs_addr: U32::new(0x10000),
                smc_config_offset: U32::new(match layout {
                    NandLayout::Bb => 0x3DF0000,
                    NandLayout::Emmc => 0x0,
                    _ => 0xF70000,
                }),
                smc_boot_size: U32::new(match layout {
                    NandLayout::Emmc => 0x3800,
                    _ => 0x3000,
                }),
                smc_boot_offset: U32::new(match layout {
                    NandLayout::Emmc => 0x800,
                    _ => 0x1000,
                }),
            },
            extra: NandExtra {
                smc: Vec::new(),
                smc_metadata: None,
                smc_config: Vec::new(),
                keyvault: Vec::new(),
                fcrt: None,
                lba_map: LbaMap::new(total_blocks),
            },
            kv: None,
            bootloaders: NandBootloaders::default(),
            update: Some(NandUpdate::default()),
            payloads: Some(Vec::new()),
            flashfs: Some(FlashFS::new()),
            mobile: Some(MobileStore::new()),
            corona_fs: Some([Default::default(), Default::default()]),
            image,
        }
    }

    /*
    pub fn clear_bootloaders(&mut self) {
        self.bootloaders.clear();
    }

    pub fn clear_update(&mut self) {
        self.update.clear();
    }
    */

    pub fn prepare_for_assembly(&mut self) -> Result<()> {
        let update = self.update.get_or_insert_with(NandUpdate::default);
        let flashfs = self.flashfs.get_or_insert_with(FlashFS::new);
        let layout = self.options.layout;
        let total_blocks = self.options.total_blocks;

        let verbose = self.build_options.verbose;
        if verbose {
            info!(
                "[builder] cb present: {}, cb_a present: {}, cb_b present: {}",
                self.bootloaders.cb.is_some(),
                self.bootloaders.cb_a.is_some(),
                self.bootloaders.cb_b.is_some()
            );
            info!(
                "[builder] cb meta: {}, cb_a meta: {}, cb_b meta: {}",
                self.bootloaders
                    .cb
                    .as_ref()
                    .map_or(false, |b| b.metadata.is_some()),
                self.bootloaders
                    .cb_a
                    .as_ref()
                    .map_or(false, |b| b.metadata.is_some()),
                self.bootloaders
                    .cb_b
                    .as_ref()
                    .map_or(false, |b| b.metadata.is_some())
            );
            info!(
                "[builder] cf_0 present: {}, cf_0 meta: {}",
                update.cf_0.is_some(),
                update
                    .cf_0
                    .as_ref()
                    .map_or(false, |cf| cf.metadata.is_some())
            );
        }

        // Decrypt newly assigned bootloaders individually
        if let Some(cpukey) = self.cpukey {
            if let Some(cb_b) = self.bootloaders.cb_b.as_mut() {
                if cb_b.metadata.is_none() {
                    info!("[builder] CB_B has no metadata — decrypting");
                    if let Some(cb_a) = self.bootloaders.cb_a.as_ref() {
                        if let Some(cb_a_key_slice) = cb_a.data.get(0..16) {
                            let cb_a_key: [u8; 16] = cb_a_key_slice.try_into().unwrap();
                            let uses_new_crypto = (cb_a.header.flags.get() & 0x1000) != 0;
                            if uses_new_crypto {
                                if let Err(e) = cb_b.decrypt_v2(&cb_a.header, &cb_a_key, &cpukey) {
                                    warn!("[builder] CB_B v2 decryption failed: {}", e);
                                }
                            } else {
                                if let Err(e) = cb_b.decrypt_v1(&cb_a_key, &cpukey) {
                                    warn!("[builder] CB_B v1 decryption failed: {}", e);
                                }
                            }
                            cb_b.populate_metadata_unchecked();
                            if verbose {
                                info!(
                                    "[builder] CB_B decrypted, meta: {:?}",
                                    cb_b.metadata
                                        .as_ref()
                                        .map(|m| (m.lockdown_value, &m.pairing_data))
                                );
                            }
                        } else {
                            warn!("[builder] CB_A is too small to derive CB_B key");
                        }
                    } else {
                        warn!(
                            "[builder] CB_B needs decrypt but CB_A is missing — cannot derive key"
                        );
                    }
                }
            }

            if let Some(cb) = self.bootloaders.cb.as_mut() {
                if cb.metadata.is_none() {
                    info!("[builder] CB (single) has no metadata — decrypting with 1BL key");
                    if let Err(e) = cb.decrypt(&ONEBL_KEY) {
                        warn!("[builder] CB decryption failed: {}", e);
                    }
                    cb.populate_metadata_unchecked();
                    info!(
                        "[builder] CB decrypted, meta: {:?}",
                        cb.metadata
                            .as_ref()
                            .map(|m| (m.lockdown_value, &m.pairing_data))
                    );
                }
            }

            if let Some(cf) = update.cf_0.as_mut() {
                if cf.metadata.is_none() {
                    info!("[builder] CF_0 has no metadata — decrypting with 1BL key");
                    if let Err(e) = cf.decrypt(&ONEBL_KEY) {
                        log::warn!("[builder] CF_0 decryption failed: {}", e);
                    }
                    cf.populate_metadata_unchecked();
                    info!(
                        "[builder] CF_0 decrypted, meta: {:?}",
                        cf.metadata
                            .as_ref()
                            .map(|m| (m.lockdown_value, &m.pairing_data))
                    );
                }
            }

            if let Some(cf) = update.cf_1.as_mut() {
                if cf.metadata.is_none() {
                    info!("[builder] CF_1 has no metadata — decrypting with 1BL key");
                    if let Err(e) = cf.decrypt(&ONEBL_KEY) {
                        log::warn!("[builder] CF_1 decryption failed: {}", e);
                    }
                    cf.populate_metadata_unchecked();
                    info!(
                        "[builder] CF_1 decrypted, meta: {:?}",
                        cf.metadata
                            .as_ref()
                            .map(|m| (m.lockdown_value, &m.pairing_data))
                    );
                }
            }
        }

        let pd = self
            .extra
            .smc_metadata
            .as_ref()
            .map(|m| m.pairing_data)
            .or_else(|| {
                self.bootloaders
                    .cb_b
                    .as_ref()
                    .and_then(|b| b.metadata.as_ref().map(|m| m.pairing_data))
            })
            .or_else(|| {
                self.bootloaders
                    .cb
                    .as_ref()
                    .and_then(|b| b.metadata.as_ref().map(|m| m.pairing_data))
            })
            .or_else(|| {
                update
                    .cf_0
                    .as_ref()
                    .and_then(|cf| cf.metadata.as_ref().map(|m| m.pairing_data))
            })
            .or_else(|| {
                update
                    .cf_1
                    .as_ref()
                    .and_then(|cf| cf.metadata.as_ref().map(|m| m.pairing_data))
            });

        let ldv_cb = self
            .bootloaders
            .cb_b
            .as_ref()
            .and_then(|b| b.metadata.as_ref().map(|m| m.lockdown_value))
            .or_else(|| {
                self.bootloaders
                    .cb
                    .as_ref()
                    .and_then(|b| b.metadata.as_ref().map(|m| m.lockdown_value))
            });

        let ldv0 = update
            .cf_0
            .as_ref()
            .and_then(|cf| cf.metadata.as_ref().map(|m| m.lockdown_value));
        let ldv1 = update
            .cf_1
            .as_ref()
            .and_then(|cf| cf.metadata.as_ref().map(|m| m.lockdown_value));
        let ldv_cf = match (ldv0, ldv1) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            _ => None,
        };

        if let Some(pd_val) = pd {
            if let Some(ref mut cb_b) = self.bootloaders.cb_b {
                if let Some(ref mut meta) = cb_b.metadata {
                    info!(
                        "[builder] Syncing PD {:02x?} -> CB_B (was {:02x?})",
                        pd_val, meta.pairing_data
                    );
                    meta.pairing_data = pd_val;
                }
            } else if let Some(ref mut cb) = self.bootloaders.cb {
                if let Some(ref mut meta) = cb.metadata {
                    info!(
                        "[builder] Syncing PD {:02x?} -> CB (was {:02x?})",
                        pd_val, meta.pairing_data
                    );
                    meta.pairing_data = pd_val;
                }
            }
            if let Some(ref mut cf) = update.cf_0 {
                if let Some(ref mut meta) = cf.metadata {
                    meta.pairing_data = pd_val;
                }
            }
            if let Some(ref mut cf) = update.cf_1 {
                if let Some(ref mut meta) = cf.metadata {
                    meta.pairing_data = pd_val;
                }
            }
            if let Some(ref mut meta) = self.extra.smc_metadata {
                meta.pairing_data = pd_val;
            }
        } else {
            warn!("[builder] Pairing data is None — PD will not be synced");
        }

        if let Some(ldv) = ldv_cb {
            if let Some(ref mut cb_b) = self.bootloaders.cb_b {
                if let Some(ref mut meta) = cb_b.metadata {
                    info!(
                        "[builder] Syncing LDV {} -> CB_B (was {})",
                        ldv, meta.lockdown_value
                    );
                    meta.lockdown_value = ldv;
                }
            } else if let Some(ref mut cb) = self.bootloaders.cb {
                if let Some(ref mut meta) = cb.metadata {
                    info!(
                        "[builder] Syncing LDV {} -> CB (was {})",
                        ldv, meta.lockdown_value
                    );
                    meta.lockdown_value = ldv;
                }
            }
        } else {
            warn!("[builder] input_ldv_cb is None — CB LDV will not be synced");
        }

        if let Some(ldv) = ldv_cf {
            if let Some(ref mut cf) = update.cf_0 {
                if let Some(ref mut meta) = cf.metadata {
                    meta.lockdown_value = ldv;
                }
            }
            if let Some(ref mut cf) = update.cf_1 {
                if let Some(ref mut meta) = cf.metadata {
                    meta.lockdown_value = ldv;
                }
            }
        }

        // Resize image so FlashFS block allocation succeeds
        let expected_size = total_blocks * layout.logical_pages_per_block() * 0x200;
        if self.image.len() != expected_size {
            self.image.resize(expected_size, 0xFF);
        }

        // Handle CG splitting for FlashFS
        let patch_slot_len = 0x10000;

        let cf_size_0 = update
            .cf_0
            .as_ref()
            .map(|cf| cf.header.size.get() as usize)
            .unwrap_or(0);
        let aligned_cf_0 = (cf_size_0 + 0xF) & !0xF;
        if let Some(cg) = update.cg_0.as_ref() {
            let cg_size = cg.header.size.get() as usize; // This is the total serialized size including header
            if aligned_cf_0 + cg_size > patch_slot_len {
                let overflow = aligned_cf_0 + cg_size - patch_slot_len;
                let cg_to_slot = cg_size - overflow;

                if cg_to_slot >= 0x10 {
                    let cg_ser = cg.serialize();
                    let overflow_data = cg_ser[cg_to_slot..].to_vec();

                    let mut entry = crate::builder::filesystem::flashfs::FileSystemEntry::new(0);
                    entry.file_name = "sysupdate.xexp1".to_string();
                    flashfs.root.set_entry_data(
                        &mut self.image,
                        &layout,
                        &mut entry,
                        &overflow_data,
                    )?;
                    flashfs.root.entries.push(entry.clone());

                    if let Some(cf) = update.cf_0.as_mut() {
                        if let Some(meta) = cf.metadata.as_mut() {
                            let chain = flashfs.root.get_block_chain(entry.block_number, 223);
                            meta.cg_blocks_used = chain.len() as u16;
                            meta.cg_block_numbers = chain;
                            info!(
                                "[builder] Split CG0: {} blocks overflowed to sysupdate.xexp1",
                                meta.cg_blocks_used
                            );
                        }
                    }
                }
            }
        }

        let cf_size_1 = update
            .cf_1
            .as_ref()
            .map(|cf| cf.header.size.get() as usize)
            .unwrap_or(0);
        let aligned_cf_1 = (cf_size_1 + 0xF) & !0xF;
        if let Some(cg) = update.cg_1.as_ref() {
            let cg_size = cg.header.size.get() as usize;
            if aligned_cf_1 + cg_size > patch_slot_len {
                let overflow = aligned_cf_1 + cg_size - patch_slot_len;
                let cg_to_slot = cg_size - overflow;

                if cg_to_slot >= 0x10 {
                    let cg_ser = cg.serialize();
                    let overflow_data = cg_ser[cg_to_slot..].to_vec();

                    let mut entry = crate::builder::filesystem::flashfs::FileSystemEntry::new(0);
                    entry.file_name = "sysupdate.xexp2".to_string();
                    flashfs.root.set_entry_data(
                        &mut self.image,
                        &layout,
                        &mut entry,
                        &overflow_data,
                    )?;
                    flashfs.root.entries.push(entry.clone());

                    if let Some(cf) = update.cf_1.as_mut() {
                        if let Some(meta) = cf.metadata.as_mut() {
                            let chain = flashfs.root.get_block_chain(entry.block_number, 223);
                            meta.cg_blocks_used = chain.len() as u16;
                            meta.cg_block_numbers = chain;
                            info!(
                                "[builder] Split CG1: {} blocks overflowed to sysupdate.xexp2",
                                meta.cg_blocks_used
                            );
                        }
                    }
                }
            }
        }

        if let Some(ref mut cb) = self.bootloaders.cb {
            cb.sync_metadata();
        }
        if let Some(ref mut cba) = self.bootloaders.cb_a {
            cba.sync_metadata();
        }
        if let Some(ref mut cbx) = self.bootloaders.cb_x {
            cbx.sync_metadata();
        }
        if let Some(ref mut cbb) = self.bootloaders.cb_b {
            cbb.sync_metadata();
        }
        if let Some(ref mut cd) = self.bootloaders.cd {
            cd.sync_metadata();
        }
        if let Some(ref mut ce) = self.bootloaders.ce {
            ce.sync_metadata();
        }
        if let Some(ref mut cf) = update.cf_0 {
            cf.sync_metadata();
        }
        if let Some(ref mut cf) = update.cf_1 {
            cf.sync_metadata();
        }
        if let Some(ref mut cg) = update.cg_0 {
            cg.sync_metadata();
        }
        if let Some(ref mut cg) = update.cg_1 {
            cg.sync_metadata();
        }

        if let Some(meta) = &self.extra.smc_metadata {
            if self.extra.smc.len() >= 0x107 {
                self.extra.smc[0x103] = meta.lockdown_value;
                self.extra.smc[0x104..0x107].copy_from_slice(&meta.pairing_data);
            }
        }
        Ok(())
    }

    pub fn assemble_logical(&mut self) -> Result<Vec<u8>> {
        let layout = self.options.layout;
        let total_blocks = self.options.total_blocks;
        let update = self.update.get_or_insert_with(NandUpdate::default);
        let flashfs = self.flashfs.get_or_insert_with(FlashFS::new);
        let mobile = self.mobile.get_or_insert_with(MobileStore::new);
        let corona_fs = self
            .corona_fs
            .get_or_insert_with(|| [Default::default(), Default::default()]);

        let expected_size = total_blocks * layout.logical_pages_per_block() * 0x200;

        let mut logical_image = self.image.clone();
        if logical_image.len() != expected_size {
            logical_image.resize(expected_size, 0xFF);
        }

        let mut header = self.header.clone();

        let smc_len = self.extra.smc.len();
        let smc_default_offset = match layout {
            NandLayout::Emmc => 0x800,
            _ => 0x1000,
        };
        let target_smc_offset = if smc_len > 0 {
            0x4000usize
                .checked_sub(smc_len)
                .ok_or_else(|| format!("SMC too large: 0x{:X} bytes", smc_len))?
        } else {
            smc_default_offset
        };

        let bootchain_start = 0x8000;
        let mut curr_bl = bootchain_start;
        let mut bl_stages = Vec::new();

        if let Some(cb) = &self.bootloaders.cb {
            bl_stages.push(("CB", cb.serialize()));
        }
        if let Some(cba) = &self.bootloaders.cb_a {
            bl_stages.push(("CB_A", cba.serialize()));
        }
        if let Some(cbx) = &self.bootloaders.cb_x {
            bl_stages.push(("CB_X", cbx.serialize()));
        }
        if let Some(cbb) = &self.bootloaders.cb_b {
            bl_stages.push(("CB_B", cbb.serialize()));
        }
        if let Some(sc) = &self.bootloaders.sc {
            bl_stages.push(("SC", sc.serialize()));
        }
        if let Some(cd) = &self.bootloaders.cd {
            bl_stages.push(("CD", cd.serialize()));
        }
        if let Some(ce) = &self.bootloaders.ce {
            bl_stages.push(("CE", ce.serialize()));
        }

        for (i, (name, mut data)) in bl_stages.into_iter().enumerate() {
            let declared_size = if data.len() >= 16 {
                let h = BootloaderHeader::read_from_prefix(&data)
                    .map(|(h, _)| h.size.get())
                    .unwrap_or(0);
                h as usize
            } else {
                0
            };

            let aligned_declared = (declared_size + 0xF) & !0xF;
            if aligned_declared > 0 && data.len() != aligned_declared {
                if data.len() < aligned_declared {
                    warn!(
                        "[builder] {} length mismatch: data is 0x{:X}, header says 0x{:X} (aligned 0x{:X}). Padding...",
                        name,
                        data.len(),
                        declared_size,
                        aligned_declared
                    );
                    data.resize(aligned_declared, 0);
                } else {
                    warn!(
                        "[builder] {} length mismatch: data is 0x{:X}, header says 0x{:X} (aligned 0x{:X}). Keeping extra bytes...",
                        name,
                        data.len(),
                        declared_size,
                        aligned_declared
                    );
                    if data.len() >= 0x10 {
                        let new_len = data.len() as u32;
                        data[0x0C..0x10].copy_from_slice(&new_len.to_be_bytes());
                    }
                }
            }

            if curr_bl + data.len() > logical_image.len() {
                return Err(BuilderError::BootchainOverflow {
                    stage: format!("{} (stage {})", name, i),
                    offset: curr_bl,
                });
            }
            info!(
                "[builder] Serializing {} at 0x{:08X} (0x{:X} bytes)",
                name,
                curr_bl,
                data.len()
            );
            logical_image[curr_bl..curr_bl + data.len()].copy_from_slice(&data);
            curr_bl += data.len();
        }

        let build_profile = self.options.image_profile.clone();
        let build_profile_l = build_profile.to_ascii_lowercase();

        let forensic_cf_default = match layout {
            NandLayout::Bb => {
                // XeLL GG payloads are typically 0x40000 bytes at 0x70000, so CF/CG must not start at 0x80000
                // (it would be overwritten by the payload). xeBuild uses 0xC0000 for BB glitch builds.
                if build_profile_l.contains("glitch") {
                    0xC0000
                } else {
                    0x80000
                }
            }
            NandLayout::Emmc => 0xB0000,
            NandLayout::Sb | NandLayout::Xsb => {
                if build_profile_l == "glitch2m"
                    || build_profile_l.contains("glitch2m")
                    || build_profile_l == "devgl"
                    || build_profile_l == "xdkbuild"
                {
                    0xD0000
                } else if build_profile_l.contains("glitch")
                    || build_profile_l.contains("glitchr")
                    || build_profile_l.contains("glitch2r")
                {
                    0xB0000
                } else {
                    0x70000
                }
            }
        };

        // If the bootchain has realigned/extended into the CF area, shift CF to the next 64KB block
        let target_cf_offset = if curr_bl > forensic_cf_default {
            (curr_bl + 0xFFFF) & 0xFFFF0000
        } else {
            forensic_cf_default
        };

        let chain_profile = if self.bootloaders.cb_b.is_some() {
            "split"
        } else {
            "single"
        };

        let sb_type = SouthbridgeType::from(self.options.motherboard);
        let (_fs_root_addr, smc_config_offset, phys_fs_block) =
            layout_calculator(sb_type, chain_profile, layout);
        header.smc_config_offset = U32::new(smc_config_offset);

        header.smc_boot_offset.set(target_smc_offset as u32);
        header.smc_boot_size.set(smc_len as u32);
        header.cf_offset.set(target_cf_offset as u32);
        header.prefix.size.set(target_cf_offset as u32);
        header.kv_addr.set(0x4000); // Enforce Block 1 KV

        let mut target_fs_block = if phys_fs_block > 0 {
            phys_fs_block as i32
        } else {
            flashfs.root.block_number
        };
        let reserve_start = layout.reserve_start(logical_image.len()) as i32;
        if layout != NandLayout::Emmc && target_fs_block >= reserve_start {
            warn!(
                "[builder] FlashFS target block {} is in/after the reserved remap area (>= 0x{:X}); forcing to 0x110 for compatibility",
                target_fs_block, reserve_start
            );
            target_fs_block = 0x110;
        }

        let cf0 = update.cf_0.as_ref().map(|b| b.serialize());
        let cg0 = update.cg_0.as_ref().map(|b| b.serialize());
        let cf1 = update.cf_1.as_ref().map(|b| b.serialize());
        let cg1 = update.cg_1.as_ref().map(|b| b.serialize());

        if !flashfs.root.entries.is_empty()
            && matches!(layout, NandLayout::Sb | NandLayout::Xsb | NandLayout::Bb)
            && target_fs_block >= 0
        {
            let page_size = 0x200usize;
            let pages_per_block = layout.logical_pages_per_block();
            let logical_block_size = pages_per_block * page_size;

            let bm_count = page_size / 2;
            let fn_count = page_size / 0x20;

            let non_deleted_count = flashfs
                .root
                .entries
                .iter()
                .filter(|e| !e.deleted)
                .count();
            let required_data_blocks: usize = flashfs
                .root
                .entries
                .iter()
                .filter(|e| !e.deleted)
                .map(|e| {
                    let len = e.data.len().max(1);
                    (len + logical_block_size - 1) / logical_block_size
                })
                .sum();

            let mut extra_non_deleted = 0usize;
            let mut extra_data_blocks = 0usize;
            if let (Some(cf0d), Some(cg0d)) = (cf0.as_ref(), cg0.as_ref()) {
                let cg0_offset = (target_cf_offset + cf0d.len() + 0xF) & !0xF;
                let slot0_end = target_cf_offset.saturating_add(0x10000);
                if cg0_offset < slot0_end {
                    let cg_to_slot = cg0d.len().min(slot0_end - cg0_offset);
                    if cg_to_slot < cg0d.len() {
                        let overflow_len = cg0d.len() - cg_to_slot;
                        let sys_name = "sysupdate.xexp1";
                        let existing = flashfs
                            .root
                            .entries
                            .iter()
                            .find(|e| !e.deleted && e.file_name.eq_ignore_ascii_case(sys_name))
                            .map(|e| e.data.len())
                            .unwrap_or(0);

                        if existing == 0 && overflow_len > 0 {
                            extra_non_deleted = 1;
                            extra_data_blocks =
                                (overflow_len + logical_block_size - 1) / logical_block_size;
                        } else if overflow_len > 0 {
                            let old_blocks =
                                (existing.max(1) + logical_block_size - 1) / logical_block_size;
                            let new_blocks =
                                ((existing + overflow_len).max(1) + logical_block_size - 1)
                                    / logical_block_size;
                            extra_data_blocks = new_blocks.saturating_sub(old_blocks);
                        }
                    }
                }
            }

            let max_entries_per_root_block = ((pages_per_block + 1) / 2) * fn_count;
            let max_bmap_per_root_block = (pages_per_block / 2) * bm_count;
            let total_blocks = layout.total_blocks(logical_image.len());

            let root_blocks_needed_for_entries =
                (non_deleted_count + extra_non_deleted + max_entries_per_root_block - 1)
                    / max_entries_per_root_block.max(1);
            let root_blocks_needed_for_bmap =
                (total_blocks + max_bmap_per_root_block - 1) / max_bmap_per_root_block.max(1);
            let root_blocks_needed = root_blocks_needed_for_entries
                .max(root_blocks_needed_for_bmap)
                .max(1);

            let reserve_start_u = reserve_start as usize;
            let config_start = reserve_start_u.saturating_sub(4);
            let available_blocks = config_start.saturating_sub(target_fs_block as usize);

            let required_total_blocks =
                required_data_blocks + extra_data_blocks + root_blocks_needed;

            if required_total_blocks > available_blocks {
                let patch_slots = if update.cf_1.is_some() {
                    2usize
                } else {
                    1usize
                };
                let patch_slot_size = patch_slots.saturating_mul(0x10000);
                let sysupdate_end = (target_cf_offset as usize).saturating_add(patch_slot_size);
                let min_fs_block =
                    ((sysupdate_end + logical_block_size - 1) / logical_block_size) as i32;
                let desired_start =
                    (config_start as i32).saturating_sub(required_total_blocks as i32);
                let new_start = desired_start.max(min_fs_block).max(4);

                if new_start < target_fs_block {
                    warn!(
                        "[builder] FlashFS target block {} leaves insufficient space (need {} blocks, have {}); moving start to {}",
                        target_fs_block, required_total_blocks, available_blocks, new_start
                    );
                    target_fs_block = new_start;
                }
            }
        }

        if !flashfs.root.entries.is_empty() && target_fs_block >= 0 {
            let fs_logical_addr =
                (target_fs_block as u32) * (layout.logical_pages_per_block() as u32) * 0x200;
            info!(
                "[builder] FlashFS root logical addr: 0x{:08X} (Block {})",
                fs_logical_addr, target_fs_block
            );
        }

        let kv_offset = header.kv_addr.get() as usize;
        if smc_len > 0 {
            if target_smc_offset + smc_len > logical_image.len() {
                return Err(BuilderError::SmcOutOfBounds {
                    offset: target_smc_offset,
                    size: smc_len,
                    image_len: logical_image.len(),
                });
            }
            logical_image[target_smc_offset..target_smc_offset + smc_len]
                .copy_from_slice(&self.extra.smc);
        }
        if !self.extra.keyvault.is_empty() {
            if kv_offset + self.extra.keyvault.len() > logical_image.len() {
                return Err(BuilderError::KvOutOfBounds {
                    offset: kv_offset,
                    size: self.extra.keyvault.len(),
                    image_len: logical_image.len(),
                });
            }
            logical_image[kv_offset..kv_offset + self.extra.keyvault.len()]
                .copy_from_slice(&self.extra.keyvault);
        }

        if let Some(cf0d) = cf0 {
            let cf0_offset = target_cf_offset;
            let reserve_two_slots = build_profile_l == "jtag"
                || build_profile_l == "1f"
                || build_profile_l == "2f"
                || build_profile_l == "devgl"
                || build_profile_l == "devkit"
                || build_profile_l == "xdkbuild"
                || build_profile_l.contains("glitch");

            let desired_patch_slots = if reserve_two_slots {
                2
            } else {
                if cf1.is_some() {
                    2
                } else {
                    1
                }
            };

            /*
            if self.options.dualpatchslots {
                if cf1.is_none() || cg1.is_none() {
                    return Err(BuilderError::Build(
                        "dualpatchslots is enabled but CF1/CG1 is missing".to_string(),
                    ));
                }
                header.patch_slots.set(2);
            } else {
                header.patch_slots.set(desired_patch_slots);
            }
            */

            header.patch_slots.set(desired_patch_slots);

            if cf0_offset + cf0d.len() > logical_image.len() {
                return Err(BuilderError::CfOverflow {
                    offset: cf0_offset,
                    need: cf0d.len(),
                });
            }
            logical_image[cf0_offset..cf0_offset + cf0d.len()].copy_from_slice(&cf0d);
            if cf0_offset + 2 <= logical_image.len() {
                let magic =
                    u16::from_be_bytes([logical_image[cf0_offset], logical_image[cf0_offset + 1]]);
                info!(
                    "[builder] CF0 magic at 0x{:08X}: 0x{:04X}",
                    cf0_offset, magic
                );
            }

            // If there is no second slot, zero it out so stale CF1/CG1 bytes from
            // the input NAND image are not carried into the output.
            if cf1.is_none() && header.patch_slots.get() >= 2 {
                let slot1_start = target_cf_offset + 0x10000;
                let slot1_end = (slot1_start + 0x10000).min(logical_image.len());
                if slot1_start < logical_image.len() {
                    logical_image[slot1_start..slot1_end].fill(0xFF);
                    info!(
                        "[builder] Cleared second CF/CG slot (0x{:X}..0x{:X}) — no CF1 present",
                        slot1_start, slot1_end
                    );
                }
            }

            let mut next_offset = cf0_offset + cf0d.len();

            if let Some(cg0d) = cg0 {
                // 16-byte align CG after CF
                let cg0_offset = (next_offset + 0xF) & !0xF;
                let max_slot_end = target_cf_offset + 0x10000;
                if cg0_offset >= max_slot_end {
                    warn!(
                        "[builder] CG0 starts at 0x{:X} which is past slot end 0x{:X}, skipping",
                        cg0_offset, max_slot_end
                    );
                    // Still advance past this slot so CF1 lands on the next 64KB boundary
                    next_offset = max_slot_end;
                } else {
                    let mut cg_to_slot = cg0d.len();
                    if cg0_offset + cg_to_slot > max_slot_end {
                        // CG overflows — write only the slot portion; overflow is in sysupdate.xexp1
                        cg_to_slot = max_slot_end - cg0_offset;
                    }
                    if cg0_offset + cg_to_slot > logical_image.len() {
                        return Err(BuilderError::CgOverflow {
                            offset: cg0_offset,
                            need: cg_to_slot,
                        });
                    }
                    logical_image[cg0_offset..cg0_offset + cg_to_slot]
                        .copy_from_slice(&cg0d[0..cg_to_slot]);
                    if cg_to_slot < cg0d.len() {
                        let overflow = &cg0d[cg_to_slot..];
                        let idx = flashfs.root.entries.iter().position(|e| {
                            !e.deleted && e.file_name.eq_ignore_ascii_case("sysupdate.xexp1")
                        });
                        match idx {
                            Some(i) => {
                                let mut new_data = Vec::with_capacity(
                                    overflow.len() + flashfs.root.entries[i].data.len(),
                                );
                                new_data.extend_from_slice(overflow);
                                new_data.extend_from_slice(&flashfs.root.entries[i].data);
                                flashfs.root.entries[i].data = new_data;
                                flashfs.root.entries[i].size =
                                    flashfs.root.entries[i].data.len() as u32;
                                info!("[builder] Prepended 0x{:X} CG0 overflow bytes to sysupdate.xexp1", overflow.len());
                            }
                            None => {
                                let mut entry =
                                    crate::builder::filesystem::flashfs::FileSystemEntry::new(0);
                                entry.file_name = "sysupdate.xexp1".to_string();
                                entry.data = overflow.to_vec();
                                entry.size = entry.data.len() as u32;
                                flashfs.root.entries.push(entry);
                                info!("[builder] Created sysupdate.xexp1 with 0x{:X} CG0 overflow bytes", overflow.len());
                            }
                        }
                    }
                    if cg0_offset + 2 <= logical_image.len() {
                        let magic = u16::from_be_bytes([
                            logical_image[cg0_offset],
                            logical_image[cg0_offset + 1],
                        ]);
                        info!(
                            "[builder] CG0 magic at 0x{:08X}: 0x{:04X}",
                            cg0_offset, magic
                        );
                    }
                    // Always advance to slot end so CF1 starts on the next clean 64KB block
                    next_offset = max_slot_end;
                }
            } else {
                // No CG0 — still advance to slot end so CF1 is placed at the next 64KB boundary
                // Should probably error here instead
                next_offset = target_cf_offset + 0x10000;
            }

            if let Some(cf1d) = cf1 {
                // Align CF1 to the next 64KB block after CG0
                let cf1_offset = (next_offset + 0xFFFF) & !0xFFFF;
                if cf1_offset + cf1d.len() > logical_image.len() {
                    return Err(BuilderError::CfOverflow {
                        offset: cf1_offset,
                        need: cf1d.len(),
                    });
                }
                logical_image[cf1_offset..cf1_offset + cf1d.len()].copy_from_slice(&cf1d);

                next_offset = cf1_offset + cf1d.len();

                if let Some(cg1d) = cg1 {
                    let cg1_offset = (next_offset + 0xF) & !0xF;
                    let max_slot_end = cf1_offset + 0x10000;
                    if cg1_offset >= max_slot_end {
                        warn!("[builder] CG1 starts at 0x{:X} which is past slot end 0x{:X}, skipping", cg1_offset, max_slot_end);
                    } else {
                        let mut cg_to_slot = cg1d.len();
                        if cg1_offset + cg_to_slot > max_slot_end {
                            cg_to_slot = max_slot_end - cg1_offset;
                        }
                        if cg1_offset + cg_to_slot > logical_image.len() {
                            return Err(BuilderError::CgOverflow {
                                offset: cg1_offset,
                                need: cg_to_slot,
                            });
                        }
                        logical_image[cg1_offset..cg1_offset + cg_to_slot]
                            .copy_from_slice(&cg1d[0..cg_to_slot]);
                        if cg_to_slot < cg1d.len() {
                            let overflow = &cg1d[cg_to_slot..];
                            let idx = flashfs.root.entries.iter().position(|e| {
                                !e.deleted && e.file_name.eq_ignore_ascii_case("sysupdate.xexp2")
                            });
                            match idx {
                                Some(i) => {
                                    let mut new_data = Vec::with_capacity(
                                        overflow.len() + flashfs.root.entries[i].data.len(),
                                    );
                                    new_data.extend_from_slice(overflow);
                                    new_data.extend_from_slice(&flashfs.root.entries[i].data);
                                    flashfs.root.entries[i].data = new_data;
                                    flashfs.root.entries[i].size =
                                        flashfs.root.entries[i].data.len() as u32;
                                    info!("[builder] Prepended 0x{:X} CG1 overflow bytes to sysupdate.xexp2", overflow.len());
                                }
                                None => {
                                    let mut entry =
                                        crate::builder::filesystem::flashfs::FileSystemEntry::new(
                                            0,
                                        );
                                    entry.file_name = "sysupdate.xexp2".to_string();
                                    entry.data = overflow.to_vec();
                                    entry.size = entry.data.len() as u32;
                                    flashfs.root.entries.push(entry);
                                    info!("[builder] Created sysupdate.xexp2 with 0x{:X} CG1 overflow bytes", overflow.len());
                                }
                            }
                        }
                    }
                }
            }
        }

        let has_vfuses = self.payloads.as_ref().map_or(false, |p| {
            p.iter()
                .any(|p| p.description.eq_ignore_ascii_case("virtual fuses"))
        });
        let patch_slot_size: u32 = 0x10000;

        let xell_payloads = [
            (self.bootloaders.xell.as_ref(), false),
        ];

        for (xell_opt, _is_rebooter) in xell_payloads {
            if let Some(xell) = xell_opt {
                let x_type = xell.identify();
                let xell_offset = xell
                    .get_target_offset(
                        layout,
                        &build_profile,
                        has_vfuses,
                        header.cf_offset.get(),
                        patch_slot_size,
                    )
                    .map_err(|e| e.to_string())? as usize;
                if xell_offset + xell.data.len() > logical_image.len() {
                    return Err(BuilderError::XellOffset(format!(
                        "XeLL ({:?}) overflow at 0x{:X}: need 0x{:X} bytes",
                        x_type,
                        xell_offset,
                        xell.data.len()
                    )));
                }
                info!(
                    "[builder] Injecting XeLL payload ({:?}) at offset 0x{:08X}",
                    x_type, xell_offset
                );
                logical_image[xell_offset..xell_offset + xell.data.len()]
                    .copy_from_slice(&xell.data);
            }
        }

        header.fs_addr.set(patch_slot_size);

        let patch_stream_start = (header.cf_offset.get() as usize)
            .saturating_add(patch_slot_size as usize)
            .saturating_add(if has_vfuses { 0x60 } else { 0x10 });

        let khv_len = 0usize;
        /*
        if let Some(records) = &self.bootloaders.khvpatch {
            if !self.options.khv_apply {
                let patch_stream = serialize_records(records);
                khv_len = patch_stream.len();
                if patch_stream_start + khv_len > logical_image.len() {
                    return Err(BuilderError::KhvOverflow {
                        offset: patch_stream_start,
                        need: khv_len,
                    });
                }
                logical_image[patch_stream_start..patch_stream_start + khv_len]
                    .copy_from_slice(&patch_stream);
                info!(
                    "[builder] Injected KHV patch stream at 0x{:08X} (Size: 0x{:X})",
                    patch_stream_start, khv_len
                );

                let logical_block_size = layout.logical_pages_per_block() * 0x200;
                let start_block = patch_stream_start / logical_block_size;
                let end_block =
                    (patch_stream_start + khv_len + logical_block_size - 1) / logical_block_size;
                for b in start_block..end_block {
                    if b < self.flashfs.root.block_map.len() {
                        self.flashfs.root.block_map[b] = 0x1FFB;
                    }
                }
            }
        }
        */
        let mut final_payloads = self.payloads.clone().unwrap_or_default();
        let mut current_payload_offset = (patch_stream_start + khv_len + 0x1F) & !0x1F;
        let mut payload_list = PayloadList::new();

        for payload in &mut final_payloads {
            let addr = if let Some(fixed) = payload.fixed_address {
                fixed as usize
            } else {
                current_payload_offset
            };

            payload.address = addr as u32;
            payload_list.entries.push(payload.clone());

            // Reserve blocks in FlashFS to prevent overwriting
            let logical_block_size = layout.logical_pages_per_block() * 0x200;
            let start_block = addr / logical_block_size;
            let end_block =
                (addr + payload.data.len() + logical_block_size - 1) / logical_block_size;

            for b in start_block..end_block {
                if b < flashfs.root.block_map.len() {
                    flashfs.root.block_map[b] = 0x1FFB;
                }
            }

            if payload.fixed_address.is_none() {
                current_payload_offset =
                    (current_payload_offset + payload.data.len() + 0x1F) & !0x1F;
            }
        }

        if !payload_list.entries.is_empty() {
            header.payload_indicator.set(0x1337);

            let table_data = payload_list.serialize();
            if table_data.len() > 0x100 {
                warn!("[builder] Payload Table at 0x100 exceeds 256 bytes! This may overwrite other header data.");
            }
            let table_len = table_data.len().min(0x100);
            logical_image[0x100..0x100 + table_len].copy_from_slice(&table_data[..table_len]);

            for payload in &payload_list.entries {
                let addr = payload.address as usize;
                if addr + payload.data.len() > logical_image.len() {
                    logical_image.resize(addr + payload.data.len(), 0xFF);
                }
                logical_image[addr..addr + payload.data.len()].copy_from_slice(&payload.data);
                info!(
                    "[builder] Injected payload '{}' at 0x{:08X} (Size: 0x{:X})",
                    payload.description,
                    addr,
                    payload.data.len()
                );
            }
        }

        header.prefix.entrypoint.set(bootchain_start as u32);
        header.apply_xebuild_header_flags(&self.options);
        let header_bytes = zerocopy::IntoBytes::as_bytes(&header);
        logical_image[..header_bytes.len()].copy_from_slice(header_bytes);

        let mut partitions_to_write = std::collections::HashMap::new();
        if !flashfs.root.entries.is_empty() && target_fs_block >= 0 {
            partitions_to_write.insert(flashfs.root.partition_type, flashfs.root.clone());
        }

        for (btype, mut root) in partitions_to_write {
            if root.entries.is_empty() {
                continue;
            }

            if btype == 0x30 || btype == 0x2C {
                if target_fs_block >= 0 {
                    root.block_number = target_fs_block;
                }
            }

            if root.block_number < 0 {
                warn!(
                    "[builder] FlashFS partition 0x{:02X} has no block number assigned, skipping",
                    btype
                );
                continue;
            }

            root.create_defaults(logical_image.len(), &layout, root.block_number as u16);
            for e in root.entries.iter_mut() {
                if !e.deleted {
                    e.block_number = 0;
                    e.page_number = 0;
                }
            }
            let logical_block_size = layout.logical_pages_per_block() * 0x200;
            let protect_range =
                |start: usize,
                 len: usize,
                 root: &mut crate::builder::filesystem::flashfs::FileSystemRoot| {
                    if len == 0 {
                        return;
                    }
                    let start_block = start / logical_block_size;
                    let end_block = (start + len + logical_block_size - 1) / logical_block_size;
                    for b in start_block..end_block {
                        if b < root.block_map.len() {
                            root.block_map[b] = 0x1FFB;
                        }
                    }
                };
            protect_range(target_smc_offset, smc_len, &mut root);
            protect_range(kv_offset, self.extra.keyvault.len(), &mut root);
            protect_range(
                bootchain_start,
                curr_bl.saturating_sub(bootchain_start),
                &mut root,
            );
            protect_range(
                target_cf_offset,
                header.patch_slots.get().max(1) as usize * 0x10000,
                &mut root,
            );
            if khv_len > 0 {
                protect_range(patch_stream_start, khv_len, &mut root);
            }
            for payload in &payload_list.entries {
                let addr = payload.address as usize;
                let start_block = addr / logical_block_size;
                let end_block =
                    (addr + payload.data.len() + logical_block_size - 1) / logical_block_size;
                for b in start_block..end_block {
                    if b < root.block_map.len() {
                        root.block_map[b] = 0x1FFB;
                    }
                }
            }

            let fs_block = root.block_number as usize;
            let fs_offset = fs_block * layout.logical_pages_per_block() * 0x200;

            info!(
                "[builder] Writing FlashFS partition 0x{:02X} at block {} (offset 0x{:08X})",
                btype, fs_block, fs_offset
            );

            root.write_logical(&mut logical_image, &layout)?;

            let fs_root_block = root.serialize_logical(layout);

            if fs_offset + fs_root_block.len() <= logical_image.len() {
                logical_image[fs_offset..fs_offset + fs_root_block.len()]
                    .copy_from_slice(&fs_root_block);
            } else {
                error!("[builder] FlashFS partition 0x{:02X} root block exceeds image bounds at block {}", btype, fs_block);
            }

            if btype == flashfs.root.partition_type {
                flashfs.root = root;
            }
        }

        if mobile.latest.iter().any(|s| s.is_some()) {
            let fs_start: u16 = match layout {
                NandLayout::Bb => std::cmp::max(4u16, flashfs.root.block_number.max(0) as u16),
                _ => 0x4E,
            };
            if flashfs.root.block_map.is_empty() {
                flashfs
                    .root
                    .create_defaults(logical_image.len(), &layout, fs_start);
            }
            mobile.write_logical(&mut logical_image, &layout, &mut flashfs.root);
        }

        if layout == NandLayout::Emmc {
            corona::write_back(
                &mut logical_image,
                corona_fs,
                &flashfs.root,
                mobile,
            )?;
        }

        Ok(logical_image)
    }

    pub fn build(&self, cpukey: [u8; 16]) -> Result<Vec<u8>> {
        let mut skel = self.clone();
        skel.build_in_place(cpukey)
    }

    pub fn build_in_place(&mut self, cpukey: [u8; 16]) -> Result<Vec<u8>> {
        let skel = self;
        skel.cpukey = Some(cpukey);
        info!(
            "[builder] Starting final image build (Profile: {}, Mode: {:?})...",
            skel.options.image_profile, skel.options.build_mode
        );
        let mut smc_for_hash = skel.extra.smc.clone();
        smc_crypt(&mut smc_for_hash, true);
        let smc_hash = calculate_smc_hash(&smc_for_hash);

        skel.prepare_for_assembly()?;

        if let Some(cb) = skel
            .bootloaders
            .cb_a
            .as_mut()
            .or(skel.bootloaders.cb.as_mut())
        {
            if cb.metadata.is_some() {
                if let Some(rc4_key) = cb.derived_key() {
                    cb.recalculate_per_box_digest(&cpukey, &rc4_key, &smc_hash);
                } else {
                    log::warn!("[builder] CB_A/CB has no derived key, skipping per-box digest recalculation");
                }
            }
        }

        if let Some(cb_b) = skel.bootloaders.cb_b.as_mut() {
            if cb_b.metadata.is_some() {
                if let Some(rc4_key) = cb_b.derived_key() {
                    cb_b.recalculate_per_box_digest(&cpukey, &rc4_key, &smc_hash);
                } else {
                    log::warn!("[builder] CB_B has no derived key, skipping per-box digest recalculation");
                }
            }
        }

        let update = skel.update.get_or_insert_with(NandUpdate::default);

        let ldv0 = update
            .cf_0
            .as_ref()
            .and_then(|cf| cf.metadata.as_ref().map(|m| m.lockdown_value));
        let ldv1 = update
            .cf_1
            .as_ref()
            .and_then(|cf| cf.metadata.as_ref().map(|m| m.lockdown_value));
        let current_max = match (ldv0, ldv1) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            _ => None,
        };

        if let Some(h) = current_max {
            if let Some(meta) = update
                .cf_0
                .as_mut()
                .and_then(|cf| cf.metadata.as_mut())
            {
                if meta.lockdown_value != h {
                    info!("[builder] Syncing CF_0 LDV to target: {}", h);
                    meta.lockdown_value = h;
                }
            }
            if let Some(meta) = update
                .cf_1
                .as_mut()
                .and_then(|cf| cf.metadata.as_mut())
            {
                if meta.lockdown_value != h {
                    info!("[builder] Syncing CF_1 LDV to target: {}", h);
                    meta.lockdown_value = h;
                }
            }
        }

        if let Some(ref mut kv) = skel.kv {
            info!("[builder] Encrypting Keyvault...");
            kv.encrypt(&cpukey)
                .map_err(|e| BuilderError::Build(e.to_string()))?;
            skel.extra.keyvault = kv.data.clone();
        } else {
            warn!(
                "[builder] No internal Keyvault object found, using raw bytes from extra.keyvault"
            );
        }

        let mut smc = crate::builder::chain::smc::RawSmc::new(skel.extra.smc.clone());
        smc.ensure_decrypted();
        info!("[builder] Re-encrypting bootloader chain...");
        let profile_l = skel.options.image_profile.to_ascii_lowercase();
        let profile_base = profile_l.split('_').next().unwrap_or("");
        let keep_cd_plaintext = matches!(profile_base, "glitch" | "glitch1" | "glitch2" | "glitch3");

        encrypt_chain(
            skel.bootloaders
                .cb_a
                .as_mut()
                .or(skel.bootloaders.cb.as_mut())
                .ok_or("Missing primary CB (CB or CB_A) for encryption")?,
            skel.bootloaders.cb_x.as_mut(),
            skel.bootloaders.cb_b.as_mut(),
            skel.bootloaders.sc.as_mut(),
            skel.bootloaders
                .cd
                .as_mut()
                .ok_or("Missing CD for encryption")?,
            skel.bootloaders
                .ce
                .as_mut()
                .ok_or("Missing CE for encryption")?,
            update.cf_0.as_mut(),
            update.cg_0.as_mut(),
            update.cf_1.as_mut(),
            update.cg_1.as_mut(),
            &mut smc,
            &cpukey,
            keep_cd_plaintext,
        )?;

        info!("[builder] Re-encrypting SMC...");
        let scramble_smc = skel
            .options
            .image_profile
            .to_ascii_lowercase()
            .contains("glitch3");
        smc.encrypt_with_scramble(scramble_smc);
        skel.extra.smc = smc.data;

        skel.assemble_logical()
    }

    pub fn apply_patch(&mut self, patch: GxpBinary) -> Result<()> {
        /*
        if let Some(khv) = patch.khv {
            info!(
                "[builder] Routing {} KHV patch records to options slot...",
                khv.records.len()
            );
            self.bootloaders.khvpatch = Some(
                khv.records
                    .iter()
                    .map(|r| PatchRecord {
                        address: r.address,
                        amount: r.amount,
                        data: r.data.clone(),
                    })
                    .collect(),
            );
        }
        */
        if let Some(cb_b) = patch.cb_b {
            if patch.header.patch_type == GxpPatchType::Rgh4Section {
                if let Some(cbb_bl) = &mut self.bootloaders.cb_b {
                    info!("[builder] Applying RGH Section 0 patches to CB_B");
                    apply_records(&cb_b.records, &mut cbb_bl.data).map_err(|e| e.to_string())?;
                }
            }
        }

        if let Some(cb) = patch.cb {
                if let Some(cbb_bl) = &mut self.bootloaders.cb_b {
                    info!("[builder] Split/Glitch3 CB: Applying primary patch section to CB_B");
                    apply_records(&cb.records, &mut cbb_bl.data).map_err(|e| e.to_string())?;
                } else if let Some(cb_bl) = &mut self.bootloaders.cb {
                    info!("[builder] Single CB: Applying patches to CB");
                    apply_records(&cb.records, &mut cb_bl.data).map_err(|e| e.to_string())?;
                }
        }

        if let Some(cd) = patch.cd {
            if let Some(cd_bl) = &mut self.bootloaders.cd {
                info!("[builder] Applying patches to CD (Filesystem Driver)");
                apply_records(&cd.records, &mut cd_bl.data).map_err(|e| e.to_string())?;
            }
        }

        if let Some(smc) = patch.smc {
            info!(
                "[builder] Applying {} records to decrypted SMC buffer",
                smc.records.len()
            );
            apply_records(&smc.records, &mut self.extra.smc).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    pub fn inject_security_file(&mut self, name: &str, data: &[u8], fs_start: u16) {
        // For now, this is a placeholder implementation
        // In a full implementation, this would inject the security file into the filesystem
        log::info!(
            "[builder] Injecting security file: {} ({} bytes) at fs_start: 0x{:X}",
            name,
            data.len(),
            fs_start
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::chain::BootloaderHeader;

    #[test]
    fn test_nand_layout_defaults_sb() {
        let skeleton = NandSkeleton::new_blank(NandLayout::Sb);
        assert_eq!(skeleton.image.len(), 0x1000000);
        assert_eq!(skeleton.header.kv_addr.get(), 0x4000);
        assert_eq!(skeleton.header.smc_boot_offset.get(), 0x1000); // SB: 0x4000 - 0x3000
        assert_eq!(skeleton.header.smc_boot_size.get(), 0x3000);
        assert_eq!(skeleton.header.fs_addr.get(), 0x10000);
        assert_eq!(skeleton.header.cf_offset.get(), 0x70000);
    }

    #[test]
    fn test_nand_layout_defaults_bb() {
        let skeleton = NandSkeleton::new_blank(NandLayout::Bb);
        assert_eq!(skeleton.image.len(), 0x4000000);
        assert_eq!(skeleton.header.kv_addr.get(), 0x4000);
        assert_eq!(skeleton.header.smc_boot_offset.get(), 0x1000); // BB: 0x4000 - 0x3000
        assert_eq!(skeleton.header.smc_boot_size.get(), 0x3000);
        assert_eq!(skeleton.header.fs_addr.get(), 0x10000);
        assert_eq!(skeleton.header.cf_offset.get(), 0x80000);
    }

    #[test]
    fn test_nand_layout_defaults_emmc() {
        let skeleton = NandSkeleton::new_blank(NandLayout::Emmc);
        assert_eq!(skeleton.image.len(), 0x3000000);
        assert_eq!(skeleton.header.kv_addr.get(), 0x4000);
        assert_eq!(skeleton.header.smc_boot_offset.get(), 0x800); // eMMC: 0x4000 - 0x3800
        assert_eq!(skeleton.header.smc_boot_size.get(), 0x3800); // eMMC SMC is 0x3800 bytes
        assert_eq!(skeleton.header.smc_config_offset.get(), 0x0); // eMMC header field is 0x0
        assert_eq!(skeleton.header.fs_addr.get(), 0x10000); // FileSystemAddress
        assert_eq!(skeleton.header.cf_offset.get(), 0xB0000);
    }

    #[test]
    fn test_dynamic_smc_placement() {
        let mut skeleton = NandSkeleton::new_blank(NandLayout::Sb);
        skeleton.extra.smc = vec![0; 0x3200]; // custom larger SMC

        let logical = skeleton.assemble_logical().unwrap();
        // 0x4000 - 0x3200 = 0x0E00
        let target_offset = 0x0E00;

        // Check header reflects new offset
        let header = NandHeader::read_from_prefix(&logical).unwrap().0;
        assert_eq!(header.smc_boot_offset.get(), target_offset as u32);
        assert_eq!(header.smc_boot_size.get(), 0x3200);
    }

    #[test]
    fn test_xebuild_header_flags() {
        let skeleton = NandSkeleton::new_blank(NandLayout::Sb);

        let mut retail_header = skeleton.header.clone();
        retail_header.copyright[0x3E] = 0xAA;
        retail_header.copyright[0x3F] = 0xBB;
        let mut retail_opts = skeleton.options.clone();
        retail_opts.image_profile = "retail".to_string();
        retail_header.apply_xebuild_header_flags(&retail_opts);
        assert_eq!(retail_header.copyright[0x3B], 0);
        assert_eq!(retail_header.copyright[0x3E], 0xAA);
        assert_eq!(retail_header.copyright[0x3F], 0xBB);

        let mut devkit_header = skeleton.header.clone();
        devkit_header.copyright[0x3E] = 0xAA;
        devkit_header.copyright[0x3F] = 0xBB;
        let mut devkit_opts = skeleton.options.clone();
        devkit_opts.image_profile = "devkit".to_string();
        devkit_header.apply_xebuild_header_flags(&devkit_opts);
        assert_eq!(devkit_header.copyright[0x3B], 0);
        assert_eq!(devkit_header.copyright[0x3E], 0xAA);
        assert_eq!(devkit_header.copyright[0x3F], 0xBB);

        let mut hacked_header = skeleton.header.clone();
        let mut hacked_opts = skeleton.options.clone();
        hacked_opts.image_profile = "glitch2".to_string();
        hacked_header.apply_xebuild_header_flags(&hacked_opts);
        assert_eq!(hacked_header.copyright[0x3B], 1);
        assert_eq!(hacked_header.copyright[0x3E], 0x00);
        assert_eq!(hacked_header.copyright[0x3F], 0x12);

        let mut xdk_header = skeleton.header.clone();
        let mut xdk_opts = skeleton.options.clone();
        xdk_opts.image_profile = "xdkbuild".to_string();
        xdk_header.apply_xebuild_header_flags(&xdk_opts);
        assert_eq!(xdk_header.copyright[0x3B], 1);
        assert_eq!(xdk_header.copyright[0x3E], 0x00);
        assert_eq!(xdk_header.copyright[0x3F], 0x12);
    }

    #[test]
    fn test_bootchain_overflow_realignment() {
        let mut skeleton = NandSkeleton::new_blank(NandLayout::Sb);
        // Create a fake massive CD bootloader to force realignment
        // SB CF 0x70000. 2BL base 0x8000.
        // We need CD to extend past 0x70000.
        let large_cd = vec![0u8; 0x69000]; // 0x8000 + 0x69000 = 0x71000 (overflows standard 0x70000)

        let bl_header = BootloaderHeader {
            magic: U16::new(0x4344), // 'CD'
            version: U16::new(1888),
            pairing: U16::new(0),
            flags: U16::new(0),
            entrypoint: U32::new(0),
            size: U32::new(0x69000),
        };

        skeleton.bootloaders.cd = Some(crate::builder::chain::cd::BootloaderCd {
            header: bl_header,
            data: large_cd,
            derived_key: None,
            metadata: None,
        });

        let logical = skeleton.assemble_logical().unwrap();
        let header = NandHeader::read_from_prefix(&logical).unwrap().0;

        // Expected realignment to next 64KB block: (0x71000 + 0xFFFF) & 0xFFFF0000 = 0x80000
        assert_eq!(header.cf_offset.get(), 0x80000);
    }
}
