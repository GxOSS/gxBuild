/*
  ecc.rs - ECC image extraction and handling.

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

use crate::builder::chain::{
    cb::BootloaderCb, cd::BootloaderCd, ce::BootloaderCe, cf::BootloaderCf, cg::BootloaderCg,
    sc::BootloaderSc, smc::RawSmc, BootloaderHeader, XenonBlType,
};
use crate::builder::nand::types::{BuilderError, Result};
use crate::core::images::blocks::NandLayout;
use log::info;
use std::path::Path;
use zerocopy::FromBytes;
use crate::core::images::blocks::strip_ecc;
use crate::builder::nand::types::*;


/// Smaller skeleton structure for ECC extraction.
/// Holds extracted components without the full builder state.
#[derive(Clone, Default)]
pub struct EccSkeleton {
    pub header: Option<NandHeader>,
    pub bootloaders: NandBootloaders,
    pub update: NandUpdate,
    pub extra: NandExtra,
    pub layout: Option<NandLayout>,
    pub xell: Vec<(u32, Vec<u8>)>, // (offset, data) pairs
}

impl EccSkeleton {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse and extract components from an ECC image.
    pub fn from_ecc<P: AsRef<Path>>(ecc_path: P) -> Result<Self> {
        let ecc_raw = std::fs::read(ecc_path.as_ref())?;

        let clean = strip_ecc(&ecc_raw);
        let layout = NandLayout::detect(&ecc_raw)
            .or_else(|_| NandLayout::detect(&clean))
            .ok();

        let mut skeleton = Self {
            layout,
            ..Default::default()
        };

        // Try to parse header
        let header_sz = std::mem::size_of::<NandHeader>();
        if clean.len() >= header_sz {
            if let Ok((h, _)) = NandHeader::read_from_prefix(&clean[..header_sz]) {
                if h.validate().is_ok() {
                    skeleton.header = Some(h);
                }
            }
        }

        // Extract SMC if header present
        if let Some(ref h) = skeleton.header {
            let smc_off = h.smc_boot_offset.get() as usize;
            let smc_sz = h.smc_boot_size.get() as usize;
            if smc_off > 0 && smc_sz > 0 && smc_off.saturating_add(smc_sz) <= clean.len() {
                let smc_data = &clean[smc_off..smc_off + smc_sz];
                if smc_data.iter().any(|b| *b != 0xFF) {
                    skeleton.extra.smc = smc_data.to_vec();
                }
            }
        } else if clean.len() >= 0x4000 {
            // Fallback SMC location
            let smc_off = 0x1000usize;
            let smc_sz = 0x3000usize;
            if smc_off.saturating_add(smc_sz) <= clean.len() {
                let smc_data = &clean[smc_off..smc_off + smc_sz];
                if smc_data.iter().any(|b| *b != 0xFF) {
                    skeleton.extra.smc = smc_data.to_vec();
                }
            }
        }

        // Walk the bootloader chain
        let cb_offset = skeleton
            .header
            .as_ref()
            .map(|h| h.cb_offset() as usize)
            .unwrap_or(0x8000);
        let cf_ptr = skeleton
            .header
            .as_ref()
            .map(|h| h.cf_offset.get() as usize)
            .unwrap_or(0);

        skeleton.walk_chain(&clean, cb_offset, cf_ptr)?;

        // Scan for XeLL
        skeleton.scan_xell(&clean);

        Ok(skeleton)
    }

    /// Walk the bootloader chain and extract components.
    fn walk_chain(&mut self, clean: &[u8], start_off: usize, cf_ptr: usize) -> Result<()> {
        let mut off = start_off;
        let mut cf_count = 0usize;
        let mut cg_count = 0usize;
        let mut cb_seen = 0usize;
        let mut cbx_written = false;

        for _ in 0..16 {
            if off.saturating_add(0x10) > clean.len() {
                break;
            }

            let blh = match BootloaderHeader::read_from_prefix(&clean[off..off + 0x10]) {
                Ok((v, _)) => v,
                Err(_) => break,
            };

            let bl_size = blh.size.get() as usize;
            if bl_size < 0x10 || bl_size > 0x2000000 || off.saturating_add(bl_size) > clean.len() {
                break;
            }

            let data = &clean[off..off + bl_size];

            match blh.get_type() {
                XenonBlType::CB => {
                    cb_seen += 1;
                    let flags = blh.flags.get();
                    let has_cba_flag = (flags & 0x800) == 0x800;
                    let is_single = cb_seen == 1 && !has_cba_flag;
                    let is_cba = cb_seen == 1 && has_cba_flag;
                    let is_cbx = cb_seen == 2
                        && has_cba_flag
                        && bl_size <= 0x800
                        && (blh.version.get() == 0x3C48 || bl_size == 0x400);

                    if is_single {
                        self.bootloaders.cb = Some(
                            BootloaderCb::parse(data)
                                .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                        );
                    } else if is_cba {
                        self.bootloaders.cb_a = Some(
                            BootloaderCb::parse(data)
                                .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                        );
                    } else if is_cbx {
                        self.bootloaders.cb_x = Some(
                            BootloaderCb::parse(data)
                                .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                        );
                        cbx_written = true;
                    } else {
                        self.bootloaders.cb_b = Some(
                            BootloaderCb::parse(data)
                                .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                        );
                    }
                }
                XenonBlType::SC => {
                    self.bootloaders.sc = Some(
                        BootloaderSc::parse(data)
                            .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                    );
                }
                XenonBlType::CD => {
                    self.bootloaders.cd = Some(
                        BootloaderCd::parse(data)
                            .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                    );
                }
                XenonBlType::CE => {
                    self.bootloaders.ce = Some(
                        BootloaderCe::parse(data)
                            .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                    );
                }
                XenonBlType::CF => {
                    if cf_count == 0 {
                        self.update.cf_0 = Some(
                            BootloaderCf::parse(data)
                                .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                        );
                    } else {
                        self.update.cf_1 = Some(
                            BootloaderCf::parse(data)
                                .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                        );
                    }
                    cf_count += 1;
                }
                XenonBlType::CG => {
                    if cg_count == 0 {
                        self.update.cg_0 = Some(
                            BootloaderCg::parse(data)
                                .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                        );
                    } else {
                        self.update.cg_1 = Some(
                            BootloaderCg::parse(data)
                                .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                        );
                    }
                    cg_count += 1;
                }
                _ => break,
            }

            off = off.saturating_add((bl_size + 0xF) & 0xFFFF_FFF0);
        }

        // Scan for CBX if not found in main chain
        if !cbx_written && clean.len() > 0x8010 {
            self.scan_cbx(clean)?;
        }

        // Scan for CF/CG at CF pointer if not found
        if cf_count == 0 && cf_ptr > 0 && cf_ptr.saturating_add(0x10) <= clean.len() {
            self.scan_cf_chain(clean, cf_ptr, &mut cf_count, &mut cg_count)?;
        }

        Ok(())
    }

    /// Scan for CBX bootloader in the 0x8000-0x20000 range.
    fn scan_cbx(&mut self, clean: &[u8]) -> Result<()> {
        let scan_end = std::cmp::min(clean.len().saturating_sub(0x10), 0x20000);
        let mut scan_off = 0x8000usize;

        while scan_off < scan_end {
            if let Ok((blh, _)) =
                BootloaderHeader::read_from_prefix(&clean[scan_off..scan_off + 0x10])
            {
                if blh.get_type() == XenonBlType::CB {
                    let bl_size = blh.size.get() as usize;
                    let flags = blh.flags.get();
                    let has_cba_flag = (flags & 0x800) == 0x800;

                    if has_cba_flag
                        && bl_size >= 0x10
                        && bl_size <= 0x800
                        && scan_off.saturating_add(bl_size) <= clean.len()
                        && (blh.version.get() == 0x3C48 || bl_size == 0x400)
                    {
                        let data = &clean[scan_off..scan_off + bl_size];
                        self.bootloaders.cb_x = Some(
                            BootloaderCb::parse(data)
                                .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                        );
                        break;
                    }
                }
            }
            scan_off = scan_off.saturating_add(0x10);
        }

        Ok(())
    }

    /// Scan for CF/CG chain at the specified offset.
    fn scan_cf_chain(
        &mut self,
        clean: &[u8],
        mut scan_off: usize,
        cf_count: &mut usize,
        cg_count: &mut usize,
    ) -> Result<()> {
        for _ in 0..8 {
            if scan_off.saturating_add(0x10) > clean.len() {
                break;
            }

            let blh = match BootloaderHeader::read_from_prefix(&clean[scan_off..scan_off + 0x10]) {
                Ok((v, _)) => v,
                Err(_) => break,
            };

            let bl_size = blh.size.get() as usize;
            if bl_size < 0x10
                || bl_size > 0x2000000
                || scan_off.saturating_add(bl_size) > clean.len()
            {
                break;
            }

            let data = &clean[scan_off..scan_off + bl_size];

            match blh.get_type() {
                XenonBlType::CF => {
                    if *cf_count == 0 {
                        self.update.cf_0 = Some(
                            BootloaderCf::parse(data)
                                .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                        );
                    } else {
                        self.update.cf_1 = Some(
                            BootloaderCf::parse(data)
                                .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                        );
                    }
                    *cf_count += 1;
                }
                XenonBlType::CG => {
                    if *cg_count == 0 {
                        self.update.cg_0 = Some(
                            BootloaderCg::parse(data)
                                .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                        );
                    } else {
                        self.update.cg_1 = Some(
                            BootloaderCg::parse(data)
                                .map_err(|e| BuilderError::Bootloader(e.to_string()))?,
                        );
                    }
                    *cg_count += 1;
                }
                _ => break,
            }

            scan_off = scan_off.saturating_add((bl_size + 0xF) & 0xFFFF_FFF0);
        }

        Ok(())
    }

    /// Scan for XeLL payloads at known offsets.
    fn scan_xell(&mut self, clean: &[u8]) {
        const CANDIDATES: [usize; 5] = [0x70000, 0xC0000, 0x100000, 0x10_0000, 0xE2_A600];

        for off in CANDIDATES {
            if off.saturating_add(4) > clean.len() {
                continue;
            }

            let magic = &clean[off..off + 4];
            if magic != b"XeLL" && magic != b"Xell" {
                continue;
            }

            let max_len = std::cmp::min(0x40000usize, clean.len() - off);
            let mut payload = clean[off..off + max_len].to_vec();

            // Trim trailing 0xFF bytes
            while payload.last().is_some_and(|b| *b == 0xFF) {
                payload.pop();
            }

            if payload.len() < 0x1000 {
                payload = clean[off..off + max_len].to_vec();
            }

            self.xell.push((off as u32, payload));
        }
    }

    /// Write all extracted components to the specified directory.
    pub fn write_to_dir<P: AsRef<Path>>(&self, output_dir: P) -> Result<usize> {
        let _ = std::fs::create_dir_all(output_dir.as_ref());
        let mut wrote = 0usize;

        // Write header
        if let Some(ref h) = self.header {
            let path = output_dir.as_ref().join("NandHeader.bin");
            std::fs::write(&path, zerocopy::IntoBytes::as_bytes(h))?;
            wrote += 1;
        }

        // Write SMC
        if !self.extra.smc.is_empty() {
            let enc_path = output_dir.as_ref().join("SMC_en.bin");
            std::fs::write(&enc_path, &self.extra.smc)?;
            wrote += 1;

            // Try to decrypt and write decrypted version
            let mut dec = RawSmc::new(self.extra.smc.clone());
            dec.ensure_decrypted();
            if self.smc_looks_decrypted(&dec.data) {
                let dec_path = output_dir.as_ref().join("SMC_dec.bin");
                std::fs::write(&dec_path, &dec.data)?;
                wrote += 1;
            }
        }

        // Write bootloaders
        macro_rules! write_bl {
            ($opt:expr, $name:expr) => {
                if let Some(ref bl) = $opt {
                    let path = output_dir.as_ref().join($name);
                    std::fs::write(&path, bl.serialize())?;
                    wrote += 1;
                }
            };
        }

        write_bl!(self.bootloaders.cb, "CB.bin");
        write_bl!(self.bootloaders.cb_a, "CBA.bin");
        write_bl!(self.bootloaders.cb_x, "CBX.bin");
        write_bl!(self.bootloaders.cb_b, "CBB.bin");
        write_bl!(self.bootloaders.sc, "SC.bin");
        write_bl!(self.bootloaders.cd, "CD.bin");
        write_bl!(self.bootloaders.ce, "CE.bin");
        write_bl!(self.update.cf_0, "CF_0.bin");
        write_bl!(self.update.cf_1, "CF_1.bin");
        write_bl!(self.update.cg_0, "CG_0.bin");
        write_bl!(self.update.cg_1, "CG_1.bin");

        // Write XeLL payloads
        for (off, data) in &self.xell {
            let name = format!("XeLL_0x{:X}.bin", off);
            let path = output_dir.as_ref().join(&name);
            std::fs::write(&path, data)?;
            wrote += 1;
        }

        Ok(wrote)
    }

    /// Check if SMC appears to be decrypted.
    fn smc_looks_decrypted(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let scan_len = std::cmp::min(data.len(), 0x200);
        data[..scan_len]
            .windows(b"Microsoft".len())
            .any(|w| w == b"Microsoft")
    }
}

/// High-level function to extract an ECC image to a directory.
/// Returns the number of files written.
pub fn extract_ecc<P: AsRef<Path>>(ecc_path: P, output_dir: P) -> Result<usize> {
    let skeleton = EccSkeleton::from_ecc(ecc_path)?;
    let count = skeleton.write_to_dir(output_dir)?;

    info!("[ecc] Extracted {} component(s) from ECC image", count);

    Ok(count)
}

/// Handle ECC extraction with full logging for CLI usage.
/// This is the main entry point for the extract command when dealing with ECC images.
pub fn handle_extract_ecc<P: AsRef<Path>>(ecc_path: P, output_dir: P) -> Result<usize> {
    let ecc_path = ecc_path.as_ref();
    let output_dir = output_dir.as_ref();

    let _ = std::fs::create_dir_all(output_dir);

    // Read ECC file
    let ecc_raw = std::fs::read(ecc_path)?;

    // Strip ECC and detect layout
    let clean = strip_ecc(&ecc_raw);
    let layout = crate::core::images::blocks::NandLayout::detect(&ecc_raw)
        .or_else(|_| crate::core::images::blocks::NandLayout::detect(&clean))
        .ok();

    // Parse and extract
    let skeleton = EccSkeleton::from_ecc(ecc_path)?;
    let wrote = skeleton.write_to_dir(output_dir)?;

    if wrote == 0 {
        return Err(BuilderError::Build(format!(
            "No extractable components found in ECC image (layout={:?}, raw={}, clean={})",
            layout,
            ecc_raw.len(),
            clean.len()
        )));
    }

    info!(
        "[cli] Extract (ECC): INPUT={:?}, Output={:?} (layout={:?}, raw={}, clean={}, files={})",
        ecc_path,
        output_dir,
        layout,
        ecc_raw.len(),
        clean.len(),
        wrote
    );

    Ok(wrote)
}
