/*
  stfs.rs - STFS (PIRS) extraction tool for Xbox 360 content packages.

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

use log::info;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use zerocopy::{
    byteorder::{BigEndian, U16, U32},
    FromBytes, Immutable, IntoBytes, KnownLayout,
};

use crate::builder::chain::cf::BootloaderCf;
use crate::builder::chain::cg::BootloaderCg;
use crate::builder::chain::BootloaderHeader;

pub const ONE_BL_KEY: [u8; 16] = [
    0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA,
];

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub struct StfsHeader {
    pub magic: [u8; 4], // "PIRS"
                        // ... many fields follow, but we mainly care about the directory start logic
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub struct RawStfsEntry {
    pub name: [u8; 40],
    pub namelen: u8,
    pub clustsize1_3: [u8; 3], // 24-bit little endian
    pub clustsize2_3: [u8; 3], // 24-bit little endian
    pub startclust_3: [u8; 3], // 24-bit little endian
    pub pathind: U16<BigEndian>,
    pub filelen: U32<BigEndian>,
    pub dati1: U32<BigEndian>,
    pub dati2: U32<BigEndian>,
}

impl RawStfsEntry {
    pub fn get_name(&self) -> String {
        let len = (self.namelen & 0x3F) as usize;
        String::from_utf8_lossy(&self.name[..len]).to_string()
    }

    pub fn is_directory(&self) -> bool {
        (self.namelen & 0x80) == 0x80
    }

    fn get_u24(bytes: &[u8; 3]) -> u32 {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
    }

    pub fn clustsize(&self) -> u32 {
        Self::get_u24(&self.clustsize1_3)
    }

    pub fn startclust(&self) -> u32 {
        Self::get_u24(&self.startclust_3)
    }
}

pub struct StfsContainer<'a> {
    data: &'a [u8],
}

impl<'a> StfsContainer<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 4 || &data[0..4] != b"PIRS" {
            return Err("Invalid STFS signature: Expected 'PIRS'".into());
        }
        info!(
            "[builder] STFS container validated (PIRS magic OK, {} bytes)",
            data.len()
        );
        Ok(Self { data })
    }

    fn directory_layout(&self) -> Result<(usize, u32, usize), String> {
        if self.data.len() < 0xC034 {
            return Err("STFS container too small to read directory metadata".to_string());
        }

        let pathind_peek = u16::from_be_bytes(
            self.data[0xC032..0xC034]
                .try_into()
                .map_err(|_| "Failed to read STFS path index")?,
        );
        let start_offset = if pathind_peek == 0xFFFF {
            0xC000
        } else {
            0xD000
        };
        let multiplier = if start_offset == 0xC000 {
            0x1000
        } else {
            0x2000
        };

        let first_clust_end = start_offset + 0x31;
        if self.data.len() < first_clust_end {
            return Err("STFS container too small to read directory cluster count".to_string());
        }

        let first_clust = u16::from_le_bytes(
            self.data[start_offset + 0x2F..first_clust_end]
                .try_into()
                .map_err(|_| "Failed to read STFS directory cluster count")?,
        ) as usize;
        let dir_len = 0x1000usize
            .checked_mul(first_clust)
            .ok_or_else(|| "STFS directory size overflow".to_string())?;
        let dir_end = start_offset
            .checked_add(dir_len)
            .ok_or_else(|| "STFS directory offset overflow".to_string())?;
        if dir_end > self.data.len() {
            return Err("STFS directory extends beyond container bounds".to_string());
        }

        Ok((start_offset, multiplier, dir_end))
    }

    pub fn extract_all(&self, target_dir: &Path) -> Result<(), String> {
        if !target_dir.exists() {
            fs::create_dir_all(target_dir).map_err(|e| e.to_string())?;
        }

        let (start_offset, multiplier, dir_end) = self.directory_layout()?;
        let dir_data = &self.data[start_offset..dir_end];

        let mut paths: HashMap<u16, PathBuf> = HashMap::new();
        paths.insert(0xFFFF, target_dir.to_path_buf());

        for i in 0..(dir_data.len() / 64) {
            let entry_bytes = &dir_data[i * 64..(i + 1) * 64];
            let entry = RawStfsEntry::read_from_prefix(entry_bytes)
                .map(|(e, _)| e)
                .map_err(|_| "Failed to parse directory entry")?;

            if entry.namelen == 0 {
                break;
            }

            let name = entry.get_name();
            let pathind = entry.pathind.get();
            let parent_path = paths.get(&pathind).ok_or("Invalid path index")?;
            let full_path = parent_path.join(&name);

            if entry.is_directory() {
                fs::create_dir_all(&full_path).map_err(|e| e.to_string())?;
                paths.insert(i as u16, full_path);
            } else {
                let mut file_len = entry.filelen.get() as usize;
                let mut file_data = Vec::with_capacity(file_len);
                let mut cluster_idx = entry.startclust();
                while file_len > 0 {
                    let mut skipped = 0u32;
                    let mut temp_clust = cluster_idx;
                    while temp_clust >= 170 {
                        temp_clust /= 170;
                        skipped += (temp_clust + 1) * multiplier;
                    }

                    let real_start =
                        (start_offset as u32 + (cluster_idx * 0x1000) + skipped) as usize;
                    let chunk_size = std::cmp::min(0x1000, file_len);

                    if real_start + chunk_size > self.data.len() {
                        return Err(format!("File '{}' extends beyond image bounds", name));
                    }

                    file_data.extend_from_slice(&self.data[real_start..real_start + chunk_size]);

                    cluster_idx += 1;
                    file_len -= chunk_size;
                }

                fs::write(&full_path, file_data).map_err(|e| e.to_string())?;
                info!("[builder] STFS extracted file: {}", name);
            }
        }

        Ok(())
    }

    pub fn extract_to_memory(&self) -> Result<HashMap<String, Vec<u8>>, String> {
        let (start_offset, multiplier, dir_end) = self.directory_layout()?;

        info!(
            "[builder] STFS extract_to_memory: start_offset=0x{:x}, multiplier=0x{:x}",
            start_offset, multiplier
        );

        let dir_data = &self.data[start_offset..dir_end];

        let mut results = HashMap::new();

        for i in 0..(dir_data.len() / 64) {
            let entry_bytes = &dir_data[i * 64..(i + 1) * 64];
            let entry = RawStfsEntry::read_from_prefix(entry_bytes)
                .map(|(e, _)| e)
                .map_err(|_| "Failed to parse directory entry")?;

            if entry.namelen == 0 {
                break;
            }
            if entry.is_directory() {
                continue;
            } // FlashFS in the update context is a flat file set

            let mut name = entry.get_name();
            // Truncate $flash_ prefix if present
            if name.to_lowercase().starts_with("$flash_") {
                name = name[7..].to_string();
            }

            let mut file_len = entry.filelen.get() as usize;
            let mut file_data = Vec::with_capacity(file_len);
            let mut cluster_idx = entry.startclust();
            while file_len > 0 {
                let mut skipped = 0u32;
                let mut temp_clust = cluster_idx;
                while temp_clust >= 170 {
                    temp_clust /= 170;
                    skipped += (temp_clust + 1) * multiplier;
                }

                let real_start = (start_offset as u32 + (cluster_idx * 0x1000) + skipped) as usize;
                let chunk_size = std::cmp::min(0x1000, file_len);

                if real_start + chunk_size > self.data.len() {
                    return Err(format!("File '{}' extends beyond image bounds", name));
                }

                file_data.extend_from_slice(&self.data[real_start..real_start + chunk_size]);

                cluster_idx += 1;
                file_len -= chunk_size;
            }

            results.insert(name.to_lowercase(), file_data);
        }

        info!(
            "[builder] STFS in-memory extraction complete: {} files extracted.",
            results.len()
        );
        Ok(results)
    }
}

pub fn parse_xboxupd(xboxupd_bytes: &[u8]) -> Result<(BootloaderCf, BootloaderCg), String> {
    // 0. Quick Magic Validation
    if xboxupd_bytes.len() < 2 {
        return Err("xboxupd buffer too small to check magic".to_string());
    }
    if &xboxupd_bytes[0..2] != b"CF" {
        return Err(format!("Invalid xboxupd magic: Expected 'CF' (0x4346), found 0x{:02X}{:02X}. Potential STFS misalignment.", xboxupd_bytes[0], xboxupd_bytes[1]));
    }

    // 1. Parse CF (slice to CF size so CF doesn't accidentally include CG bytes)
    let (cf_header, _) = BootloaderHeader::read_from_prefix(xboxupd_bytes)
        .map_err(|_| "Failed to parse CF header")?;
    let cf_size = ((cf_header.size.get() as usize) + 0xF) & !0xF;
    if xboxupd_bytes.len() < cf_size {
        return Err("xboxupd buffer too small to contain full CF".to_string());
    }
    let mut cf = BootloaderCf::parse(&xboxupd_bytes[..cf_size])?;

    if !cf.is_decrypted() {
        if let Err(e) = cf.decrypt(&ONE_BL_KEY) {
            return Err(format!("CF decryption failed: {}", e));
        }
    }
    if !cf.is_decrypted() {
        return Err("Failed to decrypt CF header.".to_string());
    }

    info!(
        "[builder] Parsing xboxupd: CF at offset 0, size=0x{:x}",
        cf.header.size.get()
    );
    cf.populate_metadata();
    let meta = cf
        .metadata
        .as_ref()
        .ok_or("Failed to populate CF metadata")?;
    let cf_size = (cf.header.size.get() as usize + 0xF) & !0xF;

    if xboxupd_bytes.len() < cf_size {
        return Err("xboxupd buffer too small to contain CG payload".to_string());
    }

    // 2. Slice memory exactly from CF endpoint to initialize CG
    let mut cg = BootloaderCg::parse(&xboxupd_bytes[cf_size..])?;

    if !cg.is_decrypted() {
        if let Err(e) = cg.decrypt(&meta.cg_nonce) {
            return Err(format!("CG decryption failed: {}", e));
        }
    }
    if !cg.is_decrypted() {
        return Err("Failed to decrypt CG header.".to_string());
    }

    cg.populate_metadata();

    // 3. Compare RotSum
    let mut cg_rotsum = [0u8; 0x14];
    if let Err(e) = cg.calculate_rotsum(&mut cg_rotsum) {
        return Err(format!("CG rotsum calculation failed: {}", e));
    }

    if cg_rotsum != meta.cg_digest {
        return Err("CG checking hash mismatch against CF signature metadata".to_string());
    }

    info!(
        "[builder] xboxupd parsed OK: CF v{} -> CG v{} ({} bytes)",
        cf.header.version.get(),
        cg.header.version.get(),
        xboxupd_bytes.len()
    );
    Ok((cf, cg))
}

#[cfg(test)]
mod tests {
    use super::StfsContainer;

    #[test]
    fn short_pirs_container_returns_error() {
        let container = StfsContainer::new(b"PIRS").unwrap();

        assert!(container.extract_to_memory().is_err());
    }
}
