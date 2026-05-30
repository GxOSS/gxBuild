/*
    mobile.rs - FlashFS mobile partition blobs (MobileB..MobileJ, types 0x31-0x39)

    Ported from RGBuildPP CXeFlashImage::LoadFileSystems / SaveFileSystems mobile paths.
*/

use crate::builder::filesystem::flashfs::FileSystemRoot;
use crate::builder::filesystem::flashfs::FsSpareData;
use crate::builder::filesystem::{FsError, Result};
use crate::core::images::blocks::{
    detect_bb_physical_format, get_page_spare_fmt, BbPhysicalFormat, FsSpareInfo, NandLayout,
};
use log::{error, info, warn};
use std::collections::HashMap;
use std::path::Path;

/// Mobile partition slot names (B=0 .. J=8).
pub const MOBILE_SLOT_NAMES: [&str; 9] = [
    "MobileB", "MobileC", "MobileD", "MobileE", "MobileF", "MobileG", "MobileH", "MobileI",
    "MobileJ",
];

pub fn is_mobile_type(block_type: u8) -> bool {
    (0x31..0x3A).contains(&block_type)
}

pub fn slot_index(data_type: u8) -> Option<usize> {
    if is_mobile_type(data_type) {
        Some((data_type - 0x31) as usize)
    } else {
        None
    }
}

pub fn type_for_slot(slot: usize) -> Option<u8> {
    if slot < 9 {
        Some(0x31 + slot as u8)
    } else {
        None
    }
}

pub fn name_for_type(data_type: u8) -> Option<&'static str> {
    slot_index(data_type).map(|s| MOBILE_SLOT_NAMES[s])
}

fn decode_pagecount(encoded: u8) -> Option<usize> {
    if encoded == 0 {
        return None;
    }
    if encoded <= 0x20 {
        let v = (0x20u8).wrapping_sub(encoded) as usize;
        return (v > 0).then_some(v);
    }
    if encoded <= 0x40 {
        let v = (0x40u8).wrapping_sub(encoded) as usize;
        return (v > 0).then_some(v);
    }
    None
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MobileData {
    pub data_type: u8,
    pub sequence: u32,
    /// Logical page index of the first page in this mobile blob.
    pub start_page: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MobileStore {
    pub entries: Vec<MobileData>,
    /// Index into `entries` for the latest version of each MobileB..J slot.
    pub latest: [Option<usize>; 9],
}

impl MobileStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// RGBuild `GetMobileName`: "MobileX" where X = 'B' + slot.
    pub fn slot_display_name(slot: usize) -> &'static str {
        MOBILE_SLOT_NAMES.get(slot).copied().unwrap_or("Mobile?")
    }

    pub fn latest_entry(&self, slot: usize) -> Option<&MobileData> {
        self.latest
            .get(slot)
            .and_then(|&idx| idx.map(|i| &self.entries[i]))
    }

    pub fn latest_mut(&mut self, slot: usize) -> Option<&mut MobileData> {
        if let Some(idx) = self.latest.get(slot).copied().flatten() {
            Some(&mut self.entries[idx])
        } else {
            None
        }
    }

    /// Scans a physical NAND image for page-granular mobile blobs (types 0x31-0x39).
    pub fn scan_physical(image: &[u8], layout: &NandLayout) -> Self {
        let mut store = MobileStore::new();
        if *layout == NandLayout::Emmc {
            return store;
        }

        let page_size = layout.page_size();
        let pages_per_block = layout.logical_pages_per_block();
        if pages_per_block == 0 {
            return store;
        }

        let total_pages = image.len() / layout.physical_page_size().max(1);
        let logical = crate::core::images::blocks::remove_spare(image);
        let bb_fmt = if *layout == NandLayout::Bb {
            detect_bb_physical_format(image)
        } else {
            BbPhysicalFormat::PerPage
        };

        let mut page = 0usize;
        while page < total_pages {
            let Some(spare0) = get_page_spare_fmt(image, page, layout, bb_fmt) else {
                page += 1;
                continue;
            };
            if spare0.len() < 16 {
                page += 1;
                continue;
            }
            if spare0[..12].iter().all(|&b| b == 0x00) {
                page += 1;
                continue;
            }
            if spare0[0] != 0xFF {
                page += 1;
                continue;
            }

            let block = page / pages_per_block;
            let parsed0 = FsSpareData::parse(&spare0, layout);
            if parsed0.block_id != (block as u16) {
                page += 1;
                continue;
            }

            let stored_pgcount = spare0[9];
            if stored_pgcount == 0 || stored_pgcount > 0x40 {
                page += 1;
                continue;
            }

            let data_type = parsed0.fs_block_type & 0x3F;
            if !is_mobile_type(data_type) {
                page += 1;
                continue;
            }

            let sequence = parsed0.fs_sequence;
            let fssize = parsed0.fs_size as usize;
            if fssize == 0 || fssize > 0x10000 {
                page += 1;
                continue;
            }

            let pagecount = fssize.ceil_div(page_size).max(1);
            let Some(decoded_pagecount) = decode_pagecount(stored_pgcount) else {
                page += 1;
                continue;
            };
            if decoded_pagecount != pagecount {
                page += 1;
                continue;
            }
            if pagecount > pages_per_block {
                page += 1;
                continue;
            }

            if page
                .checked_add(pagecount)
                .map(|end| end <= total_pages)
                .unwrap_or(false)
                == false
            {
                page += 1;
                continue;
            }

            let mut ok = true;
            for p in 0..pagecount {
                let cur_page = page + p;
                let Some(spare) = get_page_spare_fmt(image, cur_page, layout, bb_fmt) else {
                    ok = false;
                    break;
                };
                if spare.len() < 16 {
                    ok = false;
                    break;
                }
                if spare[0] != 0xFF {
                    ok = false;
                    break;
                }
                if spare[9] != stored_pgcount {
                    ok = false;
                    break;
                }
                let parsed = FsSpareData::parse(&spare, layout);
                if parsed.block_id != (block as u16)
                    || (parsed.fs_block_type & 0x3F) != data_type
                    || parsed.fs_sequence != sequence
                    || parsed.fs_size as usize != fssize
                {
                    ok = false;
                    break;
                }
            }
            if !ok {
                page += 1;
                continue;
            }

            let logical_offset = page * page_size;
            if logical_offset
                .checked_add(fssize)
                .map(|end| end <= logical.len())
                .unwrap_or(false)
                == false
            {
                page += 1;
                continue;
            }
            let data = logical[logical_offset..logical_offset + fssize].to_vec();

            if let Some(slot) = slot_index(data_type) {
                if let Some(existing_idx) = store.latest[slot] {
                    let existing = &store.entries[existing_idx];
                    let replace = existing.sequence < sequence
                        || (existing.sequence == sequence && existing.start_page < page);
                    if replace {
                        store.entries[existing_idx] = MobileData {
                            data_type,
                            sequence,
                            start_page: page,
                            data,
                        };
                    }
                } else {
                    store.entries.push(MobileData {
                        data_type,
                        sequence,
                        start_page: page,
                        data,
                    });
                    let entry_idx = store.entries.len() - 1;
                    store.latest[slot] = Some(entry_idx);
                }
            }
            page += pagecount;
        }

        for slot in 0..9 {
            let Some(idx) = store.latest[slot] else {
                continue;
            };
            let e = &store.entries[idx];
            info!(
                "[mobile] Found type 0x{:02X} @ page 0x{:X}, seq {}, size 0x{:X}",
                e.data_type,
                e.start_page,
                e.sequence,
                e.data.len()
            );
        }

        store
    }

    /// Adds a new mobile blob, bumping the sequence for that slot (RGBuild `MobileAddFile`).
    pub fn add_entry(&mut self, data_type: u8, data: Vec<u8>) -> Result<()> {
        if !is_mobile_type(data_type) {
            return Err(FsError::InvalidMobileType(data_type));
        }
        let slot = slot_index(data_type).unwrap();
        let sequence = self.latest_entry(slot).map(|e| e.sequence + 1).unwrap_or(1);
        let idx = self.entries.len();
        self.entries.push(MobileData {
            data_type,
            sequence,
            start_page: 0,
            data,
        });
        self.latest[slot] = Some(idx);
        info!(
            "[mobile] Queued {} (type 0x{:02X}, seq {}, size 0x{:X})",
            Self::slot_display_name(slot),
            data_type,
            sequence,
            self.entries[idx].data.len()
        );
        Ok(())
    }

    pub fn add_from_path(&mut self, slot: usize, path: &Path) -> Result<()> {
        let data_type =
            type_for_slot(slot).ok_or_else(|| FsError::InvalidMobileSlot(slot))?;
        let data = std::fs::read(path)?;
        self.add_entry(data_type, data)
    }

    /// Writes all latest mobile blobs into the logical image and returns per-page spare metadata.
    pub fn write_logical(
        &mut self,
        image: &mut [u8],
        layout: &NandLayout,
        fs_root: &mut FileSystemRoot,
    ) -> HashMap<usize, FsSpareInfo> {
        let mut page_meta = HashMap::new();
        if *layout == NandLayout::Emmc {
            warn!("[mobile] eMMC mobile write not supported (no spare metadata)");
            return page_meta;
        }

        let page_size = layout.page_size();
        let pages_per_block = layout.logical_pages_per_block();

        for slot in 0..9 {
            let Some(idx) = self.latest[slot] else {
                continue;
            };
            let entry = &mut self.entries[idx];
            if entry.data.is_empty() {
                continue;
            }

            if entry.start_page == 0 {
                let block = fs_root.allocate_new_block(image, layout, 1, 0);
                if block == 0 {
                    error!(
                        "[mobile] Could not allocate block for {}",
                        Self::slot_display_name(slot)
                    );
                    continue;
                }
                let map_idx = block as usize;
                if map_idx < fs_root.block_map.len() {
                    fs_root.block_map[map_idx] = 0x1FFB;
                }
                entry.start_page = block as usize * pages_per_block;
            }

            let pagecount = entry.data.len().ceil_div(page_size).max(1);
            let write_len = pagecount * page_size;
            let offset = entry.start_page * page_size;
            if offset + write_len > image.len() {
                error!(
                    "[mobile] {} write out of bounds (page 0x{:X}, len 0x{:X})",
                    Self::slot_display_name(slot),
                    entry.start_page,
                    write_len
                );
                continue;
            }

            let mut padded = entry.data.clone();
            padded.resize(write_len, 0);
            image[offset..offset + write_len].copy_from_slice(&padded);

            let base = if *layout == NandLayout::Bb {
                0x40u8
            } else {
                0x20u8
            };
            let encoded_pgcount = base.saturating_sub(pagecount as u8);
            for z in 0..pagecount {
                let page = entry.start_page + z;
                page_meta.insert(
                    page,
                    FsSpareInfo {
                        sequence: entry.sequence,
                        size: write_len as u16,
                        page_count: encoded_pgcount,
                        block_type: entry.data_type,
                    },
                );
            }

            info!(
                "[mobile] Wrote {} at page 0x{:X} ({} pages, seq {})",
                Self::slot_display_name(slot),
                entry.start_page,
                pagecount,
                entry.sequence
            );
        }

        page_meta
    }

    /// Tier 2: load `MobileB.bin` … `MobileJ.bin` from the data folder when NAND has no entry.
    pub fn apply_data_folder_tier(&mut self, data_dir: &Path) {
        if !data_dir.is_dir() {
            return;
        }
        for slot in 0..9 {
            if self.latest[slot].is_some() {
                continue;
            }
            let name = MOBILE_SLOT_NAMES[slot];
            let candidates = [data_dir.join(format!("{}.bin", name)), data_dir.join(name)];
            let Some(path) = candidates.iter().find(|p| p.is_file()) else {
                continue;
            };
            match std::fs::read(path) {
                Ok(data) => {
                    if let Some(data_type) = type_for_slot(slot) {
                        let _ = self.add_entry(data_type, data);
                        info!(
                            "[mobile] Loaded {} from data folder: {}",
                            name,
                            path.display()
                        );
                    }
                }
                Err(e) => {
                    warn!("[mobile] Failed to read {}: {}", path.display(), e);
                }
            }
        }
    }

    /// Builds page-level spare metadata for already-placed mobile entries (parse / rebuild path).
    pub fn collect_spare_meta(&self, layout: &NandLayout) -> HashMap<usize, FsSpareInfo> {
        let page_size = 0x200usize;
        let mut page_meta = HashMap::new();
        for slot in 0..9 {
            let Some(entry) = self.latest_entry(slot) else {
                continue;
            };
            if entry.start_page == 0 || entry.data.is_empty() {
                continue;
            }
            let pagecount = entry.data.len().ceil_div(page_size).max(1);
            let base = if *layout == NandLayout::Bb {
                0x40u8
            } else {
                0x20u8
            };
            let encoded_pgcount = base.saturating_sub(pagecount as u8);
            let write_len = pagecount * page_size;
            for z in 0..pagecount {
                page_meta.insert(
                    entry.start_page + z,
                    FsSpareInfo {
                        sequence: entry.sequence,
                        size: write_len as u16,
                        page_count: encoded_pgcount,
                        block_type: entry.data_type,
                    },
                );
            }
        }
        page_meta
    }
}

trait CeilDiv {
    fn ceil_div(self, rhs: usize) -> usize;
}
impl CeilDiv for usize {
    fn ceil_div(self, rhs: usize) -> usize {
        if rhs == 0 {
            0
        } else {
            (self + rhs - 1) / rhs
        }
    }
}
