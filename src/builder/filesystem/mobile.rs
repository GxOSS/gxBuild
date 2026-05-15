/*
    mobile.rs - FlashFS mobile partition blobs (MobileB..MobileJ, types 0x31-0x39)

    Ported from RGBuildPP CXeFlashImage::LoadFileSystems / SaveFileSystems mobile paths.
*/

use crate::builder::filesystem::flashfs::FileSystemRoot;
use crate::builder::filesystem::flashfs::FsSpareData;
use crate::core::images::blocks::{get_page_spare, FsSpareInfo, NandLayout};
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
        self.latest.get(slot).and_then(|&idx| idx.map(|i| &self.entries[i]))
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
        let total_pages = image.len() / layout.physical_page_size().max(1);

        let mut mobile_pages: Vec<usize> = Vec::new();
        let mut mobile_types: Vec<u8> = Vec::new();
        let mut mobile_vers: Vec<u32> = Vec::new();

        for page in 0..total_pages {
            let Some(spare) = get_page_spare(image, page, layout) else {
                continue;
            };
            let parsed = FsSpareData::parse(&spare, layout);
            // Mobile page-count lives in spare[9] directly (not MetaType2 ×4 encoding).
            if spare[9] == 0 {
                continue;
            }
            let btype = parsed.fs_block_type & 0x3F;
            if !is_mobile_type(btype) {
                continue;
            }
            mobile_pages.push(page);
            mobile_types.push(btype);
            mobile_vers.push(parsed.fs_sequence);
        }

        let mut i = 0usize;
        while i < mobile_pages.len() {
            let Some(spare) = get_page_spare(image, mobile_pages[i], layout) else {
                i += 1;
                continue;
            };
            let parsed = FsSpareData::parse(&spare, layout);
            let fssize = parsed.fs_size as usize;
            let stored_pgcount = spare[9];
            let pgcount = fssize.ceil_div(page_size).max(1);
            let pgcount2 = 0x20usize.saturating_sub(stored_pgcount as usize);
            if pgcount != pgcount2 && pgcount == 1 && fssize >= page_size {
                i += 1;
                continue;
            }

            let mut pagescalc = 0usize;
            for y in (i + 1)..mobile_pages.len() {
                if mobile_types[y] != mobile_types[i] || mobile_vers[y] != mobile_vers[i] {
                    continue;
                }
                if mobile_pages[y] < mobile_pages[i] || mobile_pages[y] >= mobile_pages[i] + pgcount
                {
                    continue;
                }
                pagescalc += 1;
                if pagescalc + 1 == pgcount {
                    break;
                }
            }
            if pagescalc + 1 != pgcount {
                i += 1;
                continue;
            }

            let start_page = mobile_pages[i];
            let data_type = mobile_types[i];
            let sequence = mobile_vers[i];
            let logical = crate::core::images::blocks::remove_spare(image);
            let logical_offset = start_page * page_size;
            let mut data = vec![0u8; fssize];
            if logical_offset + fssize <= logical.len() {
                data.copy_from_slice(&logical[logical_offset..logical_offset + fssize]);
            }

            store.entries.push(MobileData {
                data_type,
                sequence,
                start_page,
                data,
            });
            let entry_idx = store.entries.len() - 1;
            if let Some(slot) = slot_index(data_type) {
                let replace = store
                    .latest
                    .get(slot)
                    .and_then(|o| o.map(|idx| store.entries[idx].sequence < sequence))
                    .unwrap_or(true);
                if replace {
                    store.latest[slot] = Some(entry_idx);
                }
            }
            info!(
                "[mobile] Found type 0x{:02X} @ page 0x{:X}, seq {}, size 0x{:X}",
                data_type, start_page, sequence, fssize
            );
            i += pagescalc + 1;
        }

        store
    }

    /// Adds a new mobile blob, bumping the sequence for that slot (RGBuild `MobileAddFile`).
    pub fn add_entry(&mut self, data_type: u8, data: Vec<u8>) -> Result<(), String> {
        if !is_mobile_type(data_type) {
            return Err(format!("Invalid mobile type 0x{:02X}", data_type));
        }
        let slot = slot_index(data_type).unwrap();
        let sequence = self
            .latest_entry(slot)
            .map(|e| e.sequence + 1)
            .unwrap_or(1);
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

    pub fn add_from_path(&mut self, slot: usize, path: &Path) -> Result<(), String> {
        let data_type = type_for_slot(slot)
            .ok_or_else(|| format!("Invalid mobile slot index {}", slot))?;
        let data = std::fs::read(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
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

            let encoded_pgcount = (0x20u8).saturating_sub(pagecount as u8);
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
            let candidates = [
                data_dir.join(format!("{}.bin", name)),
                data_dir.join(name),
            ];
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
    pub fn collect_spare_meta(&self) -> HashMap<usize, FsSpareInfo> {
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
            let encoded_pgcount = (0x20u8).saturating_sub(pagecount as u8);
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
