/*


    Ported from emoose's RGBuildPP
*/

use crate::core::images::blocks::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use log::{error, info};
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FsSpareData {
    pub block_id: u16,
    pub fs_sequence: u32,
    pub fs_size: u16,
    pub fs_page_count: u16,
    pub fs_block_type: u8,
    pub bad_block: bool,
}

impl FsSpareData {
    /// Parses spare metadata from a 16-byte spare area.
    pub fn parse(data: &[u8], layout: &NandLayout) -> Self {
        if data.len() < 16 {
            return FsSpareData { block_id: 0, fs_sequence: 0, fs_size: 0, fs_page_count: 0, fs_block_type: 0, bad_block: false };
        }

        let meta_type = match layout {
            NandLayout::Xsb => SpareMetaType::MetaType0,
            NandLayout::Sb => SpareMetaType::MetaType1,
            NandLayout::Bb => SpareMetaType::MetaType2,
            NandLayout::Emmc => SpareMetaType::MetaTypeNone,
        };

        match meta_type {
            SpareMetaType::MetaType0 => {
                let block_id = u16::from_le_bytes([data[0], data[1] & 0xF]);
                let fs_sequence = (data[2] as u32) | ((data[3] as u32) << 8) | ((data[4] as u32) << 16);
                let bad_block = data[5] != 0xFF;
                let fs_size = u16::from_be_bytes([data[8], data[7]]);
                let fs_page_count = data[9] as u16;
                let fs_block_type = data[12] & 0x3F;
                FsSpareData { block_id, fs_sequence, fs_size, fs_page_count, fs_block_type, bad_block }
            }
            SpareMetaType::MetaType1 => {
                let block_id = u16::from_le_bytes([data[1], data[2] & 0xF]);
                let fs_sequence = (data[0] as u32) | ((data[3] as u32) << 8) | ((data[4] as u32) << 16);
                let bad_block = data[5] != 0xFF;
                let fs_size = u16::from_be_bytes([data[8], data[7]]);
                let fs_page_count = data[9] as u16;
                let fs_block_type = data[12] & 0x3F;
                FsSpareData { block_id, fs_sequence, fs_size, fs_page_count, fs_block_type, bad_block }
            }
            SpareMetaType::MetaType2 => {
                let block_id = u16::from_le_bytes([data[1], data[2] & 0xF]);
                let fs_sequence = (data[5] as u32) | ((data[4] as u32) << 8) | ((data[3] as u32) << 16);
                let bad_block = data[0] != 0xFF;
                let fs_size = u16::from_be_bytes([data[8], data[7]]);
                let fs_page_count = data[9] as u16;
                let fs_block_type = data[12] & 0x3F;
                FsSpareData { block_id, fs_sequence, fs_size, fs_page_count, fs_block_type, bad_block }
            }
            SpareMetaType::MetaTypeNone => FsSpareData { block_id: 0, fs_sequence: 0, fs_size: 0, fs_page_count: 0, fs_block_type: 0, bad_block: false },
        }
    }
}

/// Calculates the base block offset for MetaType2 NANDs.
pub fn get_fs_base_block_for_meta2(image: &[u8], layout: &NandLayout, fs_root_spare_page: usize) -> u16 {
    if *layout != NandLayout::Bb {
        return 0;
    }

    let Some(spare) = get_page_spare(image, fs_root_spare_page, layout) else {
        return 0;
    };
    let parsed = FsSpareData::parse(&spare, layout);

    let reserved = 0x1E0u32
        .saturating_sub(parsed.fs_page_count as u32)
        .saturating_sub(((parsed.fs_size >> 8) as u32) << 2);

    (reserved * 8) as u16
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileSystemEntry {
    pub page_number: i32,
    pub file_name: String,
    pub source_path: Option<String>,
    pub block_number: u16,
    pub size: u32,
    pub timestamp: i32,
    pub deleted: bool,
    pub data: Vec<u8>,
}

impl FileSystemEntry {
    pub fn new(page_number: i32) -> Self {
        FileSystemEntry { page_number, file_name: String::new(), source_path: None, block_number: 0, size: 0, timestamp: 0, deleted: false, data: Vec::new() }
    }

    pub fn read_from(&mut self, chunk: &[u8]) {
        let mut cursor = Cursor::new(chunk);
        let mut name_buf = [0u8; 0x16];
        let _ = cursor.read_exact(&mut name_buf);
        let first_byte = name_buf[0];
        let name = if first_byte == 0x05 {
            self.deleted = true;
            let end = name_buf[1..].iter().position(|&c| c == 0).unwrap_or(0x15);
            format!("_{}", String::from_utf8_lossy(&name_buf[1..1 + end]))
        } else {
            let end = name_buf.iter().position(|&c| c == 0).unwrap_or(0x16);
            String::from_utf8_lossy(&name_buf[..end]).to_string()
        };
        self.file_name = name;
        self.block_number = cursor.read_u16::<BigEndian>().unwrap_or(0);
        self.size = cursor.read_u32::<BigEndian>().unwrap_or(0);
        self.timestamp = cursor.read_i32::<BigEndian>().unwrap_or(0);
    }

    pub fn write_into(&self, chunk: &mut [u8]) {
        let mut cursor = Cursor::new(chunk);
        let mut name_buf = [0u8; 0x16];
        let mut actual_name = self.file_name.clone();
        if self.deleted && !actual_name.is_empty() {
            actual_name.replace_range(..1, "\x05");
        }
        let name_bytes = actual_name.as_bytes();
        let len = std::cmp::min(name_bytes.len(), 0x16);
        name_buf[..len].copy_from_slice(&name_bytes[..len]);
        let _ = cursor.write_all(&name_buf);
        let _ = cursor.write_u16::<BigEndian>(self.block_number);
        let _ = cursor.write_u32::<BigEndian>(self.size);
        let _ = cursor.write_i32::<BigEndian>(self.timestamp);
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileSystemRoot {
    pub block_number: i32,
    pub version: i32,
    pub entries: Vec<FileSystemEntry>,
    pub block_map: Vec<u16>,
    pub block_offset: u16,
    pub partition_type: u8,
}

impl FileSystemRoot {
    pub fn new(block_number: i32, version: i32, partition_type: u8) -> Self {
        let actual_version = if version == 0 { 3 } else { version };
        FileSystemRoot { block_number, version: actual_version, entries: Vec::new(), block_map: Vec::new(), block_offset: 0, partition_type }
    }

    /// Reads FlashFS from a logical clean buffer.
    pub fn read(&mut self, image: &[u8], layout: &NandLayout) {
        self.entries.clear();
        let pages_per_block = layout.logical_pages_per_block();
        let logical_block_size = pages_per_block * 0x200;
        let total_blocks = image.len() / logical_block_size;

        self.block_map = vec![0; total_blocks];
        let mut current_block = self.block_number as usize;
        let mut loop_count = 0;

        if *layout == NandLayout::Emmc {
            let mut bmap_idx = 0;
            loop {
                if current_block >= total_blocks {
                    return;
                }
                let offset = current_block * logical_block_size;
                if offset + logical_block_size > image.len() {
                    return;
                }
                let mut cursor = Cursor::new(&image[offset..offset + logical_block_size]);
                for _ in 0..(layout.page_size() / 2) {
                    if bmap_idx >= total_blocks {
                        break;
                    }
                    if let Ok(val) = cursor.read_u16::<BigEndian>() {
                        self.block_map[bmap_idx] = val;
                        bmap_idx += 1;
                    }
                }
                let next = self.block_map[current_block] & 0x7FFF;
                if bmap_idx >= total_blocks {
                    current_block = next as usize;
                    break;
                }
                if next == 0 || next >= 0x1FFB || next as usize >= total_blocks {
                    return;
                }
                current_block = next as usize;
                loop_count += 1;
                if loop_count > 1000 {
                    error!("[flashfs] Chained eMMC FS root loop limit exceeded!");
                    return;
                }
            }

            loop {
                if current_block >= total_blocks {
                    break;
                }
                let offset = current_block * logical_block_size;
                if offset + logical_block_size > image.len() {
                    break;
                }
                let mut found_empty = false;
                for i in 0..(layout.page_size() / 0x20) {
                    let entry_offset = offset + (i * 0x20);
                    let mut entry = FileSystemEntry::new(current_block as i32);
                    entry.read_from(&image[entry_offset..entry_offset + 0x20]);
                    if entry.file_name.is_empty() {
                        found_empty = true;
                        break;
                    }
                    if !self.entries.iter().any(|e| e.file_name == entry.file_name) {
                        self.entries.push(entry);
                    }
                }
                if found_empty {
                    break;
                }
                let next = self.block_map[current_block] & 0x7FFF;
                if next == 0 || next >= 0x1FFB || next as usize >= total_blocks {
                    break;
                }
                current_block = next as usize;
            }

            let to_load: Vec<(usize, u16, usize)> = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.block_number > 0 && e.size > 0)
                .map(|(i, e)| (i, e.block_number, e.size as usize))
                .collect();
            for (i, block_number, size) in to_load {
                let raw = self.get_chain_data(image, layout, block_number);
                self.entries[i].data = if raw.len() >= size { raw[..size].to_vec() } else { raw };
            }
            return;
        }

        loop {
            if current_block >= total_blocks {
                break;
            }
            let start_page = current_block * pages_per_block;

            let mut block_map_pages = Vec::new();
            let mut file_name_pages = Vec::new();
            for i in 0..pages_per_block {
                if i % 2 == 0 {
                    block_map_pages.push(start_page + i);
                } else {
                    file_name_pages.push(start_page + i);
                }
            }

            let mut break_files = false;
            for page in file_name_pages {
                if break_files {
                    break;
                }
                let page_offset = page * layout.page_size();
                if page_offset + layout.page_size() > image.len() {
                    break;
                }
                for i in 0..(layout.page_size() / 0x20) {
                    let entry_offset = page_offset + (i * 0x20);
                    let mut entry = FileSystemEntry::new(page as i32);
                    entry.read_from(&image[entry_offset..entry_offset + 0x20]);
                    if entry.file_name.is_empty() {
                        break_files = true;
                        break;
                    }
                    if !self.entries.iter().any(|e| e.file_name == entry.file_name) {
                        self.entries.push(entry);
                    }
                }
            }

            let mut j = 0;
            for page in block_map_pages {
                let offset = page * 0x200;
                if offset + 0x200 > image.len() {
                    break;
                }
                let mut cursor = Cursor::new(&image[offset..offset + 0x200]);
                for _ in 0..256 {
                    let global_j = loop_count * (pages_per_block / 2 * 256) + j;
                    if global_j >= total_blocks {
                        break;
                    }
                    if let Ok(val) = cursor.read_u16::<BigEndian>() {
                        self.block_map[global_j] = val;
                        j += 1;
                    }
                }
            }

            let bmap_val = self.block_map[current_block];
            if (bmap_val & 0x7FFF) < 0x1FFB && (bmap_val & 0x7FFF) > 0 {
                current_block = (bmap_val & 0x7FFF) as usize;
                loop_count += 1;
                if loop_count > 1000 {
                    error!("[flashfs] Chained FS root loop limit exceeded!");
                    break;
                }
            } else {
                break;
            }
        }

        if self.block_number >= 0 && (self.block_number as usize) < self.block_map.len() {
            if current_block < self.block_map.len() {
                self.block_map[current_block] = 0x1FFF;
            }
        }

        // Load file data for each entry from its block chain.
        // Collect (block_number, size) first to avoid borrow conflict with get_chain_data(&self).
        let to_load: Vec<(usize, u16, usize)> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.block_number > 0 && e.size > 0)
            .map(|(i, e)| (i, e.block_number, e.size as usize))
            .collect();
        for (i, block_number, size) in to_load {
            let raw = self.get_chain_data(image, layout, block_number);
            self.entries[i].data = if raw.len() >= size { raw[..size].to_vec() } else { raw };
        }

        // Calibrate BlockOffset for Big-Block NANDs by searching for .xex headers
        if *layout == NandLayout::Bb {
            self.calibrate_block_offset(image, layout);
        }
    }

    /// Calibrates the physical BlockOffset for MetaType2 NANDs.
    pub fn calibrate_block_offset(&mut self, image: &[u8], layout: &NandLayout) {
        if *layout != NandLayout::Bb {
            return;
        }

        let pages_per_block = layout.logical_pages_per_block();
        let logical_block_size = pages_per_block * 0x200;

        for entry in self.entries.iter().filter(|e| !e.deleted && e.file_name.to_lowercase().ends_with(".xex")) {
            let base_block = entry.block_number;

            for &offset in &[0xAE0u16, 0x2E0u16, 0x0u16] {
                let physical_block = base_block.wrapping_add(offset) as usize;
                let page_offset = physical_block * logical_block_size;

                if page_offset + 4 <= image.len() {
                    let sig = &image[page_offset..page_offset + 4];
                    if sig == b"XEX2" || sig == b"XEX1" {
                        info!("[flashfs] Calibrated BlockOffset: 0x{:X} (Found {} signature at block {})", offset, String::from_utf8_lossy(sig), physical_block);
                        self.block_offset = offset;
                        return;
                    }
                }
            }
        }
    }

    pub fn create_defaults(&mut self, image_len: usize, layout: &NandLayout, fs_start_block: u16) {
        let logical_block_size = layout.logical_pages_per_block() * 0x200;
        let total_blocks = image_len / logical_block_size;
        self.block_map = vec![0x1FFE; total_blocks];

        let protect_end = std::cmp::max(4usize, fs_start_block as usize);
        for i in 0..protect_end {
            if i < self.block_map.len() {
                self.block_map[i] = 0x1FFB;
            }
        }

        if *layout != NandLayout::Emmc {
            let reserve_start = layout.reserve_start(image_len);
            for i in reserve_start..self.block_map.len() {
                self.block_map[i] = 0x1FFB;
            }
        }

        if self.block_number >= 0 && (self.block_number as usize) < self.block_map.len() {
            self.block_map[self.block_number as usize] = 0x1FFF;
        }
        if *layout != NandLayout::Emmc {
            let config_start = layout.reserve_start(image_len).saturating_sub(4);
            for i in 0..5 {
                if config_start + i < self.block_map.len() {
                    self.block_map[config_start + i] = 0x1FFB;
                }
            }
        }
    }

    pub fn build_from_folder(image: &mut [u8], layout: &NandLayout, folder_path: &std::path::Path, fs_start_block: u16, partition_type: u8) -> Result<Self, String> {
        let mut root = FileSystemRoot::new(fs_start_block as i32, 3, partition_type);
        root.create_defaults(image.len(), layout, fs_start_block);
        for entry in std::fs::read_dir(folder_path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if path.is_file() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("Mobile") {
                    continue;
                }
                let content = std::fs::read(&path).map_err(|e| e.to_string())?;
                let mut new_entry = FileSystemEntry::new(0);
                new_entry.file_name = name;
                root.set_entry_data(image, layout, &mut new_entry, &content)?;
                root.entries.push(new_entry);
            }
        }
        Ok(root)
    }

    pub fn build_from_memory(image: &mut [u8], layout: &NandLayout, files: &HashMap<String, Vec<u8>>, fs_start_block: u16, partition_type: u8) -> Result<Self, String> {
        let mut root = FileSystemRoot::new(fs_start_block as i32, 3, partition_type);
        root.create_defaults(image.len(), layout, fs_start_block);
        info!("[flashfs] Building FlashFS from memory with {} assets...", files.len());
        let mut ordered_files: Vec<_> = files.iter().collect();
        ordered_files
            .sort_by(|(left_name, left_content), (right_name, right_content)| right_content.len().cmp(&left_content.len()).then_with(|| left_name.cmp(right_name)));
        for (name, content) in ordered_files {
            info!("[flashfs]   * Processing asset: {} (Size: 0x{:X})", name, content.len());
            let mut new_entry = FileSystemEntry::new(0);
            new_entry.file_name = name.clone();
            root.set_entry_data(image, layout, &mut new_entry, content)?;
            root.entries.push(new_entry);
        }
        Ok(root)
    }

    pub fn get_block_chain(&self, start_block: u16, limit: usize) -> Vec<u16> {
        let mut list = Vec::new();
        let mut current = start_block;
        let mut visited = std::collections::HashSet::new();
        let mut i = 0;
        loop {
            if !visited.insert(current) {
                error!("[flashfs] Cycle detected in block chain at block {}!", current);
                break;
            }
            list.push(current);
            if current as usize >= self.block_map.len() {
                break;
            }
            current = self.block_map[current as usize] & 0x7FFF;
            i += 1;
            if current == 0 || (current & 0x1FFE) == 0x1FFE || current as usize >= self.block_map.len() || i >= limit {
                break;
            }
        }
        list
    }

    /// Sets every block in the chain starting at `start_block` back to 0x1FFE (free).
    pub fn free_block_chain(&mut self, start_block: u16) {
        let chain = self.get_block_chain(start_block, self.block_map.len());
        for block in chain {
            if (block as usize) < self.block_map.len() {
                self.block_map[block as usize] = 0x1FFE;
            }
        }
    }

    pub fn get_chain_data(&self, image: &[u8], layout: &NandLayout, start_block: u16) -> Vec<u8> {
        let chain = self.get_block_chain(start_block, self.block_map.len());
        let mut data = Vec::new();
        let pages_per_block = layout.logical_pages_per_block();

        let base_block_offset: u16 = if *layout == NandLayout::Bb && crate::core::images::blocks::has_spare(image) {
            let root_block = self.block_number as usize;
            let root_spare_page = root_block * pages_per_block;
            get_fs_base_block_for_meta2(image, layout, root_spare_page)
        } else {
            0
        };

        let page_size = layout.page_size();
        for cluster in chain {
            // Add base block offset for big-block NANDs
            let adjusted_cluster = cluster.wrapping_add(base_block_offset);
            let logical_block_offset = (adjusted_cluster + self.block_offset) as usize * pages_per_block * page_size;

            if crate::core::images::blocks::has_spare(image) {
                if let Some(blk_data) = crate::core::images::blocks::read_logical_from_physical(image, logical_block_offset, pages_per_block * page_size, *layout) {
                    data.extend_from_slice(&blk_data);
                }
            } else {
                let blk_size = pages_per_block * page_size;
                if logical_block_offset + blk_size <= image.len() {
                    data.extend_from_slice(&image[logical_block_offset..logical_block_offset + blk_size]);
                }
            }
        }
        data
    }

    pub fn allocate_new_block(&mut self, image: &mut [u8], layout: &NandLayout, blocks_needed: usize, minimum_block: u16) -> u16 {
        let page_size = layout.page_size();
        let pages_per_block = layout.logical_pages_per_block();
        let logical_block_size = pages_per_block * page_size;
        let total_blocks = layout.total_blocks(image.len());

        let start_search = std::cmp::max(4, minimum_block as usize);

        let init_block = |image: &mut [u8], layout: &NandLayout, logical_offset: usize, logical_block_size: usize| {
            let zero_block = vec![0u8; logical_block_size];
            Self::write_data_hybrid(image, logical_offset, &zero_block, layout);
        };

        if blocks_needed > 1 {
            for x in start_search..total_blocks {
                if x + blocks_needed > self.block_map.len() {
                    break;
                }
                if (0..blocks_needed).any(|i| (self.block_map[x + i] & 0x7FFF) != 0x1FFE) {
                    continue;
                }

                for i in 0..blocks_needed {
                    let block = x + i;
                    self.block_map[block] = if i + 1 < blocks_needed { (block + 1) as u16 } else { 0x1FFF };
                    init_block(image, layout, block * logical_block_size, logical_block_size);
                }

                return x as u16;
            }
        }

        for x in start_search..total_blocks {
            if x >= self.block_map.len() {
                break;
            }
            if (self.block_map[x] & 0x7FFF) != 0x1FFE {
                continue;
            }

            self.block_map[x] = 0x1FFF;
            init_block(image, layout, x * logical_block_size, logical_block_size);
            return x as u16;
        }

        let mut free_count = 0;
        let mut protected_count = 0;
        let mut in_use_count = 0;
        for &b in &self.block_map {
            match b & 0x7FFF {
                0x1FFE => free_count += 1,
                0x1FFF | 0 => in_use_count += 1,
                _ => protected_count += 1,
            }
        }
        error!(
            "[flashfs] ALLOCATION FAILURE: No free blocks found! (Free: {}, Protected: {}, In-Use: {}, Total: {})",
            free_count,
            protected_count,
            in_use_count,
            self.block_map.len()
        );
        0
    }

    pub fn set_block_data(&self, image: &mut [u8], layout: &NandLayout, block: u16, data: &[u8]) {
        let page_size = layout.page_size();
        let pages_per_block = layout.logical_pages_per_block();
        let start_page = (block + self.block_offset) as usize * pages_per_block;
        let block_offset = start_page * page_size;

        Self::write_data_hybrid(image, block_offset, data, layout);
    }

    pub fn set_chain_data(&mut self, image: &mut [u8], layout: &NandLayout, start_block: u16, data: &[u8]) -> Result<(), String> {
        let placeholder;
        let data: &[u8] = if data.is_empty() {
            placeholder = [0u8; 1];
            &placeholder[..]
        } else {
            data
        };
        let chunk_size = layout.logical_pages_per_block() * layout.page_size();
        let needed = (data.len() + chunk_size - 1) / chunk_size;

        loop {
            let chain = self.get_block_chain(start_block, self.block_map.len());

            if chain.len() == needed {
                // Exact fit - write and done.
                let mut wrote = 0;
                for (i, &b) in chain.iter().enumerate() {
                    let sz = std::cmp::min(chunk_size, data.len() - wrote);
                    self.set_block_data(image, layout, b, &data[wrote..wrote + sz]);
                    wrote += sz;
                    if i == needed - 1 {
                        break;
                    }
                }
                return Ok(());
            } else if chain.len() < needed {
                // Too short - extend by one block and loop.
                let curr = *chain.last().unwrap_or(&start_block);
                let min_alloc = if self.block_number >= 0 { self.block_number as u16 } else { 0 };
                let next = self.allocate_new_block(image, layout, 1, min_alloc);
                if next == 0 {
                    return Err(format!("FlashFS allocation failure extending chain starting at {} (need {} blocks, have {})", start_block, needed, chain.len()));
                }
                info!("[flashfs]   + Expanding chain: {} -> {}", curr, next);
                self.block_map[curr as usize] = next;
                // Loop repeats with updated block_map.
            } else {
                // Too long - shrink: free tail blocks after [needed-1], then re-run for exact fit.
                let tail_start = chain[needed]; // first excess block
                self.free_block_chain(tail_start);
                self.block_map[chain[needed - 1] as usize] = 0x1FFF; // re-mark end of chain
                                                                     // Loop again - chain is now exactly `needed` long.
            }
        }
    }

    pub fn set_entry_data(&mut self, image: &mut [u8], layout: &NandLayout, entry: &mut FileSystemEntry, data: &[u8]) -> Result<(), String> {
        let min_alloc = if self.block_number >= 0 { self.block_number as u16 } else { 0 };
        if entry.block_number == 0 {
            entry.block_number = self.allocate_new_block(image, layout, 1, min_alloc);
            if entry.block_number == 0 {
                return Err(format!("FlashFS allocation failure allocating starting block for '{}'", entry.file_name));
            }
        }
        self.set_chain_data(image, layout, entry.block_number, data)?;
        entry.size = data.len() as u32;
        entry.data = data.to_vec();
        Ok(())
    }

    pub fn replace_file(&mut self, image: &mut [u8], layout: &NandLayout, name: &str, data: &[u8]) -> Result<(), String> {
        let entry_idx = self
            .entries
            .iter()
            .position(|e| e.file_name == name && !e.deleted)
            .ok_or_else(|| format!("File not found or already deleted: {}", name))?;

        // Use a temporary entry reference to update data
        let mut entry = self.entries[entry_idx].clone();
        self.set_entry_data(image, layout, &mut entry, data)?;
        self.entries[entry_idx] = entry;

        info!("[flashfs] Replaced asset: {} (New Size: 0x{:X})", name, data.len());
        Ok(())
    }

    pub fn inject_file(&mut self, image: &mut [u8], layout: &NandLayout, name: &str, data: &[u8]) -> Result<(), String> {
        if self.entries.iter().any(|e| e.file_name == name && !e.deleted) {
            return Err(format!("File already exists: {}. Use replace instead.", name));
        }

        let mut new_entry = FileSystemEntry::new(0);
        new_entry.file_name = name.to_string();
        self.set_entry_data(image, layout, &mut new_entry, data)?;
        self.entries.push(new_entry);

        info!("[flashfs] Injected new asset: {} (Size: 0x{:X})", name, data.len());
        Ok(())
    }

    /// Forensically deletes a file by marking it with the 0x05 prefix and freeing its chain.
    pub fn delete_file(&mut self, name: &str) -> Result<(), String> {
        let entry_idx = self
            .entries
            .iter()
            .position(|e| e.file_name == name && !e.deleted)
            .ok_or_else(|| format!("File not found: {}", name))?;

        let start_block = self.entries[entry_idx].block_number;
        if start_block != 0 {
            self.free_block_chain(start_block);
        }

        self.entries[entry_idx].deleted = true;
        // The 0x05 prefix is handled during write_into/write_logical
        info!("[flashfs] Forensically deleted asset: {}", name);
        Ok(())
    }

    pub fn extract_asset(&self, name: &str) -> Option<Vec<u8>> {
        self.entries.iter().find(|e| e.file_name == name && !e.deleted).map(|e| e.data.clone())
    }

    pub fn write_logical(&mut self, image: &mut [u8], layout: &NandLayout) -> Result<(), String> {
        let page_size = layout.page_size();
        let pages_per_block = layout.logical_pages_per_block();
        let logical_block_size = pages_per_block * page_size;

        let bm_count = page_size / 2;
        let fn_count = page_size / 0x20;

        let mut non_deleted_count = 0;
        for i in 0..self.entries.len() {
            if self.entries[i].deleted {
                continue;
            }
            non_deleted_count += 1;

            let min_alloc = if self.block_number >= 0 { self.block_number as u16 } else { 0 };
            if self.entries[i].block_number == 0 {
                let blk = self.allocate_new_block(image, layout, 1, min_alloc);
                if blk == 0 {
                    return Err(format!("FlashFS allocation failure allocating data blocks for '{}'", self.entries[i].file_name));
                }
                self.entries[i].block_number = blk;
            }

            let blk_num = self.entries[i].block_number;
            let entry_data = self.entries[i].data.clone();
            self.set_chain_data(image, layout, blk_num, &entry_data)?;
        }

        let root_blocks_needed = if *layout == NandLayout::Emmc {
            let bmap_blocks = (self.block_map.len() + bm_count - 1) / bm_count.max(1);
            let entry_blocks = (non_deleted_count + fn_count - 1) / fn_count.max(1);
            bmap_blocks + entry_blocks
        } else {
            let max_entries_per_root_block = ((pages_per_block + 1) / 2) * fn_count;
            let max_bmap_per_root_block = (pages_per_block / 2) * bm_count;
            let root_blocks_needed_for_entries = (non_deleted_count + max_entries_per_root_block - 1) / max_entries_per_root_block.max(1);
            let root_blocks_needed_for_bmap = (self.block_map.len() + max_bmap_per_root_block - 1) / max_bmap_per_root_block.max(1);
            root_blocks_needed_for_entries.max(root_blocks_needed_for_bmap)
        }
        .max(1);

        let mut new_root_chain: Vec<u16> = Vec::new();
        let root_start = if self.block_number >= 0 { self.block_number as u16 } else { 0 };

        if root_start != 0 {
            let old_chain = self.get_block_chain(root_start, self.block_map.len());
            for &b in old_chain.iter().skip(1) {
                self.free_block_chain(b);
            }
            self.block_map[root_start as usize] = 0x1FFF;
            new_root_chain.push(root_start);
        }

        while new_root_chain.len() < root_blocks_needed {
            let blk = self.allocate_new_block(image, layout, 1, root_start);
            if blk == 0 {
                error!("[flashfs] Failed to allocate new root chain block (need {} blocks)", root_blocks_needed);
                for &b in new_root_chain.iter().skip(if root_start != 0 { 1 } else { 0 }) {
                    self.free_block_chain(b);
                }
                return Err(format!("FlashFS allocation failure allocating root chain (need {} blocks)", root_blocks_needed));
            }
            new_root_chain.push(blk);
        }

        if root_start == 0 {
            self.block_number = new_root_chain[0] as i32;
            self.version += 1;
        }

        for i in 0..new_root_chain.len().saturating_sub(1) {
            self.block_map[new_root_chain[i] as usize] = new_root_chain[i + 1];
        }
        if let Some(&last) = new_root_chain.last() {
            self.block_map[last as usize] = 0x1FFF;
        }

        if root_start != 0 {
            self.block_number = root_start as i32;
            self.version += 1;
        }

        let mut entry_idx = 0;
        let mut bmap_idx = 0;

        for (root_chain_idx, &root_block) in new_root_chain.iter().enumerate() {
            let mut root_buffer = vec![0x00u8; logical_block_size];
            if *layout == NandLayout::Emmc {
                let bmap_blocks = (self.block_map.len() + bm_count - 1) / bm_count.max(1);
                if root_chain_idx < bmap_blocks {
                    let mut bm_in_page = 0;
                    while bmap_idx < self.block_map.len() && bm_in_page < bm_count {
                        let off = bm_in_page * 2;
                        root_buffer[off..off + 2].copy_from_slice(&self.block_map[bmap_idx].to_be_bytes());
                        bm_in_page += 1;
                        bmap_idx += 1;
                    }
                } else {
                    let mut fn_in_page = 0;
                    while entry_idx < self.entries.len() {
                        if self.entries[entry_idx].deleted {
                            entry_idx += 1;
                            continue;
                        }
                        if fn_in_page >= fn_count {
                            break;
                        }
                        let off = fn_in_page * 0x20;
                        let mut chunk = [0u8; 0x20];
                        self.entries[entry_idx].write_into(&mut chunk);
                        root_buffer[off..off + 0x20].copy_from_slice(&chunk);
                        fn_in_page += 1;
                        entry_idx += 1;
                    }
                }
                let logical_start = root_block as usize * page_size;
                Self::write_data_hybrid(image, logical_start, &root_buffer, layout);
                continue;
            }
            let mut bm_pages = Vec::new();
            let mut fn_pages = Vec::new();
            for i in 0..pages_per_block {
                if i % 2 == 0 {
                    bm_pages.push(i);
                } else {
                    fn_pages.push(i);
                }
            }

            let mut fn_p_idx = 0;
            let mut fn_in_page = 0;
            while entry_idx < self.entries.len() {
                if self.entries[entry_idx].deleted {
                    entry_idx += 1;
                    continue;
                }

                if fn_p_idx >= fn_pages.len() {
                    break;
                }

                let off = fn_pages[fn_p_idx] * page_size + fn_in_page * 0x20;
                let mut chunk = [0u8; 0x20];
                self.entries[entry_idx].write_into(&mut chunk);
                root_buffer[off..off + 0x20].copy_from_slice(&chunk);

                fn_in_page += 1;
                if fn_in_page >= fn_count {
                    fn_in_page = 0;
                    fn_p_idx += 1;
                }
                entry_idx += 1;
            }

            let mut bm_p_idx = 0;
            let mut bm_in_page = 0;
            while bmap_idx < self.block_map.len() {
                if bm_p_idx >= bm_pages.len() {
                    break;
                }

                let off = bm_pages[bm_p_idx] * page_size + bm_in_page * 2;
                root_buffer[off..off + 2].copy_from_slice(&self.block_map[bmap_idx].to_be_bytes());

                bm_in_page += 1;
                if bm_in_page >= bm_count {
                    bm_in_page = 0;
                    bm_p_idx += 1;
                }
                bmap_idx += 1;
            }

            let logical_start = root_block as usize * pages_per_block * page_size;
            Self::write_data_hybrid(image, logical_start, &root_buffer, layout);
        }
        Ok(())
    }

    fn write_data_hybrid(image: &mut [u8], logical_offset: usize, data: &[u8], layout: &NandLayout) {
        if crate::core::images::blocks::has_spare(image) {
            crate::core::images::blocks::write_logical_data(image, logical_offset, data, *layout);
        } else {
            if logical_offset + data.len() <= image.len() {
                image[logical_offset..logical_offset + data.len()].copy_from_slice(data);
            }
        }
    }

    pub fn serialize_logical(&self, layout: NandLayout) -> Vec<u8> {
        let page_size = layout.page_size();
        let pages_per_block = layout.logical_pages_per_block();
        let logical_block_size = pages_per_block * page_size;

        let mut image = vec![0x00u8; logical_block_size];

        let mut bm_pages = Vec::new();
        let mut fn_pages = Vec::new();
        for i in 0..pages_per_block {
            if i % 2 == 0 {
                bm_pages.push(i);
            } else {
                fn_pages.push(i);
            }
        }
        let fn_count = page_size / 0x20;
        let mut j = 0;
        for entry_source in &self.entries {
            if entry_source.deleted {
                continue;
            }
            let entry = entry_source.clone();
            let fn_p_idx = j / fn_count;
            if fn_p_idx < fn_pages.len() {
                let off = fn_pages[fn_p_idx] * page_size + (j % fn_count) * 0x20;
                if off + 0x20 <= image.len() {
                    let mut chunk = [0u8; 0x20];
                    entry.write_into(&mut chunk);
                    image[off..off + 0x20].copy_from_slice(&chunk);
                }
            }
            j += 1;
        }
        let bm_count = page_size / 2;
        for (idx, &block) in self.block_map.iter().enumerate() {
            let bm_p_idx = idx / bm_count;
            if bm_p_idx < bm_pages.len() {
                let off = bm_pages[bm_p_idx] * page_size + (idx % bm_count) * 2;
                if off + 2 <= image.len() {
                    image[off..off + 2].copy_from_slice(&block.to_be_bytes());
                }
            }
        }
        image
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct FlashFS {
    pub root: FileSystemRoot,
}

impl FlashFS {
    pub fn new() -> Self {
        FlashFS { root: FileSystemRoot::new(-1, 0, 0x30) }
    }

    fn pick_fs_root(best_main: Option<(usize, u32)>, best_alt: Option<(usize, u32)>, logical: &[u8], layout: &NandLayout) -> FileSystemRoot {
        if let Some((block, seq)) = best_main {
            let mut root = FileSystemRoot::new(block as i32, seq as i32, 0x30);
            root.read(logical, layout);
            return root;
        }
        if let Some((block, seq)) = best_alt {
            let mut root = FileSystemRoot::new(block as i32, seq as i32, 0x2C);
            root.read(logical, layout);
            return root;
        }
        FileSystemRoot::new(-1, 0, 0x30)
    }

    /// Scans physical image for FlashFS signatures.
    pub fn scan_physical(image: &[u8], layout: &NandLayout) -> Self {
        let mut fs = FlashFS::new();
        let total_blocks = layout.total_blocks(image.len());
        let pages_per_block = layout.logical_pages_per_block();
        let mut best_main: Option<(usize, u32)> = None;
        let mut best_alt: Option<(usize, u32)> = None;

        if *layout == NandLayout::Emmc {
            let corona = crate::builder::filesystem::corona::load_slots(image);
            if let Some((block, ver)) = crate::builder::filesystem::corona::best_fs_from_slots(&corona) {
                best_main = Some((block, ver));
            }
        }

        let bb_fmt = if *layout == NandLayout::Bb {
            detect_bb_physical_format(image)
        } else {
            BbPhysicalFormat::PerPage
        };
        for block in 0..total_blocks {
            if is_bad_block(image, block, layout) {
                continue;
            }
            if let Some(spare) = get_page_spare_fmt(image, block * pages_per_block, layout, bb_fmt) {
                let parsed = FsSpareData::parse(&spare, layout);
                let btype = parsed.fs_block_type;
                let seq = parsed.fs_sequence;
                match btype {
                    0x30 => {
                        if best_main.map(|(_, s)| seq > s).unwrap_or(true) {
                            best_main = Some((block, seq));
                        }
                    }
                    0x2C => {
                        if best_alt.map(|(_, s)| seq > s).unwrap_or(true) {
                            best_alt = Some((block, seq));
                        }
                    }
                    _ => {}
                }
            }
        }

        let logical = remove_spare(image);
        fs.root = Self::pick_fs_root(best_main, best_alt, &logical, layout);
        fs
    }

    /// Scans physical image for FlashFS signatures with LBA map awareness.
    pub fn scan_physical_with_lba(image: &[u8], layout: &NandLayout, lba_map: &crate::core::images::blocks::LbaMap) -> Self {
        let mut fs = FlashFS::new();
        let total_blocks = layout.total_blocks(image.len());
        let pages_per_block = layout.logical_pages_per_block();
        let mut best_main: Option<(usize, u32)> = None;
        let mut best_alt: Option<(usize, u32)> = None;

        if *layout == NandLayout::Emmc {
            let corona = crate::builder::filesystem::corona::load_slots(image);
            for entry in corona.iter() {
                if entry.fs_version > 0 {
                    let block = entry.fs_block_idx as usize;
                    let ver = entry.fs_version;
                    if best_main.map(|(_, v)| ver > v).unwrap_or(true) {
                        info!("[flashfs] Corona slot: block {}, version {}", block, ver);
                        best_main = Some((block, ver));
                    }
                }
            }

            for &offset in &EMMC_ANCHOR_OFFSETS {
                if offset + 0x20 > image.len() {
                    continue;
                }
                if &image[offset..offset + 4] == b"ANCH" {
                    let mut cursor = Cursor::new(&image[offset + 4..offset + 20]);
                    let version = cursor.read_u32::<BigEndian>().unwrap_or(0);
                    let block = cursor.read_u32::<BigEndian>().unwrap_or(0) as usize;
                    if best_main.map(|(_, v)| version > v).unwrap_or(true) {
                        info!("[flashfs] EMMC Anchor v{} found at 0x{:X}: block {}", version, offset, block);
                        best_main = Some((block, version));
                    }
                }
            }
        }

        info!("[flashfs] FlashFS scan: {} blocks to examine, {} known bad blocks", total_blocks, lba_map.bad_blocks.len());

        if *layout != NandLayout::Emmc {
            let bb_fmt = if *layout == NandLayout::Bb {
                detect_bb_physical_format(image)
            } else {
                BbPhysicalFormat::PerPage
            };
            for block in 0..total_blocks {
                if lba_map.is_bad(block) || is_bad_block(image, block, layout) {
                    continue;
                }
                if let Some(spare) = get_page_spare_fmt(image, block * pages_per_block, layout, bb_fmt) {
                    let parsed = FsSpareData::parse(&spare, layout);
                    let seq = parsed.fs_sequence;
                    match parsed.fs_block_type {
                        0x30 => {
                            if best_main.map(|(_, s)| seq > s).unwrap_or(true) {
                                best_main = Some((block, seq));
                            }
                        }
                        0x2C => {
                            if best_alt.map(|(_, s)| seq > s).unwrap_or(true) {
                                best_alt = Some((block, seq));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        let logical = remove_spare(image);
        fs.root = Self::pick_fs_root(best_main, best_alt, &logical, layout);

        if fs.root.block_number >= 0 {
            info!("[flashfs] Root found: block {}, version {}", fs.root.block_number, fs.root.version);
        } else {
            info!("[flashfs] No FlashFS root detected in image.");
        }

        fs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_entry_data_can_span_fragmented_free_blocks() {
        let layout = NandLayout::Sb;
        let mut image = vec![0xFF; 0x1000000];
        let mut root = FileSystemRoot::new(0x110, 3, 0x30);
        root.create_defaults(image.len(), &layout, 0x110);

        // leave only isolated free blocks so no two-block run exists.
        for block in 4..root.block_map.len() {
            if block == 0x110 {
                continue;
            }
            root.block_map[block] = if block % 2 == 0 { 0x1FFE } else { 0x1FFB };
        }

        let chunk_size = layout.logical_pages_per_block() * 0x200;
        let data = vec![0xAB; chunk_size + 0x20];
        let mut entry = FileSystemEntry::new(0);
        entry.file_name = "sysupdate.xexp1".to_string();

        root.set_entry_data(&mut image, &layout, &mut entry, &data).unwrap();

        assert_ne!(entry.block_number, 0);
        let chain = root.get_block_chain(entry.block_number, root.block_map.len());
        assert_eq!(chain.len(), 2);
        assert_ne!(chain[1], chain[0] + 1);
    }
}
