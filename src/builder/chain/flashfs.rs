/*
    flashfs.rs - 4 type FlashFS parser and builder
    
    Modified in 2026 by Exposure / Zach for GGX
    Licensed under GPLv2 (inherited from RGBuild).
*/

use std::io::{Read, Write, Cursor};
use std::collections::HashMap;
use crate::core::data::blocks::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use log::{info, error};

/// Calculates the base block offset for MetaType2 (Big-Block) NANDs when reading FlashFS file data.
/// Based on x360Utils NANDFileSystem.GetBaseBlockForMeta2():
///   baseBlock = (0x1E0 - FsPageCount - (FsSize0 << 2)) * 8
///
/// This offset must be added to each block number in the chain when extracting file data
/// from big-block NAND images.
pub fn get_fs_base_block_for_meta2(
    image: &[u8],
    layout: &NandLayout,
    fs_root_spare_page: usize,
) -> u16 {
    if *layout != NandLayout::Bb { return 0; }

    // Read the spare data from the FS root block's first page
    let spare_offset = fs_root_spare_page * layout.physical_page_size() + layout.page_size();
    if spare_offset + 16 > image.len() { return 0; }

    let spare = &image[spare_offset..spare_offset + 16];
    let parsed = FsSpareData::parse(spare, layout);

    // reserved = 0x1E0 - FsPageCount - (FsSize0 << 2)
    // Note: FsSize for MetaType2 has FsSize0 at byte [8], FsSize1 at byte [7]
    // The size is (FsSize0 << 8) | FsSize1, but we need FsSize0 << 2
    // x360Utils: reserved -= meta.Meta2.FsSize0 << 2
    // FsSize0 = spare[8] = the high byte of fs_size word = fs_size >> 8
    // (fs_size >> 8) << 2 is NOT the same as fs_size >> 6 when the low byte of fs_size is non-zero.
    // Example: fs_size=0x01C0 -> (>>8)<<2 = 4, but >>6 = 7 (wrong).
    let reserved = 0x1E0u32
        .saturating_sub(parsed.fs_page_count as u32)
        .saturating_sub(((parsed.fs_size >> 8) as u32) << 2);

    (reserved * 8) as u16
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum FileSystemExEntries {
    FsRootEntryAlt = 0x2c,
    FsRootEntry = 0x30,
    MobileB = 0x31,
    MobileC = 0x32,
    MobileD = 0x33,
    MobileE = 0x34,
    MobileF = 0x35,
    MobileG = 0x36,
    MobileH = 0x37,
    MobileI = 0x38,
    MobileJ = 0x39,
    InvalidMobileJ = 0x40,
    InUseMobileJ = 0x80,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FsSpareData {
    pub block_id: u16,
    pub fs_sequence: u32,
    pub fs_size: u16,
    pub fs_page_count: u8,
    pub fs_block_type: u8,
    pub bad_block: bool,
}

impl FsSpareData {
    /// Parses spare metadata from a 16-byte spare area.
    /// Based on x360Utils NANDSpare.MetaData with correct byte offsets per MetaType:
    ///
    /// | Field       | MetaType0 (Pre-Jasper) | MetaType1 (Jasper/Trinity/Corona) | MetaType2 (Big-Block) |
    /// |-------------|----------------------|----------------------------------|----------------------|
    /// | BlockID     | [1]&0xF<<8 \| [0]    | [2]&0xF<<8 \| [1]                | [2]&0xF<<8 \| [1]    |
    /// | BadBlock    | [5]                  | [5]                              | [0]                  |
    /// | FsSequence  | [2]\|[3]<<8\|[4]<<16 | [0]\|[3]<<8\|[4]<<16             | [5]\|[4]<<8\|[3]<<16 |
    /// | FsSize      | [8]<<8 \| [7]        | [8]<<8 \| [7]                    | [8]<<8 \| [7]        |
    /// | FsPageCount | [9]                  | [9]                              | [9] * 4              |
    /// | FsBlockType | [12] & 0x3F          | [12] & 0x3F                      | [12] & 0x3F          |
    pub fn parse(data: &[u8], layout: &NandLayout) -> Self {
        if data.len() < 16 {
            return FsSpareData { block_id: 0, fs_sequence: 0, fs_size: 0, fs_page_count: 0, fs_block_type: 0, bad_block: false };
        }

        // Determine MetaType from layout
        let meta_type = match layout {
            NandLayout::Xsb => crate::core::data::blocks::SpareMetaType::MetaType0,
            NandLayout::Sb  => crate::core::data::blocks::SpareMetaType::MetaType1,
            NandLayout::Bb  => crate::core::data::blocks::SpareMetaType::MetaType2,
            NandLayout::Emmc => crate::core::data::blocks::SpareMetaType::MetaTypeNone,
        };

        match meta_type {
            crate::core::data::blocks::SpareMetaType::MetaType0 => {
                // Pre-Jasper: BlockID at [0..1], FsSequence at [2..4], BadBlock at [5]
                let block_id = u16::from_le_bytes([data[0], data[1] & 0xF]);
                let fs_sequence = (data[2] as u32)
                    | ((data[3] as u32) << 8)
                    | ((data[4] as u32) << 16);
                let bad_block = data[5] != 0xFF;
                let fs_size = u16::from_be_bytes([data[8], data[7]]);
                let fs_page_count = data[9];
                let fs_block_type = data[12] & 0x3F;
                FsSpareData { block_id, fs_sequence, fs_size, fs_page_count, fs_block_type, bad_block }
            }
            crate::core::data::blocks::SpareMetaType::MetaType1 => {
                // Jasper/Trinity/Corona: BlockID at [1..2], FsSequence at [0,3..4], BadBlock at [5]
                let block_id = u16::from_le_bytes([data[1], data[2] & 0xF]);
                let fs_sequence = (data[0] as u32)
                    | ((data[3] as u32) << 8)
                    | ((data[4] as u32) << 16);
                let bad_block = data[5] != 0xFF;
                let fs_size = u16::from_be_bytes([data[8], data[7]]);
                let fs_page_count = data[9];
                let fs_block_type = data[12] & 0x3F;
                FsSpareData { block_id, fs_sequence, fs_size, fs_page_count, fs_block_type, bad_block }
            }
            crate::core::data::blocks::SpareMetaType::MetaType2 => {
                // Big-Block: BlockID at [1..2], FsSequence at [3..5], BadBlock at [0]
                let block_id = u16::from_le_bytes([data[1], data[2] & 0xF]);
                let fs_sequence = (data[5] as u32)
                    | ((data[4] as u32) << 8)
                    | ((data[3] as u32) << 16);
                let bad_block = data[0] != 0xFF;
                let fs_size = u16::from_be_bytes([data[8], data[7]]);
                let fs_page_count = data[9] * 4; // Big-block: page count multiplied by 4
                let fs_block_type = data[12] & 0x3F;
                FsSpareData { block_id, fs_sequence, fs_size, fs_page_count, fs_block_type, bad_block }
            }
            crate::core::data::blocks::SpareMetaType::MetaTypeNone => {
                FsSpareData { block_id: 0, fs_sequence: 0, fs_size: 0, fs_page_count: 0, fs_block_type: 0, bad_block: false }
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileSystemEntry {
    pub page_number: i32,
    pub file_name: String,
    pub block_number: u16,
    pub size: u32,
    pub timestamp: i32,
    pub deleted: bool,
    pub data: Vec<u8>,
}

impl FileSystemEntry {
    pub fn new(page_number: i32) -> Self {
        FileSystemEntry { page_number, file_name: String::new(), block_number: 0, size: 0, timestamp: 0, deleted: false, data: Vec::new() }
    }
    
    pub fn read_from(&mut self, chunk: &[u8]) {
        let mut cursor = Cursor::new(chunk);
        let mut name_buf = [0u8; 0x16];
        let _ = cursor.read_exact(&mut name_buf);
        // Check the raw first byte before any lossy UTF-8 conversion.
        // Slicing the lossy string after conversion is fragile if 0x05 was substituted by U+FFFD (3 bytes).
        // Matches RGBuild: if (FileName[0] == 0x05) { FileName = "_" + ...; Deleted = true; }
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
}

impl FileSystemRoot {
    pub fn new(block_number: i32, version: i32) -> Self {
        FileSystemRoot { block_number, version, entries: Vec::new(), block_map: Vec::new(), block_offset: 0 }
    }

    /// Reads FlashFS from a logical clean buffer.
    pub fn read(&mut self, image: &[u8], layout: &NandLayout) {
        self.entries.clear();
        let pages_per_block = layout.logical_pages_per_block();
        let start_page = self.block_number as usize * pages_per_block;
        
        let mut block_map_pages = Vec::new();
        let mut file_name_pages = Vec::new();
        for i in 0..pages_per_block {
            if i % 2 == 0 { block_map_pages.push(start_page + i); } 
            else { file_name_pages.push(start_page + i); }
        }
        
        let mut break_files = false;
        for page in file_name_pages {
            if break_files { break; }
            let page_offset = page * 0x200;
            if page_offset + 0x200 > image.len() { break; }
            for i in 0..(0x200 / 0x20) {
                let entry_offset = page_offset + (i * 0x20);
                let mut entry = FileSystemEntry::new(page as i32);
                entry.read_from(&image[entry_offset..entry_offset + 0x20]);
                if entry.file_name.is_empty() { break_files = true; break; }
                if !self.entries.iter().any(|e| e.file_name == entry.file_name) {
                    self.entries.push(entry);
                }
            }
        }
        
        let logical_block_size = pages_per_block * 0x200;
        let total_blocks = image.len() / logical_block_size;
        self.block_map = vec![0; total_blocks];
        let mut j = 0;
        for page in block_map_pages {
            let offset = page * 0x200;
            if offset + 0x200 > image.len() { break; }
            let mut cursor = Cursor::new(&image[offset..offset + 0x200]);
            for _ in 0..128 {
                if j >= total_blocks { break; }
                if let Ok(val) = cursor.read_u16::<BigEndian>() {
                    self.block_map[j] = val;
                    j += 1;
                }
            }
            if j >= total_blocks { break; }
        }
        if self.block_number >= 0 && (self.block_number as usize) < self.block_map.len() {
            self.block_map[self.block_number as usize] = 0x1FFF;
        }

        // Calibrate BlockOffset for Big-Block NANDs by searching for .xex headers
        if *layout == NandLayout::Bb {
            self.calibrate_block_offset(image, layout);
        }
    }

    /// Calibrates the physical BlockOffset for Big-Block (MetaType2) NANDs.
    /// Ported from RGBuild::NANDImage.cs (LoadFileSystem): 
    /// Searches for "XEX2" or "XEX1" headers at common offsets (0xAE0, 0x2E0) 
    /// relative to an existing .xex file's starting block.
    pub fn calibrate_block_offset(&mut self, image: &[u8], layout: &NandLayout) {
        if *layout != NandLayout::Bb { return; }

        let pages_per_block = layout.logical_pages_per_block();
        let logical_block_size = pages_per_block * 0x200;

        for entry in self.entries.iter().filter(|e| !e.deleted && e.file_name.to_lowercase().ends_with(".xex")) {
            let base_block = entry.block_number;
            
            // Common offsets to check: 0xAE0, 0x2E0, 0x0
            for &offset in &[0xAE0u16, 0x2E0u16, 0x0u16] {
                let physical_block = base_block.wrapping_add(offset) as usize;
                let page_offset = physical_block * logical_block_size;
                
                if page_offset + 4 <= image.len() {
                    let sig = &image[page_offset..page_offset + 4];
                    if sig == b"XEX2" || sig == b"XEX1" {
                        info!("[flashfs] Calibrated BlockOffset: 0x{:X} (Found {} signature at block {})", 
                               offset, String::from_utf8_lossy(sig), physical_block);
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
        
        // Reserve the System/Bootloader area (0-3 is critical, 0-fs_start_block for others)
        let system_limit = std::cmp::max(4, fs_start_block as usize);
        for i in 0..system_limit {
            if i < self.block_map.len() { self.block_map[i] = 0x1FFB; }
        }

        if self.block_number >= 0 && (self.block_number as usize) < self.block_map.len() {
            self.block_map[self.block_number as usize] = 0x1FFF;
        }
        let config_start = layout.reserve_start(image_len).saturating_sub(4);
        for i in 0..5 {
            if config_start + i < self.block_map.len() { self.block_map[config_start + i] = 0x1FFB; }
        }
    }

    pub fn build_from_folder(image: &mut [u8], layout: &NandLayout, folder_path: &std::path::Path, fs_start_block: u16) -> std::io::Result<Self> {
        let mut root = FileSystemRoot::new(-1, 0);
        root.create_defaults(image.len(), layout, fs_start_block);
        for entry in std::fs::read_dir(folder_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let name = entry.file_name().to_string_lossy().to_string();
                let content = std::fs::read(&path)?;
                let mut new_entry = FileSystemEntry::new(0);
                new_entry.file_name = name;
                root.set_entry_data(image, layout, &mut new_entry, &content);
                root.entries.push(new_entry);
            }
        }
        if root.block_number == -1 { root.block_number = root.allocate_new_block(image, layout, 1, fs_start_block) as i32; }
        root.write_logical(image, layout);
        Ok(root)
    }

    pub fn build_from_memory(image: &mut [u8], layout: &NandLayout, files: &HashMap<String, Vec<u8>>, fs_start_block: u16) -> std::io::Result<Self> {
        let mut root = FileSystemRoot::new(-1, 0);
        root.create_defaults(image.len(), layout, fs_start_block);
        info!("[flashfs] Building FlashFS from memory with {} assets...", files.len());
        for (name, content) in files {
            info!("[flashfs]   * Processing asset: {} (Size: 0x{:X})", name, content.len());
            let mut new_entry = FileSystemEntry::new(0);
            new_entry.file_name = name.clone();
            root.set_entry_data(image, layout, &mut new_entry, content);
            root.entries.push(new_entry);
        }
        if root.block_number == -1 { root.block_number = root.allocate_new_block(image, layout, 1, fs_start_block) as i32; }
        root.write_logical(image, layout);
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
            if current as usize >= self.block_map.len() { break; }
            current = self.block_map[current as usize] & 0x7FFF;
            i += 1;
            if current == 0 || (current & 0x1FFE) == 0x1FFE || current as usize >= self.block_map.len() || i >= limit {
                break;
            }
        }
        list
    }

    /// Sets every block in the chain starting at `start_block` back to 0x1FFE (free).
    /// Equivalent to RGBuild's FreeBlockChain. Required by set_chain_data shrink path.
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

        // For MetaType2 (Big-Block), calculate base block offset for file data.
        // Based on x360Utils NANDFileSystem.GetBaseBlockForMeta2():
        //   baseBlock = (0x1E0 - FsPageCount - (FsSize0 << 2)) * 8
        let base_block_offset: u16 = if *layout == NandLayout::Bb {
            // Find the FS root block's spare data to extract FsPageCount and FsSize
            // The FS root block is at self.block_number
            let root_block = self.block_number as usize;
            let root_spare_page = root_block * pages_per_block;
            get_fs_base_block_for_meta2(image, layout, root_spare_page)
        } else {
            0
        };

        for cluster in chain {
            // Add base block offset for big-block NANDs
            let adjusted_cluster = cluster.wrapping_add(base_block_offset);
            let start_page = (adjusted_cluster + self.block_offset) as usize * pages_per_block;
            for p in 0..pages_per_block {
                let off = (start_page + p) * 0x200;
                if off + 0x200 <= image.len() { data.extend_from_slice(&image[off..off + 0x200]); }
            }
        }
        data
    }

    pub fn allocate_new_block(&mut self, image: &mut [u8], layout: &NandLayout, blocks_needed: usize, minimum_block: u16) -> u16 {
        let p_block_size = layout.logical_pages_per_block() * 0x200;
        let total_blocks = image.len() / p_block_size;
        
        // Never allow allocation below block 4 to protect the header/SMC/KV
        let start_search = std::cmp::max(4, minimum_block as usize);

        for x in start_search..total_blocks {
            let mut cont = false;
            for i in 0..blocks_needed {
                if x + i >= self.block_map.len() || (self.block_map[x+i] & 0x7FFF) != 0x1FFE { cont = true; break; }
            }
            if cont { continue; }
            self.block_map[x] = 0x1FFF;
            let off = x * p_block_size;
            if off + p_block_size <= image.len() { image[off..off + p_block_size].fill(0); }
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
        error!("[flashfs] ALLOCATION FAILURE: No free blocks found! (Free: {}, Protected: {}, In-Use: {}, Total: {})", 
               free_count, protected_count, in_use_count, self.block_map.len());
        0
    }

    pub fn set_block_data(&self, image: &mut [u8], layout: &NandLayout, block: u16, data: &[u8]) {
        let pages_per_block = layout.logical_pages_per_block();
        let start_page = (block + self.block_offset) as usize * pages_per_block;
        let mut cursor = Cursor::new(data);
        for p in 0..pages_per_block {
            let off = (start_page + p) * 0x200;
            if off + 0x200 > image.len() { break; }
            let mut chunk = [0u8; 0x200];
            let _ = cursor.read(&mut chunk);
            image[off..off + 0x200].copy_from_slice(&chunk);
        }
    }

    pub fn set_chain_data(&mut self, image: &mut [u8], layout: &NandLayout, start_block: u16, data: &[u8]) {
        // Guard: zero-length data → needed=0 → shrink path frees the start block immediately.
        // RGBuild: if (data.Length == 0) data = new byte[1];
        let placeholder;
        let data: &[u8] = if data.is_empty() {
            placeholder = [0u8; 1];
            &placeholder[..]
        } else {
            data
        };
        let chunk_size = layout.logical_pages_per_block() * 0x200;
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
                    if i == needed - 1 { break; }
                }
                break;
            } else if chain.len() < needed {
                // Too short - extend by one block and loop.
                let curr = *chain.last().unwrap_or(&start_block);
                let next = self.allocate_new_block(image, layout, 1, 0);
                if next == 0 {
                    error!("[flashfs] Failed to allocate additional block for chain starting at {}. Required expansion beyond {} blocks", start_block, chain.len());
                    break;
                }
                info!("[flashfs]   + Expanding chain: {} -> {}", curr, next);
                self.block_map[curr as usize] = next;
                // Loop repeats with updated block_map.
            } else {
                // Too long - shrink: free tail blocks after [needed-1], then re-run for exact fit.
                // This matches RGBuild SetChainData's shrink branch.
                let tail_start = chain[needed]; // first excess block
                self.free_block_chain(tail_start);
                self.block_map[chain[needed - 1] as usize] = 0x1FFF; // re-mark end of chain
                // Loop again - chain is now exactly `needed` long.
            }
        }
    }

    pub fn set_entry_data(&mut self, image: &mut [u8], layout: &NandLayout, entry: &mut FileSystemEntry, data: &[u8]) {
        if entry.block_number == 0 {
            let chunk_size = layout.logical_pages_per_block() * 0x200;
            let needed = (data.len() + chunk_size - 1) / chunk_size;
            entry.block_number = self.allocate_new_block(image, layout, needed, 0);
        }
        self.set_chain_data(image, layout, entry.block_number, data);
        entry.size = data.len() as u32;
        entry.data = data.to_vec();
    }

    /// Surgically replaces the content of an existing file.
    pub fn replace_file(&mut self, image: &mut [u8], layout: &NandLayout, name: &str, data: &[u8]) -> Result<(), String> {
        let entry_idx = self.entries.iter().position(|e| e.file_name == name && !e.deleted)
            .ok_or_else(|| format!("File not found or already deleted: {}", name))?;
        
        // Use a temporary entry reference to update data
        let mut entry = self.entries[entry_idx].clone();
        self.set_entry_data(image, layout, &mut entry, data);
        self.entries[entry_idx] = entry;
        
        info!("[flashfs] Replaced asset: {} (New Size: 0x{:X})", name, data.len());
        Ok(())
    }

    /// Injects a new file into the filesystem root.
    pub fn inject_file(&mut self, image: &mut [u8], layout: &NandLayout, name: &str, data: &[u8]) -> Result<(), String> {
        if self.entries.iter().any(|e| e.file_name == name && !e.deleted) {
            return Err(format!("File already exists: {}. Use replace instead.", name));
        }

        let mut new_entry = FileSystemEntry::new(0);
        new_entry.file_name = name.to_string();
        self.set_entry_data(image, layout, &mut new_entry, data);
        self.entries.push(new_entry);

        info!("[flashfs] Injected new asset: {} (Size: 0x{:X})", name, data.len());
        Ok(())
    }

    /// Forensically deletes a file by marking it with the 0x05 prefix and freeing its chain.
    pub fn delete_file(&mut self, name: &str) -> Result<(), String> {
        let entry_idx = self.entries.iter().position(|e| e.file_name == name && !e.deleted)
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

    /// High-level extraction of a filesystem asset.
    pub fn extract_asset(&self, name: &str) -> Option<Vec<u8>> {
        self.entries.iter()
            .find(|e| e.file_name == name && !e.deleted)
            .map(|e| e.data.clone())
    }

    pub fn write_logical(&mut self, image: &mut [u8], layout: &NandLayout) {
        let pages_per_block = layout.logical_pages_per_block();
        let start_page = self.block_number as usize * pages_per_block;
        let mut bm_pages = Vec::new();
        let mut fn_pages = Vec::new();
        for i in 0..pages_per_block {
            if i % 2 == 0 { bm_pages.push(start_page + i); } else { fn_pages.push(start_page + i); }
        }
        let fn_count = 0x200 / 0x20;
        // Process entries in-place so block_number allocations persist to self.entries.
        // Matches RGBuild Write() which operates on reference-type entries directly.
        let mut j = 0;
        for i in 0..self.entries.len() {
            if self.entries[i].deleted { continue; }
            // Allocate block if not yet assigned.
            if self.entries[i].block_number == 0 {
                let chunk_size = layout.logical_pages_per_block() * 0x200;
                let data_len = self.entries[i].data.len();
                let needed = (data_len + chunk_size - 1) / chunk_size;
                let blk = self.allocate_new_block(image, layout, needed.max(1), 0);
                self.entries[i].block_number = blk;
            }
            let block_number = self.entries[i].block_number;
            let data = self.entries[i].data.clone();
            self.set_chain_data(image, layout, block_number, &data);
            let fn_p_idx = j / fn_count;
            if fn_p_idx < fn_pages.len() {
                let off = fn_pages[fn_p_idx] * 0x200 + (j % fn_count) * 0x20;
                let mut chunk = [0u8; 0x20];
                self.entries[i].write_into(&mut chunk);
                image[off..off + 0x20].copy_from_slice(&chunk);
            }
            j += 1;
        }
        let bm_count = 0x200 / 2;
        for (idx, &block) in self.block_map.iter().enumerate() {
            let bm_p_idx = idx / bm_count;
            if bm_p_idx < bm_pages.len() {
                let off = bm_pages[bm_p_idx] * 0x200 + (idx % bm_count) * 2;
                image[off..off + 2].copy_from_slice(&block.to_be_bytes());
            }
        }
    }

    pub fn serialize_logical(&self, layout: NandLayout) -> Vec<u8> {
        let pages_per_block = layout.logical_pages_per_block();
        let logical_block_size = pages_per_block * 0x200;
        // serialize_logical() produces exactly ONE FlashFS block (0x4000 bytes for Sb/Bb).
        // The caller writes this buffer at the correct block offset in the full NAND image.
        let mut image = vec![0xFFu8; logical_block_size];
        let start_page = self.block_number as usize * pages_per_block;
        let mut bm_pages = Vec::new();
        let mut fn_pages = Vec::new();
        for i in 0..pages_per_block {
            if i % 2 == 0 { bm_pages.push(start_page + i); } else { fn_pages.push(start_page + i); }
        }
        let fn_count = 0x200 / 0x20;
        let mut j = 0;
        for entry_source in &self.entries {
            if entry_source.deleted { continue; }
            let entry = entry_source.clone();
            // Note: file data lives at chain block offsets in the full NAND image,
            // not inside this root block. serialize_logical() only writes the directory
            // and block-map pages into the single root block buffer.
            let fn_p_idx = j / fn_count;
            if fn_p_idx < fn_pages.len() {
                // Adjust offset to be within this single block
                let local_page = fn_pages[fn_p_idx] - start_page;
                let off = local_page * 0x200 + (j % fn_count) * 0x20;
                if off + 0x20 <= image.len() {
                    let mut chunk = [0u8; 0x20];
                    entry.write_into(&mut chunk);
                    image[off..off + 0x20].copy_from_slice(&chunk);
                }
            }
            j += 1;
        }
        let bm_count = 0x200 / 2;
        for (idx, &block) in self.block_map.iter().enumerate() {
            let bm_p_idx = idx / bm_count;
            if bm_p_idx < bm_pages.len() {
                let local_page = bm_pages[bm_p_idx] - start_page;
                let off = local_page * 0x200 + (idx % bm_count) * 2;
                if off + 2 <= image.len() {
                    image[off..off+2].copy_from_slice(&block.to_be_bytes());
                }
            }
        }
        image
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct FlashFS {
    pub root: FileSystemRoot,
    pub partitions: std::collections::HashMap<u8, FileSystemRoot>,
}

impl FlashFS {
    pub fn new() -> Self {
        FlashFS { root: FileSystemRoot::new(-1, 0), partitions: std::collections::HashMap::new() }
    }

    /// Scans a physical (raw) image for FlashFS signatures using spare metadata,
    /// then reads block content from the logical (spare-stripped) view.
    pub fn scan_physical(image: &[u8], layout: &NandLayout) -> Self {
        let mut fs = FlashFS::new();
        let total_blocks = layout.total_blocks(image.len());
        let pages_per_block = layout.logical_pages_per_block();
        let mut best: std::collections::HashMap<u8, (usize, u32)> = std::collections::HashMap::new();

        // Phase 1: walk spare data in the physical image to locate FS root blocks.
        for block in 0..total_blocks {
            if is_bad_block(image, block, layout) { continue; }
            if let Some(spare) = get_page_spare(image, block * pages_per_block, layout) {
                let parsed = FsSpareData::parse(&spare, layout);
                let btype = parsed.fs_block_type;
                if btype == 0x30 || btype == 0x2C || (0x31..=0x39).contains(&btype) {
                    let seq = parsed.fs_sequence;
                    let newer = match best.get(&btype) { Some(&(_, b_seq)) => seq > b_seq, None => true };
                    if newer { best.insert(btype, (block, seq)); }
                }
            }
        }

        // Phase 2: strip spare so root.read() uses correct 0x200-byte page stride.
        let logical = crate::core::data::blocks::remove_spare(image);

        for (btype, (block, seq)) in best {
            let mut root = FileSystemRoot::new(block as i32, seq as i32);
            root.read(&logical, layout);
            if btype == 0x30 || btype == 0x2C { fs.root = root.clone(); }
            fs.partitions.insert(btype, root);
        }
        fs
    }

    /// Scans a physical (raw) image for FlashFS signatures using spare metadata,
    /// with LBA map awareness for accurate bad block remapping.
    /// Based on x360Utils NANDReader ScanForFsRootAndMobile with LBA tracking.
    pub fn scan_physical_with_lba(image: &[u8], layout: &NandLayout, lba_map: &crate::core::data::blocks::LbaMap) -> Self {
        let mut fs = FlashFS::new();
        let total_blocks = layout.total_blocks(image.len());
        let pages_per_block = layout.logical_pages_per_block();
        let mut best: std::collections::HashMap<u8, (usize, u32)> = std::collections::HashMap::new();
        
        // Phase 1: EMMC Anchor Discovery
        if *layout == NandLayout::Emmc {
            for &offset in &EMMC_ANCHOR_OFFSETS {
                if offset + 0x20 > image.len() { continue; }
                let sig = &image[offset..offset + 4];
                if sig == b"ANCH" {
                    let mut cursor = Cursor::new(&image[offset + 4..offset + 20]);
                    // xeBuild selects the anchor with the HIGHEST VERSION, not sequence.
                    // Log: "anchor block v 2 at 0x2fec000 is selected" (v2 > v1).
                    let version = cursor.read_u32::<BigEndian>().unwrap_or(0);
                    let block   = cursor.read_u32::<BigEndian>().unwrap_or(0) as usize;
                    let _seq    = cursor.read_u32::<BigEndian>().unwrap_or(0);

                    // best stores (block, version) - compare by version
                    let newer = match best.get(&0x30) { Some(&(_, b_ver)) => version > b_ver, None => true };
                    if newer {
                        info!("[flashfs] EMMC Anchor v{} found at 0x{:X}: block {}", version, offset, block);
                        best.insert(0x30, (block, version));
                    }
                }
            }
        }

        info!("[flashfs] FlashFS scan: {} blocks to examine, {} known bad blocks", total_blocks, lba_map.bad_blocks.len());

        // Phase 1.5: walk spare data (Small Block / Big Block only), skipping known bad blocks from LBA map
        if *layout != NandLayout::Emmc {
            for block in 0..total_blocks {
                // Skip blocks known to be bad
                if lba_map.is_bad(block) { continue; }
                if is_bad_block(image, block, layout) { continue; }
                if let Some(spare) = get_page_spare(image, block * pages_per_block, layout) {
                    let parsed = FsSpareData::parse(&spare, layout);
                    let btype = parsed.fs_block_type;
                    if btype == 0x30 || btype == 0x2C || (0x31..=0x39).contains(&btype) {
                        let seq = parsed.fs_sequence;
                        let newer = match best.get(&btype) { Some(&(_, b_seq)) => seq > b_seq, None => true };
                        if newer { best.insert(btype, (block, seq)); }
                    }
                }
            }
        }

        // Phase 2: strip spare so root.read() uses correct 0x200-byte page stride.
        let logical = crate::core::data::blocks::remove_spare(image);

        for (btype, (block, seq)) in best {
            let mut root = FileSystemRoot::new(block as i32, seq as i32);
            root.read(&logical, layout);
            if btype == 0x30 || btype == 0x2C { fs.root = root.clone(); }
            fs.partitions.insert(btype, root);
        }

        if fs.root.block_number >= 0 {
            info!("[flashfs] Root found: block {}, version {}", fs.root.block_number, fs.root.version);
        } else {
            info!("[flashfs] No FlashFS root detected in image.");
        }

        fs
    }
}
