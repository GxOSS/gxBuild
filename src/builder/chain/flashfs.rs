/*
    flashfs.rs - 4 type FlashFS parser and builder
    
    Modified in 2026 by Exposure / Zach for GGX
    Licensed under GPLv2 (inherited from RGBuild).
*/

use std::io::{Read, Write, Cursor};
use std::collections::HashMap;
use crate::core::data::blocks::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

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
    pub fn parse(data: &[u8], layout: &NandLayout) -> Self {
        if data.len() < 16 {
            return FsSpareData { block_id: 0, fs_sequence: 0, fs_size: 0, fs_page_count: 0, fs_block_type: 0, bad_block: false };
        }
        match layout {
            NandLayout::Xsb | NandLayout::Sb => {
                let block_id = u16::from_le_bytes([data[0], data[1] & 0xF]);
                // RGBuild: seq = (seq3<<24)|(seq2<<16)|(seq1<<8)|seq0
                // where seq0=spare[2], seq1=spare[3], seq2=spare[4], seq3=spare[6]
                let fs_sequence = ((data[6] as u32) << 24)
                    | ((data[4] as u32) << 16)
                    | ((data[3] as u32) << 8)
                    |  (data[2] as u32);
                // spare[5] != 0xFF means manufacturer marked bad (same sense as is_bad_block)
                let bad_block = data[5] != 0xFF;
                let fs_size = u16::from_be_bytes([data[7], data[8]]);
                let fs_page_count = data[9];
                let fs_block_type = data[12];
                FsSpareData { block_id, fs_sequence, fs_size, fs_page_count, fs_block_type, bad_block }
            }
            NandLayout::Bb => {
                let block_id = u16::from_le_bytes([data[1], data[2] & 0xF]);
                let fs_sequence = u32::from_be_bytes([0, data[5], data[4], data[3]]);
                // spare[0] != 0xFF means manufacturer marked bad
                let bad_block = data[0] != 0xFF;
                let fs_size = u16::from_be_bytes([data[7], data[8]]);
                let fs_page_count = data[9];
                let fs_block_type = data[12];
                FsSpareData { block_id, fs_sequence, fs_size, fs_page_count, fs_block_type, bad_block }
            }
            NandLayout::Emmc => {
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
        let end = name_buf.iter().position(|&c| c == 0).unwrap_or(0x16);
        let mut name = String::from_utf8_lossy(&name_buf[..end]).to_string();
        if !name.is_empty() && name_buf[0] == 0x05 {
            self.deleted = true;
            name = format!("_{}", &name[1..]);
        }
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
        println!(" -> Building FlashFS from memory with {} assets...", files.len());
        for (name, content) in files {
            println!("   * Processing asset: {} (Size: 0x{:X})", name, content.len());
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
                eprintln!("[FlashFS] Cycle detected in block chain at block {}!", current);
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
        for cluster in chain {
            let start_page = (cluster + self.block_offset) as usize * pages_per_block;
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
        let chunk_size = layout.logical_pages_per_block() * 0x200;
        let needed = (data.len() + chunk_size - 1) / chunk_size;

        loop {
            let chain = self.get_block_chain(start_block, self.block_map.len());

            if chain.len() == needed {
                // Exact fit — write and done.
                let mut wrote = 0;
                for (i, &b) in chain.iter().enumerate() {
                    let sz = std::cmp::min(chunk_size, data.len() - wrote);
                    self.set_block_data(image, layout, b, &data[wrote..wrote + sz]);
                    wrote += sz;
                    if i == needed - 1 { break; }
                }
                break;
            } else if chain.len() < needed {
                // Too short — extend by one block and loop.
                let curr = *chain.last().unwrap_or(&start_block);
                let next = self.allocate_new_block(image, layout, 1, 0);
                if next == 0 {
                    eprintln!("[FlashFS] Failed to allocate additional block for chain starting at {}", start_block);
                    break;
                }
                println!("     + Expanding chain: {} -> {}", curr, next);
                self.block_map[curr as usize] = next;
                // Loop repeats with updated block_map.
            } else {
                // Too long — shrink: free tail blocks after [needed-1], then re-run for exact fit.
                // This matches RGBuild SetChainData's shrink branch.
                let tail_start = chain[needed]; // first excess block
                self.free_block_chain(tail_start);
                self.block_map[chain[needed - 1] as usize] = 0x1FFF; // re-mark end of chain
                // Loop again — chain is now exactly `needed` long.
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
        let mut image = vec![0xFFu8; self.block_map.len() * logical_block_size];
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
            if entry.block_number != 0 {
                let chain = self.get_block_chain(entry.block_number, self.block_map.len());
                let mut wrote = 0;
                for (i, &block) in chain.iter().enumerate() {
                    let mut to_write = logical_block_size;
                    if i == chain.len() - 1 { to_write = entry.data.len() - wrote; }
                    let off = block as usize * logical_block_size;
                    image[off..off + to_write].copy_from_slice(&entry.data[wrote..wrote+to_write]);
                    wrote += to_write;
                }
            }
            let fn_p_idx = j / fn_count;
            if fn_p_idx < fn_pages.len() {
                let off = fn_pages[fn_p_idx] * 0x200 + (j % fn_count) * 0x20;
                let mut chunk = [0u8; 0x20];
                entry.write_into(&mut chunk);
                image[off..off + 0x20].copy_from_slice(&chunk);
            }
            j += 1;
        }
        let bm_count = 0x200 / 2;
        for (idx, &block) in self.block_map.iter().enumerate() {
            let bm_p_idx = idx / bm_count;
            if bm_p_idx < bm_pages.len() {
                let off = bm_pages[bm_p_idx] * 0x200 + (idx % bm_count) * 2;
                image[off..off+2].copy_from_slice(&block.to_be_bytes());
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
}
