/*
    flashfs.rs - 4 type FlashFS parser and builder
    
    Copyright 2017 Stoker25

    Modified in 2026 by Exposure / Zach for GGX

    This file has been taken from RGBuild and modified, and therefore retains the original
    License.
*/

use std::io::{Read, Write, Cursor};
use crate::builder::tools::blocks::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

#[derive(Debug, Clone, Copy, PartialEq)]
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

#[derive(Debug, Clone)]
pub struct FsSpareData {
    pub block_id: u16,
    pub fs_sequence: u32,
    pub fs_size: u16,
    pub fs_page_count: u8,
    pub fs_block_type: u8,
    pub bad_block: bool,
}

impl FsSpareData {
    pub fn parse(data: &[u8; 16], layout: &NandLayout) -> Self {
        match layout {
            NandLayout::Layout0 | NandLayout::Layout1 => {
                let block_id = u16::from_le_bytes([data[0], data[1] & 0xF]);
                let fs_sequence = u32::from_be_bytes([data[6], data[2], data[3], data[4]]);
                let bad_block = data[5] == 0xFF; 
                let fs_size = u16::from_be_bytes([data[7], data[8]]);
                let fs_page_count = data[9];
                let fs_block_type = data[12]; 

                FsSpareData { block_id, fs_sequence, fs_size, fs_page_count, fs_block_type, bad_block }
            }
            NandLayout::Layout2 => {
                let block_id = u16::from_le_bytes([data[1], data[2] & 0xF]);
                let fs_sequence = u32::from_be_bytes([0, data[5], data[4], data[3]]);
                let bad_block = data[0] == 0xFF;
                let fs_size = u16::from_be_bytes([data[7], data[8]]);
                let fs_page_count = data[9];
                let fs_block_type = data[12];

                FsSpareData { block_id, fs_sequence, fs_size, fs_page_count, fs_block_type, bad_block }
            }
            NandLayout::Layout3 => {
                FsSpareData { block_id: 0, fs_sequence: 0, fs_size: 0, fs_page_count: 0, fs_block_type: 0, bad_block: false }
            }
        }
    }
}

#[derive(Debug, Clone)]
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
        FileSystemEntry {
            page_number,
            file_name: String::new(),
            block_number: 0,
            size: 0,
            timestamp: 0,
            deleted: false,
            data: Vec::new(),
        }
    }
    
    pub fn read_from(&mut self, chunk: &[u8]) {
        let mut cursor = Cursor::new(chunk);
        
        let mut name_buf = [0u8; 0x16];
        cursor.read_exact(&mut name_buf).unwrap();
        
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
        
        cursor.write_all(&name_buf).unwrap();
        cursor.write_u16::<BigEndian>(self.block_number).unwrap();
        cursor.write_u32::<BigEndian>(self.size).unwrap();
        cursor.write_i32::<BigEndian>(self.timestamp).unwrap();
    }
}

#[derive(Debug, Clone)]
pub struct FileSystemRoot {
    pub block_number: i32,
    pub version: i32,
    pub entries: Vec<FileSystemEntry>,
    pub block_map: Vec<u16>,
    pub block_offset: u16,
}

impl FileSystemRoot {
    pub fn new(block_number: i32, version: i32) -> Self {
        FileSystemRoot {
            block_number,
            version,
            entries: Vec::new(),
            block_map: Vec::new(),
            block_offset: 0,
        }
    }

    pub fn read(&mut self, image: &[u8], layout: &NandLayout) {
        self.entries.clear();
        let pages_per_block = layout.block_size() / 0x210;
        let start_page = self.block_number as usize * pages_per_block;
        
        let mut block_map_pages = Vec::new();
        let mut file_name_pages = Vec::new();
        
        for i in 0..pages_per_block {
            if i % 2 == 0 {
                block_map_pages.push(start_page + i);
            } else {
                file_name_pages.push(start_page + i);
            }
        }
        
        let entries_per_page = 0x200 / 0x20;
        let mut break_files = false;

        for page in file_name_pages {
            if break_files { break; }
            let page_offset = page * 0x210;
            if page_offset + 0x200 > image.len() { break; }
            
            for i in 0..entries_per_page {
                let entry_offset = page_offset + (i * 0x20);
                let chunk = &image[entry_offset..entry_offset + 0x20];
                
                let mut entry = FileSystemEntry::new(page as i32);
                entry.read_from(chunk);
                
                if entry.file_name.is_empty() {
                    break_files = true;
                    break;
                }
                
                if !self.entries.iter().any(|e| e.file_name == entry.file_name) {
                    self.entries.push(entry);
                }
            }
        }
        
        let total_blocks = image.len() / layout.block_size();
        self.block_map = vec![0; total_blocks];
        
        let mut j = 0;
        for page in block_map_pages {
            let page_offset = page * 0x210;
            if page_offset + 0x200 > image.len() { break; }
            
            let mut cursor = Cursor::new(&image[page_offset..page_offset + 0x200]);
            for _ in 0..(0x200 / 2) {
                if j >= total_blocks { break; }
                if let Ok(val) = cursor.read_u16::<BigEndian>() {
                    self.block_map[j] = val;
                    j += 1;
                } else {
                    break;
                }
            }
            if j >= total_blocks { break; }
        }
        
        if self.block_number >= 0 && (self.block_number as usize) < self.block_map.len() {
            self.block_map[self.block_number as usize] = 0x1FFF;
        }
    }

    pub fn create_defaults(&mut self, image_len: usize, layout: &NandLayout, fs_start_block: u16) {
        let total_blocks = image_len / layout.block_size();
        self.block_map = vec![0x1FFE; total_blocks];
        
        // Reserve up to the fs_start_block for firmware
        for i in 0..fs_start_block as usize {
            if i < self.block_map.len() {
                self.block_map[i] = 0x1FFB;
            }
        }
        
        // The root itself is reserved
        if self.block_number >= 0 && (self.block_number as usize) < self.block_map.len() {
            self.block_map[self.block_number as usize] = 0x1FFF;
        }
        
        let config_start = layout.reserve_start().saturating_sub(4);
        for i in 0..5 {
            if config_start + i < self.block_map.len() {
                self.block_map[config_start + i] = 0x1FFB;
            }
        }
    }

    pub fn build_from_folder(&mut self, image: &mut [u8], layout: &NandLayout, folder_path: &std::path::Path) -> std::io::Result<()> {
        for entry in std::fs::read_dir(folder_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let name = entry.file_name().to_string_lossy().to_string();
                let file_content = std::fs::read(&path)?;
                
                let mut new_entry = FileSystemEntry::new(0);
                new_entry.file_name = name;
                self.set_entry_data(image, layout, &mut new_entry, &file_content);
                self.entries.push(new_entry);
            }
        }
        self.write(image, layout);
        Ok(())
    }

    pub fn get_block_chain(&self, start_block: u16, limit: usize) -> Vec<u16> {
        if start_block as usize >= self.block_map.len() {
            return Vec::new();
        }
        let mut block_list = Vec::new();
        let mut current_block = start_block;
        let mut i = 0;
        
        loop {
            block_list.push(current_block);
            if current_block as usize >= self.block_map.len() { break; }
            current_block = self.block_map[current_block as usize];
            current_block &= 0x7FFF;
            
            i += 1;
            if current_block == 0 || (current_block & 0x1FFE) == 0x1FFE || current_block as usize >= self.block_map.len() || i >= limit {
                break;
            }
        }
        
        block_list
    }

    pub fn get_chain_data(&self, image: &[u8], layout: &NandLayout, start_block: u16) -> Vec<u8> {
        let chain = self.get_block_chain(start_block, self.block_map.len());
        let mut data = Vec::new();
        let block_size = layout.block_size();
        let pages_per_block = block_size / 0x210;
        
        for cluster in chain {
            let start_offset = (cluster + self.block_offset) as usize * block_size;
            for p in 0..pages_per_block {
                let page_offset = start_offset + (p * 0x210);
                if page_offset + 0x200 <= image.len() {
                    data.extend_from_slice(&image[page_offset..page_offset + 0x200]);
                }
            }
        }
        data
    }

    pub fn allocate_new_block(&mut self, image: &mut [u8], layout: &NandLayout, blocks_needed: usize, minimum_block: u16) -> u16 {
        let total_blocks = image.len() / layout.block_size();
        for x in minimum_block as usize..total_blocks {
            let mut cont = false;
            for i in 0..blocks_needed {
                if x + i >= self.block_map.len() {
                    cont = true;
                    break;
                }
                if (self.block_map[x + i] & 0x7FFF) != 0x1FFE {
                    cont = true;
                    break;
                }
            }

            if cont { continue; }

            self.block_map[x] = 0x1FFF;
            
            // Blank the newly allocated block natively in memory
            let start_offset = x * layout.block_size();
            if start_offset + layout.block_size() <= image.len() {
                image[start_offset..start_offset + layout.block_size()].fill(0);
            }
            return x as u16;
        }
        0
    }

    pub fn set_block_data(&self, image: &mut [u8], layout: &NandLayout, block: u16, data: &[u8]) {
        let block_size = layout.block_size();
        let pages_per_block = block_size / 0x210;
        let start_offset = (block + self.block_offset) as usize * block_size;
        
        if start_offset + block_size > image.len() { return; }

        let mut data_cursor = Cursor::new(data);
        for p in 0..pages_per_block {
            let page_offset = start_offset + (p * 0x210);
            // Zero out spare block mapping info (FsSequence, FsSize) for block recreation natively
            image[page_offset + 0x200..page_offset + 0x210].fill(0);
            
            // Write payload chunk
            let mut chunk = vec![0u8; 0x200];
            let read_bytes = data_cursor.read(&mut chunk).unwrap_or(0);
            image[page_offset..page_offset + 0x200].copy_from_slice(&chunk);
        }
    }

    pub fn free_block_chain(&mut self, start_block: u16) {
        let chain = self.get_block_chain(start_block, self.block_map.len());
        for block in chain {
            if (block as usize) < self.block_map.len() {
                self.block_map[block as usize] = 0x1FFE;
            }
        }
    }

    pub fn set_chain_data(&mut self, image: &mut [u8], layout: &NandLayout, start_block: u16, data: &[u8]) {
        let mut actual_data = data.to_vec();
        if actual_data.is_empty() {
            actual_data = vec![0];
        }
        
        let current_chain = self.get_block_chain(start_block, self.block_map.len());
        let logic_block_size = layout.block_size() / 0x210 * 0x200; // Raw payload span inside a block
        let mut blocks_needed = actual_data.len() / logic_block_size;
        if actual_data.len() % logic_block_size > 0 {
            blocks_needed += 1;
        }
        
        if current_chain.len() == blocks_needed {
            let mut wrote = 0;
            for (i, &block) in current_chain.iter().enumerate() {
                let mut to_write = logic_block_size;
                if i == blocks_needed - 1 {
                    to_write = actual_data.len() - wrote;
                }
                self.set_block_data(image, layout, block, &actual_data[wrote..wrote+to_write]);
                wrote += to_write;
            }
        } else if current_chain.len() < blocks_needed {
            let blocks_to_allocate = blocks_needed - current_chain.len();
            let mut current_block = *current_chain.last().unwrap_or(&0);
            
            for _ in 0..blocks_to_allocate {
                let next_block = self.allocate_new_block(image, layout, 1, 0);
                self.block_map[current_block as usize] = next_block;
                current_block = next_block;
            }
            self.set_chain_data(image, layout, start_block, data);
        } else {
            self.free_block_chain(current_chain[blocks_needed - 1]);
            self.block_map[current_chain[blocks_needed - 1] as usize] = 0x1FFF;
            self.set_chain_data(image, layout, start_block, data);
        }
    }

    pub fn get_entry_data(&self, image: &[u8], layout: &NandLayout, entry: &FileSystemEntry) -> Vec<u8> {
        let mut data = self.get_chain_data(image, layout, entry.block_number);
        if data.len() > entry.size as usize {
            data.truncate(entry.size as usize);
        }
        data
    }

    pub fn set_entry_data(&mut self, image: &mut [u8], layout: &NandLayout, entry: &mut FileSystemEntry, data: &[u8]) {
        if entry.block_number == 0 {
            let logic_block_size = layout.block_size() / 0x210 * 0x200;
            let needed = std::cmp::max(1, (data.len() + logic_block_size - 1) / logic_block_size);
            entry.block_number = self.allocate_new_block(image, layout, needed, 0);
        }
        self.set_chain_data(image, layout, entry.block_number, data);
        entry.size = data.len() as u32;
        entry.data = data.to_vec();
    }

    pub fn delete_entry(&mut self, entry: &FileSystemEntry) {
        self.free_block_chain(entry.block_number);
        self.entries.retain(|e| e.file_name != entry.file_name);
    }

    pub fn write(&mut self, image: &mut [u8], layout: &NandLayout) {
        let pages_per_block = layout.logical_pages_per_block();
        let start_page = self.block_number as usize * pages_per_block;
        
        let mut block_map_pages = Vec::new();
        let mut file_name_pages = Vec::new();
        
        for i in 0..pages_per_block {
            if i % 2 == 0 { block_map_pages.push(start_page + i); } 
            else { file_name_pages.push(start_page + i); }
        }

        let fn_count = 0x200 / 0x20;
        let bm_count = 0x200 / 2;
        
        // Use physical_page_size for raw IO offsets
        let physical_page_size = layout.physical_page_size();

        // Ensure blocks are zeroed out before applying new block maps natively
        for &page in &block_map_pages {
            let offset = page * physical_page_size;
            if offset + 0x200 <= image.len() {
                image[offset..offset + physical_page_size].fill(0);
            }
        }
        for &page in &file_name_pages {
            let offset = page * physical_page_size;
            if offset + 0x200 <= image.len() {
                image[offset..offset + physical_page_size].fill(0);
            }
        }

        let mut current_fn_page = 0;
        let mut j = 0;
        
        // Safe copy of non-deleted entries avoiding borrow rules on SetEntryData
        let entries_to_write: Vec<_> = self.entries.iter().filter(|e| !e.deleted).cloned().collect();
        for mut entry in entries_to_write {
            let data = entry.data.clone();
            self.set_entry_data(image, layout, &mut entry, &data);
            
            if j > 0 && j % fn_count == 0 {
                current_fn_page += 1;
            }
            if current_fn_page < file_name_pages.len() {
                let page_offset = file_name_pages[current_fn_page] * physical_page_size;
                let chunk_start = page_offset + ((j % fn_count) * 0x20);
                if chunk_start + 0x20 <= image.len() {
                    let mut chunk = [0u8; 0x20];
                    entry.write_into(&mut chunk);
                    image[chunk_start..chunk_start + 0x20].copy_from_slice(&chunk);
                }
            }
            j += 1;
        }

        let mut current_bm_page = 0;
        let mut bm_j = 0;
        for &block in &self.block_map {
            if bm_j > 0 && bm_j % bm_count == 0 {
                current_bm_page += 1;
            }
            if current_bm_page < block_map_pages.len() {
                let page_offset = block_map_pages[current_bm_page] * physical_page_size;
                let chunk_start = page_offset + ((bm_j % bm_count) * 2);
                if chunk_start + 2 <= image.len() {
                    image[chunk_start..chunk_start + 2].copy_from_slice(&block.to_be_bytes());
                }
            }
            bm_j += 1;
        }
    }
}

pub struct FlashFS {
    pub root: FileSystemRoot,
    pub partitions: std::collections::HashMap<u8, FileSystemRoot>,
}

impl FlashFS {
    pub fn new() -> Self {
        FlashFS {
            root: FileSystemRoot::new(-1, 0),
            partitions: std::collections::HashMap::new(),
        }
    }

    /// Scans a raw NAND image for all filesystem partitions using Highest Sequence Wins.
    pub fn scan(image: &[u8], layout: &NandLayout) -> Self {
        let mut fs = FlashFS::new();
        let total_blocks = layout.total_blocks(image.len());
        let pages_per_block = layout.logical_pages_per_block();
        
        let mut best_sequences: std::collections::HashMap<u8, (usize, u32)> = std::collections::HashMap::new();

        for block in 0..total_blocks {
            // Check if block is bad
            if is_bad_block(image, block, layout) {
                continue;
            }

            // Peek first page spare
            if let Some(spare) = get_page_spare(image, block * pages_per_block) {
                let parsed = FsSpareData::parse(&spare, layout);
                let btype = parsed.fs_block_type;

                // Identify if it's a known partition type
                if btype == 0x30 || btype == 0x2C || (0x31..=0x39).contains(&btype) {
                    let seq = parsed.fs_sequence;
                    let is_newer = match best_sequences.get(&btype) {
                        Some(&(_, best_seq)) => seq > best_seq,
                        None => true,
                    };

                    if is_newer {
                        best_sequences.insert(btype, (block, seq));
                    }
                }
            }
        }

        // Hydrate all found partitions
        for (btype, (block, seq)) in best_sequences {
            let mut root = FileSystemRoot::new(block as i32, seq as i32);
            root.read(image, layout);
            
            if btype == 0x30 || btype == 0x2C {
                fs.root = root.clone();
            }
            fs.partitions.insert(btype, root);
        }

        fs
    }
}
