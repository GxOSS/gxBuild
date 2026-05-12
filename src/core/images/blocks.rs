/*
    blocks.rs - ECC, Spare data, and bad blocks manager

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under GPLv2 (inherited from xenon-bltool).
*/
use log::info;

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NandLayout {
    Xsb,
    Sb,
    Bb,
    Emmc,
}

pub const EMMC_ANCHOR_OFFSETS: [usize; 4] = [0x2fe0000, 0x2fe4000, 0x2fe8000, 0x2fec000];

#[derive(Clone, Copy, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SpareMetaType {
    /// Small Block XSB
    MetaType0,
    /// Small Block PSB/KSB
    MetaType1,
    /// Big Block
    MetaType2,
    /// eMMC / Logical Image
    #[default]
    MetaTypeNone,
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SpareProfile {
    None,
    Metadata,
    FileSystem,
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BadBlock {
    pub block: usize,
    pub target: usize,
}

impl NandLayout {
    pub fn block_size(&self) -> usize {
        match self {
            NandLayout::Xsb | NandLayout::Sb => 0x4200,
            NandLayout::Bb => 0x21000,
            NandLayout::Emmc => 0x200,
        }
    }

    pub fn logical_pages_per_block(&self) -> usize {
        match self {
            NandLayout::Xsb | NandLayout::Sb => 32,
            NandLayout::Bb => 256,
            NandLayout::Emmc => 1,
        }
    }

    pub fn total_blocks(&self, image_len: usize) -> usize {
        let logical_block_size = self.logical_pages_per_block() * 0x200;
        let physical_block_size = self.block_size();

        if physical_block_size > 0 && image_len % physical_block_size == 0 {
            image_len / physical_block_size
        } else if logical_block_size > 0 && image_len % logical_block_size == 0 {
            image_len / logical_block_size
        } else {
            // Default fallback if it's neither perfectly logical nor perfectly physical
            image_len / physical_block_size
        }
    }

    pub fn page_size(&self) -> usize {
        0x200
    }

    pub fn spare_size(&self) -> usize {
        match self {
            NandLayout::Emmc => 0,
            _ => 0x10,
        }
    }

    pub fn physical_page_size(&self) -> usize {
        self.page_size() + self.spare_size()
    }

    pub fn logical_to_physical(&self, logical_page: usize) -> u64 {
        match self {
            NandLayout::Emmc => logical_page as u64,
            NandLayout::Xsb | NandLayout::Sb => {
                ((logical_page / 512) * 528 + (logical_page % 512)) as u64
            }
            NandLayout::Bb => {
                ((logical_page / 2048) * 2112 + (logical_page % 2048)) as u64
            }
        }
    }
}

/// Reads `len` bytes starting from logical page `logical_page` in a physical NAND image.
/// Handles cross-page boundary reads transparently by translating each logical page
/// to its physical offset and reading chunks that don't cross physical page boundaries.
pub fn read_logical_from_physical(
    image: &[u8],
    logical_page: usize,
    len: usize,
    layout: NandLayout,
) -> Option<Vec<u8>> {
    if image.is_empty() || len == 0 { return None; }

    let logical_page_size = layout.page_size();
    let mut result = vec![0u8; len];
    let mut cur = 0;

    while cur < len {
        let current_logical = logical_page + (cur / logical_page_size);
        let phys_offset = layout.logical_to_physical(current_logical);
        let page_offset = current_logical % logical_page_size;
        let chunk_len = logical_page_size - page_offset;
        let to_read = std::cmp::min(chunk_len, len - cur);

        if (phys_offset as usize) + to_read > image.len() {
            result.truncate(cur);
            if result.is_empty() { return None; }
            break;
        }

        let src_start = phys_offset as usize + page_offset;
        result[cur..cur + to_read].copy_from_slice(&image[src_start..src_start + to_read]);
        cur += to_read;
    }

    Some(result)
}

/// Writes `data` starting from logical byte offset `logical_offset` into a physical NAND image.
/// Safely handles spare area gaps by translating the logical offset to physical and writing
/// across page boundaries.
pub fn write_logical_data(
    image: &mut [u8],
    logical_offset: usize,
    data: &[u8],
    layout: NandLayout,
) {
    if image.is_empty() || data.is_empty() { return; }

    let logical_page_size = layout.page_size();
    let mut cur = 0;
    let len = data.len();

    while cur < len {
        let current_logical_byte = logical_offset + cur;
        let phys_offset = layout.logical_to_physical(current_logical_byte);
        
        // Calculate how many bytes we can write in the current physical page
        let page_offset = current_logical_byte % logical_page_size;
        let chunk_len = logical_page_size - page_offset;
        let to_write = std::cmp::min(chunk_len, len - cur);

        if (phys_offset as usize) + to_write > image.len() {
            break;
        }

        let dest_start = phys_offset as usize;
        image[dest_start..dest_start + to_write].copy_from_slice(&data[cur..cur + to_write]);
        cur += to_write;
    }
}

impl NandLayout {

    pub fn marker_offset(&self) -> usize {
        match self {
            NandLayout::Xsb | NandLayout::Sb => 0x205,
            NandLayout::Bb => 0x200,
            NandLayout::Emmc => 0, // No marker
        }
    }

    pub fn id_offset(&self) -> usize {
        match self {
            // Xsb/Sb: block ID LSB is at spare[0]
            NandLayout::Xsb | NandLayout::Sb => 0x200,
            // Bb: spare[0] is the bad-block marker (0xFF = good), block ID LSB is at spare[1]
            NandLayout::Bb => 0x201,
            NandLayout::Emmc => 0,
        }
    }

    pub fn reserve_start(&self, _image_len: usize) -> usize {
        match self {
            // Sb is always 16 MB; Xsb has the same reserve region.
            NandLayout::Xsb | NandLayout::Sb => 0x3E0,
            NandLayout::Bb => 0x1E0,
            NandLayout::Emmc => 0,
        }
    }

    pub fn max_blocks(&self) -> usize {
        match self {
            NandLayout::Xsb | NandLayout::Sb => 0x400,
            NandLayout::Bb => 0x200, 
            NandLayout::Emmc => 0, // Not applicable
        }
    }

    pub fn physical_block_size(&self) -> usize {
        self.block_size()
    }

    pub fn detect(image: &[u8]) -> Result<Self, String> {
        let len = image.len();
        let layout = match len {
            // Physical sizes (data + spare, 0x210 bytes/page)
            // 16 MB small block (physical) → Sb; promote to Xsb later via spare inspection
            len if len >= 0x1080000 && len <= 0x1080000 + 0x1000 => Ok(NandLayout::Sb),
            // 64 MB big block (physical)
            len if len >= 0x4200000 && len <= 0x4200000 + 0x1000 => Ok(NandLayout::Bb),
            // 256 MB big block (physical)
            len if len >= 0x10800000 && len <= 0x10800000 + 0x1000 => Ok(NandLayout::Bb),
            // 512 MB big block (physical)
            len if len >= 0x21000000 && len <= 0x21000000 + 0x1000 => Ok(NandLayout::Bb),

            // Logical sizes (no spare, 0x200 bytes/page)
            // 16 MB
            0x1000000 => Ok(NandLayout::Sb),
            // 64 MB
            0x4000000 => Ok(NandLayout::Bb),
            // 256 MB
            0x10000000 => Ok(NandLayout::Bb),
            // 512 MB
            0x20000000 => Ok(NandLayout::Bb),

            // eMMC - no spare (48 MB Trinity/Corona slim, or 4 GB Corona 4G)
            0x3000000 => Ok(NandLayout::Emmc),
            len if len >= 0x30000000 => Ok(NandLayout::Emmc),
            _ => Err(format!("Could not detect NAND layout for size 0x{:x}", len)),
        };

        if let Ok(l) = &layout {
            info!("[blocks] Detected NAND Layout: {:?} (Image Size: 0x{:x})", l, len);
        }
        layout
    }
}

pub fn calculate_ecc(data: &mut [u8]) {
    if data.len() < 0x210 { return; }
    let mut val: u32 = 0;
    let mut v: u32 = 0;
    for i in 0..0x1066 {
        if (i & 31) == 0 {
            let offset = i / 8;
            v = !u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        }
        val ^= v & 1;
        v >>= 1;
        if (val & 1) != 0 { val ^= 0x6954559; }
        val >>= 1;
    }
    val = !val;
    let mut ecc_temp = (val << 6).to_le_bytes();
    // Merge FsBlockType (bottom 6 bits) from the existing metadata byte
    // We mask out the bottom 6 bits of the new ECC byte to prevent bit collision.
    ecc_temp[0] = (ecc_temp[0] & !0x3f) | (data[0x20C] & 0x3F);
    data[0x20C..0x210].copy_from_slice(&ecc_temp);
}

#[derive(Clone, Debug)]
pub struct FsSpareInfo {
    pub sequence: u32,
    pub size: u16,
    pub page_count: u8,
    pub block_type: u8,
}

pub fn add_spare(
    image: &[u8],
    layout: NandLayout,
    meta_type: SpareMetaType,
    blockstart: usize,
    fs_meta: Option<&std::collections::HashMap<usize, FsSpareInfo>>,
    jtag_syscall: Option<u16>
) -> Vec<u8> {
    let page_size = layout.page_size();
    let total_pages = (image.len() + page_size - 1) / page_size;

    info!("[blocks] Finalizing physical image: Generating ECC and Spare Areas...");

    match layout {
        NandLayout::Bb => {
            // Big-block: pack 4 pages + 0x40 spare into 0x840-byte chunks
            let chunk_data = 0x800usize; // 4 pages × 0x200
            let chunk_spare = 0x40usize;  // 4 spare regions × 0x10
            let chunk_total = chunk_data + chunk_spare;
            let chunks = (total_pages + 3) / 4; // Round up
            
            let mut result = vec![0u8; chunks * chunk_total];
            let block_number_base = blockstart / layout.block_size();

            for chunk in 0..chunks {
                let chunk_offset = chunk * chunk_total;
                let page_base = chunk * 4;

                for page_in_chunk in 0..4 {
                    let page_idx = page_base + page_in_chunk;
                    if page_idx >= total_pages { break; }

                    let read_offset = page_idx * page_size;
                    let mut data_block = [0u8; 0x200];
                    let bytes_remaining = image.len().saturating_sub(read_offset);
                    if bytes_remaining > 0 {
                        let sz = std::cmp::min(0x200, bytes_remaining);
                        data_block[..sz].copy_from_slice(&image[read_offset..read_offset + sz]);
                    }

                    // Write data portion
                    let data_offset = chunk_offset + (page_in_chunk * 0x200);
                    result[data_offset..data_offset + 0x200].copy_from_slice(&data_block);

                    // Generate spare data
                    let mut spare = [0u8; 16];
                    spare[0] = 0xFF; // Big-block bad-block marker
                    let val = (page_idx / 256) + block_number_base;
                    
                    if let Some(fs) = fs_meta.and_then(|m| m.get(&val)) {
                        // MetaType2 Encoding for FlashFS
                        spare[1] = (val & 0xFF) as u8;
                        spare[2] = ((val >> 8) & 0xFF) as u8;
                        spare[5] = (fs.sequence & 0xFF) as u8;
                        spare[4] = ((fs.sequence >> 8) & 0xFF) as u8;
                        spare[3] = ((fs.sequence >> 16) & 0xFF) as u8;
                        spare[7] = (fs.size & 0xFF) as u8;
                        spare[8] = ((fs.size >> 8) & 0xFF) as u8;
                        spare[9] = fs.page_count;
                        spare[12] = fs.block_type;
                    } else {
                        spare[1] = (val & 0xFF) as u8;
                        spare[2] = ((val >> 8) & 0xFF) as u8;
                    }

                    // Write spare portion
                    let spare_offset = chunk_offset + 0x800 + (page_in_chunk * 0x10);
                    result[spare_offset..spare_offset + 0x10].copy_from_slice(&spare);
                }

                // Calculate ECC for the entire chunk (data + spare)
                // Big-block ECC is calculated per-page over data+spare combined
                let page_size = layout.page_size();
                for page_in_chunk in 0..4 {
                    let page_size_512 = 0x200; // BB internal ECC chunks are always 512
                    let page_start = chunk_offset + (page_in_chunk * page_size_512);
                    let spare_start = chunk_offset + page_size + (page_in_chunk * 0x10);
                    let mut page_with_spare = [0u8; 0x210];
                    page_with_spare[..0x200].copy_from_slice(&result[page_start..page_start + 0x200]);
                    page_with_spare[0x200..0x210].copy_from_slice(&result[spare_start..spare_start + 0x10]);
                    calculate_ecc(&mut page_with_spare);
                    // Copy ECC back
                    result[spare_start + 0x0C..spare_start + 0x10]
                        .copy_from_slice(&page_with_spare[0x20C..0x210]);
                }
            }
            result
        }
        NandLayout::Xsb | NandLayout::Sb => {
            // Small-block: one page + spare per 0x210-byte chunk
            let p_page_size = layout.physical_page_size();
            let mut result = vec![0u8; total_pages * p_page_size];
            let block_number_base = blockstart / layout.block_size();

            for i in 0..total_pages {
                let read_offset = i * page_size;
                let mut data_block = vec![0u8; page_size];
                let bytes_remaining = image.len().saturating_sub(read_offset);
                if bytes_remaining > 0 {
                    let sz = std::cmp::min(page_size, bytes_remaining);
                    data_block[..sz].copy_from_slice(&image[read_offset..read_offset + sz]);
                }

                let mut spare = [0u8; 16];
                let val = (i / 32) + block_number_base;
                
                // JTAG syscall injection into Page 1 spare (offset 10, Big Endian)
                if i == 1 {
                    if let Some(syscall) = jtag_syscall {
                        spare[10] = (syscall >> 8) as u8;
                        spare[11] = (syscall & 0xFF) as u8;
                        info!("[blocks] Injected JTAG Syscall 0x{:04X} into Page 1 spare", syscall);
                    }
                }

                if let Some(fs) = fs_meta.and_then(|m| m.get(&val)) {
                    spare[5] = 0xFF;
                    spare[7] = (fs.size & 0xFF) as u8;
                    spare[8] = ((fs.size >> 8) & 0xFF) as u8;
                    spare[9] = fs.page_count;
                    spare[12] = fs.block_type;

                    match meta_type {
                        SpareMetaType::MetaType0 => {
                            spare[0] = (val & 0xFF) as u8;
                            spare[1] = ((val / 0x100) & 0xFF) as u8;
                            spare[2] = (fs.sequence & 0xFF) as u8;
                            spare[3] = ((fs.sequence >> 8) & 0xFF) as u8;
                            spare[4] = ((fs.sequence >> 16) & 0xFF) as u8;
                        }
                        SpareMetaType::MetaType1 => {
                            spare[1] = (val & 0xFF) as u8;
                            spare[2] = ((val / 0x100) & 0xFF) as u8;
                            spare[0] = (fs.sequence & 0xFF) as u8;
                            spare[3] = ((fs.sequence >> 8) & 0xFF) as u8;
                            spare[4] = ((fs.sequence >> 16) & 0xFF) as u8;
                        }
                        _ => {}
                    }
                } else {
                    spare[5] = 0xFF;
                    match meta_type {
                        SpareMetaType::MetaType0 => {
                            spare[0] = (val & 0xFF) as u8;
                            spare[1] = ((val / 0x100) & 0xFF) as u8;
                        }
                        SpareMetaType::MetaType1 => {
                            spare[1] = (val & 0xFF) as u8;
                            spare[2] = ((val / 0x100) & 0xFF) as u8;
                        }
                        _ => {}
                    }
                }

                let write_offset = i * p_page_size;
                let page_slice = &mut result[write_offset..write_offset + p_page_size];
                page_slice[..page_size].copy_from_slice(&data_block);
                page_slice[page_size..p_page_size].copy_from_slice(&spare);
                calculate_ecc(page_slice);
            }
            result
        }
        NandLayout::Emmc => {
            // eMMC has no spare data
            image.to_vec()
        }
    }
}

/// Returns true if the image has spare/ECC data appended to each page.
/// Matches J-Runner's hasecc() detection: validates multiple pages and ECC bytes
/// to prevent false positives from erased or corrupted NAND.
pub fn has_spare(image: &[u8]) -> bool {
    // Check for small-block format (spare at +0x200 per page)
    // J-Runner iterates through multiple pages; we check the first few with validation.
    if image.len() > 0x210 {
        let mut counter = 0;
        let mut i: usize = 0x200;
        
        while i < image.len() && counter <= 0x100 {
            // Every 0x800 bytes, there's a 0x40-byte spare block for big-block
            if i % 0x800 == 0 {
                if i + 0x40 <= image.len() {
                    // Check big-block spare pattern
                    if image[i] == 0xFF && 
                       image.get(i + 0x10).copied().unwrap_or(0) == 0xFF &&
                       image.get(i + 0x20).copied().unwrap_or(0) == 0xFF &&
                       image.get(i + 0x30).copied().unwrap_or(0) == 0xFF &&
                       image.get(i + 3).copied().unwrap_or(0) == 0x00 &&
                       image.get(i + 4).copied().unwrap_or(0) == 0x00 
                    {
                        // Verify not all 0xFF
                        let spare_block = &image[i..i + 0x40];
                        if spare_block.iter().any(|&b| b != 0xFF) {
                            return true;
                        }
                    }
                }
                i += 0x40;
            } else {
                // Small-block spare at 0x10 per page
                if i + 0x10 <= image.len() {
                    let spare0 = image[i];
                    let spare5 = image.get(i + 5).copied().unwrap_or(0);
                    let spare3 = image.get(i + 3).copied().unwrap_or(0);
                    let spare4 = image.get(i + 4).copied().unwrap_or(0);
                    
                    // Check: (spare[0]==0xFF || spare[5]==0xFF) && ECC bytes zero && non-uniform data
                    if (spare0 == 0xFF || spare5 == 0xFF) &&
                       spare3 == 0x00 && spare4 == 0x00 &&
                       i + 0x10 <= image.len()
                    {
                        // Check bytes 0xC-0xF are not all 0xFF or all 0x00
                        let ecc_bytes = &image[i + 0xC..i + 0x10];
                        let all_ff = ecc_bytes.iter().all(|&b| b == 0xFF);
                        let all_00 = ecc_bytes.iter().all(|&b| b == 0x00);
                        if !all_ff && !all_00 {
                            return true;
                        }
                    }
                }
                i += 0x10;
            }
            
            i += 0x200;
            if i % 0x4200 == 0 { counter += 1; }
        }
    }
    
    // Big-block fallback: check first spare block at 0x800
    // J-Runner checks data[0x800], data[0x810], data[0x820] for 0xFF
    if image.len() > 0x840 {
        if image[0x800] == 0xFF && 
           image.get(0x810).copied().unwrap_or(0) == 0xFF && 
           image.get(0x820).copied().unwrap_or(0) == 0xFF 
        {
            return true;
        }
    }
    
    false
}

/// Inspects the first valid page's spare data and promotes `Sb` → `Xsb` if
/// the block-ID LSB is at spare[0] (Xsb) rather than spare[1] (Sb).
/// Matches J-Runner's identifylayout(): spare[5]==0xFF && spare[0]!=0x00 → layout 0 (Xsb).
pub fn promote_layout(image: &[u8], layout: NandLayout) -> NandLayout {
    if layout != NandLayout::Sb { return layout; }
    if image.len() < 0x210 { return layout; }
    let spare5 = image[0x205]; // bad-block marker for SB layouts
    let spare0 = image[0x200]; // block-ID LSB for Xsb, or 0x00 for Sb
    if spare5 == 0xFF && spare0 != 0x00 {
        // Non-zero at spare[0] with FF at spare[5] = Xenon spare format
        return NandLayout::Xsb;
    }
    layout
}

/// Detects the spare metadata format (MetaType0/MetaType1/MetaType2) of a physical NAND image.
/// Based on x360Utils NANDSpare.DetectSpareType():
/// 1. Read spare at block 1, page 0 spare area (offset 0x4400)
/// 2. Check if bad - if so, retry at end of image
/// 3. Try MetaType0: LBA == 1 at bytes [1]&0xF<<8 | [0]
/// 4. Try MetaType1: LBA == 1 at bytes [2]&0xF<<8 | [1]
/// 5. Try MetaType2: Read spare at 0x21200, check LBA == 1
pub fn detect_meta_type(image: &[u8], layout: NandLayout) -> SpareMetaType {
    if layout == NandLayout::Emmc { return SpareMetaType::MetaTypeNone; }
    if image.len() < 0x4410 { return SpareMetaType::MetaTypeNone; }

    // Helper to read 16-byte spare at raw offset
    let read_spare = |offset: usize| -> Option<[u8; 16]> {
        if offset + 16 <= image.len() {
            let mut s = [0u8; 16];
            s.copy_from_slice(&image[offset..offset + 16]);
            Some(s)
        } else { None }
    };

    // Try spare at block 1, page 0 (offset 0x4400)
    let spare = match layout {
        NandLayout::Bb => read_spare(0x21800), // Block 1, page 0 spare: 0x21000 (block_size) + 0x800 (spare offset in 0x840-chunk)
        _ => read_spare(0x4400),
    };

    let spare = match spare {
        Some(s) => s,
        None => {
            // Retry at end of image
            if image.len() > 0x4000 {
                read_spare(image.len() - 0x4000).unwrap_or([0u8; 16])
            } else {
                return SpareMetaType::MetaTypeNone;
            }
        }
    };

    // Check for bad block (MetaType0/1: bad marker at [5], MetaType2: at [0])
    let is_bad_mt0_1 = spare[5] != 0xFF;
    let is_bad_mt2 = spare[0] != 0xFF;

    if is_bad_mt0_1 && is_bad_mt2 {
        // Block 1 is bad - retry at end of image
        if image.len() > 0x4000 {
            if let Some(s) = read_spare(image.len() - 0x4000) {
                return detect_from_spare(&s, layout);
            }
        }
        return SpareMetaType::MetaTypeNone;
    }

    detect_from_spare(&spare, layout)
}

/// Internal helper to determine MetaType from a spare data sample.
fn detect_from_spare(spare: &[u8; 16], _layout: NandLayout) -> SpareMetaType {
    // Try MetaType2 (Big Block) first - LBA at bytes [1..2]
    // MetaType2: BlockID = (spare[2]&0xF)<<8 | spare[1]
    let lba_mt2 = ((spare[2] as u16 & 0xF) << 8) | spare[1] as u16;
    if spare[0] == 0xFF && lba_mt2 == 1 {
        return SpareMetaType::MetaType2;
    }

    // Try MetaType0 - LBA at bytes [0..1]
    // MetaType0: BlockID = (spare[1]&0xF)<<8 | spare[0]
    let lba_mt0 = ((spare[1] as u16 & 0xF) << 8) | spare[0] as u16;
    if spare[5] == 0xFF && lba_mt0 == 1 {
        return SpareMetaType::MetaType0;
    }

    // Try MetaType1 - LBA at bytes [1..2]
    // MetaType1: BlockID = (spare[2]&0xF)<<8 | spare[1]
    let lba_mt1 = ((spare[2] as u16 & 0xF) << 8) | spare[1] as u16;
    if spare[5] == 0xFF && lba_mt1 == 1 {
        return SpareMetaType::MetaType1;
    }

    // Default: MetaType1 is most common (Jasper/Trinity/Corona)
    SpareMetaType::MetaType1
}

pub fn remove_spare(image: &[u8]) -> Vec<u8> {
    let Ok(layout) = NandLayout::detect(image) else { return image.to_vec() };
    if layout == NandLayout::Emmc { return image.to_vec(); }
    // Gate on actual spare presence rather than blindly stripping.
    if !has_spare(image) { return image.to_vec(); }

    info!("[blocks] Multi-Core Prep: Stripping Physical Spares/ECC to create Clean Buffer...");
    
    // Big-block NAND uses 0x840-byte chunks (4 pages × 0x200 data + 0x40 spare)
    // Small-block NAND uses 0x210-byte chunks (1 page × 0x200 data + 0x10 spare)
    match layout {
        NandLayout::Bb => {
            // Big-block: strip 0x840 → 0x800
            let chunk_in = 0x840usize;
            let chunk_out = 0x800usize;
            let chunks = image.len() / chunk_in;
            let mut result = vec![0u8; chunks * chunk_out];
            
            for i in 0..chunks {
                let in_offset = i * chunk_in;
                let out_offset = i * chunk_out;
                result[out_offset..out_offset + chunk_out]
                    .copy_from_slice(&image[in_offset..in_offset + chunk_out]);
            }
            result
        }
        NandLayout::Xsb | NandLayout::Sb => {
            // Small-block: strip 0x210 → 0x200
            let p_page = layout.physical_page_size(); // 0x210
            let l_page = layout.page_size();          // 0x200
            let pages = image.len() / p_page;
            let mut result = vec![0u8; pages * l_page];
            
            for i in 0..pages {
                result[i * l_page..(i + 1) * l_page]
                    .copy_from_slice(&image[i * p_page..i * p_page + l_page]);
            }
            result
        }
        NandLayout::Emmc => {
            // Should not reach here due to early return, but handle anyway
            image.to_vec()
        }
    }
}

pub fn get_page_spare(image: &[u8], page: usize, layout: &NandLayout) -> Option<Vec<u8>> {
    let spare_size = layout.spare_size();
    if spare_size == 0 { return None; }
    
    match layout {
        NandLayout::Bb => {
            // Big-block: spare is packed at 0x800 boundaries (4 pages share 0x40 bytes of spare)
            // Pages 0-3 share spare at 0x800, pages 4-7 share spare at 0x1040, etc.
            let group = page / 4;
            let page_in_group = page % 4;
            let group_offset = group * 0x840;
            let spare_offset = group_offset + 0x800 + (page_in_group * 0x10);
            
            if spare_offset + spare_size <= image.len() {
                Some(image[spare_offset..spare_offset + spare_size].to_vec())
            } else { None }
        }
        NandLayout::Xsb | NandLayout::Sb => {
            // Small-block: spare is at offset page_size after each page's data
            let offset = (page * layout.physical_page_size()) + layout.page_size();
            if offset + spare_size <= image.len() {
                Some(image[offset..offset + spare_size].to_vec())
            } else { None }
        }
        NandLayout::Emmc => None,
    }
}

pub fn is_bad_block(image: &[u8], block_number: usize, layout: &NandLayout) -> bool {
    let block_size = layout.block_size();
    let marker_offset = layout.marker_offset();
    let offset = block_number * block_size;
    if offset + block_size > image.len() { return false; }

    let p_page_size = layout.physical_page_size();
    let l_page_size = layout.page_size();
    
    match layout {
        NandLayout::Bb => {
            // Big-block: check first page's spare marker in each 0x840 group
            let pages_per_block = block_size / 0x800; // 0x21000 / 0x800 = 128 groups
            for group in 0..pages_per_block {
                let group_offset = offset + (group * 0x840);
                if group_offset + 0x840 > image.len() { break; }
                
                // Bad-block marker is at spare[0] for big-block (absolute offset +0x800 in group)
                if image.get(group_offset + 0x800).copied().unwrap_or(0) != 0xFF {
                    return true;
                }
            }
            false
        }
        NandLayout::Xsb | NandLayout::Sb => {
            // Small-block: check every page's spare
            let mut i = 0;
            while i + p_page_size <= block_size {
                let page_offset = offset + i;
                let spare = &image[page_offset + l_page_size..page_offset + p_page_size];
                
                // All-zero spare indicates bad block
                if spare.iter().all(|&b| b == 0x00) { return true; }
                
                // Check bad-block marker
                if image[page_offset + marker_offset] != 0xFF {
                    return true;
                }
                i += p_page_size;
            }
            false
        }
        NandLayout::Emmc => false, // eMMC has no spare/bad-block markers
    }
}

#[derive(Clone, Debug)]
pub struct BlockMap {
    pub blocks: Vec<BadBlock>,
    pub layout: NandLayout,
}

impl BlockMap {
    pub fn new(image: &[u8]) -> Option<Self> {
        let layout = NandLayout::detect(image).ok()?;
        let mut bad_blocks = Vec::new();
        for block in 0..layout.total_blocks(image.len()) {
            if is_bad_block(image, block, &layout) {
                bad_blocks.push(BadBlock { block, target: block });
            }
        }
        Some(Self { blocks: bad_blocks, layout })
    }

    pub fn map_and_heal(&mut self, image: &mut [u8]) -> Result<(), String> {
        let bad_indices: Vec<usize> = self.blocks.iter().map(|b| b.block).collect();
        if bad_indices.is_empty() { return Ok(()); }
        
        info!("[blocks] Found {} Bad Physical Blocks. Attempting Healing/Remapping...", bad_indices.len());
        let remapped = resolve_remapped_blocks(image, &bad_indices, &self.layout)?;
        for (i, &bad_block) in bad_indices.iter().enumerate() {
            let target = remapped[i].ok_or_else(|| format!("Bad block {} not remapped", bad_block))?;
            info!("[blocks] Remapping Bad Block {} -> Reserved Physical Block {}", bad_block, target);
            let b_size = self.layout.block_size();
            let mut buf = vec![0u8; b_size];
            buf.copy_from_slice(&image[target * b_size..target * b_size + b_size]);
            image[bad_block * b_size..bad_block * b_size + b_size].copy_from_slice(&buf);
            image[target * b_size..target * b_size + b_size].fill(0xFF);
            self.blocks[i].target = target;
        }
        Ok(())
    }
}

pub fn resolve_remapped_blocks(image: &[u8], bad_blocks: &[usize], layout: &NandLayout) -> Result<Vec<Option<usize>>, String> {
    let mut remapped = vec![None; bad_blocks.len()];
    let mut resolved = 0;
    let b_size = layout.block_size();
    let res_start = layout.reserve_start(image.len());
    let pages_per_block = layout.logical_pages_per_block();

    for block_idx in (0..0x20).rev() {
        if resolved == bad_blocks.len() { break; }
        let physical_block = res_start + block_idx;
        let offset = physical_block * b_size;
        if offset + b_size > image.len() { continue; }

        // Extract block IDs via FsSpareData so nibble masking matches FsSpareData::parse.
        let first_page = physical_block * pages_per_block;
        let last_page  = first_page + pages_per_block - 1;

        let id1 = get_page_spare(image, first_page, layout)
            .map(|s| crate::builder::chain::flashfs::FsSpareData::parse(&s, layout).block_id as usize)
            .unwrap_or(usize::MAX);
        let id2 = get_page_spare(image, last_page, layout)
            .map(|s| crate::builder::chain::flashfs::FsSpareData::parse(&s, layout).block_id as usize)
            .unwrap_or(usize::MAX);

        for (i, &bad) in bad_blocks.iter().enumerate() {
            if remapped[i].is_some() { continue; }
            if bad == id1 || bad == id2 {
                remapped[i] = Some(physical_block);
                resolved += 1;
                break;
            }
        }
    }
    Ok(remapped)
}

pub struct NandProcessor;

/// Tracks logical-to-physical block mapping after bad block healing.
/// Based on x360Utils NANDReader LBA tracking functionality.
/// This allows the builder to:
/// 1. Know which physical blocks are bad (and thus shouldn't be used)
/// 2. Write correct spare metadata when finalizing a NAND image
/// 3. Verify that the built image has proper bad block markers
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LbaMap {
    /// List of bad physical blocks that were detected and remapped.
    pub bad_blocks: Vec<usize>,
    /// Maps each logical block number to its physical location.
    /// If a logical block was remapped due to bad block, this tracks
    /// the new physical location.
    pub logical_to_physical: Vec<usize>,
    /// Spare metadata format detected (MetaType0/1/2/None).
    pub meta_type: SpareMetaType,
}

impl LbaMap {
    pub fn new(total_blocks: usize) -> Self {
        // Default: each logical block maps to the same physical block
        Self {
            bad_blocks: Vec::new(),
            logical_to_physical: (0..total_blocks).collect(),
            meta_type: SpareMetaType::MetaTypeNone,
        }
    }

    pub fn from_layout(layout: NandLayout, total_blocks: usize) -> Self {
        let mut map = Self::new(total_blocks);
        map.meta_type = match layout {
            NandLayout::Bb => SpareMetaType::MetaType2,
            _ => SpareMetaType::MetaType1,
        };
        map
    }

    /// Updates the mapping after bad block healing.
    /// Called when a bad block at `bad_block` is replaced with content from `replacement_block`.
    pub fn record_remap(&mut self, bad_block: usize, replacement_block: usize) {
        if !self.bad_blocks.contains(&bad_block) {
            self.bad_blocks.push(bad_block);
        }
        // Find all logical blocks that pointed to the replacement and redirect them
        for (logical, physical) in self.logical_to_physical.iter_mut().enumerate() {
            if *physical == replacement_block {
                *physical = bad_block;
                info!("[blocks] LBA {:#X}: physical block {:#X} -> {:#X} (bad block healed)",
                      logical, replacement_block, bad_block);
            }
        }
    }

    /// Returns the physical block for a given logical block number.
    pub fn physical_block(&self, logical: usize) -> Option<usize> {
        self.logical_to_physical.get(logical).copied()
    }

    /// Returns true if a physical block is known to be bad.
    pub fn is_bad(&self, physical: usize) -> bool {
        self.bad_blocks.contains(&physical)
    }

    /// Finds the next available reserve block, starting from the end of the NAND.
    pub fn find_available_reserve_block(&self, layout: &NandLayout, image_len: usize) -> Option<usize> {
        let res_start = layout.reserve_start(image_len);
        let max_blocks = layout.max_blocks();
        
        // Scan backwards from the very last block (e.g., 0x3FF or 0x1FF)
        for block_idx in (0..0x20).rev() {
            let physical_block = res_start + block_idx;
            if physical_block >= max_blocks { continue; }

            // Is this block already used as a bad block OR as a target for another remap?
            if !self.bad_blocks.contains(&physical_block) && 
               !self.logical_to_physical.contains(&physical_block) {
                return Some(physical_block);
            }
        }
        None
    }

    /// Handles a live write-time remapping request.
    /// If a block fails during a write, this finds a reserve target and records the remap.
    pub fn get_live_remap_target(&mut self, bad_block: usize, layout: &NandLayout, image_len: usize) -> Option<usize> {
        // 1. Don't remap if it's already in the reserve area
        if bad_block >= layout.reserve_start(image_len) {
            return None;
        }

        // 2. Find a target
        let target = self.find_available_reserve_block(layout, image_len)?;

        // 3. Record it
        if !self.bad_blocks.contains(&bad_block) {
            self.bad_blocks.push(bad_block);
        }
        
        // Update the mapping: any logical block that used to point to 'bad_block' 
        // now points to 'target'.
        for physical in self.logical_to_physical.iter_mut() {
            if *physical == bad_block {
                *physical = target;
            }
        }

        info!("[blocks] Live Remap: failed block {:#X} -> redirected to {:#X}", bad_block, target);
        Some(target)
    }
}

impl NandProcessor {
    /// Preprocesses a raw NAND image: detects layout, heals bad blocks, strips spare.
    /// Returns the clean logical image and layout type.
    pub fn preprocess_nand(raw_image: &[u8]) -> Result<(Vec<u8>, NandLayout), String> {
        let (clean, layout, _lba_map) = Self::preprocess_nand_with_lba(raw_image)?;
        Ok((clean, layout))
    }

    /// Preprocesses a raw NAND image and returns an LBA map for tracking
    /// logical-to-physical block mappings after bad block healing.
    /// Based on x360Utils NANDReader FindBadBlocks + SeekToLbaEx functionality.
    pub fn preprocess_nand_with_lba(raw_image: &[u8]) -> Result<(Vec<u8>, NandLayout, LbaMap), String> {
        let base_layout = NandLayout::detect(raw_image)?;
        if base_layout == NandLayout::Emmc {
            let total_blocks = raw_image.len() / (base_layout.logical_pages_per_block() * 0x200);
            return Ok((raw_image.to_vec(), base_layout, LbaMap::new(total_blocks)));
        }

        // Promote Sb → Xsb while spare data is still present (matches J-Runner identifylayout).
        let layout = promote_layout(raw_image, base_layout);
        if layout != base_layout {
            info!("[blocks] Promoted layout: {:?} -> {:?} (Xenon spare format detected)", base_layout, layout);
        }

        // Detect spare metadata format
        let meta_type = detect_meta_type(raw_image, layout);
        info!("[blocks] Detected spare metadata format: {:?}", meta_type);

        let mut working = raw_image.to_vec();
        let total_blocks = layout.total_blocks(working.len());
        let mut lba_map = LbaMap::new(total_blocks);
        lba_map.meta_type = meta_type;

        if let Some(mut bm) = BlockMap::new(&working) {
            if !bm.blocks.is_empty() {
                // Record bad blocks before healing
                for bad in &bm.blocks {
                    lba_map.bad_blocks.push(bad.block);
                }
                bm.map_and_heal(&mut working)?;
            }
        }
        let mut clean = remove_spare(&working);
        if layout == NandLayout::Bb && clean.len() > 0x4000000 {
            clean.truncate(0x4000000);
        }
        Ok((clean, layout, lba_map))
    }

    /// Finalizes a clean NAND image by adding ECC/spare data for physical output.
    /// If an LbaMap is provided, it uses the metadata format for correct spare layout.
    pub fn finalize_nand(clean_data: &[u8], layout: NandLayout, meta_type: SpareMetaType, fs_meta: Option<&std::collections::HashMap<usize, FsSpareInfo>>, jtag_syscall: Option<u16>) -> Vec<u8> {
        if layout == NandLayout::Emmc { return clean_data.to_vec(); }
        add_spare(clean_data, layout, meta_type, 0, fs_meta, jtag_syscall)
    }
}
