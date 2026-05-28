/*
  blocks.rs - ECC, Spare data, and bad blocks manager

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
use log::{info, warn};

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
            NandLayout::Xsb | NandLayout::Sb => ((logical_page / 512) * 528 + (logical_page % 512)) as u64,
            NandLayout::Bb => ((logical_page / 2048) * 2112 + (logical_page % 2048)) as u64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BbPhysicalFormat {
    PerPage,
    Chunked,
}

fn bb_spare_offset_per_page(page: usize) -> usize {
    (page * 0x210) + 0x200
}

fn bb_spare_offset_chunked(page: usize) -> usize {
    let chunk = page / 4;
    let idx = page % 4;
    (chunk * 0x840) + 0x800 + (idx * 0x10)
}

fn bb_data_offset_chunked(page: usize) -> usize {
    let chunk = page / 4;
    let idx = page % 4;
    (chunk * 0x840) + (idx * 0x200)
}

fn bb_meta2_block_id(spare: &[u8]) -> Option<u16> {
    if spare.len() < 3 {
        return None;
    }
    Some((spare[1] as u16) | (((spare[2] as u16) & 0xF) << 8))
}

fn bb_score_spare(candidate: &[u8]) -> i32 {
    if candidate.len() < 16 {
        return i32::MIN / 2;
    }

    if candidate[..12].iter().all(|&b| b == 0x00) {
        return -10;
    }

    let mut score = 0;
    if candidate[0] == 0xFF {
        score += 5;
    } else if candidate[0] == 0x00 {
        score -= 1;
    } else {
        score -= 2;
    }

    if candidate[3] == 0x00 && candidate[4] == 0x00 {
        score += 1;
    }
    if candidate[5] == 0xFF {
        score += 1;
    }

    let ecc = &candidate[0x0C..0x10];
    if ecc.iter().all(|&b| b == 0x00) || ecc.iter().all(|&b| b == 0xFF) {
        score -= 1;
    } else {
        score += 1;
    }

    score
}

pub fn detect_bb_physical_format(image: &[u8]) -> BbPhysicalFormat {
    let mut per_page_hits = 0i32;
    let mut chunked_hits = 0i32;

    let blocks_to_sample = 64usize;
    for block in 0..blocks_to_sample {
        let page0 = block * 256;

        let a_off = bb_spare_offset_per_page(page0);
        if a_off + 16 <= image.len() {
            let s = &image[a_off..a_off + 16];
            if bb_score_spare(s) > 0 {
                per_page_hits += 1;
            }
            if s[0] == 0xFF {
                if let Some(id) = bb_meta2_block_id(s) {
                    if id == (block as u16) {
                        per_page_hits += 4;
                    }
                }
            }
        }

        let b_off = bb_spare_offset_chunked(page0);
        if b_off + 16 <= image.len() {
            let s = &image[b_off..b_off + 16];
            if bb_score_spare(s) > 0 {
                chunked_hits += 1;
            }
            if s[0] == 0xFF {
                if let Some(id) = bb_meta2_block_id(s) {
                    if id == (block as u16) {
                        chunked_hits += 4;
                    }
                }
            }
        }
    }

    if chunked_hits > per_page_hits {
        return BbPhysicalFormat::Chunked;
    }
    BbPhysicalFormat::PerPage
}

pub fn read_logical_from_physical(image: &[u8], logical_offset: usize, len: usize, layout: NandLayout) -> Option<Vec<u8>> {
    if image.is_empty() || len == 0 {
        return None;
    }

    let logical_page_size = layout.page_size();
    let bb_fmt = if layout == NandLayout::Bb { Some(detect_bb_physical_format(image)) } else { None };
    let mut result = vec![0u8; len];
    let mut cur = 0;

    while cur < len {
        let current_logical_offset = logical_offset + cur;
        let current_page = current_logical_offset / logical_page_size;
        let page_offset = current_logical_offset % logical_page_size;
        let phys_offset = match layout {
            NandLayout::Emmc => current_logical_offset,
            NandLayout::Xsb | NandLayout::Sb => (current_page * layout.physical_page_size()) + page_offset,
            NandLayout::Bb => match bb_fmt.unwrap_or(BbPhysicalFormat::PerPage) {
                BbPhysicalFormat::PerPage => (current_page * layout.physical_page_size()) + page_offset,
                BbPhysicalFormat::Chunked => bb_data_offset_chunked(current_page) + page_offset,
            },
        };

        let chunk_len = logical_page_size - page_offset;
        let to_read = std::cmp::min(chunk_len, len - cur);

        if phys_offset + to_read > image.len() {
            result.truncate(cur);
            if result.is_empty() {
                return None;
            }
            break;
        }

        result[cur..cur + to_read].copy_from_slice(&image[phys_offset..phys_offset + to_read]);
        cur += to_read;
    }

    Some(result)
}

pub fn write_logical_data(image: &mut [u8], logical_offset: usize, data: &[u8], layout: NandLayout) {
    if image.is_empty() || data.is_empty() {
        return;
    }

    let logical_page_size = layout.page_size();
    let bb_fmt = if layout == NandLayout::Bb { Some(detect_bb_physical_format(image)) } else { None };
    let mut cur = 0;
    let len = data.len();

    while cur < len {
        let current_logical_byte = logical_offset + cur;
        let current_page = current_logical_byte / logical_page_size;
        let page_offset = current_logical_byte % logical_page_size;
        let phys_offset = match layout {
            NandLayout::Emmc => current_logical_byte,
            NandLayout::Xsb | NandLayout::Sb => (current_page * layout.physical_page_size()) + page_offset,
            NandLayout::Bb => match bb_fmt.unwrap_or(BbPhysicalFormat::PerPage) {
                BbPhysicalFormat::PerPage => (current_page * layout.physical_page_size()) + page_offset,
                BbPhysicalFormat::Chunked => bb_data_offset_chunked(current_page) + page_offset,
            },
        };

        let chunk_len = logical_page_size - page_offset;
        let to_write = std::cmp::min(chunk_len, len - cur);

        if phys_offset + to_write > image.len() {
            break;
        }

        image[phys_offset..phys_offset + to_write].copy_from_slice(&data[cur..cur + to_write]);
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
            NandLayout::Xsb | NandLayout::Sb => 0x3E0,
            NandLayout::Bb => {
                let total = self.total_blocks(_image_len);
                total.saturating_sub(0x20)
            }
            NandLayout::Emmc => 0,
        }
    }

    pub fn max_blocks(&self) -> usize {
        match self {
            NandLayout::Xsb | NandLayout::Sb => 0x400,
            NandLayout::Bb => 0x200,
            NandLayout::Emmc => 0,
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
            // eMMC
            0x3000000 => Ok(NandLayout::Emmc),
            len if len >= 0x30000000 => Ok(NandLayout::Emmc),
            _ => {
                let aligned_sb_phys = len % 0x4200 == 0;
                let aligned_sb_log = len % 0x4000 == 0;
                let aligned_bb_phys = len % 0x21000 == 0;
                let aligned_bb_log = len % 0x20000 == 0;

                if has_spare(image) {
                    if let Some(spare) = get_page_spare(image, 256, &NandLayout::Bb) {
                        if spare.len() >= 3 {
                            let lba_mt2 = ((spare[2] as u16 & 0xF) << 8) | spare[1] as u16;
                            if spare[0] == 0xFF && lba_mt2 == 1 {
                                return Ok(NandLayout::Bb);
                            }
                        }
                    }

                    if len >= 0x4410 {
                        let spare = &image[0x4400..0x4410];
                        let lba_mt0 = ((spare[1] as u16 & 0xF) << 8) | spare[0] as u16;
                        let lba_mt1 = ((spare[2] as u16 & 0xF) << 8) | spare[1] as u16;
                        if spare[5] == 0xFF && (lba_mt0 == 1 || lba_mt1 == 1) {
                            return Ok(NandLayout::Sb);
                        }
                    }
                }

                let bb_candidate = aligned_bb_phys || aligned_bb_log;
                let sb_candidate = aligned_sb_phys || aligned_sb_log;

                if bb_candidate && !sb_candidate {
                    Ok(NandLayout::Bb)
                } else if sb_candidate && !bb_candidate {
                    Ok(NandLayout::Sb)
                } else if bb_candidate && sb_candidate {
                    let mut per_page_hits = 0i32;
                    let mut chunked_hits = 0i32;
                    let blocks_to_sample = 64usize;
                    for block in 0..blocks_to_sample {
                        let page0 = block * 256;

                        let a_off = bb_spare_offset_per_page(page0);
                        if a_off + 16 <= image.len() {
                            let s = &image[a_off..a_off + 16];
                            if bb_score_spare(s) > 0 {
                                per_page_hits += 1;
                            }
                            if s[0] == 0xFF {
                                if let Some(id) = bb_meta2_block_id(s) {
                                    if id == (block as u16) {
                                        per_page_hits += 4;
                                    }
                                }
                            }
                        }

                        let b_off = bb_spare_offset_chunked(page0);
                        if b_off + 16 <= image.len() {
                            let s = &image[b_off..b_off + 16];
                            if bb_score_spare(s) > 0 {
                                chunked_hits += 1;
                            }
                            if s[0] == 0xFF {
                                if let Some(id) = bb_meta2_block_id(s) {
                                    if id == (block as u16) {
                                        chunked_hits += 4;
                                    }
                                }
                            }
                        }
                    }

                    if std::cmp::max(per_page_hits, chunked_hits) > 10 {
                        Ok(NandLayout::Bb)
                    } else {
                        Ok(NandLayout::Sb)
                    }
                } else {
                    Err(format!("Could not detect NAND layout for size 0x{:x}", len))
                }
            }
        };

        if let Ok(l) = &layout {
            info!("[blocks] Detected NAND Layout: {:?} (Image Size: 0x{:x})", l, len);
        }
        layout
    }
}

pub fn calculate_ecc(data: &mut [u8]) {
    if data.len() < 0x210 {
        return;
    }
    let mut val: u32 = 0;
    let mut v: u32 = 0;
    for i in 0..0x1066 {
        if (i & 31) == 0 {
            let offset = i / 8;
            v = !u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        }
        val ^= v & 1;
        v >>= 1;
        if (val & 1) != 0 {
            val ^= 0x6954559;
        }
        val >>= 1;
    }
    val = !val;
    let mut ecc_temp = (val << 6).to_le_bytes();

    ecc_temp[0] = (ecc_temp[0] & !0x3f) | (data[0x20C] & 0x3F);
    data[0x20C..0x210].copy_from_slice(&ecc_temp);
}

fn compute_ecc(data: &[u8]) -> [u8; 4] {
    let mut val: u32 = 0;
    let mut v: u32 = 0;
    for i in 0..0x1066 {
        if (i & 31) == 0 {
            let offset = i / 8;
            v = !u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        }
        val ^= v & 1;
        v >>= 1;
        if (val & 1) != 0 {
            val ^= 0x6954559;
        }
        val >>= 1;
    }
    val = !val;
    let mut ecc_temp = (val << 6).to_le_bytes();
    ecc_temp[0] = (ecc_temp[0] & !0x3f) | (data[0x20C] & 0x3F);
    ecc_temp
}

/// Verify the ECC of a physical `0x210`-byte page.
/// Returns `true` if the page ECC is valid, `false` if a mismatch is detected.
pub fn ecc_verify_and_correct(page: &mut [u8]) -> bool {
    if page.len() < 0x210 {
        return true;
    }
    let stored = [page[0x20C], page[0x20D], page[0x20E], page[0x20F]];
    let computed = compute_ecc(page);
    stored == computed
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
    mobile_meta: Option<&std::collections::HashMap<usize, FsSpareInfo>>,
    jtag_syscall: Option<u16>,
) -> Vec<u8> {
    let page_size = layout.page_size();
    let total_pages = (image.len() + page_size - 1) / page_size;

    info!("[blocks] Finalizing physical image: Generating ECC and Spare Areas...");

    match layout {
        NandLayout::Bb => {
            let p_page_size = layout.physical_page_size();
            let mut result = vec![0u8; total_pages * p_page_size];
            let block_number_base = blockstart / layout.block_size();

            for i in 0..total_pages {
                let read_offset = i * page_size;
                let write_offset = i * p_page_size;
                let page_slice = &mut result[write_offset..write_offset + p_page_size];
                page_slice[..page_size].fill(0);

                let bytes_remaining = image.len().saturating_sub(read_offset);
                if bytes_remaining > 0 {
                    let sz = std::cmp::min(page_size, bytes_remaining);
                    page_slice[..sz].copy_from_slice(&image[read_offset..read_offset + sz]);
                }

                let mut spare = [0xFFu8; 16];
                let val = (i / layout.logical_pages_per_block()) + block_number_base;
                let reserve_start = layout.reserve_start(image.len());

                if val >= reserve_start {
                    // Reserve region: leave spare fully erased (0xFF), no ECC
                } else if let Some(fs) = mobile_meta.and_then(|m| m.get(&i)).or_else(|| fs_meta.and_then(|m| m.get(&val))) {
                    spare[1] = (val & 0xFF) as u8;
                    spare[2] = ((val >> 8) & 0xFF) as u8;
                    spare[5] = (fs.sequence & 0xFF) as u8;
                    spare[4] = ((fs.sequence >> 8) & 0xFF) as u8;
                    spare[3] = ((fs.sequence >> 16) & 0xFF) as u8;
                    spare[7] = (fs.size & 0xFF) as u8;
                    spare[8] = ((fs.size >> 8) & 0xFF) as u8;
                    spare[9] = fs.page_count;
                    spare[12] = fs.block_type;
                    page_slice[page_size..p_page_size].copy_from_slice(&spare);
                    calculate_ecc(page_slice);
                } else {
                    spare[1] = (val & 0xFF) as u8;
                    spare[2] = ((val >> 8) & 0xFF) as u8;
                    page_slice[page_size..p_page_size].copy_from_slice(&spare);
                    calculate_ecc(page_slice);
                }
            }
            result
        }
        NandLayout::Xsb | NandLayout::Sb => {
            let p_page_size = layout.physical_page_size();
            let mut result = vec![0u8; total_pages * p_page_size];
            let block_number_base = blockstart / layout.block_size();

            for i in 0..total_pages {
                let read_offset = i * page_size;
                let write_offset = i * p_page_size;
                let page_slice = &mut result[write_offset..write_offset + p_page_size];
                page_slice[..page_size].fill(0);

                let bytes_remaining = image.len().saturating_sub(read_offset);
                if bytes_remaining > 0 {
                    let sz = std::cmp::min(page_size, bytes_remaining);
                    page_slice[..sz].copy_from_slice(&image[read_offset..read_offset + sz]);
                }

                let mut spare = [0xFFu8; 16];
                let val = (i / 32) + block_number_base;
                let reserve_start = layout.reserve_start(image.len());

                // JTAG syscall injection into Page 1 spare (offset 10, Big Endian)
                if i == 1 {
                    if let Some(syscall) = jtag_syscall {
                        spare[10] = (syscall >> 8) as u8;
                        spare[11] = (syscall & 0xFF) as u8;
                        info!("[blocks] Injected JTAG Syscall 0x{:04X} into Page 1 spare", syscall);
                    }
                }

                if val >= reserve_start {
                    // Reserve region: leave spare fully erased (0xFF), no ECC
                } else if let Some(fs) = mobile_meta.and_then(|m| m.get(&i)).or_else(|| fs_meta.and_then(|m| m.get(&val))) {
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
                    page_slice[page_size..p_page_size].copy_from_slice(&spare);
                    calculate_ecc(page_slice);
                } else {
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
                    page_slice[page_size..p_page_size].copy_from_slice(&spare);
                    calculate_ecc(page_slice);
                }
            }
            result
        }
        NandLayout::Emmc => image.to_vec(),
    }
}

pub fn has_spare(image: &[u8]) -> bool {
    if image.len() > 0x210 {
        // Quick geometry guard: logical images (no spare/ECC) typically are not aligned
        // to physical page sizes (0x210 for 512+16, 0x840 for 2048+64).
        // This avoids false positives when heuristic byte-pattern scans happen to match.
        if (image.len() % 0x210 != 0) && (image.len() % 0x840 != 0) {
            return false;
        }

        let mut counter = 0;
        let mut i: usize = 0x200;

        while i < image.len() && counter <= 0x100 {
            if i % 0x800 == 0 {
                if i + 0x40 <= image.len() {
                    // Check big-block spare pattern
                    if image[i] == 0xFF
                        && image.get(i + 0x10).copied().unwrap_or(0) == 0xFF
                        && image.get(i + 0x20).copied().unwrap_or(0) == 0xFF
                        && image.get(i + 0x30).copied().unwrap_or(0) == 0xFF
                        && image.get(i + 3).copied().unwrap_or(0) == 0x00
                        && image.get(i + 4).copied().unwrap_or(0) == 0x00
                    {
                        let spare_block = &image[i..i + 0x40];
                        if spare_block.iter().any(|&b| b != 0xFF) {
                            return true;
                        }
                    }
                }
                i += 0x40;
            } else {
                if i + 0x10 <= image.len() {
                    let spare0 = image[i];
                    let spare5 = image.get(i + 5).copied().unwrap_or(0);
                    let spare3 = image.get(i + 3).copied().unwrap_or(0);
                    let spare4 = image.get(i + 4).copied().unwrap_or(0);

                    if (spare0 == 0xFF || spare5 == 0xFF) && spare3 == 0x00 && spare4 == 0x00 && i + 0x10 <= image.len() {
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
            if i % 0x4200 == 0 {
                counter += 1;
            }
        }
    }

    if image.len() > 0x840 {
        if image[0x800] == 0xFF && image.get(0x810).copied().unwrap_or(0) == 0xFF && image.get(0x820).copied().unwrap_or(0) == 0xFF {
            return true;
        }
    }

    false
}

pub fn promote_layout(image: &[u8], layout: NandLayout) -> NandLayout {
    if layout != NandLayout::Sb {
        return layout;
    }
    if !has_spare(image) {
        return layout;
    }
    if image.len() < 0x210 {
        return layout;
    }
    let spare5 = image[0x205]; // bad-block marker for SB layouts
    let spare0 = image[0x200]; // block-ID LSB for Xsb, or 0x00 for Sb
    if spare5 == 0xFF && spare0 != 0x00 {
        return NandLayout::Xsb;
    }
    layout
}

pub fn detect_meta_type(image: &[u8], layout: NandLayout) -> SpareMetaType {
    if layout == NandLayout::Emmc {
        return SpareMetaType::MetaTypeNone;
    }
    if !has_spare(image) {
        return SpareMetaType::MetaTypeNone;
    }
    let read_spare = |offset: usize| -> Option<[u8; 16]> {
        if offset + 16 <= image.len() {
            let mut s = [0u8; 16];
            s.copy_from_slice(&image[offset..offset + 16]);
            Some(s)
        } else {
            None
        }
    };

    // Try spare at block 1, page 0
    let spare = match layout {
        NandLayout::Bb => get_page_spare(image, layout.logical_pages_per_block(), &layout).and_then(|v| v.try_into().ok()),
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

    let is_bad_mt0_1 = spare[5] != 0xFF;
    let is_bad_mt2 = spare[0] != 0xFF;

    if is_bad_mt0_1 && is_bad_mt2 {
        if image.len() > 0x4000 {
            if let Some(s) = read_spare(image.len() - 0x4000) {
                return detect_from_spare(&s, layout);
            }
        }
        return SpareMetaType::MetaTypeNone;
    }

    detect_from_spare(&spare, layout)
}

fn detect_from_spare(spare: &[u8; 16], _layout: NandLayout) -> SpareMetaType {
    let lba_mt2 = ((spare[2] as u16 & 0xF) << 8) | spare[1] as u16;
    if spare[0] == 0xFF && lba_mt2 == 1 {
        return SpareMetaType::MetaType2;
    }

    let lba_mt0 = ((spare[1] as u16 & 0xF) << 8) | spare[0] as u16;
    if spare[5] == 0xFF && lba_mt0 == 1 {
        return SpareMetaType::MetaType0;
    }

    let lba_mt1 = ((spare[2] as u16 & 0xF) << 8) | spare[1] as u16;
    if spare[5] == 0xFF && lba_mt1 == 1 {
        return SpareMetaType::MetaType1;
    }

    // Could probably error instead
    SpareMetaType::MetaType1
}

pub fn remove_spare(image: &[u8]) -> Vec<u8> {
    let Ok(layout) = NandLayout::detect(image) else {
        return image.to_vec();
    };
    if layout == NandLayout::Emmc {
        return image.to_vec();
    }
    if !has_spare(image) {
        return image.to_vec();
    }

    info!("[blocks] Multi-Core Prep: Stripping Physical Spares/ECC to create Clean Buffer...");

    match layout {
        NandLayout::Bb => {
            match detect_bb_physical_format(image) {
                BbPhysicalFormat::Chunked => {
                    let chunk_in = 0x840usize;
                    let chunk_out = 0x800usize;
                    let chunks = image.len() / chunk_in;
                    let mut result = vec![0u8; chunks * chunk_out];
                    let mut ecc_bad = 0usize;
                    for i in 0..chunks {
                        let in_offset = i * chunk_in;
                        let out_offset = i * chunk_out;
                        // Chunked BB: 4 data pages (0x200 each) followed by 4 spare (0x10 each)
                        for p in 0..4 {
                            let data_start = in_offset + p * 0x200;
                            let spare_start = in_offset + 0x800 + p * 0x10;
                            let mut buf = [0u8; 0x210];
                            buf[..0x200].copy_from_slice(&image[data_start..data_start + 0x200]);
                            buf[0x200..0x210].copy_from_slice(&image[spare_start..spare_start + 0x10]);
                            if !ecc_verify_and_correct(&mut buf) {
                                ecc_bad += 1;
                            }
                        }
                        result[out_offset..out_offset + chunk_out].copy_from_slice(&image[in_offset..in_offset + chunk_out]);
                    }
                    if ecc_bad > 0 {
                        warn!("[blocks] ECC: {} page(s) failed verification out of {}", ecc_bad, chunks * 4);
                    }
                    result
                }
                BbPhysicalFormat::PerPage => {
                    let p_page = layout.physical_page_size();
                    let l_page = layout.page_size();
                    let pages = image.len() / p_page;
                    let mut result = vec![0u8; pages * l_page];
                    let mut ecc_bad = 0usize;
                    for i in 0..pages {
                        if p_page >= 0x210 {
                            let mut buf = [0u8; 0x210];
                            buf.copy_from_slice(&image[i * p_page..i * p_page + 0x210]);
                            if !ecc_verify_and_correct(&mut buf) {
                                ecc_bad += 1;
                            }
                        }
                        result[i * l_page..(i + 1) * l_page].copy_from_slice(&image[i * p_page..i * p_page + l_page]);
                    }
                    if ecc_bad > 0 {
                        warn!("[blocks] ECC: {} page(s) failed verification out of {}", ecc_bad, pages);
                    }
                    result
                }
            }
        }
        NandLayout::Xsb | NandLayout::Sb => {
            let p_page = layout.physical_page_size();
            let l_page = layout.page_size();
            let pages = image.len() / p_page;
            let mut result = vec![0u8; pages * l_page];
            let mut ecc_bad = 0usize;

            for i in 0..pages {
                let src = &image[i * p_page..i * p_page + p_page];
                if p_page >= 0x210 {
                    let mut buf = [0u8; 0x210];
                    buf.copy_from_slice(&src[..0x210]);
                    if !ecc_verify_and_correct(&mut buf) {
                        ecc_bad += 1;
                    }
                }
                result[i * l_page..(i + 1) * l_page].copy_from_slice(&src[..l_page]);
            }
            if ecc_bad > 0 {
                warn!("[blocks] ECC: {} page(s) failed verification out of {}", ecc_bad, pages);
            }
            result
        }
        NandLayout::Emmc => {
            // Should not reach here due to early return, but handle anyway
            image.to_vec()
        }
    }
}

pub fn get_page_spare_fmt(image: &[u8], page: usize, layout: &NandLayout, bb_fmt: BbPhysicalFormat) -> Option<Vec<u8>> {
    let spare_size = layout.spare_size();
    if spare_size == 0 {
        return None;
    }

    match layout {
        NandLayout::Bb => {
            let offset = match bb_fmt {
                BbPhysicalFormat::PerPage => bb_spare_offset_per_page(page),
                BbPhysicalFormat::Chunked => bb_spare_offset_chunked(page),
            };
            if offset + spare_size <= image.len() {
                Some(image[offset..offset + spare_size].to_vec())
            } else {
                None
            }
        }
        NandLayout::Xsb | NandLayout::Sb => {
            let offset = (page * layout.physical_page_size()) + layout.page_size();
            if offset + spare_size <= image.len() {
                Some(image[offset..offset + spare_size].to_vec())
            } else {
                None
            }
        }
        NandLayout::Emmc => None,
    }
}

pub fn get_page_spare(image: &[u8], page: usize, layout: &NandLayout) -> Option<Vec<u8>> {
    let bb_fmt = if *layout == NandLayout::Bb {
        detect_bb_physical_format(image)
    } else {
        BbPhysicalFormat::PerPage
    };
    get_page_spare_fmt(image, page, layout, bb_fmt)
}

pub fn is_bad_block(image: &[u8], block_number: usize, layout: &NandLayout) -> bool {
    let block_size = layout.block_size();
    let offset = block_number * block_size;
    if offset + block_size > image.len() {
        return false;
    }

    match layout {
        NandLayout::Bb => {
            let pages_per_block = layout.logical_pages_per_block();
            if pages_per_block == 0 {
                return false;
            }

            let page = block_number * pages_per_block;
            let Some(spare) = get_page_spare(image, page, layout) else {
                return false;
            };
            if spare.len() < 16 {
                return false;
            }
            if spare[..12].iter().all(|&b| b == 0x00) {
                return false;
            }
            if spare[0] != 0xFF {
                return true;
            }
            false
        }
        NandLayout::Xsb | NandLayout::Sb => {
            let marker_offset = layout.marker_offset();
            let p_page_size = layout.physical_page_size();
            let l_page_size = layout.page_size();
            let mut i = 0;
            while i + p_page_size <= block_size {
                let page_offset = offset + i;
                let spare = &image[page_offset + l_page_size..page_offset + p_page_size];

                if spare.iter().all(|&b| b == 0x00) {
                    return true;
                }

                if image[page_offset + marker_offset] != 0xFF {
                    return true;
                }
                i += p_page_size;
            }
            false
        }
        NandLayout::Emmc => false,
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
        if bad_indices.is_empty() {
            return Ok(());
        }

        info!("[blocks] Found {} Bad Physical Blocks. Attempting Healing/Remapping...", bad_indices.len());
        let remapped = resolve_remapped_blocks(image, &bad_indices, &self.layout)?;
        for (i, &bad_block) in bad_indices.iter().enumerate() {
            let Some(target) = remapped[i] else {
                info!("[blocks] Bad Block {} has no remap entry; leaving as-is", bad_block);
                continue;
            };
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
        if resolved == bad_blocks.len() {
            break;
        }
        let physical_block = res_start + block_idx;
        let offset = physical_block * b_size;
        if offset + b_size > image.len() {
            continue;
        }

        let first_page = physical_block * pages_per_block;
        let last_page = first_page + pages_per_block - 1;

        let id1 = get_page_spare(image, first_page, layout)
            .map(|s| crate::builder::filesystem::FsSpareData::parse(&s, layout).block_id as usize)
            .unwrap_or(usize::MAX);
        let id2 = get_page_spare(image, last_page, layout)
            .map(|s| crate::builder::filesystem::FsSpareData::parse(&s, layout).block_id as usize)
            .unwrap_or(usize::MAX);

        for (i, &bad) in bad_blocks.iter().enumerate() {
            if remapped[i].is_some() {
                continue;
            }
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

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LbaMap {
    pub bad_blocks: Vec<usize>,
    pub logical_to_physical: Vec<usize>,
    pub meta_type: SpareMetaType,
}

impl LbaMap {
    pub fn new(total_blocks: usize) -> Self {
        Self { bad_blocks: Vec::new(), logical_to_physical: (0..total_blocks).collect(), meta_type: SpareMetaType::MetaTypeNone }
    }

    pub fn from_layout(layout: NandLayout, total_blocks: usize) -> Self {
        let mut map = Self::new(total_blocks);
        map.meta_type = match layout {
            NandLayout::Bb => SpareMetaType::MetaType2,
            _ => SpareMetaType::MetaType1,
        };
        map
    }

    pub fn record_remap(&mut self, bad_block: usize, replacement_block: usize) {
        if !self.bad_blocks.contains(&bad_block) {
            self.bad_blocks.push(bad_block);
        }

        for (logical, physical) in self.logical_to_physical.iter_mut().enumerate() {
            if *physical == replacement_block {
                *physical = bad_block;
                info!("[blocks] LBA {:#X}: physical block {:#X} -> {:#X} (bad block healed)", logical, replacement_block, bad_block);
            }
        }
    }

    pub fn physical_block(&self, logical: usize) -> Option<usize> {
        self.logical_to_physical.get(logical).copied()
    }

    pub fn is_bad(&self, physical: usize) -> bool {
        self.bad_blocks.contains(&physical)
    }

    pub fn find_available_reserve_block(&self, layout: &NandLayout, image_len: usize) -> Option<usize> {
        let res_start = layout.reserve_start(image_len);
        let max_blocks = layout.total_blocks(image_len);

        for block_idx in (0..0x20).rev() {
            let physical_block = res_start + block_idx;
            if physical_block >= max_blocks {
                continue;
            }

            if !self.bad_blocks.contains(&physical_block) && !self.logical_to_physical.contains(&physical_block) {
                return Some(physical_block);
            }
        }
        None
    }

    pub fn get_live_remap_target(&mut self, bad_block: usize, layout: &NandLayout, image_len: usize) -> Option<usize> {
        if bad_block >= layout.reserve_start(image_len) {
            return None;
        }

        let target = self.find_available_reserve_block(layout, image_len)?;

        if !self.bad_blocks.contains(&bad_block) {
            self.bad_blocks.push(bad_block);
        }

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
    pub fn preprocess_nand(raw_image: &[u8]) -> Result<(Vec<u8>, NandLayout), String> {
        let (clean, layout, _lba_map) = Self::preprocess_nand_with_lba(raw_image)?;
        Ok((clean, layout))
    }

    pub fn preprocess_nand_with_lba(raw_image: &[u8]) -> Result<(Vec<u8>, NandLayout, LbaMap), String> {
        Self::preprocess_nand_with_lba_options(raw_image, true)
    }

    pub fn preprocess_nand_with_lba_options(raw_image: &[u8], remap_bad_blocks: bool) -> Result<(Vec<u8>, NandLayout, LbaMap), String> {
        let base_layout = NandLayout::detect(raw_image)?;
        if base_layout == NandLayout::Emmc {
            let total_blocks = raw_image.len() / (base_layout.logical_pages_per_block() * 0x200);
            return Ok((raw_image.to_vec(), base_layout, LbaMap::new(total_blocks)));
        }

        let layout = promote_layout(raw_image, base_layout);
        if layout != base_layout {
            info!("[blocks] Promoted layout: {:?} -> {:?} (Xenon spare format detected)", base_layout, layout);
        }

        let meta_type = detect_meta_type(raw_image, layout);
        info!("[blocks] Detected spare metadata format: {:?}", meta_type);

        let mut working = raw_image.to_vec();
        let total_blocks = layout.total_blocks(working.len());
        let mut lba_map = LbaMap::new(total_blocks);
        lba_map.meta_type = meta_type;

        if has_spare(&working) {
            if let Some(mut bm) = BlockMap::new(&working) {
                if !bm.blocks.is_empty() {
                    for bad in &bm.blocks {
                        lba_map.bad_blocks.push(bad.block);
                    }
                    if remap_bad_blocks {
                        bm.map_and_heal(&mut working)?;
                    }
                }
            }
        }
        let mut clean = remove_spare(&working);
        if layout == NandLayout::Bb && clean.len() > 0x4000000 {
            clean.truncate(0x4000000);
        }
        Ok((clean, layout, lba_map))
    }

    pub fn finalize_nand(
        clean_data: &[u8],
        layout: NandLayout,
        meta_type: SpareMetaType,
        fs_meta: Option<&std::collections::HashMap<usize, FsSpareInfo>>,
        mobile_meta: Option<&std::collections::HashMap<usize, FsSpareInfo>>,
        jtag_syscall: Option<u16>,
    ) -> Vec<u8> {
        if layout == NandLayout::Emmc {
            return clean_data.to_vec();
        }
        add_spare(clean_data, layout, meta_type, 0, fs_meta, mobile_meta, jtag_syscall)
    }
}

#[cfg(test)]
mod nand_layout_detection_tests {
    use super::NandLayout;

    #[test]
    fn detects_partial_smallblock_logical_by_alignment() {
        let buf = vec![0u8; 0x4000 * 4];
        assert_eq!(NandLayout::detect(&buf).unwrap(), NandLayout::Sb);
    }

    #[test]
    fn detects_partial_smallblock_physical_by_alignment() {
        let buf = vec![0u8; 0x4200 * 4];
        assert_eq!(NandLayout::detect(&buf).unwrap(), NandLayout::Sb);
    }

    #[test]
    fn detects_partial_bigblock_physical_by_spare_signature() {
        let mut buf = vec![0xFFu8; 0x21000 * 2];

        let set_spare = |img: &mut [u8], page: usize, spare: [u8; 16]| {
            let off = page * 0x210 + 0x200;
            img[off..off + 16].copy_from_slice(&spare);
        };

        set_spare(&mut buf, 0, [0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
        set_spare(&mut buf, 256, [0xFF, 0x01, 0x00, 0x00, 0x00, 0xFF, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4]);

        assert_eq!(NandLayout::detect(&buf).unwrap(), NandLayout::Bb);
    }
}
