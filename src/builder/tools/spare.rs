use zerocopy::{FromBytes, byteorder::big_endian};

pub enum NandLayout {
    Xsb, // Xenon Small Block
    Sb, // Small Block
    Bb, // Big Block
    Emmc, // eMMC
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
        image_len / self.block_size()
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

    pub fn marker_offset(&self) -> usize {
        match self {
            NandLayout::Xsb | NandLayout::Sb => 0x205,
            NandLayout::Bb => 0x200,
            NandLayout::Emmc => 0, // No marker
        }
    }

    pub fn id_offset(&self) -> usize {
        match self {
            NandLayout::Xsb => 0x200,
            NandLayout::Sb | NandLayout::Bb => 0x201,
            NandLayout::Emmc => 0,
        }
    }

    pub fn reserve_start(&self) -> usize {
        match self {
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
            v = !u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
        }
        val ^= v & 1;
        v >>= 1;
        if (val & 1) != 0 {
            val ^= 0x6954559;
        }
        val >>= 1;
    }
    val = !val;
    // Apply bit shift and encode to LE to match the byte reversal output from original strings
    let ecc_temp = (val << 6).to_le_bytes();
    data[0x20C..0x210].copy_from_slice(&ecc_temp);
}

/// Expands a 0x200-byte chunked image into a 0x210-byte aligned image with proper spare layouts.
pub fn add_spare(image: &[u8], layout: NandLayout, blockstart: usize) -> Vec<u8> {
    let page_size = 0x200;
    let spare_size = 0x10;
    let page_with_spare_size = 0x210;

    let total_pages = (image.len() + page_size - 1) / page_size;
    let mut result = vec![0u8; total_pages * page_with_spare_size];
    let block_number_base = blockstart / 0x4200;

    for i in 0..total_pages {
        let read_offset = i * page_size;
        let mut data_block = vec![0u8; page_size];
        let bytes_remaining = image.len().saturating_sub(read_offset);

        if bytes_remaining > 0 {
            let bytes_to_copy = std::cmp::min(page_size, bytes_remaining);
            data_block[..bytes_to_copy].copy_from_slice(&image[read_offset..read_offset + bytes_to_copy]);
        }

        let mut sparedata = [0u8; 16];

        match layout {
            NandLayout::Layout0 => {
                sparedata[5] = 0xFF;
                let val = (i / 32) + block_number_base;
                sparedata[0] = (val & 0xFF) as u8;
                sparedata[1] = ((val / 0x100) & 0xFF) as u8;
            }
            NandLayout::Layout1 => {
                sparedata[5] = 0xFF;
                let val = (i / 32) + block_number_base;
                sparedata[1] = (val & 0xFF) as u8;
                sparedata[2] = ((val / 0x100) & 0xFF) as u8;
            }
            NandLayout::Layout2 => {
                sparedata[0] = 0xFF;
                let val = (i / 0x100) + (blockstart / 0x21000);
                sparedata[1] = (val & 0xFF) as u8;
                sparedata[2] = ((val >> 8) & 0xFF) as u8;
            }
        }

        let write_offset = i * page_with_spare_size;
        let page_slice = &mut result[write_offset..write_offset + page_with_spare_size];
        page_slice[..page_size].copy_from_slice(&data_block);
        page_slice[page_size..page_with_spare_size].copy_from_slice(&sparedata);

        calcecc(page_slice);
    }

    result
}

/// Strips ECC/Spare data (0x10 bounds) dynamically to output clean 0x200 blocks. 
/// Automatically handles Big Block (0x840 padding) when detected.
pub fn remove_spare(image: &[u8]) -> Vec<u8> {
    if image.len() >= 0x840 && image[0x800] == 0xFF && image[0x810] == 0xFF && image[0x820] == 0xFF {
        let pages = image.len() / 0x840;
        let mut result = vec![0u8; pages * 0x800];
        for i in 0..pages {
            result[i * 0x800..(i + 1) * 0x800].copy_from_slice(&image[i * 0x840..i * 0x840 + 0x800]);
        }
        return result;
    }

    let pages = image.len() / 0x210;
    let mut result = vec![0u8; pages * 0x200];
    for i in 0..pages {
        result[i * 0x200..(i + 1) * 0x200].copy_from_slice(&image[i * 0x210..i * 0x210 + 0x200]);
    }
    result
}

/// Fetches precisely 16 bytes of metadata for a selected absolute page mapping
pub fn get_page_spare(image: &[u8], page: usize) -> Option<[u8; 16]> {
    let offset = (page * 0x210) + 0x200;
    if offset + 16 <= image.len() {
        let mut spare = [0u8; 16];
        spare.copy_from_slice(&image[offset..offset + 16]);
        Some(spare)
    } else {
        None
    }
}

pub fn get_block_type(image: RawImage, block: usize, pages_per_block: usize) -> NandLayout {
    let offset = block * pages_per_block;
    let spare = get_page_spare(image, offset)?;
    // The Xbox 360 sets byte 0xC (12) of the spare block to hold the logical indicator (e.g. 0x2C for FileSystems)
    Some(spare[0xC])
}

/// Checks if a physical block is marked as a Bad Block by inspecting its page marker.
pub fn is_bad_block(image: &[u8], block_number: usize, layout: &NandLayout) -> bool {
    let block_size = layout.block_size();
    let marker_offset = layout.marker_offset();
    let offset = block_number * block_size;

    if offset + block_size > image.len() {
        return false;
    }

    let mut flag = false;
    let bigblock = matches!(layout, NandLayout::Layout2);

    let mut i = 0;
    while i + 0x210 <= block_size {
        let page_offset = offset + i;
        if page_offset + 0x210 > image.len() {
            break;
        }

        let spare = &image[page_offset + 0x200..page_offset + 0x210];
        if spare.iter().all(|&b| b == 0x00) {
            return true;
        }

        let marker = image[page_offset + marker_offset];
        if marker != 0xFF {
            if !bigblock {
                return true;
            } else if !flag {
                return true;
            }
        }

        flag = true;
        i += 0x210;
    }

    false
}

pub struct BadBlock {
    pub block: usize,
    pub target: usize,
}

pub struct BlockMap {
    pub blocks: Option<Vec<BadBlock>>,
    pub block_type: NandLayout,
}

impl BlockMap {
    /// Parse a raw image-with-spare into a BlockMap.
    pub fn new(image: RawImage) -> Self {
        // Add size sanity check

        // Check block type
        let block_type = get_block_type(image, 0x14, 0x210);
        
        // Check for bad blocks
    }
    pub fn check_all_blocks(image: RawImage) -> Self {
        let mut bad_blocks = Vec::new();
        let block_type = get_block_type(image, 0x14, 0x210);
        let pages_per_block = block_type.logical_pages_per_block();
        let total_blocks = block_type.total_blocks(image.data.len());
        for block in 0..total_blocks {
            if is_bad_block(&image.data, block, &block_type) {
                println!("[GGX] Bad block found: {}", block);
                bad_blocks.push(BadBlock {
                    block,
                    target: block,
                });
            }
        }
        Self {
            blocks: Some(bad_blocks),
            block_type,
        }
    }
}