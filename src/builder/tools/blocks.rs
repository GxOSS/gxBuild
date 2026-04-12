
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NandLayout {
    Xsb,  // Xenon Small Block (Layout0)
    Sb,   // Small Block (Layout1)
    Bb,   // Big Block (Layout2)
    Emmc, // eMMC (Layout3)
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

    pub fn reserve_start(&self, image_len: usize) -> usize {
        match self {
            NandLayout::Xsb => 0x3E0,
            NandLayout::Sb => {
                if image_len >= 0x4200000 {
                    0xF80
                } else {
                    0x3E0
                }
            }
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
        match len {
            // Physical Sizes (with spare)
            len if len >= 0x1080000 && len <= 0x1080000 + 0x1000 => Ok(NandLayout::Xsb), // 16MB XSB/SB
            len if len >= 0x4200000 && len <= 0x4200000 + 0x1000 => Ok(NandLayout::Bb),  // 64MB BB (Jasper)
            len if len >= 0x10800000 && len <= 0x10800000 + 0x1000 => Ok(NandLayout::Bb), // 256MB BB
            len if len >= 0x21000000 && len <= 0x21000000 + 0x1000 => Ok(NandLayout::Bb), // 512MB BB
            
            // Logical Sizes (no spare)
            0x1000000 => Ok(NandLayout::Sb),   // 16MB Logical
            0x4000000 => Ok(NandLayout::Bb),   // 64MB Logical
            0x10000000 => Ok(NandLayout::Bb),  // 256MB Logical
            0x20000000 => Ok(NandLayout::Bb),  // 512MB Logical
            
            // eMMC
            0x3000000 => Ok(NandLayout::Emmc), // 48MB Corona 4G System
            len if len >= 0x40000000 || (len >= 0x30000000 && len < 0x40000000) => Ok(NandLayout::Emmc), // 1GB - 4GB
            _ => {
                Err(format!("Could not detect NAND layout for size 0x{:x}", len))
            }
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

/// Legacy wrapper for add_spare using SpareProfile
pub fn addecc(image: &[u8], layout: NandLayout, _profile: SpareProfile, blockstart: usize) -> Vec<u8> {
    add_spare(image, layout, blockstart)
}

/// Compatibility alias for remove_spare
pub fn unecc(image: &[u8]) -> Vec<u8> {
    remove_spare(image)
}

/// Expands a 0x200-byte chunked image into a 0x210-byte aligned image with proper spare layouts.
pub fn add_spare(image: &[u8], layout: NandLayout, blockstart: usize) -> Vec<u8> {
    let page_size = layout.page_size();
    let page_with_spare_size = layout.physical_page_size();

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
            NandLayout::Xsb => {
                sparedata[5] = 0xFF;
                let val = (i / 32) + block_number_base;
                sparedata[0] = (val & 0xFF) as u8;
                sparedata[1] = ((val / 0x100) & 0xFF) as u8;
            }
            NandLayout::Sb => {
                sparedata[5] = 0xFF;
                let val = (i / 32) + block_number_base;
                sparedata[1] = (val & 0xFF) as u8;
                sparedata[2] = ((val / 0x100) & 0xFF) as u8;
            }
            NandLayout::Bb => {
                sparedata[0] = 0xFF;
                let val = (i / 0x100) + (blockstart / 0x21000);
                sparedata[1] = (val & 0xFF) as u8;
                sparedata[2] = ((val >> 8) & 0xFF) as u8;
            }
            NandLayout::Emmc => {}
        }

        let write_offset = i * page_with_spare_size;
        let page_slice = &mut result[write_offset..write_offset + page_with_spare_size];
        page_slice[..page_size].copy_from_slice(&data_block);
        
        if page_with_spare_size > page_size {
            let spare_chunk = &sparedata[..page_with_spare_size - page_size];
            page_slice[page_size..page_with_spare_size].copy_from_slice(spare_chunk);
        }

        calculate_ecc(page_slice);
    }

    result
}

/// Strips ECC/Spare data dynamically to output clean pages. 
/// Automatically handles Big Block alignment when detected.
pub fn remove_spare(image: &[u8]) -> Vec<u8> {
    let layout = match NandLayout::detect(image) {
        Ok(l) => l,
        Err(_) => return image.to_vec(),
    };

    if matches!(layout, NandLayout::Emmc) {
        return image.to_vec();
    }
    
    let physical_page = layout.physical_page_size();
    let logical_page = layout.page_size();

    if layout == NandLayout::Bb {
         // Big Block often uses a redundant 0x840 (2112) layout check
         let pages = image.len() / physical_page;
         let mut result = vec![0u8; pages * logical_page];
         for i in 0..pages {
             result[i * logical_page..(i + 1) * logical_page].copy_from_slice(&image[i * physical_page..i * physical_page + logical_page]);
         }
         return result;
    }

    let pages = image.len() / physical_page;
    let mut result = vec![0u8; pages * logical_page];
    for i in 0..pages {
        result[i * logical_page..(i + 1) * logical_page].copy_from_slice(&image[i * physical_page..i * physical_page + logical_page]);
    }
    result
}

/// Fetches precisely the spare metadata for a selected absolute page mapping
pub fn get_page_spare(image: &[u8], page: usize, layout: &NandLayout) -> Option<Vec<u8>> {
    let spare_size = layout.spare_size();
    if spare_size == 0 { return None; }

    let p_page_size = layout.physical_page_size();
    let l_page_size = layout.page_size();

    let offset = (page * p_page_size) + l_page_size;
    if offset + spare_size <= image.len() {
        Some(image[offset..offset + spare_size].to_vec())
    } else {
        None
    }
}

/// Helper explicitly verifying block type marker offset 0xC 
pub fn get_block_type(image: &[u8], block: usize, pages_per_block: usize, layout: &NandLayout) -> Option<u8> {
    let offset = block * pages_per_block;
    let spare = get_page_spare(image, offset, layout)?;
    // The Xbox 360 sets byte 0xC (12) of the spare block to hold the logical indicator (e.g. 0x2C for FileSystems)
    if spare.len() > 0xC {
        Some(spare[0xC])
    } else {
        None
    }
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
    let bigblock = matches!(layout, NandLayout::Bb);

    let mut i = 0;
    let p_page_size = layout.physical_page_size();
    let l_page_size = layout.page_size();
    while i + p_page_size <= block_size {
        let page_offset = offset + i;
        if page_offset + p_page_size > image.len() {
            break;
        }

        let spare = &image[page_offset + l_page_size..page_offset + p_page_size];
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
        i += p_page_size;
    }

    false
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BlockMap {
    pub blocks: Vec<BadBlock>,
    pub layout: NandLayout,
}

impl BlockMap {
    pub fn is_bad(&self, block: usize) -> bool {
        self.blocks.iter().any(|b| b.block == block)
    }

    /// Parse a raw image-with-spare into a BlockMap.
    pub fn new(image: &[u8]) -> Option<Self> {
        let layout = NandLayout::detect(image).ok()?;
        let mut bad_blocks = Vec::new();
        let total_blocks = layout.total_blocks(image.len());

        for block in 0..total_blocks {
            if is_bad_block(image, block, &layout) {
                bad_blocks.push(BadBlock {
                    block,
                    target: block,
                });
            }
        }
        Some(Self {
            blocks: bad_blocks,
            layout,
        })
    }

    pub fn map_and_heal(&mut self, image: &mut [u8]) -> Result<(), String> {
         let bad_blocks_indices: Vec<usize> = self.blocks.iter().map(|b| b.block).collect();
         if bad_blocks_indices.is_empty() { return Ok(()); }
         
         if bad_blocks_indices.len() > 32 {
             return Err(format!("Too many bad blocks: {}", bad_blocks_indices.len()));
         }

         let remapped = resolve_remapped_blocks(image, &bad_blocks_indices, &self.layout)?;
         remap_bad_blocks(image, &bad_blocks_indices, &remapped, &self.layout)?;

         // Update our targets
         for (i, target) in remapped.iter().enumerate() {
             if let Some(t) = target {
                 self.blocks[i].target = *t;
             }
         }
         Ok(())
    }
}

/// Scans the reserved block area and resolves the physical remapped targets for a list of bad block IDs.
pub fn resolve_remapped_blocks(
    image: &[u8],
    bad_blocks: &[usize],
    layout: &NandLayout,
) -> Result<Vec<Option<usize>>, String> {
    if bad_blocks.is_empty() {
        return Ok(Vec::new());
    }
    let mut remapped = vec![None; bad_blocks.len()];
    let mut resolved_count = 0;

    let block_size = layout.block_size();
    let id_offset = layout.id_offset();
    let marker_offset = layout.marker_offset();
    let reserve_start = layout.reserve_start(image.len());

    // Iterate backwards through the 32 reserved blocks
    for block_idx in (0..0x20).rev() {
        if resolved_count == bad_blocks.len() {
            break;
        }

        let physical_block = reserve_start + block_idx;
        let offset = physical_block * block_size;

        if offset + block_size > image.len() {
            continue;
        }

        let last_page_offset = offset + block_size - 0x210;

        // Verify the reserve sector hasn't also physically failed
        if image[offset + marker_offset] != 0xFF && image[last_page_offset + marker_offset] != 0xFF
        {
            continue;
        }

        let b1 = image[offset + id_offset] as usize;
        let b2 = image[offset + id_offset + 1] as usize;
        let reserve_id_1 = (b2 << 8) | b1;

        let lb1 = image[last_page_offset + id_offset] as usize;
        let lb2 = image[last_page_offset + id_offset + 1] as usize;
        let reserve_id_2 = (lb2 << 8) | lb1;

        for (i, &bad_block) in bad_blocks.iter().enumerate() {
            if remapped[i].is_some() {
                continue;
            }
            // ID matches exactly the offset mapped against bad block arrays
            if bad_block == reserve_id_1 || bad_block == reserve_id_2 {
                remapped[i] = Some(physical_block);
                resolved_count += 1;
                break;
            }
        }
    }

    if resolved_count < bad_blocks.len() {
        return Err(format!(
            "Failed to resolve all bad blocks in the reserve sector! Resolved {} out of {}",
            resolved_count,
            bad_blocks.len()
        ));
    }

    Ok(remapped)
}

/// Dynamically injects the payload from the reserved remapped blocks into the logical block spaces.
pub fn remap_bad_blocks(
    image: &mut [u8],
    bad_blocks: &[usize],
    remapped_targets: &[Option<usize>],
    layout: &NandLayout,
) -> Result<(), String> {
    let block_size = layout.block_size();

    for (i, &bad_block) in bad_blocks.iter().enumerate() {
        let Some(remapped) = remapped_targets[i] else {
            return Err(format!("Bad block {} was not remapped", bad_block));
        };

        let bad_offset = bad_block * block_size;
        let remapped_offset = remapped * block_size;

        if bad_offset + block_size > image.len() || remapped_offset + block_size > image.len() {
            return Err("Offsets out of bounds during remapping".to_string());
        }

        let mut buffer = vec![0u8; block_size];
        buffer.copy_from_slice(&image[remapped_offset..remapped_offset + block_size]);
        image[bad_offset..bad_offset + block_size].copy_from_slice(&buffer);
        
        // Blank the physical reserve block post-extradition to emulate native clean states
        image[remapped_offset..remapped_offset + block_size].fill(0xFF);
    }

    Ok(())
}