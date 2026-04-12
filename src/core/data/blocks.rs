/*
    blocks.rs - NAND Layout definitions, ECC, and Physical Block management.
    
    Modified in 2026 by Exposure / Zach for GGX
*/



#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NandLayout {
    /// Small Block, Xenon-era spare format. Promoted from Sb at runtime
    /// after inspecting bootloaders / FlashFS spare data — never returned by detect().
    Xsb,
    /// Small Block (16 MB). Default for all 16 MB images until spare format is confirmed.
    Sb,
    /// Big Block (64 MB / 256 MB / 512 MB).
    Bb,
    /// eMMC, no spare (48 MB / 4 GB).
    Emmc,
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

            // eMMC — no spare (48 MB Trinity/Corona slim, or 4 GB Corona 4G)
            0x3000000 => Ok(NandLayout::Emmc),
            len if len >= 0x30000000 => Ok(NandLayout::Emmc),
            _ => Err(format!("Could not detect NAND layout for size 0x{:x}", len)),
        };

        if let Ok(l) = &layout {
            println!(" -> Detected NAND Layout: {:?} (Image Size: 0x{:x})", l, len);
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
    let ecc_temp = (val << 6).to_le_bytes();
    data[0x20C..0x210].copy_from_slice(&ecc_temp);
}

pub fn add_spare(image: &[u8], layout: NandLayout, blockstart: usize) -> Vec<u8> {
    let page_size = layout.page_size();
    let p_page_size = layout.physical_page_size();
    let total_pages = (image.len() + page_size - 1) / page_size;
    let mut result = vec![0u8; total_pages * p_page_size];
    let block_number_base = blockstart / layout.block_size();

    println!(" -> Finalizing physical image: Generating ECC and Spare Areas...");
    for i in 0..total_pages {
        let read_offset = i * page_size;
        let mut data_block = [0u8; 0x200];
        let bytes_remaining = image.len().saturating_sub(read_offset);
        if bytes_remaining > 0 {
            let sz = std::cmp::min(0x200, bytes_remaining);
            data_block[..sz].copy_from_slice(&image[read_offset..read_offset + sz]);
        }

        let mut spare = [0u8; 16];
        match layout {
            NandLayout::Xsb => {
                spare[5] = 0xFF;
                let val = (i / 32) + block_number_base;
                spare[0] = (val & 0xFF) as u8;
                spare[1] = ((val / 0x100) & 0xFF) as u8;
            }
            NandLayout::Sb => {
                spare[5] = 0xFF;
                let val = (i / 32) + block_number_base;
                spare[1] = (val & 0xFF) as u8;
                spare[2] = ((val / 0x100) & 0xFF) as u8;
            }
            NandLayout::Bb => {
                spare[0] = 0xFF;
                let val = (i / 256) + (blockstart / 0x21000);
                spare[1] = (val & 0xFF) as u8;
                spare[2] = ((val >> 8) & 0xFF) as u8;
            }
            NandLayout::Emmc => {}
        }

        let write_offset = i * p_page_size;
        let page_slice = &mut result[write_offset..write_offset + p_page_size];
        page_slice[..0x200].copy_from_slice(&data_block);
        if p_page_size > 0x200 {
            page_slice[0x200..p_page_size].copy_from_slice(&spare[..p_page_size - 0x200]);
        }
        calculate_ecc(page_slice);
    }
    result
}

/// Returns true if the image has spare/ECC data appended to each page.
/// Matches J-Runner's hasecc() detection: checks the spare bytes of the
/// first page (SB: data[0x205] or data[0x200]; BB: data[0x800]).
pub fn has_spare(image: &[u8]) -> bool {
    // Small-block indicator: spare[5] == 0xFF (good block marker) or spare[0] == 0xFF (Bb marker)
    if image.len() > 0x210 {
        // SB formats: spare at +0x200, bad-block marker at +0x205 (Sb/Xsb) or +0x200 (Bb)
        if image[0x205] == 0xFF { return true; } // Sb/Xsb: marker at spare[5]
        if image[0x200] == 0xFF { return true; } // Bb:    marker at spare[0]
    }
    // BB format: spare packed at 0x800 boundary (4 pages × 0x200 = 0x800, spare block at +0x800)
    if image.len() > 0x840 {
        if image[0x800] == 0xFF { return true; }
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

pub fn remove_spare(image: &[u8]) -> Vec<u8> {
    let Ok(layout) = NandLayout::detect(image) else { return image.to_vec() };
    if layout == NandLayout::Emmc { return image.to_vec(); }
    // Gate on actual spare presence rather than blindly stripping.
    if !has_spare(image) { return image.to_vec(); }

    let p_page = layout.physical_page_size();
    let l_page = layout.page_size();
    let pages = image.len() / p_page;

    println!(" -> Multi-Core Prep: Stripping Physical Spares/ECC to create Clean Buffer...");
    let mut result = vec![0u8; pages * l_page];
    for i in 0..pages {
        result[i * l_page..(i + 1) * l_page].copy_from_slice(&image[i * p_page..i * p_page + l_page]);
    }
    result
}

pub fn get_page_spare(image: &[u8], page: usize, layout: &NandLayout) -> Option<Vec<u8>> {
    let spare_size = layout.spare_size();
    if spare_size == 0 { return None; }
    let offset = (page * layout.physical_page_size()) + layout.page_size();
    if offset + spare_size <= image.len() {
        Some(image[offset..offset + spare_size].to_vec())
    } else { None }
}

pub fn is_bad_block(image: &[u8], block_number: usize, layout: &NandLayout) -> bool {
    let block_size = layout.block_size();
    let marker_offset = layout.marker_offset();
    let offset = block_number * block_size;
    if offset + block_size > image.len() { return false; }

    let p_page_size = layout.physical_page_size();
    let l_page_size = layout.page_size();
    let mut i = 0;
    let mut flag = false;
    while i + p_page_size <= block_size {
        let page_offset = offset + i;
        let spare = &image[page_offset + l_page_size..page_offset + p_page_size];
        if spare.iter().all(|&b| b == 0x00) { return true; }
        if image[page_offset + marker_offset] != 0xFF {
            if layout != &NandLayout::Bb || !flag { return true; }
        }
        flag = true;
        i += p_page_size;
    }
    false
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
        
        println!(" -> Found {} Bad Physical Blocks. Attempting Healing/Remapping...", bad_indices.len());
        let remapped = resolve_remapped_blocks(image, &bad_indices, &self.layout)?;
        for (i, &bad_block) in bad_indices.iter().enumerate() {
            let target = remapped[i].ok_or_else(|| format!("Bad block {} not remapped", bad_block))?;
            println!("   - Remapping Bad Block {} -> Reserved Physical Block {}", bad_block, target);
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

impl NandProcessor {
    pub fn preprocess_nand(raw_image: &[u8]) -> Result<(Vec<u8>, NandLayout), String> {
        let base_layout = NandLayout::detect(raw_image)?;
        if base_layout == NandLayout::Emmc { return Ok((raw_image.to_vec(), base_layout)); }

        // Promote Sb → Xsb while spare data is still present (matches J-Runner identifylayout).
        let layout = promote_layout(raw_image, base_layout);
        if layout != base_layout {
            println!(" -> Promoted layout: {:?} -> {:?} (Xenon spare format detected)", base_layout, layout);
        }

        let mut working = raw_image.to_vec();
        if let Some(mut bm) = BlockMap::new(&working) {
            bm.map_and_heal(&mut working)?;
        }
        let mut clean = remove_spare(&working);
        if layout == NandLayout::Bb && clean.len() > 0x4000000 {
            clean.truncate(0x4000000);
        }
        Ok((clean, layout))
    }

    pub fn finalize_nand(clean_data: &[u8], layout: NandLayout) -> Vec<u8> {
        if layout == NandLayout::Emmc { return clean_data.to_vec(); }
        add_spare(clean_data, layout, 0)
    }
}
