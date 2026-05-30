/*
    corona.rs - Corona / eMMC FlashFS metadata (XE_CORONA_FS_DATA)

    Ported from RGBuildPP CXeFlashImage LoadFileSystems / SaveFileSystems.
*/

use crate::builder::filesystem::flashfs::FileSystemRoot;
use crate::builder::filesystem::mobile::MobileStore;
use crate::builder::filesystem::{FsError, Result};
use crate::crypto::sha;
use log::info;

/// RGBuildPP `XE_FLASH_CORONA_FS_DATA_ADDR`
pub const CORONA_FS_DATA_BASE: usize = 0x2FE8000;
pub const CORONA_FS_DATA_STRIDE: usize = 0x4000;
pub const CORONA_FS_DATA_SLOTS: usize = 2;
pub const CORONA_FS_DATA_SIZE: usize = 0x200;

/// On-disk Corona FlashFS descriptor (512 bytes at 0x2FE8000 + n * 0x4000).
#[derive(Debug, Clone)]
pub struct CoronaFsData {
    pub section_digest: [u8; 0x14],
    pub unknown: u32,
    pub fs_version: u32,
    pub fs_block_idx: u16,
    pub unknown_word: u16,
    pub mobile1_block_idx: u16,
    pub mobile1_length: u16,
    pub unknown2: [u8; 8],
    pub mobile2_block_idx: u16,
    pub mobile2_length: u16,
    pub padding: [u8; 0x1D0],
}

impl Default for CoronaFsData {
    fn default() -> Self {
        Self {
            section_digest: [0u8; 0x14],
            unknown: 0,
            fs_version: 0,
            fs_block_idx: 0,
            unknown_word: 0,
            mobile1_block_idx: 0,
            mobile1_length: 0,
            unknown2: [0u8; 8],
            mobile2_block_idx: 0,
            mobile2_length: 0,
            padding: [0u8; 0x1D0],
        }
    }
}

pub type CoronaFsSlots = [CoronaFsData; CORONA_FS_DATA_SLOTS];

impl CoronaFsData {
    pub fn from_bytes(raw: &[u8]) -> Self {
        let mut c = Self::default();
        if raw.len() < 0x30 {
            return c;
        }
        c.section_digest.copy_from_slice(&raw[0..0x14]);
        c.unknown = u32::from_be_bytes(raw[0x14..0x18].try_into().unwrap_or([0; 4]));
        c.fs_version = u32::from_be_bytes(raw[0x18..0x1C].try_into().unwrap_or([0; 4]));
        c.fs_block_idx = u16::from_be_bytes(raw[0x1C..0x1E].try_into().unwrap_or([0; 2]));
        c.unknown_word = u16::from_be_bytes(raw[0x1E..0x20].try_into().unwrap_or([0; 2]));
        c.mobile1_block_idx = u16::from_be_bytes(raw[0x20..0x22].try_into().unwrap_or([0; 2]));
        c.mobile1_length = u16::from_be_bytes(raw[0x22..0x24].try_into().unwrap_or([0; 2]));
        c.unknown2.copy_from_slice(&raw[0x24..0x2C]);
        c.mobile2_block_idx = u16::from_be_bytes(raw[0x2C..0x2E].try_into().unwrap_or([0; 2]));
        c.mobile2_length = u16::from_be_bytes(raw[0x2E..0x30].try_into().unwrap_or([0; 2]));
        if raw.len() >= CORONA_FS_DATA_SIZE {
            c.padding.copy_from_slice(&raw[0x30..CORONA_FS_DATA_SIZE]);
        }
        c
    }

    pub fn to_bytes(&self) -> [u8; CORONA_FS_DATA_SIZE] {
        let mut raw = [0u8; CORONA_FS_DATA_SIZE];
        raw[0..0x14].copy_from_slice(&self.section_digest);
        raw[0x14..0x18].copy_from_slice(&self.unknown.to_be_bytes());
        raw[0x18..0x1C].copy_from_slice(&self.fs_version.to_be_bytes());
        raw[0x1C..0x1E].copy_from_slice(&self.fs_block_idx.to_be_bytes());
        raw[0x1E..0x20].copy_from_slice(&self.unknown_word.to_be_bytes());
        raw[0x20..0x22].copy_from_slice(&self.mobile1_block_idx.to_be_bytes());
        raw[0x22..0x24].copy_from_slice(&self.mobile1_length.to_be_bytes());
        raw[0x24..0x2C].copy_from_slice(&self.unknown2);
        raw[0x2C..0x2E].copy_from_slice(&self.mobile2_block_idx.to_be_bytes());
        raw[0x2E..0x30].copy_from_slice(&self.mobile2_length.to_be_bytes());
        raw[0x30..CORONA_FS_DATA_SIZE].copy_from_slice(&self.padding);
        raw
    }

    /// SHA-1 over payload starting at `dwUnknown` (RGBuildPP `XeCryptSha` on struct tail).
    pub fn refresh_digest(&mut self) -> Result<()> {
        let mut raw = self.to_bytes();
        let hash = sha(&[&raw[0x14..CORONA_FS_DATA_SIZE]])
            .map_err(|e| FsError::CoronaDigest(e.to_string()))?;
        raw[0..0x14].copy_from_slice(&hash[..0x14]);
        self.section_digest.copy_from_slice(&hash[..0x14]);
        Ok(())
    }

    pub fn sync_from_fs_root(&mut self, root: &FileSystemRoot) {
        if root.block_number >= 0 {
            self.fs_block_idx = root.block_number as u16;
        }
        self.fs_version = root.version.max(1) as u32;
    }

    pub fn sync_from_mobile(&mut self, mobile: &MobileStore) {
        if let Some(m) = mobile.latest_entry(0) {
            self.mobile1_block_idx = m.start_page as u16;
            self.mobile1_length = m.data.len().min(0xFFFF) as u16;
        }
        if let Some(m) = mobile.latest_entry(1) {
            self.mobile2_block_idx = m.start_page as u16;
            self.mobile2_length = m.data.len().min(0xFFFF) as u16;
        }
    }
}

/// Load both Corona FS metadata slots from an eMMC image.
pub fn load_slots(image: &[u8]) -> CoronaFsSlots {
    let mut slots = [CoronaFsData::default(), CoronaFsData::default()];
    for (i, slot) in slots.iter_mut().enumerate() {
        let offset = CORONA_FS_DATA_BASE + i * CORONA_FS_DATA_STRIDE;
        if offset + CORONA_FS_DATA_SIZE <= image.len() {
            *slot = CoronaFsData::from_bytes(&image[offset..offset + CORONA_FS_DATA_SIZE]);
            if slot.fs_version > 0 {
                info!(
                    "[corona] Slot {}: FS block {}, version {}",
                    i, slot.fs_block_idx, slot.fs_version
                );
            }
        }
    }
    slots
}

/// Best (block, version) from Corona slots for FlashFS root discovery.
pub fn best_fs_from_slots(slots: &CoronaFsSlots) -> Option<(usize, u32)> {
    let mut best: Option<(usize, u32)> = None;
    for slot in slots {
        if slot.fs_version == 0 {
            continue;
        }
        let block = slot.fs_block_idx as usize;
        let ver = slot.fs_version;
        if best.map(|(_, v)| ver > v).unwrap_or(true) {
            best = Some((block, ver));
        }
    }
    best
}

/// Default FS start block for a new eMMC FlashFS when no Corona/header hint exists.
pub fn default_emmc_fs_block(header_fs_addr: u32, slots: &CoronaFsSlots) -> u16 {
    if let Some((block, _)) = best_fs_from_slots(slots) {
        return block.min(0xFFFF) as u16;
    }
    if header_fs_addr >= 0x200 {
        return (header_fs_addr / 0x200).min(0xFFFF) as u16;
    }
    0x80
}

/// Write Corona metadata slots after FlashFS (and optional mobile) are placed.
pub fn write_back(
    image: &mut [u8],
    slots: &mut CoronaFsSlots,
    root: &FileSystemRoot,
    mobile: &MobileStore,
) -> Result<()> {
    if root.block_number < 0 && root.entries.is_empty() {
        return Ok(());
    }

    for (i, slot) in slots.iter_mut().enumerate() {
        if i > 0 && slot.fs_version == 0 {
            continue;
        }
        if root.block_number < 0 && slot.fs_version == 0 {
            continue;
        }

        slot.sync_from_fs_root(root);
        slot.sync_from_mobile(mobile);
        slot.refresh_digest()?;

        let offset = CORONA_FS_DATA_BASE + i * CORONA_FS_DATA_STRIDE;
        if offset + CORONA_FS_DATA_SIZE > image.len() {
            return Err(FsError::CoronaWriteOutOfBounds { slot: i, offset });
        }

        let raw = slot.to_bytes();
        image[offset..offset + CORONA_FS_DATA_SIZE].copy_from_slice(&raw);
        info!(
            "[corona] Wrote slot {} @ 0x{:X}: block {}, version {}",
            i, offset, slot.fs_block_idx, slot.fs_version
        );
    }

    Ok(())
}
