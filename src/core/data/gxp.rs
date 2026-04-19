/*
    gxp.rs - gxBuild Patch (GXP) binary parser

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use log::{info, warn};

/// GXP Header Magic: "GXP\0" (0x47 0x58 0x50 0x00)
pub const GXP_MAGIC: [u8; 4] = [0x47, 0x58, 0x50, 0x00];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MotherboardType {
    Any = 0,
    Xenon = 1,
    Zephyr = 2,
    Falcon = 3,
    Jasper = 4,
    Trinity = 5,
    Corona = 6,
    Winchester = 7,
    Unknown = 0xFFFF,
}

impl From<u16> for MotherboardType {
    fn from(v: u16) -> Self {
        match v {
            0 => MotherboardType::Any,
            1 => MotherboardType::Xenon,
            2 => MotherboardType::Zephyr,
            3 => MotherboardType::Falcon,
            4 => MotherboardType::Jasper,
            5 => MotherboardType::Trinity,
            6 => MotherboardType::Corona,
            7 => MotherboardType::Winchester,
            _ => MotherboardType::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GxpPatchType {
    Disabled = 0,
    Rgh4Section = 1,   // CB_B, CD, KHV, SMC
    Jtag4Section = 2,  // 1BL, CB, CD, KHV
    Rgh3Section = 3,   // CB, CD, KHV
    Standalone = 4,    // 1 Section (Target BL)
    Addon = 5,         // 1 Section (Target BL at offset)
    Jtag5Section = 7,  // 1BL, CB, CD, KHV, SMC
    Unknown = 0xFF,
}

impl From<u8> for GxpPatchType {
    fn from(v: u8) -> Self {
        match v {
            0 => GxpPatchType::Disabled,
            1 => GxpPatchType::Rgh4Section,
            2 => GxpPatchType::Jtag4Section,
            3 => GxpPatchType::Rgh3Section,
            4 => GxpPatchType::Standalone,
            5 => GxpPatchType::Addon,
            7 => GxpPatchType::Jtag5Section,
            _ => GxpPatchType::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootloaderId {
    None = 0,
    OneBl = 1,
    Cb = 2,
    CbA = 3,
    CbB = 4,
    Cd = 5,
    Khv = 6,
    Smc = 7,
    Unknown = 0xFF,
}

impl From<u8> for BootloaderId {
    fn from(v: u8) -> Self {
        match v {
            0 => BootloaderId::None,
            1 => BootloaderId::OneBl,
            2 => BootloaderId::Cb,
            3 => BootloaderId::CbA,
            4 => BootloaderId::CbB,
            5 => BootloaderId::Cd,
            6 => BootloaderId::Khv,
            7 => BootloaderId::Smc,
            _ => BootloaderId::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PatchRecord {
    pub address: u32,
    pub amount: u32,
    pub data: Vec<u8>, // Switched to Vec<u8> for byte-level granularity
}

#[derive(Debug, Clone)]
pub struct GxpHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub motherboard: MotherboardType,
    pub patch_type: GxpPatchType,
    pub bootloader: BootloaderId,
    pub offset: u32,
}

impl GxpHeader {
    pub fn new_legacy(section_count: usize) -> Self {
        let patch_type = match section_count {
            4 => GxpPatchType::Jtag4Section,
            3 => GxpPatchType::Rgh3Section,
            1 => GxpPatchType::Addon,
            _ => GxpPatchType::Unknown,
        };
        
        Self {
            magic: [0u8; 4],
            version: 0,
            motherboard: MotherboardType::Any,
            patch_type,
            bootloader: if patch_type == GxpPatchType::Addon { BootloaderId::Khv } else { BootloaderId::None },
            offset: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GxpSection {
    pub records: Vec<PatchRecord>,
}

#[derive(Debug, Clone)]
pub struct GxpBinary {
    pub header: GxpHeader,
    pub sections: Vec<GxpSection>,
    pub is_legacy: bool,
    
    // Categorized accessors
    pub onebl: Option<GxpSection>,
    pub cb: Option<GxpSection>,
    pub cb_a: Option<GxpSection>,
    pub cb_b: Option<GxpSection>,
    pub cd: Option<GxpSection>,
    pub khv: Option<GxpSection>,
    pub smc: Option<GxpSection>,
}

/// Core record reading logic. 
/// Handles legacy word-based patches and modern GXP patches with section-aware granularity.
fn read_patch_sections(mut reader: impl Read, patch_type: GxpPatchType, is_legacy: bool, smc_id: BootloaderId) -> io::Result<Vec<GxpSection>> {
    let mut sections = Vec::new();
    let mut cur_records = Vec::new();

    loop {
        let mut buf = [0u8; 4];
        if reader.read_exact(&mut buf).is_err() {
            if !cur_records.is_empty() {
                sections.push(GxpSection { records: cur_records });
            }
            break;
        }

        let word = u32::from_be_bytes(buf);

        if word == 0xFFFFFFFF {
            sections.push(GxpSection { records: std::mem::take(&mut cur_records) });
            continue;
        }

        let address = word;
        let mut amt_buf = [0u8; 4];
        reader.read_exact(&mut amt_buf)?;
        let amount = u32::from_be_bytes(amt_buf);
        
        // Determine granularity: SMC sections in GXP files are byte-based.
        let current_section_idx = sections.len();
        let is_byte_mode = if is_legacy {
            false
        } else {
            match patch_type {
                GxpPatchType::Rgh4Section => current_section_idx == 3, // Section 4 (SMC)
                GxpPatchType::Jtag5Section => current_section_idx == 4, // Section 5 (SMC)
                GxpPatchType::Standalone | GxpPatchType::Addon => smc_id == BootloaderId::Smc,
                _ => false,
            }
        };

        let mut data = Vec::new();
        if is_byte_mode {
            let byte_count = amount as usize;
            data.resize(byte_count, 0);
            reader.read_exact(&mut data)?;
        } else {
            let word_count = amount as usize;
            data.reserve(word_count * 4);
            for _ in 0..word_count {
                let mut word_buf = [0u8; 4];
                reader.read_exact(&mut word_buf)?;
                data.extend_from_slice(&word_buf);
            }
        }

        cur_records.push(PatchRecord {
            address,
            amount,
            data,
        });
    }

    Ok(sections)
}

pub fn parse_patch_binary<P: AsRef<Path>>(path: P) -> anyhow::Result<GxpBinary> {
    let mut file = File::open(&path)?;
    let mut magic_buf = [0u8; 4];
    file.read_exact(&mut magic_buf)?;

    let (header, is_legacy) = if magic_buf == GXP_MAGIC {
        // GXP Format
        let mut meta_buf = [0u8; 12];
        file.read_exact(&mut meta_buf)?;
        
        let header = GxpHeader {
            magic: GXP_MAGIC,
            version: u32::from_be_bytes([meta_buf[0], meta_buf[1], meta_buf[2], meta_buf[3]]),
            motherboard: MotherboardType::from(u16::from_be_bytes([meta_buf[4], meta_buf[5]])),
            patch_type: GxpPatchType::from(meta_buf[6]),
            bootloader: BootloaderId::from(meta_buf[7]),
            offset: u32::from_be_bytes([meta_buf[8], meta_buf[9], meta_buf[10], meta_buf[11]]),
        };
        (header, false)
    } else {
        // Legacy format detection
        file.seek(SeekFrom::Start(0))?;
        let temp_sections = read_patch_sections(&mut file, GxpPatchType::Unknown, true, BootloaderId::None)?;
        let header = GxpHeader::new_legacy(temp_sections.len());
        // Rewind again so unified loop can read it fully (though we already have them, we rebuild for consistency)
        file.seek(SeekFrom::Start(0))?;
        (header, true)
    };

    if !is_legacy {
        info!("[gxp] Detected GXP binary: {:?}", path.as_ref());
        info!("[gxp] Metadata: Type={:?}, Kernel={}, MB={:?}, BL={:?}, Offset=0x{:X}", 
            header.patch_type, header.version, header.motherboard, header.bootloader, header.offset);
    } else {
        info!("[gxp] Detected legacy xeBuild binary: {:?}", path.as_ref());
        info!("[gxp] Heuristic: Type={:?}, Sections={}", header.patch_type, if header.patch_type == GxpPatchType::Addon { 1 } else if header.patch_type == GxpPatchType::Rgh3Section { 3 } else { 4 });
    }

    let sections_raw = read_patch_sections(file, header.patch_type, is_legacy, header.bootloader)?;

    let mut binary = GxpBinary {
        header: header.clone(),
        sections: sections_raw.clone(),
        is_legacy,
        onebl: None,
        cb: None,
        cb_a: None,
        cb_b: None,
        cd: None,
        khv: None,
        smc: None,
    };

    // Route sections based on patch type
    match header.patch_type {
        GxpPatchType::Rgh4Section => {
            if sections_raw.len() >= 4 {
                binary.cb_b = Some(sections_raw[0].clone());
                binary.cd = Some(sections_raw[1].clone());
                binary.khv = Some(sections_raw[2].clone());
                binary.smc = Some(sections_raw[3].clone());
            } else {
                warn!("[gxp] RGH 4-Section Patch has only {} sections!", sections_raw.len());
            }
        }
        GxpPatchType::Jtag5Section => {
            if sections_raw.len() >= 5 {
                binary.onebl = Some(sections_raw[0].clone());
                binary.cb = Some(sections_raw[1].clone());
                binary.cd = Some(sections_raw[2].clone());
                binary.khv = Some(sections_raw[3].clone());
                binary.smc = Some(sections_raw[4].clone());
            } else {
                warn!("[gxp] JTAG 5-Section Patch has only {} sections!", sections_raw.len());
            }
        }
        GxpPatchType::Jtag4Section => {
            if sections_raw.len() >= 4 {
                binary.onebl = Some(sections_raw[0].clone());
                binary.cb = Some(sections_raw[1].clone());
                binary.cd = Some(sections_raw[2].clone());
                binary.khv = Some(sections_raw[3].clone());
            } else {
                warn!("[gxp] JTAG 4-Section Patch has only {} sections!", sections_raw.len());
            }
        }
        GxpPatchType::Rgh3Section => {
            if sections_raw.len() >= 3 {
                binary.cb = Some(sections_raw[0].clone());
                binary.cd = Some(sections_raw[1].clone());
                binary.khv = Some(sections_raw[2].clone());
            } else {
                warn!("[gxp] RGH 3-Section Patch has only {} sections!", sections_raw.len());
            }
        }
        GxpPatchType::Standalone | GxpPatchType::Addon => {
            if !sections_raw.is_empty() {
                let sec = Some(sections_raw[0].clone());
                match header.bootloader {
                    BootloaderId::OneBl => binary.onebl = sec,
                    BootloaderId::Cb => binary.cb = sec,
                    BootloaderId::CbA => binary.cb_a = sec,
                    BootloaderId::CbB => binary.cb_b = sec,
                    BootloaderId::Cd => binary.cd = sec,
                    BootloaderId::Khv => binary.khv = sec,
                    BootloaderId::Smc => binary.smc = sec,
                    _ => binary.khv = sec,
                }
            }
        }
        _ => {
            if is_legacy && !sections_raw.is_empty() {
                 binary.khv = Some(sections_raw[0].clone());
            }
        }
    }

    Ok(binary)
}

/// Low-level function to apply a set of patch records to a buffer.
pub fn apply_records(records: &[PatchRecord], data: &mut Vec<u8>) -> anyhow::Result<()> {
    info!("[gxp] Applying {} records to buffer (size 0x{:X})", records.len(), data.len());
    let mut modified_words = 0;
    
    for record in records {
        let offset = record.address as usize;

        // Safety: 4MB limit to prevent runaway allocation if a patch record is corrupt.
        if offset + record.data.len() > data.len() {
            if offset + record.data.len() > 0x400000 {
                anyhow::bail!("Patch address 0x{:X} exceeds 4MB safety limit", offset + record.data.len());
            }
            data.resize(offset + record.data.len(), 0);
        }

        data[offset..offset + record.data.len()].copy_from_slice(&record.data);
        modified_words += (record.data.len() + 3) / 4;
    }
    
    info!("[gxp] Modified {} words.", modified_words);
    Ok(())
}

/// Convenience function: Parses a patch file and applies its first section to a buffer.
pub fn parse_and_apply_to_buffer<P: AsRef<Path>>(path: P, data: &mut Vec<u8>) -> anyhow::Result<()> {
    let patch = parse_patch_binary(path)?;
    if let Some(section) = patch.sections.first() {
        apply_records(&section.records, data)
    } else {
        anyhow::bail!("Patch file contains no sections")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_legacy_word_alignment() {
        // Mock a legacy patch: Address 0, Count 1, Data [0x11, 0x22, 0x33, 0x44]
        let mut mock_data = Vec::new();
        mock_data.extend_from_slice(&0u32.to_be_bytes()); // Address
        mock_data.extend_from_slice(&1u32.to_be_bytes()); // Count (Words)
        mock_data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // Data
        mock_data.extend_from_slice(&0xFFFFFFFFu32.to_be_bytes()); // Sentinel

        let sections = read_patch_sections(Cursor::new(mock_data), GxpPatchType::Unknown, true, BootloaderId::None).unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].records.len(), 1);
        assert_eq!(sections[0].records[0].data, vec![0x11, 0x22, 0x33, 0x44]);

        let mut buffer = vec![0u8; 8];
        apply_records(&sections[0].records, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0]);
    }

    #[test]
    fn test_byte_level_smc_patch() {
        // Mock a GXP Standalone SMC patch: Address 2, Count 1, Data [0x99]
        let mut mock_data = Vec::new();
        mock_data.extend_from_slice(&2u32.to_be_bytes()); // Address
        mock_data.extend_from_slice(&1u32.to_be_bytes()); // Count (Bytes!)
        mock_data.push(0x99); // Data (1 byte)
        mock_data.extend_from_slice(&0xFFFFFFFFu32.to_be_bytes()); // Sentinel (aligned to word for reader)

        let sections = read_patch_sections(Cursor::new(mock_data), GxpPatchType::Standalone, false, BootloaderId::Smc).unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].records.len(), 1);
        assert_eq!(sections[0].records[0].data, vec![0x99]);

        let mut buffer = vec![0u8; 4];
        apply_records(&sections[0].records, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0, 0, 0x99, 0]);
    }

    #[test]
    fn test_jtag5_section_routing() {
        // Create 5 sections separated by 0xFFFFFFFF
        let mut mock_data = Vec::new();
        for i in 0..5 {
            mock_data.extend_from_slice(&0u32.to_be_bytes()); // Address
            mock_data.extend_from_slice(&1u32.to_be_bytes()); // Count
            if i == 4 {
                mock_data.push(0xEE); // Section 5 is Byte-based SMC
            } else {
                mock_data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
            }
            mock_data.extend_from_slice(&0xFFFFFFFFu32.to_be_bytes());
        }

        let sections = read_patch_sections(Cursor::new(mock_data), GxpPatchType::Jtag5Section, false, BootloaderId::None).unwrap();
        assert_eq!(sections.len(), 5);
        assert_eq!(sections[4].records[0].data, vec![0xEE]);

        let binary = GxpBinary {
            header: GxpHeader { 
                magic: GXP_MAGIC, version: 0, motherboard: MotherboardType::Any, 
                patch_type: GxpPatchType::Jtag5Section, bootloader: BootloaderId::None, offset: 0 
            },
            sections: sections.clone(),
            is_legacy: false,
            onebl: Some(sections[0].clone()),
            cb: Some(sections[1].clone()),
            cb_a: None,
            cb_b: None,
            cd: Some(sections[2].clone()),
            khv: Some(sections[3].clone()),
            smc: Some(sections[4].clone()),
        };

        assert!(binary.smc.is_some());
        assert_eq!(binary.smc.unwrap().records[0].data, vec![0xEE]);
    }
}
