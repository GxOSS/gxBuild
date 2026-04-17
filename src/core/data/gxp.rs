/*
    gxp.rs - gxBuild Patch (GXP) binary parser
    
    This file defines the GXP header format and provides logic for parsing
    both modern multi-component RGH/JTAG patchsets and legacy xeBuild binaries.
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
    pub data: Vec<u32>,
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

/// Core record reading logic shared between GXP and legacy formats.
fn read_patch_sections(mut reader: impl Read) -> io::Result<Vec<GxpSection>> {
    let mut sections = Vec::new();
    let mut cur_section = Vec::new();

    loop {
        let mut buf = [0u8; 4];
        if reader.read_exact(&mut buf).is_err() {
            if !cur_section.is_empty() {
                sections.push(GxpSection { records: cur_section });
            }
            break;
        }

        let word = u32::from_be_bytes(buf);

        if word == 0xFFFFFFFF {
            sections.push(GxpSection { records: std::mem::take(&mut cur_section) });
            continue;
        }

        let address = word;
        let mut amt_buf = [0u8; 4];
        reader.read_exact(&mut amt_buf)?;
        let amount = u32::from_be_bytes(amt_buf);
        let count = amount as usize;

        let mut data = Vec::with_capacity(count);
        for _ in 0..count {
            let mut data_buf = [0u8; 4];
            reader.read_exact(&mut data_buf)?;
            data.push(u32::from_be_bytes(data_buf));
        }

        cur_section.push(PatchRecord {
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
        let temp_sections = read_patch_sections(&mut file)?;
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

    let sections_raw = read_patch_sections(file)?;

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

        for (i, &word) in record.data.iter().enumerate() {
            let write_pos = offset + (i * 4);
            
            // Safety: 4MB limit to prevent runaway allocation if a patch record is corrupt.
            if write_pos + 4 > data.len() {
                if write_pos + 4 > 0x400000 {
                    anyhow::bail!("Patch address 0x{:X} exceeds 4MB safety limit", write_pos);
                }
                data.resize(write_pos + 4, 0);
            }

            data[write_pos..write_pos + 4].copy_from_slice(&word.to_be_bytes());
            modified_words += 1;
        }
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
