/*
    xebuild.rs - Raw xeBuild binary parser and patcher
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/

use std::fs::File;
use std::io::{self, Read};
use crate::builder::builder::*;
use log::info;

/// xeBuild binary patch format
// 3 types: JTAG, RGH, Addon

#[derive(Debug, PartialEq)]
pub enum XeBuildBinaryType {
    Jtag,
    Rgh,
    Addon,
    Unknown,
}

#[derive(Debug)]
pub struct XeBuildPatch {
    pub records: Vec<PatchRecord>,
}

#[derive(Debug)]
pub struct XeBuildBinary {
    pub xetype: XeBuildBinaryType,
    pub onebl: Option<XeBuildPatch>,
    pub cb: Option<XeBuildPatch>,
    pub cb_b: Option<XeBuildPatch>,
    pub cd: Option<XeBuildPatch>,
    pub khv: Option<XeBuildPatch>,
    pub generic: Option<XeBuildPatch>,
}

/// Reads patch records from any byte source (file, memory buffer, etc)
/// Returns a Vec of sections, each section being a Vec<PatchRecord>.
pub fn parse_patch_records(mut reader: impl Read) -> io::Result<Vec<Vec<PatchRecord>>> {
    let mut sections = Vec::new();
    let mut cur_section = Vec::new();

    loop {
        let mut buf = [0u8; 4];
        if reader.read_exact(&mut buf).is_err() {
            if !cur_section.is_empty() {
                sections.push(cur_section);
            }
            break;
        }

        let word = u32::from_be_bytes(buf);

        if word == 0xFFFFFFFF {
            sections.push(std::mem::take(&mut cur_section));
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
            amount: amount,
            data,
        });
    }

    Ok(sections)
}

pub fn parse_xe_binary(path: &str) -> anyhow::Result<XeBuildBinary> {
    let file = File::open(path)?;
    info!("[gxpatcher] Parsing xeBuild binary: '{}'", path);

    let mut sections = parse_patch_records(file)?;
    let section_count = sections.len();

    let mut output = XeBuildBinary {
        xetype: XeBuildBinaryType::Unknown,
        onebl: None,
        cb: None,
        cb_b: None,
        cd: None,
        khv: None,
        generic: None,
    };

    if section_count == 1 {
        output.xetype = XeBuildBinaryType::Addon;
        info!("[gxpatcher] Detected Addon patch binary (1 section)");
        output.khv = Some(XeBuildPatch { records: sections.remove(0) });
    } else if section_count == 3 {
        output.xetype = XeBuildBinaryType::Rgh;
        info!("[gxpatcher] Detected RGH patch binary (3 sections)");
        output.cb = Some(XeBuildPatch { records: sections.remove(0) });
        output.cd = Some(XeBuildPatch { records: sections.remove(0) });
        output.khv = Some(XeBuildPatch { records: sections.remove(0) });
    } else if section_count == 4 {
        output.xetype = XeBuildBinaryType::Jtag;
        info!("[gxpatcher] Detected JTAG patch binary (4 sections)");
        output.onebl = Some(XeBuildPatch { records: sections.remove(0) });
        output.cb = Some(XeBuildPatch { records: sections.remove(0) });
        output.cd = Some(XeBuildPatch { records: sections.remove(0) });
        output.khv = Some(XeBuildPatch { records: sections.remove(0) });
    } else {
        info!("[gxpatcher] Detected unknown patch binary ({} sections)", section_count);
        if !sections.is_empty() {
            output.khv = Some(XeBuildPatch { records: sections.remove(0) });
        }
    }

    Ok(output)
}

/// Lowlevel function, apply section of patch binary to target data.
pub fn apply_xe_buffer(patch: &XeBuildPatch, data: &mut Vec<u8>) -> anyhow::Result<()> {
    info!("[gxpatcher] apply_xe_buffer: Attempting to apply {} records to buffer of size 0x{:X}", patch.records.len(), data.len());
    let mut modified_words = 0;
    
    for (idx, record) in patch.records.iter().enumerate() {
        let offset = record.address as usize;
        // info!("[gxpatcher]   -> Record {}: offset=0x{:X}", idx, offset);

        for (i, &word) in record.data.iter().enumerate() {
            let write_pos = offset + (i * 4);
            
            // If the patch address is beyond the current buffer, resize it (padding with zeros)
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
    
    info!("[gxpatcher] apply_xe_buffer: Successfully modified {} words.", modified_words);
    Ok(())
}

pub fn apply_xe_patch(patch: XeBuildBinary, nand: &mut NandSkeleton) -> anyhow::Result<()> {
    if let Some(khv) = patch.khv {
        info!("[gxpatcher] Queuing {} KHV patch record(s) into NAND options...", khv.records.len());
        nand.bootloaders.khvpatch = Some(khv.records);
    }

    if let Some(cb) = patch.cb {
        if patch.xetype == XeBuildBinaryType::Rgh {
            if let Some(cbb_bl) = &mut nand.bootloaders.cb_b {
                info!("[gxpatcher] Applying RGH Section 0 patch record(s) to CB_B ({} bytes)", cbb_bl.data.len());
                apply_xe_buffer(&cb, &mut cbb_bl.data)?;
            } else if let Some(cb_bl) = &mut nand.bootloaders.cb {
                // Fallback to CB if CB_B isn't present (glitch1)
                info!("[gxpatcher] Applying RGH Section 0 patch record(s) to CB ({} bytes)", cb_bl.data.len());
                apply_xe_buffer(&cb, &mut cb_bl.data)?;
            }
        } else {
            // JTAG or other types
            if let Some(cb_bl) = &mut nand.bootloaders.cb {
                info!("[gxpatcher] Applying patch record(s) to CB ({} bytes)", cb_bl.data.len());
                apply_xe_buffer(&cb, &mut cb_bl.data)?;
            }
        }
    }

    if let Some(cd) = patch.cd {
        if let Some(cd_bl) = &mut nand.bootloaders.cd {
            info!("[gxpatcher] Applying {} RGH patch record(s) to CD ({} bytes)", cd.records.len(), cd_bl.data.len());
            apply_xe_buffer(&cd, &mut cd_bl.data)?;
        }
    }

    Ok(())
}
