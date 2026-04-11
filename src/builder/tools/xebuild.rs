/*
    xebuild.rs - Raw xeBuild binary parser and patcher
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use crate::builder::builder::*;

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

// This hash function probably needs to return a String
// get_hash removed (unused)

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

        // word is amount of words to follow
        let mut data = Vec::with_capacity(word as usize);
        for _ in 0..word {
            let mut data_buf = [0u8; 4];
            reader.read_exact(&mut data_buf)?;
            data.push(u32::from_be_bytes(data_buf));
        }

        // next word is address
        let mut addr_buf = [0u8; 4];
        reader.read_exact(&mut addr_buf)?;
        let address = u32::from_be_bytes(addr_buf);

        cur_section.push(PatchRecord {
            address,
            amount: word,
            data,
        });
    }

    Ok(sections)
}

pub fn parse_xe_binary(path: &str) -> anyhow::Result<XeBuildBinary> {
    let mut file = File::open(path)?;
    let mut header = [0u8; 4];
    file.read_exact(&mut header)?;

    let mut output = XeBuildBinary {
        xetype: XeBuildBinaryType::Unknown,
        onebl: None,
        cb: None,
        cb_b: None,
        cd: None,
        khv: None,
        generic: None,
    };

    if &header == b"JTAG" {
        output.xetype = XeBuildBinaryType::Jtag;
        let mut sections = parse_patch_records(&mut file)?;
        if sections.is_empty() {
            return Err(anyhow::anyhow!("Empty JTAG patch file"));
        }
        output.generic = Some(XeBuildPatch {
            records: sections.remove(0),
        });
    } else if &header == b"RGH\0" || &header == b"RGH " {
        output.xetype = XeBuildBinaryType::Rgh;
        let mut sections = parse_patch_records(&mut file)?;
        if sections.len() < 3 {
            return Err(anyhow::anyhow!("RGH patch file missing sections (expected 3+)"));
        }
        output.cb = Some(XeBuildPatch {
            records: sections.remove(0),
        });
        output.cd = Some(XeBuildPatch {
            records: sections.remove(0),
        });
        output.khv = Some(XeBuildPatch {
            records: sections.remove(0),
        });
    } else {
        // Fallback or Addon?
        output.xetype = XeBuildBinaryType::Addon;
        file.seek(SeekFrom::Start(0))?;
        let mut sections = parse_patch_records(&mut file)?;
        if !sections.is_empty() {
            output.khv = Some(XeBuildPatch {
                records: sections.remove(0),
            });
        }
    }

    Ok(output)
}

/// Lowlevel function, apply section of patch binary to target data.
fn apply_xe_buffer(patch: &XeBuildPatch, data: &mut Vec<u8>) -> anyhow::Result<()> {
    for record in &patch.records {
        let offset = record.address as usize;
        for (i, &word) in record.data.iter().enumerate() {
            let write_pos = offset + (i * 4);
            if write_pos + 4 > data.len() {
                anyhow::bail!(
                    "Patch address 0x{:X} is out of bounds for buffer of size 0x{:X}",
                    record.address,
                    data.len()
                );
            }
            data[write_pos..write_pos + 4].copy_from_slice(&word.to_be_bytes());
        }
    }
    Ok(())
}

// Create or insert CDXell patch
// apply_cdxell removed (unused)

pub fn apply_xe_patch(patch: XeBuildBinary, nand: &mut NandSkeleton) -> anyhow::Result<()> {
    if let Some(khv) = patch.khv {
        println!(" -> Appending KHV patches to NandSkeleton options...");
        if let Some(patches) = &mut nand.options.patches {
            for record in khv.records {
                patches.khv.push(PatchRecord {
                    address: record.address,
                    amount: record.amount,
                    data: record.data,
                });
            }
        }
    }

    if let Some(cb) = patch.cb {
        if let Some(cb_bl) = &mut nand.bootloaders.cb {
            apply_xe_buffer(&cb, &mut cb_bl.data)?;
        }
    }

    if let Some(cd) = patch.cd {
        if let Some(cd_bl) = &mut nand.bootloaders.cd {
            apply_xe_buffer(&cd, &mut cd_bl.data)?;
        }
    }

    Ok(())
}
