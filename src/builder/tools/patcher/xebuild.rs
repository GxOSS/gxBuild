/*
    xebuild.rs - Raw xeBuild binary parser and patcher
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/

use std::fs;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use crc32fast::Hasher;
use crate::builder::builder::*;
use crate::builder::chain::*;

// xeBuild binary patch format
// 3 types: JTAG, RGH, Addon

#[derive(Debug, PartialEq)]
pub enum XeBuildBinaryType {
    Jtag,
    Rgh,
    Addon,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub enum XeBuildPatchType {
    Onebl,
    Cb,
    CbB,
    Cd,
    Khv,
    Generic,
}

/// One patch entry – copy `data` to `address`.
#[derive(Debug)]
pub struct PatchRecord {
    pub address: u32,
    pub amount: u32,
    pub data: Vec<u32>,
}

#[derive(Debug)]
pub struct XeBuildPatch {
    pub patch_type: XeBuildPatchType,
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

// This hash function probably needs to return a String, not XeBuildIni (which doesn't exist here)
// It was also missing the import for fs.
fn get_hash(path: impl AsRef<Path>) -> std::io::Result<String> {
    let data = fs::read(path)?;
    let mut hasher = Hasher::new();
    hasher.update(&data);
    Ok(format!("{:08x}", hasher.finalize()))
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

        reader.read_exact(&mut buf)?;
        let amount = u32::from_be_bytes(buf);
        let count = amount as usize;

        let mut data = Vec::with_capacity(count);
        for _ in 0..count {
            reader.read_exact(&mut buf)?;
            data.push(u32::from_be_bytes(buf));
        }

        cur_section.push(PatchRecord {
            address,
            amount,
            data,
        });
    }

    Ok(sections)
}

/// Read a patch file from disk, parse into XeBuildBinary
pub fn parse_xe_binary(path: &str) -> anyhow::Result<XeBuildBinary> {
    let mut f = File::open(path)?;

    let mut output = XeBuildBinary {
        xetype: XeBuildBinaryType::Unknown,
        onebl: None,
        cb: None,
        cb_b: None,
        cd: None,
        khv: None,
        generic: None,
    };
    // Check for XEPATCH0 header
    let mut header_buf = [0u8; 8];
    if f.read_exact(&mut header_buf).is_ok() {
        if &header_buf == b"XEPATCH0" {
            // Skip Version (4 bytes) and Record Count (4 bytes)
            let mut skip = [0u8; 8];
            f.read_exact(&mut skip)?;
        } else {
            // No header, rewind to start
            f.seek(SeekFrom::Start(0))?;
        }
    } else {
        // Very small file, could be raw
        f.seek(SeekFrom::Start(0))?;
    }

    let sections = parse_patch_records(&mut f)?;
    let section_count = sections.len();

    
    
    // Create a mutable copy of sections to work with
    let mut sections = sections;

    if section_count == 1 {
        output.xetype = XeBuildBinaryType::Addon;
        output.generic = Some(XeBuildPatch {
            patch_type: XeBuildPatchType::Generic,
            records: sections.remove(0),
        });
    } else if section_count == 3 {
        output.xetype = XeBuildBinaryType::Rgh;
        output.cb_b = Some(XeBuildPatch {
            patch_type: XeBuildPatchType::CbB,
            records: sections.remove(0),
        });
        output.cd = Some(XeBuildPatch {
            patch_type: XeBuildPatchType::Cd,
            records: sections.remove(0),
        });
        output.khv = Some(XeBuildPatch {
            patch_type: XeBuildPatchType::Khv,
            records: sections.remove(0),
        });
    } else if section_count == 4 {
        output.xetype = XeBuildBinaryType::Jtag;
        output.onebl = Some(XeBuildPatch {
            patch_type: XeBuildPatchType::Onebl,
            records: sections.remove(0),
        });
        output.cb = Some(XeBuildPatch {
            patch_type: XeBuildPatchType::Cb,
            records: sections.remove(0),
        });
        output.cd = Some(XeBuildPatch {
            patch_type: XeBuildPatchType::Cd,
            records: sections.remove(0),
        });
        output.khv = Some(XeBuildPatch {
            patch_type: XeBuildPatchType::Khv,
            records: sections.remove(0),
        });
    }

    Ok(output)
}

/// Lowlevel function, apply section of patch binary to target data. Used by apply_xe_patch
fn apply_xe_buffer(patch: XeBuildPatch, data: &mut Vec<u8>) -> anyhow::Result<()> {
    for record in patch.records {
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
            // Use word.to_be_bytes() to ensure Big Endian write
            data[write_pos..write_pos + 4].copy_from_slice(&word.to_be_bytes());
        }
    }
    Ok(())
}

// Create or insert CDXell patch
fn apply_cdxell(nand: &mut NandSkeleton, patch: XeBuildPatch) -> anyhow::Result<()> {
    let mut patch_data = Vec::new();
    for record in patch.records {
        patch_data.extend_from_slice(&record.address.to_be_bytes());
        patch_data.extend_from_slice(&record.amount.to_be_bytes());
        for &word in &record.data {
            patch_data.extend_from_slice(&word.to_be_bytes());
        }
    }
    // Add EOF marker
    patch_data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);

    if let Some(ref mut patches) = nand.options.patches {
        patches.xebuild = Some(patch_data);
    } else {
        nand.options.patches = Some(NandPatches {
            rglp: None,
            xebuild: Some(patch_data),
        });
    }
    Ok(())
}


/// Wrapper function, apply XeBuildPatch to NandSkeleton
pub fn apply_xe_patch(patch: XeBuildBinary, nand: &mut NandSkeleton) -> anyhow::Result<()> {
    if (patch.xetype == XeBuildBinaryType::Jtag) {
        anyhow::bail!("JTAG not implemented :( sorry")
    }
    if (patch.xetype == XeBuildBinaryType::Rgh) {
        // TODO: Add name matching for image and motherboard type

        if (nand.options.build_type == BuildType::Retail) {
            anyhow::bail!("Patching a retail image would break the security chain!");
            // TODO: Add dialog / arg to ask if they want to continue anyway
        }

        // Apply CD patches
        if let Some(cd_patch) = patch.cd {
            if let Some(ref mut cd) = nand.bootloaders.cd {
                apply_xe_buffer(cd_patch, &mut cd.data)?;
            }
        }

        // Apply CB/CB_B patches depending on NandSkeleton image type
        if nand.options.image_type == ImageType::Split {
            if let Some(cb_b_patch) = patch.cb_b {
                if let Some(ref mut cb_b) = nand.bootloaders.cb_b {
                    apply_xe_buffer(cb_b_patch, &mut cb_b.data)?;
                }
            }
        }
        if nand.options.image_type == ImageType::Single {
            if let Some(cb_patch) = patch.cb {
                if let Some(ref mut cb) = nand.bootloaders.cb {
                    apply_xe_buffer(cb_patch, &mut cb.data)?;
                }
            }
        }

        // Insert KHV patches
        if let Some(khv_patch) = patch.khv {
            apply_cdxell(nand, khv_patch)?;
        }
    }
    Ok(())
}
