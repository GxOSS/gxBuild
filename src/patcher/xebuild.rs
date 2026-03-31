use std::fs::File;
use std::io::{self, Read};

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
    let f = File::open(path)?;
    let mut sections = parse_patch_records(f)?;
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
fn apply_xe_buffer(patch: XeBuildPatch, data: &mut Vec<u8>) -> anyhow::Result<Vec<u8>> {
    // To be implemented later
    Ok(data.clone())
}

// /// Wrapper function, apply XeBuildPatch to NandSkeleton
// pub fn apply_xe_patch(patch: XeBuildBinary, nand: NandSkeleton) -> anyhow::Result<NandSkeleton> {
//     // To be implemented later
// }
