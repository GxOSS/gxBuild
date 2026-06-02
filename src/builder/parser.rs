use log::info;
use thiserror::Error;
use crate::builder::types::*;
use crate::crypto::{hmac_sha, Rc4};
#[derive(Error, Debug)]
pub enum BuilderError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Filesystem error: {0}")]
    Fs(#[from] crate::builder::filesystem::FsError),

    #[error("Invalid hex string: {0}")]
    InvalidHex(String),

    #[error("Image too small: got {got} bytes, need {need}")]
    ImageTooSmall { got: usize, need: usize },

    #[error("Invalid NAND magic: 0x{magic:04X}")]
    InvalidMagic { magic: u16 },

    #[error(
        "{component} out of bounds: offset 0x{offset:X} + size 0x{size:X} > image 0x{image_len:X}"
    )]
    OutOfBounds {
        component: String,
        offset: usize,
        size: usize,
        image_len: usize,
    },

    #[error("Invalid KV size: 0x{size:X} (expected 0x4000)")]
    InvalidKvSize { size: usize },

    #[error("Offset overflow: {0}")]
    OffsetOverflow(String),

    #[error("Failed to parse NAND header: {0}")]
    HeaderParse(String),

    #[error("Bootloader chain overflow at stage {stage}: {message}")]
    BootloaderOverflow { stage: String, message: String },

    #[error("Bootchain stage {stage} overflow at 0x{offset:X}")]
    BootchainOverflow { stage: String, offset: usize },

    #[error(
        "SMC write out of bounds: offset 0x{offset:X} + size 0x{size:X} > image 0x{image_len:X}"
    )]
    SmcOutOfBounds {
        offset: usize,
        size: usize,
        image_len: usize,
    },

    #[error("Keyvault write out of bounds: offset 0x{offset:X} + size 0x{size:X} > image 0x{image_len:X}")]
    KvOutOfBounds {
        offset: usize,
        size: usize,
        image_len: usize,
    },

    #[error("CF overflow at 0x{offset:X}: need 0x{need:X} bytes")]
    CfOverflow { offset: usize, need: usize },

    #[error("CG overflow at 0x{offset:X}: need 0x{need:X} bytes")]
    CgOverflow { offset: usize, need: usize },

    #[error("KHV patch stream overflow at 0x{offset:X}: need 0x{need:X} bytes")]
    KhvOverflow { offset: usize, need: usize },

    #[error("Patch error: {0}")]
    Patch(String),

    #[error("XeLL offset error: {0}")]
    XellOffset(String),

    #[error("Assembly error: {0}")]
    Assembly(String),

    #[error("Build error: {0}")]
    Build(String),

    #[error("Bootloader error: {0}")]
    Bootloader(String),
}

impl From<String> for BuilderError {
    fn from(s: String) -> Self {
        BuilderError::Build(s)
    }
}

impl From<&str> for BuilderError {
    fn from(s: &str) -> Self {
        BuilderError::Build(s.to_string())
    }
}

impl From<BuilderError> for String {
    fn from(e: BuilderError) -> Self {
        e.to_string()
    }
}

pub type Result<T> = std::result::Result<T, BuilderError>;

pub struct BlDiscovery {
    pub magic: String,
    pub version: u16,
    pub size: u32,
    pub key_source: String,
}

pub fn bl_is_valid_magic(magic: u16) -> bool {
    matches!(
        magic & 0xFFF,
        0x342 | 0x343 | 0x344 | 0x345 | 0x346 | 0x347 | 0x341
    )
}

pub fn bl_magic_to_str(magic: u16) -> String {
    match magic {
        0x4342 | 0x5342 => "CB",
        0x4343 | 0x5343 => "SC",
        0x4344 | 0x5344 => "CD",
        0x4345 | 0x5345 => "CE",
        0x4346 | 0x5346 => "CF",
        0x4347 | 0x5347 => "CG",
        0x0341 => "1BL",
        _ => "??",
    }
    .to_string()
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(BuilderError::InvalidHex(format!(
            "odd length ({}): '{}'",
            hex.len(),
            hex
        )));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| BuilderError::InvalidHex(format!("byte '{}': {}", &hex[i..i + 2], e)))
        })
        .collect()
}

pub fn bl_try_identify(data: &[u8], parent_key: &[u8; 16]) -> Option<BlDiscovery> {
    if data.len() < 0x10 {
        return None;
    }

    let magic_val = u16::from_be_bytes([data[0], data[1]]);
    let version = u16::from_be_bytes([data[2], data[3]]);
    let size = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

    if bl_is_valid_magic(magic_val) && version >= 1888 && version < 20000 && size < 0x2000000 {
        return Some(BlDiscovery {
            magic: bl_magic_to_str(magic_val),
            version,
            size,
            key_source: "Plain".to_string(),
        });
    }

    let devkit_key = [0u8; 16];
    let key_sources: [(&str, &[u8; 16]); 3] = [
        ("Retail", &NAND_RETAIL_1BL_KEY),
        ("Devkit", &devkit_key),
        ("Chain", parent_key),
    ];

    for (key_name, key_base) in key_sources {
        if key_name == "Chain" && key_base.iter().all(|&x| x == 0) {
            continue;
        }
        for &salt_off in &[0x10usize, 0x20usize] {
            if data.len() < salt_off + 0x10 {
                continue;
            }
            let dk = match hmac_sha(key_base, &[&data[salt_off..salt_off + 0x10]]) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let mut block = data[0..0x10].to_vec();
            if let Ok(mut rc4) = Rc4::new(&dk[..0x10]) {
                let _ = rc4.crypt(&mut block);
            } else {
                continue;
            }

            let dm = u16::from_be_bytes([block[0], block[1]]);
            let dv = u16::from_be_bytes([block[2], block[3]]);
            let ds = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);

            if bl_is_valid_magic(dm) && dv >= 1888 && dv < 20000 && ds < 0x2000000 {
                return Some(BlDiscovery {
                    magic: bl_magic_to_str(dm),
                    version: dv,
                    size: ds,
                    key_source: key_name.to_string(),
                });
            }
        }
    }
    None
}

/// Scans `scan_range` bytes from `start_offset` in 0x10-byte steps for a valid bootloader.
pub fn bl_scan<F>(
    read_fn: &mut F,
    start_offset: usize,
    scan_range: usize,
    parent_key: &[u8; 16],
) -> Option<(usize, BlDiscovery)>
where
    F: FnMut(usize, usize) -> Option<Vec<u8>>,
{
    for offset in (start_offset..start_offset + scan_range).step_by(0x10) {
        let buf = read_fn(offset, 0x100)?;
        if let Some(r) = bl_try_identify(&buf, parent_key) {
            info!(
                "[builder] bl_scan: found {} v{} at 0x{:08X} via {} key",
                r.magic, r.version, offset, r.key_source
            );
            return Some((offset, r));
        }
    }
    None
}


