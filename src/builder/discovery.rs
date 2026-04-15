/*
    discovery.rs - Bootloader discovery engine using try_id pattern.

    Based on proven successful patterns from scratch iterations (V25, V43, V46).
    By Exposure / Zach for the public domain.
*/


// This file is sort of a file of workarounds, proven ways from research to identify bootloaders
// in an image or from a raw NAND dump.

use crate::builder::deps::excrypt::{self, Rc4};
use log::{debug, info};

pub const RETAIL_1BL_KEY: [u8; 16] = [
    0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
    0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA,
];

pub const DEVKIT_1BL_KEY: [u8; 16] = [0u8; 16];


#[derive(Debug, Clone)]
pub struct BootloaderDiscoveryResult {
    pub magic: String, // phonic name
    pub version: u16,
    pub size: u32,
    pub key_source: String, // ("Plain", "Retail", "Devkit", "Chain")
    pub derived_key: [u8; 16], // Derived RC4 key
    pub salt_offset: usize, // (0x10 or 0x20), indicates where HMAC-SHA salt is located
    pub was_encrypted: bool,
}

/// Identifies a bootloader at the given buffer by checking magic bytes and
/// attempting HMAC-SHA + RC4 decryption with known keys.
pub fn try_identify_bootloader(
    data: &[u8],
    parent_key: &[u8; 16],
) -> Option<BootloaderDiscoveryResult> {
    if data.len() < 0x10 {
        return None;
    }

    let magic_val = u16::from_be_bytes([data[0], data[1]]);
    let version = u16::from_be_bytes([data[2], data[3]]);
    let size = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

    if is_valid_bootloader_magic(magic_val)
        && version >= 1888
        && version < 20000
        && size < 0x2000000
    {
        debug!(
            "[discovery] Bootloader identified (plain/unencrypted): {} v{} ({} bytes)",
            magic_to_string(magic_val), version, size
        );
        return Some(BootloaderDiscoveryResult {
            magic: magic_to_string(magic_val),
            version,
            size,
            key_source: "Plain".to_string(),
            derived_key: [0u8; 16],
            salt_offset: 0,
            was_encrypted: false,
        });
    }

    let key_sources: [(&str, &[u8; 16]); 3] = [
        ("Retail", &RETAIL_1BL_KEY),
        ("Devkit", &DEVKIT_1BL_KEY),
        ("Chain", parent_key),
    ];

    for (key_name, key_base) in key_sources {
        if key_name == "Chain" && key_base.iter().all(|&x| x == 0) {
            continue;
        }

        for &salt_off in &[0x10, 0x20] {
            if data.len() < salt_off + 0x10 {
                continue;
            }

            let salt = &data[salt_off..salt_off + 0x10];

            let derived_key_result = excrypt::hmac_sha(key_base, &[salt]);
            let derived_key = match derived_key_result {
                Ok(k) => k,
                Err(_) => continue,
            };

            let mut test_block = data[0..0x10].to_vec();
            if let Ok(mut rc4) = Rc4::new(&derived_key[..0x10]) {
                let _ = rc4.crypt(&mut test_block);
            } else {
                continue;
            }

            let decrypted_magic = u16::from_be_bytes([test_block[0], test_block[1]]);
            let decrypted_version = u16::from_be_bytes([test_block[2], test_block[3]]);
            let decrypted_size =
                u32::from_be_bytes([test_block[12], test_block[13], test_block[14], test_block[15]]);

            if is_valid_bootloader_magic(decrypted_magic)
                && decrypted_version >= 1888
                && decrypted_version < 20000
                && decrypted_size < 0x2000000
            {
                let mut res_key = [0u8; 16];
                res_key.copy_from_slice(&derived_key[..0x10]);

                debug!(
                    "[discovery] Bootloader identified: {} v{} ({} bytes) at salt offset 0x{:02X} via {} key",
                    magic_to_string(decrypted_magic),
                    decrypted_version,
                    decrypted_size,
                    salt_off,
                    key_name
                );

                return Some(BootloaderDiscoveryResult {
                    magic: magic_to_string(decrypted_magic),
                    version: decrypted_version,
                    size: decrypted_size,
                    key_source: key_name.to_string(),
                    derived_key: res_key,
                    salt_offset: salt_off,
                    was_encrypted: true,
                });
            }
        }
    }

    None
}

/// Checks if a 16-bit value is a valid Xbox 360 bootloader magic.
fn is_valid_bootloader_magic(magic: u16) -> bool {
    matches!(
        magic & 0xFFF,
        0x342 | 0x343 | 0x344 | 0x345 | 0x346 | 0x347 | 0x341
    )
}

/// Converts a magic value to a human-readable bootloader type string.
fn magic_to_string(magic: u16) -> String {
    match magic {
        0x4342 | 0x5342 => "CB".to_string(),
        0x4343 | 0x5343 => "SC".to_string(),
        0x4344 | 0x5344 => "CD".to_string(),
        0x4345 | 0x5345 => "CE".to_string(),
        0x4346 | 0x5346 => "CF".to_string(),
        0x4347 | 0x5347 => "CG".to_string(),
        0x0341 => "1BL".to_string(),
        _ => "??".to_string(),
    }
}

/// Scans a range of logical offsets for bootloaders, handling big-block
/// 128KB sync-gap boundaries. This matches the proven V25 pattern that
/// successfully discovered CF at 0x80000 in big-block images.
///
/// # Arguments
/// * `read_fn` - Function that reads `len` bytes from a logical offset
/// * `start_offset` - Starting logical offset to scan from
/// * `scan_range` - Maximum range to scan (typically 0x20000 for 128KB)
/// * `parent_key` - Derived key from previous bootloader stage
///
/// # Returns
/// * `Some((logical_offset, result))` if a bootloader is found
/// * `None` if no bootloader found in range
pub fn scan_for_bootloader<F>(
    read_fn: &mut F,
    start_offset: usize,
    scan_range: usize,
    parent_key: &[u8; 16],
) -> Option<(usize, BootloaderDiscoveryResult)>
where
    F: FnMut(usize, usize) -> Option<Vec<u8>>,
{
    info!(
        "[discovery] Scanning for bootloader: range 0x{:08X}..0x{:08X} ({} KB)",
        start_offset,
        start_offset + scan_range,
        scan_range / 1024
    );
    // Scan in 0x10-byte steps through the range
    for offset in (start_offset..start_offset + scan_range).step_by(0x10) {
        let buf = read_fn(offset, 0x100)?;
        if let Some(result) = try_identify_bootloader(&buf, parent_key) {
            info!(
                "[discovery] Found {} v{} at logical offset 0x{:08X} (via {} key)",
                result.magic, result.version, offset, result.key_source
            );
            return Some((offset, result));
        }
    }
    info!("[discovery] No bootloader found in scanned range.");
    None
}
