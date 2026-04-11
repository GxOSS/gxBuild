/*
    parser.rs - Basic NAND component parsers
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/

use crate::builder::chain::cf::BootloaderCf;
use crate::builder::chain::cg::BootloaderCg;

pub const ONE_BL_KEY: [u8; 16] = [
    0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
    0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0x47,
];

pub fn parse_xboxupd(xboxupd_bytes: &[u8]) -> Result<(BootloaderCf, BootloaderCg), String> {
    // 1. Parse CF
    let mut cf = BootloaderCf::parse(xboxupd_bytes)?;

    if !cf.is_decrypted() {
        cf.decrypt(&ONE_BL_KEY);
    }
    if !cf.is_decrypted() {
        return Err("Failed to decrypt CF header.".to_string());
    }

    let cf_size = cf.header.header.size.get() as usize;

    if xboxupd_bytes.len() < cf_size {
        return Err("xboxupd buffer too small to contain CG payload".to_string());
    }

    // 2. Slice memory exactly from CF endpoint to initialize CG
    let mut cg = BootloaderCg::parse(&xboxupd_bytes[cf_size..])?;

    if !cg.is_decrypted() {
        cg.decrypt(&cf.header.cg_hmac);
    }
    if !cg.is_decrypted() {
        return Err("Failed to decrypt CG header.".to_string());
    }

    // 3. Compare RotSum 
    let mut cg_rotsum = [0u8; 0x14];
    cg.calculate_rotsum(&mut cg_rotsum);

    if cg_rotsum != cf.header.cg_hash {
        return Err("CG checking hash mismatch against CF signature metadata".to_string());
    }

    Ok((cf, cg))
}