/*
    parser.rs - Multi file type parser and identifier
    Copyright 2024 Emma https://ipg.gay/
    
    Modified in 2026 by Exposure / Zach for GGX

    This file has been taken from xenon-bltool and modified, and therefore retains the original
    License.

    xenon-bltool is free software: you can redistribute it and/or modify it under the terms of
    the GNU General Public License as published by the Free Software Foundation, version 2 of
    the License.

    xenon-bltool is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with xenon-bltool.
    If not, see <https://www.gnu.org/licenses/>.
*/

use crate::builder::chain::cf::BootloaderCf;
use crate::builder::chain::cg::BootloaderCg;

pub const ONE_BL_KEY: [u8; 16] = [
    0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
    0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA,
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

pub enum PatchType {
    XeBuild = 0,
    Update = 1,
}

pub fn parse_patch(patch_bytes: &[u8]) -> Result<(PatchType, Vec<u8>), String> {
    
}