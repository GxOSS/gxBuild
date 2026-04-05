/*
    cg.rs - Handling for Xbox 360 CG/7BL bootloader stages.
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

use zerocopy::{FromBytes, byteorder::big_endian};
use crate::builder::builder::BootloaderHeader;
use crate::builder::deps::excrypt::{self, Rc4};
use crate::builder::deps::compression::{bootloader_delta_block, lzxdelta_apply_patch};

#[derive(FromBytes)]
#[repr(C)]
pub struct BootloaderCgHeader {
    pub header: BootloaderHeader,
    pub key: [u8; 0x10],
    pub original_size: u32<big_endian>,
    pub original_hash: [u8; 0x14],
    pub new_size: u32<big_endian>,
    pub new_hash: [u8; 0x14],
}

pub struct BootloaderCg {
    pub header: BootloaderCgHeader,
    pub data: Vec<u8>,
}

impl BootloaderCg {
    pub fn is_decrypted(&self) -> bool {
        (self.header.original_size.get() & 0xFFF) == 0x000
    }

    pub fn print_info(&self) {
        let indicator = if (self.header.header.magic.get() & 0xF000) == 0x5000 {
            "SG"
        } else {
            "CG"
        };
        println!("{} version: {}", indicator, self.header.header.version.get());
        println!("{} size: 0x{:x}", indicator, self.header.header.size.get());

        if self.is_decrypted() {
            println!(
                "{} base size: 0x{:x}",
                indicator,
                self.header.original_size.get()
            );
            println!("{}-G base hash: {:02x?}", indicator, self.header.original_hash);
            println!(
                "{} target size: 0x{:x}",
                indicator,
                self.header.new_size.get()
            );
            println!("{}-G target hash: {:02x?}", indicator, self.header.new_hash);
        } else {
            println!("{} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, cg_hmac: &[u8; 0x10]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        if let Ok(cg_key) = excrypt::hmac_sha(cg_hmac, &[&self.header.key]) {
            if let Ok(mut rc4) = Rc4::new(&cg_key) {
                let encrypted_payload_slice = unsafe {
                    std::slice::from_raw_parts_mut(
                        &mut self.header.original_size as *mut _ as *mut u8,
                        (size_aligned - 0x20) as usize
                    )
                };
                let _ = rc4.crypt(encrypted_payload_slice);
            }
        }
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        if let Ok(hash) = excrypt::rot_sum_sha(
            unsafe { std::slice::from_raw_parts(&self.header as *const _ as *const u8, 0x10) },
            unsafe { std::slice::from_raw_parts(&self.header.original_size as *const _ as *const u8, (size_aligned - 0x20) as usize) },
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn apply_patch(
        &self,
        base_data: &[u8],
    ) -> Result<Vec<u8>, String> {
        let original_size = self.header.original_size.get() as usize;
        let new_size = self.header.new_size.get() as usize;
        let size_of_compressed = self.header.header.size.get() as usize - std::mem::size_of::<BootloaderCgHeader>();

        if base_data.len() < original_size {
            return Err("Base data provided is smaller than original_size".into());
        }

        if let Ok(base_kernel_hash) = excrypt::sha(&[base_data]) {
            if base_kernel_hash != self.header.original_hash {
                return Err("Base kernel hash did not match expected".into());
            }
        }

        let mut output_buf = vec![0u8; new_size];
        output_buf[..original_size].copy_from_slice(&base_data[..original_size]);
        // The rest is automatically padded with 0 since vec! initializes with 0

        let r = unsafe {
            lzxdelta_apply_patch(
                self.data.as_ptr() as *const bootloader_delta_block,
                size_of_compressed,
                0x8000,
                output_buf.as_mut_ptr(),
            )
        };

        if r != 0 {
            return Err(format!("lzxdelta_apply_patch returned error code {}", r));
        }

        if let Ok(updated_kernel_hash) = excrypt::sha(&[&output_buf]) {
            if updated_kernel_hash != self.header.new_hash {
                return Err("Updated kernel hash did not match expected".into());
            }
        }

        Ok(output_buf)
    }
}
