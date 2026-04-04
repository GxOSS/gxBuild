/*
    ce.rs - Handling for Xbox 360 CE/5BL bootloader stages.
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

use crate::builder::builder::BootloaderHeader;
use crate::builder::deps::excrypt::{
    ExCryptHmacSha, ExCryptRc4Ecb, ExCryptRc4Key, ExCryptRc4State, ExCryptRotSumSha,
};
use crate::builder::deps::xenia::compression::{
    Compress, Decompress,
};
use zerocopy::byteorder::big_endian;
use zerocopy::FromBytes;

#[derive(FromBytes)]
#[repr(C)]
pub struct BootloaderCeHeader {
    pub header: BootloaderHeader,
    pub key: [u8; 0x10],
    pub target_address: u64<big_endian>,
    pub uncompressed_size: u32<big_endian>,
    pub unknown: u32<big_endian>,
}

#[derive(FromBytes, Clone, Copy, Debug)]
#[repr(C)]
struct BootloaderCompressionBlock {
    pub compressed_size: u16<big_endian>,
    pub decompressed_size: u16<big_endian>,
}

pub struct BootloaderCe {
    pub header: BootloaderCeHeader,
    pub data: Vec<u8>,
}

impl BootloaderCe {
    pub fn is_decrypted(&self) -> bool {
        self.header.unknown.get() == 0x00000000
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        unsafe {
            ExCryptRotSumSha(
                &self.header as *const _ as *const u8,
                0x10,
                &self.header.target_address as *const _ as *const u8,
                size_aligned - 0x20,
                sha_out.as_mut_ptr(),
                0x14,
            );
        }
    }

    pub fn print_info(&self) {
        let indicator = if (self.header.header.magic.get() & 0xF000) == 0x5000 {
            "SE"
        } else {
            "CE"
        };
        println!("{} version: {}", indicator, self.header.header.version.get());
        println!("{} size: 0x{:x}", indicator, self.header.header.size.get());

        if self.is_decrypted() {
            println!(
                "{} decompressed size: 0x{:x}",
                indicator,
                self.header.uncompressed_size.get()
            );
            println!(
                "{} load address: 0x{:x}",
                indicator,
                self.header.target_address.get()
            );
        } else {
            println!("{} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, cd_key: &[u8; 0x10]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        let mut ce_key = [0u8; 0x10];
        let mut rc4 = ExCryptRc4State {
            s: [0; 256],
            i: 0,
            j: 0,
        };

        unsafe {
            ExCryptHmacSha(
                cd_key.as_ptr(),
                0x10,
                self.header.key.as_ptr(),
                0x10,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                ce_key.as_mut_ptr(),
                0x10,
            );

            ExCryptRc4Key(&mut rc4, ce_key.as_ptr(), 0x10);

            let encrypted_payload_ptr = &mut self.header.target_address as *mut _ as *mut u8;
            ExCryptRc4Ecb(&mut rc4, encrypted_payload_ptr, size_aligned - 0x20);
        }
    }

    /// Native Rust implementation of get_full_compressed_buffer logic
    fn get_full_compressed_buffer(
        &self,
        in_buf: &[u8],
        expected_decompressed_size: u32,
    ) -> Result<Vec<u8>, &'static str> {
        let mut decompressed_size_parsed = 0u32;
        let mut parsed_bytes = 0usize;
        let mut out_buf = Vec::new();

        while decompressed_size_parsed < expected_decompressed_size {
            if in_buf.len() < parsed_bytes + std::mem::size_of::<BootloaderCompressionBlock>() {
                return Err("Buffer underflow reading compression block header");
            }

            let block_ptr =
                &in_buf[parsed_bytes] as *const _ as *const BootloaderCompressionBlock;
            let block = unsafe { std::ptr::read_unaligned(block_ptr) };

            let c_size = block.compressed_size.get() as u32;
            let d_size = block.decompressed_size.get() as u32;

            decompressed_size_parsed += d_size;

            let block_header_size = std::mem::size_of::<BootloaderCompressionBlock>();
            let block_data_start = parsed_bytes + block_header_size;
            let block_data_end = block_data_start + c_size as usize;

            if block_data_end > in_buf.len() {
                return Err("Compressed size extends past input buffer limits");
            }

            // Copy the data segment
            out_buf.extend_from_slice(&in_buf[block_data_start..block_data_end]);

            parsed_bytes = block_data_end;
        }

        if decompressed_size_parsed > expected_decompressed_size {
            return Err("Decompressed size parsed is larger than expected");
        }

        Ok(out_buf)
    }

    pub fn decompress(&self) -> Result<Vec<u8>, String> {
        let size = self.header.header.size.get();
        let _size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let uncompressed_size = self.header.uncompressed_size.get();

        // The data begins immediately following the CE Header Struct.
        // Assuming self.data aligns exactly after the header bounds natively.
        let consolidated_compressed = self
            .get_full_compressed_buffer(&self.data, uncompressed_size)
            .map_err(|e| format!("Decompression structuring failed: {}", e))?;

        let mut decompressed = vec![0u8; uncompressed_size as usize];

        let r = unsafe {
            lzx_decompress(
                consolidated_compressed.as_ptr(),
                consolidated_compressed.len(),
                decompressed.as_mut_ptr(),
                decompressed.len(),
                0x20000,
                std::ptr::null_mut(),
                0,
            )
        };

        if r != 0 {
            return Err(format!("lzx_decompress returned error code {}", r));
        }

        Ok(decompressed)
    }
}
