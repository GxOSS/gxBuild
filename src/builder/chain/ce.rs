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

use super::BootloaderHeader;
use crate::builder::deps::excrypt::{self, Rc4};
use crate::builder::deps::xenia;
use crate::builder::chain::cf::BootloaderCf;
use crate::builder::chain::cg::BootloaderCg;
use zerocopy::{FromBytes, IntoBytes};
use log::info;
use zerocopy::byteorder::{U16, U32, U64, BigEndian};
use byteorder::{BigEndian as RealBigEndian, ByteOrder};

#[derive(Clone, Debug)]
pub struct CeMetadata {
    pub target_address: u64,
    pub uncompressed_size: u32,
}

#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, Clone, Copy)]
#[repr(C)]
pub struct BootloaderCeHeader {
    pub header: BootloaderHeader,
    pub target_address: U64<BigEndian>,
    pub uncompressed_size: U32<BigEndian>,
    pub unknown: U32<BigEndian>,
}

#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, Clone, Copy, Debug)]
#[repr(C)]
struct BootloaderCompressionBlock {
    pub compressed_size: U16<BigEndian>,
    pub decompressed_size: U16<BigEndian>,
}

#[derive(Clone)]
pub struct BootloaderCe {
    pub header: BootloaderHeader,
    pub data: Vec<u8>,
    pub metadata: Option<CeMetadata>,
    pub data_ce: Option<Vec<u8>>,
    pub data_kernel: Option<Vec<u8>>,
    pub data_hv: Option<Vec<u8>>,
}

impl BootloaderCe {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let (header, payload) = BootloaderHeader::read_from_prefix(data)
            .map_err(|_| "Failed to parse CE header")?;
            
        let mut data_vec = payload.to_vec();
        let expected_payload_size = ((header.size.get() as usize + 0xF) & 0xFFFFFFF0) - 0x10;
        if data_vec.len() < expected_payload_size {
            data_vec.resize(expected_payload_size, 0);
        }
            
        Ok(Self {
            header: header.clone(),
            data: data_vec,
            metadata: None,
            data_ce: None,
            data_kernel: None,
            data_hv: None,
        })
    }

    pub fn populate_metadata(&mut self) {
        if !self.is_decrypted() || self.data.len() < 0x20 { return; }

        let target_address = RealBigEndian::read_u64(&self.data[0x10..0x18]);
        let uncompressed_size = RealBigEndian::read_u32(&self.data[0x18..0x1C]);

        self.metadata = Some(CeMetadata {
            target_address,
            uncompressed_size,
        });
    }

    pub fn sync_metadata(&mut self) {
        if !self.is_decrypted() || self.data.len() < 0x20 { return; }
        if let Some(meta) = &self.metadata {
            RealBigEndian::write_u64(&mut self.data[0x10..0x18], meta.target_address);
            RealBigEndian::write_u32(&mut self.data[0x18..0x1C], meta.uncompressed_size);
        }
    }

    pub fn is_decrypted(&self) -> bool {
        if self.data.len() < 0x20 { return false; }
        // `unknown` field is at relative 0x1C (absolute 0x2C); zero in all decrypted retail CEs.
        // Matches xenon-bltool ce_is_decrypted().
        &self.data[0x1C..0x20] == &[0, 0, 0, 0]
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_len = (size_aligned - 0x10) as usize; // data after header

        if self.data.len() < payload_len { return; }

        if let Ok(hash) = excrypt::rot_sum_sha(
            &IntoBytes::as_bytes(&self.header)[..0x10],
            &self.data[0x10..payload_len], // Skip key, start at target_address (0x10 rel)
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn print_info(&self) {
        let indicator = if (self.header.magic.get() & 0xF000) == 0x5000 {
            "SE"
        } else {
            "CE"
        };
        info!("[builder] {} version: {}", indicator, self.header.version.get());
        info!("[builder] {} size: 0x{:x}", indicator, self.header.size.get());

        if self.is_decrypted() {
            // Decrypted fields: target_address at 0x10, uncompressed_size at 0x18 (rel payload)
            let target_address = RealBigEndian::read_u64(&self.data[0x10..0x18]);
            let uncompressed_size = RealBigEndian::read_u32(&self.data[0x18..0x1C]);

            info!(
                "[builder] {} decompressed size: 0x{:x}",
                indicator,
                uncompressed_size
            );
            info!(
                "[builder] {} load address: 0x{:x}",
                indicator,
                target_address
            );
        } else {
            info!("[builder] {} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, cd_key: &[u8; 16]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = (size_aligned - 0x10) as usize;

        if self.data.len() < payload_size { return; }

        if let Ok(derived_key) = excrypt::hmac_sha(cd_key, &[&self.data[0..16]]) {
            let mut final_key = [0u8; 16];
            final_key.copy_from_slice(&derived_key[..16]);
            info!("[builder] CE Decryption Key Derived: {:02x?}", final_key);

            if let Ok(mut rc4) = Rc4::new(&final_key) {
                // Encryption starts at target_address, which is 0x10 rel into payload (absolute 0x20)
                let _ = rc4.crypt(&mut self.data[0x10..payload_size]);
            }
        }
        
        // After decryption, the payload after the CE header metadata is the LZX compressed buffer
        // Metadata in CE payload after the key: target_address(8), uncompressed_size(4), unknown(4) = 16 bytes (0x10)
        // Total plain/metadata before compressed data: 0x20 (key + target info)
        if self.data.len() >= 0x20 {
            self.data_ce = Some(self.data[0x20..payload_size].to_vec());
        }

        self.populate_metadata();
    }

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
        let _size = self.header.size.get();
        if self.data.len() < 0x1C { return Err("Payload too small to read decompression size".to_string()); }
        let uncompressed_size = RealBigEndian::read_u32(&self.data[0x18..0x1C]);

        let data = self.data_ce.as_ref().ok_or("No CE data available")?;

        let consolidated_compressed = self
            .get_full_compressed_buffer(data, uncompressed_size)
            .map_err(|e| format!("Decompression structuring failed: {}", e))?;

        let mut decompressed = vec![0u8; uncompressed_size as usize];
        info!("[builder] Decompressing CE Kernel (LZX)...");
        xenia::decompress(
            &consolidated_compressed,
            &mut decompressed,
            0x20000,
            None,
        ).map_err(|e| format!("lzx_decompress returned error code {}", e))?;

        Ok(decompressed)
    }

    pub fn apply_update(&mut self, cf: &BootloaderCf, cg: &BootloaderCg) -> Result<(), String> {
        let cf_meta = cf.metadata.as_ref().ok_or("CF metadata missing")?;
        if cf_meta.source_version != self.header.version.get() {
            return Err(format!(
                "Mismatching base kernel version (CE is {}, CF expects {})",
                self.header.version.get(),
                cf_meta.source_version
            ));
        }

        info!("[builder] Applying CG kernel delta patch to CE base kernel (base v{} -> target patch)...", self.header.version.get());

        let base_kernel = self.data_kernel.as_ref()
            .ok_or("CE Base Kernel has not been decompressed yet. Cannot apply patch.")?;

        let patched_kernel = cg.apply_patch(base_kernel)?;
        
        self.data_kernel = Some(patched_kernel);
        
        Ok(())
    }

    /// Split Decompressed CE into Kernel and Hypervisor
    pub fn split_into_stages(&self) -> Result<(), String> {
        // TODO: Implement
        Ok(())
    }

    pub fn serialize(&self) -> Vec<u8> {
        // Always serialize the raw payload (self.data).
        // data_ce is a transient working buffer populated only after decrypt() - it must
        // not be the serialization source. All other bootloaders (cb, cd, cf, cg) use self.data.
        let mut out = IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
