/*
    sc.rs - Handling for Xbox 360 SC bootloader stages.
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
use crate::builder::deps::excrypt::{
    ExCryptBnQwBeSigVerify,
    ExCryptHmacSha,
    ExCryptRc4Ecb,
    ExCryptRc4Key,
    ExCryptRc4State,
    ExCryptRotSumSha,
    ExCryptRsa,
    ExCryptSig,
};

#[derive(FromBytes)]
#[repr(C)]
pub struct BootloaderScHeader {
    pub header: BootloaderHeader,
    pub key: [u8; 0x10],
    pub signature: [u8; 0x100], // matching EXCRYPT_SIG size
}

pub struct BootloaderSc {
    pub header: BootloaderScHeader,
    pub data: Vec<u8>,
}

impl BootloaderSc {
    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        // Size minus the Generic Header is the hashable payload
        unsafe {
            ExCryptRotSumSha(
                &self.header as *const _ as *const u8,
                0x10, // hash header key independently
                self.data.as_ptr(),
                size_aligned - std::mem::size_of::<BootloaderGenericHeader>() as u32,
                sha_out.as_mut_ptr(),
                0x14,
            );
        }
    }

    pub fn verify_signature(&self, salt: &[u8], pubkey: &ExCryptRsa) -> bool {
        let mut bl_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut bl_hash);

        let signature_ptr = self.header.signature.as_ptr() as *const ExCryptSig;

        let result = unsafe {
            ExCryptBnQwBeSigVerify(
                signature_ptr,
                bl_hash.as_ptr(),
                salt.as_ptr(),
                pubkey,
            )
        };

        result == 1
    }

    pub fn decrypt(&mut self, dec_key: &[u8; 0x10]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        let mut rc4 = ExCryptRc4State {
            s: [0; 256],
            i: 0,
            j: 0,
        };

        unsafe {
            ExCryptHmacSha(
                dec_key.as_ptr(),
                0x10,
                self.header.key.as_ptr(),
                0x10,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                self.header.key.as_mut_ptr(),
                0x10,
            );

            ExCryptRc4Key(&mut rc4, self.header.key.as_ptr(), 0x10);

            let encrypted_payload_ptr = self.data.as_mut_ptr();
            ExCryptRc4Ecb(
                &mut rc4,
                encrypted_payload_ptr,
                size_aligned - std::mem::size_of::<BootloaderGenericHeader>() as u32,
            );
        }
    }
}