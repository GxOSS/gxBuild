/*
    cf.rs - Handling for Xbox 360 CF/6BL bootloader stages.
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
use crate::builder::deps::crypto::{
    ExCryptBnQwBeSigVerify, ExCryptHmacSha, ExCryptRc4Ecb, ExCryptRc4Key, ExCryptRc4State,
    ExCryptRotSumSha, ExCryptRsa, ExCryptSig,
};

#[derive(FromBytes)]
#[repr(C)]
pub struct BootloaderCfHeader {
    pub header: BootloaderHeader,
    pub base_ver: u16<big_endian>,
    pub base_flags: u16<big_endian>,
    pub target_ver: u16<big_endian>,
    pub target_flags: u16<big_endian>,
    pub unknown: u32<big_endian>,
    pub cg_size: u32<big_endian>,
    pub key: [u8; 0x10],
    pub pairing: [u8; 0x200],
    pub signature: [u8; 0x100], // EXCRYPT_SIG
    pub cg_hmac: [u8; 0x10],
    pub cg_hash: [u8; 0x14],
}

pub struct BootloaderCf {
    pub header: BootloaderCfHeader,
    pub data: Vec<u8>,
}

impl BootloaderCf {
    pub fn is_decrypted(&self) -> bool {
        self.header.pairing[0] == 0x00
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        unsafe {
            ExCryptRotSumSha(
                &self.header as *const _ as *const u8,
                0x20, // 0x20 for CF
                self.header.cg_hmac.as_ptr(),
                size_aligned - 0x330,
                sha_out.as_mut_ptr(),
                0x14,
            );
        }
    }

    pub fn verify_signature(&self, rsa_1bl: &ExCryptRsa) -> bool {
        let mut cf_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut cf_hash);

        let signature_ptr = self.header.signature.as_ptr() as *const ExCryptSig;
        let expected_salt = b"XBOX_ROM_6\0";

        let result = unsafe {
            ExCryptBnQwBeSigVerify(
                signature_ptr,
                cf_hash.as_ptr(),
                expected_salt.as_ptr(),
                rsa_1bl,
            )
        };

        result == 1
    }

    pub fn print_info(&self) {
        let indicator = if (self.header.header.magic.get() & 0xF000) == 0x5000 {
            "SF"
        } else {
            "CF"
        };
        println!("{} version: {}", indicator, self.header.header.version.get());
        println!("{} size: 0x{:x}", indicator, self.header.header.size.get());
        println!("{} entrypoint: 0x{:x}", indicator, self.header.header.entrypoint.get());
        println!("{} base version: {}", indicator, self.header.base_ver.get());
        println!("{} target version: {}", indicator, self.header.target_ver.get());
        println!("{}-G size: 0x{:x}", indicator, self.header.cg_size.get());

        if self.is_decrypted() {
            println!("{}-G key: {:02x?}", indicator, self.header.cg_hmac);
            println!("{}-G checksum: {:02x?}", indicator, self.header.cg_hash);
            println!("{} signature: (requires keys to verify)", indicator);
        } else {
            println!("{} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, onebl_key: &[u8; 0x10]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        let mut cf_key = [0u8; 0x10];
        let mut rc4 = ExCryptRc4State {
            s: [0; 256],
            i: 0,
            j: 0,
        };

        unsafe {
            ExCryptHmacSha(
                onebl_key.as_ptr(),
                0x10,
                self.header.key.as_ptr(),
                0x10,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                cf_key.as_mut_ptr(),
                0x10,
            );

            ExCryptRc4Key(&mut rc4, cf_key.as_ptr(), 0x10);

            let encrypted_payload_ptr = self.header.pairing.as_mut_ptr();
            ExCryptRc4Ecb(&mut rc4, encrypted_payload_ptr, size_aligned - 0x30);
        }
    }
}
