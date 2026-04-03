/*
    cd.rs - Handling for Xbox 360 CD/4BL bootloader stages.
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
pub struct BootloaderCdHeader {
    pub header: BootloaderHeader,
    pub key: [u8; 0x10],
    pub signature: [u8; 0x100], // EXCRYPT_SIG
    pub idk_yet: [u8; 0x120],
    pub cf_salt: [u8; 10],
    pub unused2: u16<big_endian>,
    pub ce_hash: [u8; 0x14],
}

pub struct BootloaderCd {
    pub header: BootloaderCdHeader,
    pub data: Vec<u8>,
}

impl BootloaderCd {
    pub fn is_decrypted(&self) -> bool {
        self.header.idk_yet[0] == 0x00
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        unsafe {
            ExCryptRotSumSha(
                &self.header as *const _ as *const u8,
                0x10,
                self.header.idk_yet.as_ptr(),
                size_aligned - 0x120,
                sha_out.as_mut_ptr(),
                0x14,
            );
        }
    }

    pub fn print_info(&self) {
        let indicator = if (self.header.header.magic.get() & 0xF000) == 0x5000 {
            "SD"
        } else {
            "CD"
        };
        println!("{} version: {}", indicator, self.header.header.version.get());
        println!("{} size: 0x{:x}", indicator, self.header.header.size.get());
        println!("{} entrypoint: 0x{:x}", indicator, self.header.header.entrypoint.get());
        println!(
            "{} cfsalt: {}",
            indicator,
            String::from_utf8_lossy(&self.header.cf_salt)
        );

        if self.is_decrypted() {
            println!("{}-E hash: {:02x?}", indicator, self.header.ce_hash);
        } else {
            println!("{} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, cbb_key: &[u8; 0x10], cpu_key: Option<&[u8; 0x10]>) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        let mut rc4 = ExCryptRc4State {
            s: [0; 256],
            i: 0,
            j: 0,
        };

        unsafe {
            ExCryptHmacSha(
                cbb_key.as_ptr(),
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

            if let Some(key) = cpu_key {
                ExCryptHmacSha(
                    key.as_ptr(),
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
            }

            ExCryptRc4Key(&mut rc4, self.header.key.as_ptr(), 0x10);

            // 0x20 = sizeof(bootloader_header), sizeof(hdr->key)
            let encrypted_payload_ptr = self.header.signature.as_mut_ptr();
            ExCryptRc4Ecb(&mut rc4, encrypted_payload_ptr, size_aligned - 0x20);
        }
    }

    pub fn verify_signature_devkit(&self, pubkey: &ExCryptRsa) -> bool {
        let mut cd_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut cd_hash);

        let signature_ptr = self.header.signature.as_ptr() as *const ExCryptSig;
        let expected_salt = b"XBOX_ROM_4\0";

        let result = unsafe {
            ExCryptBnQwBeSigVerify(
                signature_ptr,
                cd_hash.as_ptr(),
                expected_salt.as_ptr(),
                pubkey,
            )
        };

        result == 1
    }
}
