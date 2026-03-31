/*
    cb.rs - Handling for Xbox 360 CB/2BL bootloader stages.
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
use crate::lib::excrypt::{
    ExCryptBnQwBeSigVerify, ExCryptHmacSha, ExCryptRc4Ecb, ExCryptRc4Key, ExCryptRc4State,
    ExCryptRotSumSha, ExCryptRsa, ExCryptSig,
};
use zerocopy::FromBytes;

#[derive(FromBytes)]
#[repr(C)]
pub struct BootloaderCbHeader {
    pub header: BootloaderHeader,
    pub key: [u8; 0x10],
    pub padding_or_args: [u8; 32], // 4 * sizeof(uint64_t)
    pub signature: [u8; 0x100],    // EXCRYPT_SIG
    pub globals: [u8; 0x128],
    pub devkit_pubkey: [u8; 0x110], // EXCRYPT_RSAPUB_2048
    pub sc_key: [u8; 0x10],
    pub sc_salt: [u8; 10],
    pub sd_salt: [u8; 10],
    pub cd_cbb_hash: [u8; 0x14],
    pub more_globals: [u8; 0x10],
}

#[derive(FromBytes)]
#[repr(C)]
pub struct BootloaderCb {
    pub header: BootloaderCbHeader,
    pub data: Vec<u8>,
}

impl BootloaderCb {
    pub fn is_decrypted(&self) -> bool {
        self.header.globals[0x110] == 0x80
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        unsafe {
            ExCryptRotSumSha(
                self as *const _ as *const u8,
                0x10,
                self.globals.as_ptr(),
                size_aligned - 0x140,
                sha_out.as_mut_ptr(),
                0x14,
            );
        }
    }

    pub fn verify_signature(&self, rsa_1bl: &ExCryptRsa) -> bool {
        let mut cb_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut cb_hash);

        let signature_ptr = self.signature.as_ptr() as *const ExCryptSig;
        let expected_salt = b"XBOX_ROM_B\0";

        let result = unsafe {
            ExCryptBnQwBeSigVerify(
                signature_ptr,
                cb_hash.as_ptr(),
                expected_salt.as_ptr(),
                rsa_1bl,
            )
        };

        result == 1
    }

    pub fn print_info(&self) {
        let magic = self.header.magic.get();
        let mut indicator = if (magic & 0xF000) == 0x5000 {
            "SB"
        } else {
            "CB"
        };

        if (self.header.flags.get() & 0x800) == 0x800 {
            indicator = "CB_A";
        }

        if self.signature[0] == 0 {
            indicator = "CB_B";
        }

        println!("{} version: {}", indicator, self.header.version.get());
        println!("{} size: 0x{:x}", indicator, self.header.size.get());
        println!(
            "{} entrypoint: 0x{:x}",
            indicator,
            self.header.entrypoint.get()
        );

        if self.is_decrypted() {
            println!("{} LDV: {}", indicator, self.more_globals[1]);
            println!("{} next hash: {:02x?}", indicator, self.cd_cbb_hash);
            if self.signature[0] != 0 {
                println!("{} signature: (requires keys to verify)", indicator);
            }
        } else {
            println!("{} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, onebl_key: &[u8; 0x10]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        let mut rc4 = ExCryptRc4State {
            s: [0; 256],
            i: 0,
            j: 0,
        };

        unsafe {
            ExCryptHmacSha(
                onebl_key.as_ptr(),
                0x10,
                self.key.as_ptr(),
                0x10,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                self.key.as_mut_ptr(),
                0x10,
            );

            ExCryptRc4Key(&mut rc4, self.key.as_ptr(), 0x10);

            let encrypted_payload_ptr = self.padding_or_args.as_mut_ptr();
            ExCryptRc4Ecb(&mut rc4, encrypted_payload_ptr, size_aligned - 0x20);
        }
    }

    pub fn decrypt_v1(&mut self, cb_a_key: &[u8; 0x10], cpu_key: &[u8; 0x10]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        let mut rc4 = ExCryptRc4State {
            s: [0; 256],
            i: 0,
            j: 0,
        };

        unsafe {
            ExCryptHmacSha(
                cb_a_key.as_ptr(),
                0x10,
                self.key.as_ptr(),
                0x10,
                cpu_key.as_ptr(),
                0x10,
                std::ptr::null(),
                0,
                self.key.as_mut_ptr(),
                0x10,
            );

            ExCryptRc4Key(&mut rc4, self.key.as_ptr(), 0x10);

            let encrypted_payload_ptr = self.padding_or_args.as_mut_ptr();
            ExCryptRc4Ecb(&mut rc4, encrypted_payload_ptr, size_aligned - 0x20);
        }
    }

    pub fn decrypt_v2(&mut self, cb_a_hdr: &BootloaderCbHeader, cpu_key: &[u8; 0x10]) {
        let size = self.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        let mut rc4 = ExCryptRc4State {
            s: [0; 256],
            i: 0,
            j: 0,
        };

        unsafe {
            // copy cb_a_hdr's BootloaderHeader and nullify flags
            let mut cb_a_hdr_copy = std::ptr::read(&cb_a_hdr.header);
            cb_a_hdr_copy.flags.set(0);

            ExCryptHmacSha(
                cb_a_hdr.key.as_ptr(),
                0x10,
                self.key.as_ptr(),
                0x10,
                cpu_key.as_ptr(),
                0x10,
                &cb_a_hdr_copy as *const _ as *const u8,
                0x10, // sizeof(bootloader_header) in C is 0x10
                self.key.as_mut_ptr(),
                0x10,
            );

            ExCryptRc4Key(&mut rc4, self.key.as_ptr(), 0x10);

            let encrypted_payload_ptr = self.padding_or_args.as_mut_ptr();
            ExCryptRc4Ecb(&mut rc4, encrypted_payload_ptr, size_aligned - 0x20);
        }
    }
}
