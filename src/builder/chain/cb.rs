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
use crate::builder::deps::excrypt::{self, Rc4, ExCryptRsa};
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

impl BootloaderCbHeader {
    pub fn new(bytes: &[u8]) -> Self {
    }
}


#[derive(FromBytes)]
#[repr(C)]
pub struct BootloaderCb {
    pub header: BootloaderCbHeader,
    pub data: Vec<u8>,
}

impl BootloaderCb {
    /// Parse
    pub fn new(data: Vec<u8>) -> Self {
        

    pub fn is_decrypted(&self) -> bool {
        self.header.globals[0x110] == 0x80
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        if let Ok(hash) = excrypt::rot_sum_sha(
            unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, 0x10) },
            &self.header.globals[..(size_aligned as usize - 0x140)],
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn verify_signature(&self, rsa_1bl: &ExCryptRsa) -> bool {
        let mut cb_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut cb_hash);

        let expected_salt = b"XBOX_ROM_B\0";
        excrypt::verify_signature(&self.header.signature, &cb_hash, expected_salt, rsa_1bl).unwrap_or(false)
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
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        if let Ok(derived_key) = excrypt::hmac_sha(onebl_key, &[&self.header.key]) {
            self.header.key.copy_from_slice(&derived_key[..0x10]);
            
            if let Ok(mut rc4) = Rc4::new(&self.header.key) {
                let _ = rc4.crypt(&mut self.header.padding_or_args[..(size_aligned as usize - 0x20)]);
            }
        }
    }

    pub fn decrypt_v1(&mut self, cb_a_key: &[u8; 0x10], cpu_key: &[u8; 0x10]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        if let Ok(derived_key) = excrypt::hmac_sha(cb_a_key, &[&self.header.key, cpu_key]) {
            self.header.key.copy_from_slice(&derived_key[..0x10]);
            
            if let Ok(mut rc4) = Rc4::new(&self.header.key) {
                let _ = rc4.crypt(&mut self.header.padding_or_args[..(size_aligned as usize - 0x20)]);
            }
        }
    }

    pub fn decrypt_v2(&mut self, cb_a_hdr: &BootloaderCbHeader, cpu_key: &[u8; 0x10]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        // copy cb_a_hdr's BootloaderHeader and nullify flags
        let mut cb_a_hdr_copy = cb_a_hdr.header;
        cb_a_hdr_copy.flags.set(0);

        if let Ok(derived_key) = excrypt::hmac_sha(
            &cb_a_hdr.key, 
            &[&self.header.key, cpu_key, unsafe { std::slice::from_raw_parts(&cb_a_hdr_copy as *const _ as *const u8, 0x10) }]
        ) {
            self.header.key.copy_from_slice(&derived_key[..0x10]);
            
            if let Ok(mut rc4) = Rc4::new(&self.header.key) {
                let _ = rc4.crypt(&mut self.header.padding_or_args[..(size_aligned as usize - 0x20)]);
            }
        }
    }
}
