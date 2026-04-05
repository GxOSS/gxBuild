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

use super::BootloaderHeader;
use crate::builder::deps::excrypt::{self, Rc4, ExCryptRsa};
use zerocopy::{FromBytes, IntoBytes};

#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, Clone, Copy)]
#[repr(C)]
pub struct BootloaderCbHeader {
    pub header: BootloaderHeader,
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
    pub fn new(_bytes: &[u8]) -> Self {
        todo!()
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct BootloaderCb {
    pub header: BootloaderCbHeader,
    pub data: Vec<u8>,
}

impl BootloaderCb {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let (header, payload) = BootloaderCbHeader::read_from_prefix(data)
            .map_err(|_| "Failed to parse CB header")?;
        Ok(Self {
            header: header.clone(),
            data: payload.to_vec(),
        })
    }

    pub fn is_decrypted(&self) -> bool {
        self.header.globals[0x110] == 0x80
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        if let Ok(hash) = excrypt::rot_sum_sha(
            &IntoBytes::as_bytes(&self.header.header)[..0x10],
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
        let magic = self.header.header.magic.get();
        let mut indicator = if (magic & 0xF000) == 0x5000 {
            "SB"
        } else {
            "CB"
        };

        if (self.header.header.flags.get() & 0x800) == 0x800 {
            indicator = "CB_A";
        }

        if self.header.signature[0] == 0 {
            indicator = "CB_B";
        }

        println!("{} version: {}", indicator, self.header.header.version.get());
        println!("{} size: 0x{:x}", indicator, self.header.header.size.get());
        println!(
            "{} entrypoint: 0x{:x}",
            indicator,
            self.header.header.entrypoint.get()
        );

        if self.is_decrypted() {
            println!("{} LDV: {}", indicator, self.header.more_globals[1]);
            println!("{} next hash: {:02x?}", indicator, self.header.cd_cbb_hash);
            if self.header.signature[0] != 0 {
                println!("{} signature: (requires keys to verify)", indicator);
            }
        } else {
            println!("{} is encrypted", indicator);
        }
    }

    pub fn decrypt(&mut self, onebl_key: &[u8; 16]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        if let Ok(derived_key) = excrypt::hmac_sha(onebl_key, &[&self.header.header.salt]) {
            let mut decrypt_key = [0u8; 16];
            decrypt_key.copy_from_slice(&derived_key[..16]);
            
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                let _ = rc4.crypt(&mut self.header.padding_or_args[..(size_aligned as usize - 0x20)]);
            }
        }
    }

    pub fn decrypt_v1(&mut self, cb_a_key: &[u8; 16], cpu_key: &[u8; 16]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        if let Ok(derived_key) = excrypt::hmac_sha(cb_a_key, &[&self.header.header.salt, cpu_key]) {
            let mut decrypt_key = [0u8; 16];
            decrypt_key.copy_from_slice(&derived_key[..16]);
            
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                let _ = rc4.crypt(&mut self.header.padding_or_args[..(size_aligned as usize - 0x20)]);
            }
        }
    }

    pub fn decrypt_v2(&mut self, cb_a_hdr: &BootloaderCbHeader, cpu_key: &[u8; 16]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        // copy cb_a_hdr's BootloaderHeader and nullify flags
        let mut cb_a_hdr_copy = cb_a_hdr.header;
        cb_a_hdr_copy.flags.set(0);

        if let Ok(derived_key) = excrypt::hmac_sha(
            &cb_a_hdr.header.salt, 
            &[&self.header.header.salt, cpu_key, &IntoBytes::as_bytes(&cb_a_hdr_copy)[..0x10]]
        ) {
            let mut decrypt_key = [0u8; 16];
            decrypt_key.copy_from_slice(&derived_key[..16]);
            
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                let _ = rc4.crypt(&mut self.header.padding_or_args[..(size_aligned as usize - 0x20)]);
            }
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = zerocopy::IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
