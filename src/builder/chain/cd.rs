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

use zerocopy::{FromBytes, IntoBytes, KnownLayout, Immutable};
use zerocopy::byteorder::{U16, U32, BigEndian};
use super::BootloaderHeader;
use crate::builder::deps::excrypt::{self, Rc4, ExCryptRsa};

#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, Clone, Copy)]
#[repr(C)]
pub struct BootloaderCdHeader {
    pub header: BootloaderHeader,
    pub key: [u8; 0x10],
    pub signature: [u8; 0x100], // EXCRYPT_SIG
    pub idk_yet: [u8; 0x120],
    pub cf_salt: [u8; 10],
    pub unused2: U16<BigEndian>,
    pub ce_hash: [u8; 0x14],
}

#[derive(Clone)]
pub struct BootloaderCd {
    pub header: BootloaderCdHeader,
    pub data: Vec<u8>,
}

impl BootloaderCd {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let (header, payload) = BootloaderCdHeader::read_from_prefix(data)
            .map_err(|_| "Failed to parse CD header")?;
        Ok(Self {
            header: header.clone(),
            data: payload.to_vec(),
        })
    }

    pub fn is_decrypted(&self) -> bool {
        self.header.idk_yet[0] == 0x00
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        if let Ok(hash) = excrypt::rot_sum_sha(
            unsafe { std::slice::from_raw_parts(&self.header as *const _ as *const u8, 0x10) },
            &self.header.idk_yet[..(size_aligned as usize - 0x120)],
        ) {
            sha_out.copy_from_slice(&hash);
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

        // Derived key starts with CBB key
        if let Ok(derived_key) = excrypt::hmac_sha(cbb_key, &[&self.header.key]) {
            self.header.key.copy_from_slice(&derived_key[..0x10]);

            // Optional CPU Key layer (2nd HMAC)
            if let Some(key) = cpu_key {
                if let Ok(derived_key_cpu) = excrypt::hmac_sha(key, &[&self.header.key]) {
                    self.header.key.copy_from_slice(&derived_key_cpu[..0x10]);
                }
            }

            if let Ok(mut rc4) = Rc4::new(&self.header.key) {
                // 0x20 = sizeof(bootloader_header), sizeof(hdr->key)
                let _ = rc4.crypt(&mut self.header.signature[..(size_aligned as usize - 0x20)]);
            }
        }
    }

    pub fn verify_signature_devkit(&self, pubkey: &ExCryptRsa) -> bool {
        let mut cd_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut cd_hash);

        let expected_salt = b"XBOX_ROM_4\0";
        excrypt::verify_signature(&self.header.signature, &cd_hash, expected_salt, pubkey).unwrap_or(false)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = zerocopy::IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
