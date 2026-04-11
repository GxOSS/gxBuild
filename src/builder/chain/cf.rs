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

use zerocopy::{FromBytes, IntoBytes};
use zerocopy::byteorder::{U16, U32, BigEndian};
use super::BootloaderHeader;
use crate::builder::deps::excrypt::{self, Rc4, ExCryptRsa};

#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, Clone, Copy)]
#[repr(C)]
pub struct BootloaderCfHeader {
    pub header: BootloaderHeader,
    pub base_ver: U16<BigEndian>,
    pub base_flags: U16<BigEndian>,
    pub target_ver: U16<BigEndian>,
    pub target_flags: U16<BigEndian>,
    pub unknown: U32<BigEndian>,
    pub cg_size: U32<BigEndian>,
    pub pairing: [u8; 0x200],
    pub signature: [u8; 0x100], // EXCRYPT_SIG
    pub cg_hmac: [u8; 0x10],
    pub cg_hash: [u8; 0x14],
}

#[derive(Clone)]
pub struct BootloaderCf {
    pub header: BootloaderCfHeader,
    pub data: Vec<u8>,
}

impl BootloaderCf {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let (header, payload) = BootloaderCfHeader::read_from_prefix(data)
            .map_err(|_| "Failed to parse CF header")?;
        Ok(Self {
            header: header.clone(),
            data: payload.to_vec(),
        })
    }

    pub fn is_decrypted(&self) -> bool {
        self.header.pairing[0] == 0x00
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        if let Ok(hash) = excrypt::rot_sum_sha(
            &IntoBytes::as_bytes(&self.header.header)[..0x10],
            unsafe { std::slice::from_raw_parts(self.header.cg_hmac.as_ptr(), (size_aligned - 0x320) as usize) },
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn verify_signature(&self, rsa_1bl: &ExCryptRsa) -> bool {
        let mut cf_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut cf_hash);

        let expected_salt = b"XBOX_ROM_6\0";
        excrypt::verify_signature(&self.header.signature, &cf_hash, expected_salt, rsa_1bl).unwrap_or(false)
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

    pub fn decrypt(&mut self, onebl_key: &[u8; 16]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = (size_aligned - 0x20) as usize; // Adjusted for new header structure

        if let Ok(derived_key) = excrypt::hmac_sha(onebl_key, &[&self.header.header.salt]) {
            let mut final_key = [0u8; 16];
            final_key.copy_from_slice(&derived_key[..16]);

            if let Ok(mut rc4) = Rc4::new(&final_key) {
                let _ = rc4.crypt(&mut self.header.pairing[..payload_size]);
            }
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}
