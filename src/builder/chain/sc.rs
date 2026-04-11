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

use zerocopy::{FromBytes, IntoBytes};
use super::BootloaderHeader;
use crate::builder::deps::excrypt::{self, Rc4, ExCryptRsa};

#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, Clone, Copy)]
#[repr(C)]
pub struct BootloaderScHeader {
    pub header: BootloaderHeader,
    pub signature: [u8; 0x100], // matching EXCRYPT_SIG size
}

#[derive(Clone)]
pub struct BootloaderSc {
    pub header: BootloaderScHeader,
    pub data: Vec<u8>,
}

impl BootloaderSc {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let (header, payload) = BootloaderScHeader::read_from_prefix(data)
            .map_err(|_| "Failed to parse SC header")?;
        Ok(Self {
            header: header.clone(),
            data: payload.to_vec(),
        })
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        // Signature is excluded from the hash
        if let Ok(hash) = excrypt::rot_sum_sha(
            &IntoBytes::as_bytes(&self.header.header)[..0x10],
            &self.data[..(size_aligned as usize - std::mem::size_of::<BootloaderScHeader>())],
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn verify_signature(&self, salt: &[u8], pubkey: &ExCryptRsa) -> bool {
        let mut bl_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut bl_hash);

        excrypt::verify_signature(&self.header.signature, &bl_hash, salt, pubkey).unwrap_or(false)
    }

    pub fn decrypt(&mut self, dec_key: &[u8; 16]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = size_aligned as usize - std::mem::size_of::<BootloaderScHeader>();

        if let Ok(derived_key) = excrypt::hmac_sha(dec_key, &[&self.header.header.salt]) {
            let mut decrypt_key = [0u8; 16];
            decrypt_key.copy_from_slice(&derived_key[..16]);
            
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                let _ = rc4.crypt(&mut self.data[..payload_size]);
            }
        }
    }

    /// Decrypts a stock devkit/devgl SC stage using the standard Zero-Key.
    pub fn decrypt_stock(&mut self) {
        let zero_key = [0u8; 16];
        self.decrypt(&zero_key);
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}