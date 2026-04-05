/*
    smc.rs - Handling for Xbox 360 SMC.

    Copyright 2024 Emma https://ipg.gay/
    Modified for GGX by Exposure / Zach
    Some code taken from RGH3 by 15432 / Alexey

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
use super::BootloaderHeader;
use crate::builder::deps::excrypt::{self, ExCryptRsa};

#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, Clone, Copy)]
#[repr(C)]
pub struct SmcHeader {
    pub header: BootloaderHeader,
    pub key: [u8; 0x10],
    pub signature: [u8; 0x100], // matching EXCRYPT_SIG size
}

#[derive(Clone)]
pub struct Smc {
    pub header: SmcHeader,
    pub data: Vec<u8>,
}

impl Smc {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let (header, payload) = SmcHeader::read_from_prefix(data)
            .map_err(|_| "Failed to parse SMC header")?;
        Ok(Self {
            header: header.clone(),
            data: payload.to_vec(),
        })
    }

    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        // Signature is excluded from the hash, just like CB/CD
        if let Ok(hash) = excrypt::rot_sum_sha(
            unsafe { std::slice::from_raw_parts(&self.header as *const _ as *const u8, 0x10) },
            &self.data[..(size_aligned as usize - std::mem::size_of::<SmcHeader>())],
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn verify_sig(&self, pubkey: &ExCryptRsa) -> bool {
        let mut bl_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut bl_hash);

        let expected_salt = b"XBOX_ROM_S\0"; // Standard SMC salt
        excrypt::verify_signature(&self.header.signature, &bl_hash, expected_salt, pubkey).unwrap_or(false)
    }

    /// Decrypts the SMC payload using the "SMC Hash" rolling-key cipher in-place.
    pub fn decrypt(&mut self) -> &mut Self {
        let mut key: [u32; 4] = [0x42, 0x75, 0x4E, 0x79]; // "BuNy"
        for i in 0..self.data.len() {
            let ciphertext_byte = self.data[i];
            let mod_val = (ciphertext_byte as u32) * 0xFB;
        
            self.data[i] ^= (key[i & 3] & 0xFF) as u8;
        
            key[(i + 1) & 3] = key[(i + 1) & 3].wrapping_add(mod_val);
            key[(i + 2) & 3] = key[(i + 2) & 3].wrapping_add(mod_val >> 8);
        }
        self
    }

    /// Encrypts the SMC payload using the "SMC Hash" rolling-key cipher in-place.
    pub fn encrypt(&mut self) -> &mut Self {
        let mut key: [u32; 4] = [0x42, 0x75, 0x4E, 0x79]; // "BuNy"
        for i in 0..self.data.len() {
            let ciphertext_byte = self.data[i] ^ (key[i & 3] & 0xFF) as u8;
            let mod_val = (ciphertext_byte as u32) * 0xFB;
        
            self.data[i] = ciphertext_byte;
        
            key[(i + 1) & 3] = key[(i + 1) & 3].wrapping_add(mod_val);
            key[(i + 2) & 3] = key[(i + 2) & 3].wrapping_add(mod_val >> 8);
        }
        self
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = IntoBytes::as_bytes(&self.header).to_vec();
        out.extend_from_slice(&self.data);
        out
    }
}