pub mod cb;
pub mod sc;
pub mod cd;
pub mod ce;
pub mod cf;
pub mod cg;
pub mod smc;
pub mod xell;

use zerocopy::{FromBytes, AsBytes, byteorder::big_endian};
use crate::builder::deps::excrypt::{self, Rc4, ExCryptRsa, ExCryptSig};
use crate::builder::builder::NandSkeleton;

#[derive(FromBytes, AsBytes, Clone, Copy)]
#[repr(C)]
pub struct BootloaderHeader {
    pub magic: u16<big_endian>,
    pub version: u16<big_endian>,
    pub pairing: u16<big_endian>,
    pub flags: u16<big_endian>,
    pub entrypoint: u32<big_endian>,
    pub size: u32<big_endian>,
}

impl BootloaderHeader {
    pub fn get_type(&self) -> XenonBlType {
        let magic = self.magic.get();
        match magic & 0xFFF {
            0x341 => XenonBlType::OneBL,
            0x342 => XenonBlType::CB,
            0x343 => XenonBlType::SC,
            0x344 => XenonBlType::CD,
            0x345 => XenonBlType::CE,
            0x346 => XenonBlType::CF,
            0x347 => XenonBlType::CG,
            0xD4D => XenonBlType::XKE,
            0xE4E => XenonBlType::HV,
            _ => {
                if magic == 0xEC4C {
                    XenonBlType::BLUPD
                } else {
                    XenonBlType::INVALID
                }
            }
        }
    }

    pub fn is_devkit(&self) -> bool {
        (self.magic.get() & 0x1000) == 0x1000
    }
}

#[derive(Debug, PartialEq)]
#[repr(u32)]
pub enum XenonBlType {
    OneBL = 0,
    CB = 1,
    SC = 2,
    CD = 3,
    CE = 4,
    CF = 5,
    CG = 6,
    HV = 0x10,
    XKE = 0x11,
    BLUPD = 0x12,
    INVALID = 0xFFFFFFFF,
}

#[derive(FromBytes)]
#[repr(C)]
pub struct BootloaderGenericHeader {
    pub header: BootloaderHeader,
    pub key: [u8; 0x10],
    pub signature: [u8; 0x100], // matching EXCRYPT_SIG size
}

pub struct BootloaderGeneric {
    pub header: BootloaderGenericHeader,
    pub data: Vec<u8>,
}

impl BootloaderGeneric {
    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        // Size minus the Generic Header is the hashable payload
        if let Ok(hash) = excrypt::rot_sum_sha(
            unsafe { std::slice::from_raw_parts(&self.header as *const _ as *const u8, 0x10) },
            &self.data[..(size_aligned as usize - std::mem::size_of::<BootloaderGenericHeader>())],
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn verify_signature(&self, salt: &[u8], pubkey: &ExCryptRsa) -> bool {
        let mut bl_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut bl_hash);

        excrypt::verify_signature(&self.header.signature, &bl_hash, salt, pubkey).unwrap_or(false)
    }

    pub fn decrypt(&mut self, dec_key: &[u8; 0x10]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = size_aligned as usize - std::mem::size_of::<BootloaderGenericHeader>();

        // High-level HMAC-SHA and RC4
        if let Ok(derived_key) = excrypt::hmac_sha(dec_key, &[&self.header.key]) {
            self.header.key.copy_from_slice(&derived_key[..0x10]);
            
            if let Ok(mut rc4) = Rc4::new(&self.header.key) {
                let _ = rc4.crypt(&mut self.data[..payload_size]);
            }
        }
    }
}

// Removed broken Keyvault implementation - should be moved to separate logic in keys.rs if needed

pub enum XellType {
    Xell1f = 0,
    Xell2f = 1,
    XellGg = 2,
    XellUnknown = 3,
}

impl XellType {
    pub fn from_hash(hash: &[u8; 0x14]) -> Self {
        
    }
}


pub struct Xell {
    pub data: Vec<u8>,
    pub xell_type: XellType,
}

impl Xell {
    pub fn new(data: Vec<u8>) -> Self {
        let xell_type = XellType::from_hash(&data);
        Self {
            data,
            xell_type,
        }
    }

    /// crc32 hash xeLL
    pub fn get_hash(&self) -> [u8; 0x14] {
        
    }

    /// identify xell with crc32
    pub fn identify(&self) -> XellType {
        
    }
}

pub fn decrypt_chain(nand: &NandSkeleton, cpukey: String) {
    
}

