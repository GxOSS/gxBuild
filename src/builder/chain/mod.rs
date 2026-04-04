pub mod cb;
pub mod cd;
pub mod ce;
pub mod cf;
pub mod cg;

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
        unsafe {
            ExCryptRotSumSha(
                &self.header as *const _ as *const u8,
                0x10, // hash header key independently
                self.data.as_ptr(),
                size_aligned - std::mem::size_of::<BootloaderGenericHeader>() as u32,
                sha_out.as_mut_ptr(),
                0x14,
            );
        }
    }

    pub fn verify_signature(&self, salt: &[u8], pubkey: &ExCryptRsa) -> bool {
        let mut bl_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut bl_hash);

        let signature_ptr = self.header.signature.as_ptr() as *const ExCryptSig;

        let result = unsafe {
            ExCryptBnQwBeSigVerify(
                signature_ptr,
                bl_hash.as_ptr(),
                salt.as_ptr(),
                pubkey,
            )
        };

        result == 1
    }

    pub fn decrypt(&mut self, dec_key: &[u8; 0x10]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        let mut rc4 = ExCryptRc4State {
            s: [0; 256],
            i: 0,
            j: 0,
        };

        unsafe {
            ExCryptHmacSha(
                dec_key.as_ptr(),
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

            ExCryptRc4Key(&mut rc4, self.header.key.as_ptr(), 0x10);

            let encrypted_payload_ptr = self.data.as_mut_ptr();
            ExCryptRc4Ecb(
                &mut rc4,
                encrypted_payload_ptr,
                size_aligned - std::mem::size_of::<BootloaderGenericHeader>() as u32,
            );
        }
    }
}

pub struct Keyvault {
    pub data: Vec<u8>,
}

impl Keyvault {
    pub fn calculate_rotsum(&self, sha_out: &mut [u8; 0x14]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        // Size minus the Generic Header is the hashable payload
        unsafe {
            ExCryptRotSumSha(
                &self.header as *const _ as *const u8,
                0x10, // hash header key independently
                self.data.as_ptr(),
                size_aligned - std::mem::size_of::<BootloaderGenericHeader>() as u32,
                sha_out.as_mut_ptr(),
                0x14,
            );
        }
    }

    pub fn verify_signature(&self, salt: &[u8], pubkey: &ExCryptRsa) -> bool {
        let mut bl_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut bl_hash);

        let signature_ptr = self.header.signature.as_ptr() as *const ExCryptSig;

        let result = unsafe {
            ExCryptBnQwBeSigVerify(
                signature_ptr,
                bl_hash.as_ptr(),
                salt.as_ptr(),
                pubkey,
            )
        };

        result == 1
    }

    pub fn decrypt(&mut self, dec_key: &[u8; 0x10]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;

        let mut rc4 = ExCryptRc4State {
            s: [0; 256],
            i: 0,
            j: 0,
        };

        unsafe {
            ExCryptHmacSha(
                dec_key.as_ptr(),
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

            ExCryptRc4Key(&mut rc4, self.header.key.as_ptr(), 0x10);

            let encrypted_payload_ptr = self.data.as_mut_ptr();
            ExCryptRc4Ecb(
                &mut rc4,
                encrypted_payload_ptr,
                size_aligned - std::mem::size_of::<BootloaderGenericHeader>() as u32,
            );
        }
    }
}

pub fn decrypt_chain(nand: &NandSkeleton, cpukey: String) {
    
}

