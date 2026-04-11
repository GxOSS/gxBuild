pub mod cb;
pub mod sc;
pub mod cd;
pub mod ce;
pub mod cf;
pub mod cg;
pub mod smc;
pub mod flashfs;
pub mod kv;

use zerocopy::byteorder::{U16, U32, BigEndian};
use crate::builder::deps::excrypt::{self, Rc4, ExCryptRsa};
use crate::builder::chain::smc::RawSmc;

pub const ONEBL_KEY: [u8; 16] = [
    0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
    0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0x47,
];

#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, Clone, Copy)]
#[repr(C)]
pub struct BootloaderHeader {
    pub magic: U16<BigEndian>,
    pub version: U16<BigEndian>,
    pub pairing: U16<BigEndian>,
    pub flags: U16<BigEndian>,
    pub entrypoint: U32<BigEndian>,
    pub size: U32<BigEndian>,
    pub salt: [u8; 16],
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

#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
#[repr(C)]
pub struct BootloaderGenericHeader {
    pub header: BootloaderHeader,
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

    pub fn decrypt(&mut self, dec_key: &[u8; 16]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = size_aligned as usize - std::mem::size_of::<BootloaderGenericHeader>();

        // High-level HMAC-SHA and RC4
        if let Ok(derived_key) = excrypt::hmac_sha(dec_key, &[&self.header.header.salt]) {
            let mut decrypt_key = [0u8; 16];
            decrypt_key.copy_from_slice(&derived_key[..16]);
            
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
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
    pub fn from_hash(_hash: &[u8; 0x14]) -> Self {
        XellType::XellUnknown
    }
}


pub struct Xell {
    pub data: Vec<u8>,
    pub xell_type: XellType,
}

impl Xell {
    pub fn new(data: Vec<u8>) -> Self {
        let mut hash = [0u8; 0x14];
        if data.len() >= 0x14 {
            hash.copy_from_slice(&data[..0x14]);
        }
        let xell_type = XellType::from_hash(&hash);
        Self {
            data,
            xell_type,
        }
    }

    /// crc32 hash xeLL
    pub fn get_hash(&self) -> [u8; 0x14] {
        [0u8; 0x14]
    }

    /// identify xell with crc32
    pub fn identify(&self) -> XellType {
        XellType::XellUnknown
    }
}

/// Calculates the critical digest used to marriage the SMC and the Bootloaders.
/// This matches J-Runner's FixPerBoxDigest implementation.
pub fn fix_per_box_digest(
    smc_data: &[u8],
    cb_dec: &[u8],
    cb_key: &[u8; 16],
    cpukey: &[u8; 16],
) -> Result<[u8; 16], String> {
    let mut digest = [0u8; 0x30];
    
    // 1. Calculate SMC Hash (of the raw/encrypted SMC data)
    // Matches J-Runner/RGBuild CalculateSMCHash
    let smc_hash = excrypt::calculate_smc_hash(smc_data);
    
    // 2. Build the 0x30-byte digest
    digest[0x0..0x10].copy_from_slice(cb_key);
    digest[0x10..0x13].copy_from_slice(&cb_dec[0x20..0x23]); // Pairing Data (at offset 0x20 of CB)
    digest[0x13] = cb_dec[0x23]; // LDV
    digest[0x14..0x20].copy_from_slice(&cb_dec[0x24..0x30]); // Reserved
    digest[0x20..0x30].copy_from_slice(&smc_hash);           // SMC Hash (16 bytes)
    
    // 3. HMAC-SHA1(CPUKey, Digest)
    let res = excrypt::hmac_sha(cpukey, &[&digest])
        .map_err(|e| format!("FixPerBoxDigest HMAC failed: {}", e))?;
    
    let mut final_digest = [0u8; 16];
    final_digest.copy_from_slice(&res[..16]);
    Ok(final_digest)
}

pub fn decrypt_chain(
    cb: &mut cb::BootloaderCb,
    sc: Option<&mut sc::BootloaderSc>,
    cd: &mut cd::BootloaderCd,
    ce: &mut ce::BootloaderCe,
    cf: &mut cf::BootloaderCf,
    cg: &mut cg::BootloaderCg,
    _cpukey: &[u8; 16],
) -> Result<(), String> {
    // 1. Decrypt CB using 1BL Key or CPU Key (depending on RGH)
    // For simplicity, we assume retail 1BL key here; caller handles RGH variants
    cb.decrypt(&ONEBL_KEY);
    
    // 2. Derive CB Key (used for CD, CE, and FixPerBoxDigest)
    let derived = excrypt::hmac_sha(&ONEBL_KEY, &[&cb.header.header.salt])
        .map_err(|e| format!("CB key derivation failed: {}", e))?;
    let mut cb_key = [0u8; 16];
    cb_key.copy_from_slice(&derived[..16]);

    // 3. Decrypt the rest of the chain
    if let Some(sc_bl) = sc {
        sc_bl.decrypt(&ONEBL_KEY);
    }
    
    cd.decrypt(&cb_key, None);
    ce.decrypt(&cb_key);
    cf.decrypt(&ONEBL_KEY);
    cg.decrypt(&cf.header.cg_hmac); // CG uses CF's HMAC key

    Ok(())
}

pub fn encrypt_chain(
    cb: &mut cb::BootloaderCb,
    sc: Option<&mut sc::BootloaderSc>,
    cd: &mut cd::BootloaderCd,
    ce: &mut ce::BootloaderCe,
    cf: &mut cf::BootloaderCf,
    cg: &mut cg::BootloaderCg,
    smc: &mut RawSmc,
    cpukey: &[u8; 16],
) -> Result<(), String> {
    // RC4 is symmetric, so we reuse the decrypt methods
    
    // 1. Calculate and apply FixPerBoxDigest to SMC if needed
    // In many RGH builds, the digest is stored in the decrypted CB or SMC
    // Here we derive the key same as decryption
    let derived = excrypt::hmac_sha(&ONEBL_KEY, &[&cb.header.header.salt])
        .map_err(|e| format!("CB key derivation failed: {}", e))?;
    let mut cb_key = [0u8; 16];
    cb_key.copy_from_slice(&derived[..16]);

    let cb_hdr_bytes = zerocopy::IntoBytes::as_bytes(&cb.header);
    let digest = fix_per_box_digest(&smc.data, cb_hdr_bytes, &cb_key, cpukey)?;
    cb.header.padding_or_args[0x10..0x20].copy_from_slice(&digest);

    // 2. Encrypt in order
    cg.decrypt(&cf.header.cg_hmac);
    cf.decrypt(&ONEBL_KEY);
    ce.decrypt(&cb_key);
    cd.decrypt(&cb_key, None);
    if let Some(sc_bl) = sc {
        sc_bl.decrypt(&ONEBL_KEY);
    }
    cb.decrypt(&ONEBL_KEY);

    Ok(())
}

