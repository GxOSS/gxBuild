pub mod cb;
pub mod sc;
pub mod cd;
pub mod ce;
pub mod cf;
pub mod cg;
pub mod smc;
pub mod flashfs;
pub mod kv;

use zerocopy::byteorder::{BigEndian as ZBigEndian, U16, U32};
    
use crate::builder::deps::excrypt::{self, Rc4, ExCryptRsa};
use crate::builder::chain::smc::RawSmc;
use log::info;

pub const ONEBL_KEY: [u8; 16] = [
    0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
    0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA,
];

#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, Clone, Copy)]
#[repr(C)]
pub struct BootloaderHeader {
    pub magic: U16<ZBigEndian>,
    pub version: U16<ZBigEndian>,
    pub pairing: U16<ZBigEndian>,
    pub flags: U16<ZBigEndian>,
    pub entrypoint: U32<ZBigEndian>,
    pub size: U32<ZBigEndian>,
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
        let payload_len = size_aligned as usize - std::mem::size_of::<BootloaderHeader>();

        if self.data.len() < payload_len { return; }

        // HMAC key/salt is at data[0..16]
        // Rotsum processes header (16) + payload skipping key and signature
        // For Generic (SC/CD/CE), that's usually header + data[0x110..]
        if let Ok(hash) = excrypt::rot_sum_sha(
            &zerocopy::IntoBytes::as_bytes(&self.header.header)[..0x10],
            &self.data[0x110..payload_len], 
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn verify_signature(&self, salt: &[u8], pubkey: &ExCryptRsa) -> bool {
        let mut bl_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut bl_hash);

        if self.data.len() < 0x110 { return false; }
        let signature: &[u8; 256] = self.data[0x10..0x110].try_into().expect("Slice to array conversion failed");

        excrypt::verify_signature(signature, &bl_hash, salt, pubkey).unwrap_or(false)
    }

    pub fn decrypt(&mut self, dec_key: &[u8; 16]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = size_aligned as usize - std::mem::size_of::<BootloaderHeader>();

        if self.data.len() < payload_size { return; }

        // Salt/Key is at the start of the payload data[0..16]
        if let Ok(derived_key) = excrypt::hmac_sha(dec_key, &[&self.data[0..16]]) {
            let mut decrypt_key = [0u8; 16];
            decrypt_key.copy_from_slice(&derived_key[..16]);
            
            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                // Decryption starts after the key
                let _ = rc4.crypt(&mut self.data[0x10..payload_size]);
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
    _cb_header: &BootloaderHeader,
    cb_payload: &[u8],
    cb_key: &[u8; 16],
    cpukey: &[u8; 16],
) -> Result<[u8; 16], String> {
    let mut digest = [0u8; 0x30];
    
    if cb_payload.len() < 0x20 {
        return Err("CB payload too small for digest calculation".into());
    }

    // 1. Calculate SMC Hash (of the raw/encrypted SMC data)
    let smc_hash = excrypt::calculate_smc_hash(smc_data);
    
    // 2. Build the 0x30-byte digest
    digest[0x0..0x10].copy_from_slice(cb_key);
    digest[0x10..0x13].copy_from_slice(&cb_payload[0..3]); // Pairing Data
    digest[0x13] = cb_payload[3]; // LDV
    digest[0x14..0x20].copy_from_slice(&cb_payload[4..16]); // Reserved (12 bytes)
    digest[0x20..0x30].copy_from_slice(&smc_hash);           // SMC Hash (16 bytes)
    
    // 3. HMAC-SHA1(CPUKey, Digest)
    let res = excrypt::hmac_sha(cpukey, &[&digest])
        .map_err(|e| format!("FixPerBoxDigest HMAC failed: {}", e))?;
    
    let mut final_digest = [0u8; 16];
    final_digest.copy_from_slice(&res[..16]);
    info!(" -> Calculated FixPerBoxDigest: {:02x?}", final_digest);
    Ok(final_digest)
}

pub fn decrypt_chain(
    cb: &mut cb::BootloaderCb,
    cb_x: Option<&mut cb::BootloaderCb>,
    cb_b: Option<&mut cb::BootloaderCb>,
    _sc: Option<&mut sc::BootloaderSc>,
    cd: &mut cd::BootloaderCd,
    ce: &mut ce::BootloaderCe,
    cf_0: Option<&mut cf::BootloaderCf>,
    cg_0: Option<&mut cg::BootloaderCg>,
    cf_1: Option<&mut cf::BootloaderCf>,
    cg_1: Option<&mut cg::BootloaderCg>,
    _cpukey: &[u8; 16],
) -> Result<(), String> {
    // Capture nonce BEFORE decrypt: xenon-bltool cb_decrypt writes the derived RC4 key
    // back into hdr->key in-place, so cb.data[0..16] is overwritten after decrypt().
    let mut cb_nonce = [0u8; 16];
    if cb.data.len() >= 16 {
        cb_nonce.copy_from_slice(&cb.data[0..16]);
    }

    // 1. Decrypt CB using 1BL Key.
    info!(" -> Decrypting CB with 1BL Key...");
    cb.decrypt(&ONEBL_KEY);
    if cb.verify_decrypted() {
        info!(" -> CB decryption verified successfully (zero-region check passed).");
    } else {
        log::warn!(" -> CB decryption verification failed — decrypted data may be corrupted.");
    }

    // 2. Derive CB Key from the original nonce (not the overwritten key).
    //    ExCryptHmacSha(onebl_key, nonce) → cb_key.
    let derived = excrypt::hmac_sha(&ONEBL_KEY, &[&cb_nonce])
        .map_err(|e| format!("CB key derivation failed: {}", e))?;
    let mut cb_key = [0u8; 16];
    cb_key.copy_from_slice(&derived[..16]);

    // Handle CB_X / CB_B if present
    if let Some(cb_x_bl) = cb_x {
        cb_x_bl.decrypt_v1(&cb_key, &[0u8; 16]); // RGH3 CB_X uses zeroed CPU key
    }
    if let Some(cb_b_bl) = cb_b {
        cb_b_bl.decrypt_v1(&cb_key, _cpukey);
    }

    // 3. Decrypt the rest of the chain
    info!(" -> Decrypting CD and CE...");
    cd.decrypt(&cb_key, None);
    ce.decrypt(&cb_key);

    // Decrypt Updates (Slot 0 and Slot 1)
    if let (Some(cf), Some(cg)) = (cf_0, cg_0) {
        cf.decrypt(&ONEBL_KEY);
        if cf.verify_decrypted() {
            info!(" -> CF slot 0 decryption verified successfully.");
        } else {
            log::warn!(" -> CF slot 0 decryption verification failed.");
        }
        if cf.data.len() >= 0x20 {
            let mut cg_hmac = [0u8; 16];
            cg_hmac.copy_from_slice(&cf.data[0x10..0x20]);
            cg.decrypt(&cg_hmac);
        }
        info!(" -> Slot 0 Updates decrypted.");
    }

    if let (Some(cf), Some(cg)) = (cf_1, cg_1) {
        cf.decrypt(&ONEBL_KEY);
        if cf.verify_decrypted() {
            info!(" -> CF slot 1 decryption verified successfully.");
        } else {
            log::warn!(" -> CF slot 1 decryption verification failed.");
        }
        if cf.data.len() >= 0x20 {
            let mut cg_hmac = [0u8; 16];
            cg_hmac.copy_from_slice(&cf.data[0x10..0x20]);
            cg.decrypt(&cg_hmac);
        }
        info!(" -> Slot 1 Updates decrypted.");
    }

    Ok(())
}

pub fn encrypt_chain(
    cb: &mut cb::BootloaderCb,
    cb_x: Option<&mut cb::BootloaderCb>,
    cb_b: Option<&mut cb::BootloaderCb>,
    _sc: Option<&mut sc::BootloaderSc>,
    cd: &mut cd::BootloaderCd,
    ce: &mut ce::BootloaderCe,
    cf_0: Option<&mut cf::BootloaderCf>,
    cg_0: Option<&mut cg::BootloaderCg>,
    cf_1: Option<&mut cf::BootloaderCf>,
    cg_1: Option<&mut cg::BootloaderCg>,
    smc: &mut RawSmc,
    cpukey: &[u8; 16],
) -> Result<(), String> {
    // RC4 is symmetric, so we reuse the decrypt methods.
    // When encrypting, the chain is in DECRYPTED state, so cb.data[0..16] is still
    // the original nonce (not yet overwritten by decrypt). Capture it for cb_key derivation.
    let mut cb_nonce = [0u8; 16];
    if cb.data.len() >= 16 {
        cb_nonce.copy_from_slice(&cb.data[0..16]);
    }

    let derived = excrypt::hmac_sha(&ONEBL_KEY, &[&cb_nonce])
        .map_err(|e| format!("CB key derivation failed: {}", e))?;
    let mut cb_key = [0u8; 16];
    cb_key.copy_from_slice(&derived[..16]);
    info!(" -> Derived CB Key: {:02x?}", cb_key);

    let digest = fix_per_box_digest(&smc.data, &cb.header, &cb.data, &cb_key, cpukey)?;
    if cb.data.len() >= 0x20 {
        cb.data[0x10..0x20].copy_from_slice(&digest);
    }

    // Encrypt in reverse order (innermost first).
    // Slot 1
    if let (Some(cf), Some(cg)) = (cf_1, cg_1) {
        if cf.data.len() >= 0x20 {
            let mut cg_hmac = [0u8; 16];
            cg_hmac.copy_from_slice(&cf.data[0x10..0x20]);
            cg.decrypt(&cg_hmac);
        }
        cf.decrypt(&ONEBL_KEY);
    }

    // Slot 0
    if let (Some(cf), Some(cg)) = (cf_0, cg_0) {
        if cf.data.len() >= 0x20 {
            let mut cg_hmac = [0u8; 16];
            cg_hmac.copy_from_slice(&cf.data[0x10..0x20]);
            cg.decrypt(&cg_hmac);
        }
        cf.decrypt(&ONEBL_KEY);
    }

    ce.decrypt(&cb_key);
    if let Some(cb_x_bl) = cb_x {
        cb_x_bl.decrypt_v1(&cb_key, &[0u8; 16]);
    }
    if let Some(cb_b_bl) = cb_b {
        cb_b_bl.decrypt_v1(&cb_key, cpukey);
    }
    cd.decrypt(&cb_key, None);
    info!(" -> CD Encrypted.");
    cb.decrypt(&ONEBL_KEY);
    info!(" -> CB Encrypted.");

    Ok(())
}
