pub mod cb;
pub mod sc;
pub mod cd;
pub mod ce;
pub mod cf;
pub mod cg;
pub mod smc;
pub mod xell;
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
    digest[0x10..0x13].copy_from_slice(&cb_payload[0x10..0x13]); // Pairing Data
    digest[0x13] = cb_payload[0x13]; // LDV
    digest[0x14..0x20].copy_from_slice(&cb_payload[0x14..0x20]); // Reserved (12 bytes)
    digest[0x20..0x30].copy_from_slice(&smc_hash);           // SMC Hash (16 bytes)
    
    // 3. HMAC-SHA1(CPUKey, Digest)
    let res = excrypt::hmac_sha(cpukey, &[&digest])
        .map_err(|e| format!("FixPerBoxDigest HMAC failed: {}", e))?;
    
    let mut final_digest = [0u8; 16];
    final_digest.copy_from_slice(&res[..16]);
    info!("[builder] Calculated FixPerBoxDigest: {:02x?}", final_digest);
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
    info!("[builder] Decrypting CB with 1BL Key...");
    cb.decrypt(&ONEBL_KEY);
    if cb.verify_decrypted() {
        info!("[builder] CB decryption verified successfully (zero-region check passed).");
    } else {
        log::warn!("[builder] CB decryption verification failed - decrypted data may be corrupted.");
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

    // Determine v1 vs v2 from CB_A header flags (bit 0x1000).
    // xenon-bltool: cb_b_decrypt_v1 vs cb_b_decrypt_v2
    // J-Runner: (CB_A[0x6..0x8] & 0x1000) != 0 → new crypto scheme
    // v2 passes the CB_A derived key + CB_A header (flags zeroed) as extra HMAC inputs.
    let cb_a_uses_new_crypto = (cb.header.flags.get() & 0x1000) != 0;

    let cd_key: [u8; 16] = if let Some(cb_b_bl) = cb_b {
        if cb_a_uses_new_crypto {
            info!("[builder] CB_A new crypto (flags & 0x1000): using decrypt_v2 for CB_B");
            cb_b_bl.decrypt_v2(&cb.header, &cb_key, _cpukey);
        } else {
            cb_b_bl.decrypt_v1(&cb_key, _cpukey);
        }
        cb_b_bl.populate_metadata_unchecked();
        cb_b_bl.derived_key()
    } else {
        cb_key
    };

    // 3. Decrypt the rest of the chain
    info!("[builder] Decrypting CD and CE...");
    cd.decrypt(&cd_key, None);
    ce.decrypt(&cd_key);

    // Decrypt Updates (Slot 0 and Slot 1)
    if let (Some(cf), Some(cg)) = (cf_0, cg_0) {
        cf.decrypt(&ONEBL_KEY);
        cf.populate_metadata_unchecked();
        if cf.verify_decrypted() {
            info!("[builder] CF slot 0 decryption verified successfully.");
        } else {
            log::warn!("[builder] CF slot 0 decryption verification failed.");
        }
        if cf.data.len() >= 0x330 {
            let mut cg_hmac = [0u8; 16];
            cg_hmac.copy_from_slice(&cf.data[0x320..0x330]);
            cg.decrypt(&cg_hmac);
        }
        info!("[builder] Slot 0 Updates decrypted.");
    }

    if let (Some(cf), Some(cg)) = (cf_1, cg_1) {
        cf.decrypt(&ONEBL_KEY);
        cf.populate_metadata_unchecked();
        if cf.verify_decrypted() {
            info!("[builder] CF slot 1 decryption verified successfully.");
        } else {
            log::warn!("[builder] CF slot 1 decryption verification failed.");
        }
        if cf.data.len() >= 0x330 {
            let mut cg_hmac = [0u8; 16];
            cg_hmac.copy_from_slice(&cf.data[0x320..0x330]);
            cg.decrypt(&cg_hmac);
        }
        info!("[builder] Slot 1 Updates decrypted.");
    }

    Ok(())
}

pub fn encrypt_chain(
    cb: &mut cb::BootloaderCb,
    mut cb_x: Option<&mut cb::BootloaderCb>,
    mut cb_b: Option<&mut cb::BootloaderCb>,
    _sc: Option<&mut sc::BootloaderSc>,
    cd: &mut cd::BootloaderCd,
    ce: &mut ce::BootloaderCe,
    mut cf_0: Option<&mut cf::BootloaderCf>,
    mut cg_0: Option<&mut cg::BootloaderCg>,
    mut cf_1: Option<&mut cf::BootloaderCf>,
    mut cg_1: Option<&mut cg::BootloaderCg>,
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
    info!("[builder] Derived CB Key for re-encryption: {:02x?}", cb_key);

    // Sync metadata back to buffers before calculating digest/re-encrypting
    cb.sync_metadata();
    if let Some(ref mut cb_x_bl) = cb_x { cb_x_bl.sync_metadata(); }
    if let Some(ref mut cb_b_bl) = cb_b { cb_b_bl.sync_metadata(); }

    cd.sync_metadata();

    if let Some(ref mut cf) = cf_0 { cf.sync_metadata(); }
    if let Some(ref mut cg) = cg_0 { cg.sync_metadata(); }
    if let Some(ref mut cf) = cf_1 { cf.sync_metadata(); }
    if let Some(ref mut cg) = cg_1 { cg.sync_metadata(); }

    let digest = fix_per_box_digest(&smc.data, &cb.header, &cb.data, &cb_key, cpukey)?;
    if cb.data.len() >= 0x30 {
        cb.data[0x20..0x30].copy_from_slice(&digest);
    }

    // Encrypt in reverse order (innermost first).
    // Slot 1 - read CG HMAC from decrypted CF, then re-encrypt CG, then re-encrypt CF
    if let (Some(cf), Some(cg)) = (cf_1, cg_1) {
        // Read CG HMAC from decrypted CF before re-encrypting
        let mut cg_hmac = [0u8; 16];
        if cf.data.len() >= 0x330 {
            cg_hmac.copy_from_slice(&cf.data[0x320..0x330]);
        }
        // Re-encrypt CG first (it uses the HMAC as key)
        cg.decrypt(&cg_hmac);
        // Now re-encrypt CF
        cf.decrypt(&ONEBL_KEY);
        info!("[builder] CF/CG slot 1 re-encrypted.");
    }

    // Slot 0 - read CG HMAC from decrypted CF, then re-encrypt CG, then re-encrypt CF
    if let (Some(cf), Some(cg)) = (cf_0, cg_0) {
        // Read CG HMAC from decrypted CF before re-encrypting
        let mut cg_hmac = [0u8; 16];
        if cf.data.len() >= 0x330 {
            cg_hmac.copy_from_slice(&cf.data[0x320..0x330]);
        }
        // Re-encrypt CG first (it uses the HMAC as key)
        cg.decrypt(&cg_hmac);
        // Now re-encrypt CF
        cf.decrypt(&ONEBL_KEY);
        info!("[builder] CF/CG slot 0 re-encrypted.");
    }

    // For split (CB_A+CB_B) and glitch3 layouts, CD/CE must be re-encrypted with the CB_B
    // derived key. In decrypted state, cb_b.data[0..16] still holds that derived key
    // (decrypt_v1 overwrites the nonce with it). Capture it BEFORE re-encrypting CB_B,
    // which would overwrite data[0..16] back to the nonce.
    let cd_key: [u8; 16] = if let Some(ref b) = cb_b {
        b.derived_key()
    } else {
        cb_key // single CB layout
    };

    ce.decrypt(&cd_key);
    if let Some(cb_x_bl) = cb_x {
        cb_x_bl.decrypt_v1(&cb_key, &[0u8; 16]);
    }
    if let Some(cb_b_bl) = cb_b {
        cb_b_bl.decrypt_v1(&cb_key, cpukey);
        info!("[builder] CB_B re-encrypted.");
    }
    cd.decrypt(&cd_key, None);
    info!("[builder] CD re-encrypted.");
    cb.decrypt(&ONEBL_KEY);
    info!("[builder] CB re-encrypted.");

    Ok(())
}

pub fn encrypt_rebooter_chain(
    cb0: &mut cb::BootloaderCb,
    cd0: &mut cd::BootloaderCd,
    cb1: &mut cb::BootloaderCb,
    cd1: &mut cd::BootloaderCd,
    ce1: &mut ce::BootloaderCe,
    update: &mut (Option<&mut cf::BootloaderCf>, Option<&mut cg::BootloaderCg>, Option<&mut cf::BootloaderCf>, Option<&mut cg::BootloaderCg>),
    smc: &mut RawSmc,
    cpukey: &[u8; 16],
) -> Result<(), String> {
    info!("[builder] Re-encrypting JTAG dual-chain...");

    // --- Chain 0 (Base) ---
    // 1. Sync metadata
    cb0.sync_metadata();
    cd0.sync_metadata();

    // 2. Derive base CB key
    let mut cb0_nonce = [0u8; 16];
    if cb0.data.len() >= 16 {
        cb0_nonce.copy_from_slice(&cb0.data[0..16]);
    }
    let derived0 = excrypt::hmac_sha(&ONEBL_KEY, &[&cb0_nonce])
        .map_err(|e| format!("Base CB key derivation failed: {}", e))?;
    let mut cb0_key = [0u8; 16];
    cb0_key.copy_from_slice(&derived0[..16]);

    // 3. Marriage digest for base chain
    let digest0 = fix_per_box_digest(&smc.data, &cb0.header, &cb0.data, &cb0_key, cpukey)?;
    if cb0.data.len() >= 0x20 {
        cb0.data[0x10..0x20].copy_from_slice(&digest0);
    }

    // 4. Encrypt base chain
    cd0.decrypt(&cb0_key, None);
    cb0.decrypt(&ONEBL_KEY);
    info!("[builder] JTAG Chain 0 (Base) re-encrypted.");

    // --- Chain 1 (Rebooter) ---
    // 1. Sync metadata
    cb1.sync_metadata();
    cd1.sync_metadata();
    ce1.sync_metadata();
    if let Some(cf) = update.0.as_mut() { cf.sync_metadata(); }
    if let Some(cg) = update.1.as_mut() { cg.sync_metadata(); }
    if let Some(cf) = update.2.as_mut() { cf.sync_metadata(); }
    if let Some(cg) = update.3.as_mut() { cg.sync_metadata(); }

    // 2. Derive rebooter CB key
    let mut cb1_nonce = [0u8; 16];
    if cb1.data.len() >= 16 {
        cb1_nonce.copy_from_slice(&cb1.data[0..16]);
    }
    let derived1 = excrypt::hmac_sha(&ONEBL_KEY, &[&cb1_nonce])
        .map_err(|e| format!("Rebooter CB key derivation failed: {}", e))?;
    let mut cb1_key = [0u8; 16];
    cb1_key.copy_from_slice(&derived1[..16]);

    // 3. Encrypt update stages (Reverse order)
    // Slot 1
    if let (Some(cf), Some(cg)) = (update.2.as_mut(), update.3.as_mut()) {
        let mut cg_hmac = [0u8; 16];
        if cf.data.len() >= 0x330 { cg_hmac.copy_from_slice(&cf.data[0x320..0x330]); }
        cg.decrypt(&cg_hmac);
        cf.decrypt(&ONEBL_KEY);
    }
    // Slot 0
    if let (Some(cf), Some(cg)) = (update.0.as_mut(), update.1.as_mut()) {
        let mut cg_hmac = [0u8; 16];
        if cf.data.len() >= 0x330 { cg_hmac.copy_from_slice(&cf.data[0x320..0x330]); }
        cg.decrypt(&cg_hmac);
        cf.decrypt(&ONEBL_KEY);
    }

    // 4. Encrypt rebooter stages
    ce1.decrypt(&cb1_key);
    cd1.decrypt(&cb1_key, None);
    cb1.decrypt(&ONEBL_KEY);
    info!("[builder] JTAG Chain 1 (Rebooter) re-encrypted.");

    Ok(())
}
