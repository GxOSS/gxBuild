pub mod cb;
pub mod cd;
pub mod ce;
pub mod cf;
pub mod cg;
pub mod kv;
pub mod sc;
pub mod smc;
pub mod xell;

use zerocopy::byteorder::{BigEndian as ZBigEndian, U16, U32};

use crate::builder::chain::smc::{smc_crypt, RawSmc};

use crate::crypto::rsa::ExCryptRsa;
use crate::crypto::{calculate_smc_hash, hmac_sha, rot_sum_sha, verify_signature, Rc4};
use log::info;

pub const ONEBL_KEY: [u8; 16] = [
    0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA,
];

#[derive(
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    Clone,
    Copy,
)]
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
    pub signature: [u8; 0x100],
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

        if self.data.len() < payload_len {
            return;
        }

        if let Ok(hash) = rot_sum_sha(
            &zerocopy::IntoBytes::as_bytes(&self.header.header)[..0x10],
            &self.data[0x110..payload_len],
        ) {
            sha_out.copy_from_slice(&hash);
        }
    }

    pub fn verify_signature(&self, salt: &[u8], pubkey: &ExCryptRsa) -> bool {
        let mut bl_hash = [0u8; 0x14];
        self.calculate_rotsum(&mut bl_hash);

        if self.data.len() < 0x110 {
            return false;
        }
        let signature: &[u8; 256] = self.data[0x10..0x110]
            .try_into()
            .expect("Slice to array conversion failed");

        verify_signature(signature, &bl_hash, salt, pubkey).unwrap_or(false)
    }

    pub fn decrypt(&mut self, dec_key: &[u8; 16]) {
        let size = self.header.header.size.get();
        let size_aligned = (size + 0xF) & 0xFFFFFFF0;
        let payload_size = size_aligned as usize - std::mem::size_of::<BootloaderHeader>();

        if self.data.len() < payload_size {
            return;
        }

        if let Ok(derived_key) = hmac_sha(dec_key, &[&self.data[0..16]]) {
            let mut decrypt_key = [0u8; 16];
            decrypt_key.copy_from_slice(&derived_key[..16]);

            if let Ok(mut rc4) = Rc4::new(&decrypt_key) {
                let _ = rc4.crypt(&mut self.data[0x10..payload_size]);
            }
        }
    }
}

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

    let smc_hash = calculate_smc_hash(smc_data);

    digest[0x0..0x10].copy_from_slice(cb_key);
    digest[0x10..0x13].copy_from_slice(&cb_payload[0x10..0x13]);
    digest[0x13] = cb_payload[0x13];
    digest[0x14..0x20].copy_from_slice(&cb_payload[0x14..0x20]);
    digest[0x20..0x30].copy_from_slice(&smc_hash);

    let res =
        hmac_sha(cpukey, &[&digest]).map_err(|e| format!("FixPerBoxDigest HMAC failed: {}", e))?;

    let mut final_digest = [0u8; 16];
    final_digest.copy_from_slice(&res[..16]);
    info!(
        "[builder] Calculated FixPerBoxDigest: {:02x?}",
        final_digest
    );
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
    let mut cb_nonce = [0u8; 16];
    if cb.data.len() >= 16 {
        cb_nonce.copy_from_slice(&cb.data[0..16]);
    }

    info!("[builder] Decrypting CB with 1BL Key...");
    if !cb.is_decrypted() {
        if let Err(e) = cb.decrypt(&ONEBL_KEY) {
            log::warn!("[builder] CB decryption failed: {}", e);
        }
    }
    if cb.verify_decrypted() {
        info!("[builder] CB decryption verified successfully (zero-region check passed).");
    } else {
        log::warn!(
            "[builder] CB decryption verification failed - decrypted data may be corrupted."
        );
    }

    let derived = hmac_sha(&ONEBL_KEY, &[&cb_nonce])
        .map_err(|e| format!("CB key derivation failed: {}", e))?;
    let mut cb_key = [0u8; 16];
    cb_key.copy_from_slice(&derived[..16]);

    if let Some(cb_x_bl) = cb_x {
        if let Err(e) = cb_x_bl.decrypt_v1(&cb_key, &[0u8; 16]) {
            log::warn!("[builder] CB_X decryption failed: {}", e);
        }
    }

    let cb_a_uses_new_crypto = (cb.header.flags.get() & 0x1000) != 0;

    let cd_key: [u8; 16] = if let Some(cb_b_bl) = cb_b {
        if cb_a_uses_new_crypto {
            info!("[builder] CB_A new crypto (flags & 0x1000): using decrypt_v2 for CB_B");
            if let Err(e) = cb_b_bl.decrypt_v2(&cb.header, &cb_key, _cpukey) {
                log::warn!("[builder] CB_B v2 decryption failed: {}", e);
            }
        } else {
            info!("[builder] Using decrypt_v1 for CB_B");
            if let Err(e) = cb_b_bl.decrypt_v1(&cb_key, _cpukey) {
                log::warn!("[builder] CB_B v1 decryption failed: {}", e);
            }
        }
        // Debug: Print first 0x30 bytes of decrypted CB_B to find LDV
        if cb_b_bl.data.len() >= 0x30 {
            info!(
                "[builder] CB_B decrypted data[0x00..0x10]: {:02x?}",
                &cb_b_bl.data[0x00..0x10]
            );
            info!(
                "[builder] CB_B decrypted data[0x10..0x20]: {:02x?}",
                &cb_b_bl.data[0x10..0x20]
            );
            info!(
                "[builder] CB_B decrypted data[0x20..0x30]: {:02x?}",
                &cb_b_bl.data[0x20..0x30]
            );
            info!(
                "[builder] CB_B byte at 0x03: {}, 0x13: {}, 0x23: {}",
                cb_b_bl.data.get(0x03).copied().unwrap_or(0),
                cb_b_bl.data.get(0x13).copied().unwrap_or(0),
                cb_b_bl.data.get(0x23).copied().unwrap_or(0)
            );
        }
        cb_b_bl.populate_metadata_unchecked();
        // Override CB_B's LDV with CB_A's LDV if CB_A has valid metadata
        // Unsure if this is correct
        if let (Some(ref mut cb_b_meta), Some(ref cb_a_meta)) =
            (&mut cb_b_bl.metadata, &cb.metadata)
        {
            let cb_a_ldv = cb_a_meta.lockdown_value;
            if cb_a_ldv != cb_b_meta.lockdown_value {
                info!(
                    "[builder] CB_B LDV override: {} -> {} (from CB_A)",
                    cb_b_meta.lockdown_value, cb_a_ldv
                );
                cb_b_meta.lockdown_value = cb_a_ldv;
            }
        }
        if let Some(ref meta) = cb_b_bl.metadata {
            info!(
                "[builder] CB_B metadata populated: LDV={}, PD={:02x?}",
                meta.lockdown_value, meta.pairing_data
            );
        } else {
            log::warn!("[builder] CB_B metadata is None after populate_metadata_unchecked!");
        }
        cb_b_bl.derived_key().unwrap_or_else(|| {
            log::warn!("[builder] CB_B has no derived key after decryption, using cb_key");
            cb_key
        })
    } else {
        cb_key
    };

    info!("[builder] Decrypting CD and CE...");
    if !cd.is_decrypted() {
        if let Err(e) = cd.decrypt(&cd_key, None) {
            log::warn!("[builder] CD decryption failed: {}", e);
        }
    }
    if !ce.is_decrypted() {
        if let Err(e) = ce.decrypt(&cd_key) {
            log::warn!("[builder] CE decryption failed: {}", e);
        }
    }

    if let (Some(cf), Some(cg)) = (cf_0, cg_0) {
        if !cf.is_decrypted() {
            if let Err(e) = cf.decrypt(&ONEBL_KEY) {
                log::warn!("[builder] CF slot 0 decryption failed: {}", e);
            }
        }
        cf.populate_metadata_unchecked();
        if cf.verify_decrypted() {
            info!("[builder] CF slot 0 decryption verified successfully.");
        } else {
            log::warn!("[builder] CF slot 0 decryption verification failed.");
        }
        if cf.data.len() >= 0x330 {
            let mut cg_hmac = [0u8; 16];
            cg_hmac.copy_from_slice(&cf.data[0x320..0x330]);
            if !cg.is_decrypted() {
                if let Err(e) = cg.decrypt(&cg_hmac) {
                    log::warn!("[builder] CG slot 0 decryption failed: {}", e);
                }
            }
        }
        info!("[builder] Slot 0 Updates decrypted.");
    }

    if let (Some(cf), Some(cg)) = (cf_1, cg_1) {
        if !cf.is_decrypted() {
            if let Err(e) = cf.decrypt(&ONEBL_KEY) {
                log::warn!("[builder] CF slot 1 decryption failed: {}", e);
            }
        }
        cf.populate_metadata_unchecked();
        if cf.verify_decrypted() {
            info!("[builder] CF slot 1 decryption verified successfully.");
        } else {
            log::warn!("[builder] CF slot 1 decryption verification failed.");
        }
        if cf.data.len() >= 0x330 {
            let mut cg_hmac = [0u8; 16];
            cg_hmac.copy_from_slice(&cf.data[0x320..0x330]);
            if !cg.is_decrypted() {
                if let Err(e) = cg.decrypt(&cg_hmac) {
                    log::warn!("[builder] CG slot 1 decryption failed: {}", e);
                }
            }
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
    keep_cd_plaintext: bool,
) -> Result<(), String> {
    let mut cb_nonce = [0u8; 16];
    if cb.data.len() >= 16 {
        cb_nonce.copy_from_slice(&cb.data[0..16]);
    }

    let derived = hmac_sha(&ONEBL_KEY, &[&cb_nonce])
        .map_err(|e| format!("CB key derivation failed: {}", e))?;
    let mut cb_key = [0u8; 16];
    cb_key.copy_from_slice(&derived[..16]);
    info!(
        "[builder] Derived CB Key for re-encryption: {:02x?}",
        cb_key
    );

    cb.sync_metadata();
    if let Some(ref mut cb_x_bl) = cb_x {
        cb_x_bl.sync_metadata();
    }
    if let Some(ref mut cb_b_bl) = cb_b {
        cb_b_bl.sync_metadata();
    }

    cd.sync_metadata();

    if let Some(ref mut cf) = cf_0 {
        cf.sync_metadata();
    }
    if let Some(ref mut cg) = cg_0 {
        cg.sync_metadata();
    }
    if let Some(ref mut cf) = cf_1 {
        cf.sync_metadata();
    }
    if let Some(ref mut cg) = cg_1 {
        cg.sync_metadata();
    }

    let mut smc_for_hash = smc.data.clone();
    smc_crypt(&mut smc_for_hash, true);
    let digest = fix_per_box_digest(&smc_for_hash, &cb.header, &cb.data, &cb_key, cpukey)?;
    if cb.data.len() >= 0x30 {
        cb.data[0x20..0x30].copy_from_slice(&digest);
    }

    // Encrypt in reverse order (innermost first).
    // Slot 1 - read CG HMAC from decrypted CF, then re-encrypt CG, then re-encrypt CF
    if let (Some(cf), Some(cg)) = (cf_1, cg_1) {
        let mut cg_hmac = [0u8; 16];
        if cf.data.len() >= 0x330 {
            cg_hmac.copy_from_slice(&cf.data[0x320..0x330]);
        }
        if let Err(e) = cg.decrypt(&cg_hmac) {
            log::warn!("[builder] CG slot 1 re-encryption failed: {}", e);
        }
        if let Err(e) = cf.decrypt(&ONEBL_KEY) {
            log::warn!("[builder] CF slot 1 re-encryption failed: {}", e);
        }
        info!("[builder] CF/CG slot 1 re-encrypted.");
    }

    // Slot 0 - read CG HMAC from decrypted CF, then re-encrypt CG, then re-encrypt CF
    if let (Some(cf), Some(cg)) = (cf_0, cg_0) {
        let mut cg_hmac = [0u8; 16];
        if cf.data.len() >= 0x330 {
            cg_hmac.copy_from_slice(&cf.data[0x320..0x330]);
        }
        if let Err(e) = cg.decrypt(&cg_hmac) {
            log::warn!("[builder] CG slot 0 re-encryption failed: {}", e);
        }
        if let Err(e) = cf.decrypt(&ONEBL_KEY) {
            log::warn!("[builder] CF slot 0 re-encryption failed: {}", e);
        }
        info!("[builder] CF/CG slot 0 re-encrypted.");
    }

    let cd_key: [u8; 16] = if let Some(ref b) = cb_b {
        b.derived_key().unwrap_or_else(|| {
            log::warn!("[builder] CB_B has no derived key, using cb_key");
            cb_key
        })
    } else {
        cb_key
    };

    if ce.is_decrypted() {
        if let Err(e) = ce.decrypt(&cd_key) {
            log::warn!("[builder] CE re-encryption failed: {}", e);
        }
    }
    if let Some(cb_x_bl) = cb_x {
        if let Err(e) = cb_x_bl.decrypt_v1(&cb_key, &[0u8; 16]) {
            log::warn!("[builder] CB_X re-encryption failed: {}", e);
        }
    }
    let cb_a_uses_new_crypto = (cb.header.flags.get() & 0x1000) != 0;
    if let Some(cb_b_bl) = cb_b {
        if cb_a_uses_new_crypto {
            info!("[builder] CB_A new crypto (flags & 0x1000): using encrypt_v2 for CB_B");
            if let Err(e) = cb_b_bl.decrypt_v2(&cb.header, &cb_key, cpukey) {
                log::warn!("[builder] CB_B v2 re-encryption failed: {}", e);
            }
        } else {
            if let Err(e) = cb_b_bl.decrypt_v1(&cb_key, cpukey) {
                log::warn!("[builder] CB_B v1 re-encryption failed: {}", e);
            }
        }
        info!("[builder] CB_B re-encrypted.");
    }
    if keep_cd_plaintext {
        info!("[builder] CD left plaintext.");
    } else {
        if let Err(e) = cd.decrypt(&cd_key, None) {
            log::warn!("[builder] CD re-encryption failed: {}", e);
        }
        info!("[builder] CD re-encrypted.");
    }
    let mut cb_rotsum = [0u8; 0x14];
    cb.calculate_rotsum(&mut cb_rotsum);
    info!(
        "[builder] CB_A rotsum hash (pre-encrypt): {:02x?}",
        cb_rotsum
    );
    if let Err(e) = cb.decrypt(&ONEBL_KEY) {
        log::warn!("[builder] CB_A re-encryption failed: {}", e);
    }
    info!("[builder] CB re-encrypted.");

    Ok(())
}

pub fn encrypt_rebooter_chain(
    cb0: &mut cb::BootloaderCb,
    cd0: &mut cd::BootloaderCd,
    cb1: &mut cb::BootloaderCb,
    cd1: &mut cd::BootloaderCd,
    ce1: &mut ce::BootloaderCe,
    update: &mut (
        Option<&mut cf::BootloaderCf>,
        Option<&mut cg::BootloaderCg>,
        Option<&mut cf::BootloaderCf>,
        Option<&mut cg::BootloaderCg>,
    ),
    smc: &mut RawSmc,
    cpukey: &[u8; 16],
) -> Result<(), String> {
    info!("[builder] Re-encrypting JTAG dual-chain...");

    cb0.sync_metadata();
    cd0.sync_metadata();

    let mut cb0_nonce = [0u8; 16];
    if cb0.data.len() >= 16 {
        cb0_nonce.copy_from_slice(&cb0.data[0..16]);
    }
    let derived0 = hmac_sha(&ONEBL_KEY, &[&cb0_nonce])
        .map_err(|e| format!("Base CB key derivation failed: {}", e))?;
    let mut cb0_key = [0u8; 16];
    cb0_key.copy_from_slice(&derived0[..16]);

    let mut smc_for_hash = smc.data.clone();
    smc_crypt(&mut smc_for_hash, true);
    let digest0 = fix_per_box_digest(&smc_for_hash, &cb0.header, &cb0.data, &cb0_key, cpukey)?;
    if cb0.data.len() >= 0x30 {
        cb0.data[0x20..0x30].copy_from_slice(&digest0);
    }

    if let Err(e) = cd0.decrypt(&cb0_key, None) {
        log::warn!("[builder] CD0 re-encryption failed: {}", e);
    }
    if let Err(e) = cb0.decrypt(&ONEBL_KEY) {
        log::warn!("[builder] CB0 re-encryption failed: {}", e);
    }
    info!("[builder] JTAG Chain 0 (Base) re-encrypted.");

    cb1.sync_metadata();
    cd1.sync_metadata();
    ce1.sync_metadata();
    if let Some(cf) = update.0.as_mut() {
        cf.sync_metadata();
    }
    if let Some(cg) = update.1.as_mut() {
        cg.sync_metadata();
    }
    if let Some(cf) = update.2.as_mut() {
        cf.sync_metadata();
    }
    if let Some(cg) = update.3.as_mut() {
        cg.sync_metadata();
    }

    let mut cb1_nonce = [0u8; 16];
    if cb1.data.len() >= 16 {
        cb1_nonce.copy_from_slice(&cb1.data[0..16]);
    }
    let derived1 = hmac_sha(&ONEBL_KEY, &[&cb1_nonce])
        .map_err(|e| format!("Rebooter CB key derivation failed: {}", e))?;
    let mut cb1_key = [0u8; 16];
    cb1_key.copy_from_slice(&derived1[..16]);

    if let (Some(cf), Some(cg)) = (update.2.as_mut(), update.3.as_mut()) {
        let mut cg_hmac = [0u8; 16];
        if cf.data.len() >= 0x330 {
            cg_hmac.copy_from_slice(&cf.data[0x320..0x330]);
        }
        if let Err(e) = cg.decrypt(&cg_hmac) {
            log::warn!("[builder] CG slot 1 (update) re-encryption failed: {}", e);
        }
        if let Err(e) = cf.decrypt(&ONEBL_KEY) {
            log::warn!("[builder] CF slot 1 (update) re-encryption failed: {}", e);
        }
    }
    if let (Some(cf), Some(cg)) = (update.0.as_mut(), update.1.as_mut()) {
        let mut cg_hmac = [0u8; 16];
        if cf.data.len() >= 0x330 {
            cg_hmac.copy_from_slice(&cf.data[0x320..0x330]);
        }
        if let Err(e) = cg.decrypt(&cg_hmac) {
            log::warn!("[builder] CG slot 0 (update) re-encryption failed: {}", e);
        }
        if let Err(e) = cf.decrypt(&ONEBL_KEY) {
            log::warn!("[builder] CF slot 0 (update) re-encryption failed: {}", e);
        }
    }

    if let Err(e) = ce1.decrypt(&cb1_key) {
        log::warn!("[builder] CE1 re-encryption failed: {}", e);
    }
    if let Err(e) = cd1.decrypt(&cb1_key, None) {
        log::warn!("[builder] CD1 re-encryption failed: {}", e);
    }
    if let Err(e) = cb1.decrypt(&ONEBL_KEY) {
        log::warn!("[builder] CB1 re-encryption failed: {}", e);
    }
    info!("[builder] JTAG Chain 1 (Rebooter) re-encrypted.");

    Ok(())
}
