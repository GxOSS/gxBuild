/*
  kv.rs - Handling for Xbox 360 Keyvault (KV).

  Copyright (c) 2026 gxBuild Contributors and Developers

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/

use crate::crypto::{hmac_sha, Rc4};
use log::info;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct KeyvaultMetadata {
    pub serial: String,
    pub region: u16,
    pub dvd_key: [u8; 16],
    pub console_id: [u8; 5],
    pub mf_date: String,
    pub osig: String,
    pub fcrt: bool,
    pub console_type: u32,
    pub version: u16,
    pub kv_type: u8,
}

#[derive(Clone)]
pub struct Keyvault {
    pub data: Vec<u8>,
    pub is_decrypted: bool,
    pub hashed: bool,
    pub metadata: Option<KeyvaultMetadata>,
}

pub const OFFSET_REGION: usize = 0xC8;
pub const OFFSET_SERIAL: usize = 0xB0;
pub const OFFSET_DVD_KEY: usize = 0x100;
pub const OFFSET_CONSOLE_ID: usize = 0x9CA;
pub const OFFSET_MF_DATE: usize = 0x9E4;
pub const OFFSET_OSIG_STR: usize = 0xC92;
#[derive(Error, Debug)]
pub enum KeyvaultError {
    #[error("Keyvault data too small: got {got}, expected {expected}")]
    DataTooSmall { got: usize, expected: usize },
    #[error("Keyvault too small for decryption: got {got}")]
    TooSmallForDecryption { got: usize },
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("RC4 initialization failed: {0}")]
    Rc4Init(String),
    #[error("RC4 operation failed: {0}")]
    Rc4Crypt(String),
    #[error("Decryption failed: invalid signatures for both KV1 and KV2")]
    DecryptionFailed,
    #[error("Failed to map KeyvaultRecord")]
    RecordMapFailed,
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, KeyvaultError>;

impl From<KeyvaultError> for String {
    fn from(e: KeyvaultError) -> Self {
        e.to_string()
    }
}

pub const OFFSET_FCRT_FLAG: usize = 0x1C;

impl Keyvault {
    pub const SIZE: usize = 0x4000;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(KeyvaultError::DataTooSmall {
                got: data.len(),
                expected: Self::SIZE,
            });
        }
        let mut kv = Self {
            data: data[..Self::SIZE].to_vec(),
            is_decrypted: false,
            hashed: false,
            metadata: None,
        };

        if kv.check_decrypted_signatures() {
            info!("[builder] Pre-decrypted Keyvault detected via signatures.");
            kv.is_decrypted = true;
            let _ = kv.refresh_metadata();
        }

        Ok(kv)
    }

    pub fn refresh_metadata(&mut self) -> Result<()> {
        if !self.is_decrypted {
            self.metadata = None;
            return Err(KeyvaultError::Other(
                "Cannot refresh metadata on encrypted Keyvault".to_string(),
            ));
        }

        let kv = gxcrypt::keyvault::KeyVault::parse(&self.data)
            .map_err(|e| KeyvaultError::Other(e.to_string()))?;

        let meta = KeyvaultMetadata {
            serial: kv.console_serial().to_string(),
            region: kv.game_region().bits() as u16,
            dvd_key: *kv.dvd_key(),
            console_id: kv.console_id().0,
            mf_date: kv.console_certificate.manufacturing_date.clone(),
            osig: self.get_osig(),
            fcrt: (kv.config.odd_features.bits() & 0x0120) != 0,
            console_type: kv.console_type().0,
            version: kv.config.odd_features.bits(),
            kv_type: self.get_kv_type(),
        };

        self.metadata = Some(meta);
        Ok(())
    }

    fn check_decrypted_signatures(&self) -> bool {
        if self.data.len() < 0x60 {
            return false;
        }

        if self.data[0x40..0x60].iter().all(|&b| b == 0x00) {
            return true;
        }

        if self.data.len() >= 0x2000 {
            let osig_sig = &self.data[0xC82..0xC86];
            let drm_sig = &self.data[0x1F64..0x1F67];
            return (osig_sig == b"OSIG") || (drm_sig == b"DRM");
        }

        false
    }

    pub fn decrypt(&mut self, cpukey: &[u8; 16]) -> Result<()> {
        if self.is_decrypted {
            return Ok(());
        }

        if self.data.len() < 0x10 {
            return Err(KeyvaultError::TooSmallForDecryption {
                got: self.data.len(),
            });
        }

        let original_data = self.data.clone();

        self.hashed = false;
        let mut kv1_data = self.data.clone();

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&kv1_data[..0x10]);
        let hmac_res = hmac_sha(cpukey, &[&nonce])
            .map_err(|e| KeyvaultError::KeyDerivation(format!("KV1: {}", e)))?;

        let mut decrypt_key = [0u8; 16];
        decrypt_key.copy_from_slice(&hmac_res[..16]);

        let mut rc4 = Rc4::new(&decrypt_key).map_err(|e| KeyvaultError::Rc4Init(e.to_string()))?;
        rc4.crypt(&mut kv1_data[0x10..])
            .map_err(|e| KeyvaultError::Rc4Crypt(e.to_string()))?;

        let kv1_valid = {
            let temp_kv = Keyvault {
                data: kv1_data.clone(),
                ..self.clone()
            };
            temp_kv.check_decrypted_signatures()
        };

        if kv1_valid {
            self.data = kv1_data;
            self.is_decrypted = true;
            let kv_type = self.get_kv_type();
            self.hashed = kv_type == 2;
            let _ = self.refresh_metadata();
            info!(
                "[builder] Keyvault decrypted as Type {} ({}).",
                kv_type,
                if kv_type == 2 { "Hashed" } else { "Retail" }
            );
            return Ok(());
        }

        let hmac_res_v2 = hmac_sha(cpukey, &[&hmac_res[..16]])
            .map_err(|e| KeyvaultError::KeyDerivation(format!("KV2: {}", e)))?;
        let mut fallback_key = [0u8; 16];
        fallback_key.copy_from_slice(&hmac_res_v2[..16]);

        let mut kv2_data = original_data;
        let mut rc4_v2 =
            Rc4::new(&fallback_key).map_err(|e| KeyvaultError::Rc4Init(e.to_string()))?;
        rc4_v2
            .crypt(&mut kv2_data[0x10..])
            .map_err(|e| KeyvaultError::Rc4Crypt(e.to_string()))?;

        if {
            let temp_kv = Keyvault {
                data: kv2_data.clone(),
                ..self.clone()
            };
            temp_kv.check_decrypted_signatures()
        } {
            info!("[builder] Keyvault decrypted as Type 2 (Hashed).");
            self.data = kv2_data;
            self.is_decrypted = true;
            self.hashed = true;
            let _ = self.refresh_metadata();
            return Ok(());
        }

        Err(KeyvaultError::DecryptionFailed)
    }

    pub fn encrypt(&mut self, cpukey: &[u8; 16]) -> Result<()> {
        if !self.is_decrypted {
            return Ok(());
        }

        if self.hashed {
            let mut message = self.data[0x10..].to_vec();
            message.extend_from_slice(&[0x07, 0x12]);

            let salt = hmac_sha(cpukey, &[&message])
                .map_err(|e| KeyvaultError::KeyDerivation(format!("KV2 salt: {}", e)))?;

            let final_key = hmac_sha(cpukey, &[&salt[..16]])
                .map_err(|e| KeyvaultError::KeyDerivation(format!("KV2 key: {}", e)))?;

            let mut rc4 =
                Rc4::new(&final_key[..16]).map_err(|e| KeyvaultError::Rc4Init(e.to_string()))?;

            rc4.crypt(&mut self.data[0x10..])
                .map_err(|e| KeyvaultError::Rc4Crypt(e.to_string()))?;

            self.data[..16].copy_from_slice(&salt[..16]);
        } else {
            let mut nonce = [0u8; 16];
            nonce.copy_from_slice(&self.data[..0x10]);
            let hmac_res = hmac_sha(cpukey, &[&nonce])
                .map_err(|e| KeyvaultError::KeyDerivation(e.to_string()))?;
            let mut rc4 =
                Rc4::new(&hmac_res[..16]).map_err(|e| KeyvaultError::Rc4Init(e.to_string()))?;
            rc4.crypt(&mut self.data[0x10..])
                .map_err(|e| KeyvaultError::Rc4Crypt(e.to_string()))?;
        }

        self.is_decrypted = false;
        self.metadata = None;
        Ok(())
    }

    pub fn get_serial(&self) -> String {
        gxcrypt::keyvault::KeyVault::parse(&self.data)
            .map(|kv| kv.console_serial().to_string())
            .unwrap_or_default()
    }

    pub fn get_dvd_key(&self) -> String {
        gxcrypt::keyvault::KeyVault::parse(&self.data)
            .map(|kv| kv.dvd_key().iter().map(|b| format!("{:02x}", b)).collect())
            .unwrap_or_default()
    }

    pub fn get_osig(&self) -> String {
        let start = OFFSET_OSIG_STR;
        let end = start + 28;
        if self.data.len() >= end {
            String::from_utf8_lossy(&self.data[start..end])
                .trim_matches(char::from(0))
                .to_string()
        } else {
            "Unknown".to_string()
        }
    }

    pub fn get_kv_type(&self) -> u8 {
        if self.data.len() < 0x1E00 {
            return 1;
        }
        let sig_region = &self.data[0x1DF8..0x1E00];
        if sig_region.iter().all(|&b| b == 0xFF || b == 0x00) {
            1
        } else {
            2
        }
    }

    pub fn get_console_id_alt(&self) -> String {
        gxcrypt::keyvault::KeyVault::parse(&self.data)
            .map(|kv| {
                kv.console_id()
                    .0
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect()
            })
            .unwrap_or_else(|_| "Unknown".to_string())
    }

    pub fn get_mf_date(&self) -> String {
        gxcrypt::keyvault::KeyVault::parse(&self.data)
            .map(|kv| kv.console_certificate.manufacturing_date.clone())
            .unwrap_or_else(|_| "Unknown".to_string())
    }

    fn ensure_decrypted(&self) -> Result<()> {
        if !self.is_decrypted {
            return Err(KeyvaultError::Other(
                "Keyvault patching requires decrypted data. Call decrypt() first.".to_string(),
            ));
        }
        Ok(())
    }

    pub fn set_region(&mut self, region_code: u16) -> std::result::Result<(), String> {
        self.ensure_decrypted().map_err(|e| e.to_string())?;
        let bytes = region_code.to_be_bytes();
        self.data[OFFSET_REGION..OFFSET_REGION + 2].copy_from_slice(&bytes);
        let _ = self.refresh_metadata();
        Ok(())
    }

    pub fn set_serial(&mut self, serial: &str) -> std::result::Result<(), String> {
        self.ensure_decrypted().map_err(|e| e.to_string())?;
        let bytes = serial.as_bytes();
        let len = bytes.len().min(12);
        self.data[OFFSET_SERIAL..OFFSET_SERIAL + 12].fill(0);
        self.data[OFFSET_SERIAL..OFFSET_SERIAL + len].copy_from_slice(&bytes[..len]);
        let _ = self.refresh_metadata();
        Ok(())
    }

    pub fn set_mf_date(&mut self, date: &str) -> std::result::Result<(), String> {
        self.ensure_decrypted().map_err(|e| e.to_string())?;
        let bytes = date.as_bytes();
        let len = bytes.len().min(8);
        self.data[OFFSET_MF_DATE..OFFSET_MF_DATE + 8].fill(0);
        self.data[OFFSET_MF_DATE..OFFSET_MF_DATE + len].copy_from_slice(&bytes[..len]);
        let _ = self.refresh_metadata();
        Ok(())
    }

    pub fn set_osig(&mut self, osig: &str) -> std::result::Result<(), String> {
        self.ensure_decrypted().map_err(|e| e.to_string())?;
        if osig.len() != 32 {
            return Err(format!(
                "OSIG string must be exactly 32 characters (got {})",
                osig.len()
            ));
        }
        self.data[OFFSET_OSIG_STR..OFFSET_OSIG_STR + 32].copy_from_slice(osig.as_bytes());
        let _ = self.refresh_metadata();
        Ok(())
    }

    pub fn set_console_id(&mut self, id: &[u8; 5]) -> std::result::Result<(), String> {
        self.ensure_decrypted().map_err(|e| e.to_string())?;
        self.data[OFFSET_CONSOLE_ID..OFFSET_CONSOLE_ID + 5].copy_from_slice(id);
        let _ = self.refresh_metadata();
        Ok(())
    }

    pub fn set_dvd_key(&mut self, key: &[u8; 16]) -> std::result::Result<(), String> {
        self.ensure_decrypted().map_err(|e| e.to_string())?;
        self.data[OFFSET_DVD_KEY..OFFSET_DVD_KEY + 16].copy_from_slice(key);
        let _ = self.refresh_metadata();
        Ok(())
    }

    pub fn apply_fcrt_patch(&mut self, enabled: bool) -> std::result::Result<(), String> {
        self.ensure_decrypted().map_err(|e| e.to_string())?;
        let mut flags = u16::from_be_bytes(
            self.data[OFFSET_FCRT_FLAG..OFFSET_FCRT_FLAG + 2]
                .try_into()
                .unwrap(),
        );
        if enabled {
            flags |= 0x0120;
        } else {
            flags &= !0x0120;
        }
        self.data[OFFSET_FCRT_FLAG..OFFSET_FCRT_FLAG + 2].copy_from_slice(&flags.to_be_bytes());
        let _ = self.refresh_metadata();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kv_decryption_detection() {
        let data = vec![0u8; 0x4000];
        let kv = Keyvault::parse(&data).unwrap();
        assert!(
            kv.is_decrypted,
            "Should detect decrypted KV via zero-pad region"
        );

        // Fallback OSIG detection on non-zero buffer where zero-pad doesn't trigger
        let mut data2 = vec![0xAAu8; 0x4000];
        data2[0xC82..0xC86].copy_from_slice(b"OSIG");
        let kv2 = Keyvault::parse(&data2).unwrap();
        assert!(
            kv2.is_decrypted,
            "Should detect decrypted KV via OSIG fallback"
        );

        // Fallback DRM detection
        let mut data3 = vec![0xAAu8; 0x4000];
        data3[0x1F64..0x1F67].copy_from_slice(b"DRM");
        let kv3 = Keyvault::parse(&data3).unwrap();
        assert!(
            kv3.is_decrypted,
            "Should detect decrypted KV via DRM fallback"
        );

        // Encrypted KV: non-zero junk, no magic -> not decrypted
        let data4 = vec![0xAAu8; 0x4000];
        let kv4 = Keyvault::parse(&data4).unwrap();
        assert!(
            !kv4.is_decrypted,
            "Non-zero non-magic buffer should be encrypted"
        );
    }

    #[test]
    fn test_kv_patching_guards() {
        // Use a non-zero buffer so the zero-pad check at 0x40..0x60 doesn't fire.
        // A real encrypted KV has non-zero ciphertext throughout.
        let data = vec![0xAAu8; 0x4000];
        let mut kv = Keyvault::parse(&data).unwrap();
        assert!(!kv.is_decrypted);

        // Attempt patching on encrypted KV
        let res = kv.set_region(0x02FE);
        assert!(res.is_err(), "Patching should fail on encrypted KV");
        assert_eq!(
            res.unwrap_err(),
            "Keyvault patching requires decrypted data. Call decrypt() first."
        );
    }

    #[test]
    fn test_kv_region_patch() {
        let mut data = vec![0u8; 0x4000];
        data[0xC82..0xC86].copy_from_slice(b"OSIG"); // Force decrypted state
        let mut kv = Keyvault::parse(&data).unwrap();

        kv.set_region(0x02FE).unwrap();
        assert_eq!(&kv.data[OFFSET_REGION..OFFSET_REGION + 2], &[0x02, 0xFE]);
    }

    #[test]
    fn test_kv_serial_patch() {
        let mut data = vec![0u8; 0x4000];
        data[0xC82..0xC86].copy_from_slice(b"OSIG");
        let mut kv = Keyvault::parse(&data).unwrap();

        kv.set_serial("123456789012").unwrap();
        assert_eq!(&kv.data[OFFSET_SERIAL..OFFSET_SERIAL + 12], b"123456789012");

        kv.set_serial("SHORT").unwrap();
        assert_eq!(&kv.data[OFFSET_SERIAL..OFFSET_SERIAL + 5], b"SHORT");
        assert_eq!(kv.data[OFFSET_SERIAL + 5], 0, "Should be null padded");
    }

    #[test]
    fn test_kv_osig_patch() {
        let mut data = vec![0u8; 0x4000];
        data[0xC82..0xC86].copy_from_slice(b"OSIG");
        let mut kv = Keyvault::parse(&data).unwrap();

        // Test invalid length
        let res = kv.set_osig("TOO_SHORT");
        assert!(res.is_err());

        let valid_osig = "PLDS    DG-16D2S        74850C  "; // Exactly 32 chars
        kv.set_osig(valid_osig).unwrap();
        assert_eq!(
            &kv.data[OFFSET_OSIG_STR..OFFSET_OSIG_STR + 32],
            valid_osig.as_bytes()
        );
    }

    #[test]
    fn test_kv_fcrt_patch() {
        let mut data = vec![0u8; 0x4000];
        data[0xC82..0xC86].copy_from_slice(b"OSIG");
        let mut kv = Keyvault::parse(&data).unwrap();

        kv.apply_fcrt_patch(false).unwrap();
        // OFFSET_FCRT_FLAG = 0x1C; 2-byte BE field; mask 0x120 cleared
        assert_eq!(
            &kv.data[OFFSET_FCRT_FLAG..OFFSET_FCRT_FLAG + 2],
            &[0x00, 0x00]
        );
        assert!(!kv.metadata.as_ref().unwrap().fcrt);

        kv.apply_fcrt_patch(true).unwrap();
        // 0x0120 in big-endian = [0x01, 0x20]
        assert_eq!(
            &kv.data[OFFSET_FCRT_FLAG..OFFSET_FCRT_FLAG + 2],
            &[0x01, 0x20]
        );
        assert!(kv.metadata.as_ref().unwrap().fcrt);
    }

    #[test]
    fn test_kv_metadata_sync() {
        let mut data = vec![0u8; 0x4000];
        data[0xC82..0xC86].copy_from_slice(b"OSIG"); // Force decrypted state
        let mut kv = Keyvault::parse(&data).unwrap();

        // Check initial parsed metadata
        assert!(kv.metadata.is_some());
        assert_eq!(kv.metadata.as_ref().unwrap().region, 0);

        // Patch and verify sync
        kv.set_region(0x01FE).unwrap();
        assert_eq!(kv.metadata.as_ref().unwrap().region, 0x01FE);

        kv.set_serial("987654321098").unwrap();
        assert_eq!(kv.metadata.as_ref().unwrap().serial, "987654321098");
    }

    #[test]
    fn test_kv_encryption_clears_metadata() {
        let mut data = vec![0u8; 0x4000];
        data[0xC82..0xC86].copy_from_slice(b"OSIG");
        let mut kv = Keyvault::parse(&data).unwrap();
        assert!(kv.metadata.is_some());

        kv.is_decrypted = true; // Simulating state for manual test
        kv.encrypt(&[0u8; 16]).unwrap();
        assert!(kv.metadata.is_none());
        assert!(!kv.is_decrypted);
    }
}
