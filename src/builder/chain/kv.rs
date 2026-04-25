/*
    kv.rs - Handling for Xbox 360 Keyvault (KV).

    Modified for GGX by Exposure / Zach
*/

use zerocopy::FromBytes;
use zerocopy::byteorder::{U16, BigEndian};
use crate::builder::deps::excrypt::{self, Rc4};
use log::{info, warn};

/// Keyvault record header - covers the first 0x110 bytes.
/// All offsets confirmed against J-Runner Nand.cs lines 674-682.
/// Fields beyond 0x110 (console_id @ 0x9CA, osig @ 0xC92, mfdate @ 0x9E4)
/// live far outside this struct and are accessed via sparse accessors below.
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, Clone, Copy, Debug)]
#[repr(C)]
pub struct KeyvaultRecord {
    pub hmac: [u8; 0x10],           // 0x000 - HMAC-SHA1 nonce (RC4 seed)
    pub unused0: [u8; 0x0C],        // 0x010
    pub version: U16<BigEndian>,    // 0x01C
    pub unused1: [u8; 0x92],        // 0x01E..0x0B0
    pub serial: [u8; 12],           // 0x0B0 - Console serial number (ASCII)
    pub unused2: [u8; 0x50],        // 0x0BC..0x10C
    pub dvd_key: [u8; 16],          // 0x100 - DVD encryption key
}

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

// Offsets for Keyvault patching (including 16-byte HMAC header)
pub const OFFSET_REGION: usize = 0xC8;      // 2 bytes (Big Endian)
pub const OFFSET_SERIAL: usize = 0xB0;      // 12 bytes (ASCIIString)
pub const OFFSET_DVD_KEY: usize = 0x100;    // 16 bytes (Binary)
pub const OFFSET_CONSOLE_ID: usize = 0x9CA; // 5 bytes (Binary)
pub const OFFSET_MF_DATE: usize = 0x9E4;    // 8 bytes (ASCIIString)
pub const OFFSET_DRIVE_INQUIRY: usize = 0xC8A; // 40 bytes (Binary)
pub const OFFSET_OSIG_STR: usize = 0xC92;   // 32 bytes (ASCIIString, inside Inquiry)
pub const OFFSET_FCRT_FLAG: usize = 0x1C;   // 2 bytes (Hardware Flags u16 BE) - J-Runner updatekvval() L684

impl Keyvault {
    pub const SIZE: usize = 0x4000;

    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err(format!("Keyvault data too small: {} bytes (expected {})", data.len(), Self::SIZE));
        }
        let mut kv = Self {
            data: data[..Self::SIZE].to_vec(),
            is_decrypted: false,
            hashed: false,
            metadata: None,
        };
        
        // Automatic detection of pre-decrypted Keyvaults
        if kv.check_decrypted_signatures() {
            info!("[builder] Pre-decrypted Keyvault detected via signatures.");
            kv.is_decrypted = true;
            let _ = kv.refresh_metadata();
        }

        Ok(kv)
    }

    /// Parses the raw buffer into the structured metadata view.
    /// Only works if the Keyvault is decrypted.
    pub fn refresh_metadata(&mut self) -> Result<(), String> {
        if !self.is_decrypted {
            self.metadata = None;
            return Err("Cannot refresh metadata on encrypted Keyvault".to_string());
        }

        let record = self.get_record()?;

        // Hardware flags at 0x1C - J-Runner updatekvval() L684:
        //   (BitConverter.ToUInt16(new byte[2] { kv[0x1D], kv[0x1C] }, 0) & 0x120) != 0
        //   = big-endian u16 at 0x1C, masked with 0x120 (bits: 0x100 | 0x020)
        let flags = u16::from_be_bytes(self.data[0x1C..0x1E].try_into().unwrap());

        let meta = KeyvaultMetadata {
            serial: self.get_serial(),
            region: u16::from_be_bytes(self.data[OFFSET_REGION..OFFSET_REGION+2].try_into().unwrap()),
            dvd_key: self.data[OFFSET_DVD_KEY..OFFSET_DVD_KEY+16].try_into().unwrap(),
            console_id: self.data[OFFSET_CONSOLE_ID..OFFSET_CONSOLE_ID+5].try_into().unwrap(),
            mf_date: self.get_mf_date(),
            osig: self.get_osig(),
            fcrt: (flags & 0x120) != 0,
            console_type: u32::from_be_bytes(self.data[0x9E0..0x9E4].try_into().unwrap()),
            version: record.version.get(),
            kv_type: self.get_kv_type(),
        };

        self.metadata = Some(meta);
        Ok(())
    }

    /// Detects if the data is already decrypted.
    /// Primary check: J-Runner updatekvval() L669 - `data[0x40..0x60]` are all zeros in decrypted KVs.
    /// Fallback: look for OSIG/DRM ASCII magic at their known certificate offsets.
    fn check_decrypted_signatures(&self) -> bool {
        if self.data.len() < 0x60 { return false; }

        // Canonical zero-pad check (J-Runner / x360Utils): decrypted KVs always have
        // zeros at 0x40..0x60 (the reserved pad region after the HMAC nonce and header).
        if self.data[0x40..0x60].iter().all(|&b| b == 0x00) {
            return true;
        }

        // Fallback: ASCII magic at known decrypted offsets
        if self.data.len() >= 0x2000 {
            let osig_sig = &self.data[0xC82..0xC86];  // "OSIG"
            let drm_sig  = &self.data[0x1F64..0x1F67]; // "DRM"
            return (osig_sig == b"OSIG") || (drm_sig == b"DRM");
        }

        false
    }

    pub fn decrypt(&mut self, cpukey: &[u8; 16]) -> Result<(), String> {
        if self.is_decrypted {
            return Ok(());
        }

        if self.data.len() < 0x10 {
            return Err("Keyvault too small for decryption".to_string());
        }

        let original_data = self.data.clone();

        // 1. Try KV1 Decryption
        self.hashed = false;
        let mut kv1_data = self.data.clone();
        
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&kv1_data[..0x10]);
        let hmac_res = excrypt::hmac_sha(cpukey, &[&nonce])
            .map_err(|e| format!("KV key derivation failed: {}", e))?;
        
        let mut decrypt_key = [0u8; 16];
        decrypt_key.copy_from_slice(&hmac_res[..16]);

        let mut rc4 = Rc4::new(&decrypt_key)
            .map_err(|e| format!("RC4 init failed: {}", e))?;
        rc4.crypt(&mut kv1_data[0x10..])
            .map_err(|e| format!("Decryption failed: {}", e))?;

        // 2. Check if KV1 was correct
        let kv1_valid = {
            let temp_kv = Keyvault { data: kv1_data.clone(), ..self.clone() };
            temp_kv.check_decrypted_signatures()
        };
        
        let kv1_looks_like_type2 = if kv1_valid {
            let sig_region = &kv1_data[0x1DF8..0x1E00];
            let all_ff = sig_region.iter().all(|&b| b == 0xFF);
            let all_00 = sig_region.iter().all(|&b| b == 0x00);
            !(all_ff || all_00)
        } else { false };

        if kv1_valid && !kv1_looks_like_type2 {
            info!("[builder] Keyvault decrypted as Type 1 (Retail).");
            self.data = kv1_data;
            self.is_decrypted = true;
            self.hashed = false;
            let _ = self.refresh_metadata();
            return Ok(());
        }

        // 3. Try KV2 Fallback
        info!("[builder] KV1 decryption invalid or Type 2 signature found. Attempting KV2 (hashed) decryption...");
        let mut kv2_data = original_data.clone();
        
        let hmac_res_v2 = excrypt::hmac_sha(cpukey, &[&hmac_res[..16]])
            .map_err(|e| format!("KV2 double-HMAC failed: {}", e))?;
        let mut fallback_key = [0u8; 16];
        fallback_key.copy_from_slice(&hmac_res_v2[..16]);
        
        let mut rc4_v2 = Rc4::new(&fallback_key)
            .map_err(|e| format!("RC4 init failed: {}", e))?;
        rc4_v2.crypt(&mut kv2_data[0x10..])
            .map_err(|e| format!("Decryption failed: {}", e))?;

        if {
            let temp_kv = Keyvault { data: kv2_data.clone(), ..self.clone() };
            temp_kv.check_decrypted_signatures()
        } {
            info!("[builder] Keyvault decrypted as Type 2 (Hashed).");
            self.data = kv2_data;
            self.is_decrypted = true;
            self.hashed = true;
            let _ = self.refresh_metadata();
            return Ok(());
        }

        // 4. Final Fallback: Use KV1 if it was valid
        if kv1_valid {
            warn!("[builder] KV2 decryption failed but KV1 was valid. Falling back to Type 1.");
            self.data = kv1_data;
            self.is_decrypted = true;
            self.hashed = false;
            let _ = self.refresh_metadata();
            return Ok(());
        }

        Err("Keyvault decryption failed: Invalid signatures for both KV1 and KV2".to_string())
    }

    pub fn encrypt(&mut self, cpukey: &[u8; 16]) -> Result<(), String> {
        if !self.is_decrypted {
            return Ok(()); // Already encrypted or never decrypted
        }

        if self.hashed {
            // KV2 / Hashed Encryption (J-Runner Style)
            let mut message = self.data[0x10..].to_vec();
            message.extend_from_slice(&[0x07, 0x12]); // KV2 secret
            
            let salt = excrypt::hmac_sha(cpukey, &[&message])
                .map_err(|e| format!("KV2 salt derivation failed: {}", e))?;
            
            let final_key = excrypt::hmac_sha(cpukey, &[&salt[..16]])
                .map_err(|e| format!("KV2 key derivation failed: {}", e))?;
            
            let mut rc4 = Rc4::new(&final_key[..16])
                .map_err(|e| format!("RC4 init failed: {}", e))?;
            
            rc4.crypt(&mut self.data[0x10..])
                .map_err(|e| format!("Encryption failed: {}", e))?;
            
            self.data[..16].copy_from_slice(&salt[..16]);
        } else {
            // KV1 / Standard Encryption
            let mut nonce = [0u8; 16];
            nonce.copy_from_slice(&self.data[..0x10]);
            let hmac_res = excrypt::hmac_sha(cpukey, &[&nonce])
                .map_err(|e| format!("Key derivation failed: {}", e))?;
            let mut rc4 = Rc4::new(&hmac_res[..16])
                .map_err(|e| format!("RC4 init failed: {}", e))?;
            rc4.crypt(&mut self.data[0x10..])
                .map_err(|e| format!("Encryption failed: {}", e))?;
        }

        self.is_decrypted = false;
        Ok(())
    }

    /// Provides a view of the record header at the start of the KV.
    pub fn get_record(&self) -> Result<KeyvaultRecord, String> {
        KeyvaultRecord::read_from_prefix(&self.data)
            .map(|(r, _)| r)
            .map_err(|_| "Failed to map KeyvaultRecord".to_string())
    }

    // High-level accessors for sparse fields not in the Record struct yet
    
    pub fn get_serial(&self) -> String {
        let start = 0xB0;
        let end = start + 12;
        String::from_utf8_lossy(&self.data[start..end]).trim_matches(char::from(0)).to_string()
    }

    pub fn get_dvd_key(&self) -> String {
        let start = 0x100;
        let end = start + 16;
        self.data[start..end].iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn get_osig(&self) -> String {
        let start = OFFSET_OSIG_STR;
        let end = start + 28; // J-Runner reads exactly 28 bytes
        if self.data.len() >= end {
            String::from_utf8_lossy(&self.data[start..end]).trim_matches(char::from(0)).to_string()
        } else {
            "Unknown".to_string()
        }
    }

    pub fn get_kv_type(&self) -> u8 {
        // J-Runner Nand.cs:679 - Check 0x1DF8 (XEKEY_SPECIAL_KEYVAULT_SIGNATURE)
        if self.data.len() < 0x1E00 { return 1; }
        let sig_region = &self.data[0x1DF8..0x1E00];
        if sig_region.iter().all(|&b| b == 0xFF || b == 0x00) {
            1
        } else {
            2
        }
    }

    pub fn get_console_id_alt(&self) -> String {
        let start = 0x9CA;
        let end = start + 5;
        if self.data.len() > end {
            self.data[start..end].iter().map(|b| format!("{:02x}", b)).collect()
        } else {
            "Unknown".to_string()
        }
    }

    pub fn get_mf_date(&self) -> String {
        let start = OFFSET_MF_DATE;
        let end = start + 8;
        if self.data.len() > end {
            String::from_utf8_lossy(&self.data[start..end]).trim_matches(char::from(0)).to_string()
        } else {
            "Unknown".to_string()
        }
    }

    // --- Patching Methods ---

    fn ensure_decrypted(&self) -> Result<(), String> {
        if !self.is_decrypted {
            return Err("Keyvault patching requires decrypted data. Call decrypt() first.".to_string());
        }
        Ok(())
    }

    pub fn set_region(&mut self, region_code: u16) -> Result<(), String> {
        self.ensure_decrypted()?;
        let bytes = region_code.to_be_bytes();
        self.data[OFFSET_REGION..OFFSET_REGION+2].copy_from_slice(&bytes);
        let _ = self.refresh_metadata();
        Ok(())
    }

    pub fn set_serial(&mut self, serial: &str) -> Result<(), String> {
        self.ensure_decrypted()?;
        let bytes = serial.as_bytes();
        let len = bytes.len().min(12);
        self.data[OFFSET_SERIAL..OFFSET_SERIAL+12].fill(0);
        self.data[OFFSET_SERIAL..OFFSET_SERIAL+len].copy_from_slice(&bytes[..len]);
        let _ = self.refresh_metadata();
        Ok(())
    }

    pub fn set_mf_date(&mut self, date: &str) -> Result<(), String> {
        self.ensure_decrypted()?;
        let bytes = date.as_bytes();
        let len = bytes.len().min(8);
        self.data[OFFSET_MF_DATE..OFFSET_MF_DATE+8].fill(0);
        self.data[OFFSET_MF_DATE..OFFSET_MF_DATE+len].copy_from_slice(&bytes[..len]);
        let _ = self.refresh_metadata();
        Ok(())
    }

    pub fn set_osig(&mut self, osig: &str) -> Result<(), String> {
        self.ensure_decrypted()?;
        if osig.len() != 32 {
            return Err(format!("OSIG string must be exactly 32 characters (got {})", osig.len()));
        }
        self.data[OFFSET_OSIG_STR..OFFSET_OSIG_STR+32].copy_from_slice(osig.as_bytes());
        let _ = self.refresh_metadata();
        Ok(())
    }

    pub fn set_console_id(&mut self, id: &[u8; 5]) -> Result<(), String> {
        self.ensure_decrypted()?;
        self.data[OFFSET_CONSOLE_ID..OFFSET_CONSOLE_ID+5].copy_from_slice(id);
        let _ = self.refresh_metadata();
        Ok(())
    }

    pub fn set_dvd_key(&mut self, key: &[u8; 16]) -> Result<(), String> {
        self.ensure_decrypted()?;
        self.data[OFFSET_DVD_KEY..OFFSET_DVD_KEY+16].copy_from_slice(key);
        let _ = self.refresh_metadata();
        Ok(())
    }

    /// Patches the FCRT requirement in the Keyvault.
    /// Setting this to false (bits cleared) is often required for custom builds
    /// to bypass mandatory DVD drive matching.
    pub fn apply_fcrt_patch(&mut self, enabled: bool) -> Result<(), String> {
        self.ensure_decrypted()?;
        // J-Runner updatekvval() L684: FCRT check reads u16 at 0x1C (BE) and tests bits 0x120.
        // We set/clear those same bits rather than writing the whole field, preserving
        // any other flags in the hardware flags word.
        let mut flags = u16::from_be_bytes(self.data[OFFSET_FCRT_FLAG..OFFSET_FCRT_FLAG+2].try_into().unwrap());
        if enabled { flags |= 0x0120; } else { flags &= !0x0120; }
        self.data[OFFSET_FCRT_FLAG..OFFSET_FCRT_FLAG+2].copy_from_slice(&flags.to_be_bytes());
        let _ = self.refresh_metadata();
        Ok(())
    }

    // kv.get_record().map(|r| r.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kv_decryption_detection() {
        // Primary detection: data[0x40..0x60] all-zero (J-Runner updatekvval() L669)
        let data = vec![0u8; 0x4000];
        let kv = Keyvault::parse(&data).unwrap();
        assert!(kv.is_decrypted, "Should detect decrypted KV via zero-pad region");

        // Fallback OSIG detection on non-zero buffer where zero-pad doesn't trigger
        let mut data2 = vec![0xAAu8; 0x4000];
        data2[0xC82..0xC86].copy_from_slice(b"OSIG");
        let kv2 = Keyvault::parse(&data2).unwrap();
        assert!(kv2.is_decrypted, "Should detect decrypted KV via OSIG fallback");

        // Fallback DRM detection
        let mut data3 = vec![0xAAu8; 0x4000];
        data3[0x1F64..0x1F67].copy_from_slice(b"DRM");
        let kv3 = Keyvault::parse(&data3).unwrap();
        assert!(kv3.is_decrypted, "Should detect decrypted KV via DRM fallback");

        // Encrypted KV: non-zero junk, no magic -> not decrypted
        let data4 = vec![0xAAu8; 0x4000];
        let kv4 = Keyvault::parse(&data4).unwrap();
        assert!(!kv4.is_decrypted, "Non-zero non-magic buffer should be encrypted");
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
        assert_eq!(res.unwrap_err(), "Keyvault patching requires decrypted data. Call decrypt() first.");
    }

    #[test]
    fn test_kv_region_patch() {
        let mut data = vec![0u8; 0x4000];
        data[0xC82..0xC86].copy_from_slice(b"OSIG"); // Force decrypted state
        let mut kv = Keyvault::parse(&data).unwrap();
        
        kv.set_region(0x02FE).unwrap();
        assert_eq!(&kv.data[OFFSET_REGION..OFFSET_REGION+2], &[0x02, 0xFE]);
    }

    #[test]
    fn test_kv_serial_patch() {
        let mut data = vec![0u8; 0x4000];
        data[0xC82..0xC86].copy_from_slice(b"OSIG");
        let mut kv = Keyvault::parse(&data).unwrap();
        
        kv.set_serial("123456789012").unwrap();
        assert_eq!(&kv.data[OFFSET_SERIAL..OFFSET_SERIAL+12], b"123456789012");
        
        kv.set_serial("SHORT").unwrap();
        assert_eq!(&kv.data[OFFSET_SERIAL..OFFSET_SERIAL+5], b"SHORT");
        assert_eq!(kv.data[OFFSET_SERIAL+5], 0, "Should be null padded");
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
        assert_eq!(&kv.data[OFFSET_OSIG_STR..OFFSET_OSIG_STR+32], valid_osig.as_bytes());
    }

    #[test]
    fn test_kv_fcrt_patch() {
        let mut data = vec![0u8; 0x4000];
        data[0xC82..0xC86].copy_from_slice(b"OSIG");
        let mut kv = Keyvault::parse(&data).unwrap();

        kv.apply_fcrt_patch(false).unwrap();
        // OFFSET_FCRT_FLAG = 0x1C; 2-byte BE field; mask 0x120 cleared
        assert_eq!(&kv.data[OFFSET_FCRT_FLAG..OFFSET_FCRT_FLAG+2], &[0x00, 0x00]);
        assert!(!kv.metadata.as_ref().unwrap().fcrt);

        kv.apply_fcrt_patch(true).unwrap();
        // 0x0120 in big-endian = [0x01, 0x20]
        assert_eq!(&kv.data[OFFSET_FCRT_FLAG..OFFSET_FCRT_FLAG+2], &[0x01, 0x20]);
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
