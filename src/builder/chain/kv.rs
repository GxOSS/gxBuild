/*
    kv.rs - Handling for Xbox 360 Keyvault (KV).

    Modified for GGX by Exposure / Zach
*/

use zerocopy::FromBytes;
use zerocopy::byteorder::{U16, BigEndian};
use crate::builder::deps::excrypt::{self, Rc4};
use log::info;

/// Keyvault record header — covers the first 0x110 bytes.
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
}

#[derive(Clone)]
pub struct Keyvault {
    pub data: Vec<u8>,
    pub is_decrypted: bool,
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
pub const OFFSET_FCRT_FLAG: usize = 0x2C;   // 4 bytes (Hardware Flags)

impl Keyvault {
    pub const SIZE: usize = 0x4000;

    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err(format!("Keyvault data too small: {} bytes (expected {})", data.len(), Self::SIZE));
        }
        let mut kv = Self {
            data: data[..Self::SIZE].to_vec(),
            is_decrypted: false,
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

        // Hardware flags at 0x2C
        let flags = u32::from_be_bytes(self.data[OFFSET_FCRT_FLAG..OFFSET_FCRT_FLAG+4].try_into().unwrap());

        let meta = KeyvaultMetadata {
            serial: self.get_serial(),
            region: u16::from_be_bytes(self.data[OFFSET_REGION..OFFSET_REGION+2].try_into().unwrap()),
            dvd_key: self.data[OFFSET_DVD_KEY..OFFSET_DVD_KEY+16].try_into().unwrap(),
            console_id: self.data[OFFSET_CONSOLE_ID..OFFSET_CONSOLE_ID+5].try_into().unwrap(),
            mf_date: self.get_mf_date(),
            osig: self.get_osig(),
            fcrt: (flags & 0x100) != 0 || (flags == 0x100), // Flexible check for FCRT bit/value
            console_type: u32::from_be_bytes(self.data[0x9E0..0x9E4].try_into().unwrap()),
            version: record.version.get(),
        };

        self.metadata = Some(meta);
        Ok(())
    }

    /// Heuristic to detect if the data is already decrypted by looking for 
    /// "OSIG" and "DRM" signatures in the certificates.
    fn check_decrypted_signatures(&self) -> bool {
        if self.data.len() < 0x2000 { return false; }

        // Raw NAND Offsets for signatures in a decrypted KV
        let osig_sig = &self.data[0xC82..0xC86];  // "OSIG"
        let drm_sig = &self.data[0x1F64..0x1F67]; // "DRM"

        (osig_sig == b"OSIG") || (drm_sig == b"DRM")
    }

    pub fn decrypt(&mut self, cpukey: &[u8; 16], hashed: bool) -> Result<(), String> {
        if self.data.len() < 0x10 {
            return Err("Keyvault too small for decryption".to_string());
        }

        let mut decrypt_key = [0u8; 16];

        if hashed {
            // KV2 / Hashed Decryption
            // 1. Calculate salt: HMAC-SHA1(CPUKey, DecryptedData[0x10..] + {0x07, 0x12})
            // Wait, decryption for hashed KV uses the salt (nonce) at [0..16]
            let mut nonce = [0u8; 16];
            nonce.copy_from_slice(&self.data[..0x10]);

            // Derive key: HMAC-SHA1(CPUKey, Nonce[0..16])
            let hmac_res = excrypt::hmac_sha(cpukey, &[&nonce])
                .map_err(|e| format!("KV2 key derivation failed: {}", e))?;
            decrypt_key.copy_from_slice(&hmac_res[..16]);
            info!("[builder] KV2 Decryption Key Derived: {:02x?}", decrypt_key);
        } else {
            // KV1 / Standard Decryption
            // 1. Extract the HMAC-SHA1 Nonce (first 16 bytes)
            let mut nonce = [0u8; 16];
            nonce.copy_from_slice(&self.data[..0x10]);

            // 2. Derive the RC4 key: HMAC-SHA1(CPUKey, Nonce)
            let hmac_res = excrypt::hmac_sha(cpukey, &[&nonce])
                .map_err(|e| format!("Key derivation failed: {}", e))?;
            decrypt_key.copy_from_slice(&hmac_res[..16]);
            info!("[builder] Keyvault Decryption Key Derived: {:02x?}", decrypt_key);
        }

        // 3. Decrypt the rest of the KV (0x10 to end) using RC4
        let mut rc4 = Rc4::new(&decrypt_key)
            .map_err(|e| format!("RC4 init failed: {}", e))?;
        
        rc4.crypt(&mut self.data[0x10..])
            .map_err(|e| format!("Decryption failed: {}", e))?;

        if let Ok(rec) = self.get_record() {
            info!("[builder] Keyvault decrypted: version={}, serial={}", rec.version.get(), self.get_serial());
        };

        self.is_decrypted = true;
        let _ = self.refresh_metadata();
        Ok(())
    }

    pub fn encrypt(&mut self, cpukey: &[u8; 16], hashed: bool) -> Result<(), String> {
        if hashed {
            // KV2 / Hashed Encryption
            // 1. Calculate salt: HMAC-SHA1(CPUKey, DecryptedData[0x10..] + {0x07, 0x12})
            let mut message = self.data[0x10..].to_vec();
            message.extend_from_slice(&[0x07, 0x12]); // "Secret" used for hashed KV
            
            let salt = excrypt::hmac_sha(cpukey, &[&message])
                .map_err(|e| format!("KV2 salt derivation failed: {}", e))?;
            info!("[builder] KV2 Hashed Salt calculated: {:02x?}", salt);
            
            // 2. Derive real RC4 key: HMAC-SHA1(CPUKey, Salt[0..16])
            let final_key = excrypt::hmac_sha(cpukey, &[&salt[..16]])
                .map_err(|e| format!("KV2 key derivation failed: {}", e))?;
            
            // 3. Encrypt payload with the derived key
            let mut rc4 = Rc4::new(&final_key[..16])
                .map_err(|e| format!("RC4 init failed: {}", e))?;
            
            rc4.crypt(&mut self.data[0x10..])
                .map_err(|e| format!("Encryption failed: {}", e))?;
            
            // 4. Store the salt in the first 16 bytes
            self.data[..16].copy_from_slice(&salt[..16]);
        } else {
            // KV1 / Standard Encryption (Symmetric to Decryption - just call the inner RC4 logic)
            // No recursive call to itself which would use the wrong branch.
            self.decrypt(cpukey, false)?;
        }
        self.is_decrypted = false;
        self.metadata = None;
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
        let end = start + 32;
        if self.data.len() >= end {
            String::from_utf8_lossy(&self.data[start..end]).trim_matches(char::from(0)).to_string()
        } else {
            "Unknown".to_string()
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
    /// Setting this to false (bit cleared) is often required for custom builds 
    /// to bypass mandatory DVD drive matching.
    pub fn apply_fcrt_patch(&mut self, enabled: bool) -> Result<(), String> {
        self.ensure_decrypted()?;
        // Bit 8 of DWORD at 0x2C is usually the FCRT flag
        // However, many tools just zero the whole DWORD or set specific bits.
        // Consistent with J-Runner / xeBuild patches.
        let val: u32 = if enabled { 0x0100 } else { 0x0000 };
        let bytes = val.to_be_bytes();
        self.data[OFFSET_FCRT_FLAG..OFFSET_FCRT_FLAG+4].copy_from_slice(&bytes);
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
        let mut data = vec![0u8; 0x4000];
        // Inject OSIG signature at decrypted offset
        data[0xC82..0xC86].copy_from_slice(b"OSIG");
        
        let kv = Keyvault::parse(&data).unwrap();
        assert!(kv.is_decrypted, "Should detect decrypted KV via OSIG signature");

        let mut data2 = vec![0u8; 0x4000];
        data2[0x1F64..0x1F67].copy_from_slice(b"DRM");
        let kv2 = Keyvault::parse(&data2).unwrap();
        assert!(kv2.is_decrypted, "Should detect decrypted KV via DRM signature");
    }

    #[test]
    fn test_kv_patching_guards() {
        let data = vec![0u8; 0x4000];
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
        assert_eq!(&kv.data[OFFSET_FCRT_FLAG..OFFSET_FCRT_FLAG+4], &[0, 0, 0, 0]);
        
        kv.apply_fcrt_patch(true).unwrap();
        assert_eq!(&kv.data[OFFSET_FCRT_FLAG..OFFSET_FCRT_FLAG+4], &[0, 0, 1, 0]); // 0x0100 BE
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
        kv.encrypt(&[0u8; 16], false).unwrap();
        assert!(kv.metadata.is_none());
        assert!(!kv.is_decrypted);
    }
}
