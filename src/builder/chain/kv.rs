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

#[derive(Clone)]
pub struct Keyvault {
    pub data: Vec<u8>,
}

impl Keyvault {
    pub const SIZE: usize = 0x4000;

    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err(format!("Keyvault data too small: {} bytes (expected {})", data.len(), Self::SIZE));
        }
        Ok(Self {
            data: data[..Self::SIZE].to_vec(),
        })
    }

    pub fn decrypt(&mut self, cpukey: &[u8; 16]) -> Result<(), String> {
        if self.data.len() < 0x10 {
            return Err("Keyvault too small for decryption".to_string());
        }

        // 1. Extract the HMAC-SHA1 Nonce (first 16 bytes)
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&self.data[..0x10]);

        // 2. Derive the RC4 key: HMAC-SHA1(CPUKey, Nonce)
        let hmac_res = excrypt::hmac_sha(cpukey, &[&nonce])
            .map_err(|e| format!("Key derivation failed: {}", e))?;
        
        let mut decrypt_key = [0u8; 16];
        decrypt_key.copy_from_slice(&hmac_res[..16]);
        info!("[builder] Keyvault Decryption Key Derived: {:02x?}", decrypt_key);

        // 3. Decrypt the rest of the KV (0x10 to end) using RC4
        let mut rc4 = Rc4::new(&decrypt_key)
            .map_err(|e| format!("RC4 init failed: {}", e))?;
        
        rc4.crypt(&mut self.data[0x10..])
            .map_err(|e| format!("Decryption failed: {}", e))?;

        if let Ok(rec) = self.get_record() {
            info!("[builder] Keyvault decrypted: version={}, serial={}", rec.version.get(), self.get_serial());
        };

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
            // KV1 / Standard Encryption (Symmetric to Decryption)
            self.decrypt(cpukey)?;
        }
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
        let start = 0xC92;
        let end = start + 28;
        if self.data.len() > end {
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
        let start = 0x9E4;
        let end = start + 8;
        if self.data.len() > end {
            String::from_utf8_lossy(&self.data[start..end]).trim_matches(char::from(0)).to_string()
        } else {
            "Unknown".to_string()
        }
    }

    // kv.get_record().map(|r| r.clone())
}
