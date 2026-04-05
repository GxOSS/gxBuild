use std::sync::Mutex;
use super::{Result, CryptoError, ExCryptRsa, ExCryptSig, ExCryptRsaPub1024};

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum XeKey {
    ManufacturingMode = 0x0,
    AlternateKeyVault = 0x1,
    RestrictedPrivilegeFlags = 0x2,
    ReservedByte3 = 0x3,
    OddFeatures = 0x4,
    OddAuthType = 0x5,
    RestrictedHvExtLoader = 0x6,
    PolicyFlashSize = 0x7,
    PolicyBuiltinUsbMuSize = 0x8,
    ReservedDword4 = 0x9,
    RestrictedPrivileges = 0xA,
    ReservedQword2 = 0xB,
    ReservedQword3 = 0xC,
    ReservedQword4 = 0xD,
    ReservedKey1 = 0xE,
    ReservedKey2 = 0xF,
    ReservedKey3 = 0x10,
    ReservedKey4 = 0x11,
    ReservedRandomKey1 = 0x12,
    ReservedRandomKey2 = 0x13,
    ConsoleSerialNumber = 0x14,
    MoboSerialNumber = 0x15,
    GameRegion = 0x16,
    ConsoleObfuscationKey = 0x17,
    KeyObfuscationKey = 0x18,
    RoamableObfuscationKey = 0x19,
    DvdKey = 0x1A,
    PrimaryActivationKey = 0x1B,
    SecondaryActivationKey = 0x1C,
    GlobalDevice2DesKey1 = 0x1D,
    GlobalDevice2DesKey2 = 0x1E,
    WirelessControllerMs2DesKey1 = 0x1F,
    WirelessControllerMs2DesKey2 = 0x20,
    WiredWebcamMs2DesKey1 = 0x21,
    WiredWebcamMs2DesKey2 = 0x22,
    WiredControllerMs2DesKey1 = 0x23,
    WiredControllerMs2DesKey2 = 0x24,
    MemoryUnitMs2DesKey1 = 0x25,
    MemoryUnitMs2DesKey2 = 0x26,
    OtherXsm3DeviceMs2DesKey1 = 0x27,
    OtherXsm3DeviceMs2DesKey2 = 0x28,
    WirelessController3p2DesKey1 = 0x29,
    WirelessController3p2DesKey2 = 0x2A,
    WiredWebcam3p2DesKey1 = 0x2B,
    WiredWebcam3p2DesKey2 = 0x2C,
    WiredController3p2DesKey1 = 0x2D,
    WiredController3p2DesKey2 = 0x2E,
    MemoryUnit3p2DesKey1 = 0x2F,
    MemoryUnit3p2DesKey2 = 0x30,
    OtherXsm3Device3p2DesKey1 = 0x31,
    OtherXsm3Device3p2DesKey2 = 0x32,
    ConsolePrivateKey = 0x33,
    XeikaPrivateKey = 0x34,
    CardeaPrivateKey = 0x35,
    ConsoleCertificate = 0x36,
    XeikaCertificate = 0x37,
    CardeaCertificate = 0x38,
}

extern "C" {
    pub fn ExKeysKeyVaultLoaded() -> i32;
    pub fn ExKeysLoadKeyVault(decrypted_kv: *const u8, length: u32) -> i32;
    pub fn ExKeysLoadKeyVaultFromPath(filepath: *const i8) -> i32;
    pub fn ExKeysGetKey(key_idx: u32, output: *mut u8, output_size: *mut u32) -> i32;
    pub fn ExKeysConsolePrivateKeySign(hash: *const u8, output_cert_sig: *mut u8) -> i32;
    pub fn ExKeysPkcs1Verify(hash: *const u8, input_sig: *const u8, key: *const ExCryptRsa) -> i32;
    pub fn ExKeysObfuscate(roaming: i32, input: *const u8, input_size: u32, output: *mut u8, output_size: *mut u32) -> i32;
    pub fn ExKeysUnObfuscate(roaming: i32, input: *const u8, input_size: u32, output: *mut u8, output_size: *mut u32) -> i32;
}

static EXKEYS_LOCK: Mutex<()> = Mutex::new(());

pub struct KeyManager;

impl KeyManager {
    pub fn load_vault(data: &[u8]) -> Result<()> {
        let _lock = EXKEYS_LOCK.lock().unwrap();
        unsafe {
            if ExKeysLoadKeyVault(data.as_ptr(), data.len() as u32) == 0 {
                return Err(CryptoError::FfiError);
            }
        }
        Ok(())
    }

    pub fn get_key(key: XeKey) -> Result<Vec<u8>> {
        let _lock = EXKEYS_LOCK.lock().unwrap();
        let mut output = vec![0u8; 256];
        let mut size = 256u32;
        unsafe {
            if ExKeysGetKey(key as u32, output.as_mut_ptr(), &mut size) == 0 {
                return Err(CryptoError::FfiError);
            }
        }
        output.truncate(size as usize);
        Ok(output)
    }

    pub fn sign_hash(hash: &[u8]) -> Result<[u8; 0x100]> {
        let _lock = EXKEYS_LOCK.lock().unwrap();
        let mut sig = [0u8; 0x100];
        unsafe {
            if ExKeysConsolePrivateKeySign(hash.as_ptr(), sig.as_mut_ptr()) == 0 {
                return Err(CryptoError::FfiError);
            }
        }
        Ok(sig)
    }

    pub fn obfuscate(data: &[u8], roaming: bool) -> Result<Vec<u8>> {
        let _lock = EXKEYS_LOCK.lock().unwrap();
        let mut output = vec![0u8; data.len() + 256]; // Buffer room
        let mut size = output.len() as u32;
        unsafe {
            if ExKeysObfuscate(roaming as i32, data.as_ptr(), data.len() as u32, output.as_mut_ptr(), &mut size) == 0 {
                return Err(CryptoError::FfiError);
            }
        }
        output.truncate(size as usize);
        Ok(output)
    }

    pub fn unobfuscate(data: &[u8], roaming: bool) -> Result<Vec<u8>> {
        let _lock = EXKEYS_LOCK.lock().unwrap();
        let mut output = vec![0u8; data.len()];
        let mut size = output.len() as u32;
        unsafe {
            if ExKeysUnObfuscate(roaming as i32, data.as_ptr(), data.len() as u32, output.as_mut_ptr(), &mut size) == 0 {
                return Err(CryptoError::FfiError);
            }
        }
        output.truncate(size as usize);
        Ok(output)
    }
}
