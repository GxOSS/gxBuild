/*
BSD 3-Clause License

Copyright (c) 2020, emoose
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

use super::{CryptoError, Result};
use crate::crypto::rc4::{ExCryptRc4, ExCryptRc4Ecb, ExCryptRc4Key, ExCryptRc4State};
use crate::crypto::rsa::{
    ExCryptBnDwLePkcs1Format, ExCryptBnDwLePkcs1Verify, ExCryptBnQwNeRsaPrvCrypt, ExCryptBnQwNeRsaPubCrypt, ExCryptRsa, ExCryptRsaPrv1024, ExCryptRsaPub1024,
};
use crate::crypto::sha::{ExCryptHmacSha, ExCryptSha};
use crate::crypto::{ExCryptBnQw_SwapDwQwLeBe, ExCryptMemDiff};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{LazyLock, Mutex};

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
    ConstantMasterKey = 0x3C,
}

static EX_IMPORTED_KEYS: LazyLock<Mutex<HashMap<u32, Vec<u8>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static EX_KEY_VAULT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

const K_ROAMABLE_OBFUSCATION_KEY_RETAIL: [u8; 16] = [0xE1, 0xBC, 0x15, 0x9C, 0x73, 0xB1, 0xEA, 0xE9, 0xAB, 0x31, 0x70, 0xF3, 0xAD, 0x47, 0xEB, 0xF3];
const K_ROAMABLE_OBFUSCATION_KEY_DEVKIT: [u8; 16] = [0xDA, 0xB6, 0x9A, 0xD9, 0x8E, 0x28, 0x76, 0x4F, 0x97, 0x7E, 0xE2, 0x48, 0x7E, 0x4F, 0x3F, 0x68];

fn key_properties(key_idx: u32) -> Option<(u32, u32)> {
    match key_idx {
        0x0 => Some((0x8, 0x1)),
        0x1 => Some((0x9, 0x1)),
        0x2 => Some((0xA, 0x1)),
        0x3 => Some((0xB, 0x1)),
        0x4 => Some((0xC, 0x2)),
        0x5 => Some((0xE, 0x2)),
        0x6 => Some((0x10, 0x4)),
        0x7 => Some((0x14, 0x4)),
        0x8 => Some((0x18, 0x4)),
        0x9 => Some((0x1C, 0x4)),
        0xA => Some((0x20, 0x8)),
        0xB => Some((0x28, 0x8)),
        0xC => Some((0x30, 0x8)),
        0xD => Some((0x38, 0x8)),
        0xE => Some((0x40, 0x10)),
        0xF => Some((0x50, 0x10)),
        0x10 => Some((0x60, 0x10)),
        0x11 => Some((0x70, 0x10)),
        0x12 => Some((0x80, 0x10)),
        0x13 => Some((0x90, 0x10)),
        0x14 => Some((0xA0, 0xC)),
        0x15 => Some((0xAC, 0xC)),
        0x16 => Some((0xB8, 0x2)),
        0x17 => Some((0xC0, 0x10)),
        0x18 => Some((0xD0, 0x10)),
        0x19 => Some((0xE0, 0x10)),
        0x1A => Some((0xF0, 0x10)),
        0x1B => Some((0x100, 0x18)),
        0x1C => Some((0x118, 0x10)),
        0x1D => Some((0x128, 0x10)),
        0x1E => Some((0x138, 0x10)),
        0x1F => Some((0x148, 0x10)),
        0x20 => Some((0x158, 0x10)),
        0x21 => Some((0x168, 0x10)),
        0x22 => Some((0x178, 0x10)),
        0x23 => Some((0x188, 0x10)),
        0x24 => Some((0x198, 0x10)),
        0x25 => Some((0x1A8, 0x10)),
        0x26 => Some((0x1B8, 0x10)),
        0x27 => Some((0x1C8, 0x10)),
        0x28 => Some((0x1D8, 0x10)),
        0x29 => Some((0x1E8, 0x10)),
        0x2A => Some((0x1F8, 0x10)),
        0x2B => Some((0x208, 0x10)),
        0x2C => Some((0x218, 0x10)),
        0x2D => Some((0x228, 0x10)),
        0x2E => Some((0x238, 0x10)),
        0x2F => Some((0x248, 0x10)),
        0x30 => Some((0x258, 0x10)),
        0x31 => Some((0x268, 0x10)),
        0x32 => Some((0x278, 0x10)),
        0x33 => Some((0x288, 0x1D0)),
        0x34 => Some((0x458, 0x390)),
        0x35 => Some((0x7E8, 0x1D0)),
        0x36 => Some((0x9B8, 0x1A8)),
        0x37 => Some((0xB60, 0x1288)),
        0x38 => Some((0x1EE8, 0x2108)),
        0x44 => Some((0x1DF8, 0x100)),
        _ => None,
    }
}

fn is_key_supported(key_idx: u32) -> bool {
    let vault_loaded = !EX_KEY_VAULT.lock().unwrap().is_empty();
    let has_property = key_properties(key_idx).is_some();
    let imported = EX_IMPORTED_KEYS.lock().unwrap().contains_key(&key_idx);
    (vault_loaded && has_property) || imported
}

fn ex_keys_key_vault_setup() {
    let roamable_key = ex_keys_get_key_ptr(XeKey::RoamableObfuscationKey as u32);
    let console_type = ex_keys_get_console_type();
    let key = if console_type == 2 {
        K_ROAMABLE_OBFUSCATION_KEY_RETAIL
    } else {
        K_ROAMABLE_OBFUSCATION_KEY_DEVKIT
    };
    if !roamable_key.is_null() {
        unsafe {
            std::slice::from_raw_parts_mut(roamable_key, 16).copy_from_slice(&key);
        }
    }
}

fn ex_keys_load_key_vault(data: &[u8]) -> bool {
    if data.len() < 0x3FF0 {
        return false;
    }
    let offset = if data.len() >= 0x4000 { 0x10 } else { 0 };
    {
        let mut vault = EX_KEY_VAULT.lock().unwrap();
        *vault = data[offset..].to_vec();
    }
    ex_keys_key_vault_setup();
    true
}

fn ex_keys_get_key(key_idx: u32, output: Option<&mut [u8]>) -> Option<u32> {
    if !is_key_supported(key_idx) {
        return None;
    }

    {
        let imported = EX_IMPORTED_KEYS.lock().unwrap();
        if let Some(key) = imported.get(&key_idx) {
            let size = key.len() as u32;
            if let Some(out) = output {
                let len = out.len().min(key.len());
                out[..len].copy_from_slice(&key[..len]);
            }
            return Some(size);
        }
    }

    let vault = EX_KEY_VAULT.lock().unwrap();
    if vault.is_empty() {
        return None;
    }

    let (offset, size) = key_properties(key_idx)?;
    if let Some(out) = output {
        let len = out.len().min(size as usize);
        out[..len].copy_from_slice(&vault[offset as usize..offset as usize + len]);
    }
    Some(size)
}

fn ex_keys_get_key_ptr(key_idx: u32) -> *mut u8 {
    if !is_key_supported(key_idx) {
        return std::ptr::null_mut();
    }

    {
        let mut imported = EX_IMPORTED_KEYS.lock().unwrap();
        if let Some(key) = imported.get_mut(&key_idx) {
            return key.as_mut_ptr();
        }
    }

    let mut vault = EX_KEY_VAULT.lock().unwrap();
    let (offset, _) = key_properties(key_idx).unwrap();
    unsafe { vault.as_mut_ptr().add(offset as usize) }
}

fn ex_keys_get_key_properties(key_idx: u32) -> u32 {
    if !is_key_supported(key_idx) {
        return 0;
    }
    {
        let imported = EX_IMPORTED_KEYS.lock().unwrap();
        if let Some(key) = imported.get(&key_idx) {
            return key.len() as u32;
        }
    }
    key_properties(key_idx).map(|(_, size)| size).unwrap_or(0)
}

fn ex_keys_get_console_type() -> u32 {
    let ptr = ex_keys_get_key_ptr(XeKey::ConsoleCertificate as u32);
    if ptr.is_null() {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr.add(0x18), 4) };
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysKeyVaultLoaded() -> i32 {
    (!EX_KEY_VAULT.lock().unwrap().is_empty()) as i32
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysLoadKeyVault(decrypted_kv: *const u8, length: u32) -> i32 {
    let data = std::slice::from_raw_parts(decrypted_kv, length as usize);
    ex_keys_load_key_vault(data) as i32
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysLoadKeyVaultFromPath(filepath: *const i8) -> i32 {
    let path = match std::ffi::CStr::from_ptr(filepath).to_str() {
        Ok(s) => std::path::Path::new(s),
        Err(_) => return 0,
    };
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let mut filesize = match file.metadata() {
        Ok(m) => m.len() as usize,
        Err(_) => return 0,
    };
    if filesize < 0x3FF0 {
        return 0;
    }
    let mut contents = Vec::new();
    if filesize >= 0x4000 {
        if file.seek(SeekFrom::Start(0x10)).is_err() {
            return 0;
        }
        filesize -= 0x10;
    }
    contents.resize(filesize, 0);
    if file.read_exact(&mut contents).is_err() {
        return 0;
    }
    {
        let mut vault = EX_KEY_VAULT.lock().unwrap();
        *vault = contents;
    }
    ex_keys_key_vault_setup();
    1
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysIsKeySupported(key_idx: u32) -> i32 {
    is_key_supported(key_idx) as i32
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysSetKey(key_idx: u32, input: *const u8, size: u32) -> i32 {
    let data = std::slice::from_raw_parts(input, size as usize);
    EX_IMPORTED_KEYS.lock().unwrap().insert(key_idx, data.to_vec());
    1
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysGetKey(key_idx: u32, output: *mut u8, output_size: *mut u32) -> i32 {
    if !output_size.is_null() {
        *output_size = 0;
    }
    let out = if output.is_null() || output_size.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts_mut(output, *output_size as usize))
    };
    match ex_keys_get_key(key_idx, out) {
        Some(size) => {
            if !output_size.is_null() {
                *output_size = size;
            }
            1
        }
        None => 0,
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysGetKeyPtr(key_idx: u32) -> *mut u8 {
    ex_keys_get_key_ptr(key_idx)
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysGetKeyProperties(key_idx: u32) -> u32 {
    ex_keys_get_key_properties(key_idx)
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysGetConsoleCertificate(output: *mut u8) -> u32 {
    let mut length = 0u32;
    ExKeysGetKey(0x36, output, &mut length);
    0
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysGetConsoleID(raw_bytes: *mut u8, hex_string: *mut i8) -> u32 {
    let ptr = ex_keys_get_key_ptr(0x36);
    if ptr.is_null() {
        return 0;
    }
    let console_cert = std::slice::from_raw_parts(ptr, 0x1A8);
    if !raw_bytes.is_null() {
        std::slice::from_raw_parts_mut(raw_bytes, 5).copy_from_slice(&console_cert[2..7]);
    }
    if !hex_string.is_null() {
        let mut counter: u64 = 0;
        for i in 0..5 {
            counter = console_cert[2 + i] as u64 + counter * 0x100;
        }
        let s = format!("{:011}{:x}", counter >> 4, counter & 0xF);
        let s_bytes = s.as_bytes();
        let out = std::slice::from_raw_parts_mut(hex_string as *mut u8, 0xC);
        let len = s_bytes.len().min(0xC);
        out[..len].copy_from_slice(&s_bytes[..len]);
    }
    0
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysGetConsoleType() -> u32 {
    ex_keys_get_console_type()
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysGetConsolePrivateKey(output: *mut ExCryptRsaPrv1024) -> u32 {
    let mut length = 0u32;
    ExKeysGetKey(0x33, output as *mut u8, &mut length);
    0
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysQwNeRsaPrvCrypt(key_idx: u32, input: *const u64, output: *mut u64) -> i32 {
    if key_idx != 0x33 && key_idx != 0x34 && key_idx != 0x35 {
        return 0;
    }
    if key_idx == 0x34 {
        return 0;
    }
    let key_ptr = ex_keys_get_key_ptr(key_idx);
    if key_ptr.is_null() {
        return 0;
    }
    ExCryptBnQwNeRsaPrvCrypt(input, output, key_ptr as *const ExCryptRsa)
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysConsolePrivateKeySign(hash: *const u8, output_cert_sig: *mut u8) -> i32 {
    let mut sig_buf = [0u64; 0x10];
    ExCryptBnDwLePkcs1Format(hash, 0, sig_buf.as_mut_ptr() as *mut u8, 0x10 * 8);
    ExCryptBnQw_SwapDwQwLeBe(sig_buf.as_ptr(), sig_buf.as_mut_ptr(), 0x10);
    if ExKeysQwNeRsaPrvCrypt(0x33, sig_buf.as_ptr(), sig_buf.as_mut_ptr()) == 0 {
        return 0;
    }
    ExCryptBnQw_SwapDwQwLeBe(sig_buf.as_ptr(), (output_cert_sig.add(0x1A8)) as *mut u64, 0x10);
    ExKeysGetConsoleCertificate(output_cert_sig);
    1
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysPkcs1Verify(hash: *const u8, input_sig: *const u8, key: *const ExCryptRsa) -> i32 {
    let mut temp_sig = [0u64; 0x20];
    let key_digits = (*key).num_digits.swap_bytes();
    let modulus_size = key_digits * 8;
    if modulus_size > 0x200 {
        return 0;
    }
    ExCryptBnQw_SwapDwQwLeBe(input_sig as *const u64, temp_sig.as_mut_ptr(), key_digits);
    if ExCryptBnQwNeRsaPubCrypt(temp_sig.as_ptr(), temp_sig.as_mut_ptr(), key) == 0 {
        return 0;
    }
    ExCryptBnQw_SwapDwQwLeBe(temp_sig.as_ptr(), temp_sig.as_mut_ptr(), key_digits);
    ExCryptBnDwLePkcs1Verify(hash, temp_sig.as_ptr() as *const u8, modulus_size)
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysConsoleSignatureVerification(hash: *const u8, input_signature: *mut u8, compare_result: *mut i32) -> i32 {
    let mut our_console_cert = [0u8; 0x1A8];
    let mut master_key = [0u8; 0x110];
    ExKeysGetConsoleCertificate(our_console_cert.as_mut_ptr());

    let diff = ExCryptMemDiff(our_console_cert.as_ptr(), input_signature, 0x1A8);
    if !compare_result.is_null() {
        *compare_result = diff;
    }

    let mut master_key_size = 0x110u32;
    if ExKeysGetKey(0x3C, master_key.as_mut_ptr(), &mut master_key_size) == 0 {
        master_key.fill(0);
        master_key_size = 0;
    }

    if master_key_size == 0x110 && u32::from_be_bytes([master_key[0], master_key[1], master_key[2], master_key[3]]) == 0x20 {
        let mut cert_checksum = [0u8; 0x14];
        ExCryptSha(input_signature, 0xA8, std::ptr::null(), 0, std::ptr::null(), 0, cert_checksum.as_mut_ptr(), 0x14);
        if ExKeysPkcs1Verify(cert_checksum.as_ptr(), input_signature.add(0xA8), master_key.as_ptr() as *const ExCryptRsa) != 0 {
            let mut console_public_key = ExCryptRsaPub1024 { rsa: ExCryptRsa { num_digits: (0x10u32).swap_bytes(), pub_exponent: 0, reserved: 0 }, modulus: [0u64; 16] };
            let pub_exp_bytes = std::slice::from_raw_parts(input_signature.add(0x24), 4);
            console_public_key.rsa.pub_exponent = u32::from_le_bytes([pub_exp_bytes[0], pub_exp_bytes[1], pub_exp_bytes[2], pub_exp_bytes[3]]);
            std::slice::from_raw_parts_mut(console_public_key.modulus.as_mut_ptr() as *mut u8, 128)
                .copy_from_slice(std::slice::from_raw_parts(input_signature.add(0x28), 128));
            if ExKeysPkcs1Verify(hash, input_signature.add(0x1A8), &console_public_key.rsa) != 0 {
                return 1;
            }
        }
    }

    0
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysObscureKey(input: *const u8, output: *mut u8) -> u32 {
    let key_obf = ex_keys_get_key_ptr(XeKey::KeyObfuscationKey as u32);
    let key = std::slice::from_raw_parts(key_obf, 16);
    let key: &[u8; 16] = key.try_into().unwrap();
    let input = std::slice::from_raw_parts(input, 16);
    let output = std::slice::from_raw_parts_mut(output, 16);
    output.copy_from_slice(input);
    xecrypt::symmetric::xe_crypt_aes_ecb_encrypt(key, output.try_into().unwrap());
    0
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysHmacShaUsingKey(
    obscured_key: *const u8,
    input1: *const u8,
    input1_size: u32,
    input2: *const u8,
    input2_size: u32,
    input3: *const u8,
    input3_size: u32,
    output: *mut u8,
    output_size: u32,
) -> u32 {
    if obscured_key.is_null() {
        return 1;
    }
    let key_obf = ex_keys_get_key_ptr(XeKey::KeyObfuscationKey as u32);
    let key_slice = std::slice::from_raw_parts(key_obf, 16);
    let key_enc: &[u8; 16] = key_slice.try_into().unwrap();
    let mut key = [0u8; 0x10];
    std::ptr::copy_nonoverlapping(obscured_key, key.as_mut_ptr(), 16);
    xecrypt::symmetric::xe_crypt_aes_ecb_decrypt(key_enc, &mut key);
    ExCryptHmacSha(key.as_ptr(), 0x10, input1, input1_size, input2, input2_size, input3, input3_size, output, output_size);
    0
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysHmacSha(
    key_idx: u32,
    input1: *const u8,
    input1_size: u32,
    input2: *const u8,
    input2_size: u32,
    input3: *const u8,
    input3_size: u32,
    output: *mut u8,
    output_size: u32,
) -> u32 {
    let key = ex_keys_get_key_ptr(key_idx);
    if key.is_null() {
        return 1;
    }
    let size = ex_keys_get_key_properties(key_idx);
    ExCryptHmacSha(key, size, input1, input1_size, input2, input2_size, input3, input3_size, output, output_size);
    0
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysObfuscate(roaming: i32, input: *const u8, input_size: u32, output: *mut u8, output_size: *mut u32) -> i32 {
    let input = std::slice::from_raw_parts(input, input_size as usize);
    let out = std::slice::from_raw_parts_mut(output.add(0x18), input_size as usize);
    out.copy_from_slice(input);
    *output_size = input_size + 0x18;

    std::slice::from_raw_parts_mut(output.add(0x10), 8).fill(0xBB);

    let key_idx = if roaming != 0 {
        XeKey::RoamableObfuscationKey as u32
    } else {
        XeKey::ConsoleObfuscationKey as u32
    };

    let result = ExKeysHmacSha(key_idx, output.add(0x10), *output_size - 0x10, std::ptr::null(), 0, std::ptr::null(), 0, output, 0x10) as i32;
    if result < 0 {
        return result;
    }

    let mut key = [0u8; 0x10];
    ExKeysHmacSha(key_idx, output, 0x10, std::ptr::null(), 0, std::ptr::null(), 0, key.as_mut_ptr(), 0x10);

    ExCryptRc4(key.as_ptr(), 0x10, output.add(0x10), *output_size - 0x10);

    1
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExKeysUnObfuscate(roaming: i32, input: *const u8, input_size: u32, output: *mut u8, output_size: *mut u32) -> i32 {
    if input_size < 0x18 {
        return 0;
    }
    let mut buf1 = [0u8; 0x18];
    buf1.copy_from_slice(std::slice::from_raw_parts(input, 0x18));

    *output_size = input_size - 0x18;
    std::slice::from_raw_parts_mut(output, *output_size as usize).copy_from_slice(std::slice::from_raw_parts(input.add(0x18), *output_size as usize));

    let key_idx = if roaming != 0 {
        XeKey::RoamableObfuscationKey as u32
    } else {
        XeKey::ConsoleObfuscationKey as u32
    };

    let mut key = [0u8; 0x10];
    let _ = ExKeysHmacSha(key_idx, buf1.as_ptr(), 0x10, std::ptr::null(), 0, std::ptr::null(), 0, key.as_mut_ptr(), 0x10);

    let mut rc4 = ExCryptRc4State { s: [0; 256], i: 0, j: 0 };
    ExCryptRc4Key(&mut rc4, key.as_ptr(), 0x10);
    ExCryptRc4Ecb(&mut rc4, buf1.as_mut_ptr().add(0x10), 8);
    ExCryptRc4Ecb(&mut rc4, output, *output_size);

    let mut hash = [0u8; 0x10];
    ExKeysHmacSha(key_idx, &buf1[0x10], 8, output, *output_size, std::ptr::null(), 0, hash.as_mut_ptr(), 0x10);

    (hash[..] == buf1[..0x10]) as i32
}

// --- Idiomatic KeyManager ---

static EXKEYS_LOCK: Mutex<()> = Mutex::new(());

pub struct KeyManager;

impl KeyManager {
    pub fn load_vault(data: &[u8]) -> Result<()> {
        let _lock = EXKEYS_LOCK.lock().unwrap();
        if ex_keys_load_key_vault(data) {
            Ok(())
        } else {
            Err(CryptoError::FfiError)
        }
    }

    pub fn get_key(key: XeKey) -> Result<Vec<u8>> {
        let _lock = EXKEYS_LOCK.lock().unwrap();
        match ex_keys_get_key(key as u32, None) {
            Some(size) => {
                let mut output = vec![0u8; size as usize];
                ex_keys_get_key(key as u32, Some(&mut output));
                Ok(output)
            }
            None => Err(CryptoError::FfiError),
        }
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
        let mut output = vec![0u8; data.len() + 256];
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
