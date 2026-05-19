/*
  excrypt/mod.rs - Handling and wrappers for ExCrypt Crypto, and Native Rust Implementations

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

pub mod keys;

use sha1::{Digest, Sha1};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid key size (expected {expected}, got {got})")]
    InvalidKeySize { expected: usize, got: usize },
    #[error("Invalid data size")]
    InvalidDataSize,
    #[error("Buffer too small")]
    BufferTooSmall,
    #[error("FFI call failed")]
    FfiError,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

#[repr(C)]
pub struct ExCryptRc4State {
    pub s: [u8; 256],
    pub i: u8,
    pub j: u8,
}

#[repr(C)]
pub struct ExCryptShaState {
    pub count: u32,
    pub state: [u32; 5],
    pub buffer: [u8; 64],
}

#[repr(C)]
pub struct ExCryptHmacShaState {
    pub sha_state: [ExCryptShaState; 2],
}

#[repr(C)]
pub struct ExCryptSig {
    pub padding: [u64; 28],
    pub one: u8,
    pub salt: [u8; 10],
    pub hash: [u8; 20],
    pub end: u8,
}

#[repr(C)]
pub struct ExCryptRsa {
    pub num_digits: u32,
    pub pub_exponent: u32,
    pub reserved: u64,
}

#[repr(C)]
pub struct ExCryptRsaPub1024 {
    pub rsa: ExCryptRsa,
    pub modulus: [u64; 16],
}

#[repr(C)]
pub struct ExCryptRsaPub2048 {
    pub rsa: ExCryptRsa,
    pub modulus: [u64; 32],
}

#[repr(C)]
pub struct ExCryptAesSchedule {
    pub keytab: [[[u8; 4]; 4]; 29],
    pub num_rounds: u32,
}

extern "C" {
    pub fn ExCryptAesCreateKeySchedule(key: *const u8, key_size: u32, state: *mut ExCryptAesSchedule);

    pub fn ExCryptAesCbcEncrypt(state: *mut ExCryptAesSchedule, input: *const u8, input_size: u32, output: *mut u8, feed: *mut u8);

    pub fn ExCryptAesCbcDecrypt(state: *mut ExCryptAesSchedule, input: *const u8, input_size: u32, output: *mut u8, feed: *mut u8);

    pub fn ExCryptBnQwBeSigVerify(sig: *const ExCryptSig, hash: *const u8, salt: *const u8, pubkey: *const ExCryptRsa) -> i32;

}

// --- Idiomatic Wrappers ---

pub struct Rc4 {
    state: ExCryptRc4State,
}

fn rc4_key(state: &mut ExCryptRc4State, key: &[u8]) -> Result<()> {
    if key.is_empty() {
        return Err(CryptoError::InvalidKeySize { expected: 1, got: 0 });
    }

    state.i = 0;
    state.j = 0;
    for (idx, slot) in state.s.iter_mut().enumerate() {
        *slot = idx as u8;
    }

    let mut key_idx = 0usize;
    for idx in 0..state.s.len() {
        key_idx = (key_idx + state.s[idx] as usize + key[idx % key.len()] as usize) & 0xFF;
        state.s.swap(idx, key_idx);
    }

    Ok(())
}

fn rc4_crypt(state: &mut ExCryptRc4State, data: &mut [u8]) {
    for byte in data {
        state.i = state.i.wrapping_add(1);
        state.j = state.j.wrapping_add(state.s[state.i as usize]);
        state.s.swap(state.i as usize, state.j as usize);

        let key_idx = state.s[state.i as usize].wrapping_add(state.s[state.j as usize]);
        *byte ^= state.s[key_idx as usize];
    }
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Result<Self> {
        let mut state = ExCryptRc4State { s: [0; 256], i: 0, j: 0 };
        rc4_key(&mut state, key)?;
        Ok(Self { state })
    }

    pub fn crypt(&mut self, data: &mut [u8]) -> Result<()> {
        rc4_crypt(&mut self.state, data);
        Ok(())
    }
}

unsafe fn ffi_slice<'a>(ptr: *const u8, len: u32) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len as usize)
    }
}

unsafe fn ffi_slice_mut<'a>(ptr: *mut u8, len: u32) -> &'a mut [u8] {
    if ptr.is_null() || len == 0 {
        &mut []
    } else {
        std::slice::from_raw_parts_mut(ptr, len as usize)
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptRc4Key(state: *mut ExCryptRc4State, key: *const u8, key_size: u32) {
    let Some(state) = state.as_mut() else {
        return;
    };
    let _ = rc4_key(state, ffi_slice(key, key_size));
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptRc4Ecb(state: *mut ExCryptRc4State, buf: *mut u8, buf_size: u32) {
    let Some(state) = state.as_mut() else {
        return;
    };
    rc4_crypt(state, ffi_slice_mut(buf, buf_size));
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptRc4(key: *const u8, key_size: u32, buf: *mut u8, buf_size: u32) {
    let mut state = ExCryptRc4State { s: [0; 256], i: 0, j: 0 };
    if rc4_key(&mut state, ffi_slice(key, key_size)).is_ok() {
        rc4_crypt(&mut state, ffi_slice_mut(buf, buf_size));
    }
}

pub fn hmac_sha(key: &[u8], inputs: &[&[u8]]) -> Result<[u8; 20]> {
    let mut inner_pad = [0u8; 64];
    let mut outer_pad = [0u8; 64];
    let key_len = key.len().min(64);
    inner_pad[..key_len].copy_from_slice(&key[..key_len]);
    outer_pad[..key_len].copy_from_slice(&key[..key_len]);

    for byte in &mut inner_pad {
        *byte ^= 0x36;
    }
    for byte in &mut outer_pad {
        *byte ^= 0x5C;
    }

    let mut inner = Sha1::new();
    inner.update(inner_pad);
    for input in inputs.iter().take(3) {
        inner.update(input);
    }
    let inner_hash = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    let output: [u8; 20] = outer.finalize().into();
    Ok(output)
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptHmacSha(
    key: *const u8,
    key_size: u32,
    input1: *const u8,
    input1_size: u32,
    input2: *const u8,
    input2_size: u32,
    input3: *const u8,
    input3_size: u32,
    output: *mut u8,
    output_size: u32,
) {
    if output.is_null() {
        return;
    }

    if let Ok(hash) = hmac_sha(ffi_slice(key, key_size), &[ffi_slice(input1, input1_size), ffi_slice(input2, input2_size), ffi_slice(input3, input3_size)]) {
        let output = ffi_slice_mut(output, output_size.min(hash.len() as u32));
        output.copy_from_slice(&hash[..output.len()]);
    }
}

pub fn rot_sum_sha(input1: &[u8], input2: &[u8]) -> Result<[u8; 20]> {
    fn excrypt_rot_sum(state: &mut [u64; 4], input: &[u8]) {
        for value in state.iter_mut() {
            *value = value.swap_bytes();
        }

        for chunk in input.chunks_exact(8) {
            let data = u64::from_be_bytes(chunk.try_into().expect("chunk size is fixed"));

            state[1] = state[1].wrapping_add(data);
            state[3] = state[3].wrapping_sub(data);

            if state[1] < data {
                state[0] = state[0].wrapping_add(1);
            }
            if state[3] > data {
                state[2] = state[2].wrapping_sub(1);
            }

            state[1] = state[1].rotate_left(29);
            state[3] = state[3].rotate_left(31);
        }

        for value in state.iter_mut() {
            *value = value.swap_bytes();
        }
    }

    fn update_rotsum_bytes(hasher: &mut Sha1, state: &[u64; 4]) {
        for value in state {
            hasher.update(value.to_le_bytes());
        }
    }

    let mut rotsum = [0u64; 4];
    excrypt_rot_sum(&mut rotsum, input1);
    excrypt_rot_sum(&mut rotsum, input2);

    let mut hasher = Sha1::new();
    update_rotsum_bytes(&mut hasher, &rotsum);
    update_rotsum_bytes(&mut hasher, &rotsum);
    hasher.update(input1);
    hasher.update(input2);

    for value in &mut rotsum {
        *value = !*value;
    }
    update_rotsum_bytes(&mut hasher, &rotsum);
    update_rotsum_bytes(&mut hasher, &rotsum);

    let output: [u8; 20] = hasher.finalize().into();
    Ok(output)
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptRotSumSha(input1: *const u8, input1_size: u32, input2: *const u8, input2_size: u32, output: *mut u8, output_size: u32) {
    if output.is_null() {
        return;
    }

    if let Ok(hash) = rot_sum_sha(ffi_slice(input1, input1_size), ffi_slice(input2, input2_size)) {
        let output = ffi_slice_mut(output, output_size.min(hash.len() as u32));
        output.copy_from_slice(&hash[..output.len()]);
    }
}

pub fn sha(inputs: &[&[u8]]) -> Result<[u8; 20]> {
    let mut hasher = Sha1::new();
    for input in inputs.iter().take(3) {
        hasher.update(input);
    }
    let output: [u8; 20] = hasher.finalize().into();
    Ok(output)
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptSha(
    input1: *const u8,
    input1_size: u32,
    input2: *const u8,
    input2_size: u32,
    input3: *const u8,
    input3_size: u32,
    output: *mut u8,
    output_size: u32,
) {
    if output.is_null() {
        return;
    }

    if let Ok(hash) = sha(&[ffi_slice(input1, input1_size), ffi_slice(input2, input2_size), ffi_slice(input3, input3_size)]) {
        let output = ffi_slice_mut(output, output_size.min(hash.len() as u32));
        output.copy_from_slice(&hash[..output.len()]);
    }
}

pub fn verify_signature(sig: &[u8; 256], hash: &[u8; 20], salt: &[u8], pubkey: &ExCryptRsa) -> Result<bool> {
    let signature_ptr = sig.as_ptr() as *const ExCryptSig;
    unsafe {
        let result = ExCryptBnQwBeSigVerify(signature_ptr, hash.as_ptr(), salt.as_ptr(), pubkey);
        Ok(result == 1)
    }
}

pub struct Aes {
    schedule: ExCryptAesSchedule,
}

impl Aes {
    pub fn new(key: &[u8]) -> Result<Self> {
        let mut schedule = ExCryptAesSchedule { keytab: [[[0; 4]; 4]; 29], num_rounds: 0 };
        unsafe {
            ExCryptAesCreateKeySchedule(key.as_ptr(), key.len() as u32, &mut schedule);
        }
        Ok(Self { schedule })
    }

    pub fn decrypt_cbc(&mut self, data: &mut [u8], iv: &mut [u8; 16]) -> Result<()> {
        unsafe {
            ExCryptAesCbcDecrypt(&mut self.schedule, data.as_ptr(), data.len() as u32, data.as_mut_ptr(), iv.as_mut_ptr());
        }
        Ok(())
    }

    pub fn encrypt_cbc(&mut self, data: &mut [u8], iv: &mut [u8; 16]) -> Result<()> {
        unsafe {
            ExCryptAesCbcEncrypt(&mut self.schedule, data.as_ptr(), data.len() as u32, data.as_mut_ptr(), iv.as_mut_ptr());
        }
        Ok(())
    }
}

pub fn calculate_smc_hash(data: &[u8]) -> [u8; 16] {
    let mut s0: u64 = 0;
    let mut s1: u64 = 0;
    for chunk in data.chunks_exact(4) {
        let val = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
        s0 = s0.wrapping_add(val);
        s1 = s1.wrapping_sub(val);
        s0 = s0.rotate_left(29);
        s1 = s1.rotate_left(31);
    }
    let mut hash = [0u8; 16];
    hash[0..8].copy_from_slice(&s0.to_be_bytes());
    hash[8..16].copy_from_slice(&s1.to_be_bytes());
    hash
}
