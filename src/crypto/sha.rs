use sha1::{Digest, Sha1};

use super::{ffi_slice, ffi_slice_mut, Result};
use xecrypt::symmetric;

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

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptRotSumSha(input1: *const u8, input1_size: u32, input2: *const u8, input2_size: u32, output: *mut u8, output_size: u32) {
    if output.is_null() {
        return;
    }

    let hash = symmetric::xe_crypt_rot_sum_sha(ffi_slice(input1, input1_size), ffi_slice(input2, input2_size));
    let output = ffi_slice_mut(output, output_size.min(hash.len() as u32));
    output.copy_from_slice(&hash[..output.len()]);
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
