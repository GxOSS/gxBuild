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

pub fn rot_sum_sha(input1: &[u8], input2: &[u8]) -> Result<[u8; 20]> {
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
