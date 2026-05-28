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

pub mod aes;
pub mod keys;
pub mod rc4;
pub mod rsa;
pub mod sha;

// Re-exports for convenient access
pub use rc4::Rc4;
pub use rsa::verify_signature;
pub use sha::{calculate_smc_hash, hmac_sha, rot_sum_sha, sha};

pub type Result<T> = std::result::Result<T, CryptoError>;

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

pub unsafe fn ffi_slice<'a>(ptr: *const u8, len: u32) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len as usize)
    }
}

pub unsafe fn ffi_slice_mut<'a>(ptr: *mut u8, len: u32) -> &'a mut [u8] {
    if ptr.is_null() || len == 0 {
        &mut []
    } else {
        std::slice::from_raw_parts_mut(ptr, len as usize)
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQw_SwapDwQwLeBe(source: *const u64, dest: *mut u64, num_qwords: u32) {
    let src = std::slice::from_raw_parts(source, num_qwords as usize);
    let dst = std::slice::from_raw_parts_mut(dest, num_qwords as usize);
    for i in 0..num_qwords as usize {
        dst[i] = src[i].swap_bytes();
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptMemDiff(buf1: *const u8, buf2: *const u8, size: u32) -> i32 {
    if size == 0 {
        return 0;
    }
    let a = std::slice::from_raw_parts(buf1, size as usize);
    let b = std::slice::from_raw_parts(buf2, size as usize);
    let mut diff = 0u8;
    for i in 0..size as usize {
        diff |= a[i] ^ b[i];
    }
    diff as i32
}
