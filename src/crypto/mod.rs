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
