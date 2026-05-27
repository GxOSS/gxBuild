pub mod keys;
pub mod sha;
pub mod aes_rsa;
pub mod rc4;

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
