pub mod corona;
pub mod flashfs;
pub mod mobile;

pub use flashfs::FsSpareData;

use thiserror::Error;

/// Unified error type for filesystem operations.
#[derive(Error, Debug)]
pub enum FsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("FlashFS allocation failure: {0}")]
    AllocationFailed(String),

    #[error("FlashFS chain error: {0}")]
    ChainError(String),

    #[error("Block out of bounds: block {block}, total {total}")]
    BlockOutOfBounds { block: usize, total: usize },

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("File already exists: {0}")]
    FileExists(String),

    #[error("Invalid mobile slot index: {0}")]
    InvalidMobileSlot(usize),

    #[error("Invalid mobile type: 0x{0:02X}")]
    InvalidMobileType(u8),

    #[error("Corona digest SHA failed: {0}")]
    CoronaDigest(String),

    #[error("Corona write out of bounds: slot {slot} @ 0x{offset:X}")]
    CoronaWriteOutOfBounds { slot: usize, offset: usize },

    #[error("Invalid filesystem data: {0}")]
    InvalidData(String),
}

pub type Result<T> = std::result::Result<T, FsError>;

impl From<FsError> for String {
    fn from(e: FsError) -> Self {
        e.to_string()
    }
}
