/// General GGX Commands file

pub mod xeini;
pub mod pygg;

use std::collections::HashMap;
use std::path::Path;
use std::fs;
use thiserror::Error;
use crate::builder::NandSkeleton;
use crate::builder::chain::*;

// Dummy struct to avoid rustc compile errors
pub struct NandSkeleton {}

#[derive(Error, Debug)]
pub enum CommandError {
    #[error("[Session] Error: Unknown Command: {0}")]
    UnknownCommand(String),
    #[error("[Session] Error: Invalid arg for {0}: {1}")]
    InvalidArg(String, String),
    #[error("[Session] Error: No CPU Key provided!")]
    NoCpuKey()
    #[error("[Session] Error: Invalid CPU Key: {0}")]
    InvalidCpuKey(String)
}

pub fn verify_cpukey(String) -> bool {
    // Verify cpukey is real
}

pub fn parse_cpukeypath(key_path: Option<AsRef<Path>>) -> Result<String, CommandError> {
    key_string = fs::read_to_string(&key_path)
    if (!verify_cpukey(key_path_string)) {
        CommandError.InvalidCpuKey(key_path_string)
    } else {
        key_path_string
        Ok(())
    }
}

pub fn parse_nand(nand_path: impl AsRef<Path>, cpu_key: String) -> Result<NandSkeleton> {
    // Populate all fields
    // Run the decryption chain
    //
}