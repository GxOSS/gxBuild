/*
  xell.rs - Handling for XeLL (Xenon Linux Loader).

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

use std::fmt;
use thiserror::Error;

// targets for xell variants
pub mod constants {
    pub const SIZE_XELLOUS: usize = 0x38C00;
    pub const SIZE_RELOADED: usize = 0x40000;
    pub const SIZE_LEGACY_GG: usize = 0x40000;

    pub const OFFSET_XELL_1F: u32 = 0x000C_0000;
    pub const OFFSET_XELL_2F: u32 = 0x00E2_A600;
    pub const OFFSET_XELL_GG: u32 = 0x0007_0000;
    pub const OFFSET_DEFAULT: u32 = 0x0007_0000;

    pub const MAGIC_XELL_LOWER: &[u8; 4] = b"Xell";
    pub const MAGIC_XELL_UPPER: &[u8; 4] = b"XeLL";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum XellType {
    Xell1f = 0,
    Xell2f = 1,
    XellGg = 2,
    Xellous = 3,
    XellReloaded = 4,
    XellUnknown = 0xFF,
}

impl fmt::Display for XellType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XellType::Xell1f => write!(f, "XeLL 1F"),
            XellType::Xell2f => write!(f, "XeLL 2F"),
            XellType::XellGg => write!(f, "XeLL GG"),
            XellType::Xellous => write!(f, "Xellous"),
            XellType::XellReloaded => write!(f, "XeLL Reloaded"),
            XellType::XellUnknown => write!(f, "Unknown XeLL variant"),
        }
    }
}

#[derive(Debug, Error)]
pub enum XellError {
    #[error("payload data is completely empty")]
    EmptyData,
    #[error("xellous payloads are not supported; use XeLL Reloaded instead")]
    XellousUnsupported,
    #[error("unknown XeLL variant")]
    UnknownType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xell {
    pub data: Vec<u8>,
    pub xell_type: XellType,
}

impl Xell {
    /// map raw data into xell struct
    pub fn parse(data: &[u8], filename: Option<&str>) -> Result<Self, XellError> {
        if data.is_empty() {
            return Err(XellError::EmptyData);
        }

        let lower_payload: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
        if lower_payload.windows(b"xellous".len()).any(|w| w == b"xellous") {
            return Err(XellError::XellousUnsupported);
        }

        let mut xell_type = XellType::XellUnknown;

        // check filename first
        if let Some(name) = filename {
            let lower = name.to_lowercase();
            if lower.contains("xell-gggggg") {
                xell_type = XellType::XellGg;
            } else if lower.contains("xell-1f") {
                xell_type = XellType::Xell1f;
            } else if lower.contains("xell-2f") {
                xell_type = XellType::Xell2f;
            } else if lower.contains("reloaded") {
                xell_type = XellType::XellReloaded;
            }
        }

        // check magic byte and size
        if (xell_type == XellType::XellUnknown || xell_type == XellType::XellReloaded) && data.len() >= 4 {
            let magic = &data[0..4];
            let len = data.len();

            if magic == constants::MAGIC_XELL_UPPER && (len == constants::SIZE_RELOADED || len == constants::SIZE_LEGACY_GG) {
                xell_type = XellType::XellReloaded;
            }
        }

        Ok(Self { data: data.to_vec(), xell_type })
    }

    #[inline]
    pub fn identify(&self) -> XellType {
        self.xell_type
    }

    /// return the target offset for the XeLL variant
    pub fn get_target_offset(&self, layout: crate::core::images::blocks::NandLayout, image_profile: &str, has_vfuses: bool, cf_offset: u32, patch_slot_size: u32) -> Result<u32, XellError> {
        let profile = image_profile.to_ascii_lowercase();
        let is_rgloader = profile.contains("rgloader") || profile.contains("glitchr") || profile.contains("glitch2r") || profile.contains("rgl");

        match self.xell_type {
            XellType::Xell1f => Ok(constants::OFFSET_XELL_1F),
            XellType::Xell2f => Ok(constants::OFFSET_XELL_2F),
            XellType::XellGg => Ok(constants::OFFSET_XELL_GG),
            XellType::Xellous | XellType::XellReloaded => {
                if is_rgloader {
                    return Ok(0x0010_0000);
                }

                if has_vfuses {
                    if layout == crate::core::images::blocks::NandLayout::Bb {
                        return Ok(0x00B8_0000);
                    }

                    return Ok(cf_offset.saturating_add(patch_slot_size.saturating_mul(2)));
                }

                Ok(constants::OFFSET_XELL_GG)
            }
            XellType::XellUnknown => Err(XellError::UnknownType),
        }
    }
}
