/*
    xell.rs - Handling for XeLL (Xenon Linux Loader).

    Created in 2026 for gxBuild by Exposure / Zach
    Modified/Contributed by erorn (2026)
    Licensed under the GNU General Public License Version 2.0
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
    pub const OFFSET_XELL_GG: u32 = 0x0007_4000;
    pub const OFFSET_DEFAULT: u32 = 0x0007_4000;

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
            } else if lower.contains("xellous") {
                xell_type = XellType::Xellous;
            } else if lower.contains("reloaded") {
                xell_type = XellType::XellReloaded;
            }
        }

        // check magic byte and size
        if xell_type == XellType::XellUnknown && data.len() >= 4 {
            let magic = &data[0..4];
            let len = data.len();

            xell_type = match magic {
                m if m == constants::MAGIC_XELL_LOWER && len == constants::SIZE_XELLOUS => {
                    XellType::Xellous
                }
                m if m == constants::MAGIC_XELL_UPPER
                    && (len == constants::SIZE_RELOADED || len == constants::SIZE_LEGACY_GG) =>
                    XellType::XellReloaded,
                _ => XellType::XellUnknown,
            };
        }

        Ok(Self {
            data: data.to_vec(),
            xell_type,
        })
    }

    #[inline]
    pub fn identify(&self) -> XellType {
        self.xell_type
    }

    /// return the target offset for the XeLL variant
    pub fn get_target_offset(&self, image_profile: &str) -> Result<u32, XellError> {
        match self.xell_type {
            XellType::Xell1f => Ok(constants::OFFSET_XELL_1F),
            XellType::Xell2f => Ok(constants::OFFSET_XELL_2F),
            XellType::XellGg => Ok(constants::OFFSET_XELL_GG),
            XellType::Xellous | XellType::XellReloaded => Ok(
                if image_profile.eq_ignore_ascii_case("bigblock")
                    || image_profile.eq_ignore_ascii_case("bb")
                {
                    constants::OFFSET_XELL_2F
                } else {
                    constants::OFFSET_XELL_GG
                },
            ),
            XellType::XellUnknown => Err(XellError::UnknownType),
        }
    }
}
