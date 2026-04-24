/*
    xell.rs - Handling for XeLL (Xenon Linux Loader).

    Modified for GGX by Exposure / Zach
*/

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum XellType {
    Xell1f = 0,
    Xell2f = 1,
    XellGg = 2,
    Xellous = 3,
    XellReloaded = 4,
    XellUnknown = 0xFF,
}

#[derive(Clone)]
pub struct Xell {
    pub data: Vec<u8>,
    pub xell_type: XellType,
}

impl Xell {
    pub fn parse(data: &[u8]) -> Self {
        let mut xell_type = XellType::XellUnknown;
        
        // XeLLous (Unfinished)
        if data.len() == 0x38C00 {
            if &data[0..4] == b"Xell" {
                xell_type = XellType::Xellous;
            }
        }

        // XeLL Reloaded
        if data.len() == 0x40000 {
            if &data[0..4] == b"XeLL" {
                xell_type = XellType::XellReloaded;
            }
        }

        Self {
            data: data.to_vec(),
            xell_type,
        }
    }

    pub fn identify(&self) -> XellType {
        self.xell_type
    }

    /// Returns the logical NAND offset for this XeLL payload based on the build and image configuration.
    /// This uses hardcoded safe offsets (e.g., 0x74000 for Glitch) to avoid conflicts with the devkit filesystem.
    pub fn get_target_offset(build_type: crate::builder::builder::BuildType, _image_type: crate::builder::builder::ImageType) -> u32 {
        use crate::builder::builder::BuildType;
        match build_type {
            BuildType::Glitch => 0x74000,
            BuildType::Jtag => 0x98000, // Audclamp standard for GGX
            _ => 0x74000, // Default to the safest known gap
        }
    }
}
