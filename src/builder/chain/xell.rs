/*
    xell.rs - Handling for XeLL (Xenon Linux Loader).

    Created in 2026 for gxBuild by Exposure / Zach
    Licensed under the GNU General Public License Version 2.0
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
    pub fn parse(data: &[u8], filename: Option<&str>) -> Self {
        let mut xell_type = XellType::XellUnknown;

        if let Some(name) = filename {
            let lower = name.to_lowercase();
            if lower.contains("xell-gggggg") {
                xell_type = XellType::XellGg;
            } else if lower.contains("xell-1f") {
                xell_type = XellType::Xell1f;
            } else if lower.contains("xell-2f") {
                xell_type = XellType::Xell2f;
            }
        }

        if xell_type == XellType::XellUnknown {
            // Fallback to content-based identification
            if data.len() == 0x38C00 && &data[0..4] == b"Xell" {
                xell_type = XellType::Xellous;
            } else if data.len() == 0x40000 && &data[0..4] == b"XeLL" {
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

    /// Returns the logical NAND offset for this XeLL payload.
    pub fn get_target_offset(xell_type: XellType, _image_profile: &str) -> u32 {
        match xell_type {
            XellType::Xell1f => 0xC0000,
            XellType::Xell2f => 0xE2A600,
            XellType::XellGg => 0x74000,
            _ => 0x74000, // Default to Glitch offset for generic/unknown
        }
    }
}
