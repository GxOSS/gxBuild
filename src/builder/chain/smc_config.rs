/*
  smc_config.rs - Handling for Xbox 360 SMC Config / XConfig.

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

use crate::core::images::blocks::NandLayout;
use thiserror::Error;

#[derive(Clone)]
pub struct SmcConfig {
    pub data: Box<[u8; 0x10000]>,
}

#[derive(Error, Debug)]
pub enum SmcConfigError {
    #[error("Invalid SMC Config size: got {got}, expected {expected}")]
    InvalidSize { got: usize, expected: usize },
}

impl From<SmcConfigError> for String {
    fn from(e: SmcConfigError) -> Self {
        e.to_string()
    }
}

impl SmcConfig {
    pub const SIZE: usize = 0x10000;
    pub const SETTINGS_SIZE: usize = 0x100;

    const OFFSET_CHECKSUM: usize = 0x00;

    const OFFSET_CPU_FAN: usize = 0x11;
    const OFFSET_GPU_FAN: usize = 0x12;

    const OFFSET_THERMAL_TARGET_CPU: usize = 0x29;
    const OFFSET_THERMAL_TARGET_GPU: usize = 0x2A;
    const OFFSET_THERMAL_TARGET_EDRAM: usize = 0x2B;
    const OFFSET_THERMAL_LIMIT_CPU: usize = 0x2C;
    const OFFSET_THERMAL_LIMIT_GPU: usize = 0x2D;
    const OFFSET_THERMAL_LIMIT_EDRAM: usize = 0x2E;

    const OFFSET_MAC_ADDRESS: usize = 0x220;

    // These are the compact compatibility fields currently used by gxBuild.
    const OFFSET_VIDEO_REGION: usize = 0x22A;
    const OFFSET_GAME_REGION: usize = 0x22C;
    const OFFSET_DVD_REGION: usize = 0x237;
    const OFFSET_RESET_CODE: usize = 0x238;

    pub fn get_scan_address(layout: &NandLayout) -> u32 {
        match layout {
            NandLayout::Emmc => 0x02FFC000,
            NandLayout::Bb => 0x3DF0000,
            _ => 0xF70000,
        }
    }

    pub fn get_logical_address(layout: &NandLayout) -> u32 {
        match layout {
            NandLayout::Emmc => 0x0,
            NandLayout::Bb => 0x3DF0000,
            _ => 0xF70000,
        }
    }

    pub fn new_empty() -> Self {
        Self {
            data: Box::new([0xFF; Self::SIZE]),
        }
    }

    pub fn parse(data: &[u8]) -> std::result::Result<Self, SmcConfigError> {
        if data.len() != Self::SIZE {
            return Err(SmcConfigError::InvalidSize {
                got: data.len(),
                expected: Self::SIZE,
            });
        }
        let mut config = Self {
            data: Box::new([0; Self::SIZE]),
        };
        config.data.copy_from_slice(data);
        Ok(config)
    }

    pub fn serialize(&mut self) -> &[u8; Self::SIZE] {
        let checksum = self.calculate_checksum();
        self.set_checksum(checksum);
        &self.data
    }

    pub fn calculate_checksum(&self) -> u16 {
        let mut sum: u32 = 0;
        for i in 0x10..Self::SETTINGS_SIZE {
            sum = sum.wrapping_add(self.data[i] as u32);
        }
        (!sum & 0xFFFF) as u16
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([
            self.data[Self::OFFSET_CHECKSUM],
            self.data[Self::OFFSET_CHECKSUM + 1],
        ])
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        let bytes = checksum.to_be_bytes();
        self.data[Self::OFFSET_CHECKSUM] = bytes[0];
        self.data[Self::OFFSET_CHECKSUM + 1] = bytes[1];
    }

    fn fan_offset(is_gpu: bool) -> usize {
        if is_gpu {
            Self::OFFSET_GPU_FAN
        } else {
            Self::OFFSET_CPU_FAN
        }
    }

    pub fn fan_settings(&self, is_gpu: bool) -> (bool, u8) {
        let raw = self.data[Self::fan_offset(is_gpu)];
        ((raw & 0x80) != 0, raw & 0x7F)
    }

    pub fn set_fan_speed(&mut self, is_gpu: bool, mode_manual: bool, speed_pct: u8) {
        let offset = Self::fan_offset(is_gpu);
        let mut val = speed_pct & 0x7F;
        if mode_manual {
            val |= 0x80;
        }
        self.data[offset] = val;
    }

    pub fn thermal_targets(&self) -> (u8, u8, u8) {
        (
            self.data[Self::OFFSET_THERMAL_TARGET_CPU],
            self.data[Self::OFFSET_THERMAL_TARGET_GPU],
            self.data[Self::OFFSET_THERMAL_TARGET_EDRAM],
        )
    }

    pub fn set_thermal_targets(&mut self, cpu: u8, gpu: u8, ram: u8) {
        self.data[Self::OFFSET_THERMAL_TARGET_CPU] = cpu;
        self.data[Self::OFFSET_THERMAL_TARGET_GPU] = gpu;
        self.data[Self::OFFSET_THERMAL_TARGET_EDRAM] = ram;
    }

    pub fn thermal_limits(&self) -> (u8, u8, u8) {
        (
            self.data[Self::OFFSET_THERMAL_LIMIT_CPU],
            self.data[Self::OFFSET_THERMAL_LIMIT_GPU],
            self.data[Self::OFFSET_THERMAL_LIMIT_EDRAM],
        )
    }

    pub fn set_thermal_limits(&mut self, cpu: u8, gpu: u8, ram: u8) {
        self.data[Self::OFFSET_THERMAL_LIMIT_CPU] = cpu;
        self.data[Self::OFFSET_THERMAL_LIMIT_GPU] = gpu;
        self.data[Self::OFFSET_THERMAL_LIMIT_EDRAM] = ram;
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.data[Self::OFFSET_MAC_ADDRESS..Self::OFFSET_MAC_ADDRESS + 6]
            .try_into()
            .unwrap()
    }

    pub fn set_mac_address(&mut self, mac: &[u8; 6]) {
        self.data[Self::OFFSET_MAC_ADDRESS..Self::OFFSET_MAC_ADDRESS + 6].copy_from_slice(mac);
    }

    pub fn video_region(&self) -> u16 {
        u16::from_be_bytes([
            self.data[Self::OFFSET_VIDEO_REGION],
            self.data[Self::OFFSET_VIDEO_REGION + 1],
        ])
    }

    pub fn game_region(&self) -> u16 {
        u16::from_be_bytes([
            self.data[Self::OFFSET_GAME_REGION],
            self.data[Self::OFFSET_GAME_REGION + 1],
        ])
    }

    pub fn dvd_region(&self) -> u8 {
        self.data[Self::OFFSET_DVD_REGION]
    }

    pub fn set_regions(&mut self, video: u16, game: u16, dvd: u8) {
        let v_bytes = video.to_be_bytes();
        self.data[Self::OFFSET_VIDEO_REGION] = v_bytes[0];
        self.data[Self::OFFSET_VIDEO_REGION + 1] = v_bytes[1];

        let g_bytes = game.to_be_bytes();
        self.data[Self::OFFSET_GAME_REGION] = g_bytes[0];
        self.data[Self::OFFSET_GAME_REGION + 1] = g_bytes[1];

        self.data[Self::OFFSET_DVD_REGION] = dvd;
    }

    pub fn reset_code(&self) -> [u8; 4] {
        self.data[Self::OFFSET_RESET_CODE..Self::OFFSET_RESET_CODE + 4]
            .try_into()
            .unwrap()
    }

    pub fn set_reset_code(&mut self, code: &[u8; 4]) {
        self.data[Self::OFFSET_RESET_CODE..Self::OFFSET_RESET_CODE + 4].copy_from_slice(code);
    }
}
