/*
    xenia/mod.rs - Handling of Xenia LZX Delta
    Copyright 2024 Emma https://ipg.gay/

    Modified in 2026 by Exposure / Zach for gxBuild

    This file has been taken from xenon-bltool and modified, and therefore retains the original
    License.

    xenon-bltool is free software: you can redistribute it and/or modify it under the terms of
    the GNU General Public License as published by the Free Software Foundation, version 2 of
    the License.

    xenon-bltool is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with xenon-bltool.
    If not, see <https://www.gnu.org/licenses/>.
*/

#[repr(C)]
#[derive(
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    Default,
    Copy,
    Clone,
)]
pub struct BootloaderDeltaBlock {
    pub old_addr: u32,
    pub new_addr: u32,
    pub decompressed_size: u16,
    pub compressed_size: u16,
}

extern "C" {
    pub fn lzx_decompress(
        lzx_data: *const u8,
        lzx_len: usize,
        dest: *mut u8,
        dest_len: usize,
        window_size: u32,
        window_data: *const u8,
        window_data_len: usize,
    ) -> i32;

    pub fn lzxdelta_apply_patch(
        patch: *const BootloaderDeltaBlock,
        patch_len: usize,
        window_size: u32,
        dest: *mut u8,
    ) -> i32;
}

pub fn decompress(
    lzx_data: &[u8],
    dest: &mut [u8],
    window_size: u32,
    window_data: Option<&[u8]>,
) -> Result<(), i32> {
    let (window_ptr, window_len) = if let Some(data) = window_data {
        (data.as_ptr(), data.len())
    } else {
        (std::ptr::null(), 0)
    };

    let result = unsafe {
        lzx_decompress(
            lzx_data.as_ptr(),
            lzx_data.len(),
            dest.as_mut_ptr(),
            dest.len(),
            window_size,
            window_ptr,
            window_len,
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}

pub fn apply_patch(patch_data: &[u8], window_size: u32, dest_mut: &mut [u8]) -> Result<(), i32> {
    let patch_ptr = patch_data.as_ptr() as *const BootloaderDeltaBlock;
    let result = unsafe {
        lzxdelta_apply_patch(
            patch_ptr,
            patch_data.len(),
            window_size,
            dest_mut.as_mut_ptr(),
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}
