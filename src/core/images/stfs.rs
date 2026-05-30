/*
  stfs.rs - STFS (PIRS) extraction tool for Xbox 360 content packages.

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

use log::info;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::builder::chain::cf::BootloaderCf;
use crate::builder::chain::cg::BootloaderCg;
use crate::builder::chain::BootloaderHeader;
use stfs::StfsPackageReader;
use zerocopy::FromBytes;

pub const ONE_BL_KEY: [u8; 16] = [
    0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA,
];

pub struct StfsContainer<'a> {
    reader: stfs::BytesStfsReader<&'a [u8]>,
}

impl<'a> StfsContainer<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 4 || &data[0..4] != b"PIRS" {
            return Err("Invalid STFS signature: Expected 'PIRS'".into());
        }

        let reader = stfs::BytesStfsReader::open(data)
            .map_err(|e| format!("Failed to open STFS package: {}", e))?;

        info!(
            "[builder] STFS container validated (PIRS magic OK, {} bytes)",
            data.len()
        );
        Ok(Self { reader })
    }

    pub fn extract_all(&self, target_dir: &Path) -> Result<(), String> {
        if !target_dir.exists() {
            fs::create_dir_all(target_dir).map_err(|e| e.to_string())?;
        }

        let tree = self.reader.package().file_table.build_tree();
        Self::extract_tree_node(&tree, target_dir, &self.reader)?;

        Ok(())
    }

    fn extract_tree_node(
        node: &stfs::StfsTreeNode,
        parent_path: &Path,
        reader: &stfs::BytesStfsReader<&'a [u8]>,
    ) -> Result<(), String> {
        for child in &node.children {
            let name = &child.entry.name;
            let full_path = parent_path.join(name);

            if child.entry.is_directory() {
                fs::create_dir_all(&full_path).map_err(|e| e.to_string())?;
                Self::extract_tree_node(child, &full_path, reader)?;
            } else {
                let mut file_data = Vec::new();
                reader
                    .extract_file(&mut file_data, &child.entry)
                    .map_err(|e| format!("Failed to extract file '{}': {}", name, e))?;
                fs::write(&full_path, file_data).map_err(|e| e.to_string())?;
                info!("[builder] STFS extracted file: {}", name);
            }
        }
        Ok(())
    }

    pub fn extract_to_memory(&self) -> Result<HashMap<String, Vec<u8>>, String> {
        info!("[builder] STFS extract_to_memory starting");

        let mut results = HashMap::new();

        for walk_entry in self.reader.package().file_table.walk_files() {
            let mut name = walk_entry.entry.name.clone();

            // Truncate $flash_ prefix if present
            if name.to_lowercase().starts_with("$flash_") {
                name = name[7..].to_string();
            }

            let mut file_data = Vec::new();
            self.reader
                .extract_file(&mut file_data, &walk_entry.entry)
                .map_err(|e| format!("Failed to extract file '{}': {}", walk_entry.path, e))?;

            results.insert(name.to_lowercase(), file_data);
        }

        info!(
            "[builder] STFS in-memory extraction complete: {} files extracted.",
            results.len()
        );
        Ok(results)
    }
}

pub fn parse_xboxupd(xboxupd_bytes: &[u8]) -> Result<(BootloaderCf, BootloaderCg), String> {
    // 0. Quick Magic Validation
    if xboxupd_bytes.len() < 2 {
        return Err("xboxupd buffer too small to check magic".to_string());
    }
    if &xboxupd_bytes[0..2] != b"CF" {
        return Err(format!("Invalid xboxupd magic: Expected 'CF' (0x4346), found 0x{:02X}{:02X}. Potential STFS misalignment.", xboxupd_bytes[0], xboxupd_bytes[1]));
    }

    // 1. Parse CF (slice to CF size so CF doesn't accidentally include CG bytes)
    let (cf_header, _) = BootloaderHeader::read_from_prefix(xboxupd_bytes)
        .map_err(|_| "Failed to parse CF header")?;
    let cf_size = ((cf_header.size.get() as usize) + 0xF) & !0xF;
    if xboxupd_bytes.len() < cf_size {
        return Err("xboxupd buffer too small to contain full CF".to_string());
    }
    let mut cf = BootloaderCf::parse(&xboxupd_bytes[..cf_size])?;

    if !cf.is_decrypted() {
        if let Err(e) = cf.decrypt(&ONE_BL_KEY) {
            return Err(format!("CF decryption failed: {}", e));
        }
    }
    if !cf.is_decrypted() {
        return Err("Failed to decrypt CF header.".to_string());
    }

    info!(
        "[builder] Parsing xboxupd: CF at offset 0, size=0x{:x}",
        cf.header.size.get()
    );
    cf.populate_metadata();
    let meta = cf
        .metadata
        .as_ref()
        .ok_or("Failed to populate CF metadata")?;
    let cf_size = (cf.header.size.get() as usize + 0xF) & !0xF;

    if xboxupd_bytes.len() < cf_size {
        return Err("xboxupd buffer too small to contain CG payload".to_string());
    }

    // 2. Slice memory exactly from CF endpoint to initialize CG
    let mut cg = BootloaderCg::parse(&xboxupd_bytes[cf_size..])?;

    if !cg.is_decrypted() {
        if let Err(e) = cg.decrypt(&meta.cg_nonce) {
            return Err(format!("CG decryption failed: {}", e));
        }
    }
    if !cg.is_decrypted() {
        return Err("Failed to decrypt CG header.".to_string());
    }

    cg.populate_metadata();

    // 3. Compare RotSum
    let mut cg_rotsum = [0u8; 0x14];
    if let Err(e) = cg.calculate_rotsum(&mut cg_rotsum) {
        return Err(format!("CG rotsum calculation failed: {}", e));
    }

    if cg_rotsum != meta.cg_digest {
        return Err("CG checking hash mismatch against CF signature metadata".to_string());
    }

    info!(
        "[builder] xboxupd parsed OK: CF v{} -> CG v{} ({} bytes)",
        cf.header.version.get(),
        cg.header.version.get(),
        xboxupd_bytes.len()
    );
    Ok((cf, cg))
}

#[cfg(test)]
mod tests {
    use super::StfsContainer;

    #[test]
    fn short_pirs_container_returns_error() {
        // The stfs crate validates the container immediately on open,
        // so short containers fail during construction, not extraction
        let result = StfsContainer::new(b"PIRS");
        assert!(result.is_err());
    }
}
