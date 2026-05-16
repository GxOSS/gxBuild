/*
    signature.rs - Signature patching engine

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under the GNU General Public License Version 2.0
*/

use log::{info, warn};

#[derive(Debug, Clone)]
pub struct Signature {
    pub name: Option<String>,
    pub pattern: Vec<Option<u8>>,
    pub replacement: Vec<Option<u8>>,
}

impl Signature {
    /// Creates Signature from hex strings.
    pub fn from_hex(
        name: Option<&str>,
        pattern_hex: &str,
        replacement_hex: &str,
    ) -> Result<Self, String> {
        let pattern = Self::parse_hex(pattern_hex)?;
        let replacement = Self::parse_hex(replacement_hex)?;

        if pattern.len() != replacement.len() {
            return Err(format!(
                "Pattern and replacement lengths must match ({} vs {})",
                pattern.len(),
                replacement.len()
            ));
        }

        Ok(Self {
            name: name.map(|s| s.to_string()),
            pattern,
            replacement,
        })
    }

    /// Parses a simple JSON-like map of "pattern": "replacement" and applies it to the data
    pub fn apply_batch(data: &mut [u8], json_str: &str) -> Result<usize, String> {
        let mut total_matches = 0;

        let content = json_str
            .trim()
            .trim_start_matches('{')
            .trim_end_matches('}');
        for pair in content.split(',') {
            let parts: Vec<&str> = pair.split(':').collect();
            if parts.len() == 2 {
                let pattern_hex = parts[0].trim().trim_matches('"');
                let replacement_hex = parts[1].trim().trim_matches('"');

                if pattern_hex.is_empty() || replacement_hex.is_empty() {
                    continue;
                }

                match Self::from_hex(None, pattern_hex, replacement_hex) {
                    Ok(sig) => {
                        total_matches += sig.apply(data);
                    }
                    Err(e) => {
                        warn!(
                            "[signature] Skipping invalid signature pair in batch: {}",
                            e
                        );
                    }
                }
            }
        }

        Ok(total_matches)
    }

    fn parse_hex(hex: &str) -> Result<Vec<Option<u8>>, String> {
        let hex = hex.replace(" ", "");
        if hex.len() % 2 != 0 {
            return Err(format!("Hex string has odd length: {}", hex));
        }

        let mut out = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            let chunk = &hex[i..i + 2];
            if chunk == "??" || chunk == ".." {
                out.push(None);
            } else {
                let byte = u8::from_str_radix(chunk, 16)
                    .map_err(|e| format!("Invalid hex byte '{}': {}", chunk, e))?;
                out.push(Some(byte));
            }
        }
        Ok(out)
    }

    /// Scans the data and applies the patch to ALL matches
    pub fn apply(&self, data: &mut [u8]) -> usize {
        if data.len() < self.pattern.len() {
            return 0;
        }

        let mut matches = 0;
        let mut i = 0;

        while i <= data.len() - self.pattern.len() {
            if self.matches_at(data, i) {
                self.patch_at(data, i);
                matches += 1;

                let log_name = self.name.as_deref().unwrap_or("unnamed");
                info!(
                    "[signature] Applied patch '{}' at offset 0x{:04X}",
                    log_name, i
                );

                i += self.pattern.len();
            } else {
                i += 1;
            }
        }

        matches
    }

    fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        for (i, p) in self.pattern.iter().enumerate() {
            if let Some(expected) = p {
                if data[offset + i] != *expected {
                    return false;
                }
            }
        }
        true
    }

    fn patch_at(&self, data: &mut [u8], offset: usize) {
        for (i, r) in self.replacement.iter().enumerate() {
            if let Some(new_val) = r {
                data[offset + i] = *new_val;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_basic() {
        let sig = Signature::from_hex(Some("test"), "AA ?? CC", "00 ?? 11").unwrap();
        let mut data = vec![0xBB, 0xAA, 0x22, 0xCC, 0xDD];

        let count = sig.apply(&mut data);
        assert_eq!(count, 1);
        assert_eq!(data, vec![0xBB, 0x00, 0x22, 0x11, 0xDD]);
    }

    #[test]
    fn test_batch_apply() {
        let json = r#"{
            "AA ?? CC": "00 ?? 11",
            "FF EE": "22 33"
        }"#;
        let mut data = vec![0xAA, 0x99, 0xCC, 0xFF, 0xEE];
        let count = Signature::apply_batch(&mut data, json).unwrap();
        assert_eq!(count, 2);
        assert_eq!(data, vec![0x00, 0x99, 0x11, 0x22, 0x33]);
    }
}
