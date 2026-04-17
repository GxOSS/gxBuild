use std::fs;
use crc32fast::Hasher;

fn main() {
    let path = "C:/Users/Exposure/Documents/gxBuild/standalone/17559/../common/cba_9188.bin";
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

    println!("Total Size: {}", data.len());

    let mut hasher1 = Hasher::new();
    hasher1.update(&data);
    println!("Full CRC32: {:08x}", hasher1.finalize());

    if data.len() >= 0x20 {
        let mut hasher2 = Hasher::new();
        hasher2.update(&data[..0x10]);
        hasher2.update(&data[0x20..]);
        println!("Skipping 0x10..0x20 CRC32: {:08x}", hasher2.finalize());
        
        // Also try skipping 0x14..0x20? Some nonces are 12 bytes? No, bootloader headers are 0x10, then 16 bytes nonce/key, starting at 0x10.
        let mut hasher3 = Hasher::new();
        hasher3.update(&data[..0x14]);
        hasher3.update(&data[0x20..]); // some older formats?
        println!("Skipping 0x14..0x20 CRC32: {:08x}", hasher3.finalize());

        let mut hasher4 = Hasher::new();
        hasher4.update(&data[0x20..]);
        println!("Skipping 0x00..0x20 CRC32: {:08x}", hasher4.finalize());
    }
}
