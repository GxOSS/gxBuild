use std::fs::File;
use std::io::Read;

fn main() {
    let path = "standalone/17559/su20076000_00000000";
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            println!("Failed to open {}: {}", path, e);
            return;
        }
    };
    let mut buffer = [0u8; 16];
    if let Ok(_) = file.read_exact(&mut buffer) {
        println!("Header of {}: {:02X?}", path, buffer);
    } else {
        println!("Failed to read header from {}", path);
    }
}
