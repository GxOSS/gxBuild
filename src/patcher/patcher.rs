// Define formats in formats/
// Dynamically support formats defined in formats/ 

// Define identify() function
// Define identify() function
// Define parse_bin() function - identify_xebuild() then load into and return patch_<jtag/rgh/addon> struct
// Define parse_rglp() function - load into and return patch_rglp struct
// Define parse_raw() function - load into and return patch_raw struct

// Define apply_patch() function - Take patch_* struct and apply it to an image

pub enum PatchType {
    XeBuidPatch,
    RawPatch,
    Unknown,
}

pub fn identify(patch: Vec<u8>) -> anyhow::Result<PatchType> {
    // Check patch data against known identifiers
}

