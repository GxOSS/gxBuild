// Raw patches compiled from source

// Input raw patch and metadata
// Export rawpatch struct

pub enum RawPatchType {
    Cb,
    Cb_a,
    Cb_b,
    Cd,
    Ce,
    Khv,
}

pub struct RawPatch {
    pub header: RawPatchType,
    pub data: Vec<u8>,
}

/// Lowlevel function, apply raw patch to data
fn apply_raw_buffer(patch: Vec<u8>, data: Vec<u8>) -> anyhow::Result {
    // Apply section of xeBuild patch to inputted data
}

/// Wrapper function, Apply RawPatch to NandSkeleton
pub fn apply_raw_patch(patch: RawPatch, nand: NandSkeleton) -> anyhow::Result<NandSkeleton> {
    // Read RawPatch
    // Grab section of nand
    // Appy raw patch with apply_raw_buffer
    // Rebuild and return NandSkeleton
}
