// use std::ffi::c_void;

#[repr(C)]
pub struct ExCryptRc4State {
    pub s: [u8; 256],
    pub i: u8,
    pub j: u8,
}

#[repr(C)]
pub struct ExCryptShaState {
    pub count: u32,
    pub state: [u32; 5],
    pub buffer: [u8; 64],
}

#[repr(C)]
pub struct ExCryptHmacShaState {
    pub sha_state: [ExCryptShaState; 2],
}

#[repr(C)]
pub struct ExCryptSig {
    pub padding: [u64; 28],
    pub one: u8,
    pub salt: [u8; 10],
    pub hash: [u8; 20],
    pub end: u8,
}

#[repr(C)]
pub struct ExCryptRsa {
    pub num_digits: u32,
    pub pub_exponent: u32,
    pub reserved: u64,
}

#[repr(C)]
pub struct ExCryptRsaPub1024 {
    pub rsa: ExCryptRsa,
    pub modulus: [u64; 16],
}

#[repr(C)]
pub struct ExCryptRsaPub2048 {
    pub rsa: ExCryptRsa,
    pub modulus: [u64; 32],
}

extern "C" {
    pub fn ExCryptRotSumSha(
        input1: *const u8,
        input1_size: u32,
        input2: *const u8,
        input2_size: u32,
        output: *mut u8,
        output_size: u32,
    );

    pub fn ExCryptHmacSha(
        key: *const u8,
        key_size: u32,
        input1: *const u8,
        input1_size: u32,
        input2: *const u8,
        input2_size: u32,
        input3: *const u8,
        input3_size: u32,
        output: *mut u8,
        output_size: u32,
    );

    pub fn ExCryptRc4Key(state: *mut ExCryptRc4State, key: *const u8, key_size: u32);

    pub fn ExCryptRc4Ecb(state: *mut ExCryptRc4State, buf: *mut u8, buf_size: u32);

    pub fn ExCryptBnQwBeSigVerify(
        sig: *const ExCryptSig,
        hash: *const u8,
        salt: *const u8,
        pubkey: *const ExCryptRsa,
    ) -> i32;

    pub fn ExCryptSha(
        input1: *const u8,
        input1_size: u32,
        input2: *const u8,
        input2_size: u32,
        input3: *const u8,
        input3_size: u32,
        output: *mut u8,
        output_size: u32,
    );
}
