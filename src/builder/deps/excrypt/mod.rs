pub mod keys;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid key size (expected {expected}, got {got})")]
    InvalidKeySize { expected: usize, got: usize },
    #[error("Invalid data size")]
    InvalidDataSize,
    #[error("Buffer too small")]
    BufferTooSmall,
    #[error("FFI call failed")]
    FfiError,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

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

#[repr(C)]
pub struct ExCryptAesSchedule {
    pub keytab: [[[u8; 4]; 4]; 29],
    pub num_rounds: u32,
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

    pub fn ExCryptAesCreateKeySchedule(
        key: *const u8,
        key_size: u32,
        state: *mut ExCryptAesSchedule,
    );

    pub fn ExCryptAesCbcEncrypt(
        state: *mut ExCryptAesSchedule,
        input: *const u8,
        input_size: u32,
        output: *mut u8,
        feed: *mut u8,
    );

    pub fn ExCryptAesCbcDecrypt(
        state: *mut ExCryptAesSchedule,
        input: *const u8,
        input_size: u32,
        output: *mut u8,
        feed: *mut u8,
    );

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

// --- Idiomatic Wrappers ---

pub struct Rc4 {
    state: ExCryptRc4State,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Result<Self> {
        let mut state = ExCryptRc4State {
            s: [0; 256],
            i: 0,
            j: 0,
        };
        unsafe {
            ExCryptRc4Key(&mut state, key.as_ptr(), key.len() as u32);
        }
        Ok(Self { state })
    }

    pub fn crypt(&mut self, data: &mut [u8]) -> Result<()> {
        unsafe {
            ExCryptRc4Ecb(&mut self.state, data.as_mut_ptr(), data.len() as u32);
        }
        Ok(())
    }
}

pub fn hmac_sha(key: &[u8], inputs: &[&[u8]]) -> Result<[u8; 20]> {
    let mut output = [0u8; 20];
    let mut in1 = std::ptr::null();
    let mut in1_s = 0;
    let mut in2 = std::ptr::null();
    let mut in2_s = 0;
    let mut in3 = std::ptr::null();
    let mut in3_s = 0;

    if inputs.len() > 0 {
        in1 = inputs[0].as_ptr();
        in1_s = inputs[0].len() as u32;
    }
    if inputs.len() > 1 {
        in2 = inputs[1].as_ptr();
        in2_s = inputs[1].len() as u32;
    }
    if inputs.len() > 2 {
        in3 = inputs[2].as_ptr();
        in3_s = inputs[2].len() as u32;
    }

    unsafe {
        ExCryptHmacSha(
            key.as_ptr(),
            key.len() as u32,
            in1,
            in1_s,
            in2,
            in2_s,
            in3,
            in3_s,
            output.as_mut_ptr(),
            20,
        );
    }
    Ok(output)
}

pub fn rot_sum_sha(input1: &[u8], input2: &[u8]) -> Result<[u8; 20]> {
    let mut output = [0u8; 20];
    unsafe {
        ExCryptRotSumSha(
            input1.as_ptr(),
            input1.len() as u32,
            input2.as_ptr(),
            input2.len() as u32,
            output.as_mut_ptr(),
            20,
        );
    }
    Ok(output)
}

pub fn sha(inputs: &[&[u8]]) -> Result<[u8; 20]> {
    let mut output = [0u8; 20];
    let mut in1 = std::ptr::null();
    let mut in1_s = 0;
    let mut in2 = std::ptr::null();
    let mut in2_s = 0;
    let mut in3 = std::ptr::null();
    let mut in3_s = 0;

    if inputs.len() > 0 {
        in1 = inputs[0].as_ptr();
        in1_s = inputs[0].len() as u32;
    }
    if inputs.len() > 1 {
        in2 = inputs[1].as_ptr();
        in2_s = inputs[1].len() as u32;
    }
    if inputs.len() > 2 {
        in3 = inputs[2].as_ptr();
        in3_s = inputs[2].len() as u32;
    }

    unsafe {
        ExCryptSha(
            in1,
            in1_s,
            in2,
            in2_s,
            in3,
            in3_s,
            output.as_mut_ptr(),
            20,
        );
    }
    Ok(output)
}

pub fn verify_signature(sig: &[u8; 256], hash: &[u8; 20], salt: &[u8], pubkey: &ExCryptRsa) -> Result<bool> {
    let signature_ptr = sig.as_ptr() as *const ExCryptSig;
    unsafe {
        let result = ExCryptBnQwBeSigVerify(
            signature_ptr,
            hash.as_ptr(),
            salt.as_ptr(),
            pubkey,
        );
        Ok(result == 1)
    }
}

pub struct Aes {
    schedule: ExCryptAesSchedule,
}

impl Aes {
    pub fn new(key: &[u8]) -> Result<Self> {
        let mut schedule = ExCryptAesSchedule {
            keytab: [[[0; 4]; 4]; 29],
            num_rounds: 0,
        };
        unsafe {
            ExCryptAesCreateKeySchedule(key.as_ptr(), key.len() as u32, &mut schedule);
        }
        Ok(Self { schedule })
    }

    pub fn decrypt_cbc(&mut self, data: &mut [u8], iv: &mut [u8; 16]) -> Result<()> {
        unsafe {
            ExCryptAesCbcDecrypt(
                &mut self.schedule,
                data.as_ptr(),
                data.len() as u32,
                data.as_mut_ptr(),
                iv.as_mut_ptr(),
            );
        }
        Ok(())
    }

    pub fn encrypt_cbc(&mut self, data: &mut [u8], iv: &mut [u8; 16]) -> Result<()> {
        unsafe {
            ExCryptAesCbcEncrypt(
                &mut self.schedule,
                data.as_ptr(),
                data.len() as u32,
                data.as_mut_ptr(),
                iv.as_mut_ptr(),
            );
        }
        Ok(())
    }
}

pub fn calculate_smc_hash(data: &[u8]) -> [u8; 16] {
    let mut s0: u64 = 0;
    let mut s1: u64 = 0;
    for chunk in data.chunks_exact(4) {
        let val = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
        s0 = s0.wrapping_add(val);
        s1 = s1.wrapping_sub(val);
        s0 = s0.rotate_left(29);
        s1 = s1.rotate_left(31);
    }
    let mut hash = [0u8; 16];
    hash[0..8].copy_from_slice(&s0.to_be_bytes());
    hash[8..16].copy_from_slice(&s1.to_be_bytes());
    hash
}
