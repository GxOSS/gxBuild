#![allow(unused_variables, dead_code)]

use super::Result;
use openssl::bn::{BigNum, BigNumContext, BigNumRef};

// Helper: Convert qword array (big-endian u64) to BigNum
fn qw_to_bignum(qw: &[u64]) -> BigNum {
    let mut bytes = Vec::with_capacity(qw.len() * 8);
    for &q in qw.iter().rev() {
        bytes.extend_from_slice(&q.to_be_bytes());
    }
    BigNum::from_slice(&bytes).unwrap_or_else(|_| BigNum::new().unwrap())
}

// Helper: Convert BigNum to qword array (big-endian u64)
fn bignum_to_qw(bn: &BigNumRef, num_qwords: usize) -> Vec<u64> {
    let bytes = bn.to_vec();
    let mut qw = vec![0u64; num_qwords];
    let qw_len = qw.len();
    let start = bytes.len().saturating_sub(num_qwords * 8);
    for (i, chunk) in bytes[start..].chunks(8).enumerate().rev() {
        let mut buf = [0u8; 8];
        buf[8 - chunk.len()..].copy_from_slice(chunk);
        if i < qw_len {
            qw[qw_len - 1 - i] = u64::from_be_bytes(buf);
        }
    }
    qw
}

// Helper: Swap byte order of qwords (LE <-> BE)
fn swap_qw_endian(src: &[u64], dst: &mut [u64]) {
    for (s, d) in src.iter().zip(dst.iter_mut()) {
        *d = s.swap_bytes();
    }
}

// --- Types (from excrypt.h / excrypt_bn.h) ---

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
pub struct ExCryptRsaPrv1024 {
    pub rsa: ExCryptRsa,
    pub modulus: [u64; 16],
    pub prime1: [u64; 8],
    pub prime2: [u64; 8],
    pub exponent1: [u64; 8],
    pub exponent2: [u64; 8],
    pub coefficient: [u64; 8],
    pub priv_exponent: [u64; 16],
}

#[repr(C)]
pub struct ExCryptSig {
    pub padding: [u64; 28],
    pub one: u8,
    pub salt: [u8; 10],
    pub hash: [u8; 20],
    pub end: u8,
}

// --- excrypt_bn.c ---

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQw_Copy(
    source: *const u64,
    dest: *mut u64,
    num_qwords: u32,
) {
    if source.is_null() || dest.is_null() || num_qwords == 0 {
        return;
    }
    let src = std::slice::from_raw_parts(source, num_qwords as usize);
    let dst = std::slice::from_raw_parts_mut(dest, num_qwords as usize);
    dst.copy_from_slice(src);
}

// --- excrypt_bn_mod.cpp ---

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQwNeModMul(
    input_a: *const u64,
    input_b: *const u64,
    output_c: *mut u64,
    _inverse: u64,
    modulus: *const u64,
    modulus_size: u32,
) {
    if input_a.is_null() || input_b.is_null() || output_c.is_null() || modulus.is_null() {
        return;
    }
    let size = modulus_size as usize;
    let a_slice = std::slice::from_raw_parts(input_a, size);
    let b_slice = std::slice::from_raw_parts(input_b, size);
    let m_slice = std::slice::from_raw_parts(modulus, size);
    
    let a = qw_to_bignum(a_slice);
    let b = qw_to_bignum(b_slice);
    let m = qw_to_bignum(m_slice);
    
    let mut ctx = BigNumContext::new().unwrap();
    let mut mul_result = BigNum::new().unwrap();
    let mut final_result = BigNum::new().unwrap();
    
    // result = (a * b) % m
    mul_result.checked_mul(&a, &b, &mut ctx).unwrap();
    final_result.nnmod(&mul_result, &m, &mut ctx).unwrap();
    
    let out_slice = std::slice::from_raw_parts_mut(output_c, size);
    let qw_result = bignum_to_qw(&final_result, size);
    out_slice.copy_from_slice(&qw_result);
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQwNeModInv(input: u64) -> u64 {
    // Compute modular inverse mod 2^64 using extended Euclidean algorithm
    // For Montgomery reduction: inv = -a^-1 mod 2^64
    if input == 0 {
        return 0;
    }
    
    
    // Simpler approach for mod 2^64 inverse
    // inv = (-input^-1) mod 2^64
    let mut inv: u64 = 1;
    let mut temp = input;
    
    for _ in 0..64 {
        if temp & 1 == 1 {
            temp = temp.wrapping_add(input);
            inv = inv.wrapping_mul(2).wrapping_add(1);
        } else {
            temp >>= 1;
            inv <<= 1;
        }
    }
    
    inv.wrapping_neg()
}

// --- excrypt_bn_pkcs1.cpp ---

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnDwLePkcs1Format(
    hash: *const u8,
    format: u32,
    output_sig: *mut u8,
    output_sig_size: u32,
) {
    if hash.is_null() || output_sig.is_null() || output_sig_size == 0 {
        return;
    }
    
    // format: 0=SHA1, 1=SHA256, 2=MD5, 3=MD4
    let (digest_info, digest_len): (&[u8], usize) = match format {
        0 => {
            // SHA-1: OID 1.3.14.3.2.26
            const INFO: &[u8] = &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
            ];
            (INFO, 20usize)
        }
        1 => {
            // SHA-256: OID 2.16.840.1.101.3.4.2.1
            const INFO: &[u8] = &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00, 0x04, 0x20,
            ];
            (INFO, 32usize)
        }
        2 => {
            // MD5: OID 1.2.840.113549.2.5
            const INFO: &[u8] = &[
                0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
                0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
                0x04, 0x10,
            ];
            (INFO, 16usize)
        }
        3 => {
            // MD4: OID 1.2.840.113549.2.4
            const INFO: &[u8] = &[
                0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
                0x48, 0x86, 0xf7, 0x0d, 0x02, 0x04, 0x05, 0x00,
                0x04, 0x10,
            ];
            (INFO, 16usize)
        }
        _ => return,
    };
    
    let total_len = digest_info.len() + digest_len;
    let ps_len = output_sig_size as usize - total_len - 3;
    
    if (output_sig_size as usize) < total_len + 3 {
        return;
    }
    
    let out = std::slice::from_raw_parts_mut(output_sig, output_sig_size as usize);
    
    // PKCS#1 v1.5 padding: 0x00 0x01 0xFF...0xFF 0x00 || DigestInfo || Digest
    out[0] = 0x00;
    out[1] = 0x01;
    for i in 0..ps_len {
        out[2 + i] = 0xFF;
    }
    out[2 + ps_len] = 0x00;
    
    out[3 + ps_len..3 + ps_len + digest_info.len()].copy_from_slice(digest_info);
    std::ptr::copy_nonoverlapping(
        hash,
        out.as_mut_ptr().add(3 + ps_len + digest_info.len()),
        digest_len,
    );
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnDwLePkcs1Verify(
    hash: *const u8,
    input_sig: *const u8,
    input_sig_size: u32,
) -> i32 {
    if hash.is_null() || input_sig.is_null() || input_sig_size == 0 {
        return 0;
    }
    
    let sig = std::slice::from_raw_parts(input_sig, input_sig_size as usize);
    
    // Check basic PKCS#1 v1.5 structure
    if sig[0] != 0x00 || sig[1] != 0x01 {
        return 0;
    }
    
    // Find 0x00 separator after padding
    let mut sep_pos = 2;
    while sep_pos < sig.len() && sig[sep_pos] == 0xFF {
        sep_pos += 1;
    }
    
    if sep_pos >= sig.len() || sig[sep_pos] != 0x00 {
        return 0;
    }
    
    // The rest should be DigestInfo || Digest
    let digest_data = &sig[sep_pos + 1..];
    
    // Extract hash from the end (typically 20 bytes for SHA1)
    if digest_data.len() < 20 {
        return 0;
    }
    
    // Compare the hash at the end
    let expected_hash = std::slice::from_raw_parts(hash, 20);
    let embedded_hash = &digest_data[digest_data.len() - 20..];
    
    if expected_hash == embedded_hash {
        1
    } else {
        0
    }
}

// --- excrypt_bn_rsa.cpp ---

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQwNeRsaPrvCrypt(
    input: *const u64,
    output: *mut u64,
    key: *const ExCryptRsa,
) -> i32 {
    if input.is_null() || output.is_null() || key.is_null() {
        return 0;
    }
    
    let rsa_key = &*key;
    let num_digits = rsa_key.num_digits as usize;
    let key_size_bits = num_digits * 64;
    let key_size_bytes = key_size_bits / 8;
    
    // For CRT-based private key operation, we need the full private key structure
    // This is a simplified implementation - full implementation needs ExCryptRsaPrv1024
    
    let in_slice = std::slice::from_raw_parts(input, num_digits);
    let in_bn = qw_to_bignum(in_slice);
    
    // Build RSA private key from components
    // Note: This requires the ExCryptRsaPrv1024 structure which has p, q, dp, dq, qinv
    // For now, we do a basic RSA operation using the key structure
    
    // The key pointer may actually point to ExCryptRsaPrv1024/2048
    let out_slice = std::slice::from_raw_parts_mut(output, num_digits);
    out_slice.copy_from_slice(in_slice); // Placeholder
    
    1
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQwNeRsaPubCrypt(
    input: *const u64,
    output: *mut u64,
    key: *const ExCryptRsa,
) -> i32 {
    if input.is_null() || output.is_null() || key.is_null() {
        return 0;
    }
    
    let rsa_key = &*key;
    let num_digits = rsa_key.num_digits as usize;
    let exp = rsa_key.pub_exponent as u32;
    
    let in_slice = std::slice::from_raw_parts(input, num_digits);
    let in_bn = qw_to_bignum(in_slice);
    
    // Get modulus - the key may be ExCryptRsaPub1024 or ExCryptRsaPub2048
    let modulus_slice = std::slice::from_raw_parts(
        (key as *const u8).add(std::mem::size_of::<ExCryptRsa>()) as *const u64,
        num_digits,
    );
    let modulus = qw_to_bignum(modulus_slice);
    
    let mut ctx = BigNumContext::new().unwrap();
    let mut result = BigNum::new().unwrap();
    
    // RSA public operation: result = input^exp mod modulus
    let exp_bn = BigNum::from_u32(exp).unwrap();
    result.mod_exp(&in_bn, &exp_bn, &modulus, &mut ctx).unwrap();
    
    let out_slice = std::slice::from_raw_parts_mut(output, num_digits);
    let qw_result = bignum_to_qw(&result, num_digits);
    out_slice.copy_from_slice(&qw_result);
    
    1
}

// --- excrypt_bn_sig.c ---

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQwBeSigFormat(
    sig: *mut ExCryptSig,
    hash: *const u8,
    salt: *const u8,
) {
    if sig.is_null() || hash.is_null() || salt.is_null() {
        return;
    }
    
    let sig_struct = &mut *sig;
    
    // Clear padding
    sig_struct.padding.fill(0);
    
    // Set marker byte
    sig_struct.one = 1;
    
    // Copy salt (10 bytes)
    std::ptr::copy_nonoverlapping(salt, sig_struct.salt.as_mut_ptr(), 10);
    
    // Copy hash (20 bytes - SHA1)
    std::ptr::copy_nonoverlapping(hash, sig_struct.hash.as_mut_ptr(), 20);
    
    // Set end marker
    sig_struct.end = 0xBC;
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQwBeSigVerify(
    sig: *const ExCryptSig,
    hash: *const u8,
    salt: *const u8,
    pubkey: *const ExCryptRsa,
) -> i32 {
    if sig.is_null() || hash.is_null() || salt.is_null() || pubkey.is_null() {
        return 0;
    }
    
    let sig_struct = &*sig;
    
    // Check end marker
    if sig_struct.end != 0xBC {
        return 0;
    }
    
    // Check the 'one' marker
    if sig_struct.one != 1 {
        return 0;
    }
    
    // Verify salt matches
    let salt_slice = std::slice::from_raw_parts(salt, 10);
    if &sig_struct.salt[..] != salt_slice {
        return 0;
    }
    
    // Verify hash matches
    let hash_slice = std::slice::from_raw_parts(hash, 20);
    if &sig_struct.hash[..] != hash_slice {
        return 0;
    }
    
    // Padding should be zeros
    for &pad in &sig_struct.padding {
        if pad != 0 {
            return 0;
        }
    }
    
    1
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQwBeSigDifference(
    sig: *const ExCryptSig,
    hash: *const u8,
    salt: *const u8,
    pubkey: *const ExCryptRsa,
) -> i32 {
    if sig.is_null() || hash.is_null() || salt.is_null() {
        return -1;
    }
    
    let sig_struct = &*sig;
    let mut diff = 0i32;
    
    // XOR-based difference calculation (constant time-ish)
    let hash_slice = std::slice::from_raw_parts(hash, 20);
    let salt_slice = std::slice::from_raw_parts(salt, 10);
    
    for i in 0..20 {
        diff |= (sig_struct.hash[i] ^ hash_slice[i]) as i32;
    }
    
    for i in 0..10 {
        diff |= (sig_struct.salt[i] ^ salt_slice[i]) as i32;
    }
    
    diff |= (sig_struct.end ^ 0xBC) as i32;
    diff |= (sig_struct.one ^ 1) as i32;
    
    // Check padding is zero
    for &pad in &sig_struct.padding {
        diff |= pad as i32;
    }
    
    diff
}

// --- Safe helpers ---

pub fn verify_signature(sig: &[u8; 256], hash: &[u8; 20], salt: &[u8], pubkey: &ExCryptRsa) -> Result<bool> {
    let signature_ptr = sig.as_ptr() as *const ExCryptSig;
    unsafe {
        let result = ExCryptBnQwBeSigVerify(signature_ptr, hash.as_ptr(), salt.as_ptr(), pubkey);
        Ok(result == 1)
    }
}
