/*
BSD 3-Clause License

Copyright (c) 2020, emoose
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
pub unsafe extern "C" fn ExCryptBnQw_Copy(source: *const u64, dest: *mut u64, num_qwords: u32) {
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
pub unsafe extern "C" fn ExCryptBnQwNeModMul(input_a: *const u64, input_b: *const u64, output_c: *mut u64, inverse: u64, modulus: *const u64, modulus_size: u32) {
    if input_a.is_null() || input_b.is_null() || output_c.is_null() || modulus.is_null() {
        return;
    }
    let size = modulus_size as usize;
    let input_a = std::slice::from_raw_parts(input_a, size);
    let input_b = std::slice::from_raw_parts(input_b, size);
    let modulus = std::slice::from_raw_parts(modulus, size);
    let output_c = std::slice::from_raw_parts_mut(output_c, size);

    // Two parallel accumulator regions within a flat 0x210-byte buffer.
    // Region A: buf[0..=size]   accessed as buf[index-1] (index in qwords, 1-based)
    // Region B: buf[33..=33+size] accessed as buf[index-1 + 33]
    // Max modulus_size supported by the original is 32 qwords (2048-bit).
    let mut buf = [0u64; 0x42]; // 0x210 bytes / 8 = 66 qwords

    // Helper: 64x64 -> (hi, lo)
    #[inline(always)]
    fn mul128(a: u64, b: u64) -> (u64, u64) {
        let w = (a as u128).wrapping_mul(b as u128);
        ((w >> 64) as u64, w as u64)
    }

    let r10 = inverse.wrapping_mul(input_a[0]);

    for a in 0..size {
        let r11 = input_b[a];
        let r12 = {
            // r12 = r10 * r11 + (buf[1] - buf[34]) * inverse
            let diff = buf[1].wrapping_sub(buf[0x21]);
            r10.wrapping_mul(r11).wrapping_add(diff.wrapping_mul(inverse))
        };

        let mut r14: u64 = 0;
        let mut r15: u64 = 0;

        for b in 0..size {
            let idx = b + 1; // 1-based, matches C's index starting at 8 bytes = qword 1

            // --- Region A: input_a[b] * r11 ---
            let (r17, _) = mul128(r11, input_a[b]);
            let r18_base = r11.wrapping_mul(input_a[b]);
            let prev_a = buf[idx];
            let (r18, c1) = r18_base.overflowing_add(prev_a);
            let r17 = r17.wrapping_add(c1 as u64);
            let (r18, c2) = r18.overflowing_add(r14);
            let r17 = r17.wrapping_add(c2 as u64);
            r14 = r17;
            buf[idx - 1] = r18;

            // --- Region B: modulus[b] * r12 ---
            let (r17, _) = mul128(r12, modulus[b]);
            let r18_base = r12.wrapping_mul(modulus[b]);
            let prev_b = buf[idx + 0x21];
            let (r18, c1) = r18_base.overflowing_add(prev_b);
            let r17 = r17.wrapping_add(c1 as u64);
            let (r18, c2) = r18.overflowing_add(r15);
            let r17 = r17.wrapping_add(c2 as u64);
            r15 = r17;
            buf[idx + 0x20] = r18;
        }

        buf[size] = r14;
        buf[size + 0x21] = r15;
    }

    // Comparison pass: scan from top to find first differing element
    let mut r16: u64 = 0;
    let mut r17: u64 = 0;
    let mut idx = size; // top element (1-based buf index)
    for _ in 0..size {
        r16 = buf[idx];
        r17 = buf[idx + 0x21];
        if r16 != r17 {
            break;
        }
        if idx == 0 {
            break;
        }
        idx = idx.wrapping_sub(1);
    }

    let mut r14: u64 = 0;
    let mut r15: u64 = 0;

    if r16 > r17 {
        // Subtract region B from region A
        for c in 0..size {
            let idx = c + 1;
            let a_val = buf[idx];
            let b_val = buf[idx + 0x21];
            let r18 = a_val.wrapping_sub(b_val).wrapping_sub(r14);
            output_c[c] = r18;

            let r17t = b_val ^ a_val;
            let r18t = r18 ^ a_val;
            r14 = ((a_val ^ (r17t | r18t)) >> 63) & 1;
        }
    } else {
        // Add modulus to region A, subtract region B
        for c in 0..size {
            let idx = c + 1;
            let a_val = buf[idx];
            let b_val = buf[idx + 0x21];
            let m_val = modulus[c];
            let r19 = a_val.wrapping_add(m_val).wrapping_add(r14);
            let r20 = r19.wrapping_sub(b_val).wrapping_sub(r15);
            output_c[c] = r20;

            let t16 = (m_val ^ r19) | (a_val ^ r19);
            r14 = ((r19 ^ t16) >> 63) & 1;
            let t17 = (r20 ^ r19) | (b_val ^ r19);
            r15 = ((r19 ^ t17) >> 63) & 1;
        }
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQwNeModInv(input: u64) -> u64 {
    // Compute the 2-adic of qw such that: val = -1 + input^2
    let mut val = input.wrapping_mul(3) ^ 2;
    let mut x = 1u64.wrapping_sub(val.wrapping_mul(input));

    // Raise it to another 32 such that: val = -1 + input^64
    let mut i = 5u32;
    while i < 32 {
        val = val.wrapping_mul(x.wrapping_add(1));
        x = x.wrapping_mul(x);
        i <<= 1;
    }

    // Done
    val.wrapping_mul(x.wrapping_add(1))
}

// --- excrypt_bn_pkcs1.cpp ---

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnDwLePkcs1Format(hash: *const u8, format: u32, output_sig: *mut u8, output_sig_size: u32) {
    if hash.is_null() || output_sig.is_null() || output_sig_size < 39 {
        return;
    }

    // Size check from C: output_sig_size - 39 > 473 means max 512 bytes
    if output_sig_size - 39 > 473 {
        return;
    }

    let out = std::slice::from_raw_parts_mut(output_sig, output_sig_size as usize);

    // Fill entire buffer with 0xFF
    out.fill(0xFF);

    // End markers (little-endian at the very end)
    out[output_sig_size as usize - 1] = 0x00;
    out[output_sig_size as usize - 2] = 0x01;

    // Copy reversed hash (20 bytes) to the START of the buffer
    let hash_slice = std::slice::from_raw_parts(hash, 20);
    for i in 0..20 {
        out[19 - i] = hash_slice[i];
    }

    // Format-specific bytes after the reversed hash (offset 0x14 = 20)
    match format {
        0 => {
            // SHA1 format bytes (from kPkcs1Format0_0 and kPkcs1Format0_1)
            // 0xE03021A05000414 as LE u64 -> 14 04 00 05 1A 21 30 E0
            out[0x14..0x1C].copy_from_slice(&[0x14, 0x04, 0x00, 0x05, 0x1A, 0x21, 0x30, 0xE0]);
            // 0x3021300906052B as LE u64 -> 2B 05 06 09 30 21 00 00
            out[0x1C..0x24].copy_from_slice(&[0x2B, 0x05, 0x06, 0x09, 0x30, 0x21, 0x00, 0x00]);
        }
        1 => {
            // SHA256 format bytes (from kPkcs1Format1_0, kPkcs1Format1_1, kPkcs1Format1_2)
            // 0x052B0E03021A0414 as LE u64 -> 14 04 1A 02 03 0E 2B 05
            out[0x14..0x1C].copy_from_slice(&[0x14, 0x04, 0x1A, 0x02, 0x03, 0x0E, 0x2B, 0x05]);
            // 0x1F300706 as LE u32 -> 06 07 30 1F
            out[0x1C..0x20].copy_from_slice(&[0x06, 0x07, 0x30, 0x1F]);
            // 0x30 as LE u16 -> 30 00
            out[0x20..0x22].copy_from_slice(&[0x30, 0x00]);
        }
        2 => {
            // MD5 format (case 2 in C)
            out[0x14] = 0x00;
        }
        _ => {}
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnDwLePkcs1Verify(hash: *const u8, input_sig: *const u8, input_sig_size: u32) -> i32 {
    if hash.is_null() || input_sig.is_null() || input_sig_size < 39 {
        return 0;
    }

    // Size check from C
    if input_sig_size - 39 > 473 {
        return 0;
    }

    // Determine format based on input_sig[0x16] (offset 22)
    // format = 0 if 0x16 == 0
    // format = 1 if 0x16 == 0x1A
    // format = 2 if 0x16 != 0x1A
    let sig = std::slice::from_raw_parts(input_sig, input_sig_size as usize);
    let format = if sig[0x16] == 0 {
        0
    } else if sig[0x16] == 0x1A {
        1
    } else {
        2
    };

    // Create expected signature
    let mut test_sig = vec![0u8; input_sig_size as usize];
    ExCryptBnDwLePkcs1Format(hash, format, test_sig.as_mut_ptr(), input_sig_size);

    // Compare
    let input = std::slice::from_raw_parts(input_sig, input_sig_size as usize);
    if test_sig == input {
        1
    } else {
        0
    }
}

// --- excrypt_bn_rsa.cpp ---

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQwNeRsaPrvCrypt(input: *const u64, output: *mut u64, key: *const ExCryptRsa) -> i32 {
    if input.is_null() || output.is_null() || key.is_null() {
        return 0;
    }

    let rsa_key = &*key;
    let num_digits = rsa_key.num_digits.swap_bytes() as usize;
    if num_digits == 0 || num_digits > 0x40 {
        return 0;
    }
    let half = num_digits / 2;

    // The key pointer is actually ExCryptRsaPrv1024 (or 2048).
    // Layout after ExCryptRsa header (all fields are LE qword arrays):
    //   modulus[num_digits], prime1[half], prime2[half],
    //   exponent1[half], exponent2[half], coefficient[half], priv_exponent[num_digits]
    let base = (key as *const u8).add(std::mem::size_of::<ExCryptRsa>()) as *const u64;
    let modulus_sl = std::slice::from_raw_parts(base, num_digits);
    let prime1_sl = std::slice::from_raw_parts(base.add(num_digits), half);
    let prime2_sl = std::slice::from_raw_parts(base.add(num_digits + half), half);
    let exp1_sl = std::slice::from_raw_parts(base.add(num_digits + half * 2), half);
    let exp2_sl = std::slice::from_raw_parts(base.add(num_digits + half * 3), half);
    let coeff_sl = std::slice::from_raw_parts(base.add(num_digits + half * 4), half);
    let privexp_sl = std::slice::from_raw_parts(base.add(num_digits + half * 5), num_digits);

    let n = qw_to_bignum(modulus_sl);
    let p = qw_to_bignum(prime1_sl);
    let q = qw_to_bignum(prime2_sl);
    let dp = qw_to_bignum(exp1_sl);
    let dq = qw_to_bignum(exp2_sl);
    let qi = qw_to_bignum(coeff_sl);
    let d = qw_to_bignum(privexp_sl);
    let e = BigNum::from_u32(rsa_key.pub_exponent.swap_bytes()).unwrap();

    let rsa = match openssl::rsa::Rsa::from_private_components(n, e, d, p, q, dp, dq, qi) {
        Ok(r) => r,
        Err(_) => return 0,
    };

    let in_slice = std::slice::from_raw_parts(input, num_digits);
    let in_bn = qw_to_bignum(in_slice);

    // Raw private-key operation: m = c^d mod n (no padding)
    let modulus_size = num_digits * 8;
    let mut buf = vec![0u8; modulus_size];

    // Serialize input as big-endian bytes (OpenSSL expects MSB first)
    let in_bytes = in_bn.to_vec();
    let start = modulus_size.saturating_sub(in_bytes.len());
    buf[start..].copy_from_slice(&in_bytes);

    let mut out_buf = vec![0u8; modulus_size];
    let result_len = match rsa.private_decrypt(&buf, &mut out_buf, openssl::rsa::Padding::NONE) {
        Ok(n) => n,
        Err(_) => return 0,
    };

    // Convert result back to LE qword array
    let result_bn = BigNum::from_slice(&out_buf[..result_len]).unwrap_or_else(|_| BigNum::new().unwrap());
    let out_slice = std::slice::from_raw_parts_mut(output, num_digits);
    out_slice.copy_from_slice(&bignum_to_qw(&result_bn, num_digits));

    1
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQwNeRsaPubCrypt(input: *const u64, output: *mut u64, key: *const ExCryptRsa) -> i32 {
    if input.is_null() || output.is_null() || key.is_null() {
        return 0;
    }

    let rsa_key = &*key;
    let num_digits = rsa_key.num_digits as usize;
    let exp = rsa_key.pub_exponent as u32;

    let in_slice = std::slice::from_raw_parts(input, num_digits);
    let in_bn = qw_to_bignum(in_slice);

    // Get modulus - the key may be ExCryptRsaPub1024 or ExCryptRsaPub2048
    let modulus_slice = std::slice::from_raw_parts((key as *const u8).add(std::mem::size_of::<ExCryptRsa>()) as *const u64, num_digits);
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
pub unsafe extern "C" fn ExCryptBnQwBeSigFormat(sig: *mut ExCryptSig, hash: *const u8, salt: *const u8) {
    if sig.is_null() || hash.is_null() || salt.is_null() {
        return;
    }

    // Build the pre-encryption struct in a local buffer
    let mut output = ExCryptSig { padding: [0u64; 28], one: 1, salt: [0u8; 10], hash: [0u8; 20], end: 0xBC };
    std::ptr::copy_nonoverlapping(salt, output.salt.as_mut_ptr(), 10);

    // hash field = SHA1(output[0..8] | hash[0..20] | salt[0..10])
    let output_bytes = std::slice::from_raw_parts(&output as *const ExCryptSig as *const u8, 8);
    let hash_slice = std::slice::from_raw_parts(hash, 20);
    let salt_slice = std::slice::from_raw_parts(salt, 10);
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(output_bytes);
    hasher.update(hash_slice);
    hasher.update(salt_slice);
    let computed: [u8; 20] = hasher.finalize().into();
    output.hash.copy_from_slice(&computed);

    // RC4-encrypt the first 0xEB bytes of output using hash as key
    let output_raw = std::slice::from_raw_parts_mut(&mut output as *mut ExCryptSig as *mut u8, 0xEB);
    super::rc4::ExCryptRc4(output.hash.as_ptr(), 20, output_raw.as_mut_ptr(), 0xEB);

    // Clear high bit of first byte
    let output_raw = std::slice::from_raw_parts_mut(&mut output as *mut ExCryptSig as *mut u8, 0x100);
    output_raw[0] &= 0x7F;

    // Write to sig reversed in 64-bit qword chunks (out64[0x1F - c] = in64[c])
    let in64 = std::slice::from_raw_parts(&output as *const ExCryptSig as *const u64, 0x20);
    let out64 = std::slice::from_raw_parts_mut(sig as *mut u64, 0x20);
    for c in 0..0x20usize {
        out64[0x1F - c] = in64[c];
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQwBeSigVerify(sig: *mut ExCryptSig, hash: *const u8, salt: *const u8, pubkey: *const ExCryptRsa) -> i32 {
    (ExCryptBnQwBeSigDifference(sig, hash, salt, pubkey) == 0) as i32
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptBnQwBeSigDifference(sig: *mut ExCryptSig, hash: *const u8, salt: *const u8, pubkey: *const ExCryptRsa) -> i32 {
    if sig.is_null() || hash.is_null() || salt.is_null() || pubkey.is_null() {
        return -1;
    }

    let rsa_key = &*pubkey;
    let num_digits_swap = rsa_key.num_digits.swap_bytes();
    let exp = rsa_key.pub_exponent.swap_bytes();

    if num_digits_swap != 0x20 || (exp != 3 && exp != 0x10001) {
        return -1;
    }

    // Byteswap the signature in-place (SwapDwQwLeBe on 32 qwords)
    let qw_sig = std::slice::from_raw_parts_mut(sig as *mut u64, 0x20);
    for qw in qw_sig.iter_mut() {
        *qw = qw.swap_bytes();
    }

    // Copy for modular exponentiation
    let mut sig_copy = [0u64; 0x20];
    sig_copy.copy_from_slice(qw_sig);

    // Get modulus (byteswapped)
    let modulus_raw = std::slice::from_raw_parts((pubkey as *const u8).add(std::mem::size_of::<ExCryptRsa>()) as *const u64, 0x20);
    let mut modulus_swap = [0u64; 0x20];
    for i in 0..0x20 {
        modulus_swap[i] = modulus_raw[i].swap_bytes();
    }

    let inverse = ExCryptBnQwNeModInv(modulus_swap[0]);

    // Square-and-multiply: result = sig^exp mod modulus
    // Loop: exp >>= 1; while exp != 0: square; after loop: one final multiply
    let mut exp_remaining = exp;
    loop {
        exp_remaining >>= 1;
        if exp_remaining == 0 {
            break;
        }
        ExCryptBnQwNeModMul(sig_copy.as_ptr(), sig_copy.as_ptr(), sig_copy.as_mut_ptr(), inverse, modulus_swap.as_ptr(), 0x20);
    }
    ExCryptBnQwNeModMul(sig_copy.as_ptr(), qw_sig.as_ptr(), qw_sig.as_mut_ptr(), inverse, modulus_swap.as_ptr(), 0x20);

    // Byteswap result back
    for qw in qw_sig.iter_mut() {
        *qw = qw.swap_bytes();
    }

    // Format the expected signature into sig_copy (reuse as EXCRYPT_SIG buffer)
    let expected_sig_ptr = sig_copy.as_mut_ptr() as *mut ExCryptSig;
    ExCryptBnQwBeSigFormat(expected_sig_ptr, hash, salt);

    // Compare
    super::ExCryptMemDiff(qw_sig.as_ptr() as *const u8, sig_copy.as_ptr() as *const u8, 256)
}

// --- Safe helpers ---

pub fn verify_signature(sig: &[u8; 256], hash: &[u8; 20], salt: &[u8], pubkey: &ExCryptRsa) -> Result<bool> {
    let mut sig_copy = *sig;
    let signature_ptr = sig_copy.as_mut_ptr() as *mut ExCryptSig;
    unsafe {
        let result = ExCryptBnQwBeSigVerify(signature_ptr, hash.as_ptr(), salt.as_ptr(), pubkey);
        Ok(result == 1)
    }
}
