use super::{CryptoError, Result};
use super::{ffi_slice, ffi_slice_mut};

#[repr(C)]
pub struct ExCryptRc4State {
    pub s: [u8; 256],
    pub i: u8,
    pub j: u8,
}

pub struct Rc4 {
    state: ExCryptRc4State,
}

fn rc4_key(state: &mut ExCryptRc4State, key: &[u8]) -> Result<()> {
    if key.is_empty() {
        return Err(CryptoError::InvalidKeySize { expected: 1, got: 0 });
    }

    state.i = 0;
    state.j = 0;
    for (idx, slot) in state.s.iter_mut().enumerate() {
        *slot = idx as u8;
    }

    let mut key_idx = 0usize;
    for idx in 0..state.s.len() {
        key_idx = (key_idx + state.s[idx] as usize + key[idx % key.len()] as usize) & 0xFF;
        state.s.swap(idx, key_idx);
    }

    Ok(())
}

fn rc4_crypt(state: &mut ExCryptRc4State, data: &mut [u8]) {
    for byte in data {
        state.i = state.i.wrapping_add(1);
        state.j = state.j.wrapping_add(state.s[state.i as usize]);
        state.s.swap(state.i as usize, state.j as usize);

        let key_idx = state.s[state.i as usize].wrapping_add(state.s[state.j as usize]);
        *byte ^= state.s[key_idx as usize];
    }
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Result<Self> {
        let mut state = ExCryptRc4State { s: [0; 256], i: 0, j: 0 };
        rc4_key(&mut state, key)?;
        Ok(Self { state })
    }

    pub fn crypt(&mut self, data: &mut [u8]) -> Result<()> {
        rc4_crypt(&mut self.state, data);
        Ok(())
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptRc4Key(state: *mut ExCryptRc4State, key: *const u8, key_size: u32) {
    let Some(state) = state.as_mut() else {
        return;
    };
    let _ = rc4_key(state, ffi_slice(key, key_size));
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptRc4Ecb(state: *mut ExCryptRc4State, buf: *mut u8, buf_size: u32) {
    let Some(state) = state.as_mut() else {
        return;
    };
    rc4_crypt(state, ffi_slice_mut(buf, buf_size));
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExCryptRc4(key: *const u8, key_size: u32, buf: *mut u8, buf_size: u32) {
    let mut state = ExCryptRc4State { s: [0; 256], i: 0, j: 0 };
    if rc4_key(&mut state, ffi_slice(key, key_size)).is_ok() {
        rc4_crypt(&mut state, ffi_slice_mut(buf, buf_size));
    }
}