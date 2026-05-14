#![allow(improper_ctypes_definitions)]
/*
    ffi.rs - interoptopus FFI and cxx-qt

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under the GNU General Public License Version 2.0
*/

use crate::core::session::Session;
use interoptopus::patterns::string::AsciiPointer;
use interoptopus::{ffi_function, ffi_type, function, Inventory, InventoryBuilder};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub type GxLogCallback = extern "C" fn(level: i32, message: *const c_char);
pub(crate) static mut LOG_CALLBACK: Option<GxLogCallback> = None;

#[no_mangle]
pub extern "C" fn gx_set_log_callback(callback: GxLogCallback) {
    unsafe {
        LOG_CALLBACK = Some(callback);
    }
}

#[ffi_type]
#[repr(C)]
pub enum FFIError {
    Ok = 0,
    NullPassed = 1,
    Panic = 2,
    Error = 3,
}

#[ffi_type(opaque)]
#[repr(C)]
pub struct GxSession {
    pub inner: Arc<Mutex<Session>>,
}

#[ffi_function]
#[no_mangle]
pub extern "C" fn gx_session_new() -> GxSession {
    GxSession {
        inner: Arc::new(Mutex::new(Session::new())),
    }
}

/// Frees the session and all associated memory.
#[ffi_function]
#[no_mangle]
pub extern "C" fn gx_session_destroy(_session: GxSession) -> FFIError {
    FFIError::Ok
}

#[ffi_function]
#[no_mangle]
pub extern "C" fn gx_session_set_build_type(
    session: &GxSession,
    build_type: AsciiPointer,
) -> FFIError {
    if let Ok(mut s) = session.inner.lock() {
        if let Ok(bt) = build_type.as_str() {
            s.set_build_type(bt.to_string());
            FFIError::Ok
        } else {
            FFIError::Error
        }
    } else {
        FFIError::Panic
    }
}

#[ffi_function]
#[no_mangle]
pub extern "C" fn gx_session_set_console(session: &GxSession, console: AsciiPointer) -> FFIError {
    if let Ok(mut s) = session.inner.lock() {
        if let Ok(c) = console.as_str() {
            s.set_console(c.to_string());
            FFIError::Ok
        } else {
            FFIError::Error
        }
    } else {
        FFIError::Panic
    }
}

#[ffi_function]
#[no_mangle]
pub extern "C" fn gx_session_set_ini_dir(session: &GxSession, path: AsciiPointer) -> FFIError {
    if let Ok(mut s) = session.inner.lock() {
        if let Ok(p) = path.as_str() {
            s.set_ini_dir(PathBuf::from(p));
            FFIError::Ok
        } else {
            FFIError::Error
        }
    } else {
        FFIError::Panic
    }
}

#[ffi_function]
#[no_mangle]
pub extern "C" fn gx_session_set_data_dir(session: &GxSession, path: AsciiPointer) -> FFIError {
    if let Ok(mut s) = session.inner.lock() {
        if let Ok(p) = path.as_str() {
            s.set_data_dir(PathBuf::from(p));
            FFIError::Ok
        } else {
            FFIError::Error
        }
    } else {
        FFIError::Panic
    }
}

#[ffi_function]
#[no_mangle]
pub extern "C" fn gx_session_set_common_dir(session: &GxSession, path: AsciiPointer) -> FFIError {
    if let Ok(mut s) = session.inner.lock() {
        if let Ok(p) = path.as_str() {
            s.set_common_dir(PathBuf::from(p));
            FFIError::Ok
        } else {
            FFIError::Error
        }
    } else {
        FFIError::Panic
    }
}

#[ffi_function]
#[no_mangle]
pub extern "C" fn gx_session_set_output_path(session: &GxSession, path: AsciiPointer) -> FFIError {
    if let Ok(mut s) = session.inner.lock() {
        if let Ok(p) = path.as_str() {
            s.set_output(PathBuf::from(p));
            FFIError::Ok
        } else {
            FFIError::Error
        }
    } else {
        FFIError::Panic
    }
}

#[ffi_function]
#[no_mangle]
pub extern "C" fn gx_session_enqueue_build(
    session: &GxSession,
    output: AsciiPointer,
    target: u8,
) -> FFIError {
    if let Ok(mut s) = session.inner.lock() {
        if let Ok(o) = output.as_str() {
            s.build(PathBuf::from(o), target);
            FFIError::Ok
        } else {
            FFIError::Error
        }
    } else {
        FFIError::Panic
    }
}

#[ffi_function]
#[no_mangle]
pub extern "C" fn gx_session_run(session: &GxSession) -> FFIError {
    if let Ok(mut s) = session.inner.lock() {
        match s.run() {
            Ok(_) => FFIError::Ok,
            Err(_) => FFIError::Error,
        }
    } else {
        FFIError::Panic
    }
}

#[ffi_function]
#[no_mangle]
pub extern "C" fn gx_session_get_last_error_len(session: &GxSession) -> i32 {
    if let Ok(s) = session.inner.lock() {
        if let Some(err) = &s.last_error {
            return err.len() as i32;
        }
    }
    0
}

pub fn my_inventory() -> Inventory {
    InventoryBuilder::new()
        .register(function!(gx_session_new))
        .register(function!(gx_session_destroy))
        .register(function!(gx_session_set_build_type))
        .register(function!(gx_session_set_console))
        .register(function!(gx_session_set_ini_dir))
        .register(function!(gx_session_set_data_dir))
        .register(function!(gx_session_set_common_dir))
        .register(function!(gx_session_set_output_path))
        .register(function!(gx_session_enqueue_build))
        .register(function!(gx_session_run))
        .register(function!(gx_session_get_last_error_len))
        .inventory()
}
