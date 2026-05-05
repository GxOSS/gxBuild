/*
    ffi.rs - Developer / Foreign Function Interface

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use crate::core::interface::gxscript::GxScriptEngine;
use crate::core::session::{Session, InternalCommand};

/// Opaque wrapper for the Session struct
pub struct GxSession {
    pub inner: Arc<Mutex<Session>>,
    pub last_error: Option<CString>,
}

#[no_mangle]
pub extern "C" fn gx_session_new() -> *mut GxSession {
    let session = GxSession {
        inner: Arc::new(Mutex::new(Session::new())),
        last_error: None,
    };
    Box::into_raw(Box::new(session))
}

#[no_mangle]
pub extern "C" fn gx_session_destroy(session: *mut GxSession) {
    if !session.is_null() {
        unsafe {
            let _ = Box::from_raw(session);
        }
    }
}

#[no_mangle]
pub extern "C" fn gx_session_get_last_error(session: *mut GxSession) -> *const c_char {
    if session.is_null() {
        return std::ptr::null();
    }
    
    let session = unsafe { &mut *session };
    if let Some(ref err) = session.last_error {
        err.as_ptr()
    } else {
        std::ptr::null()
    }
}

// Helper to set error
fn set_error(session: &mut GxSession, msg: &str) {
    session.last_error = CString::new(msg).ok();
}

#[no_mangle]
pub extern "C" fn gx_session_push_parse_ini(
    session: *mut GxSession,
    path: *const c_char,
    target: *const c_char,
    ini_base: *const c_char,
    common: *const c_char,
    data: *const c_char,
) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    
    let path = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    let target = unsafe { CStr::from_ptr(target) }.to_string_lossy().into_owned();
    let ini_base = unsafe { CStr::from_ptr(ini_base) }.to_string_lossy().into_owned();
    let common = unsafe { CStr::from_ptr(common) }.to_string_lossy().into_owned();
    let data = unsafe { CStr::from_ptr(data) }.to_string_lossy().into_owned();
    
    session.inner.lock().unwrap().enqueue(InternalCommand::ParseIni {
        path: PathBuf::from(path),
        target,
        ini_base: PathBuf::from(ini_base),
        common: PathBuf::from(common),
        data: PathBuf::from(data),
    });
    
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_parse_image(
    session: *mut GxSession,
    path: *const c_char,
    key_ptr: *const u8, // Optional 16-byte key
) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    
    let path = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    let key = if !key_ptr.is_null() {
        let mut k = [0u8; 16];
        unsafe { std::ptr::copy_nonoverlapping(key_ptr, k.as_mut_ptr(), 16) };
        Some(k)
    } else {
        None
    };
    
    session.inner.lock().unwrap().enqueue(InternalCommand::ParseImage {
        path: PathBuf::from(path),
        key,
    });
    
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_parse_key(
    session: *mut GxSession,
    key_ptr: *const u8,
) -> i32 {
    if session.is_null() || key_ptr.is_null() { return -1; }
    let session = unsafe { &mut *session };
    
    let mut key = [0u8; 16];
    unsafe { std::ptr::copy_nonoverlapping(key_ptr, key.as_mut_ptr(), 16) };
    
    session.inner.lock().unwrap().enqueue(InternalCommand::ParseKey { key });
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_build(
    session: *mut GxSession,
    output: *const c_char,
    target: u8,
) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    
    let output = unsafe { CStr::from_ptr(output) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().enqueue(InternalCommand::Build {
        output: PathBuf::from(output),
        target,
    });
    
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_parse_keybin(
    session: *mut GxSession,
    key_ptr: *const u8,
) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    
    let key = if !key_ptr.is_null() {
        let mut k = [0u8; 16];
        unsafe { std::ptr::copy_nonoverlapping(key_ptr, k.as_mut_ptr(), 16) };
        Some(k)
    } else {
        None
    };
    
    session.inner.lock().unwrap().enqueue(InternalCommand::ParseKeybin { key });
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_create_image(
    session: *mut GxSession,
    layout_id: i32,
) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    
    let layout = match layout_id {
        0 => crate::core::data::blocks::NandLayout::Xsb,
        1 => crate::core::data::blocks::NandLayout::Sb,
        2 => crate::core::data::blocks::NandLayout::Bb,
        3 => crate::core::data::blocks::NandLayout::Emmc,
        _ => {
            set_error(session, "Invalid NAND layout ID");
            return 1;
        }
    };
    
    session.inner.lock().unwrap().enqueue(InternalCommand::CreateImage { layout });
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_parse_flashfs(session: *mut GxSession, path: *const c_char) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let path = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().enqueue(InternalCommand::ParseFlashfs { path: PathBuf::from(path) });
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_parse_patch(session: *mut GxSession, path: *const c_char) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let path = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().enqueue(InternalCommand::ParsePatch { path: PathBuf::from(path) });
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_apply_patch(session: *mut GxSession, path: *const c_char, ptype: u8, target: u8) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let path = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    let target = if target == 0xFF { None } else { Some(target) };
    session.inner.lock().unwrap().enqueue(InternalCommand::ApplyPatch { path: PathBuf::from(path), ptype, target });
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_extract(session: *mut GxSession, id: *const c_char) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let id = unsafe { CStr::from_ptr(id) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().enqueue(InternalCommand::Extract { id });
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_extract_all(session: *mut GxSession) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    session.inner.lock().unwrap().enqueue(InternalCommand::ExtractAll);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_replace(session: *mut GxSession, id: u8, path: *const c_char) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let path = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().enqueue(InternalCommand::Replace { id, path: PathBuf::from(path) });
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_list(session: *mut GxSession) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    session.inner.lock().unwrap().enqueue(InternalCommand::List);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_delete(session: *mut GxSession, id: u8) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    session.inner.lock().unwrap().enqueue(InternalCommand::Delete { id });
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_clear(session: *mut GxSession) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    session.inner.lock().unwrap().enqueue(InternalCommand::Clear);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_compress(session: *mut GxSession) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    session.inner.lock().unwrap().enqueue(InternalCommand::Compress);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_decompress(session: *mut GxSession) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    session.inner.lock().unwrap().enqueue(InternalCommand::Decompress);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_update(session: *mut GxSession, path: *const c_char) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let path = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().enqueue(InternalCommand::Update { path: PathBuf::from(path) });
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_finalize_flashfs(session: *mut GxSession) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    session.inner.lock().unwrap().enqueue(InternalCommand::FinalizeFlashfs);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_extract_stfs(session: *mut GxSession, path: *const c_char, target_dir: *const c_char) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let path = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    let target_dir = unsafe { CStr::from_ptr(target_dir) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().enqueue(InternalCommand::ExtractStfs { 
        path: PathBuf::from(path), 
        target_dir: PathBuf::from(target_dir) 
    });
    0
}

#[no_mangle]
pub extern "C" fn gx_session_run_once(session: *mut GxSession, command_id: i32, arg1: *const c_char) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    
    let _arg1_str = if !arg1.is_null() {
        Some(unsafe { CStr::from_ptr(arg1).to_string_lossy().into_owned() })
    } else {
        None
    };
    
    let command = match command_id {
        21 => InternalCommand::List,
        22 => InternalCommand::Clear,
        23 => InternalCommand::Compress,
        24 => InternalCommand::Decompress,
        25 => InternalCommand::FinalizeFlashfs,
        // ... add more as needed, but most are complex and better via push_ functions
        _ => {
            set_error(session, "Command ID not supported in run_once (use push_ functions)");
            return 1;
        }
    };
    
    if let Err(e) = session.inner.lock().unwrap().run_once(command) {
        set_error(session, &e);
        return 1;
    }
    
    0
}

#[no_mangle]
pub extern "C" fn gx_session_run(session: *mut GxSession) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    
    if let Err(e) = session.inner.lock().unwrap().run() {
        set_error(session, &e);
        return 1;
    }
    
    0
}

// ── Build configuration setters ──────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn gx_session_set_build_type(session: *mut GxSession, build_type: *const c_char) -> i32 {
    if session.is_null() || build_type.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let s = unsafe { CStr::from_ptr(build_type) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().set_build_type(s);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_set_console(session: *mut GxSession, console: *const c_char) -> i32 {
    if session.is_null() || console.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let s = unsafe { CStr::from_ptr(console) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().set_console(s);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_set_ini_dir(session: *mut GxSession, path: *const c_char) -> i32 {
    if session.is_null() || path.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let s = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().set_ini_dir(PathBuf::from(s));
    0
}

#[no_mangle]
pub extern "C" fn gx_session_set_common_dir(session: *mut GxSession, path: *const c_char) -> i32 {
    if session.is_null() || path.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let s = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().set_common_dir(PathBuf::from(s));
    0
}

#[no_mangle]
pub extern "C" fn gx_session_set_data_dir(session: *mut GxSession, path: *const c_char) -> i32 {
    if session.is_null() || path.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let s = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().set_data_dir(PathBuf::from(s));
    0
}

#[no_mangle]
pub extern "C" fn gx_session_set_output(session: *mut GxSession, path: *const c_char) -> i32 {
    if session.is_null() || path.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let s = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().set_output(PathBuf::from(s));
    0
}

#[no_mangle]
pub extern "C" fn gx_session_set_cpukey(session: *mut GxSession, hex_key: *const c_char) -> i32 {
    if session.is_null() || hex_key.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let s = unsafe { CStr::from_ptr(hex_key) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().set_cpukey(s);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_set_option(
    session: *mut GxSession,
    key: *const c_char,
    value: *const c_char,
) -> i32 {
    if session.is_null() || key.is_null() || value.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let k = unsafe { CStr::from_ptr(key) }.to_string_lossy();
    let v = unsafe { CStr::from_ptr(value) }.to_string_lossy();
    session.inner.lock().unwrap().set_option(&k, &v);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_load_options_ini(
    session: *mut GxSession,
    content: *const c_char,
) -> i32 {
    if session.is_null() || content.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let s = unsafe { CStr::from_ptr(content) }.to_string_lossy();
    
    if let Err(e) = session.inner.lock().unwrap().load_options_ini(&s) {
        set_error(session, &e);
        return 1;
    }
    0
}

#[no_mangle]
pub extern "C" fn gx_session_load_options_ini_file(
    session: *mut GxSession,
    path: *const c_char,
) -> i32 {
    if session.is_null() || path.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let p = unsafe { CStr::from_ptr(path) }.to_string_lossy();
    
    if let Err(e) = session.inner.lock().unwrap().load_options_ini_file(p.as_ref()) {
        set_error(session, &e);
        return 1;
    }
    0
}

#[no_mangle]
pub extern "C" fn gx_session_add_addon(session: *mut GxSession, addon: *const c_char) -> i32 {
    if session.is_null() || addon.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let s = unsafe { CStr::from_ptr(addon) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().add_addon(s);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_swap_bootloader(
    session: *mut GxSession,
    bl_type: *const c_char,
    path: *const c_char,
    is_rebooter: i32,
) -> i32 {
    if session.is_null() || bl_type.is_null() || path.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let t = unsafe { CStr::from_ptr(bl_type) }.to_string_lossy().into_owned();
    let p = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().swap_bootloader(t, PathBuf::from(p), is_rebooter != 0);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_clear_addons(session: *mut GxSession) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    session.inner.lock().unwrap().clear_addons();
    0
}

#[no_mangle]
pub extern "C" fn gx_session_set_ini_ext(session: *mut GxSession, ext: *const c_char) -> i32 {
    if session.is_null() || ext.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let s = unsafe { CStr::from_ptr(ext) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().set_ini_ext(s);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_set_bl_ext(session: *mut GxSession, ext: *const c_char) -> i32 {
    if session.is_null() || ext.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let s = unsafe { CStr::from_ptr(ext) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().set_bl_ext(s);
    0
}

/// Resolves paths, discovers assets, and queues all commands ready for gx_session_run.
/// Equivalent to calling gxBuild CLI with all the options that were set via the setters.
#[no_mangle]
pub extern "C" fn gx_session_prepare_build(session: *mut GxSession) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    if let Err(e) = session.inner.lock().unwrap().prepare_build() {
        set_error(session, &e);
        return 1;
    }
    0
}

/// Resets the command queue and asset pools for a fresh build.
/// Keeps the active NAND, CPU key, and build config options in place.
#[no_mangle]
pub extern "C" fn gx_session_reset_build(session: *mut GxSession) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    session.inner.lock().unwrap().reset_build();
    0
}

#[no_mangle]
pub extern "C" fn gx_session_run_script(session: *mut GxSession, path: *const c_char) -> i32 {
    if session.is_null() || path.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let path_str = unsafe { CStr::from_ptr(path) }.to_string_lossy();
    
    let mut script = GxScriptEngine::new(session.inner.clone());
    if let Err(e) = script.run_file(&path_str) {
        set_error(session, &e);
        return 1;
    }
    0
}

#[no_mangle]
pub extern "C" fn gx_session_shell(session: *mut GxSession) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    
    let mut script = GxScriptEngine::new(session.inner.clone());
    script.repl();
    0
}