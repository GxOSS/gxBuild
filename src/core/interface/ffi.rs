/*
    ffi.rs - Developer / Foreign Function Interface

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use crate::core::session::{Session, InternalCommand};
use std::sync::{Arc, Mutex};
use crate::core::interface::gxscript::GxScriptEngine;
use serde::Serialize;

pub type GxLogCallback = extern "C" fn(level: i32, message: *const c_char);
pub(crate) static mut LOG_CALLBACK: Option<GxLogCallback> = None;

#[no_mangle]
pub extern "C" fn gx_set_log_callback(callback: GxLogCallback) {
    unsafe { LOG_CALLBACK = Some(callback); }
}


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
pub extern "C" fn gx_session_push_apply_smc_signature_patch(session: *mut GxSession, json: *const c_char) -> i32 {
    if session.is_null() || json.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let json = unsafe { CStr::from_ptr(json) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().enqueue(InternalCommand::ApplySmcSignature { json });
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_apply_options(session: *mut GxSession) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    session.inner.lock().unwrap().enqueue(InternalCommand::ApplyOptions);
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_extract(session: *mut GxSession, id: *const c_char, output_dir: *const c_char) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let id = unsafe { CStr::from_ptr(id) }.to_string_lossy().into_owned();
    let output_dir = unsafe { CStr::from_ptr(output_dir) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().enqueue(InternalCommand::Extract { id, output_dir: PathBuf::from(output_dir) });
    0
}

#[no_mangle]
pub extern "C" fn gx_session_push_extract_all(session: *mut GxSession, output_dir: *const c_char) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let output_dir = unsafe { CStr::from_ptr(output_dir) }.to_string_lossy().into_owned();
    session.inner.lock().unwrap().enqueue(InternalCommand::ExtractAll { output_dir: PathBuf::from(output_dir) });
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
    
    let res = session.inner.lock().unwrap().run_once(command);
    if let Err(e) = res {
        set_error(session, &e);
        return 1;
    }
    
    0
}

#[no_mangle]
pub extern "C" fn gx_session_run(session: *mut GxSession) -> i32 {
    if session.is_null() { return -1; }
    let session = unsafe { &mut *session };
    
    let res = session.inner.lock().unwrap().run();
    crate::core::logger::flush_logger();
    if let Err(e) = res {
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
pub extern "C" fn gx_session_load_ini(
    session: *mut GxSession,
    content: *const c_char,
    target: *const c_char,
) -> i32 {
    if session.is_null() || content.is_null() || target.is_null() { return -1; }
    let session = unsafe { &mut *session };
    let c = unsafe { CStr::from_ptr(content) }.to_string_lossy();
    let t = unsafe { CStr::from_ptr(target) }.to_string_lossy();
    
    let res = session.inner.lock().unwrap().load_ini(&c, &t);
    if let Err(e) = res {
        set_error(session, &e);
        return 1;
    }
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
    
    let res = session.inner.lock().unwrap().load_options_ini(&s);
    if let Err(e) = res {
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
    
    let res = session.inner.lock().unwrap().load_options_ini_file(p.as_ref());
    if let Err(e) = res {
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
    let res = session.inner.lock().unwrap().prepare_build();
    if let Err(e) = res {
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

#[derive(Serialize)]
struct NandMetadata {
    flash_type: String,
    motherboard: String,
    cb: u16,
    cba: u16,
    cbb: u16,
    cbx: u16,
    cd: u16,
    ce: u16,
    cf_0: u16,
    cg_0: u16,
    cf_1: u16,
    cg_1: u16,
    cb_ldv: u8,
    cb_pd: String,
    cf_0_ldv: u8,
    cf_0_pd: String,
    cf_1_ldv: u8,
    cf_1_pd: String,
    smc_ver: String,
    smc_type: String,
    smc_ldv: u8,
    smc_pd: String,
    dvd_key: String,
    serial: String,
    console_id: String,
    osig: String,
    region: String,
    mfdate: String,
    kv_type: String,
    fcrt: bool,
    bad_blocks: Vec<BadBlockInfo>,
}

#[derive(Serialize)]
struct BadBlockInfo {
    block: usize,
    target: usize,
}

#[no_mangle]
pub extern "C" fn gx_session_get_info(session: *mut GxSession) -> *const c_char {
    if session.is_null() { return std::ptr::null(); }
    let session = unsafe { &mut *session };
    let inner = session.inner.lock().unwrap();
    
    let meta = if let Some(nand) = &inner.active_nand {
        NandMetadata {
            flash_type: format!("{:?}", nand.layout),
            motherboard: format!("{:?}", nand.options.motherboard),
            cb: nand.bootloaders.cb.as_ref().map(|bl| bl.header.version.get()).unwrap_or(0),
            cba: nand.bootloaders.cb_a.as_ref().map(|bl| bl.header.version.get()).unwrap_or(0),
            cbb: nand.bootloaders.cb_b.as_ref().map(|bl| bl.header.version.get()).unwrap_or(0),
            cbx: nand.bootloaders.cb_x.as_ref().map(|bl| bl.header.version.get()).unwrap_or(0),
            cd: nand.bootloaders.cd.as_ref().map(|bl| bl.header.version.get()).unwrap_or(0),
            ce: nand.bootloaders.ce.as_ref().map(|bl| bl.header.version.get()).unwrap_or(0),
            cf_0: nand.update.cf_0.as_ref().map(|bl| bl.header.version.get()).unwrap_or(0),
            cg_0: nand.update.cg_0.as_ref().map(|bl| bl.header.version.get()).unwrap_or(0),
            cf_1: nand.update.cf_1.as_ref().map(|bl| bl.header.version.get()).unwrap_or(0),
            cg_1: nand.update.cg_1.as_ref().map(|bl| bl.header.version.get()).unwrap_or(0),
            // J-Runner reads LDV/PD from CB_B (split) or CB (single). CB_A never holds per-box data.
            cb_ldv: nand.bootloaders.cb_b.as_ref().and_then(|bl| bl.metadata.as_ref().map(|m| m.ldv))
                .or_else(|| nand.bootloaders.cb.as_ref().and_then(|bl| bl.metadata.as_ref().map(|m| m.ldv)))
                .unwrap_or(0),
            cb_pd: nand.bootloaders.cb_b.as_ref().and_then(|bl| bl.metadata.as_ref().map(|m| format!("0x{}", hex::encode_upper(&m.pairing_data))))
                .or_else(|| nand.bootloaders.cb.as_ref().and_then(|bl| bl.metadata.as_ref().map(|m| format!("0x{}", hex::encode_upper(&m.pairing_data)))))
                .unwrap_or_else(|| "".to_string()),
            cf_0_ldv: nand.update.cf_0.as_ref().and_then(|cf| cf.metadata.as_ref().map(|m| m.lockdown_value)).unwrap_or(0),
            cf_0_pd: nand.update.cf_0.as_ref().and_then(|cf| cf.metadata.as_ref().map(|m| format!("0x{}", hex::encode_upper(&m.pairing_data)))).unwrap_or_else(|| "".to_string()),
            cf_1_ldv: nand.update.cf_1.as_ref().and_then(|cf| cf.metadata.as_ref().map(|m| m.lockdown_value)).unwrap_or(0),
            cf_1_pd: nand.update.cf_1.as_ref().and_then(|cf| cf.metadata.as_ref().map(|m| format!("0x{}", hex::encode_upper(&m.pairing_data)))).unwrap_or_else(|| "".to_string()),
            smc_ver: if let Some(m) = &nand.extra.smc_metadata { format!("{}.{:02}", m.major_version, m.minor_version) } else if !nand.extra.smc.is_empty() { format!("{}.{:02}", nand.extra.smc[0x101], nand.extra.smc[0x102]) } else { "0.00".to_string() },
            smc_type: format!("{:?}", nand.options.motherboard),
            smc_ldv: if let Some(m) = &nand.extra.smc_metadata { m.lockdown_value } else if !nand.extra.smc.is_empty() { nand.extra.smc[0x103] } else { 0 },
            smc_pd: if let Some(m) = &nand.extra.smc_metadata { format!("0x{}", hex::encode_upper(&m.pairing_data)) } else if nand.extra.smc.len() >= 0x107 { format!("0x{}", hex::encode_upper(&nand.extra.smc[0x104..0x107])) } else { "0x000000".to_string() },
            dvd_key: nand.kv.as_ref().and_then(|kv| kv.metadata.as_ref()).map(|m| hex::encode(m.dvd_key)).unwrap_or_default(),
            serial: nand.kv.as_ref().and_then(|kv| kv.metadata.as_ref()).map(|m| m.serial.clone()).unwrap_or_default(),
            console_id: nand.kv.as_ref().and_then(|kv| kv.metadata.as_ref()).map(|m| hex::encode(m.console_id)).unwrap_or_default(),
            osig: nand.kv.as_ref().and_then(|kv| kv.metadata.as_ref()).map(|m| m.osig.clone()).unwrap_or_default(),
            region: nand.kv.as_ref().and_then(|kv| kv.metadata.as_ref()).map(|m| format!("0x{:04X}", m.region)).unwrap_or_default(),
            mfdate: nand.kv.as_ref().and_then(|kv| kv.metadata.as_ref()).map(|m| m.mf_date.clone()).unwrap_or_default(),
            kv_type: nand.kv.as_ref().and_then(|kv| kv.metadata.as_ref()).map(|m| m.kv_type.to_string()).unwrap_or_default(),
            fcrt: nand.kv.as_ref().and_then(|kv| kv.metadata.as_ref()).map(|m| m.fcrt).unwrap_or(false),
            bad_blocks: nand.lba_map.as_ref().map(|lba| {
                lba.bad_blocks.iter().map(|&b| {
                    BadBlockInfo { 
                        block: b, 
                        target: lba.logical_to_physical.get(b).copied().unwrap_or(b) 
                    }
                }).collect()
            }).unwrap_or_default(),
        }
    } else {
        return std::ptr::null();
    };

    let json = serde_json::to_string(&meta).unwrap_or_default();
    let c_str = CString::new(json).unwrap_or_default();
    c_str.into_raw()
}

#[no_mangle]
pub extern "C" fn gx_session_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

#[no_mangle]
pub extern "C" fn gx_session_remap_block(session: *mut GxSession, bad_block: u32) -> u32 {
    if session.is_null() { return 0xFFFFFFFF; }
    let session = unsafe { &mut *session };
    let mut inner = session.inner.lock().unwrap();
    
    if let Some(ref mut nand) = inner.active_nand {
        if let Some(ref mut lba) = nand.lba_map {
            let image_len = nand.image.len();
            if let Some(target) = lba.get_live_remap_target(bad_block as usize, &nand.layout, image_len) {
                return target as u32;
            }
        }
    }
    
    0xFFFFFFFF
}