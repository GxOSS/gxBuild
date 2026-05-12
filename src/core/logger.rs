/*
    logger.rs - Small logging interface

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

use std::fs;
use std::path::Path;
use std::ffi::CString;
use std::time::{SystemTime, UNIX_EPOCH};
use fern::colors::{Color, ColoredLevelConfig};

pub fn init_logger(mode: &str, verbose: bool) -> Result<(), fern::InitError> {
    // 1. Create logs directory if it doesn't exist
    let log_dir = Path::new("logs");
    if !log_dir.exists() {
        let _ = fs::create_dir_all(log_dir);
    }

    // 2. Generate filename: gxbuild-<mode>-<secs>.log
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let timestamp = since_the_epoch.as_secs();
    let filename = format!("logs/gxbuild-{}-{}.log", mode, timestamp);

    // 3. Configure logging level
    // We set the dispatcher to Info to allow verbose logs through, 
    // and control the active level via log::set_max_level globally.
    let level = log::LevelFilter::Info;

    // 4. Configure colors for stdout
    let colors = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Green)
        .debug(Color::White)
        .trace(Color::BrightBlack);

    // 5. Setup fern
    if log::max_level() == log::LevelFilter::Off {
        fern::Dispatch::new()
            .format(move |out, message, record| {
                if let Some(cb) = unsafe { crate::core::interface::ffi::LOG_CALLBACK } {
                    let msg = CString::new(format!("{}", message)).unwrap_or_default();
                    cb(record.level() as i32, msg.as_ptr());
                }
                out.finish(format_args!(
                    "[{}] {}",
                    colors.color(record.level()),
                    message
                ))
            })
            .level(level)
            .chain(std::io::stdout())
            .chain(
                fern::log_file(filename)?
            )
            .apply()?;
    }

    // 6. Set global level
    if verbose {
        log::set_max_level(log::LevelFilter::Info);
    } else {
        log::set_max_level(log::LevelFilter::Error);
    }

    Ok(())
}

pub fn flush_logger() {
    log::logger().flush();
}
