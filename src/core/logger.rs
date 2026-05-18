/*
  logger.rs - Small logging interface

  Copyright (c) 2026 gxBuild Contributors and Developers

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/

use fern::colors::{Color, ColoredLevelConfig};
use std::ffi::CString;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn init_logger(mode: &str, verbose: bool) -> Result<(), fern::InitError> {
    // Create logs directory if it doesn't exist
    let log_dir = Path::new("logs");
    if !log_dir.exists() {
        let _ = fs::create_dir_all(log_dir);
    }

    // Generate filename: gxbuild-<mode>-<secs>.log
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let timestamp = since_the_epoch.as_secs();
    let filename = format!("logs/gxbuild-{}-{}.log", mode, timestamp);

    // Configure logging level
    let level = log::LevelFilter::Info;

    // Configure colors for stdout
    let colors = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Green)
        .debug(Color::White)
        .trace(Color::BrightBlack);

    // Setup fern
    if log::max_level() == log::LevelFilter::Off {
        fern::Dispatch::new()
            .format(move |out, message, record| {
                if let Some(cb) = unsafe { crate::core::interface::ffi::LOG_CALLBACK } {
                    let msg = CString::new(format!("{}", message)).unwrap_or_default();
                    cb(record.level() as i32, msg.as_ptr());
                }
                out.finish(format_args!("[{}] {}", colors.color(record.level()), message))
            })
            .level(level)
            .chain(std::io::stdout())
            .chain(fern::log_file(filename)?)
            .apply()?;
    }

    // Set global level
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
