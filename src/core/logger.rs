/*
    logger.rs
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/

use std::fs;
use std::path::Path;
use chrono::Local;
use fern::colors::{Color, ColoredLevelConfig};

pub fn init_logger(mode: &str, verbose: bool) -> Result<(), fern::InitError> {
    // 1. Create logs directory if it doesn't exist
    let log_dir = Path::new("logs");
    if !log_dir.exists() {
        fs::create_dir_all(log_dir)?;
    }

    // 2. Generate filename: gxbuild-<mode>-<date>-<time>.log
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d-%H-%M-%S").to_string();
    let filename = format!("logs/gxbuild-{}-{}.log", mode, timestamp);

    // 3. Configure logging level
    let level = if verbose {
        log::LevelFilter::Info
    } else {
        log::LevelFilter::Error
    };

    // 4. Configure colors for stdout
    let colors = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Green)
        .debug(Color::White)
        .trace(Color::BrightBlack);

    // 5. Setup fern
    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{}] [{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
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

    Ok(())
}
