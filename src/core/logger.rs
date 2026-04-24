/*
    logger.rs - Small logging interface

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under GPLv2 (inherited from xenon-bltool).
*/

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use fern::colors::{Color, ColoredLevelConfig};

pub fn init_logger(mode: &str, verbose: bool) -> Result<(), fern::InitError> {
    // 1. Create logs directory if it doesn't exist
    let log_dir = Path::new("logs");
    if !log_dir.exists() {
        fs::create_dir_all(log_dir)?;
    }

    // 2. Generate filename: gxbuild-<mode>-<secs>.log
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let timestamp = since_the_epoch.as_secs();
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

    Ok(())
}
