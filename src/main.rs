/*
    main.rs - gxBuild release entry point

    Created in 2026 by Exposure / Zach for gxBuild.
    Licensed under the GNU General Public License Version 2.0
*/

#[cfg(feature = "cli")]
fn main() {
    libgxbuild::core::interface::cli::ggx_cli();
}

#[cfg(not(feature = "cli"))]
fn main() {
    println!("gxbuild successfully compiled (CLI feature disabled).");
}