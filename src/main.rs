// GGXBuild release entry point

pub mod core;
pub mod deps;

fn main() {
    core::adapters::cli::ggx_cli();
}