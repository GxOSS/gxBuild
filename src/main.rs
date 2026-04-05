/*
    main.rs
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/


// GGXBuild release entry point

pub mod core;

fn main() {
    core::adapters::cli::ggx_cli();
}