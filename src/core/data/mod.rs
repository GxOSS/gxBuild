/*
    commands/mod.rs
    
    This file was wrote by ExposureMG / Zach for the Public Domain.

    You may freely distribute, modify, and use this code for any purpose,
    commercial or non-commercial, on the terms that it comes with No Warranty.

    ExposureMG / Zach is not responsible or liable for any damage caused by this code.
*/

pub mod xeini;


use crate::builder::builder::NandSkeleton;

pub fn extract(_nand: &Option<NandSkeleton>, _id: String) {}
pub fn extract_all(_nand: &Option<NandSkeleton>) {}
pub fn apply_xe_ini(_nand: Option<NandSkeleton>, _ini: xeini::XeBuildIni) -> anyhow::Result<Option<NandSkeleton>> {
    Ok(_nand)
}