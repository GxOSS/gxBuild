/*
  optini.rs - xeBuild style options.ini parser

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

use log::{info, warn};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OptionsIniError {
    #[error("[ini] Incorrect formatting in options.ini")]
    BadOptionsFormat(),
}

#[derive(Debug, Clone)]
pub struct CoreOptions {
    pub noenter: Option<bool>,
    pub nolog: Option<bool>,
    pub noinfo: Option<bool>,
    pub gxunsafe: Option<bool>,
    pub verbose: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct CoreBuilderOptions {
    pub nosecurity: Option<bool>,
    pub nosusecurity: Option<bool>,
    pub noremap: Option<bool>,
    pub nandmu: Option<bool>,
    pub nochainpatch: Option<bool>,
    pub nofcrt: Option<bool>,
    pub dualpatchslots: Option<bool>,
    pub mfg: Option<bool>,
    pub xsb: Option<bool>,
    pub nomobile: Option<bool>,
    pub full_image: Option<bool>,
    pub noecc: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct BuilderOptions {
    pub gxunsafe: Option<bool>,
    pub verbose: Option<bool>,
    pub noflashfs: Option<bool>,
    pub xellbutton: Option<String>,
    pub xellbutton2: Option<String>,
    pub noecdremap: Option<bool>,
    pub smcnocheck: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct JtagOptions {
    pub jtag_syscall: Option<u16>,
    pub jtag_pairing_2bl: Option<[u8; 3]>,
    pub cygnos: Option<bool>,
    pub demon: Option<bool>,
    pub smcnoeject: Option<bool>,
    pub smcnoblink: Option<bool>,
    pub patchsmc: Option<bool>,
    pub olddvd: Option<bool>,
    pub nodvd: Option<bool>,
    pub dualboot: Option<bool>,
}

impl Default for JtagOptions {
    fn default() -> Self {
        JtagOptions {
            jtag_syscall: None,
            jtag_pairing_2bl: None,
            cygnos: None,
            demon: None,
            smcnoeject: None,
            smcnoblink: None,
            patchsmc: None,
            olddvd: None,
            nodvd: None,
            dualboot: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmcConfigOptions {
    pub cputemp: Option<String>,
    pub gputemp: Option<String>,
    pub edramtemp: Option<String>,
    pub overcputemp: Option<String>,
    pub overgputemp: Option<String>,
    pub overedramtemp: Option<String>,
    pub cpufan: Option<String>,
    pub gpufan: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KeyvaultOptions {
    pub avregion: Option<String>,
    pub gameregion: Option<String>,
    pub dvdregion: Option<String>,
    pub macid: Option<String>,
    pub serial: Option<String>,
    pub consoleid: Option<String>,
    pub osig: Option<String>,
    pub mfdate: Option<String>,
    pub dvdkey: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GxBuildKeys {
    pub ctype: Option<String>,
    pub _1blkey: Option<String>,
    pub cpukey: Option<String>,
    pub cfldv: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OptionsIni {
    pub keys: GxBuildKeys,
    pub core: CoreOptions,
    pub core_builder: CoreBuilderOptions,
    pub builder: BuilderOptions,
    pub jtag: JtagOptions,
    pub smc_config: SmcConfigOptions,
    pub keyvault: KeyvaultOptions,
}

impl OptionsIni {
    pub fn new() -> Self {
        OptionsIni {
            keys: GxBuildKeys {
                ctype: None,
                _1blkey: None,
                cpukey: None,
                cfldv: None,
            },
            core: CoreOptions {
                noenter: None,
                nolog: None,
                noinfo: None,
                gxunsafe: None,
                verbose: None,
            },
            core_builder: CoreBuilderOptions {
                nosecurity: None,
                nosusecurity: None,
                noremap: None,
                nandmu: None,
                nochainpatch: None,
                nofcrt: None,
                dualpatchslots: None,
                mfg: None,
                xsb: None,
                nomobile: None,
                full_image: None,
                noecc: None,
            },
            builder: BuilderOptions {
                gxunsafe: None,
                verbose: None,
                noflashfs: None,
                xellbutton: None,
                xellbutton2: None,
                noecdremap: None,
                smcnocheck: None,
            },
            jtag: JtagOptions {
                jtag_syscall: None,
                jtag_pairing_2bl: None,
                cygnos: None,
                demon: None,
                smcnoeject: None,
                smcnoblink: None,
                patchsmc: None,
                olddvd: None,
                nodvd: None,
                dualboot: None,
            },
            smc_config: SmcConfigOptions {
                cputemp: None,
                gputemp: None,
                edramtemp: None,
                overcputemp: None,
                overgputemp: None,
                overedramtemp: None,
                cpufan: None,
                gpufan: None,
            },
            keyvault: KeyvaultOptions {
                avregion: None,
                gameregion: None,
                dvdregion: None,
                macid: None,
                serial: None,
                consoleid: None,
                osig: None,
                mfdate: None,
                dvdkey: None,
            },
        }
    }

    pub fn merge(&mut self, other: OptionsIni) {
        // GxBuildKeys
        if let Some(v) = other.keys.ctype {
            self.keys.ctype = Some(v);
        }
        if let Some(v) = other.keys._1blkey {
            self.keys._1blkey = Some(v);
        }
        if let Some(v) = other.keys.cpukey {
            self.keys.cpukey = Some(v);
        }
        if let Some(v) = other.keys.cfldv {
            self.keys.cfldv = Some(v);
        }

        // CoreOptions
        if let Some(v) = other.core.noenter {
            self.core.noenter = Some(v);
        }
        if let Some(v) = other.core.nolog {
            self.core.nolog = Some(v);
        }
        if let Some(v) = other.core.noinfo {
            self.core.noinfo = Some(v);
        }
        if let Some(v) = other.core.gxunsafe {
            self.core.gxunsafe = Some(v);
        }
        if let Some(v) = other.core.verbose {
            self.core.verbose = Some(v);
        }

        // CoreBuilderOptions
        if let Some(v) = other.core_builder.nosecurity {
            self.core_builder.nosecurity = Some(v);
        }
        if let Some(v) = other.core_builder.nosusecurity {
            self.core_builder.nosusecurity = Some(v);
        }
        if let Some(v) = other.core_builder.noremap {
            self.core_builder.noremap = Some(v);
        }
        if let Some(v) = other.core_builder.nandmu {
            self.core_builder.nandmu = Some(v);
        }
        if let Some(v) = other.core_builder.nochainpatch {
            self.core_builder.nochainpatch = Some(v);
        }
        if let Some(v) = other.core_builder.nofcrt {
            self.core_builder.nofcrt = Some(v);
        }
        if let Some(v) = other.core_builder.dualpatchslots {
            self.core_builder.dualpatchslots = Some(v);
        }
        if let Some(v) = other.core_builder.mfg {
            self.core_builder.mfg = Some(v);
        }
        if let Some(v) = other.core_builder.xsb {
            self.core_builder.xsb = Some(v);
        }
        if let Some(v) = other.core_builder.nomobile {
            self.core_builder.nomobile = Some(v);
        }
        if let Some(v) = other.core_builder.full_image {
            self.core_builder.full_image = Some(v);
        }
        if let Some(v) = other.core_builder.noecc {
            self.core_builder.noecc = Some(v);
        }

        // BuilderOptions
        if let Some(v) = other.builder.gxunsafe {
            self.builder.gxunsafe = Some(v);
        }
        if let Some(v) = other.builder.verbose {
            self.builder.verbose = Some(v);
        }
        if let Some(v) = other.builder.noflashfs {
            self.builder.noflashfs = Some(v);
        }
        if let Some(v) = other.builder.xellbutton {
            self.builder.xellbutton = Some(v);
        }
        if let Some(v) = other.builder.xellbutton2 {
            self.builder.xellbutton2 = Some(v);
        }
        if let Some(v) = other.builder.noecdremap {
            self.builder.noecdremap = Some(v);
        }
        if let Some(v) = other.builder.smcnocheck {
            self.builder.smcnocheck = Some(v);
        }

        // JtagOptions
        if let Some(v) = other.jtag.jtag_syscall {
            self.jtag.jtag_syscall = Some(v);
        }
        if let Some(v) = other.jtag.jtag_pairing_2bl {
            self.jtag.jtag_pairing_2bl = Some(v);
        }
        if let Some(v) = other.jtag.cygnos {
            self.jtag.cygnos = Some(v);
        }
        if let Some(v) = other.jtag.demon {
            self.jtag.demon = Some(v);
        }
        if let Some(v) = other.jtag.smcnoeject {
            self.jtag.smcnoeject = Some(v);
        }
        if let Some(v) = other.jtag.smcnoblink {
            self.jtag.smcnoblink = Some(v);
        }
        if let Some(v) = other.jtag.patchsmc {
            self.jtag.patchsmc = Some(v);
        }
        if let Some(v) = other.jtag.olddvd {
            self.jtag.olddvd = Some(v);
        }
        if let Some(v) = other.jtag.nodvd {
            self.jtag.nodvd = Some(v);
        }
        if let Some(v) = other.jtag.dualboot {
            self.jtag.dualboot = Some(v);
        }

        // SmcConfigOptions
        if let Some(v) = other.smc_config.cputemp {
            self.smc_config.cputemp = Some(v);
        }
        if let Some(v) = other.smc_config.gputemp {
            self.smc_config.gputemp = Some(v);
        }
        if let Some(v) = other.smc_config.edramtemp {
            self.smc_config.edramtemp = Some(v);
        }
        if let Some(v) = other.smc_config.overcputemp {
            self.smc_config.overcputemp = Some(v);
        }
        if let Some(v) = other.smc_config.overgputemp {
            self.smc_config.overgputemp = Some(v);
        }
        if let Some(v) = other.smc_config.overedramtemp {
            self.smc_config.overedramtemp = Some(v);
        }
        if let Some(v) = other.smc_config.cpufan {
            self.smc_config.cpufan = Some(v);
        }
        if let Some(v) = other.smc_config.gpufan {
            self.smc_config.gpufan = Some(v);
        }

        // KeyvaultOptions
        if let Some(v) = other.keyvault.avregion {
            self.keyvault.avregion = Some(v);
        }
        if let Some(v) = other.keyvault.gameregion {
            self.keyvault.gameregion = Some(v);
        }
        if let Some(v) = other.keyvault.dvdregion {
            self.keyvault.dvdregion = Some(v);
        }
        if let Some(v) = other.keyvault.macid {
            self.keyvault.macid = Some(v);
        }
        if let Some(v) = other.keyvault.serial {
            self.keyvault.serial = Some(v);
        }
        if let Some(v) = other.keyvault.consoleid {
            self.keyvault.consoleid = Some(v);
        }
        if let Some(v) = other.keyvault.osig {
            self.keyvault.osig = Some(v);
        }
        if let Some(v) = other.keyvault.mfdate {
            self.keyvault.mfdate = Some(v);
        }
        if let Some(v) = other.keyvault.dvdkey {
            self.keyvault.dvdkey = Some(v);
        }
    }

    pub fn set_option(&mut self, key: &str, value: &str) {
        let v = value;
        let is_true = v.eq_ignore_ascii_case("true");
        match key.to_lowercase().as_str() {
            "region" | "avregion" => self.keyvault.avregion = Some(v.to_string()),
            "gameregion" => self.keyvault.gameregion = Some(v.to_string()),
            "dvdregion" => self.keyvault.dvdregion = Some(v.to_string()),
            "unsafe" | "gxunsafe" => {
                self.core.gxunsafe = Some(is_true);
                self.builder.gxunsafe = Some(is_true);
            }
            "verbose" => {
                self.core.verbose = Some(is_true);
                self.builder.verbose = Some(is_true);
                let _ = crate::core::logger::init_logger("build", is_true);
            }
            "nomobile" => self.core_builder.nomobile = Some(is_true),
            "noremap" => self.core_builder.noremap = Some(is_true),
            "nandmu" => self.core_builder.nandmu = Some(is_true),
            "cputemp" => self.smc_config.cputemp = Some(v.to_string()),
            "gputemp" => self.smc_config.gputemp = Some(v.to_string()),
            "edramtemp" => self.smc_config.edramtemp = Some(v.to_string()),
            "overcputemp" => self.smc_config.overcputemp = Some(v.to_string()),
            "overgputemp" => self.smc_config.overgputemp = Some(v.to_string()),
            "overedramtemp" => self.smc_config.overedramtemp = Some(v.to_string()),
            "cpufan" => self.smc_config.cpufan = Some(v.to_string()),
            "gpufan" => self.smc_config.gpufan = Some(v.to_string()),
            "macid" | "mac" => self.keyvault.macid = Some(v.to_string()),
            "dvdkey" => self.keyvault.dvdkey = Some(v.to_string()),
            "cfldv" => self.keys.cfldv = Some(v.to_string()),
            "serial" => self.keyvault.serial = Some(v.to_string()),
            "consoleid" => self.keyvault.consoleid = Some(v.to_string()),
            "osig" => self.keyvault.osig = Some(v.to_string()),
            "mfdate" => self.keyvault.mfdate = Some(v.to_string()),
            "nofcrt" => self.core_builder.nofcrt = Some(is_true),
            "xellbutton" => self.builder.xellbutton = Some(v.to_string()),
            "xellbutton2" => self.builder.xellbutton2 = Some(v.to_string()),
            "cygnos" => self.jtag.cygnos = Some(is_true),
            "demon" => self.jtag.demon = Some(is_true),
            "smcnoeject" => self.jtag.smcnoeject = Some(is_true),
            "smcnoblink" => self.jtag.smcnoblink = Some(is_true),
            "patchsmc" => self.jtag.patchsmc = Some(is_true),
            "olddvd" => self.jtag.olddvd = Some(is_true),
            "nodvd" => self.jtag.nodvd = Some(is_true),
            "dualboot" => self.jtag.dualboot = Some(is_true),
            "dualpatchslots" => self.core_builder.dualpatchslots = Some(is_true),
            "nolog" => self.core.nolog = Some(is_true),
            "noinfo" => self.core.noinfo = Some(is_true),
            "noenter" => self.core.noenter = Some(is_true),
            "noecc" => self.core_builder.noecc = Some(is_true),
            "noecdremap" => self.builder.noecdremap = Some(is_true),
            "smcnocheck" => self.builder.smcnocheck = Some(is_true),
            "nosecurity" => self.core_builder.nosecurity = Some(is_true),
            "nosusecurity" => self.core_builder.nosusecurity = Some(is_true),
            "nochainpatch" => self.core_builder.nochainpatch = Some(is_true),
            "mfg" => self.core_builder.mfg = Some(is_true),
            "xsb" => self.core_builder.xsb = Some(is_true),
            "full_image" => self.core_builder.full_image = Some(is_true),
            _ => warn!("[session] set_option: unknown key '{}'", key),
        }
    }
}

pub fn parse_options_ini(content: &str) -> Result<OptionsIni, OptionsIniError> {
    info!("[ini] Parsing options.ini");

    let mut options = OptionsIni::new();

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            return Err(OptionsIniError::BadOptionsFormat());
        } else {
            let parts: Vec<String> = line
                .split(" = ")
                .map(|s| s.trim_end_matches(';').trim().to_string())
                .collect();
            match parts.as_slice() {
                [key, value] => match key.to_lowercase().as_str() {
                    "type" => options.keys.ctype = Some(value.clone()),
                    "1blkey" => options.keys._1blkey = Some(value.clone()),
                    "cpukey" => options.keys.cpukey = Some(value.clone()),
                    "cfldv" => options.keys.cfldv = Some(value.clone()),
                    "dvdkey" => options.keyvault.dvdkey = Some(value.clone()),
                    "xellbutton" => options.builder.xellbutton = Some(value.clone()),
                    "xellbutton2" => options.builder.xellbutton2 = Some(value.clone()),
                    "cygnos" => options.jtag.cygnos = Some(value.eq_ignore_ascii_case("true")),
                    "demon" => options.jtag.demon = Some(value.eq_ignore_ascii_case("true")),
                    "smcnoeject" => options.jtag.smcnoeject = Some(value.eq_ignore_ascii_case("true")),
                    "smcnoblink" => options.jtag.smcnoblink = Some(value.eq_ignore_ascii_case("true")),
                    "patchsmc" => options.jtag.patchsmc = Some(value.eq_ignore_ascii_case("true")),
                    "olddvd" => options.jtag.olddvd = Some(value.eq_ignore_ascii_case("true")),
                    "nodvd" => options.jtag.nodvd = Some(value.eq_ignore_ascii_case("true")),
                    "dualboot" => options.jtag.dualboot = Some(value.eq_ignore_ascii_case("true")),
                    "nomobile" => {
                        options.core_builder.nomobile = Some(value.eq_ignore_ascii_case("true"))
                    }
                    "noremap" => options.core_builder.noremap = Some(value.eq_ignore_ascii_case("true")),
                    "noecdremap" => options.builder.noecdremap = Some(value.eq_ignore_ascii_case("true")),
                    "nandmu" => options.core_builder.nandmu = Some(value.eq_ignore_ascii_case("true")),
                    "nosecurity" => options.core_builder.nosecurity = Some(value.eq_ignore_ascii_case("true")),
                    "nosusecurity" => {
                        options.core_builder.nosusecurity = Some(value.eq_ignore_ascii_case("true"))
                    }
                    "noecc" => options.core_builder.noecc = Some(value.eq_ignore_ascii_case("true")),
                    "noflashfs" => options.builder.noflashfs = Some(value.eq_ignore_ascii_case("true")),
                    "dualpatchslots" => {
                        options.core_builder.dualpatchslots = Some(value.eq_ignore_ascii_case("true"))
                    }
                    "smcnocheck" => options.builder.smcnocheck = Some(value.eq_ignore_ascii_case("true")),
                    "noenter" => options.core.noenter = Some(value.eq_ignore_ascii_case("true")),
                    "nolog" => options.core.nolog = Some(value.eq_ignore_ascii_case("true")),
                    "noinfo" => options.core.noinfo = Some(value.eq_ignore_ascii_case("true")),
                    "gxunsafe" | "unsafe" => {
                        let b = value.eq_ignore_ascii_case("true");
                        options.core.gxunsafe = Some(b);
                        options.builder.gxunsafe = Some(b);
                    }
                    "verbose" => {
                        let b = value.eq_ignore_ascii_case("true");
                        options.core.verbose = Some(b);
                        options.builder.verbose = Some(b);
                    }
                    "nochainpatch" => {
                        options.core_builder.nochainpatch = Some(value.eq_ignore_ascii_case("true"))
                    }
                    "cputemp" => options.smc_config.cputemp = Some(value.clone()),
                    "gputemp" => options.smc_config.gputemp = Some(value.clone()),
                    "edramtemp" => options.smc_config.edramtemp = Some(value.clone()),
                    "overcputemp" => options.smc_config.overcputemp = Some(value.clone()),
                    "overgputemp" => options.smc_config.overgputemp = Some(value.clone()),
                    "overedramtemp" => options.smc_config.overedramtemp = Some(value.clone()),
                    "cpufan" => options.smc_config.cpufan = Some(value.clone()),
                    "gpufan" => options.smc_config.gpufan = Some(value.clone()),
                    "avregion" => options.keyvault.avregion = Some(value.clone()),
                    "gameregion" => options.keyvault.gameregion = Some(value.clone()),
                    "dvdregion" => options.keyvault.dvdregion = Some(value.clone()),
                    "macid" => options.keyvault.macid = Some(value.clone()),
                    "serial" => options.keyvault.serial = Some(value.clone()),
                    "consoleid" => options.keyvault.consoleid = Some(value.clone()),
                    "osig" => options.keyvault.osig = Some(value.clone()),
                    "mfdate" => options.keyvault.mfdate = Some(value.clone()),
                    "nofcrt" => options.core_builder.nofcrt = Some(value.eq_ignore_ascii_case("true")),
                    "mfg" => options.core_builder.mfg = Some(value.eq_ignore_ascii_case("true")),
                    "xsb" => options.core_builder.xsb = Some(value.eq_ignore_ascii_case("true")),
                    "full_image" => {
                        options.core_builder.full_image = Some(value.eq_ignore_ascii_case("true"))
                    }
                    _ => warn!("[ini] Unknown option: {}", key),
                },
                _ => {}
            }
        }
    }
    Ok(options)
}
