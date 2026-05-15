use log::{info, warn};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OptionsIniError {
    #[error("[ini] Incorrect formatting in options.ini")]
    BadOptionsFormat(),
}

#[derive(Debug, Clone)]
pub struct OptionsIni {
    pub ctype: Option<String>,
    pub _1blkey: Option<String>,
    pub cpukey: Option<String>,
    pub cfldv: Option<String>,
    pub dvdkey: Option<String>,
    pub xellbutton: Option<String>,
    pub xellbutton2: Option<String>,
    pub cygnos: Option<bool>,
    pub demon: Option<bool>,
    pub smcnoeject: Option<bool>,
    pub smcnoblink: Option<bool>,
    pub patchsmc: Option<bool>,
    pub olddvd: Option<bool>,
    pub nodvd: Option<bool>,
    pub dualboot: Option<bool>,
    pub nomobile: Option<bool>,
    pub noremap: Option<bool>,
    pub noecdremap: Option<bool>,
    pub nandmu: Option<bool>,
    pub nosecurity: Option<bool>,
    pub nosusecurity: Option<bool>,
    pub noecc: Option<bool>,
    pub noflashfs: Option<bool>,
    pub smcnocheck: Option<bool>,
    pub cputemp: Option<String>,
    pub gputemp: Option<String>,
    pub edramtemp: Option<String>,
    pub overcputemp: Option<String>,
    pub overgputemp: Option<String>,
    pub overedramtemp: Option<String>,
    pub cpufan: Option<String>,
    pub gpufan: Option<String>,
    pub avregion: Option<String>,
    pub gameregion: Option<String>,
    pub dvdregion: Option<String>,
    pub macid: Option<String>,
    pub noenter: Option<bool>,
    pub nolog: Option<bool>,
    pub noinfo: Option<bool>,
    pub gxunsafe: Option<bool>,
    pub verbose: Option<bool>,
    pub cba: Option<String>,
    pub cbb: Option<String>,
    pub full_image: Option<bool>,
    pub xsb: Option<bool>,
    pub serial: Option<String>,
    pub consoleid: Option<String>,
    pub osig: Option<String>,
    pub mfdate: Option<String>,
    pub fcrt: Option<bool>,
}

impl OptionsIni {
    pub fn new() -> Self {
        OptionsIni {
            ctype: None,
            _1blkey: None,
            cpukey: None,
            cfldv: None,
            dvdkey: None,
            xellbutton: None,
            xellbutton2: None,
            cygnos: None,
            demon: None,
            smcnoeject: None,
            smcnoblink: None,
            patchsmc: None,
            olddvd: None,
            nodvd: None,
            dualboot: None,
            nomobile: None,
            noremap: None,
            noecdremap: None,
            nandmu: None,
            nosecurity: None,
            nosusecurity: None,
            noecc: None,
            noflashfs: None,
            smcnocheck: None,
            noenter: None,
            nolog: None,
            noinfo: None,
            gxunsafe: None,
            verbose: None,
            cba: None,
            cbb: None,
            cputemp: None,
            gputemp: None,
            edramtemp: None,
            overcputemp: None,
            overgputemp: None,
            overedramtemp: None,
            cpufan: None,
            gpufan: None,
            avregion: None,
            gameregion: None,
            dvdregion: None,
            macid: None,
            full_image: None,
            xsb: None,
            serial: None,
            consoleid: None,
            osig: None,
            mfdate: None,
            fcrt: None,
        }
    }

    pub fn merge(&mut self, other: OptionsIni) {
        if let Some(v) = other.ctype { self.ctype = Some(v); }
        if let Some(v) = other._1blkey { self._1blkey = Some(v); }
        if let Some(v) = other.cpukey { self.cpukey = Some(v); }
        if let Some(v) = other.cfldv { self.cfldv = Some(v); }
        if let Some(v) = other.dvdkey { self.dvdkey = Some(v); }
        if let Some(v) = other.xellbutton { self.xellbutton = Some(v); }
        if let Some(v) = other.xellbutton2 { self.xellbutton2 = Some(v); }
        if let Some(v) = other.cygnos { self.cygnos = Some(v); }
        if let Some(v) = other.demon { self.demon = Some(v); }
        if let Some(v) = other.smcnoeject { self.smcnoeject = Some(v); }
        if let Some(v) = other.smcnoblink { self.smcnoblink = Some(v); }
        if let Some(v) = other.patchsmc { self.patchsmc = Some(v); }
        if let Some(v) = other.olddvd { self.olddvd = Some(v); }
        if let Some(v) = other.nodvd { self.nodvd = Some(v); }
        if let Some(v) = other.dualboot { self.dualboot = Some(v); }
        if let Some(v) = other.nomobile { self.nomobile = Some(v); }
        if let Some(v) = other.noremap { self.noremap = Some(v); }
        if let Some(v) = other.noecdremap { self.noecdremap = Some(v); }
        if let Some(v) = other.nandmu { self.nandmu = Some(v); }
        if let Some(v) = other.nosecurity { self.nosecurity = Some(v); }
        if let Some(v) = other.nosusecurity { self.nosusecurity = Some(v); }
        if let Some(v) = other.noecc { self.noecc = Some(v); }
        if let Some(v) = other.noflashfs { self.noflashfs = Some(v); }
        if let Some(v) = other.smcnocheck { self.smcnocheck = Some(v); }
        if let Some(v) = other.noenter { self.noenter = Some(v); }
        if let Some(v) = other.nolog { self.nolog = Some(v); }
        if let Some(v) = other.noinfo { self.noinfo = Some(v); }
        if let Some(v) = other.gxunsafe { self.gxunsafe = Some(v); }
        if let Some(v) = other.verbose { self.verbose = Some(v); }
        if let Some(v) = other.cba { self.cba = Some(v); }
        if let Some(v) = other.cbb { self.cbb = Some(v); }
        if let Some(v) = other.cputemp { self.cputemp = Some(v); }
        if let Some(v) = other.gputemp { self.gputemp = Some(v); }
        if let Some(v) = other.edramtemp { self.edramtemp = Some(v); }
        if let Some(v) = other.overcputemp { self.overcputemp = Some(v); }
        if let Some(v) = other.overgputemp { self.overgputemp = Some(v); }
        if let Some(v) = other.overedramtemp { self.overedramtemp = Some(v); }
        if let Some(v) = other.cpufan { self.cpufan = Some(v); }
        if let Some(v) = other.gpufan { self.gpufan = Some(v); }
        if let Some(v) = other.avregion { self.avregion = Some(v); }
        if let Some(v) = other.gameregion { self.gameregion = Some(v); }
        if let Some(v) = other.dvdregion { self.dvdregion = Some(v); }
        if let Some(v) = other.macid { self.macid = Some(v); }
        if let Some(v) = other.full_image { self.full_image = Some(v); }
        if let Some(v) = other.xsb { self.xsb = Some(v); }
        if let Some(v) = other.serial { self.serial = Some(v); }
        if let Some(v) = other.consoleid { self.consoleid = Some(v); }
        if let Some(v) = other.osig { self.osig = Some(v); }
        if let Some(v) = other.mfdate { self.mfdate = Some(v); }
        if let Some(v) = other.fcrt { self.fcrt = Some(v); }
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
                    "type" => options.ctype = Some(value.clone()),
                    "1blkey" => options._1blkey = Some(value.clone()),
                    "cpukey" => options.cpukey = Some(value.clone()),
                    "cfldv" => options.cfldv = Some(value.clone()),
                    "dvdkey" => options.dvdkey = Some(value.clone()),
                    "xellbutton" => options.xellbutton = Some(value.clone()),
                    "xellbutton2" => options.xellbutton2 = Some(value.clone()),
                    "cygnos" => options.cygnos = Some(value.eq_ignore_ascii_case("true")),
                    "demon" => options.demon = Some(value.eq_ignore_ascii_case("true")),
                    "smcnoeject" => options.smcnoeject = Some(value.eq_ignore_ascii_case("true")),
                    "smcnoblink" => options.smcnoblink = Some(value.eq_ignore_ascii_case("true")),
                    "patchsmc" => options.patchsmc = Some(value.eq_ignore_ascii_case("true")),
                    "olddvd" => options.olddvd = Some(value.eq_ignore_ascii_case("true")),
                    "nodvd" => options.nodvd = Some(value.eq_ignore_ascii_case("true")),
                    "dualboot" => options.dualboot = Some(value.eq_ignore_ascii_case("true")),
                    "nomobile" => options.nomobile = Some(value.eq_ignore_ascii_case("true")),
                    "noremap" => options.noremap = Some(value.eq_ignore_ascii_case("true")),
                    "noecdremap" => options.noecdremap = Some(value.eq_ignore_ascii_case("true")),
                    "nandmu" => options.nandmu = Some(value.eq_ignore_ascii_case("true")),
                    "nosecurity" => options.nosecurity = Some(value.eq_ignore_ascii_case("true")),
                    "nosusecurity" => options.nosusecurity = Some(value.eq_ignore_ascii_case("true")),
                    "noecc" => options.noecc = Some(value.eq_ignore_ascii_case("true")),
                    "noflashfs" => options.noflashfs = Some(value.eq_ignore_ascii_case("true")),
                    "smcnocheck" => options.smcnocheck = Some(value.eq_ignore_ascii_case("true")),
                    "noenter" => options.noenter = Some(value.eq_ignore_ascii_case("true")),
                    "nolog" => options.nolog = Some(value.eq_ignore_ascii_case("true")),
                    "noinfo" => options.noinfo = Some(value.eq_ignore_ascii_case("true")),
                    "gxunsafe" | "unsafe" => options.gxunsafe = Some(value.eq_ignore_ascii_case("true")),
                    "verbose" => options.verbose = Some(value.eq_ignore_ascii_case("true")),
                    "cba" => options.cba = Some(value.clone()),
                    "cbb" => options.cbb = Some(value.clone()),
                    "cputemp" => options.cputemp = Some(value.clone()),
                    "gputemp" => options.gputemp = Some(value.clone()),
                    "edramtemp" => options.edramtemp = Some(value.clone()),
                    "overcputemp" => options.overcputemp = Some(value.clone()),
                    "overgputemp" => options.overgputemp = Some(value.clone()),
                    "overedramtemp" => options.overedramtemp = Some(value.clone()),
                    "cpufan" => options.cpufan = Some(value.clone()),
                    "gpufan" => options.gpufan = Some(value.clone()),
                    "avregion" => options.avregion = Some(value.clone()),
                    "gameregion" => options.gameregion = Some(value.clone()),
                    "dvdregion" => options.dvdregion = Some(value.clone()),
                    "macid" => options.macid = Some(value.clone()),
                    "serial" => options.serial = Some(value.clone()),
                    "consoleid" => options.consoleid = Some(value.clone()),
                    "osig" => options.osig = Some(value.clone()),
                    "mfdate" => options.mfdate = Some(value.clone()),
                    "fcrt" => options.fcrt = Some(value.eq_ignore_ascii_case("true")),
                    _ => warn!("[ini] Unknown option: {}", key),
                },
                _ => {}
            }
        }
    }
    Ok(options)
}
