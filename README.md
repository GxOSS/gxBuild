<p align="center">
  <img src="assets/gx_banner_colour_trans.png" alt="gxBuild Colour Transparent Banner" width="600">
</p>

<p align="center">
  <a href="https://github.com/ExposureMG/gxBuild/issues"><img src="https://img.shields.io/github/issues/ExposureMG/gxBuild?" alt="GitHub issues"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-%23E32F26.svg?&logo=rust&logoColor=white" alt="Rust"></a>
</p>

# gxBuild
> [!CAUTION]
> * gxBuild is **UNSTABLE**!
> * The app is still **UNTESTED** against real consoles!
> * There is a **99.99%** chance you will brick your console!

gxBuild is an Xbox 360 NAND image builder and patcher. It is based on [x360utils](https://github.com/Swizzy/x360Utils), [xenon-bltool](https://github.com/InvoxiPlayGames/xenon-bltool), and [RGBuildPP](https://github.com/emoose/RGBuildPP).

Sister Repos: 

- [gxBuild Support Files](https://github.com/ExposureMG/gxBuild-Support-Files)
- [gxBuild Patches](https://github.com/ExposureMG/gxBuild-patches)

## Table of Contents

- [Background](#background)
- [Features](#features)
- [Install](#install)
- [Usage](#usage)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Background

gxBuild was created to provide a modern, highly compatible alternative to older tools like xeBuild, but with added extensibility. It aims to bridge multiple Xbox 360 modding workflows by incorporating features for retail, devkit, and custom image building, alongside scripting and Foreign Function Interface (FFI) capabilities for developers.

## Features

- **Compatibility:** Mostly compatible with xeBuild.
- **Image Types:** Supports NAND, Shadowboot, and XeLL images.
- **Hack Support:** Build JTAG, Glitch (RGH1, RGH2, RGH3, RJTAG), and DevGL images.
- **XDK/Development:** Full support for RGBuild, XDKBuild, and Devkit images.
- **Scripting:** Full scripting support and an Interactive Shell powered by Rhai.
- **Patching:** Supports XEPATCH, GXS2, and JSON Signature Patches.
- **Developer-Friendly:** Fully set up with [Interoptopus](https://github.com/ralfbiedert/interoptopus) for FFI bindings with C# and C.

## Install

Ensure you have [Rust and Cargo installed](https://www.rust-lang.org/tools/install). Clone the repository and build using one of the following feature combinations:

### Default (CLI, FFI, and Rhai Scripting)
```bash
cargo build --release

```

### CLI Only

```bash
cargo build --no-default-features --features cli

```

### FFI Only

```bash
cargo build --no-default-features --features ffi

```

### CLI + Rhai Scripting

```bash
cargo build --no-default-features --features cli,rhai

```

### FFI + Rhai Scripting

```bash
cargo build --no-default-features --features ffi,rhai

```

## Usage

*Documentation Coming Soon.* Refer to the internal `README.md` files located in each subfolder for detailed technical explanations of individual submodules and underlying logic.

## Testing

*Legend: ✓ = Tested Working*

| Platform | Retail Single | Retail Split | Argon / Aud | JTAG FJZ | RJTAG | Glitch1 | Glitch2 | Glitch3 | Glitch2.3 | XDKBuild | RGBuild |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Xenon** |  |  |  |  |  |  |  |  |  |  |  |
| **Zephyr** |  |  |  |  |  |  |  |  |  |  |  |
| **Falcon** |  |  |  |  |  |  |  |  |  |  |  |
| **Jasper** |  |  |  |  |  |  |  |  |  |  |  |
| **Jasper BB** |  |  |  |  |  |  |  |  |  |  |  |
| **Trinity** |  |  |  |  |  |  |  |  |  |  |  |
| **Trinity BB** |  |  |  |  |  |  |  |  |  |  |  |
| **Corona** |  |  |  |  |  |  |  |  |  |  |  |
| **Corona 4G** |  |  |  |  |  |  |  |  |  |  |  |

## Contributing

See [CONTRIBUTING.md](/CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests. Refer to [CREDITS.md](/CREDITS.md) to see the history of contributors and projects that made gxBuild possible.

## License

This project is multi-licensed. Releases are distributed under the **GNU General Public License v2** (inherited from xenon-bltool).

Component breakdown:

* **Original gxBuild code:** Zlib License
* **xenon-bltool:** GPL v2
* **libmspack:** Relicensed as GPL v2
* **ExCrypt:** BSD 3-Clause License
* **Xenia:** BSD 3-Clause License
* **x360utils:** Unlicense

All code taken from other projects has been properly attributed in their respective file headers.
