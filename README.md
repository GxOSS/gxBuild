<p align="center">
  <img src="assets/gx_banner_colour_trans.png" alt="gxBuild Colour Transparent Banner" width="600">
</p>

<p align="center">
  <a href="https://github.com/ExposureMG/gxBuild/issues"><img src="https://img.shields.io/github/issues/gxOSS/gxBuild?" alt="GitHub issues"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-%23E32F26.svg?&logo=rust&logoColor=white" alt="Rust"></a>
</p>

# gxBuild
> [!CAUTION]
> * gxBuild is **UNSTABLE**!
> * The app is still **UNTESTED** against real consoles!
> * There is a **99.99%** chance you will brick your console!

Xbox 360 NAND image builder and patcher. Based on [x360utils](https://github.com/Swizzy/x360Utils), [xenon-bltool](https://github.com/InvoxiPlayGames/xenon-bltool), and [RGBuildPP](https://github.com/emoose/RGBuildPP).

Sister Repos: 

- [gxBuild Support Files](https://github.com/ExposureMG/gxBuild-Support-Files)
- [gxBuild Patches](https://github.com/ExposureMG/gxBuild-patches)

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

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

*Documentation Coming Soon.*

## Contributing

See [CONTRIBUTING.md](/CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests. Refer to [CREDITS.md](/CREDITS.md) to see the history of contributors and projects that made gxBuild possible.

## License

This project is multi-licensed. Releases are distributed under the **GNU General Public License v2** inherited from xenon-bltool.

Component breakdown:

* **Original gxBuild code:** Zlib License
* **xenon-bltool:** GPL v2
* **x360utils:** Unlicense
* **XeCrypt:** MIT License
* **STFS:** MIT License

All code taken from other projects has been properly attributed in their respective file headers.
