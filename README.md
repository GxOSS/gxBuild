# gxBuild

>[!CAUTION]
> * gxBuild is **UNSTABLE**!
> * The app is still **UNTESTED** against real consoles!
> * There is a **99.99%** chance you will brick your console!

![gxBuild Colour Transparent Banner](assets/gx_banner_colour_trans.png)

gxBuild is a Xbox 360 image builder and patcher.

Based on [x360utils](https://github.com/Swizzy/x360Utils), [xenon-bltool](https://github.com/InvoxiPlayGames/xenon-bltool), and [RGBuildPP](https://github.com/emoose/RGBuildPP). Releases are licensed under the GPL v2 (inherited from xenon-bltool).


## Features

- Mostly compatible with xeBuild
- NAND, Shadowboot and XeLL support
- JTAG and Glitch Images
- RGBuild / XDKBuild Images
- Devkit / DevGL Images
- Full Scripting support and Interactive Shell
- XEPATCH, GXS2, and JSON Signature Patches

## Documentation

Coming Soon

## Info

- [CREDITS.md](docs/CREDITS.md) - Project Credits
- [CONTRIBUTING.md](docs/CONTRIBUTING.md) - Contribution Guidelines
- [CHANGELOG.md](docs/CHANGELOG.md) - Changelog

## Testing

✓ = Tested Working

| Platform | Retail Single | Retail Split | Argon / Aud | JTAG FJZ | RJTAG | Glitch1 | Glitch2 | Glitch3 | Glitch2.3 | XDKBuild | RGBuild |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | 
| Xenon |  |  |  |  |  |  |  |  |  |  |  |
| Zephyr |  |  |  |  |  |  |  |  |  |  |  |
| Falcon |  |  |  |  |  |  |  |  |  |  |  |
| Jasper |  |  |  |  |  |  |  |  |  |  |  |
| Jasper BB |  |  |  |  |  |  |  |  |  |  |  |
| Trinity |  |  |  |  |  |  |  |  |  |  |  |
| Trinity BB |  |  |  |  |  |  |  |  |  |  |  |
| Corona |  |  |  |  |  |  |  |  |  |  |  |
| Corona 4G |  |  |  |  |  |  |  |  |  |  |  |

## Developer

In every folder ive included a README explaining the files and submodules.

The project is fully setup with [Interoptopus](https://github.com/ralfbiedert/interoptopus) for ffi bindings with C# and C.

### Building

Default (CLI, FFI, Rhai)

```bash
cargo build --release
```

CLI Only

```bash
cargo build --no-default-features --features cli
```

FFI Only

```bash
cargo build --no-default-features --features ffi
```

CLI + Rhai Scripting

```bash
cargo build --no-default-features --features cli,rhai
```

FFI + Rhai Scripting

```bash
cargo build --no-default-features --features ffi,rhai
```

## License

gxBuild is multi-licensed, distributed under the GPL version 2.

Original gxBuild code is Zlib.

x360utils is licensed under the unlicense.

xenon-bltool is licensed under the GPL v2.

libmspack is relicensed as GPL v2.

ExCrypt is licensed under the BSD 3-Clause License.

Xenia is licensed under the BSD 3-Clause License.

All code taken from other projects has been properly attributed in the header.
