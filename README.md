# gxBuild

>[!CAUTION]
> * gxBuild is **UNSTABLE**!
> * The app is still **UNTESTED** against real consoles!
> * There is a **99.99%** chance you will brick your console!

![gxBuild Colour Transparent Banner](assets/gx_banner_colour_trans.png)

gxBuild is a Xbox 360 image builder and patcher. Features full nand, xell and shadowboot parsing, patching and building. Stays as close to xeBuild as possible, with a few changes. 

Based on [x360utils](https://github.com/Swizzy/x360Utils), [xenon-bltool](), and ~~J-Runner with Extras~~ (Replaced with legally valid permissive code). Releases are licensed under the GPL v2 (inherited from xenon-bltool).

## Features

| Feature | gxBuild | xeBuild | RGBuild |
| ------- | ------- | ------- | ------- |
| Retail | ✅ | ✅ | ❌ |
| Devkit | ✅ | ✅ | ❌ |
| DevGL | ✅ | ✅ | ❌ |
| RGLoader | ✅ | ❌ | ✅ |
| XDKBuild | ✅ | - | ❌ |
| Glitch3 | ✅ | ❌ | ❌ |
| SMC Patcher | ✅ | ❌ | ❌ |
| KV Patcher | ✅ | ❌ | ❌ |
| RGLP | ✅ | ❌ | ✅ |
| API | ✅ | ❌ | ❌ |
| Wireless | ❌ | ✅ | ❌ |
| UI Editor | ✅ | ❌ | ✅ |

## Documentation

- [Usage](https://exposuremg.github.io/gxBuild/usage/)  - General Usage
- [Patches](https://exposuremg.github.io/gxBuild/patches/) - Patch format
- [Scripting](https://exposuremg.github.io/gxBuild/scripting/) - Python Scripting
- [Developer](https://exposuremg.github.io/gxBuild/developer/) - FFI Interface

## Info

- [CREDITS.md](CREDITS.md) - Project Credits
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution Guidelines
- [CONTACT.md](CONTACT.md) - Contact Information
- [CHANGELOG.md](CHANGELOG.md) - Changelog
- [TODO.md](TODO.md) - TODO List

## Testing

Any testing is greatly appreciated, as I don't have the funds for every platform.

✓ = Tested Working

- = Builds correctly

× = Does not built correctly


| Platform | Retail Single | Retail Split | ArgonData | AudClamp | RJTAG | Glitch1 | Glitch2 | Glitch3 | Glitch2.3 | XDKBuild | RGBuild |
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

Documentation is available on [ExposureMG's GitHub Pages](https://exposuremg.github.io/gxBuild/home/)

### Building

Build gxBuild default (FFI Only)

```bash
cargo build --release
```

Build gxBuild with CLI

```bash
cargo build --release --features cli
```

Build gxBuild with CXX-Qt bindings

```bash
cargo build --release --features gui
```

## License

gxBuild is multi-licensed, distributed under the GPL v2.

Original code by ExposureMG is for the public domain.
x360utils is licensed under the unlicense (Permissive).
xenon-bltool is licensed under the GPL v2.
libmspack is relicensed as GPL v2.
ExCrypt is licensed under the BSD 3-Clause License.
Xenia is licensed under a custom permissive license.

All code taken from other projects has been properly attributed in the header.
