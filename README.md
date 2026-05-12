# gxBuild

>[!CAUTION]
> * gxBuild is in **BETA**!
> * The app is still **UNTESTED** against real consoles!
> * There is a **99.99%** chance you will brick your console!

![gxBuild Colour Transparent Banner](assets/gx_banner_colour_trans.png)

gxBuild is a Xbox 360 image builder and patcher. Features full nand, xell and shadowboot parsing, patching and building. Stays as close to xeBuild as possible, with a few changes. 

Based on [x360utils](), [xenon-bltool](), and [J-Runner with Extras]()

## Features

| Feature | gxBuild | xeBuild | RGBuild |
| ------- | ------- | ------- | ------- |
| Retail | ✅ | ❌ | ❌ |
| Devkit | ✅ | - | ❌ |
| DevGL | ✅ | - | ❌ |
| RGLoader | ✅ | ❌ | ✅ |
| XDKBuild | ✅ | ❌ | ❌ |
| Glitch3 | ✅ | ❌ | ❌ |
| SMC Patcher | ✅ | ❌ | ❌ |
| KV Patcher | ✅ | ❌ | ❌ |
| CE Patcher | ✅ | ❌ | ❌ |
| RGLP | ✅ | ❌ | ✅ |
| API | ✅ | ❌ | ❌ |
| Wireless | - | ✅ | - |
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

## License

Original code by ExposureMG is for the public domain.
x360utils is unlicense (Permissive)
J-Runner is MIT (Permissive)
xenon-bltool is GPL v2

All code taken from other projects has been properly attributed in the header.
