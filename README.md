# gxBuild

gxBuild is a Xbox 360 image builder and patcher. Implements full nand, xell and shadowboot parsing and building, with a number of complex targets like JTAG-2f and DevGL.

Aims for near-complete compatibility with xeBuild where possible, with only a few minor changes to syntax. Includes full xeBuild and RGBuild patching, the xeBuild folder structure and inis, crc32 hashing, and expands on xeBuild with Glitch3, native RGBuild, shadowboots, xell images, and CE patching.

## Get Started

Compatible with any x86 and aarch64 platform.

Officially supported:
- [Windows x32]()
- [Windows x64]()
- [Linux AMD64]()
- [MacOS aarch64]()

## Documentation

Documentation is hosted on the [GGX Project](https://ggx-project.github.io/gxBuild/home/) site:
- [Usage](https://ggx-project.github.io/gxBuild/usage/)  - General Usage
- [Patches](https://ggx-project.github.io/gxBuild/patches/) - Patch format
- [Scripting](https://ggx-project.github.io/gxBuild/scripting/) - Python Scripting
- [Developer](https://ggx-project.github.io/gxBuild/developer/) - FFI Interface

## Credits

I referenced ALLOT of projects in the building of this. 

These are the projects i directly took code from:
 [xenon-bltool](https://github.com/InvoxiPlayGames/xenon-bltool) by [InxoviPlayGames](https://github.com/InvoxiPlayGames)
- [x360utils](https://github.com/Swizzy/x360Utils) by [Swizzy](https://github.com/Swizzy)
- [RGBuild](https://github.com/RGLoader/RGBuild) by [emoose](https://github.com/stoker25) / [stoker25](https://github.com/stoker25), [tydye81](https://github.com/tydye81) and [sk1080](https://github.com/sk1080)
- [J-Runner with Extras](https://github.com/J-Runner-with-Extras/J-Runner-with-Extras) by J-Runner Contributors
- [RGH3](https://github.com/15432/RGH3) by [15432](https://github.com/15432)
- [Xbox 360 Crypto](https://github.com/GoobyCorp/Xbox-360-Crypto) by [GoobyCorp](https://github.com/GoobyCorp)

And these are the projects i referenced:

- [Xbox 360 Research](https://ggx-project.github.io/expo-research/home/) by [ExposureMG](https://github.com/ExposureMG)
- [Xbox 360 Research](https://github.com/Byrom90/Xbox_360_Research) by [Byrom90](https://github.com/Byrom90)
- [Xbox 360 Research](https://github.com/InvoxiPlayGames/x360-Research) by [InxoviPlayGames](https://github.com/InvoxiPlayGames)
- [xeBuild Patch Sources](https://github.com/mitchellwaite/xbox360_xebuild_patches) by [mitchellwaite](https://github.com/mitchellwaite)
- [XDKBuild](https://github.com/xvistaman2005/XDKBuild) by [xvistaman2005](https://github.com/xvistaman2005)
- [360hub Discord Server](https://discord.gg/z9r3HMUxp7)

Last but not least:

- c0z for xeBuild patches
- Ikari for FreeBoot
- team xeBuild / fbBuild / ggBuild

## License

All code wrote by ExposureMG is for the public domain.

All code taken from other projects has been properly attributed in the header.