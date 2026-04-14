# gxBuild

A Rust Xbox 360 image builder and patcher.

Backwards compatible with xeBuild

## About

Full start to finish NAND building and patching. Follows and extends the xeBuild format for compatibility. 

Formats:
- XSB Small Block, PSB/KSB Small Block, Big Block and eMMC
- Single CB, Split CB, Glitch3, 1f, 2f (WIP), RGBuild, XDKBuild, Devkit and DevGL
- System Update (STFS PIRS) and Xboxupd.bin
- Shadowboot (WIP) and XeLL image

Features:
- Spare data handling and Bad Block remapping
- Full FlashFS Parser and Builder
- CE LZX Decompression
- Base kernel and hypervisor updater
- xeBuild and RGLoader patching
- SMC and Keyvault patching (WIP)
- xe / gg / fb ini support

## Usage and Scripting

gxBuild has 3 ways it can be interfaced; CLI, TUI, and FFI. The CLI mirrors xeBuild with some minor changes and expansions. the TUI can be accessed with `gxBuild tui`.

For full usage type `gxBuild help`

gxBuild bundles rust-python for scripting, and exports all processed data into the interpreter. 

## Documentation

Documentation is hosted on the [GGX Project]() site:
- [Usage]() - General Usage
- [Patches]() - Patch format
- [Scripting]() - Python Scripting
- [Developer]() - FFI Interface


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

- [Xbox 360 Research](https://exposuremg.github.io/) by [ExposureMG](https://github.com/ExposureMG)
- [Xbox 360 Research](https://github.com/Byrom90/Xbox_360_Research) by [Byrom90](https://github.com/Byrom90)
- [Xbox 360 Research](https://github.com/InvoxiPlayGames/x360-Research) by [InxoviPlayGames](https://github.com/InvoxiPlayGames)
- [xeBuild Patch Sources](https://github.com/mitchellwaite/xbox360_xebuild_patches) by [mitchellwaite](https://github.com/mitchellwaite)
- [XDKBuild](https://github.com/xvistaman2005/XDKBuild) by [xvistaman2005](https://github.com/xvistaman2005)
- [360hub Discord Server](https://discord.gg/z9r3HMUxp7)

And these are the people who deserve credit:

- c0z for xeBuild patches
- Ikari for FreeBoot
- team xeBuild / fbBuild / ggBuild

## License

All code wrote by ExposureMG is for the public domain.

All code taken from other projects has been properly attributed in the header.