# gxBuild

A Rust Xbox 360 NAND image builder and patcher.

Uses the fbBuild/ggBuild/xeBuild CLI and INI style.

## Download

Available for Windows, Mac and Linux.

Download from [GitHub Releases](https://github.com/GGX-Project/ggx/releases).

## PyGG

PyGG is an optional `rust-python` scripting engine for gxBuild. All gxBuild functions and cli inputs are exposed to a script or a shell, allowing custom workflows and automation.

Download from [GitHub Releases](https://github.com/GGX-Project/ggx/releases).

## Documentation

Documentation is hosted on [GitHub Pages](https://exposuremg.github.io/ggx/home/).

## Credits

I referenced ALLOT of projects in the building of this. 

These are the projects i directly took code from:

- [xenon-bltool]() by [InxoviPlayGames]()
- [RGBuild]() by [emoose](), [tydye81]() and [sk1080]()
- [J-Runner with Extras]() by J-Runner Contributors
- [RGH3]() by [15432]()
- [Xbox 360 Crypto]() by [GoobyCorp]()

And these are the projects i referenced:

- [Xbox 360 Research]() by [ExposureMG]()
- [Xbox 360 Research]() by [Byrom90]()
- [Xbox 360 Research]() by [InxoviPlayGames]()
- [xeBuild Patch Sources]() by [mitchellwaite]()
- [XDKBuild]() by [xvistaman2005]()
- [360hub Discord Server]()

And these are the people who deserve credit either way:

- c0z for his work on xeBuild patches
- Ikari for his work on FreeBoot
- team xeBuild / fbBuild / ggBuild

## Developer Info

Heavily uses zerocopy for byteorder.
Slimmed versions of ExCrypt, Mspack and Xenon-bltool are included locally and compiled with cc.

## License

All code wrote by ExposureMG is for the public domain.

All code taken from other projects has been properly attributed in the header.