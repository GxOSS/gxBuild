# GGXBuild

A session-based Rust NAND building and patching tool for Xbox 360.

Supported inputs:
- All image and block types
- xeBuild and RGLoader patches
- xeBuild INI

## Project setup:

Interface commands and adapters are dynamically loaded from the adapters/ and commands/ directories

src/
├── builder/ - NAND parsing and building
├───── images/ - Image types available to build, dynamically loaded
├── crypto/ - ExCrypt and related crypto
├── patcher/ - Patching engine
├── interface/
├───── adapters/ - Supported input methods (CLI, FFI)
├───────── data/ - Shared data type inputs
├───────────── xebuild.rs - xeBuild INI parser
├───────────── luascript.rs - GGXBuild Luascript parser
├───────── cli.rs - Interface session with CLI, optional xeBuild style.
├───────── ffi.rs - Export session over FFI
├───── commands/ - Commands available in session
├───── luavm.rs - `mlua` LuaVM object
├───── session.rs - Session and queue manager, Loads commands and listens on adapters
├───── interface.rs - module entry point
└── main.rs - Entry point

## Libraries

- `builder` - NAND parsing and building - Based on [flash-dump-tool](), [RGBuild](), [extract360.py](), and [xenon-bltool]()
- `crypto` - Directly includes [ExCrypt](). Some logic from [Xbox-360-Crypto]()
- `compression` - Directly includes [LibLZX]() and [libmspack LZXD]()
- `patcher` - Based on [RGBuild](). Referenced from [mitchellwaite]()
- `interface` - Directly includes [mlua](). Original work.