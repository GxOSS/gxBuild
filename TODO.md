# GGXBuild TODO

builder.rs
- Rewrite nand parse function

Rewrite nand build function
- ~~Assemble-Logical = Assemble Full NAND image~~
- Assemble-Shadow = Assemble Shadowboot image
- Assemble-Xell = Assemble XeLL image
- ~~Build = Build final image from assembled~~

commands.rs
- Session Commands

1. Parse NAND
2. Extract
3. Extract-All
4. Extract-Required
5. Encrypt / Decrypt
6. Decompress
7. Compress
8. Load / Apply INI
9. Load FlashFS Folder
10. Apply-XePatch
11. Apply-RGLP
12. Build NAND
13. Build XeLL Image


Next Release:

General:
- Python Scripting
- Upgraded Build System
- LZX Recompression
- Error Handler / Saftey net

Parsing:
- STFS PIRS
- Xboxupd.bin
- Shadowboot
- XDK Recovery

Patching:
- Keyvault
- SMC
- RGLP

New Projects:
- GGX-Devkit: PPC dissasembler and patch builder
- Gay-Runner with Sextras: Python Qt6 example GUI for GGX

- GGX-Loader: ExposureMG's custom patchset

- Glitch3s: Glitch2, 17559 base kernel