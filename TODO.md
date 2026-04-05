# GGXBuild TODO

- Rewrite spare data parser -> spare.rs In Progress

- SC bootloader file -> sc.rs In Progress

- SMC file -> smc.rs Implemented

- Error handler -> error.rs In Progress

mod.rs
- Keyvault crypto
- Keyvault parser
- XeLL image file - In Progress

builder.rs
- Rewrite nand parse function
- Rewrite nand build function

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

- SMC Patching and XEPATCH1

- GGX-Devkit: PPC dissasembler and patch builder

- Gay-Runner with Sextras: Python Qt6 example GUI for GGX

- PyGG

- STFS / Xboxupd.bin parsing into CF/CG

- Better build.rs - options to disable CLI, FFI INI, python, etc

- LZX recompression with LibLZX (?)