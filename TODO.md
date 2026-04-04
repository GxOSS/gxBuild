# GGXBuild TODO

| Feature | Status | Tested |
|-----|-----|-----|
| INI parsing | Complete | No |
| Patching | Complete | No |
| Crypto | Complete | No |
| Decompression | Incomplete | No |
| Recompression | Not Started | No |
| NAND Building | Incomplete | No |
| FlashFS | Incomplete | No |

| Interface | Status | Tested |
|-----|-----|-----|
| Session structured | Complete | No |
| Session commands | Incomplete | No |
| CLI structured | Complete | No |
| PyGG Interpreter | Complete | No |
| PyGG Shell | Complete | No |





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
12. Build



- Better build.rs

Options to disable CLI, FFI interface, xeBuild INI, Python interpreter, etc



- LZX recompression with LibLZX (?)

## Commands:

- Extract
- Extract-All
- Patch
- Replace
- ...