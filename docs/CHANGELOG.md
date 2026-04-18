# gxBuild Changelog

Changes from xeBuild 1.21

## Version 1.22

- Python Scripting and Shell (gxPy)
- TUI Image Builder / Editor
- Developer FFI API
- Image Editing Support

- "olddvd" option removed
- "-noenter" arg removed, replaced with "noenter" option
- "-v" verbose arg removed, replaced with "verbose" option
- "-v" now prints gxBuild version
- "unsafe" option added: Disable CRC32 mismatch failure
- "nolog" option added: Disable file logging
- "noinfo" option added: Disable console logging

- Extended Image Support
    - XeLL Image Support (_xell1.ini, _xell2.ini, _xell3.ini, _xelljtag.ini)
    - Shadowboot Image Support (_shadow.ini)
    - Glitch3 Image Support (_glitch3.ini and patches_g3*.bin)
    - XDKBuild Image Support (_xdkbuild.ini and patches_xdk*.bin)
    - RGBuild Image Support (_rgbuild.ini and patches_rg*.bin)

- GXP Patch Format (.GXP)
    - Full xeBuild support remains
    - 4-Section RGH Patches (CB, CD, KHV, SMC)
    - 5-Section JTAG Patches (1BL, CB, CD, KHV, SMC)
    - 1-Section Standalone Patches (Single Bootloader)
    - 1-Section Addon Patches (Insert at offset)
