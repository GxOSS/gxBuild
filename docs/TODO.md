# GGXBuild TODO

## Current Release (1.22)

Xell:
- Assemble xell image skeleton method
- Xell discovery from nand
- Xell discovery and injection from filesearch

Smc:
- SMC discovery from system

FlashFS:
- eMMC
- mobile partitions

Image Building:
- Fix CRC32
- Place KHV patches

## Next Release (1.23)

## gxBuild

- Entire image parser / builder (256MB/512MB/4GB) (FatX whole partition extraction / injection)
- Shadowboot parsing & building
- Rebooter image parsing & building (started)
- CAB LZX Recompression with LibLZX

### gxDevkit

- Parse and build CF and CG to / from kernel and hypervisor
- Apply CF and CG to K/HV
- Patch assembly and dissasembly
- Loaderpatch / RGLP to GXP