---
description: Test gxBuild release
---

# gxBuild Testing

Follow these instructions to succesfully test gxBuild:

- Run `cargo build --release --no-default-features --features cli` in gxBuild/
- Move gxbuild.exe from gxBuild/target/release/ to gxBuild/standalone
- cd into gxBuild/standalone
- Run gxbuild.exe -t glitch -c jasper -d 9199 -o verbose;unsafe
- Check the log in gxBuild/standalone/logs/