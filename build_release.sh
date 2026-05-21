#!/bin/bash

cargo build --release --no-default-features --features cli

git clone https://github.com/ExposureMG/gxBuild-Support-Files.git release

cp target/release/gxbuild release/