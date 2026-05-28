cargo build --release --no-default-features --features cli

cp ./target/release/gxbuild ~/Projects/GxOSS/gxBuild-support-files/

chmod +x ~/Projects/GxOSS/gxBuild-support-files/gxbuild
