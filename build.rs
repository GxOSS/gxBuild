fn main() {
    let excrypt_path = "src/builder/deps/excrypt/src";
    let mspack_path = "src/builder/deps/mspack";
    let xenia_path = "src/builder/deps/xenia";
    let bltool_path = "src/builder/deps/xenon_bltool";

    // C Source files
    let mut build_c = cc::Build::new();
    build_c.files([
        format!("{}/excrypt_aes.c", excrypt_path),
        format!("{}/excrypt_bn.c", excrypt_path),
        format!("{}/excrypt_bn_sig.c", excrypt_path),
        format!("{}/excrypt_des.c", excrypt_path),
        format!("{}/excrypt_ecc.c", excrypt_path),
        format!("{}/excrypt_md5.c", excrypt_path),
        format!("{}/excrypt_parve.c", excrypt_path),
        format!("{}/excrypt_rc4.c", excrypt_path),
        format!("{}/excrypt_rotsum.c", excrypt_path),
        format!("{}/excrypt_sha.c", excrypt_path),
        format!("{}/excrypt_sha2.c", excrypt_path),
        format!("{}/rijndael.c", excrypt_path),
        
        format!("{}/lzxd.c", mspack_path),
        format!("{}/system.c", mspack_path),

        format!("{}/lzx-delta.c", xenia_path),
        format!("{}/utility.c", bltool_path),
    ]);
    
    build_c.include(excrypt_path);
    build_c.include(mspack_path);
    build_c.include(xenia_path);
    build_c.include(bltool_path);
    build_c.flag("-maes");
    build_c.warnings(false);
    build_c.compile("gx_crypto_c");

    // C++ Source files
    let mut build_cpp = cc::Build::new();
    build_cpp.cpp(true);
    build_cpp.files([
        format!("{}/excrypt_bn_rsa.cpp", excrypt_path),
        format!("{}/excrypt_bn_pkcs1.cpp", excrypt_path),
        format!("{}/exkeys.cpp", excrypt_path),
        format!("{}/excrypt_bn_key.cpp", excrypt_path),
        format!("{}/excrypt_bn_mod.cpp", excrypt_path),
        format!("{}/excrypt_mem.cpp", excrypt_path),
    ]);
    
    build_cpp.include(excrypt_path);
    build_cpp.include(mspack_path);
    build_cpp.include(xenia_path);
    build_cpp.include(bltool_path);
    build_cpp.flag("-maes");
    build_cpp.warnings(false);
    build_cpp.compile("gx_crypto_cpp");

    // Link Windows Cryptography Next Generation (CNG) for RSA support
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        println!("cargo:rustc-link-lib=bcrypt");
    }

    println!("cargo:rerun-if-changed=src/builder/deps");
}
