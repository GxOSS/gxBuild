fn main() {
    let excrypt_path = "src/deps/excrypt";
    let mspack_path = "src/deps/mspack";

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
        format!("{}/excrypt_bn_key.c", excrypt_path),
        format!("{}/excrypt_bn_mod.c", excrypt_path),
        format!("{}/excrypt_mem.c", excrypt_path),
        
        format!("{}/lzxd.c", mspack_path),
        format!("{}/system.c", mspack_path),
    ]);
    
    build_c.include(excrypt_path);
    build_c.include(&mspack_path);
    build_c.warnings(false); // Suppress warnings from 3rdparty code

    // C++ Source files
    let mut build_cpp = cc::Build::new();
    build_cpp.cpp(true);
    build_cpp.files([
        format!("{}/excrypt_bn_rsa.cpp", excrypt_path),
        format!("{}/excrypt_bn_pkcs1.cpp", excrypt_path),
        format!("{}/exkeys.cpp", excrypt_path),
    ]);
    
    build_cpp.include(excrypt_path);
    build_cpp.include(&mspack_path);
    build_cpp.warnings(false);

    // Link Windows Cryptography Next Generation (CNG) for RSA support
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        println!("cargo:rustc-link-lib=bcrypt");
    }

    // println!("cargo:rerun-if-changed=src/lib/xenon-bltool");
}
