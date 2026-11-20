// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{
    env,
    path::{Path, PathBuf},
};

fn main() {
    let mbedtls_enabled = env::var_os("CARGO_FEATURE_MBEDTLS").is_some();

    let mut config = cmake::Config::new("libquicr");
    config
        .define("QUICR_INSTALL", "ON")
        .define("QUICR_BUILD_SHARED", "OFF")
        .define("QUICR_BUILD_TESTS", "OFF")
        .define("QUICR_BUILD_BENCHMARKS", "OFF")
        .define("QUICR_BUILD_EXAMPLES", "OFF")
        .define("QUICR_BUILD_TOOLS", "OFF");

    if mbedtls_enabled {
        config.define("WITH_MBEDTLS", "ON");
    } else {
        config.define("WITH_MBEDTLS", "OFF");
    }

    let dst = config.build();

    let lib_dir = dst.join("lib");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=quicr_c");
    println!("cargo:rustc-link-lib=static=quicr");
    println!("cargo:rustc-link-lib=static=picohttp-core");
    println!("cargo:rustc-link-lib=static=picoquic-log");
    println!("cargo:rustc-link-lib=static=picoquic-core");
    let tls_library = if mbedtls_enabled {
        "picotls-mbedtls"
    } else {
        "picotls-openssl"
    };
    if !link_static_if_present(&lib_dir, tls_library) {
        panic!("selected TLS backend `{tls_library}` was not built");
    }
    link_static_if_present(&lib_dir, "picotls-minicrypto");
    println!("cargo:rustc-link-lib=static=picotls-core");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-Ilibquicr/include")
        .clang_arg(format!("-I{}/include", dst.display()))
        .allowlist_function("quicr_.*")
        .allowlist_type("quicr_.*")
        .allowlist_var("QUICR_.*")
        .generate()
        .expect("failed to generate libquicr bindings");

    bindings
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs"))
        .unwrap();

    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=libquicr/include/quicr/quicr.h");
    println!("cargo:rerun-if-changed=libquicr");
}

fn link_static_if_present(lib_dir: &Path, name: &str) -> bool {
    let unix_archive = lib_dir.join(format!("lib{name}.a"));
    let msvc_archive = lib_dir.join(format!("{name}.lib"));
    let present = unix_archive.exists() || msvc_archive.exists();

    if present {
        println!("cargo:rustc-link-lib=static={name}");
    }

    present
}
