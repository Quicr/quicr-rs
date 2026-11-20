// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

//! Raw, generated FFI bindings to libquicr.
//!
//! This crate is an implementation detail of the safe `quicr` crate. Its items
//! mirror the C ABI, expose unmanaged pointers, and do not encode ownership,
//! aliasing, callback, or thread-safety requirements in their Rust types.
//! Applications should use `quicr` instead.
//!
//! The bundled libquicr source is built by CMake. OpenSSL is selected by default;
//! building with `--no-default-features --features mbedtls` selects mbedTLS.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

#[cfg(all(feature = "_openssl", feature = "mbedtls"))]
compile_error!("default features and feature `mbedtls` cannot be enabled together");

#[cfg(not(any(feature = "_openssl", feature = "mbedtls")))]
compile_error!("default features must be enabled unless feature `mbedtls` is selected");

extern crate link_cplusplus;

#[cfg(feature = "_openssl")]
extern crate openssl_sys;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
