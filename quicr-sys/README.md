# quicr-sys

Low-level native build and generated FFI bindings for
[libquicr](https://github.com/quicr/libquicr).

Most applications should depend on the safe `quicr` crate instead.

The generated items expose the C ABI directly and do not encode pointer
ownership, callback lifetimes, aliasing, or thread-safety requirements in their
types.

OpenSSL is used by default. The low-level crate can instead be built with:

```sh
cargo build -p quicr-sys --no-default-features --features mbedtls
```
