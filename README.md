# quicr

Safe Rust API for [libquicr](https://github.com/quicr/libquicr).

The API preserves libquicr's C++ concepts while using conventional Rust ownership,
errors, and RAII. Managers and handlers own native resources, sessions are checked
handles, and callback-scoped protocol values are exposed as borrows or copied into
owned Rust values as appropriate. Applications use ordinary Rust types and do not
interact with the underlying C API directly.

## Project direction

The current implementation uses libquicr through an internal FFI layer. The
long-term goal is a native Rust implementation behind the same Rust-shaped API.
Applications can use the library today without adopting the FFI layer as part of
their own architecture; keeping that implementation detail behind the public API
is intended to make a future transition practical.

## Examples

Run the interactive publisher or subscriber from the workspace:

```sh
cargo run -p quicr --example simple_publish
cargo run -p quicr --example simple_subscribe
```

The examples prompt for a relay URI, namespace, and track name. Their structure
matches the corresponding libquicr C++ examples: create a session manager, add a
transport, wait for the session, register a track handler, and exchange objects.

## TLS backends

OpenSSL is used by default. To build with mbedTLS:

```sh
cargo build -p quicr --no-default-features --features mbedtls
```

Exactly one TLS backend must be selected.

## Callback and lifetime model

Native callbacks can be concurrent and may run synchronously while libquicr holds
internal locks. Callback implementations must be thread-safe and must follow the
re-entry restrictions documented on each callback trait. Borrowed callback values
must not be retained after the callback returns.

Dropping managers and handlers requests native cleanup. Use a handler's explicit
`close` method when the application needs to observe removal errors. Persistent
native `BUSY` responses still depend on libquicr's final handler-destruction
guarantees.

See the crate API documentation for type-specific contracts and error behavior.
