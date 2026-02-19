# quicr-rs

Safe Rust FFI bindings for [libquicr](https://github.com/Quicr/libquicr), a publish/subscribe transport library based on the IETF MoQ (Media over QUIC) specification. Built on picoquic (QUIC) and picotls (TLS), with an Embassy async runtime that works on both desktop and embedded (ESP32) platforms.

## Architecture

```
┌─────────────────────────────────────────────┐
│                Application                  │
├─────────────────────────────────────────────┤
│     Publisher      │      Subscriber        │
├─────────────────────────────────────────────┤
│               Client API                    │
├─────────────────────────────────────────────┤
│            libquicr (C++ FFI)               │
├─────────────────────────────────────────────┤
│         picoquic     │    picotls           │
├─────────────────────────────────────────────┤
│              mbedtls / openssl              │
└─────────────────────────────────────────────┘
```

## Feature flags

| Feature     | Default | Description                                    |
|-------------|---------|------------------------------------------------|
| `std`       | yes     | Standard library support (Embassy std backend) |
| `mbedtls`   | yes     | Use MbedTLS for TLS/crypto                     |
| `openssl`   | no      | Use OpenSSL for TLS/crypto                     |
| `boringssl` | no      | Use BoringSSL for TLS/crypto                   |
| `esp-idf`   | no      | ESP-IDF component build (see below)            |
| `defmt`     | no      | Use `defmt` instead of `log` (for embedded)    |

## Building – Desktop (macOS / Linux)

### Prerequisites

- Rust 1.75+
- C++20 compiler (clang or gcc)
- cmake 3.16+
- git (for submodules)

### Steps

```bash
# Clone with submodules (libquicr, picoquic, picotls, mbedtls, etc.)
git clone --recursive <repo-url>
cd quicr-rs

# Or if already cloned:
git submodule update --init --recursive

# Build with default features (std + mbedtls)
cargo build

# Run an example (needs a relay – see examples/README.md)
cargo run --example pubsub -- --mode publish
```

## Building – ESP-IDF (ESP32)

On ESP targets, the C++ stack is **not** built by `build.rs`. Instead it is built as an ESP-IDF component by `esp-idf-sys`, and the Rust build script only runs `bindgen` to generate FFI bindings.

```
┌──────────────────────────────────────────────────────┐
│  Your ESP-IDF Rust Project                           │
│    Cargo.toml: quicr = { features = ["esp-idf"] }    │
└──────────────────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────┐
│  esp-idf-sys builds all components including:        │
│    - freertos, lwip, mbedtls, pthread (from IDF)     │
│    - libquicr (via esp-component/CMakeLists.txt)     │
│    - quicr_ffi (the C wrapper)                       │
└──────────────────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────┐
│  quicr crate build.rs (esp-idf path)                 │
│    - Runs bindgen only (no cmake, no cc)             │
│    - Targets 32-bit ARM for correct struct layout    │
│    - No link directives (esp-idf-sys handles it)     │
└──────────────────────────────────────────────────────┘
```

### What the ESP component does

- Builds libquicr, picoquic, picotls, and spdlog using ESP-IDF's toolchain and
  mbedtls.
- Provides POSIX compatibility stubs (`compat_stubs.c`) for headers that
  picoquic expects but ESP-IDF doesn't ship (e.g. `netinet/udp.h`,
  `sys/prctl.h`).
- Enables C++ exceptions and RTTI (required by libquicr) which ESP-IDF disables
  by default.
- Links everything into the IDF component library so `esp-idf-sys` can find the
  symbols.

## Quick start

```rust
use quicr::{ClientBuilder, FullTrackName, ObjectHeaders};

// Create and connect
let client = ClientBuilder::new()
    .endpoint_id("my-client")
    .connect_uri("moqt://relay.example.com:4433")
    .build()?;

client.connect().await?;

// Publish
let track = FullTrackName::from_strings(&["audio", "room1"], "mic");
let publisher = client.publish(track).await?;
let headers = ObjectHeaders::new(0, 0);
publisher.publish(&headers, &audio_data)?;

// Subscribe
let track = FullTrackName::from_strings(&["audio", "room1"], "mic");
let mut subscriber = client.subscribe(track).await?;
loop {
    let obj = subscriber.recv().await;
    if subscriber.is_done() { break; }
}
```

See `examples/README.md` for runnable demos (pubsub, chat, relay).
