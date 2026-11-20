// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{
    ffi::CString,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

/// QUIC congestion-control algorithm used by the transport.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CongestionControl {
    /// Bottleneck Bandwidth and Round-trip propagation time (BBR).
    #[default]
    Bbr,
    /// C4 congestion control.
    C4,
    /// CUBIC congestion control.
    Cubic,
    /// New Reno congestion control.
    NewReno,
}

/// Transport-level settings shared by clients and servers.
///
/// [`Default`] matches the native library defaults. Paths and strings are
/// borrowed only while creating the native transport; this crate keeps their
/// backing storage alive for that operation.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TransportConfig {
    /// TLS certificate path, or `None` to pass an empty path.
    pub tls_cert_path: Option<PathBuf>,
    /// TLS private-key path, or `None` to pass an empty path.
    pub tls_key_path: Option<PathBuf>,
    /// PEM CA bundle used to verify servers.
    ///
    /// `None` disables server verification in the native transport.
    pub tls_root_trust_path: Option<PathBuf>,
    /// Initial number of entries reserved by the time queue. Defaults to `1000`.
    pub time_queue_init_queue_size: u32,
    /// Maximum time-queue duration. Defaults to 2 seconds.
    ///
    /// Sub-millisecond precision is truncated during native conversion.
    pub time_queue_max_duration: Duration,
    /// Width of each time-queue bucket. Defaults to 500 milliseconds.
    ///
    /// Sub-millisecond precision is truncated during native conversion.
    pub time_queue_bucket_interval: Duration,
    /// Receive time-queue capacity. Defaults to `1000`.
    pub time_queue_rx_size: u32,
    /// Enables native transport debug behavior. Disabled by default.
    pub debug: bool,
    /// Minimum QUIC congestion window, in bytes. Defaults to 131,072 bytes.
    pub quic_cwin_minimum: u64,
    /// Wi-Fi shadow round-trip time. Defaults to 20 milliseconds.
    ///
    /// Sub-microsecond precision is truncated during native conversion.
    pub quic_wifi_shadow_rtt: Duration,
    /// Connection idle timeout. Defaults to 30 seconds.
    ///
    /// Sub-millisecond precision is truncated during native conversion.
    pub idle_timeout: Duration,
    /// Congestion-control algorithm. Defaults to [`CongestionControl::Bbr`].
    pub congestion_control: CongestionControl,
    /// QLOG output path, or `None` to disable QLOG output.
    pub quic_qlog_path: Option<PathBuf>,
    /// Native pacing/congestion-control bypass priority limit. Defaults to `0`.
    pub quic_priority_limit: u8,
    /// Maximum number of active connections. Defaults to `2`.
    pub max_connections: usize,
    /// Enables TLS key logging. Disabled by default.
    pub ssl_keylog: bool,
    /// Requested socket buffer size, in bytes. Defaults to 1,000,000 bytes.
    pub socket_buffer_size: usize,
    /// Maximum queued callback count. Defaults to `2000`.
    pub callback_queue_size: u32,
    /// Interval between metrics samples. Defaults to 5 seconds.
    ///
    /// Sub-millisecond precision is truncated during native conversion.
    pub metrics_sample_interval: Duration,
    /// Initial per-stream receive window, in bytes.
    ///
    /// The default `0` requests the QUIC implementation's default.
    pub initial_max_stream_data: u64,
    /// Initial stream limit. Defaults to `512`.
    pub initial_max_stream_id: u64,
    /// Number of server QUIC instances (shards). Defaults to `1`.
    pub quic_shards: usize,
    /// Enables AF_XDP when supported. Enabled by default.
    pub use_af_xdp: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            tls_cert_path: None,
            tls_key_path: None,
            tls_root_trust_path: None,
            time_queue_init_queue_size: 1000,
            time_queue_max_duration: Duration::from_millis(2000),
            time_queue_bucket_interval: Duration::from_millis(500),
            time_queue_rx_size: 1000,
            debug: false,
            quic_cwin_minimum: 131_072,
            quic_wifi_shadow_rtt: Duration::from_micros(20_000),
            idle_timeout: Duration::from_millis(30_000),
            congestion_control: CongestionControl::Bbr,
            quic_qlog_path: None,
            quic_priority_limit: 0,
            max_connections: 2,
            ssl_keylog: false,
            socket_buffer_size: 1_000_000,
            callback_queue_size: 2000,
            metrics_sample_interval: Duration::from_millis(5000),
            initial_max_stream_data: 0,
            initial_max_stream_id: 512,
            quic_shards: 1,
            use_af_xdp: true,
        }
    }
}

/// Configuration for a client session.
///
/// [`Default`] leaves required identity and connection values empty; callers
/// normally set [`endpoint_id`](Self::endpoint_id) and
/// [`connect_uri`](Self::connect_uri) before creating a session.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ClientConfig {
    /// UTF-8 endpoint identifier sent during setup.
    ///
    /// Interior NUL bytes are rejected when the session is created.
    pub endpoint_id: String,
    /// Shared transport settings.
    pub transport_config: TransportConfig,
    /// Lifetime of an unclassified incoming stream. Defaults to 3 seconds.
    ///
    /// Sub-millisecond precision is truncated during native conversion.
    pub unknown_stream_expiry: Duration,
    /// UTF-8 URI of the server to connect to.
    ///
    /// Interior NUL bytes are rejected when the session is created.
    pub connect_uri: String,
    /// Delay between native service ticks. Defaults to 333 microseconds.
    ///
    /// Sub-microsecond precision is truncated during native conversion.
    pub tick_service_sleep_delay: Duration,
}

/// Configuration for a server session.
///
/// The default binds an unspecified IPv4 address and port `0`, allowing the
/// operating system to select an available port.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ServerConfig {
    /// UTF-8 endpoint identifier sent during setup.
    ///
    /// Interior NUL bytes are rejected when the session is created.
    pub endpoint_id: String,
    /// Shared transport settings.
    pub transport_config: TransportConfig,
    /// Lifetime of an unclassified incoming stream. Defaults to 3 seconds.
    ///
    /// Sub-millisecond precision is truncated during native conversion.
    pub unknown_stream_expiry: Duration,
    /// Local IP address and UDP port on which to listen.
    pub bind_address: SocketAddr,
    /// Delay between native service ticks. Defaults to 333 microseconds.
    ///
    /// Sub-microsecond precision is truncated during native conversion.
    pub tick_service_sleep_delay: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            endpoint_id: String::new(),
            transport_config: TransportConfig::default(),
            unknown_stream_expiry: Duration::from_millis(3000),
            bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            tick_service_sleep_delay: Duration::from_micros(333),
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            endpoint_id: String::new(),
            transport_config: TransportConfig::default(),
            unknown_stream_expiry: Duration::from_millis(3000),
            connect_uri: String::new(),
            tick_service_sleep_delay: Duration::from_micros(333),
        }
    }
}

/// Reason a Rust configuration value could not be represented natively.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfigErrorKind {
    /// A string or path contains an interior NUL byte.
    InteriorNull,
    /// A path is not valid UTF-8 on a platform whose native API requires it.
    ///
    /// Unix paths are passed as raw bytes and do not produce this error.
    NonUtf8Path,
    /// A duration does not fit in the native integer field.
    OutOfRange,
}

/// Identifies an invalid configuration field and the validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigError {
    field: &'static str,
    kind: ConfigErrorKind,
}

impl ConfigError {
    /// Returns the dotted name of the invalid field.
    pub fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the kind of validation failure.
    pub fn kind(&self) -> ConfigErrorKind {
        self.kind
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self.kind {
            ConfigErrorKind::InteriorNull => "contains a null byte",
            ConfigErrorKind::NonUtf8Path => "is not valid UTF-8",
            ConfigErrorKind::OutOfRange => "is outside the native range",
        };

        write!(formatter, "{} {reason}", self.field)
    }
}

impl std::error::Error for ConfigError {}

pub(crate) struct NativeClientConfig {
    pub raw: quicr_sys::quicr_client_config_t,
    _endpoint_id: CString,
    _connect_uri: CString,
    _transport: NativeTransportConfig,
}

pub(crate) struct NativeServerConfig {
    pub raw: quicr_sys::quicr_server_config_t,
    _endpoint_id: CString,
    _bind_ip: CString,
    _transport: NativeTransportConfig,
}

struct NativeTransportConfig {
    raw: quicr_sys::quicr_transport_config_t,
    _tls_cert_filename: CString,
    _tls_key_filename: CString,
    _tls_root_trust_filename: CString,
    _quic_qlog_path: CString,
}

impl ClientConfig {
    pub(crate) fn to_native(&self) -> Result<NativeClientConfig, ConfigError> {
        let endpoint_id = c_string("endpoint_id", &self.endpoint_id)?;
        let connect_uri = c_string("connect_uri", &self.connect_uri)?;
        let transport = native_transport(&self.transport_config)?;
        let unknown_stream_expiry_ms =
            duration_millis_u32("unknown_stream_expiry", self.unknown_stream_expiry)?;
        let tick_service_sleep_delay_us =
            duration_micros_u64("tick_service_sleep_delay", self.tick_service_sleep_delay)?;

        let raw = quicr_sys::quicr_client_config_t {
            endpoint_id: endpoint_id.as_ptr(),
            transport_config: transport.raw,
            unknown_stream_expiry_ms,
            connect_uri: connect_uri.as_ptr(),
            tick_service_sleep_delay_us,
        };

        Ok(NativeClientConfig {
            raw,
            _endpoint_id: endpoint_id,
            _connect_uri: connect_uri,
            _transport: transport,
        })
    }
}

impl ServerConfig {
    pub(crate) fn to_native(&self) -> Result<NativeServerConfig, ConfigError> {
        let endpoint_id = c_string("endpoint_id", &self.endpoint_id)?;
        let bind_ip = c_string("bind_address", &bind_ip(self.bind_address))?;
        let transport = native_transport(&self.transport_config)?;
        let unknown_stream_expiry_ms =
            duration_millis_u32("unknown_stream_expiry", self.unknown_stream_expiry)?;
        let tick_service_sleep_delay_us =
            duration_micros_u64("tick_service_sleep_delay", self.tick_service_sleep_delay)?;

        let raw = quicr_sys::quicr_server_config_t {
            endpoint_id: endpoint_id.as_ptr(),
            transport_config: transport.raw,
            unknown_stream_expiry_ms,
            bind_ip: bind_ip.as_ptr(),
            port: self.bind_address.port(),
            tick_service_sleep_delay_us,
        };

        Ok(NativeServerConfig {
            raw,
            _endpoint_id: endpoint_id,
            _bind_ip: bind_ip,
            _transport: transport,
        })
    }
}

fn bind_ip(address: SocketAddr) -> String {
    match address {
        SocketAddr::V4(address) => address.ip().to_string(),
        SocketAddr::V6(address) if address.scope_id() != 0 => {
            format!("{}%{}", address.ip(), address.scope_id())
        }
        SocketAddr::V6(address) => address.ip().to_string(),
    }
}

fn native_transport(config: &TransportConfig) -> Result<NativeTransportConfig, ConfigError> {
    let tls_cert_filename = path_c_string(
        "transport_config.tls_cert_path",
        config.tls_cert_path.as_deref(),
    )?;
    let tls_key_filename = path_c_string(
        "transport_config.tls_key_path",
        config.tls_key_path.as_deref(),
    )?;
    let tls_root_trust_filename = path_c_string(
        "transport_config.tls_root_trust_path",
        config.tls_root_trust_path.as_deref(),
    )?;
    let quic_qlog_path = path_c_string(
        "transport_config.quic_qlog_path",
        config.quic_qlog_path.as_deref(),
    )?;
    let time_queue_max_duration = duration_millis_u32(
        "transport_config.time_queue_max_duration",
        config.time_queue_max_duration,
    )?;
    let time_queue_bucket_interval = duration_millis_u32(
        "transport_config.time_queue_bucket_interval",
        config.time_queue_bucket_interval,
    )?;
    let quic_wifi_shadow_rtt_us = duration_micros_u32(
        "transport_config.quic_wifi_shadow_rtt",
        config.quic_wifi_shadow_rtt,
    )?;
    let idle_timeout_ms =
        duration_millis_u64("transport_config.idle_timeout", config.idle_timeout)?;
    let metrics_sample_ms = duration_millis_u64(
        "transport_config.metrics_sample_interval",
        config.metrics_sample_interval,
    )?;

    let raw = quicr_sys::quicr_transport_config_t {
        tls_cert_filename: tls_cert_filename.as_ptr(),
        tls_key_filename: tls_key_filename.as_ptr(),
        tls_root_trust_filename: tls_root_trust_filename.as_ptr(),
        time_queue_init_queue_size: config.time_queue_init_queue_size,
        time_queue_max_duration,
        time_queue_bucket_interval,
        time_queue_rx_size: config.time_queue_rx_size,
        debug: config.debug,
        quic_cwin_minimum: config.quic_cwin_minimum,
        quic_wifi_shadow_rtt_us,
        idle_timeout_ms,
        congestion_control: congestion_control_to_native(config.congestion_control),
        quic_qlog_path: quic_qlog_path.as_ptr(),
        quic_priority_limit: config.quic_priority_limit,
        max_connections: config.max_connections,
        ssl_keylog: config.ssl_keylog,
        socket_buffer_size: config.socket_buffer_size,
        callback_queue_size: config.callback_queue_size,
        metrics_sample_ms,
        initial_max_stream_data: config.initial_max_stream_data,
        initial_max_stream_id: config.initial_max_stream_id,
        quic_shards: config.quic_shards,
        use_af_xdp: config.use_af_xdp,
    };

    Ok(NativeTransportConfig {
        raw,
        _tls_cert_filename: tls_cert_filename,
        _tls_key_filename: tls_key_filename,
        _tls_root_trust_filename: tls_root_trust_filename,
        _quic_qlog_path: quic_qlog_path,
    })
}

fn c_string(field: &'static str, value: &str) -> Result<CString, ConfigError> {
    CString::new(value).map_err(|_| ConfigError {
        field,
        kind: ConfigErrorKind::InteriorNull,
    })
}

fn path_c_string(
    field: &'static str,
    value: Option<&std::path::Path>,
) -> Result<CString, ConfigError> {
    let Some(value) = value else {
        return c_string(field, "");
    };

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        CString::new(value.as_os_str().as_bytes()).map_err(|_| ConfigError {
            field,
            kind: ConfigErrorKind::InteriorNull,
        })
    }

    #[cfg(not(unix))]
    {
        let value = value.to_str().ok_or(ConfigError {
            field,
            kind: ConfigErrorKind::NonUtf8Path,
        })?;

        c_string(field, value)
    }
}

fn duration_millis_u32(field: &'static str, value: Duration) -> Result<u32, ConfigError> {
    value.as_millis().try_into().map_err(|_| ConfigError {
        field,
        kind: ConfigErrorKind::OutOfRange,
    })
}

fn duration_millis_u64(field: &'static str, value: Duration) -> Result<u64, ConfigError> {
    value.as_millis().try_into().map_err(|_| ConfigError {
        field,
        kind: ConfigErrorKind::OutOfRange,
    })
}

fn duration_micros_u32(field: &'static str, value: Duration) -> Result<u32, ConfigError> {
    value.as_micros().try_into().map_err(|_| ConfigError {
        field,
        kind: ConfigErrorKind::OutOfRange,
    })
}

fn duration_micros_u64(field: &'static str, value: Duration) -> Result<u64, ConfigError> {
    value.as_micros().try_into().map_err(|_| ConfigError {
        field,
        kind: ConfigErrorKind::OutOfRange,
    })
}

fn congestion_control_to_native(value: CongestionControl) -> quicr_sys::quicr_congestion_control_t {
    match value {
        CongestionControl::Bbr => quicr_sys::QUICR_CONGESTION_CONTROL_BBR as _,
        CongestionControl::C4 => quicr_sys::QUICR_CONGESTION_CONTROL_C4 as _,
        CongestionControl::Cubic => quicr_sys::QUICR_CONGESTION_CONTROL_CUBIC as _,
        CongestionControl::NewReno => quicr_sys::QUICR_CONGESTION_CONTROL_NEW_RENO as _,
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::CStr, net::SocketAddr, path::PathBuf, time::Duration};

    use super::{ClientConfig, ConfigErrorKind, ServerConfig, TransportConfig};

    #[test]
    fn rejects_null_bytes_in_strings() {
        let config = ClientConfig {
            connect_uri: "moqt://relay\0.example".into(),
            ..ClientConfig::default()
        };

        assert_eq!(config.to_native().err().unwrap().field(), "connect_uri");
    }

    #[test]
    fn rejects_durations_outside_native_range() {
        let config = ClientConfig {
            unknown_stream_expiry: Duration::MAX,
            ..ClientConfig::default()
        };

        let error = config.to_native().err().unwrap();
        assert_eq!(error.field(), "unknown_stream_expiry");
        assert_eq!(error.kind(), ConfigErrorKind::OutOfRange);
    }

    #[test]
    fn client_config_preserves_native_fields_and_backing_storage() {
        let config = ClientConfig {
            endpoint_id: "client-id".into(),
            connect_uri: "moq://127.0.0.1:4443/relay".into(),
            unknown_stream_expiry: Duration::from_millis(123),
            tick_service_sleep_delay: Duration::from_micros(456),
            transport_config: TransportConfig {
                tls_root_trust_path: Some(PathBuf::from("roots.pem")),
                time_queue_max_duration: Duration::from_millis(789),
                ..TransportConfig::default()
            },
        };

        let native = config.to_native().unwrap();

        assert_eq!(
            unsafe { CStr::from_ptr(native.raw.endpoint_id) }.to_bytes(),
            b"client-id"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(native.raw.connect_uri) }.to_bytes(),
            b"moq://127.0.0.1:4443/relay"
        );
        assert_eq!(native.raw.unknown_stream_expiry_ms, 123);
        assert_eq!(native.raw.tick_service_sleep_delay_us, 456);
        assert_eq!(native.raw.transport_config.time_queue_max_duration, 789);
        assert_eq!(
            unsafe { CStr::from_ptr(native.raw.transport_config.tls_root_trust_filename) }
                .to_bytes(),
            b"roots.pem"
        );
    }

    #[test]
    fn server_config_preserves_bind_address() {
        let config = ServerConfig {
            bind_address: "127.0.0.1:4443".parse::<SocketAddr>().unwrap(),
            ..ServerConfig::default()
        };

        let native = config.to_native().unwrap();

        assert_eq!(
            unsafe { CStr::from_ptr(native.raw.bind_ip) }.to_bytes(),
            b"127.0.0.1"
        );
        assert_eq!(native.raw.port, 4443);
    }

    #[test]
    fn server_config_preserves_ipv6_scope_id() {
        let config = ServerConfig {
            bind_address: "[fe80::1%7]:4443".parse::<SocketAddr>().unwrap(),
            ..ServerConfig::default()
        };

        let native = config.to_native().unwrap();

        assert_eq!(
            unsafe { CStr::from_ptr(native.raw.bind_ip) }.to_bytes(),
            b"fe80::1%7"
        );
        assert_eq!(native.raw.port, 4443);
    }

    #[cfg(unix)]
    #[test]
    fn transport_config_preserves_non_utf8_paths() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let path = PathBuf::from(OsString::from_vec(b"cert-\xff.pem".to_vec()));
        let config = ClientConfig {
            transport_config: TransportConfig {
                tls_cert_path: Some(path),
                ..TransportConfig::default()
            },
            ..ClientConfig::default()
        };

        let native = config.to_native().unwrap();

        assert_eq!(
            unsafe { CStr::from_ptr(native.raw.transport_config.tls_cert_filename) }.to_bytes(),
            b"cert-\xff.pem"
        );
    }
}
