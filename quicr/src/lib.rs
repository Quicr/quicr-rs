// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

//! Safe Rust bindings for [libquicr](https://github.com/quicr/libquicr).
//!
//! `quicr` exposes the main libquicr concepts—session managers, sessions, track
//! handlers, protocol values, and callbacks—as native Rust types. Its shape stays
//! close to the C++ API where that helps users compare implementations, while
//! constructors, errors, ownership, and teardown follow Rust conventions.
//!
//! # Getting started
//!
//! A client creates a [`SessionManager`], adds a transport using
//! [`SessionManager::add_transport`], and registers handlers with
//! [`SessionManager::add_handler`]. The `simple_publish` and `simple_subscribe`
//! examples in the repository demonstrate complete client flows.
//!
//! Protocol names are byte-oriented rather than UTF-8-only:
//!
//! ```
//! use quicr::{FullTrackName, TrackNamespace};
//!
//! let namespace = TrackNamespace::new([b"example".as_slice(), b"camera".as_slice()])?;
//! let track = FullTrackName::new(namespace, b"video".as_slice());
//!
//! assert_eq!(track.name(), b"video");
//! # Ok::<(), quicr::TrackNamespaceError>(())
//! ```
//!
//! # Ownership and teardown
//!
//! Managers and handlers own their native counterparts through RAII. A [`Session`]
//! is a lightweight handle whose operations fail with [`SessionExpired`] after its
//! manager has removed the native session. Dropping a manager begins native
//! teardown and waits for Rust calls already using its resources.
//!
//! Handler registration is tied to both the manager and the session. Prefer an
//! explicit handler `close` operation when the application must observe a removal
//! error; dropping remains the non-fallible cleanup path. If native removal keeps
//! returning a busy status, final cleanup depends on libquicr's finalization
//! behavior.
//!
//! # Callbacks
//!
//! Callback implementations must be [`Send`] and [`Sync`]. libquicr may invoke
//! callbacks concurrently or synchronously from an operation that triggered them.
//! Borrowed callback arguments are valid only for that callback invocation; values
//! that need to outlive it must be copied. Panics are caught at the FFI boundary:
//! a panic in a reply-producing callback becomes an internal-error reply, while a
//! panic in a notification callback aborts the process.
//!
//! Some callbacks run while libquicr holds internal locks. Each callback trait
//! documents which operations may safely be called from that callback. In
//! particular, do not destroy the active manager, session, or handler from one of
//! its own callbacks unless the callback documentation explicitly permits it.
//!
//! # Replies
//!
//! Request callbacks return [`Reply<T, E>`], which currently represents an
//! immediate success or rejection. The distinct type leaves room for libquicr's
//! deferred-reply model without forcing a future breaking change to callback
//! signatures.
//!
//! # TLS backends
//!
//! OpenSSL is enabled by default. To use mbedTLS, disable default features and
//! enable the `mbedtls` feature:
//!
//! ```text
//! cargo build -p quicr --no-default-features --features mbedtls
//! ```

#![warn(missing_docs)]

mod attributes;
mod config;
mod error;
mod extensions;
mod filter;
mod handler;
mod metrics;
mod object;
mod reply;
mod session;
mod session_manager;
mod track_name;

pub use attributes::{
    AttributeError, AuthorizationToken, JoiningFetchAttributes, PublishAttributes,
    PublishNamespaceAttributes, StandaloneFetchAttributes, SubscribeAttributes,
    SubscribeNamespaceAttributes, TokenAliasType,
};
pub use config::{
    ClientConfig, ConfigError, ConfigErrorKind, CongestionControl, ServerConfig, TransportConfig,
};
pub use error::{ErrorCode, ProtocolError};
pub use extensions::{ExtensionError, TrackExtensions, TrackExtensionsIter};
pub use filter::{Filter, FilterError, FilterKind, SubscriptionFilter, TrackFilter};
pub use handler::{
    BoundPublishFetch, BoundPublishTrack, CloseError, FetchTrackHandler, FetchTrackOptions,
    ForwardingSubscribeTrackCallbacks, ForwardingSubscribeTrackHandler, HandlerCreateError,
    HandlerOperationError, PublishFetchHandler, PublishFetchOptions, PublishNamespaceCallbacks,
    PublishNamespaceHandler, PublishNamespaceStatus, PublishObjectStatus, PublishTrackCallbacks,
    PublishTrackHandler, PublishTrackOptions, PublishTrackStatus, SubscribeNamespaceCallbacks,
    SubscribeNamespaceHandler, SubscribeNamespaceHandlerRef, SubscribeNamespaceMode,
    SubscribeNamespaceOptions, SubscribeNamespaceStatus, SubscribeTrackCallbacks,
    SubscribeTrackHandler, SubscribeTrackOptions, SubscribeTrackStatus, TrackHandler, TrackStatus,
    TrackStatusHandler, TrackStatusHandlerCallbacks, TrackStatusHandlerStatus,
};
pub use metrics::{
    ConnectionMetrics, MinMaxAvg, PublishTrackMetrics, PublishTrackQuicMetrics,
    QuicConnectionMetrics, SubscribeTrackMetrics,
};
pub use object::{
    Extensions, FetchEndLocation, GroupOrder, Location, ObjectHeaders, ObjectStatus,
    StreamHeaderProperties, SubgroupIdType, TrackMode,
};
pub use reply::{
    FetchError, FetchErrorCode, FetchResponse, InvalidReplyError, PublishError, PublishErrorCode,
    PublishNamespaceError, PublishNamespaceErrorCode, PublishOkAttributes, PublishResponse,
    Redirect, Reply, ReplyCode, ReplyError, RequestError, RequestErrorCode, SessionError,
    SubscribeResponse, TrackStatusResponse,
};
pub use session::{
    ClientSessionCallbacks, ServerSessionCallbacks, Session, SessionExpired, SessionOperationError,
    SessionStatus, SetupAttributes, SetupError, SetupErrorCode, StreamClosedFlag,
};
pub use session_manager::{
    AddTransportError, HandlerRegistrationError, ManagerCreateError, SessionManager,
    SessionManagerBuilder, SessionManagerCallbacks,
};
pub use track_name::{FullTrackName, TrackNamespace, TrackNamespaceError};
