// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{
    collections::HashMap,
    ffi::{CString, c_void},
    fmt,
    panic::{self, AssertUnwindSafe},
    ptr::{self, NonNull},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread::{self, ThreadId},
    time::Duration,
};

use crate::{
    ConnectionMetrics, ErrorCode, FetchError, FetchErrorCode, FetchResponse, FullTrackName,
    InvalidReplyError, JoiningFetchAttributes, PublishAttributes, PublishError, PublishErrorCode,
    PublishNamespaceAttributes, PublishNamespaceError, PublishNamespaceErrorCode, PublishResponse,
    Reply, ReplyCode, ReplyError, RequestError, RequestErrorCode, SessionError,
    StandaloneFetchAttributes, SubscribeAttributes, SubscribeNamespaceAttributes,
    SubscribeNamespaceHandlerRef, SubscribeResponse, SubscribeTrackHandler, TrackExtensions,
    TrackHandler, TrackNamespace, TrackStatusResponse,
    extensions::NativeTrackExtensions,
    handler::{Registration, goaway_registration, registration},
    reply::{NativePublishResponse, NativeReplyErrorBacking},
    track_name::NativeTrackNamespace,
};

/// A cloneable handle to a session owned by a [`crate::SessionManager`].
///
/// Clones refer to the same native session but do not keep the manager alive. Once libquicr
/// removes the session, or manager teardown begins, the handle becomes an inert tombstone:
/// [`Session::is_expired`] returns `true` and operations fail without using the native pointer.
/// Pointer reuse for a later native session creates distinct session state, so an old tombstone
/// never becomes active again.
#[derive(Clone)]
pub struct Session {
    state: Arc<SessionState>,
}

impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}

impl Eq for Session {}

pub(crate) struct SessionState {
    key: usize,
    access: Mutex<SessionAccessState>,
    quiesced: Condvar,
    registrations: Mutex<Vec<Registration>>,
    manager_lifecycle: Arc<SessionLifecycle>,
}

pub(crate) struct SessionRegistry {
    sessions: Mutex<HashMap<usize, Arc<SessionState>>>,
    lifecycle: Arc<SessionLifecycle>,
}

#[derive(Default)]
struct SessionLifecycle {
    state: Mutex<SessionLifecycleState>,
    quiesced: Condvar,
}

#[derive(Default)]
struct SessionLifecycleState {
    closing: bool,
    in_flight: usize,
}

struct SessionPermit<'a> {
    lifecycle: &'a SessionLifecycle,
}

#[derive(Clone, Copy)]
enum SessionPhase {
    Active(usize),
    Closing,
    Expired,
}

struct SessionAccessState {
    phase: SessionPhase,
    in_flight: HashMap<ThreadId, usize>,
}

struct SessionCallPermit<'a> {
    session: &'a SessionState,
    thread: ThreadId,
}

impl SessionState {
    fn new(
        raw: *mut quicr_sys::quicr_session_t,
        lifecycle: Arc<SessionLifecycle>,
        active: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            key: raw as usize,
            access: Mutex::new(SessionAccessState {
                phase: if active {
                    SessionPhase::Active(raw as usize)
                } else {
                    SessionPhase::Expired
                },
                in_flight: HashMap::new(),
            }),
            quiesced: Condvar::new(),
            registrations: Mutex::new(Vec::new()),
            manager_lifecycle: lifecycle,
        })
    }

    fn enter(&self) -> Option<(*mut quicr_sys::quicr_session_t, SessionCallPermit<'_>)> {
        let thread = thread::current().id();
        let mut state = lock(&self.access);
        let SessionPhase::Active(raw) = state.phase else {
            return None;
        };

        *state.in_flight.entry(thread).or_default() += 1;
        Some((
            raw as *mut quicr_sys::quicr_session_t,
            SessionCallPermit {
                session: self,
                thread,
            },
        ))
    }

    fn begin_removal(&self) {
        let thread = thread::current().id();
        let mut state = lock(&self.access);
        if matches!(state.phase, SessionPhase::Active(_)) {
            state.phase = SessionPhase::Closing;
        }

        while state.in_flight.values().sum::<usize>()
            > state.in_flight.get(&thread).copied().unwrap_or_default()
        {
            state = self
                .quiesced
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
    }

    fn finish_removal(&self) {
        let mut state = lock(&self.access);
        state.phase = SessionPhase::Expired;
        self.quiesced.notify_all();
    }

    fn is_active(&self) -> bool {
        matches!(lock(&self.access).phase, SessionPhase::Active(_))
    }

    fn is_expired(&self) -> bool {
        matches!(lock(&self.access).phase, SessionPhase::Expired)
    }

    fn clear(&self) {
        self.finish_removal();
    }

    fn reserve_registration(&self) -> Result<bool, std::collections::TryReserveError> {
        let state = lock(&self.access);
        if !matches!(state.phase, SessionPhase::Active(_)) {
            return Ok(false);
        }

        lock(&self.registrations).try_reserve(1)?;
        Ok(true)
    }

    fn retain_registration(&self, registration: Registration) -> Result<(), Registration> {
        let state = lock(&self.access);
        let current_thread_is_in_flight = state.in_flight.contains_key(&thread::current().id());
        let can_retain = matches!(state.phase, SessionPhase::Active(_))
            || matches!(state.phase, SessionPhase::Closing) && current_thread_is_in_flight;
        if !can_retain {
            return Err(registration);
        }

        lock(&self.registrations).push(registration);
        Ok(())
    }

    fn remove_registration(&self, key: (*const c_void, bool)) {
        let mut registrations = lock(&self.registrations);
        if let Some(index) = registrations
            .iter()
            .position(|registration| registration.key() == key)
        {
            registrations.swap_remove(index);
        }
    }

    fn take_registrations(&self) -> Vec<Registration> {
        std::mem::take(&mut *lock(&self.registrations))
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            lifecycle: Arc::new(SessionLifecycle::default()),
        }
    }
}

impl SessionLifecycle {
    fn enter(&self) -> Option<SessionPermit<'_>> {
        let mut state = lock(&self.state);
        if state.closing {
            return None;
        }

        state.in_flight += 1;
        Some(SessionPermit { lifecycle: self })
    }

    fn begin_shutdown(&self) {
        let mut state = lock(&self.state);
        state.closing = true;

        while state.in_flight != 0 {
            state = self
                .quiesced
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
    }

    fn is_closing(&self) -> bool {
        lock(&self.state).closing
    }
}

impl Drop for SessionPermit<'_> {
    fn drop(&mut self) {
        let mut state = lock(&self.lifecycle.state);
        state.in_flight -= 1;

        if state.closing && state.in_flight == 0 {
            self.lifecycle.quiesced.notify_all();
        }
    }
}

impl Drop for SessionCallPermit<'_> {
    fn drop(&mut self) {
        let mut state = lock(&self.session.access);
        let count = state
            .in_flight
            .get_mut(&self.thread)
            .expect("session call permit was not registered");
        *count -= 1;
        if *count == 0 {
            state.in_flight.remove(&self.thread);
        }

        if matches!(state.phase, SessionPhase::Closing) {
            self.session.quiesced.notify_all();
        }
    }
}

impl SessionRegistry {
    pub(crate) fn get_or_create(&self, raw: *mut quicr_sys::quicr_session_t) -> Option<Session> {
        let raw = NonNull::new(raw)?;
        let key = raw.as_ptr() as usize;

        let lifecycle = lock(&self.lifecycle.state);
        let mut sessions = lock(&self.sessions);
        let state = if let Some(state) = sessions.get(&key) {
            Arc::clone(state)
        } else {
            let state = SessionState::new(
                raw.as_ptr(),
                Arc::clone(&self.lifecycle),
                !lifecycle.closing,
            );

            if !lifecycle.closing {
                sessions.insert(key, Arc::clone(&state));
            }

            state
        };

        Some(Session::from_state(state))
    }

    pub(crate) fn register_new(&self, raw: *mut quicr_sys::quicr_session_t) -> Option<Session> {
        let raw = NonNull::new(raw)?;
        let key = raw.as_ptr() as usize;

        let lifecycle = lock(&self.lifecycle.state);
        let mut sessions = lock(&self.sessions);
        let replace = sessions.get(&key).is_none_or(|state| state.is_expired());
        if replace {
            let state = SessionState::new(
                raw.as_ptr(),
                Arc::clone(&self.lifecycle),
                !lifecycle.closing,
            );
            if !lifecycle.closing {
                sessions.insert(key, Arc::clone(&state));
            }
            return Some(Session::from_state(state));
        }

        sessions.get(&key).cloned().map(Session::from_state)
    }

    pub(crate) fn begin_removal(&self, raw: *mut quicr_sys::quicr_session_t) -> Option<Session> {
        let raw = NonNull::new(raw)?;
        let key = raw.as_ptr() as usize;

        let lifecycle = lock(&self.lifecycle.state);
        let mut sessions = lock(&self.sessions);
        let state = Arc::clone(sessions.entry(key).or_insert_with(|| {
            SessionState::new(
                raw.as_ptr(),
                Arc::clone(&self.lifecycle),
                !lifecycle.closing,
            )
        }));
        drop(sessions);
        drop(lifecycle);
        state.begin_removal();

        Some(Session::from_state(state))
    }

    pub(crate) fn finish_removal(&self, session: &Session) {
        session.state.finish_removal();
    }

    pub(crate) fn begin_shutdown(&self) {
        self.lifecycle.begin_shutdown();
    }

    pub(crate) fn is_shutting_down(&self) -> bool {
        self.lifecycle.is_closing()
    }

    pub(crate) fn invalidate_all(&self) {
        for state in lock(&self.sessions).values() {
            state.clear();
        }
    }

    pub(crate) fn take_registrations(&self) -> Vec<(usize, Vec<Registration>)> {
        lock(&self.sessions)
            .values()
            .filter_map(|state| {
                let registrations = state.take_registrations();
                (!registrations.is_empty()).then_some((state.key, registrations))
            })
            .collect()
    }
}

impl Session {
    pub(crate) fn from_state(state: Arc<SessionState>) -> Self {
        Self { state }
    }

    /// Returns the session's current native status.
    ///
    /// Returns [`SessionExpired`] if teardown has begun, the session was removed, or libquicr no
    /// longer accepts the status query.
    pub fn status(&self) -> Result<SessionStatus, SessionExpired> {
        let (result, status) = self.with_raw(|raw| {
            let mut status = 0;
            let result = unsafe { quicr_sys::quicr_session_get_status(raw, &mut status) };
            (result, status)
        })?;

        if result != quicr_sys::QUICR_STATUS_OK as quicr_sys::quicr_status_t {
            return Err(SessionExpired);
        }

        Ok(SessionStatus::from_native(status))
    }

    pub(crate) fn with_raw<R>(
        &self,
        function: impl FnOnce(*mut quicr_sys::quicr_session_t) -> R,
    ) -> Result<R, SessionExpired> {
        let _manager_permit = self.state.manager_lifecycle.enter().ok_or(SessionExpired)?;
        let (raw, _session_permit) = self.state.enter().ok_or(SessionExpired)?;
        Ok(function(raw))
    }

    /// Returns whether this handle can no longer be used for session operations.
    ///
    /// Expiration is permanent for this handle. A `false` result is only a snapshot; concurrent
    /// removal or manager teardown can make a subsequent operation return an expiration error.
    pub fn is_expired(&self) -> bool {
        self.state.manager_lifecycle.is_closing() || !self.state.is_active()
    }

    pub(crate) fn key(&self) -> usize {
        self.state.key
    }

    pub(crate) fn reserve_registration(&self) -> Result<bool, std::collections::TryReserveError> {
        self.state.reserve_registration()
    }

    pub(crate) fn retain_registration(
        &self,
        registration: Registration,
    ) -> Result<(), Registration> {
        self.state.retain_registration(registration)
    }

    pub(crate) fn remove_registration(&self, key: (*const c_void, bool)) {
        self.state.remove_registration(key);
    }

    pub(crate) fn take_registrations(&self) -> Vec<Registration> {
        self.state.take_registrations()
    }

    /// Requests disconnection of this session.
    ///
    /// The request's acceptance does not promise when native disconnection callbacks will run.
    pub fn disconnect(&self) -> Result<(), SessionOperationError> {
        self.with_raw(disconnect)
            .map_err(|_| SessionOperationError::Expired)?
    }

    /// Sends a namespace advertisement on this session.
    pub fn send_namespace(
        &self,
        track_namespace: &TrackNamespace,
    ) -> Result<(), SessionOperationError> {
        let track_namespace =
            track_namespace
                .to_native()
                .map_err(|error| match error.status() as u32 {
                    quicr_sys::QUICR_STATUS_INVALID_ARGUMENT => {
                        SessionOperationError::InvalidArgument
                    }
                    quicr_sys::QUICR_STATUS_OUT_OF_MEMORY => SessionOperationError::OutOfMemory,
                    _ => SessionOperationError::Failed,
                })?;

        let result = self
            .with_raw(|session| unsafe {
                quicr_sys::quicr_session_send_namespace(session, track_namespace.raw)
            })
            .map_err(|_| SessionOperationError::Expired)?;

        native_operation_result(result)
    }

    /// Signals that advertisement of `track_namespace` is complete.
    pub fn send_namespace_done(
        &self,
        track_namespace: &TrackNamespace,
    ) -> Result<(), SessionOperationError> {
        let track_namespace =
            track_namespace
                .to_native()
                .map_err(|error| match error.status() as u32 {
                    quicr_sys::QUICR_STATUS_INVALID_ARGUMENT => {
                        SessionOperationError::InvalidArgument
                    }
                    quicr_sys::QUICR_STATUS_OUT_OF_MEMORY => SessionOperationError::OutOfMemory,
                    _ => SessionOperationError::Failed,
                })?;

        let result = self
            .with_raw(|session| unsafe {
                quicr_sys::quicr_session_send_namespace_done(session, track_namespace.raw)
            })
            .map_err(|_| SessionOperationError::Expired)?;

        native_operation_result(result)
    }

    /// Sends a GOAWAY directing the peer toward `new_session_uri`.
    ///
    /// `timeout` must fit in native milliseconds, and the URI must contain no interior NUL byte.
    /// `first_unprocessed_request_id` identifies the first request the peer should consider
    /// unprocessed when supplied. Acceptance by this method does not guarantee that the peer
    /// receives or follows the redirect.
    pub fn goaway(
        &self,
        new_session_uri: &str,
        timeout: Duration,
        first_unprocessed_request_id: Option<u64>,
    ) -> Result<(), SessionOperationError> {
        self.with_raw(|session| {
            goaway(
                session,
                new_session_uri,
                timeout,
                first_unprocessed_request_id,
            )
        })
        .map_err(|_| SessionOperationError::Expired)?
    }

    /// Sends a GOAWAY associated with a track handler.
    ///
    /// The URI and timeout validation are the same as for [`Session::goaway`]. The handler is
    /// borrowed for the call; its existing owner remains responsible for its lifetime.
    pub fn goaway_handler<H: TrackHandler>(
        &self,
        new_session_uri: &str,
        timeout: Duration,
        handler: &H,
    ) -> Result<(), SessionOperationError> {
        let uri = CString::new(new_session_uri).map_err(|_| SessionOperationError::InvalidUri)?;
        let timeout_ms = timeout
            .as_millis()
            .try_into()
            .map_err(|_| SessionOperationError::InvalidArgument)?;
        let registration = registration(handler);

        let result = self
            .with_raw(|session| unsafe {
                goaway_registration(&registration, session, uri.as_ptr(), timeout_ms)
            })
            .map_err(|_| SessionOperationError::Expired)?;

        native_operation_result(result)
    }

    /// Applies the current options of a registered subscribe-track handler.
    ///
    /// The handler must be associated with this session as required by libquicr.
    pub fn update_track_subscription(
        &self,
        handler: &SubscribeTrackHandler,
    ) -> Result<(), SessionOperationError> {
        let result = self
            .with_raw(|session| unsafe {
                quicr_sys::quicr_session_update_subscribe_track_handler(session, handler.inner.raw)
            })
            .map_err(|_| SessionOperationError::Expired)?;

        native_operation_result(result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Failure from a direct [`Session`] operation.
pub enum SessionOperationError {
    /// The session was removed, manager teardown began, or the native session was not found.
    Expired,
    /// A URI contains an interior NUL byte and cannot cross the native boundary.
    InvalidUri,
    /// An argument is invalid or cannot be represented by the native API.
    InvalidArgument,
    /// Native allocation failed.
    OutOfMemory,
    /// The native API accepted the call but did not apply the requested change.
    NotApplied,
    /// The native API reported another failure.
    Failed,
}

impl fmt::Display for SessionOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => formatter.write_str("session has expired"),
            Self::InvalidUri => formatter.write_str("new session URI contains a null byte"),
            Self::InvalidArgument => formatter.write_str("invalid session operation"),
            Self::OutOfMemory => formatter.write_str("session operation ran out of memory"),
            Self::NotApplied => formatter.write_str("session operation was not applied"),
            Self::Failed => formatter.write_str("session operation failed"),
        }
    }
}

impl std::error::Error for SessionOperationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Reason reported when a native stream closes.
pub enum StreamClosedFlag {
    /// The stream ended with a FIN.
    Fin,
    /// The stream was reset.
    Reset,
    /// The peer requested that sending stop.
    StopSending,
    /// A stream-close flag not recognized by this crate.
    Unknown(u8),
}

impl StreamClosedFlag {
    fn from_native(value: quicr_sys::quicr_stream_closed_flag_t) -> Self {
        match value {
            value if value == quicr_sys::QUICR_STREAM_CLOSED_FLAG_FIN as _ => Self::Fin,
            value if value == quicr_sys::QUICR_STREAM_CLOSED_FLAG_RESET as _ => Self::Reset,
            value if value == quicr_sys::QUICR_STREAM_CLOSED_FLAG_STOP_SENDING as _ => {
                Self::StopSending
            }
            value => Self::Unknown(value),
        }
    }
}

fn disconnect(session: *mut quicr_sys::quicr_session_t) -> Result<(), SessionOperationError> {
    let result = unsafe { quicr_sys::quicr_session_disconnect(session) };
    native_operation_result(result)
}

fn native_operation_result(result: quicr_sys::quicr_status_t) -> Result<(), SessionOperationError> {
    match result as u32 {
        quicr_sys::QUICR_STATUS_OK => Ok(()),
        quicr_sys::QUICR_STATUS_NOT_FOUND => Err(SessionOperationError::Expired),
        quicr_sys::QUICR_STATUS_INVALID_ARGUMENT => Err(SessionOperationError::InvalidArgument),
        quicr_sys::QUICR_STATUS_OUT_OF_MEMORY => Err(SessionOperationError::OutOfMemory),
        quicr_sys::QUICR_STATUS_NOT_APPLIED => Err(SessionOperationError::NotApplied),
        _ => Err(SessionOperationError::Failed),
    }
}

fn goaway(
    session: *mut quicr_sys::quicr_session_t,
    new_session_uri: &str,
    timeout: Duration,
    first_unprocessed_request_id: Option<u64>,
) -> Result<(), SessionOperationError> {
    let uri = CString::new(new_session_uri).map_err(|_| SessionOperationError::InvalidUri)?;
    let timeout_ms = timeout
        .as_millis()
        .try_into()
        .map_err(|_| SessionOperationError::InvalidArgument)?;

    let result = unsafe {
        quicr_sys::quicr_session_goaway(
            session,
            uri.as_ptr(),
            timeout_ms,
            first_unprocessed_request_id
                .as_ref()
                .map_or(ptr::null(), |request_id| request_id),
        )
    };
    native_operation_result(result)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
/// Current native session state.
pub enum SessionStatus {
    /// The session is ready for protocol operations.
    Ready,
    /// The session is not currently ready.
    NotReady,
    /// An internal session failure occurred.
    InternalError,
    /// Session parameters are invalid.
    InvalidParams,
    /// The session is connecting.
    Connecting,
    /// The session is disconnecting.
    Disconnecting,
    /// The session is not connected.
    NotConnected,
    /// The connection attempt failed.
    FailedToConnect,
    /// The session is waiting for peer setup.
    PendingPeerSetup,
    /// A native status not recognized by this crate.
    Unknown(u8),
}

impl SessionStatus {
    pub(crate) fn from_native(status: quicr_sys::quicr_session_status_t) -> Self {
        match status {
            status if status == quicr_sys::QUICR_SESSION_STATUS_READY as _ => Self::Ready,
            status if status == quicr_sys::QUICR_SESSION_STATUS_NOT_READY as _ => Self::NotReady,
            status if status == quicr_sys::QUICR_SESSION_STATUS_INTERNAL_ERROR as _ => {
                Self::InternalError
            }
            status if status == quicr_sys::QUICR_SESSION_STATUS_INVALID_PARAMS as _ => {
                Self::InvalidParams
            }
            status if status == quicr_sys::QUICR_SESSION_STATUS_CONNECTING as _ => Self::Connecting,
            status if status == quicr_sys::QUICR_SESSION_STATUS_DISCONNECTING as _ => {
                Self::Disconnecting
            }
            status if status == quicr_sys::QUICR_SESSION_STATUS_NOT_CONNECTED as _ => {
                Self::NotConnected
            }
            status if status == quicr_sys::QUICR_SESSION_STATUS_FAILED_TO_CONNECT as _ => {
                Self::FailedToConnect
            }
            status if status == quicr_sys::QUICR_SESSION_STATUS_PENDING_PEER_SETUP as _ => {
                Self::PendingPeerSetup
            }
            status => Self::Unknown(status),
        }
    }
}

/// Indicates that a [`Session`] handle is permanently expired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionExpired;

impl std::fmt::Display for SessionExpired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("session has expired")
    }
}

impl std::error::Error for SessionExpired {}

/// Attributes borrowed from an incoming session setup message.
///
/// Values are valid only for the duration of the setup callback.
pub struct SetupAttributes<'a> {
    endpoint_id: &'a [u8],
}

impl SetupAttributes<'_> {
    /// Returns the peer's opaque endpoint identifier.
    pub fn endpoint_id(&self) -> &[u8] {
        self.endpoint_id
    }
}

/// Error-code type accepted by [`SetupError`].
pub type SetupErrorCode = ErrorCode;

/// A rejection returned from a setup callback.
///
/// Setup rejects do not support redirects through this type. Reasons are validated for native
/// string representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupError {
    code: SetupErrorCode,
    reason: Option<String>,
}

impl SetupError {
    /// Constructs a setup rejection without a reason.
    ///
    /// Returns [`InvalidReplyError`] for redirect and unknown codes.
    pub fn new(code: SetupErrorCode) -> Result<Self, InvalidReplyError> {
        if matches!(code, SetupErrorCode::Redirect | SetupErrorCode::Unknown(_)) {
            return Err(InvalidReplyError);
        }

        Ok(Self { code, reason: None })
    }

    fn known(code: SetupErrorCode) -> Self {
        debug_assert!(!matches!(
            code,
            SetupErrorCode::Redirect | SetupErrorCode::Unknown(_)
        ));
        Self { code, reason: None }
    }

    /// Adds a human-readable reason.
    ///
    /// Returns [`InvalidReplyError`] if the reason contains an interior NUL byte.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Result<Self, InvalidReplyError> {
        let reason = reason.into();
        CString::new(reason.as_str()).map_err(|_| InvalidReplyError)?;
        self.reason = Some(reason);
        Ok(self)
    }

    /// Returns the setup error code.
    pub fn code(&self) -> SetupErrorCode {
        self.code
    }

    /// Returns the optional human-readable reason.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

/// Receives callbacks for a client session.
///
/// Callbacks may run concurrently and may be invoked synchronously while libquicr locks are held.
/// Return promptly. Do not call manager, session, or handler operations on the same native objects,
/// and do not destroy a callback-owning object from its callback. Reply-returning methods must
/// produce their response before returning; deferred replies are not currently supported.
///
/// A panic in a reply-returning method is converted to an internal-error reply. A panic in a
/// notification method aborts the process because unwinding across the native boundary is invalid.
pub trait ClientSessionCallbacks: Send + Sync + 'static {
    /// Accepts or rejects the peer's setup message.
    fn setup_received(
        &self,
        _session: &Session,
        _attributes: SetupAttributes<'_>,
    ) -> Reply<(), SetupError> {
        Reply::ok(())
    }

    /// Reports a change in native session status.
    fn status_changed(&self, _session: &Session, _status: SessionStatus) {}

    /// Reports that a native stream closed.
    ///
    /// This callback does not carry a [`Session`] because libquicr does not provide one here.
    fn stream_closed(&self, _stream_id: u64, _flag: StreamClosedFlag) {}

    /// Reports a sampled set of connection metrics.
    fn metrics_sampled(&self, _session: &Session, _metrics: ConnectionMetrics) {}

    /// Handles a subscription for a track this client has not published.
    fn unpublished_subscribe_received(
        &self,
        _session: &Session,
        _full_track_name: FullTrackName,
        _attributes: SubscribeAttributes,
    ) -> Reply<(), SessionError> {
        Reply::ok(())
    }

    /// Accepts or rejects an incoming standalone fetch.
    fn standalone_fetch_received(
        &self,
        _session: &Session,
        _request_id: u64,
        _full_track_name: FullTrackName,
        _attributes: StandaloneFetchAttributes,
    ) -> Reply<FetchResponse, FetchError> {
        Reply::err(FetchError::known(FetchErrorCode::InternalError))
    }

    /// Accepts or rejects an incoming joining fetch.
    fn joining_fetch_received(
        &self,
        _session: &Session,
        _request_id: u64,
        _full_track_name: FullTrackName,
        _attributes: JoiningFetchAttributes,
    ) -> Reply<FetchResponse, FetchError> {
        Reply::err(FetchError::known(FetchErrorCode::InternalError))
    }

    /// Reports cancellation of a previously received fetch request.
    fn fetch_cancel_received(&self, _session: &Session, _request_id: u64) {}

    /// Returns status information for an incoming track-status request.
    fn track_status_received(
        &self,
        _session: &Session,
        _full_track_name: FullTrackName,
    ) -> Reply<TrackStatusResponse, RequestError> {
        Reply::ok(TrackStatusResponse {
            largest_location: None,
            track_properties: TrackExtensions::new(),
        })
    }

    /// Accepts or rejects an incoming namespace publication.
    fn publish_namespace_received(
        &self,
        _session: &Session,
        _track_namespace: TrackNamespace,
        _attributes: PublishNamespaceAttributes,
    ) -> Reply<(), PublishNamespaceError> {
        Reply::ok(())
    }

    /// Accepts or rejects an incoming publish.
    ///
    /// On acceptance, return a [`PublishResponse`] whose handler receives the track. The optional
    /// namespace handler is borrowed only for this callback; a handler created from it and returned
    /// in the response is retained by the manager for the accepted publish.
    fn publish_received(
        &self,
        _session: &Session,
        _request_id: u64,
        _attributes: PublishAttributes,
        _namespace_handler: Option<SubscribeNamespaceHandlerRef<'_>>,
    ) -> Reply<PublishResponse, PublishError> {
        Reply::err(PublishError::known(PublishErrorCode::NotSupported))
    }
}

impl ClientSessionCallbacks for () {}

/// Receives callbacks for a server session.
///
/// Callbacks may run concurrently and may be invoked synchronously while libquicr locks are held.
/// Return promptly. Do not call manager, session, or handler operations on the same native objects,
/// and do not destroy a callback-owning object from its callback. Reply-returning methods must
/// produce their response before returning; deferred replies are not currently supported.
///
/// A panic in a reply-returning method is converted to an internal-error reply. A panic in a
/// notification method aborts the process because unwinding across the native boundary is invalid.
pub trait ServerSessionCallbacks: Send + Sync + 'static {
    /// Accepts or rejects the peer's setup message.
    fn setup_received(
        &self,
        _session: &Session,
        _attributes: SetupAttributes<'_>,
    ) -> Reply<(), SetupError> {
        Reply::ok(())
    }

    /// Reports a change in native session status.
    fn status_changed(&self, _session: &Session, _status: SessionStatus) {}

    /// Reports that a native stream closed.
    ///
    /// This callback does not carry a [`Session`] because libquicr does not provide one here.
    fn stream_closed(&self, _stream_id: u64, _flag: StreamClosedFlag) {}

    /// Reports a sampled set of connection metrics.
    fn metrics_sampled(&self, _session: &Session, _metrics: ConnectionMetrics) {}

    /// Accepts or rejects a publisher request to begin a new group.
    fn new_group_requested(
        &self,
        _full_track_name: FullTrackName,
        _group_id: u64,
    ) -> Reply<(), SessionError> {
        Reply::ok(())
    }

    /// Accepts or rejects an incoming standalone fetch.
    fn standalone_fetch_received(
        &self,
        _session: &Session,
        _request_id: u64,
        _full_track_name: FullTrackName,
        _attributes: StandaloneFetchAttributes,
    ) -> Reply<FetchResponse, FetchError> {
        Reply::err(FetchError::known(FetchErrorCode::InternalError))
    }

    /// Accepts or rejects an incoming joining fetch.
    fn joining_fetch_received(
        &self,
        _session: &Session,
        _request_id: u64,
        _full_track_name: FullTrackName,
        _attributes: JoiningFetchAttributes,
    ) -> Reply<FetchResponse, FetchError> {
        Reply::err(FetchError::known(FetchErrorCode::InternalError))
    }

    /// Reports cancellation of a previously received fetch request.
    fn fetch_cancel_received(&self, _session: &Session, _request_id: u64) {}

    /// Returns status information for an incoming track-status request.
    fn track_status_received(
        &self,
        _session: &Session,
        _full_track_name: FullTrackName,
    ) -> Reply<TrackStatusResponse, RequestError> {
        Reply::ok(TrackStatusResponse {
            largest_location: None,
            track_properties: TrackExtensions::new(),
        })
    }

    /// Accepts or rejects an incoming namespace publication.
    fn publish_namespace_received(
        &self,
        _session: &Session,
        _track_namespace: TrackNamespace,
        _attributes: PublishNamespaceAttributes,
    ) -> Reply<(), PublishNamespaceError> {
        Reply::ok(())
    }

    /// Accepts or rejects an incoming publish.
    ///
    /// On acceptance, return a [`PublishResponse`] whose handler receives the track. The optional
    /// namespace handler is borrowed only for this callback; a handler created from it and returned
    /// in the response is retained by the manager for the accepted publish.
    fn publish_received(
        &self,
        _session: &Session,
        _request_id: u64,
        _attributes: PublishAttributes,
        _namespace_handler: Option<SubscribeNamespaceHandlerRef<'_>>,
    ) -> Reply<PublishResponse, PublishError> {
        Reply::err(PublishError::known(PublishErrorCode::NotSupported))
    }

    /// Accepts or rejects an incoming track subscription.
    fn subscribe_received(
        &self,
        _session: &Session,
        _request_id: u64,
        _full_track_name: FullTrackName,
        _attributes: SubscribeAttributes,
    ) -> Reply<SubscribeResponse, RequestError> {
        Reply::ok(SubscribeResponse {
            track_status: TrackStatusResponse {
                largest_location: None,
                track_properties: TrackExtensions::new(),
            },
            is_publisher_initiated: false,
            expires: None,
        })
    }

    /// Answers a namespace subscription with matching namespaces.
    ///
    /// Redirect errors for this namespace-level operation must not include
    /// [`Redirect::track_name`](crate::Redirect::track_name); an invalid redirect is converted to
    /// an internal-error reply.
    fn subscribe_namespace_received(
        &self,
        _session: &Session,
        _prefix: TrackNamespace,
        _attributes: SubscribeNamespaceAttributes,
    ) -> Reply<Vec<TrackNamespace>, RequestError> {
        Reply::ok(Vec::new())
    }

    /// Answers a request to enumerate tracks under a namespace prefix.
    ///
    /// Redirect errors for this namespace-level operation must not include
    /// [`Redirect::track_name`](crate::Redirect::track_name); an invalid redirect is converted to
    /// an internal-error reply.
    fn subscribe_tracks_received(
        &self,
        _session: &Session,
        _prefix: TrackNamespace,
        _attributes: SubscribeNamespaceAttributes,
    ) -> Reply<Vec<TrackNamespace>, RequestError> {
        Reply::ok(Vec::new())
    }

    /// Reports that the peer finished a previously accepted publish.
    fn publish_done_received(&self, _session: &Session, _request_id: u64) {}

    /// Reports that the peer unsubscribed from a previously accepted publish.
    fn unsubscribe_received(&self, _session: &Session, _request_id: u64) {}

    /// Reports completion of a namespace publication request.
    fn publish_namespace_done_received(&self, _session: &Session, _request_id: u64) {}

    /// Reports cancellation of a namespace subscription.
    fn unsubscribe_namespace_received(&self, _session: &Session, _track_namespace: TrackNamespace) {
    }
}

impl ServerSessionCallbacks for () {}

pub(crate) struct ClientCallbackState {
    callbacks: Box<dyn ClientSessionCallbacks>,
    registry: Arc<SessionRegistry>,
    accepted_publishes: Arc<AcceptedPublishHandlers>,
    reply_backings: Mutex<HashMap<ThreadId, ReplyBacking>>,
}

pub(crate) struct ServerCallbackState {
    callbacks: Box<dyn ServerSessionCallbacks>,
    registry: Arc<SessionRegistry>,
    accepted_publishes: Arc<AcceptedPublishHandlers>,
    reply_backings: Mutex<HashMap<ThreadId, ReplyBacking>>,
}

#[derive(Default)]
struct ReplyBacking {
    track_extensions: Vec<NativeTrackExtensions>,
    namespace_lists: Vec<NativeNamespaceList>,
    errors: Vec<NativeReplyErrorBacking>,
    publish_response: Option<NativePublishResponse>,
}

#[derive(Default)]
pub(crate) struct AcceptedPublishHandlers {
    active: Mutex<HashMap<(usize, u64), SubscribeTrackHandler>>,
    retired: Mutex<Vec<SubscribeTrackHandler>>,
}

impl AcceptedPublishHandlers {
    fn retain(
        &self,
        session: *mut quicr_sys::quicr_session_t,
        request_id: u64,
        handler: SubscribeTrackHandler,
    ) {
        let replaced = lock(&self.active).insert((session as usize, request_id), handler);
        if let Some(handler) = replaced {
            lock(&self.retired).push(handler);
        }
    }

    fn retire(&self, session: *mut quicr_sys::quicr_session_t, request_id: u64) {
        if let Some(handler) = lock(&self.active).remove(&(session as usize, request_id)) {
            lock(&self.retired).push(handler);
        }
    }

    pub(crate) fn retire_session(&self, session: usize) {
        let mut active = lock(&self.active);
        let keys: Vec<_> = active
            .keys()
            .filter(|(key, _)| *key == session)
            .copied()
            .collect();
        let handlers: Vec<_> = keys
            .into_iter()
            .filter_map(|key| active.remove(&key))
            .collect();
        drop(active);

        lock(&self.retired).extend(handlers);
    }

    pub(crate) fn retry_retired(&self) {
        let handlers = std::mem::take(&mut *lock(&self.retired));
        let mut retained = Vec::new();

        for handler in handlers {
            if let Err(error) = handler.close() {
                retained.push(error.into_handler());
            }
        }

        lock(&self.retired).extend(retained);
    }

    pub(crate) fn take_active(&self) -> Vec<(usize, SubscribeTrackHandler)> {
        std::mem::take(&mut *lock(&self.active))
            .into_iter()
            .map(|((session, _), handler)| (session, handler))
            .collect()
    }

    pub(crate) fn clear(&self) {
        lock(&self.active).clear();
        lock(&self.retired).clear();
    }
}

struct NativeNamespaceList {
    raw: Box<quicr_sys::quicr_track_namespace_list_t>,
    _namespaces: Vec<NativeTrackNamespace>,
    _pointers: Vec<*const quicr_sys::quicr_track_namespace_t>,
}

unsafe impl Send for NativeNamespaceList {}

impl NativeNamespaceList {
    fn new(namespaces: Vec<TrackNamespace>) -> Option<Self> {
        let namespaces: Vec<_> = namespaces
            .iter()
            .map(TrackNamespace::to_native)
            .collect::<Result<_, _>>()
            .ok()?;
        let pointers: Vec<_> = namespaces
            .iter()
            .map(|namespace| namespace.raw.cast_const())
            .collect();

        let raw = Box::new(quicr_sys::quicr_track_namespace_list_t {
            entries: pointers.as_ptr(),
            count: pointers.len(),
        });

        Some(Self {
            raw,
            _namespaces: namespaces,
            _pointers: pointers,
        })
    }

    fn as_ptr(&self) -> *const quicr_sys::quicr_track_namespace_list_t {
        &*self.raw
    }
}

impl ClientCallbackState {
    pub(crate) fn new(
        callbacks: impl ClientSessionCallbacks,
        registry: Arc<SessionRegistry>,
        accepted_publishes: Arc<AcceptedPublishHandlers>,
    ) -> Box<Self> {
        Box::new(Self {
            callbacks: Box::new(callbacks),
            registry,
            accepted_publishes,
            reply_backings: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn native_callbacks(&mut self) -> quicr_sys::quicr_session_client_callbacks_t {
        quicr_sys::quicr_session_client_callbacks_t {
            user_data: (self as *mut Self).cast(),
            setup_received: Some(setup_received),
            on_stream_closed: Some(client_stream_closed),
            status_changed: Some(status_changed),
            publish_received: Some(client_publish_received),
            publish_namespace_received: Some(client_publish_namespace_received),
            standalone_fetch_received: Some(client_standalone_fetch_received),
            joining_fetch_received: Some(client_joining_fetch_received),
            fetch_cancel_received: Some(client_fetch_cancel_received),
            track_status_received: Some(client_track_status_received),
            unpublished_subscribe_received: Some(unpublished_subscribe_received),
            metrics_sampled: Some(connection_metrics_sampled),
        }
    }
}

impl ServerCallbackState {
    pub(crate) fn new(
        callbacks: impl ServerSessionCallbacks,
        registry: Arc<SessionRegistry>,
        accepted_publishes: Arc<AcceptedPublishHandlers>,
    ) -> Box<Self> {
        Box::new(Self {
            callbacks: Box::new(callbacks),
            registry,
            accepted_publishes,
            reply_backings: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn native_callbacks(&mut self) -> quicr_sys::quicr_session_server_callbacks_t {
        quicr_sys::quicr_session_server_callbacks_t {
            user_data: (self as *mut Self).cast(),
            setup_received: Some(server_setup_received),
            on_stream_closed: Some(server_stream_closed),
            status_changed: Some(server_status_changed),
            publish_received: Some(server_publish_received),
            publish_namespace_received: Some(server_publish_namespace_received),
            standalone_fetch_received: Some(server_standalone_fetch_received),
            joining_fetch_received: Some(server_joining_fetch_received),
            fetch_cancel_received: Some(server_fetch_cancel_received),
            track_status_received: Some(server_track_status_received),
            subscribe_namespace_received: Some(subscribe_namespace_received),
            subscribe_tracks_received: Some(subscribe_tracks_received),
            subscribe_received: Some(subscribe_received),
            new_group_requested: Some(new_group_requested),
            metrics_sampled: Some(server_metrics_sampled),
            publish_done_received: Some(publish_done_received),
            unsubscribe_received: Some(unsubscribe_received),
            publish_namespace_done_received: Some(publish_namespace_done_received),
            unsubscribe_namespace_received: Some(unsubscribe_namespace_received),
        }
    }
}

unsafe extern "C" fn status_changed(
    session: *mut quicr_sys::quicr_session_t,
    status: quicr_sys::quicr_session_status_t,
    user_data: *mut c_void,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { &*user_data.cast::<ClientCallbackState>() };
        let session = state
            .registry
            .get_or_create(session)
            .expect("libquicr invoked a client callback with a null session");

        state
            .callbacks
            .status_changed(&session, SessionStatus::from_native(status));
    }));

    if result.is_err() {
        std::process::abort();
    }
}

unsafe extern "C" fn server_status_changed(
    session: *mut quicr_sys::quicr_session_t,
    status: quicr_sys::quicr_session_status_t,
    user_data: *mut c_void,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
        let session = state
            .registry
            .get_or_create(session)
            .expect("libquicr invoked a server callback with a null session");

        state
            .callbacks
            .status_changed(&session, SessionStatus::from_native(status));
    }));

    if result.is_err() {
        std::process::abort();
    }
}

unsafe extern "C" fn client_stream_closed(
    stream_id: u64,
    flag: quicr_sys::quicr_stream_closed_flag_t,
    user_data: *mut c_void,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { &*user_data.cast::<ClientCallbackState>() };

        state
            .callbacks
            .stream_closed(stream_id, StreamClosedFlag::from_native(flag));
    }));

    if result.is_err() {
        std::process::abort();
    }
}

unsafe extern "C" fn server_stream_closed(
    stream_id: u64,
    flag: quicr_sys::quicr_stream_closed_flag_t,
    user_data: *mut c_void,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { &*user_data.cast::<ServerCallbackState>() };

        state
            .callbacks
            .stream_closed(stream_id, StreamClosedFlag::from_native(flag));
    }));

    if result.is_err() {
        std::process::abort();
    }
}

unsafe extern "C" fn connection_metrics_sampled(
    session: *mut quicr_sys::quicr_session_t,
    metrics: *const quicr_sys::quicr_connection_metrics_t,
    user_data: *mut c_void,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { &*user_data.cast::<ClientCallbackState>() };
        let session = state
            .registry
            .get_or_create(session)
            .expect("libquicr invoked a client callback with a null session");
        let metrics = unsafe { metrics.as_ref() }
            .copied()
            .expect("libquicr invoked a metrics callback with null metrics");

        state.callbacks.metrics_sampled(&session, metrics.into());
    }));

    if result.is_err() {
        std::process::abort();
    }
}

unsafe extern "C" fn server_metrics_sampled(
    session: *mut quicr_sys::quicr_session_t,
    metrics: *const quicr_sys::quicr_connection_metrics_t,
    user_data: *mut c_void,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
        let session = state
            .registry
            .get_or_create(session)
            .expect("libquicr invoked a server callback with a null session");
        let metrics = unsafe { metrics.as_ref() }
            .copied()
            .expect("libquicr invoked a metrics callback with null metrics");

        state.callbacks.metrics_sampled(&session, metrics.into());
    }));

    if result.is_err() {
        std::process::abort();
    }
}

unsafe extern "C" fn publish_done_received(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
    state.accepted_publishes.retry_retired();

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let session = state
            .registry
            .get_or_create(session)
            .expect("libquicr invoked publish_done_received with a null session");

        state.callbacks.publish_done_received(&session, request_id);
    }));

    state.accepted_publishes.retire(session, request_id);

    if result.is_err() {
        std::process::abort();
    }
}

unsafe extern "C" fn unsubscribe_received(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
    state.accepted_publishes.retry_retired();

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let session = state
            .registry
            .get_or_create(session)
            .expect("libquicr invoked unsubscribe_received with a null session");

        state.callbacks.unsubscribe_received(&session, request_id);
    }));

    state.accepted_publishes.retire(session, request_id);

    if result.is_err() {
        std::process::abort();
    }
}

unsafe extern "C" fn publish_namespace_done_received(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    user_data: *mut c_void,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
        let session = state
            .registry
            .get_or_create(session)
            .expect("libquicr invoked publish_namespace_done_received with a null session");

        state
            .callbacks
            .publish_namespace_done_received(&session, request_id);
    }));

    if result.is_err() {
        std::process::abort();
    }
}

unsafe extern "C" fn unsubscribe_namespace_received(
    session: *mut quicr_sys::quicr_session_t,
    track_namespace: *const quicr_sys::quicr_track_namespace_t,
    user_data: *mut c_void,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
        let session = state
            .registry
            .get_or_create(session)
            .expect("libquicr invoked unsubscribe_namespace_received with a null session");
        let track_namespace = unsafe { TrackNamespace::copy_from_raw(track_namespace) }
            .expect("libquicr invoked unsubscribe_namespace_received with a null namespace");

        state
            .callbacks
            .unsubscribe_namespace_received(&session, track_namespace);
    }));

    if result.is_err() {
        std::process::abort();
    }
}

unsafe extern "C" fn setup_received(
    session: *mut quicr_sys::quicr_session_t,
    attributes: *const quicr_sys::quicr_setup_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ClientCallbackState>() };
    begin_reply(&state.reply_backings);

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let session = state
            .registry
            .get_or_create(session)
            .ok_or_else(|| SetupError::known(SetupErrorCode::InternalError))?;
        let attributes = unsafe { attributes.as_ref() }
            .ok_or_else(|| SetupError::known(SetupErrorCode::InternalError))?;
        let endpoint_id = byte_span(attributes, attributes.endpoint_id)
            .ok_or_else(|| SetupError::known(SetupErrorCode::InternalError))?;

        state
            .callbacks
            .setup_received(&session, SetupAttributes { endpoint_id })
            .into_result()
    }))
    .unwrap_or_else(|_| Err(SetupError::known(SetupErrorCode::InternalError)));

    complete_setup_reply(reply, result, &state.reply_backings);
}

unsafe extern "C" fn server_setup_received(
    session: *mut quicr_sys::quicr_session_t,
    attributes: *const quicr_sys::quicr_setup_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
    begin_reply(&state.reply_backings);

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let session = state
            .registry
            .get_or_create(session)
            .ok_or_else(|| SetupError::known(SetupErrorCode::InternalError))?;
        let attributes = unsafe { attributes.as_ref() }
            .ok_or_else(|| SetupError::known(SetupErrorCode::InternalError))?;
        let endpoint_id = byte_span(attributes, attributes.endpoint_id)
            .ok_or_else(|| SetupError::known(SetupErrorCode::InternalError))?;

        state
            .callbacks
            .setup_received(&session, SetupAttributes { endpoint_id })
            .into_result()
    }))
    .unwrap_or_else(|_| Err(SetupError::known(SetupErrorCode::InternalError)));

    complete_setup_reply(reply, result, &state.reply_backings);
}

unsafe extern "C" fn unpublished_subscribe_received(
    session: *mut quicr_sys::quicr_session_t,
    full_track_name: *const quicr_sys::quicr_full_track_name_t,
    attributes: *const quicr_sys::quicr_subscribe_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ClientCallbackState>() };
    begin_reply(&state.reply_backings);

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let session = state
            .registry
            .get_or_create(session)
            .ok_or_else(|| SessionError::known(ErrorCode::InternalError))?;
        let full_track_name = unsafe { FullTrackName::copy_from_raw(full_track_name) }
            .ok_or_else(|| SessionError::known(ErrorCode::InternalError))?;
        let attributes = unsafe { SubscribeAttributes::copy_from_raw(attributes) }
            .map_err(|_| SessionError::known(ErrorCode::InternalError))?;

        state
            .callbacks
            .unpublished_subscribe_received(&session, full_track_name, attributes)
            .into_result()
    }))
    .unwrap_or_else(|_| Err(SessionError::known(ErrorCode::InternalError)));

    complete_empty_reply(reply, result, &state.reply_backings);
}

unsafe extern "C" fn client_standalone_fetch_received(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    full_track_name: *const quicr_sys::quicr_full_track_name_t,
    attributes: *const quicr_sys::quicr_standalone_fetch_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ClientCallbackState>() };
    standalone_fetch_reply(
        session,
        request_id,
        full_track_name,
        attributes,
        reply,
        &state.registry,
        &state.reply_backings,
        |session, request_id, name, attributes| {
            state
                .callbacks
                .standalone_fetch_received(session, request_id, name, attributes)
                .into_result()
        },
    );
}

unsafe extern "C" fn server_standalone_fetch_received(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    full_track_name: *const quicr_sys::quicr_full_track_name_t,
    attributes: *const quicr_sys::quicr_standalone_fetch_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
    standalone_fetch_reply(
        session,
        request_id,
        full_track_name,
        attributes,
        reply,
        &state.registry,
        &state.reply_backings,
        |session, request_id, name, attributes| {
            state
                .callbacks
                .standalone_fetch_received(session, request_id, name, attributes)
                .into_result()
        },
    );
}

unsafe extern "C" fn client_joining_fetch_received(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    full_track_name: *const quicr_sys::quicr_full_track_name_t,
    attributes: *const quicr_sys::quicr_joining_fetch_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ClientCallbackState>() };
    joining_fetch_reply(
        session,
        request_id,
        full_track_name,
        attributes,
        reply,
        &state.registry,
        &state.reply_backings,
        |session, request_id, name, attributes| {
            state
                .callbacks
                .joining_fetch_received(session, request_id, name, attributes)
                .into_result()
        },
    );
}

unsafe extern "C" fn server_joining_fetch_received(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    full_track_name: *const quicr_sys::quicr_full_track_name_t,
    attributes: *const quicr_sys::quicr_joining_fetch_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
    joining_fetch_reply(
        session,
        request_id,
        full_track_name,
        attributes,
        reply,
        &state.registry,
        &state.reply_backings,
        |session, request_id, name, attributes| {
            state
                .callbacks
                .joining_fetch_received(session, request_id, name, attributes)
                .into_result()
        },
    );
}

unsafe extern "C" fn client_fetch_cancel_received(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    user_data: *mut c_void,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { &*user_data.cast::<ClientCallbackState>() };
        let session = state
            .registry
            .get_or_create(session)
            .expect("libquicr invoked fetch_cancel_received with a null session");

        state.callbacks.fetch_cancel_received(&session, request_id);
    }));

    if result.is_err() {
        std::process::abort();
    }
}

unsafe extern "C" fn server_fetch_cancel_received(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    user_data: *mut c_void,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
        let session = state
            .registry
            .get_or_create(session)
            .expect("libquicr invoked fetch_cancel_received with a null session");

        state.callbacks.fetch_cancel_received(&session, request_id);
    }));

    if result.is_err() {
        std::process::abort();
    }
}

unsafe extern "C" fn client_track_status_received(
    session: *mut quicr_sys::quicr_session_t,
    full_track_name: *const quicr_sys::quicr_full_track_name_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ClientCallbackState>() };
    track_status_reply(
        session,
        full_track_name,
        reply,
        &state.registry,
        &state.reply_backings,
        |session, name| {
            state
                .callbacks
                .track_status_received(session, name)
                .into_result()
        },
    );
}

unsafe extern "C" fn server_track_status_received(
    session: *mut quicr_sys::quicr_session_t,
    full_track_name: *const quicr_sys::quicr_full_track_name_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
    track_status_reply(
        session,
        full_track_name,
        reply,
        &state.registry,
        &state.reply_backings,
        |session, name| {
            state
                .callbacks
                .track_status_received(session, name)
                .into_result()
        },
    );
}

unsafe extern "C" fn client_publish_namespace_received(
    session: *mut quicr_sys::quicr_session_t,
    track_namespace: *const quicr_sys::quicr_track_namespace_t,
    attributes: *const quicr_sys::quicr_publish_namespace_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ClientCallbackState>() };
    publish_namespace_reply(
        session,
        track_namespace,
        attributes,
        reply,
        &state.registry,
        &state.reply_backings,
        |session, track_namespace, attributes| {
            state
                .callbacks
                .publish_namespace_received(session, track_namespace, attributes)
                .into_result()
        },
    );
}

unsafe extern "C" fn server_publish_namespace_received(
    session: *mut quicr_sys::quicr_session_t,
    track_namespace: *const quicr_sys::quicr_track_namespace_t,
    attributes: *const quicr_sys::quicr_publish_namespace_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
    publish_namespace_reply(
        session,
        track_namespace,
        attributes,
        reply,
        &state.registry,
        &state.reply_backings,
        |session, track_namespace, attributes| {
            state
                .callbacks
                .publish_namespace_received(session, track_namespace, attributes)
                .into_result()
        },
    );
}

unsafe extern "C" fn client_publish_received(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    attributes: *const quicr_sys::quicr_publish_attributes_t,
    handler: *const quicr_sys::quicr_subscribe_namespace_handler_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ClientCallbackState>() };
    publish_reply(
        session,
        request_id,
        attributes,
        handler,
        reply,
        &state.registry,
        &state.reply_backings,
        &state.accepted_publishes,
        |session, request_id, attributes, handler| {
            state
                .callbacks
                .publish_received(session, request_id, attributes, handler)
                .into_result()
        },
    );
}

unsafe extern "C" fn server_publish_received(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    attributes: *const quicr_sys::quicr_publish_attributes_t,
    handler: *const quicr_sys::quicr_subscribe_namespace_handler_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
    publish_reply(
        session,
        request_id,
        attributes,
        handler,
        reply,
        &state.registry,
        &state.reply_backings,
        &state.accepted_publishes,
        |session, request_id, attributes, handler| {
            state
                .callbacks
                .publish_received(session, request_id, attributes, handler)
                .into_result()
        },
    );
}

unsafe extern "C" fn new_group_requested(
    full_track_name: *const quicr_sys::quicr_full_track_name_t,
    group_id: u64,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
    begin_reply(&state.reply_backings);

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let full_track_name = unsafe { FullTrackName::copy_from_raw(full_track_name) }
            .ok_or_else(|| SessionError::known(ErrorCode::InternalError))?;

        state
            .callbacks
            .new_group_requested(full_track_name, group_id)
            .into_result()
    }))
    .unwrap_or_else(|_| Err(SessionError::known(ErrorCode::InternalError)));

    complete_empty_reply(reply, result, &state.reply_backings);
}

unsafe extern "C" fn subscribe_namespace_received(
    session: *mut quicr_sys::quicr_session_t,
    prefix: *const quicr_sys::quicr_track_namespace_t,
    attributes: *const quicr_sys::quicr_subscribe_namespace_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
    track_namespaces_reply(
        session,
        prefix,
        attributes,
        reply,
        &state.registry,
        &state.reply_backings,
        |session, prefix, attributes| {
            state
                .callbacks
                .subscribe_namespace_received(session, prefix, attributes)
                .into_result()
        },
    );
}

unsafe extern "C" fn subscribe_tracks_received(
    session: *mut quicr_sys::quicr_session_t,
    prefix: *const quicr_sys::quicr_track_namespace_t,
    attributes: *const quicr_sys::quicr_subscribe_namespace_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
    track_namespaces_reply(
        session,
        prefix,
        attributes,
        reply,
        &state.registry,
        &state.reply_backings,
        |session, prefix, attributes| {
            state
                .callbacks
                .subscribe_tracks_received(session, prefix, attributes)
                .into_result()
        },
    );
}

unsafe extern "C" fn subscribe_received(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    full_track_name: *const quicr_sys::quicr_full_track_name_t,
    attributes: *const quicr_sys::quicr_subscribe_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<ServerCallbackState>() };
    begin_reply(&state.reply_backings);

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let session = state
            .registry
            .get_or_create(session)
            .ok_or_else(|| RequestError::known(RequestErrorCode::InternalError))?;
        let name = unsafe { FullTrackName::copy_from_raw(full_track_name) }
            .ok_or_else(|| RequestError::known(RequestErrorCode::InternalError))?;
        let attributes = unsafe { SubscribeAttributes::copy_from_raw(attributes) }
            .map_err(|_| RequestError::known(RequestErrorCode::InternalError))?;

        state
            .callbacks
            .subscribe_received(&session, request_id, name, attributes)
            .into_result()
    }))
    .unwrap_or_else(|_| Err(RequestError::known(RequestErrorCode::InternalError)));

    complete_subscribe_reply(reply, result, &state.reply_backings);
}

#[allow(clippy::too_many_arguments)]
fn standalone_fetch_reply(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    full_track_name: *const quicr_sys::quicr_full_track_name_t,
    attributes: *const quicr_sys::quicr_standalone_fetch_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    registry: &SessionRegistry,
    backings: &Mutex<HashMap<ThreadId, ReplyBacking>>,
    callback: impl FnOnce(
        &Session,
        u64,
        FullTrackName,
        StandaloneFetchAttributes,
    ) -> Result<FetchResponse, FetchError>,
) {
    begin_reply(backings);

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let session = registry
            .get_or_create(session)
            .ok_or_else(|| FetchError::known(FetchErrorCode::InternalError))?;
        let name = unsafe { FullTrackName::copy_from_raw(full_track_name) }
            .ok_or_else(|| FetchError::known(FetchErrorCode::InternalError))?;
        let attributes = unsafe { StandaloneFetchAttributes::copy_from_raw(attributes) }
            .map_err(|_| FetchError::known(FetchErrorCode::InternalError))?;

        callback(&session, request_id, name, attributes)
    }))
    .unwrap_or_else(|_| Err(FetchError::known(FetchErrorCode::InternalError)));

    complete_fetch_reply(reply, result, backings);
}

#[allow(clippy::too_many_arguments)]
fn joining_fetch_reply(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    full_track_name: *const quicr_sys::quicr_full_track_name_t,
    attributes: *const quicr_sys::quicr_joining_fetch_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    registry: &SessionRegistry,
    backings: &Mutex<HashMap<ThreadId, ReplyBacking>>,
    callback: impl FnOnce(
        &Session,
        u64,
        FullTrackName,
        JoiningFetchAttributes,
    ) -> Result<FetchResponse, FetchError>,
) {
    begin_reply(backings);

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let session = registry
            .get_or_create(session)
            .ok_or_else(|| FetchError::known(FetchErrorCode::InternalError))?;
        let name = unsafe { FullTrackName::copy_from_raw(full_track_name) }
            .ok_or_else(|| FetchError::known(FetchErrorCode::InternalError))?;
        let attributes = unsafe { JoiningFetchAttributes::copy_from_raw(attributes) }
            .map_err(|_| FetchError::known(FetchErrorCode::InternalError))?;

        callback(&session, request_id, name, attributes)
    }))
    .unwrap_or_else(|_| Err(FetchError::known(FetchErrorCode::InternalError)));

    complete_fetch_reply(reply, result, backings);
}

fn publish_namespace_reply(
    session: *mut quicr_sys::quicr_session_t,
    track_namespace: *const quicr_sys::quicr_track_namespace_t,
    attributes: *const quicr_sys::quicr_publish_namespace_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    registry: &SessionRegistry,
    backings: &Mutex<HashMap<ThreadId, ReplyBacking>>,
    callback: impl FnOnce(
        &Session,
        TrackNamespace,
        PublishNamespaceAttributes,
    ) -> Result<(), PublishNamespaceError>,
) {
    begin_reply(backings);

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let session = registry.get_or_create(session).ok_or_else(|| {
            PublishNamespaceError::known(PublishNamespaceErrorCode::InternalError)
        })?;
        let track_namespace = unsafe { TrackNamespace::copy_from_raw(track_namespace) }
            .ok_or_else(|| {
                PublishNamespaceError::known(PublishNamespaceErrorCode::InternalError)
            })?;
        let attributes = unsafe { PublishNamespaceAttributes::copy_from_raw(attributes) }
            .map_err(|_| PublishNamespaceError::known(PublishNamespaceErrorCode::InternalError))?;

        callback(&session, track_namespace, attributes)
    }))
    .unwrap_or_else(|_| {
        Err(PublishNamespaceError::known(
            PublishNamespaceErrorCode::InternalError,
        ))
    });

    match result {
        Ok(()) => {
            let status = unsafe { quicr_sys::quicr_reply_accept(reply) };

            if !reply_status_ok(status) {
                reject_internal_error(
                    reply,
                    PublishNamespaceErrorCode::InternalError.native() as u64,
                );
            }
        }
        Err(error) => {
            reject_namespace_reply(reply, error.code().native() as u64, &error, backings);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn publish_reply(
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    attributes: *const quicr_sys::quicr_publish_attributes_t,
    handler: *const quicr_sys::quicr_subscribe_namespace_handler_t,
    reply: *mut quicr_sys::quicr_reply_t,
    registry: &SessionRegistry,
    backings: &Mutex<HashMap<ThreadId, ReplyBacking>>,
    accepted_publishes: &AcceptedPublishHandlers,
    callback: impl FnOnce(
        &Session,
        u64,
        PublishAttributes,
        Option<SubscribeNamespaceHandlerRef<'_>>,
    ) -> Result<PublishResponse, PublishError>,
) {
    begin_reply(backings);
    accepted_publishes.retry_retired();

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let session = registry
            .get_or_create(session)
            .ok_or_else(|| PublishError::known(PublishErrorCode::InternalError))?;
        let attributes = unsafe { PublishAttributes::copy_from_raw(attributes) }
            .map_err(|_| PublishError::known(PublishErrorCode::InternalError))?;
        let handler = unsafe { SubscribeNamespaceHandlerRef::from_raw(handler) };

        callback(&session, request_id, attributes, handler)
    }))
    .unwrap_or_else(|_| Err(PublishError::known(PublishErrorCode::InternalError)));

    let response = match result {
        Ok(response) => response.into_native(),
        Err(error) => {
            reject_reply(reply, error.code().native() as u64, &error, backings);
            return;
        }
    };
    let response = match response {
        Ok(response) => response,
        Err(_) => {
            let error = PublishError::known(PublishErrorCode::InternalError);
            reject_reply(reply, error.code().native() as u64, &error, backings);
            return;
        }
    };

    let response_ptr = response.as_ptr();

    let status = unsafe { quicr_sys::quicr_reply_accept_publish(reply, response_ptr) };

    if !retain_accepted_publish(
        status,
        response,
        accepted_publishes,
        session,
        request_id,
        backings,
    ) {
        reject_internal_error(reply, PublishErrorCode::InternalError.native() as u64);
    }
}

fn track_namespaces_reply(
    session: *mut quicr_sys::quicr_session_t,
    prefix: *const quicr_sys::quicr_track_namespace_t,
    attributes: *const quicr_sys::quicr_subscribe_namespace_attributes_t,
    reply: *mut quicr_sys::quicr_reply_t,
    registry: &SessionRegistry,
    backings: &Mutex<HashMap<ThreadId, ReplyBacking>>,
    callback: impl FnOnce(
        &Session,
        TrackNamespace,
        SubscribeNamespaceAttributes,
    ) -> Result<Vec<TrackNamespace>, RequestError>,
) {
    begin_reply(backings);

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let session = registry
            .get_or_create(session)
            .ok_or_else(|| RequestError::known(RequestErrorCode::InternalError))?;
        let prefix = unsafe { TrackNamespace::copy_from_raw(prefix) }
            .ok_or_else(|| RequestError::known(RequestErrorCode::InternalError))?;
        let attributes = unsafe { SubscribeNamespaceAttributes::copy_from_raw(attributes) }
            .map_err(|_| RequestError::known(RequestErrorCode::InternalError))?;

        callback(&session, prefix, attributes)
    }))
    .unwrap_or_else(|_| Err(RequestError::known(RequestErrorCode::InternalError)));

    let namespaces = match result {
        Ok(namespaces) => namespaces,
        Err(error) => {
            reject_namespace_reply(reply, error.code().native() as u64, &error, backings);
            return;
        }
    };
    if namespaces.is_empty() {
        let status = unsafe { quicr_sys::quicr_reply_accept_track_namespaces(reply, ptr::null()) };

        if !reply_status_ok(status) {
            reject_internal_error(reply, RequestErrorCode::InternalError.native() as u64);
        }

        return;
    }

    let Some(list) = NativeNamespaceList::new(namespaces) else {
        let error = RequestError::known(RequestErrorCode::InternalError);
        reject_reply(reply, error.code().native() as u64, &error, backings);
        return;
    };

    let list_ptr = list.as_ptr();

    let status = unsafe { quicr_sys::quicr_reply_accept_track_namespaces(reply, list_ptr) };

    if !reply_status_ok(status) {
        reject_internal_error(reply, RequestErrorCode::InternalError.native() as u64);
        return;
    }

    let mut backing = ReplyBacking::default();
    backing.namespace_lists.push(list);
    retire_reply_backing(backing, backings);
}

fn track_status_reply(
    session: *mut quicr_sys::quicr_session_t,
    full_track_name: *const quicr_sys::quicr_full_track_name_t,
    reply: *mut quicr_sys::quicr_reply_t,
    registry: &SessionRegistry,
    backings: &Mutex<HashMap<ThreadId, ReplyBacking>>,
    callback: impl FnOnce(&Session, FullTrackName) -> Result<TrackStatusResponse, RequestError>,
) {
    begin_reply(backings);

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let session = registry
            .get_or_create(session)
            .ok_or_else(|| RequestError::known(RequestErrorCode::InternalError))?;
        let name = unsafe { FullTrackName::copy_from_raw(full_track_name) }
            .ok_or_else(|| RequestError::known(RequestErrorCode::InternalError))?;

        callback(&session, name)
    }))
    .unwrap_or_else(|_| Err(RequestError::known(RequestErrorCode::InternalError)));

    let response = match result {
        Ok(response) => response,
        Err(error) => {
            reject_reply(reply, error.code().native() as u64, &error, backings);
            return;
        }
    };

    let mut backing = ReplyBacking::default();
    let track_extensions = match NativeTrackExtensions::new(&response.track_properties) {
        Ok(track_extensions) => track_extensions,
        Err(_) => {
            reject_internal_error(reply, RequestErrorCode::InternalError.native() as u64);
            return;
        }
    };

    let track_extensions_ptr = track_extensions.as_ptr();
    backing.track_extensions.push(track_extensions);

    let response = quicr_sys::quicr_track_status_response_t {
        has_largest_location: response.largest_location.is_some(),
        largest_location: native_location(response.largest_location.unwrap_or_default()),
        track_extensions: track_extensions_ptr,
    };

    let status = unsafe { quicr_sys::quicr_reply_accept_track_status(reply, &response) };

    if !reply_status_ok(status) {
        reject_internal_error(reply, RequestErrorCode::InternalError.native() as u64);
        return;
    }

    retire_reply_backing(backing, backings);
}

fn complete_subscribe_reply(
    reply: *mut quicr_sys::quicr_reply_t,
    result: Result<SubscribeResponse, RequestError>,
    backings: &Mutex<HashMap<ThreadId, ReplyBacking>>,
) {
    let response = match result {
        Ok(response) => response,
        Err(error) => {
            reject_reply(reply, error.code().native() as u64, &error, backings);
            return;
        }
    };

    let mut backing = ReplyBacking::default();
    let track_extensions = match NativeTrackExtensions::new(&response.track_status.track_properties)
    {
        Ok(track_extensions) => track_extensions,
        Err(_) => {
            reject_internal_error(reply, RequestErrorCode::InternalError.native() as u64);
            return;
        }
    };

    let track_extensions_ptr = track_extensions.as_ptr();
    backing.track_extensions.push(track_extensions);

    let expires_ms = match response
        .expires
        .map(|expires| {
            u64::try_from(expires.as_millis())
                .ok()
                .filter(|millis| *millis <= i64::MAX as u64)
                .ok_or(())
        })
        .transpose()
    {
        Ok(expires) => expires,
        Err(_) => {
            reject_internal_error(reply, RequestErrorCode::InternalError.native() as u64);
            return;
        }
    };

    let response = quicr_sys::quicr_subscribe_response_t {
        track_status: quicr_sys::quicr_track_status_response_t {
            has_largest_location: response.track_status.largest_location.is_some(),
            largest_location: native_location(
                response.track_status.largest_location.unwrap_or_default(),
            ),
            track_extensions: track_extensions_ptr,
        },
        is_publisher_initiated: response.is_publisher_initiated,
        has_expires: expires_ms.is_some(),
        expires_ms: expires_ms.unwrap_or_default(),
    };

    let status = unsafe { quicr_sys::quicr_reply_accept_subscribe(reply, &response) };

    if !reply_status_ok(status) {
        reject_internal_error(reply, RequestErrorCode::InternalError.native() as u64);
        return;
    }

    retire_reply_backing(backing, backings);
}

fn complete_fetch_reply(
    reply: *mut quicr_sys::quicr_reply_t,
    result: Result<FetchResponse, FetchError>,
    backings: &Mutex<HashMap<ThreadId, ReplyBacking>>,
) {
    let response = match result {
        Ok(response) => response,
        Err(error) => {
            reject_reply(reply, error.code().native() as u64, &error, backings);
            return;
        }
    };

    let response = quicr_sys::quicr_fetch_response_t {
        has_largest_location: response.largest_location.is_some(),
        largest_location: native_location(response.largest_location.unwrap_or_default()),
        publisher_default_group_order: response.publisher_default_group_order.native(),
    };

    let status = unsafe { quicr_sys::quicr_reply_accept_fetch(reply, &response) };

    if !reply_status_ok(status) {
        reject_internal_error(reply, FetchErrorCode::InternalError.native() as u64);
    }
}

fn complete_empty_reply(
    reply: *mut quicr_sys::quicr_reply_t,
    result: Result<(), SessionError>,
    backings: &Mutex<HashMap<ThreadId, ReplyBacking>>,
) {
    match result {
        Ok(()) => {
            let status = unsafe { quicr_sys::quicr_reply_accept(reply) };

            if !reply_status_ok(status) {
                reject_internal_error(reply, ErrorCode::InternalError.native());
            }
        }
        Err(error) => {
            reject_reply(reply, error.code().native(), &error, backings);
        }
    }
}

fn complete_setup_reply(
    reply: *mut quicr_sys::quicr_reply_t,
    result: Result<(), SetupError>,
    backings: &Mutex<HashMap<ThreadId, ReplyBacking>>,
) {
    match result {
        Ok(()) => {
            let status = unsafe { quicr_sys::quicr_reply_accept(reply) };

            if !reply_status_ok(status) {
                reject_internal_error(reply, SetupErrorCode::InternalError.native());
            }
        }
        Err(error) => {
            let code = error.code();
            let mut reply_error = SessionError::known(error.code());
            if let Some(reason) = error.reason {
                reply_error = reply_error
                    .with_reason(reason)
                    .expect("SetupError validates its reason");
            }

            reject_reply(reply, code.native(), &reply_error, backings);
        }
    }
}

fn reject_reply<C: ReplyCode>(
    reply: *mut quicr_sys::quicr_reply_t,
    code: u64,
    error: &ReplyError<C>,
    backings: &Mutex<HashMap<ThreadId, ReplyBacking>>,
) {
    let mut backing = ReplyBacking::default();
    let Some((reason, redirect)) = retain_reply_error(error, &mut backing) else {
        reject_internal_error(reply, C::internal_error_code());
        return;
    };

    let status = unsafe { quicr_sys::quicr_reply_reject(reply, code, reason, redirect) };

    if reply_status_ok(status) {
        retire_reply_backing(backing, backings);
    } else {
        reject_internal_error(reply, C::internal_error_code());
    }
}

fn reject_namespace_reply<C: ReplyCode>(
    reply: *mut quicr_sys::quicr_reply_t,
    code: u64,
    error: &ReplyError<C>,
    backings: &Mutex<HashMap<ThreadId, ReplyBacking>>,
) {
    if !namespace_reply_error_valid(error) {
        reject_internal_error(reply, C::internal_error_code());
    } else {
        reject_reply(reply, code, error, backings);
    }
}

fn namespace_reply_error_valid<C: ReplyCode>(error: &ReplyError<C>) -> bool {
    error
        .redirect_details()
        .is_none_or(|redirect| redirect.track_name.is_none())
}

fn reject_internal_error(reply: *mut quicr_sys::quicr_reply_t, code: u64) {
    unsafe {
        quicr_sys::quicr_reply_reject(reply, code, ptr::null(), ptr::null());
    }
}

fn reply_status_ok(status: quicr_sys::quicr_status_t) -> bool {
    status == quicr_sys::QUICR_STATUS_OK as _
}

fn retain_accepted_publish(
    status: quicr_sys::quicr_status_t,
    response: NativePublishResponse,
    accepted_publishes: &AcceptedPublishHandlers,
    session: *mut quicr_sys::quicr_session_t,
    request_id: u64,
    backings: &Mutex<HashMap<ThreadId, ReplyBacking>>,
) -> bool {
    if !reply_status_ok(status) {
        return false;
    }

    accepted_publishes.retain(session, request_id, response.handler());
    let backing = ReplyBacking {
        publish_response: Some(response),
        ..ReplyBacking::default()
    };
    retire_reply_backing(backing, backings);
    true
}

fn retain_reply_error<C>(
    error: &ReplyError<C>,
    backing: &mut ReplyBacking,
) -> Option<(*const std::ffi::c_char, *const quicr_sys::quicr_redirect_t)> {
    let error_backing = NativeReplyErrorBacking::new(error).ok()?;

    let pointers = (error_backing.reason_ptr(), error_backing.redirect_ptr());
    backing.errors.push(error_backing);

    Some(pointers)
}

fn begin_reply(backings: &Mutex<HashMap<ThreadId, ReplyBacking>>) {
    lock(backings).remove(&std::thread::current().id());
}

fn retire_reply_backing(backing: ReplyBacking, backings: &Mutex<HashMap<ThreadId, ReplyBacking>>) {
    if !backing.track_extensions.is_empty()
        || !backing.namespace_lists.is_empty()
        || !backing.errors.is_empty()
        || backing.publish_response.is_some()
    {
        lock(backings).insert(std::thread::current().id(), backing);
    }
}

fn native_location(location: crate::Location) -> quicr_sys::quicr_location_t {
    quicr_sys::quicr_location_t {
        group: location.group,
        object: location.object,
    }
}

#[cfg(test)]
fn native_fetch_error(
    error: FetchError,
    backing: &mut ReplyBacking,
) -> quicr_sys::quicr_fetch_error_t {
    let (reason, redirect) = retain_reply_error(&error, backing).unwrap();
    quicr_sys::quicr_fetch_error_t {
        code: error.code().native(),
        reason,
        redirect,
    }
}

fn byte_span(
    _owner: &quicr_sys::quicr_setup_attributes_t,
    span: quicr_sys::quicr_byte_span_t,
) -> Option<&[u8]> {
    if span.data.is_null() {
        return (span.size == 0).then_some(&[]);
    }

    Some(unsafe { std::slice::from_raw_parts(span.data, span.size) })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        ffi::CStr,
        sync::{Arc, Barrier, Mutex, mpsc},
        thread,
        time::Duration,
    };

    use crate::{
        FetchError, FetchErrorCode, FullTrackName, GroupOrder, PublishResponse, Redirect,
        SubscribeTrackHandler, SubscribeTrackOptions, TrackNamespace,
    };

    use super::{
        AcceptedPublishHandlers, ReplyBacking, SessionOperationError, SessionRegistry,
        SessionStatus, SetupError, begin_reply, goaway, namespace_reply_error_valid,
        native_fetch_error, retain_accepted_publish, retain_reply_error, retire_reply_backing,
    };

    #[test]
    fn registry_reuses_session_state() {
        let registry = SessionRegistry::default();
        let raw = std::ptr::NonNull::<quicr_sys::quicr_session_t>::dangling().as_ptr();

        let first = registry.get_or_create(raw).unwrap();
        let second = registry.get_or_create(raw).unwrap();

        assert!(Arc::ptr_eq(&first.state, &second.state));
    }

    #[test]
    fn removed_registry_session_is_invalidated_before_callback() {
        let registry = SessionRegistry::default();
        let raw = std::ptr::NonNull::<quicr_sys::quicr_session_t>::dangling().as_ptr();
        let retained = registry.get_or_create(raw).unwrap();

        let removed = registry.begin_removal(raw).unwrap();
        assert!(Arc::ptr_eq(&retained.state, &removed.state));
        assert!(retained.is_expired());
        assert!(removed.is_expired());

        let concurrent = registry.get_or_create(raw).unwrap();
        assert!(Arc::ptr_eq(&removed.state, &concurrent.state));
        assert!(concurrent.is_expired());

        registry.finish_removal(&removed);
        let late = registry.get_or_create(raw).unwrap();
        assert!(Arc::ptr_eq(&removed.state, &late.state));
        assert!(late.is_expired());

        let reused = registry.register_new(raw).unwrap();
        assert!(!Arc::ptr_eq(&removed.state, &reused.state));
        assert!(!reused.is_expired());
    }

    #[test]
    fn registry_invalidates_all_sessions() {
        let registry = SessionRegistry::default();
        let first_raw = std::ptr::NonNull::<quicr_sys::quicr_session_t>::dangling().as_ptr();
        let second_raw = (first_raw as usize + 1) as *mut quicr_sys::quicr_session_t;
        let first = registry.get_or_create(first_raw).unwrap();
        let second = registry.get_or_create(second_raw).unwrap();

        registry.invalidate_all();

        assert!(first.is_expired());
        assert!(second.is_expired());
    }

    #[test]
    fn removal_drains_other_threads_before_final_callback() {
        let registry = Arc::new(SessionRegistry::default());
        let raw = std::ptr::NonNull::<quicr_sys::quicr_session_t>::dangling().as_ptr();
        let session = registry.get_or_create(raw).unwrap();
        let retained = session.clone();
        let other_raw = (raw as usize + 1) as *mut quicr_sys::quicr_session_t;
        let other = registry.get_or_create(other_raw).unwrap();

        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let call = thread::spawn(move || {
            session
                .with_raw(|_| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
                .unwrap();
        });
        entered_rx.recv().unwrap();

        let (removed_tx, removed_rx) = mpsc::sync_channel(0);
        let removal_registry = Arc::clone(&registry);
        let raw_key = raw as usize;
        let removal = thread::spawn(move || {
            let removed = removal_registry
                .begin_removal(raw_key as *mut quicr_sys::quicr_session_t)
                .unwrap();
            removed_tx.send(removed).unwrap();
        });

        assert!(removed_rx.recv_timeout(Duration::from_millis(50)).is_err());
        assert!(other.with_raw(|raw| raw == other_raw).unwrap());
        release_tx.send(()).unwrap();
        call.join().unwrap();

        let removed = removed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        removal.join().unwrap();
        assert!(retained.is_expired());
        assert!(removed.is_expired());
        assert!(retained.with_raw(|_| ()).is_err());
        registry.finish_removal(&removed);
    }

    #[test]
    fn nested_same_thread_removal_does_not_deadlock() {
        let registry = SessionRegistry::default();
        let raw = std::ptr::NonNull::<quicr_sys::quicr_session_t>::dangling().as_ptr();
        let session = registry.get_or_create(raw).unwrap();

        let removed = session
            .with_raw(|raw| registry.begin_removal(raw).unwrap())
            .unwrap();

        assert!(removed.is_expired());
        registry.finish_removal(&removed);
    }

    #[test]
    fn closing_session_retains_registration_until_removal_finishes() {
        let registry = SessionRegistry::default();
        let raw = std::ptr::NonNull::<quicr_sys::quicr_session_t>::dangling().as_ptr();
        let session = registry.get_or_create(raw).unwrap();
        let name = FullTrackName::new(TrackNamespace::new(["test"]).unwrap(), "track");
        let handler = SubscribeTrackHandler::new(
            &name,
            SubscribeTrackOptions {
                priority: 127,
                group_order: Some(GroupOrder::Ascending),
                filter: None,
            },
        )
        .unwrap();

        let removed = session
            .with_raw(|raw| {
                assert!(session.reserve_registration().unwrap());
                let removed = registry.begin_removal(raw).unwrap();
                assert!(
                    session
                        .retain_registration(crate::handler::registration(&handler))
                        .is_ok()
                );
                removed
            })
            .unwrap();

        assert_eq!(removed.take_registrations().len(), 1);
        registry.finish_removal(&removed);
    }

    #[test]
    fn shutdown_waits_for_in_flight_session_calls() {
        let registry = Arc::new(SessionRegistry::default());
        let raw = std::ptr::NonNull::<quicr_sys::quicr_session_t>::dangling().as_ptr();
        let session = registry.get_or_create(raw).unwrap();
        let retained = session.clone();

        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let call = thread::spawn(move || {
            session
                .with_raw(|_| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
                .unwrap();
        });

        entered_rx.recv().unwrap();

        let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(0);
        let shutdown_registry = Arc::clone(&registry);
        let shutdown = thread::spawn(move || {
            shutdown_registry.begin_shutdown();
            shutdown_tx.send(()).unwrap();
        });

        assert!(shutdown_rx.recv_timeout(Duration::from_millis(50)).is_err());
        release_tx.send(()).unwrap();
        shutdown_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        call.join().unwrap();
        shutdown.join().unwrap();
        assert!(retained.is_expired());
    }

    #[test]
    fn shutdown_does_not_register_new_session_states() {
        let registry = SessionRegistry::default();
        registry.begin_shutdown();

        let raw = std::ptr::NonNull::<quicr_sys::quicr_session_t>::dangling().as_ptr();
        let first = registry.get_or_create(raw).unwrap();
        let second = registry.get_or_create(raw).unwrap();

        assert!(first.is_expired());
        assert!(second.is_expired());
        assert!(!Arc::ptr_eq(&first.state, &second.state));
    }

    #[test]
    fn maps_known_session_status() {
        assert_eq!(
            SessionStatus::from_native(quicr_sys::QUICR_SESSION_STATUS_READY as _),
            SessionStatus::Ready
        );
    }

    #[test]
    fn rejects_invalid_setup_errors() {
        assert!(SetupError::new(crate::ErrorCode::Redirect).is_err());
        assert!(SetupError::new(crate::ErrorCode::Unknown(9_999)).is_err());
    }

    #[test]
    fn validates_goaway_arguments_before_calling_native_code() {
        let session = std::ptr::NonNull::<quicr_sys::quicr_session_t>::dangling().as_ptr();

        assert_eq!(
            goaway(session, "moq://new\0.invalid", Duration::ZERO, None),
            Err(SessionOperationError::InvalidUri)
        );
        assert_eq!(
            goaway(session, "moq://new.example", Duration::MAX, None),
            Err(SessionOperationError::InvalidArgument)
        );
    }

    #[test]
    fn retains_rich_fetch_error_storage() {
        let mut backing = ReplyBacking::default();
        let native = native_fetch_error(
            FetchError::redirect(
                FetchErrorCode::Redirect,
                Redirect {
                    uri: Some("moq://example.test".into()),
                    ..Redirect::default()
                },
            )
            .unwrap()
            .with_reason("moved")
            .unwrap(),
            &mut backing,
        );

        assert_eq!(
            unsafe { CStr::from_ptr(native.reason) }.to_bytes(),
            b"moved"
        );
        assert_eq!(
            unsafe { CStr::from_ptr((*native.redirect).connect_uri) }.to_bytes(),
            b"moq://example.test"
        );
        assert_eq!(backing.errors.len(), 1);
    }

    #[test]
    fn rejects_track_names_in_namespace_redirects() {
        let valid = FetchError::redirect(
            FetchErrorCode::Redirect,
            Redirect {
                track_namespace: Some(TrackNamespace::new(["moved"]).unwrap()),
                ..Redirect::default()
            },
        )
        .unwrap();
        let invalid = FetchError::redirect(
            FetchErrorCode::Redirect,
            Redirect {
                track_name: Some(b"track".to_vec()),
                ..Redirect::default()
            },
        )
        .unwrap();

        assert!(namespace_reply_error_valid(&valid));
        assert!(!namespace_reply_error_valid(&invalid));
    }

    #[test]
    fn replaces_retired_backing_on_same_thread() {
        let backings = Mutex::new(HashMap::new());

        retire_reply_backing(error_backing("first"), &backings);
        retire_reply_backing(error_backing("second"), &backings);

        let backings = backings.lock().unwrap();
        assert_eq!(backings.len(), 1);

        let backing = backings.get(&thread::current().id()).unwrap();
        let reason = unsafe { CStr::from_ptr(backing.errors[0].reason_ptr()) };
        assert_eq!(reason.to_bytes(), b"second");
    }

    #[test]
    fn separates_retired_backings_across_threads() {
        let backings = Arc::new(Mutex::new(HashMap::new()));
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();

        for reason in ["first", "second"] {
            let backings = Arc::clone(&backings);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                retire_reply_backing(error_backing(reason), &backings);
                barrier.wait();
            }));
        }

        barrier.wait();

        for thread in threads {
            thread.join().unwrap();
        }

        let backings = backings.lock().unwrap();
        assert_eq!(backings.len(), 2);
    }

    #[test]
    fn retains_accepted_publish_until_native_consumption() {
        let name = FullTrackName::new(TrackNamespace::new(["test"]).unwrap(), "track");
        let handler = SubscribeTrackHandler::new(
            &name,
            SubscribeTrackOptions {
                priority: 127,
                group_order: Some(GroupOrder::Ascending),
                filter: None,
            },
        )
        .unwrap();
        let response = PublishResponse::new(handler).into_native().unwrap();
        let accepted = AcceptedPublishHandlers::default();
        let backings = Mutex::new(HashMap::new());
        let session = std::ptr::NonNull::<quicr_sys::quicr_session_t>::dangling().as_ptr();

        assert!(retain_accepted_publish(
            quicr_sys::QUICR_STATUS_OK as _,
            response,
            &accepted,
            session,
            42,
            &backings,
        ));
        assert_eq!(accepted.active.lock().unwrap().len(), 1);
        assert!(
            backings
                .lock()
                .unwrap()
                .get(&thread::current().id())
                .unwrap()
                .publish_response
                .is_some()
        );

        begin_reply(&backings);
        assert!(backings.lock().unwrap().is_empty());

        accepted.retire(session, 42);
        assert!(accepted.active.lock().unwrap().is_empty());
        assert_eq!(accepted.retired.lock().unwrap().len(), 1);

        accepted.retry_retired();
        assert!(accepted.retired.lock().unwrap().is_empty());
    }

    fn error_backing(reason: &str) -> ReplyBacking {
        let error = FetchError::known(FetchErrorCode::InternalError)
            .with_reason(reason)
            .unwrap();
        let mut backing = ReplyBacking::default();
        retain_reply_error(&error, &mut backing).unwrap();
        backing
    }
}
