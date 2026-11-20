// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{
    collections::HashMap,
    ffi::c_void,
    fmt,
    panic::{self, AssertUnwindSafe},
    ptr::{self, NonNull},
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{
    ClientConfig, ClientSessionCallbacks, ConfigError, ServerConfig, ServerSessionCallbacks,
    Session, SessionExpired, TrackHandler,
    handler::{Registration, registration},
    session::{AcceptedPublishHandlers, ClientCallbackState, ServerCallbackState, SessionRegistry},
};

/// Owns libquicr transports, sessions, callback state, and handler registrations.
///
/// A manager must outlive every operation on the [`Session`] handles it creates. Session handles
/// are non-owning: dropping the manager begins shutdown, waits for wrapper-tracked in-flight
/// session calls, unregisters retained handlers where possible, destroys the native manager, and
/// expires all handles. This describes the wrapper's ordering; it does not add guarantees about
/// callbacks or resource release that libquicr itself does not provide.
///
/// The manager is intentionally used through `&mut self` for transport and registration changes.
pub struct SessionManager {
    inner: NonNull<quicr_sys::quicr_session_manager_t>,
    callbacks: Box<CallbackState>,
    #[allow(clippy::vec_box)]
    server_callbacks: Vec<Box<ServerCallbackState>>,
}

/// Receives session-manager lifecycle notifications.
///
/// Notifications may be concurrent and may run while libquicr locks are held. Do not re-enter the
/// same manager or destroy it from a callback. A panic aborts the process because unwinding across
/// the native boundary is invalid.
pub trait SessionManagerCallbacks: Send + Sync + 'static {
    /// Reports a newly accepted server session.
    ///
    /// The supplied handle is owned by the manager and may be cloned for later use. It becomes
    /// expired when the session is removed or manager teardown starts.
    fn on_new_server_session(&self, _session: &Session) {}

    /// Reports removal of a session.
    ///
    /// The handle is already closing and session operations return [`SessionExpired`]. It remains
    /// a tombstone after this callback returns.
    fn on_session_removed(&self, _session: &Session) {}
}

/// Configures and creates a [`SessionManager`].
#[derive(Default)]
pub struct SessionManagerBuilder {
    callbacks: Option<Box<dyn SessionManagerCallbacks>>,
}

struct CallbackState {
    callbacks: Option<Box<dyn SessionManagerCallbacks>>,
    registry: Arc<SessionRegistry>,
    client_callbacks: Mutex<HashMap<usize, Box<ClientCallbackState>>>,
    #[allow(clippy::vec_box)]
    retired_client_callbacks: Mutex<Vec<Box<ClientCallbackState>>>,
    accepted_publishes: Arc<AcceptedPublishHandlers>,
    retired_registrations: Mutex<Vec<Registration>>,
}

impl SessionManager {
    /// Creates a manager with no lifecycle callback receiver.
    pub fn new() -> Result<Self, ManagerCreateError> {
        Self::builder().build()
    }

    /// Alias for [`SessionManager::new`].
    pub fn try_new() -> Result<Self, ManagerCreateError> {
        Self::new()
    }

    /// Returns a builder for configuring a manager.
    pub fn builder() -> SessionManagerBuilder {
        SessionManagerBuilder::default()
    }

    /// Adds a client transport and returns its session handle.
    ///
    /// The manager owns the native transport, callback receiver, and session. `callbacks` may be
    /// invoked concurrently as described by [`ClientSessionCallbacks`]. A successful return means
    /// libquicr accepted creation; it does not guarantee that connection establishment remains
    /// successful.
    pub fn add_transport(
        &mut self,
        config: &ClientConfig,
        callbacks: impl ClientSessionCallbacks,
    ) -> Result<Session, AddTransportError> {
        self.callbacks.collect_retired();
        let native_config = config.to_native().map_err(AddTransportError::Config)?;

        let mut callback_state = ClientCallbackState::new(
            callbacks,
            Arc::clone(&self.callbacks.registry),
            Arc::clone(&self.callbacks.accepted_publishes),
        );
        let native_callbacks = callback_state.native_callbacks();

        let mut session = ptr::null_mut();

        let status = unsafe {
            quicr_sys::quicr_session_manager_add_client(
                self.inner.as_ptr(),
                &native_config.raw,
                &native_callbacks,
                &mut session,
            )
        };
        if status != quicr_sys::QUICR_STATUS_OK as quicr_sys::quicr_status_t {
            return Err(AddTransportError::from_client_status(status));
        }

        let session = NonNull::new(session).ok_or(AddTransportError::InternalError)?;
        let session_handle = self
            .callbacks
            .registry
            .register_new(session.as_ptr())
            .ok_or(AddTransportError::InternalError)?;

        self.callbacks
            .register_client_callbacks(session.as_ptr(), callback_state);

        Ok(session_handle)
    }

    /// Adds a server transport.
    ///
    /// The manager retains `callbacks` for the server's lifetime. A successful return means
    /// libquicr accepted creation; subsequent listening and session behavior remain native
    /// concerns.
    pub fn add_server(
        &mut self,
        config: &ServerConfig,
        callbacks: impl ServerSessionCallbacks,
    ) -> Result<(), AddTransportError> {
        self.callbacks.collect_retired();
        let native_config = config.to_native().map_err(AddTransportError::Config)?;

        let mut callback_state = ServerCallbackState::new(
            callbacks,
            Arc::clone(&self.callbacks.registry),
            Arc::clone(&self.callbacks.accepted_publishes),
        );
        let native_callbacks = callback_state.native_callbacks();

        let status = unsafe {
            quicr_sys::quicr_session_manager_add_server(
                self.inner.as_ptr(),
                &native_config.raw,
                &native_callbacks,
            )
        };
        if status != quicr_sys::QUICR_STATUS_OK as quicr_sys::quicr_status_t {
            return Err(AddTransportError::from_server_status(status));
        }

        self.server_callbacks.push(callback_state);

        Ok(())
    }

    /// Registers a track handler with `session`.
    ///
    /// The manager retains registration state so the native handler remains valid until explicit
    /// removal, session removal, or manager teardown. The caller may retain or drop its own handler
    /// value independently. `session` must belong to this manager; libquicr determines how a
    /// mismatched association is reported.
    pub fn add_handler<H: TrackHandler>(
        &mut self,
        session: &Session,
        handler: &H,
    ) -> Result<(), HandlerRegistrationError> {
        self.callbacks.collect_retired();
        let registration = registration(handler);
        let status = session
            .with_raw(|raw_session| unsafe {
                match session.reserve_registration() {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(HandlerRegistrationError::SessionExpired(SessionExpired));
                    }
                    Err(_) => return Err(HandlerRegistrationError::OutOfMemory),
                }

                let status = match &registration {
                    Registration::Publish(handler) => {
                        quicr_sys::quicr_session_manager_add_publish_track_handler(
                            self.inner.as_ptr(),
                            raw_session,
                            handler.raw,
                        )
                    }
                    Registration::Subscribe(handler) => {
                        quicr_sys::quicr_session_manager_add_subscribe_track_handler(
                            self.inner.as_ptr(),
                            raw_session,
                            handler.raw,
                        )
                    }
                    Registration::Fetch(handler) => {
                        quicr_sys::quicr_session_manager_add_fetch_track_handler(
                            self.inner.as_ptr(),
                            raw_session,
                            handler.raw,
                        )
                    }
                    Registration::PublishNamespace(handler) => {
                        quicr_sys::quicr_session_manager_add_publish_namespace_handler(
                            self.inner.as_ptr(),
                            raw_session,
                            handler.raw,
                        )
                    }
                    Registration::SubscribeNamespace(handler) => {
                        quicr_sys::quicr_session_manager_add_subscribe_namespace_handler(
                            self.inner.as_ptr(),
                            raw_session,
                            handler.raw,
                        )
                    }
                    Registration::TrackStatus(handler) => {
                        quicr_sys::quicr_session_manager_add_track_status_track_handler(
                            self.inner.as_ptr(),
                            raw_session,
                            handler.raw,
                        )
                    }
                };

                if status == quicr_sys::QUICR_STATUS_OK as quicr_sys::quicr_status_t
                    && session.retain_registration(registration).is_err()
                {
                    return Err(HandlerRegistrationError::SessionExpired(SessionExpired));
                }

                Ok(status)
            })
            .map_err(HandlerRegistrationError::SessionExpired)??;

        if status != quicr_sys::QUICR_STATUS_OK as quicr_sys::quicr_status_t {
            return Err(HandlerRegistrationError::from_status(status));
        }

        Ok(())
    }

    /// Removes a track handler registration from `session`.
    ///
    /// On success the manager releases its retained registration. Native busy or not-applied
    /// results leave ownership arranged for a later safe release.
    pub fn remove_handler<H: TrackHandler>(
        &mut self,
        session: &Session,
        handler: &H,
    ) -> Result<(), HandlerRegistrationError> {
        self.callbacks.collect_retired();
        let registration = registration(handler);
        let key = registration.key();
        let status = match session.with_raw(|raw_session| unsafe {
            let status = match &registration {
                Registration::Publish(handler) => {
                    quicr_sys::quicr_session_manager_remove_publish_track_handler(
                        self.inner.as_ptr(),
                        raw_session,
                        handler.raw,
                    )
                }
                Registration::Subscribe(handler) => {
                    quicr_sys::quicr_session_manager_remove_subscribe_track_handler(
                        self.inner.as_ptr(),
                        raw_session,
                        handler.raw,
                    )
                }
                Registration::Fetch(handler) => {
                    quicr_sys::quicr_session_manager_remove_fetch_track_handler(
                        self.inner.as_ptr(),
                        raw_session,
                        handler.raw,
                    )
                }
                Registration::PublishNamespace(handler) => {
                    quicr_sys::quicr_session_manager_remove_publish_namespace_handler(
                        self.inner.as_ptr(),
                        raw_session,
                        handler.raw,
                    )
                }
                Registration::SubscribeNamespace(handler) => {
                    quicr_sys::quicr_session_manager_remove_subscribe_namespace_handler(
                        self.inner.as_ptr(),
                        raw_session,
                        handler.raw,
                    )
                }
                Registration::TrackStatus(handler) => {
                    quicr_sys::quicr_session_manager_remove_track_status_track_handler(
                        self.inner.as_ptr(),
                        raw_session,
                        handler.raw,
                    )
                }
            };

            if status == quicr_sys::QUICR_STATUS_OK as quicr_sys::quicr_status_t {
                session.remove_registration(key);
            }

            status
        }) {
            Ok(status) => status,
            Err(error) => return Err(HandlerRegistrationError::SessionExpired(error)),
        };

        if status != quicr_sys::QUICR_STATUS_OK as quicr_sys::quicr_status_t {
            return Err(HandlerRegistrationError::from_status(status));
        }

        Ok(())
    }
}

impl SessionManagerBuilder {
    /// Installs the receiver for manager lifecycle notifications.
    ///
    /// The manager owns the receiver until teardown. See [`SessionManagerCallbacks`] for callback
    /// concurrency and re-entry restrictions.
    pub fn callbacks(mut self, callbacks: impl SessionManagerCallbacks) -> Self {
        self.callbacks = Some(Box::new(callbacks));
        self
    }

    /// Builds the configured manager.
    pub fn build(self) -> Result<SessionManager, ManagerCreateError> {
        self.try_build()
    }

    /// Alias for [`SessionManagerBuilder::build`].
    pub fn try_build(self) -> Result<SessionManager, ManagerCreateError> {
        let registry = Arc::new(SessionRegistry::default());
        let accepted_publishes = Arc::new(AcceptedPublishHandlers::default());
        let mut callback_state = Box::new(CallbackState {
            callbacks: self.callbacks,
            registry,
            client_callbacks: Mutex::new(HashMap::new()),
            retired_client_callbacks: Mutex::new(Vec::new()),
            accepted_publishes,
            retired_registrations: Mutex::new(Vec::new()),
        });
        let native_callbacks = quicr_sys::quicr_session_manager_callbacks_t {
            user_data: (&mut *callback_state as *mut CallbackState).cast(),
            new_server_session: Some(new_server_session),
            session_removed: Some(session_removed),
        };

        let mut manager = ptr::null_mut();

        let status =
            unsafe { quicr_sys::quicr_session_manager_create(&native_callbacks, &mut manager) };
        if status != quicr_sys::QUICR_STATUS_OK as quicr_sys::quicr_status_t {
            return Err(ManagerCreateError::from_status(status));
        }

        let inner = NonNull::new(manager).ok_or(ManagerCreateError::InternalError)?;

        Ok(SessionManager {
            inner,
            callbacks: callback_state,
            server_callbacks: Vec::new(),
        })
    }
}

impl CallbackState {
    fn retire_client_callbacks(&self, session: *mut quicr_sys::quicr_session_t) {
        if let Some(callbacks) = lock(&self.client_callbacks).remove(&(session as usize)) {
            lock(&self.retired_client_callbacks).push(callbacks);
        }
    }

    fn collect_retired(&self) {
        lock(&self.retired_client_callbacks).clear();
        self.accepted_publishes.retry_retired();
        self.retry_retired_registrations();
    }

    fn invalidate_all(&self) {
        self.registry.invalidate_all();
        lock(&self.client_callbacks).clear();
        lock(&self.retired_client_callbacks).clear();
        self.accepted_publishes.clear();
    }

    fn register_client_callbacks(
        &self,
        session: *mut quicr_sys::quicr_session_t,
        callbacks: Box<ClientCallbackState>,
    ) {
        lock(&self.client_callbacks).insert(session as usize, callbacks);
    }

    fn begin_session_removal(&self, raw: *mut quicr_sys::quicr_session_t) -> Option<Session> {
        let session = self.registry.begin_removal(raw)?;
        lock(&self.retired_registrations).extend(session.take_registrations());
        Some(session)
    }

    fn retry_retired_registrations(&self) {
        let registrations = std::mem::take(&mut *lock(&self.retired_registrations));
        let mut retained = Vec::new();

        for registration in registrations {
            if let Err(registration) = registration.try_release() {
                retained.push(registration);
            }
        }

        lock(&self.retired_registrations).extend(retained);
    }

    fn retire_registration(&self, registration: Registration) {
        lock(&self.retired_registrations).push(registration);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
/// Failure to create a [`SessionManager`].
pub enum ManagerCreateError {
    /// libquicr rejected manager creation arguments.
    InvalidArgument,
    /// Native allocation failed.
    OutOfMemory,
    /// Manager creation failed for another native reason.
    InternalError,
}

impl ManagerCreateError {
    fn from_status(status: quicr_sys::quicr_status_t) -> Self {
        match status as u32 {
            quicr_sys::QUICR_STATUS_INVALID_ARGUMENT => Self::InvalidArgument,
            quicr_sys::QUICR_STATUS_OUT_OF_MEMORY => Self::OutOfMemory,
            _ => Self::InternalError,
        }
    }
}

impl fmt::Display for ManagerCreateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "invalid session manager configuration",
            Self::OutOfMemory => "session manager creation ran out of memory",
            Self::InternalError => "session manager creation failed",
        })
    }
}

impl std::error::Error for ManagerCreateError {}

#[derive(Debug, Eq, PartialEq)]
/// Failure while adding a client or server transport.
pub enum AddTransportError {
    /// Conversion of the supplied transport configuration failed.
    Config(ConfigError),
    /// libquicr rejected a transport argument.
    InvalidArgument,
    /// Native allocation failed.
    OutOfMemory,
    /// Transport creation failed for an otherwise uncategorized native reason.
    InternalError,
    /// The client transport could not establish its initial connection.
    ConnectionFailed,
}

impl AddTransportError {
    fn from_client_status(status: quicr_sys::quicr_status_t) -> Self {
        match status as u32 {
            quicr_sys::QUICR_STATUS_INVALID_ARGUMENT => Self::InvalidArgument,
            quicr_sys::QUICR_STATUS_OUT_OF_MEMORY => Self::OutOfMemory,
            quicr_sys::QUICR_STATUS_INTERNAL_ERROR => Self::ConnectionFailed,
            _ => Self::InternalError,
        }
    }

    fn from_server_status(status: quicr_sys::quicr_status_t) -> Self {
        match status as u32 {
            quicr_sys::QUICR_STATUS_INVALID_ARGUMENT => Self::InvalidArgument,
            quicr_sys::QUICR_STATUS_OUT_OF_MEMORY => Self::OutOfMemory,
            _ => Self::InternalError,
        }
    }
}

impl fmt::Display for AddTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => error.fmt(formatter),
            Self::InvalidArgument => formatter.write_str("invalid transport configuration"),
            Self::OutOfMemory => formatter.write_str("transport creation ran out of memory"),
            Self::InternalError => formatter.write_str("transport creation failed"),
            Self::ConnectionFailed => formatter.write_str("client transport failed to connect"),
        }
    }
}

impl std::error::Error for AddTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
/// Failure while adding or removing a session handler.
pub enum HandlerRegistrationError {
    /// The session is expired or manager teardown has begun.
    SessionExpired(SessionExpired),
    /// libquicr rejected the manager, session, or handler association.
    InvalidArgument,
    /// Allocation for registration bookkeeping failed.
    OutOfMemory,
    /// Registration failed for an otherwise uncategorized native reason.
    InternalError,
    /// The session or handler registration was not found.
    NotFound,
    /// The native API did not apply the requested registration change.
    NotApplied,
}

impl HandlerRegistrationError {
    fn from_status(status: quicr_sys::quicr_status_t) -> Self {
        match status as u32 {
            quicr_sys::QUICR_STATUS_INVALID_ARGUMENT => Self::InvalidArgument,
            quicr_sys::QUICR_STATUS_OUT_OF_MEMORY => Self::OutOfMemory,
            quicr_sys::QUICR_STATUS_NOT_FOUND => Self::NotFound,
            quicr_sys::QUICR_STATUS_NOT_APPLIED => Self::NotApplied,
            _ => Self::InternalError,
        }
    }
}

impl fmt::Display for HandlerRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionExpired(error) => error.fmt(formatter),
            Self::InvalidArgument => formatter.write_str("invalid track handler registration"),
            Self::OutOfMemory => {
                formatter.write_str("track handler registration ran out of memory")
            }
            Self::InternalError => formatter.write_str("track handler registration failed"),
            Self::NotFound => formatter.write_str("session or track handler was not found"),
            Self::NotApplied => formatter.write_str("track handler registration was not applied"),
        }
    }
}

impl std::error::Error for HandlerRegistrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SessionExpired(error) => Some(error),
            _ => None,
        }
    }
}

impl Drop for SessionManager {
    fn drop(&mut self) {
        self.callbacks.registry.begin_shutdown();

        let mut deferred_registrations = Vec::new();
        for (session, registrations) in self.callbacks.registry.take_registrations() {
            for registration in registrations {
                let status = unsafe {
                    remove_registration(
                        self.inner.as_ptr(),
                        session as *mut quicr_sys::quicr_session_t,
                        &registration,
                    )
                };
                if status != quicr_sys::QUICR_STATUS_OK as quicr_sys::quicr_status_t {
                    deferred_registrations.push(registration);
                } else if let Err(registration) = registration.try_release() {
                    self.callbacks.retire_registration(registration);
                }
            }
        }

        let accepted_publishes = self.callbacks.accepted_publishes.take_active();
        for (session, handler) in &accepted_publishes {
            unsafe {
                quicr_sys::quicr_session_manager_remove_subscribe_track_handler(
                    self.inner.as_ptr(),
                    *session as *mut quicr_sys::quicr_session_t,
                    handler.inner.raw,
                );
            }
        }
        self.callbacks.accepted_publishes.retry_retired();
        self.callbacks.retry_retired_registrations();

        unsafe { quicr_sys::quicr_session_manager_destroy(self.inner.as_ptr()) };
        for registration in deferred_registrations {
            if let Err(registration) = registration.try_release() {
                self.callbacks.retire_registration(registration);
            }
        }
        drop(accepted_publishes);
        self.callbacks.accepted_publishes.retry_retired();
        self.callbacks.retry_retired_registrations();
        self.callbacks.invalidate_all();
    }
}

unsafe fn remove_registration(
    manager: *mut quicr_sys::quicr_session_manager_t,
    session: *mut quicr_sys::quicr_session_t,
    registration: &Registration,
) -> quicr_sys::quicr_status_t {
    unsafe {
        match registration {
            Registration::Publish(handler) => {
                quicr_sys::quicr_session_manager_remove_publish_track_handler(
                    manager,
                    session,
                    handler.raw,
                )
            }
            Registration::Subscribe(handler) => {
                quicr_sys::quicr_session_manager_remove_subscribe_track_handler(
                    manager,
                    session,
                    handler.raw,
                )
            }
            Registration::Fetch(handler) => {
                quicr_sys::quicr_session_manager_remove_fetch_track_handler(
                    manager,
                    session,
                    handler.raw,
                )
            }
            Registration::PublishNamespace(handler) => {
                quicr_sys::quicr_session_manager_remove_publish_namespace_handler(
                    manager,
                    session,
                    handler.raw,
                )
            }
            Registration::SubscribeNamespace(handler) => {
                quicr_sys::quicr_session_manager_remove_subscribe_namespace_handler(
                    manager,
                    session,
                    handler.raw,
                )
            }
            Registration::TrackStatus(handler) => {
                quicr_sys::quicr_session_manager_remove_track_status_track_handler(
                    manager,
                    session,
                    handler.raw,
                )
            }
        }
    }
}

unsafe extern "C" fn new_server_session(
    _manager: *mut quicr_sys::quicr_session_manager_t,
    session: *mut quicr_sys::quicr_session_t,
    user_data: *mut c_void,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let callback_state = unsafe { &*user_data.cast::<CallbackState>() };
        let raw = NonNull::new(session)
            .expect("libquicr invoked a new-session callback with a null session");
        let session = callback_state
            .registry
            .register_new(raw.as_ptr())
            .expect("non-null session failed to enter the session registry");

        if let Some(callbacks) = callback_state.callbacks.as_deref() {
            callbacks.on_new_server_session(&session);
        }
    }));

    if result.is_err() {
        std::process::abort();
    }
}

unsafe extern "C" fn session_removed(
    _manager: *mut quicr_sys::quicr_session_manager_t,
    session: *mut quicr_sys::quicr_session_t,
    user_data: *mut c_void,
) {
    let state = unsafe { &*user_data.cast::<CallbackState>() };
    state.accepted_publishes.retry_retired();

    let session_handle = panic::catch_unwind(AssertUnwindSafe(|| {
        state
            .begin_session_removal(session)
            .expect("libquicr invoked a removed-session callback with a null session")
    }))
    .unwrap_or_else(|_| std::process::abort());

    if !state.registry.is_shutting_down() {
        state
            .accepted_publishes
            .retire_session(session_handle.key());
        state.retire_client_callbacks(session);
    }

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        if let Some(callbacks) = state.callbacks.as_deref() {
            callbacks.on_session_removed(&session_handle);
        }
    }));

    state.registry.finish_removal(&session_handle);

    if result.is_err() {
        std::process::abort();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use super::{
        AcceptedPublishHandlers, AddTransportError, CallbackState, ManagerCreateError,
        SessionManager, SessionManagerCallbacks,
    };
    use crate::{
        ClientConfig, FullTrackName, GroupOrder, SubscribeTrackHandler, SubscribeTrackOptions,
        TrackNamespace, handler::registration, session::SessionRegistry,
    };

    struct Callbacks;

    impl SessionManagerCallbacks for Callbacks {}

    #[test]
    fn creates_and_destroys_manager() {
        let _manager = SessionManager::new().unwrap();
    }

    #[test]
    fn creates_and_destroys_manager_with_callbacks() {
        let _manager = SessionManager::builder()
            .callbacks(Callbacks)
            .build()
            .unwrap();
    }

    #[test]
    fn fallible_manager_creation_succeeds() {
        let _manager = SessionManager::try_new().unwrap();
        let _manager = SessionManager::builder()
            .callbacks(Callbacks)
            .try_build()
            .unwrap();
    }

    #[test]
    fn categorizes_manager_and_transport_failures() {
        assert_eq!(
            ManagerCreateError::from_status(quicr_sys::QUICR_STATUS_OUT_OF_MEMORY as _),
            ManagerCreateError::OutOfMemory
        );
        assert_eq!(
            AddTransportError::from_client_status(quicr_sys::QUICR_STATUS_INVALID_ARGUMENT as _),
            AddTransportError::InvalidArgument
        );
        assert_eq!(
            AddTransportError::from_client_status(quicr_sys::QUICR_STATUS_OUT_OF_MEMORY as _),
            AddTransportError::OutOfMemory
        );
        assert_eq!(
            AddTransportError::from_client_status(quicr_sys::QUICR_STATUS_INTERNAL_ERROR as _),
            AddTransportError::ConnectionFailed
        );
        assert_eq!(
            AddTransportError::from_server_status(quicr_sys::QUICR_STATUS_INTERNAL_ERROR as _),
            AddTransportError::InternalError
        );
    }

    #[test]
    fn reports_client_connection_failure() {
        let mut manager = SessionManager::new().unwrap();
        let config = ClientConfig {
            connect_uri: "not-a-moq-uri".into(),
            ..ClientConfig::default()
        };

        assert!(matches!(
            manager.add_transport(&config, ()),
            Err(AddTransportError::ConnectionFailed)
        ));
    }

    #[test]
    fn session_removal_releases_registered_handlers() {
        let registry = Arc::new(SessionRegistry::default());
        let callbacks = CallbackState {
            callbacks: None,
            registry: Arc::clone(&registry),
            client_callbacks: Mutex::new(HashMap::new()),
            retired_client_callbacks: Mutex::new(Vec::new()),
            accepted_publishes: Arc::new(AcceptedPublishHandlers::default()),
            retired_registrations: Mutex::new(Vec::new()),
        };

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
        let inner = Arc::clone(&handler.inner);

        assert!(session.reserve_registration().unwrap());
        assert!(session.retain_registration(registration(&handler)).is_ok());
        assert_eq!(Arc::strong_count(&inner), 3);

        callbacks.begin_session_removal(raw).unwrap();
        assert_eq!(Arc::strong_count(&inner), 3);
        callbacks.retry_retired_registrations();
        assert_eq!(Arc::strong_count(&inner), 2);
    }
}
