// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{
    ffi::c_void,
    marker::PhantomData,
    mem::ManuallyDrop,
    ptr::{self, NonNull},
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{Filter, TrackNamespace};

use super::{
    CloseError, HandlerCreateError, HandlerOperationError, NoCallbacks, OK, PublishInner,
    PublishTrackHandler, abort_on_panic, operation,
};

/// The current state of a [`PublishNamespaceHandler`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PublishNamespaceStatus {
    /// The namespace publication is active.
    Ok,
    /// No usable session connection is available.
    NotConnected,
    /// The namespace is not published.
    NotPublished,
    /// A response from the peer is pending.
    PendingResponse,
    /// The peer rejected authorization for the publication.
    NotAuthorized,
    /// A publication-done message is being sent.
    SendingDone,
    /// The handler encountered an unspecified error.
    Error,
    /// A status value not known by this crate version.
    Unknown(u8),
}

impl PublishNamespaceStatus {
    fn from_native(value: quicr_sys::quicr_publish_namespace_handler_status_t) -> Self {
        use quicr_sys::*;
        match value {
            value if value == QUICR_PUBLISH_NAMESPACE_HANDLER_STATUS_OK as _ => Self::Ok,
            value if value == QUICR_PUBLISH_NAMESPACE_HANDLER_STATUS_NOT_CONNECTED as _ => {
                Self::NotConnected
            }
            value if value == QUICR_PUBLISH_NAMESPACE_HANDLER_STATUS_NOT_PUBLISHED as _ => {
                Self::NotPublished
            }
            value if value == QUICR_PUBLISH_NAMESPACE_HANDLER_STATUS_PENDING_RESPONSE as _ => {
                Self::PendingResponse
            }
            value if value == QUICR_PUBLISH_NAMESPACE_HANDLER_STATUS_NOT_AUTHORIZED as _ => {
                Self::NotAuthorized
            }
            value if value == QUICR_PUBLISH_NAMESPACE_HANDLER_STATUS_SENDING_DONE as _ => {
                Self::SendingDone
            }
            value if value == QUICR_PUBLISH_NAMESPACE_HANDLER_STATUS_ERROR as _ => Self::Error,
            value => Self::Unknown(value),
        }
    }
}

/// Receives publish-namespace notifications.
///
/// Notifications may be concurrent and may run synchronously while native locks are held. Do not
/// re-enter operations on the same handler or destroy it from a callback. A panic aborts the
/// process because unwinding across the native boundary is invalid.
pub trait PublishNamespaceCallbacks: Send + Sync + 'static {
    /// Reports a transition in the namespace publication state.
    fn status_changed(&self, _status: PublishNamespaceStatus) {}
}

impl PublishNamespaceCallbacks for NoCallbacks {}

struct PublishCallbackState {
    callbacks: Box<dyn PublishNamespaceCallbacks>,
}

/// An owning RAII handle for publishing tracks under a namespace prefix.
///
/// Construction is detached; register the handler with
/// [`SessionManager::add_handler`](crate::SessionManager::add_handler). Tracks added with
/// [`Self::publish_track`] are retained by this handler until explicitly unpublished or until
/// close/drop removes them. Remove the namespace handler from its session before explicit close.
pub struct PublishNamespaceHandler {
    pub(crate) inner: Arc<PublishNamespaceInner>,
}

/// Internal shared ownership for a native publish-namespace handler.
#[doc(hidden)]
pub struct PublishNamespaceInner {
    /// The native handler pointer.
    pub raw: *mut quicr_sys::quicr_publish_namespace_handler_t,
    callbacks: ManuallyDrop<Box<PublishCallbackState>>,
    tracks: Mutex<Vec<Arc<PublishInner>>>,
    destroyed: bool,
}

unsafe impl Send for PublishNamespaceInner {}
unsafe impl Sync for PublishNamespaceInner {}

impl PublishNamespaceHandler {
    /// Creates a detached namespace publisher without callbacks.
    pub fn new(prefix: &TrackNamespace) -> Result<Self, HandlerCreateError> {
        Self::new_with_callbacks(prefix, NoCallbacks)
    }

    /// Creates a detached namespace publisher with callbacks.
    ///
    /// Callback delivery may begin synchronously when the handler is later registered; see
    /// [`PublishNamespaceCallbacks`] for callback restrictions.
    pub fn new_with_callbacks(
        prefix: &TrackNamespace,
        callbacks: impl PublishNamespaceCallbacks,
    ) -> Result<Self, HandlerCreateError> {
        let prefix = prefix
            .to_native()
            .map_err(|error| HandlerCreateError::from_status(error.status()))?;

        let mut callback_state = Box::new(PublishCallbackState {
            callbacks: Box::new(callbacks),
        });
        let native_callbacks = quicr_sys::quicr_publish_namespace_handler_callbacks_t {
            user_data: (&mut *callback_state as *mut PublishCallbackState).cast(),
            status_changed: Some(publish_status_changed),
        };

        let mut raw = ptr::null_mut();
        let status = unsafe {
            quicr_sys::quicr_publish_namespace_handler_create(
                &native_callbacks,
                prefix.raw,
                &mut raw,
            )
        };
        if status != OK {
            return Err(HandlerCreateError::from_status(status));
        }
        if raw.is_null() {
            return Err(HandlerCreateError::InternalError);
        }

        Ok(Self {
            inner: Arc::new(PublishNamespaceInner {
                raw,
                callbacks: ManuallyDrop::new(callback_state),
                tracks: Mutex::new(Vec::new()),
                destroyed: false,
            }),
        })
    }

    /// Unpublishes retained tracks and explicitly destroys the native handler.
    ///
    /// A session registration must first be removed. If unpublishing a track or destroying the
    /// handler fails, [`CloseError`] preserves the handler and remaining retained tracks for
    /// retry. Dropping performs the same cleanup on a best-effort basis.
    pub fn close(self) -> Result<(), CloseError<Self>> {
        let inner = match Arc::try_unwrap(self.inner) {
            Ok(inner) => inner,
            Err(inner) => {
                return Err(CloseError::new(Self { inner }, HandlerOperationError::Busy));
            }
        };

        match inner.try_destroy() {
            Ok(()) => Ok(()),
            Err((inner, error)) => Err(CloseError::new(
                Self {
                    inner: Arc::new(inner),
                },
                error,
            )),
        }
    }

    /// Explicitly closes the handler, returning it unchanged on failure.
    ///
    /// Use [`Self::close`] when the failure reason is needed.
    pub fn try_close(self) -> Result<(), Self> {
        self.close().map_err(CloseError::into_handler)
    }

    /// Returns the namespace publisher's current state.
    pub fn status(&self) -> Result<PublishNamespaceStatus, HandlerOperationError> {
        let mut status = 0;
        let result = unsafe {
            quicr_sys::quicr_publish_namespace_handler_get_status(self.inner.raw, &mut status)
        };

        if result != OK {
            return Err(HandlerOperationError::from_status(result));
        }

        Ok(PublishNamespaceStatus::from_native(status))
    }

    /// Publishes `track` through this namespace handler.
    ///
    /// On success this handler retains shared ownership of `track`, keeping its native resource
    /// alive even if the caller drops its handle. Call [`Self::unpublish_track`] before explicitly
    /// closing the track; closing this namespace also unpublishes all retained tracks.
    pub fn publish_track(
        &mut self,
        track: &PublishTrackHandler,
    ) -> Result<(), HandlerOperationError> {
        let status = unsafe {
            quicr_sys::quicr_publish_namespace_handler_publish_track(
                self.inner.raw,
                track.inner.raw,
            )
        };
        operation(status)?;

        let mut tracks = lock(&self.inner.tracks);
        if !tracks
            .iter()
            .any(|existing| Arc::ptr_eq(existing, &track.inner))
        {
            tracks.push(Arc::clone(&track.inner));
        }

        Ok(())
    }

    /// Stops publishing `track` through this namespace handler.
    ///
    /// On success the shared ownership retained by [`Self::publish_track`] is released. The track
    /// handler itself remains valid and may be reused or explicitly closed.
    pub fn unpublish_track(
        &mut self,
        track: &PublishTrackHandler,
    ) -> Result<(), HandlerOperationError> {
        let status = unsafe {
            quicr_sys::quicr_publish_namespace_handler_unpublish_track(
                self.inner.raw,
                track.inner.raw,
            )
        };
        operation(status)?;

        let mut tracks = lock(&self.inner.tracks);
        if let Some(index) = tracks
            .iter()
            .position(|existing| Arc::ptr_eq(existing, &track.inner))
        {
            tracks.swap_remove(index);
        }

        Ok(())
    }
}

impl Drop for PublishNamespaceInner {
    fn drop(&mut self) {
        if self.destroyed {
            return;
        }
        unsafe { quicr_sys::quicr_publish_namespace_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
    }
}

impl PublishNamespaceInner {
    fn try_destroy(mut self) -> Result<(), (Self, HandlerOperationError)> {
        unsafe { quicr_sys::quicr_publish_namespace_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
        Ok(())
    }
}

unsafe extern "C" fn publish_status_changed(
    _handler: *mut quicr_sys::quicr_publish_namespace_handler_t,
    status: quicr_sys::quicr_publish_namespace_handler_status_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let state = unsafe { &*user_data.cast::<PublishCallbackState>() };
        state
            .callbacks
            .status_changed(PublishNamespaceStatus::from_native(status));
    });
}

/// Selects which names a namespace subscription reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SubscribeNamespaceMode {
    /// Report matching child namespaces.
    Namespaces,
    /// Report namespaces containing matching tracks.
    Tracks,
}

impl SubscribeNamespaceMode {
    fn native(self) -> quicr_sys::quicr_subscribe_namespace_mode_t {
        match self {
            Self::Namespaces => quicr_sys::QUICR_SUBSCRIBE_NAMESPACE_MODE_NAMESPACES as _,
            Self::Tracks => quicr_sys::QUICR_SUBSCRIBE_NAMESPACE_MODE_TRACKS as _,
        }
    }
}

/// The current state of a [`SubscribeNamespaceHandler`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SubscribeNamespaceStatus {
    /// The namespace subscription is active.
    Ok,
    /// The namespace is not subscribed.
    NotSubscribed,
    /// The handler encountered an unspecified error.
    Error,
    /// A status value not known by this crate version.
    Unknown(u8),
}

impl SubscribeNamespaceStatus {
    fn from_native(value: quicr_sys::quicr_subscribe_namespace_handler_status_t) -> Self {
        match value {
            value if value == quicr_sys::QUICR_SUBSCRIBE_NAMESPACE_HANDLER_STATUS_OK as _ => {
                Self::Ok
            }
            value
                if value
                    == quicr_sys::QUICR_SUBSCRIBE_NAMESPACE_HANDLER_STATUS_NOT_SUBSCRIBED as _ =>
            {
                Self::NotSubscribed
            }
            value if value == quicr_sys::QUICR_SUBSCRIBE_NAMESPACE_HANDLER_STATUS_ERROR as _ => {
                Self::Error
            }
            value => Self::Unknown(value),
        }
    }
}

/// Receives subscribe-namespace notifications.
///
/// Notifications may be concurrent and may run synchronously while native locks are held. Do not
/// re-enter operations on the same handler or destroy it from a callback. A panic aborts the
/// process because unwinding across the native boundary is invalid.
pub trait SubscribeNamespaceCallbacks: Send + Sync + 'static {
    /// Reports a transition in the namespace subscription state.
    fn status_changed(&self, _status: SubscribeNamespaceStatus) {}
    /// Reports a matching namespace.
    ///
    /// The namespace is copied into a Rust-owned value before this callback is invoked.
    fn namespace_received(&self, _track_namespace: TrackNamespace) {}
    /// Reports that the peer has finished publishing a previously reported namespace.
    ///
    /// The namespace is copied into a Rust-owned value before this callback is invoked.
    fn namespace_done(&self, _track_namespace: TrackNamespace) {}
}

impl SubscribeNamespaceCallbacks for NoCallbacks {}

/// Initial settings for a [`SubscribeNamespaceHandler`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscribeNamespaceOptions {
    /// Whether callbacks report namespaces or track-bearing namespaces.
    pub mode: SubscribeNamespaceMode,
    /// An optional filter applied to the subscription.
    pub filter: Option<Filter>,
}

struct SubscribeCallbackState {
    callbacks: Box<dyn SubscribeNamespaceCallbacks>,
}

/// An owning RAII handle for subscribing to a namespace prefix.
///
/// Construction is detached; register the handler with
/// [`SessionManager::add_handler`](crate::SessionManager::add_handler). The session retains shared
/// ownership until removal, so remove it before calling [`Self::close`].
pub struct SubscribeNamespaceHandler {
    pub(crate) inner: Arc<SubscribeNamespaceInner>,
}

/// A non-owning callback-scoped view of a subscribe-namespace handler.
///
/// This view does not register, remove, close, or extend the lifetime of the underlying handler.
/// It is valid only for the lifetime supplied by the API that created it.
pub struct SubscribeNamespaceHandlerRef<'a> {
    raw: NonNull<quicr_sys::quicr_subscribe_namespace_handler_t>,
    marker: PhantomData<&'a quicr_sys::quicr_subscribe_namespace_handler_t>,
}

impl<'a> SubscribeNamespaceHandlerRef<'a> {
    pub(crate) unsafe fn from_raw(
        raw: *const quicr_sys::quicr_subscribe_namespace_handler_t,
    ) -> Option<Self> {
        NonNull::new(raw.cast_mut()).map(|raw| Self {
            raw,
            marker: PhantomData,
        })
    }

    /// Returns the referenced handler's current state.
    pub fn status(&self) -> Result<SubscribeNamespaceStatus, HandlerOperationError> {
        let mut status = 0;
        let result = unsafe {
            quicr_sys::quicr_subscribe_namespace_handler_get_status(self.raw.as_ptr(), &mut status)
        };
        if result != OK {
            return Err(HandlerOperationError::from_status(result));
        }

        Ok(SubscribeNamespaceStatus::from_native(status))
    }
}

/// Internal shared ownership for a native subscribe-namespace handler.
#[doc(hidden)]
pub struct SubscribeNamespaceInner {
    /// The native handler pointer.
    pub raw: *mut quicr_sys::quicr_subscribe_namespace_handler_t,
    callbacks: ManuallyDrop<Box<SubscribeCallbackState>>,
    destroyed: bool,
}

unsafe impl Send for SubscribeNamespaceInner {}
unsafe impl Sync for SubscribeNamespaceInner {}

impl SubscribeNamespaceHandler {
    /// Creates a detached namespace subscriber without callbacks.
    pub fn new(
        prefix: &TrackNamespace,
        options: SubscribeNamespaceOptions,
    ) -> Result<Self, HandlerCreateError> {
        Self::new_with_callbacks(prefix, options, NoCallbacks)
    }

    /// Creates a detached namespace subscriber with callbacks.
    ///
    /// Callback delivery may begin synchronously when the handler is later registered; see
    /// [`SubscribeNamespaceCallbacks`] for concurrency, re-entry, ownership, and panic
    /// constraints.
    pub fn new_with_callbacks(
        prefix: &TrackNamespace,
        options: SubscribeNamespaceOptions,
        callbacks: impl SubscribeNamespaceCallbacks,
    ) -> Result<Self, HandlerCreateError> {
        let SubscribeNamespaceOptions { mode, filter } = options;
        let prefix = prefix
            .to_native()
            .map_err(|error| HandlerCreateError::from_status(error.status()))?;
        let filter = filter.map(Filter::native);

        let mut callback_state = Box::new(SubscribeCallbackState {
            callbacks: Box::new(callbacks),
        });
        let native_callbacks = quicr_sys::quicr_subscribe_namespace_handler_callbacks_t {
            user_data: (&mut *callback_state as *mut SubscribeCallbackState).cast(),
            status_changed: Some(subscribe_status_changed),
            namespace_received: Some(namespace_received),
            namespace_done_received: Some(namespace_done_received),
        };

        let mut raw = ptr::null_mut();
        let status = unsafe {
            quicr_sys::quicr_subscribe_namespace_handler_create(
                &native_callbacks,
                prefix.raw,
                mode.native(),
                filter.as_ref().map_or(ptr::null(), |filter| filter),
                &mut raw,
            )
        };
        if status != OK {
            return Err(HandlerCreateError::from_status(status));
        }
        if raw.is_null() {
            return Err(HandlerCreateError::InternalError);
        }

        Ok(Self {
            inner: Arc::new(SubscribeNamespaceInner {
                raw,
                callbacks: ManuallyDrop::new(callback_state),
                destroyed: false,
            }),
        })
    }

    /// Explicitly destroys the native handler.
    ///
    /// This fails with [`HandlerOperationError::Busy`] while a session registration or other
    /// shared owner remains. On failure, [`CloseError`] preserves the handler for removal and
    /// retry. Dropping is the best-effort RAII alternative.
    pub fn close(self) -> Result<(), CloseError<Self>> {
        let inner = match Arc::try_unwrap(self.inner) {
            Ok(inner) => inner,
            Err(inner) => {
                return Err(CloseError::new(Self { inner }, HandlerOperationError::Busy));
            }
        };

        match inner.try_destroy() {
            Ok(()) => Ok(()),
            Err((inner, error)) => Err(CloseError::new(
                Self {
                    inner: Arc::new(inner),
                },
                error,
            )),
        }
    }

    /// Explicitly destroys the native handler, returning it unchanged on failure.
    ///
    /// Use [`Self::close`] when the failure reason is needed.
    pub fn try_close(self) -> Result<(), Self> {
        self.close().map_err(CloseError::into_handler)
    }

    /// Returns the namespace subscriber's current state.
    pub fn status(&self) -> Result<SubscribeNamespaceStatus, HandlerOperationError> {
        let mut status = 0;
        let result = unsafe {
            quicr_sys::quicr_subscribe_namespace_handler_get_status(self.inner.raw, &mut status)
        };
        if result != OK {
            return Err(HandlerOperationError::from_status(result));
        }
        Ok(SubscribeNamespaceStatus::from_native(status))
    }
}

impl Drop for SubscribeNamespaceInner {
    fn drop(&mut self) {
        if self.destroyed {
            return;
        }
        unsafe { quicr_sys::quicr_subscribe_namespace_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
    }
}

impl SubscribeNamespaceInner {
    fn try_destroy(mut self) -> Result<(), (Self, HandlerOperationError)> {
        unsafe { quicr_sys::quicr_subscribe_namespace_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
        Ok(())
    }
}

unsafe extern "C" fn subscribe_status_changed(
    _handler: *mut quicr_sys::quicr_subscribe_namespace_handler_t,
    status: quicr_sys::quicr_subscribe_namespace_handler_status_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let state = unsafe { &*user_data.cast::<SubscribeCallbackState>() };
        state
            .callbacks
            .status_changed(SubscribeNamespaceStatus::from_native(status));
    });
}

unsafe extern "C" fn namespace_received(
    _handler: *mut quicr_sys::quicr_subscribe_namespace_handler_t,
    track_namespace: *const quicr_sys::quicr_track_namespace_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let Some(track_namespace) = (unsafe { TrackNamespace::copy_from_raw(track_namespace) })
        else {
            return;
        };
        let state = unsafe { &*user_data.cast::<SubscribeCallbackState>() };
        state.callbacks.namespace_received(track_namespace);
    });
}

unsafe extern "C" fn namespace_done_received(
    _handler: *mut quicr_sys::quicr_subscribe_namespace_handler_t,
    track_namespace: *const quicr_sys::quicr_track_namespace_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let Some(track_namespace) = (unsafe { TrackNamespace::copy_from_raw(track_namespace) })
        else {
            return;
        };
        let state = unsafe { &*user_data.cast::<SubscribeCallbackState>() };
        state.callbacks.namespace_done(track_namespace);
    });
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
mod tests {
    use super::{
        PublishNamespaceHandler, PublishNamespaceStatus, SubscribeNamespaceHandler,
        SubscribeNamespaceMode, SubscribeNamespaceOptions, SubscribeNamespaceStatus,
    };
    use crate::TrackNamespace;

    #[test]
    fn creates_detached_handlers() {
        let namespace = TrackNamespace::new(["test"]).unwrap();
        let publish = PublishNamespaceHandler::new(&namespace).unwrap();
        let subscribe = SubscribeNamespaceHandler::new(
            &namespace,
            SubscribeNamespaceOptions {
                mode: SubscribeNamespaceMode::Namespaces,
                filter: None,
            },
        )
        .unwrap();

        assert!(publish.status().is_ok());
        assert!(subscribe.status().is_ok());
    }

    #[test]
    fn preserves_unknown_native_statuses() {
        assert_eq!(
            PublishNamespaceStatus::from_native(u8::MAX),
            PublishNamespaceStatus::Unknown(u8::MAX)
        );
        assert_eq!(
            SubscribeNamespaceStatus::from_native(u8::MAX),
            SubscribeNamespaceStatus::Unknown(u8::MAX)
        );
    }
}
