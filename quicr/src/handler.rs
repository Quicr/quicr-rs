// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{
    ffi::c_void,
    fmt,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
    ptr, slice,
    sync::Arc,
    time::Duration,
};

use crate::{
    Filter, FullTrackName, GroupOrder, Location, ObjectHeaders, PublishTrackMetrics, Session,
    StreamHeaderProperties, SubscribeTrackMetrics, TrackMode,
};

mod fetch;
mod namespace;
mod publish_fetch;
mod track_status;

pub use fetch::{FetchTrackHandler, FetchTrackOptions};
pub use namespace::{
    PublishNamespaceCallbacks, PublishNamespaceHandler, PublishNamespaceStatus,
    SubscribeNamespaceCallbacks, SubscribeNamespaceHandler, SubscribeNamespaceHandlerRef,
    SubscribeNamespaceMode, SubscribeNamespaceOptions, SubscribeNamespaceStatus,
};
pub use publish_fetch::{BoundPublishFetch, PublishFetchHandler, PublishFetchOptions};
pub use track_status::{
    TrackStatus, TrackStatusHandler, TrackStatusHandlerCallbacks, TrackStatusHandlerStatus,
};

const OK: quicr_sys::quicr_status_t = quicr_sys::QUICR_STATUS_OK as _;

/// An error returned while allocating or configuring a native handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HandlerCreateError {
    /// One or more constructor arguments are invalid or outside the native API's range.
    InvalidArgument,
    /// The native library could not allocate the handler.
    OutOfMemory,
    /// The native library failed for another reason.
    InternalError,
}

impl HandlerCreateError {
    pub(crate) fn from_status(status: quicr_sys::quicr_status_t) -> Self {
        match status as u32 {
            quicr_sys::QUICR_STATUS_INVALID_ARGUMENT => Self::InvalidArgument,
            quicr_sys::QUICR_STATUS_OUT_OF_MEMORY => Self::OutOfMemory,
            _ => Self::InternalError,
        }
    }
}

impl fmt::Display for HandlerCreateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "invalid track handler configuration",
            Self::OutOfMemory => "track handler creation ran out of memory",
            Self::InternalError => "track handler creation failed",
        })
    }
}

impl std::error::Error for HandlerCreateError {}

/// An error returned by an operation on an existing handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HandlerOperationError {
    /// An argument is invalid or outside the native API's range.
    InvalidArgument,
    /// The native library could not allocate memory needed by the operation.
    OutOfMemory,
    /// The native library failed for another reason.
    InternalError,
    /// The session or handler is no longer registered or available.
    NotFound,
    /// The handler is still shared, bound, registered, or otherwise in use.
    Busy,
    /// The request was valid but the native library did not apply it.
    NotApplied,
}

impl HandlerOperationError {
    pub(crate) fn from_status(status: quicr_sys::quicr_status_t) -> Self {
        match status as u32 {
            quicr_sys::QUICR_STATUS_INVALID_ARGUMENT => Self::InvalidArgument,
            quicr_sys::QUICR_STATUS_OUT_OF_MEMORY => Self::OutOfMemory,
            quicr_sys::QUICR_STATUS_NOT_FOUND => Self::NotFound,
            quicr_sys::QUICR_STATUS_NOT_APPLIED => Self::NotApplied,
            _ => Self::InternalError,
        }
    }
}

impl fmt::Display for HandlerOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "invalid track handler operation",
            Self::OutOfMemory => "track handler operation ran out of memory",
            Self::InternalError => "track handler operation failed",
            Self::NotFound => "session or track handler was not found",
            Self::Busy => "track handler is busy",
            Self::NotApplied => "track handler operation was not applied",
        })
    }
}

impl std::error::Error for HandlerOperationError {}

/// An explicit handler close failure that retains ownership of the handler.
///
/// Explicit close methods consume a handler so that successful destruction cannot leave a usable
/// Rust value. On failure this error returns that value through [`Self::into_handler`] or
/// [`Self::into_parts`], allowing the caller to remove registrations or bindings and retry.
pub struct CloseError<H> {
    handler: H,
    error: HandlerOperationError,
}

impl<H> CloseError<H> {
    fn new(handler: H, error: HandlerOperationError) -> Self {
        Self { handler, error }
    }

    /// Borrows the handler that could not be closed.
    pub fn handler(&self) -> &H {
        &self.handler
    }

    /// Returns the native operation error that prevented closing.
    pub fn error(&self) -> HandlerOperationError {
        self.error
    }

    /// Recovers the handler, discarding the close failure reason.
    pub fn into_handler(self) -> H {
        self.handler
    }

    /// Recovers both the handler and the close failure reason.
    pub fn into_parts(self) -> (H, HandlerOperationError) {
        (self.handler, self.error)
    }
}

impl<H> fmt::Debug for CloseError<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloseError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<H> fmt::Display for CloseError<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "failed to close handler: {}", self.error)
    }
}

impl<H: 'static> std::error::Error for CloseError<H> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

pub(crate) fn operation(status: quicr_sys::quicr_status_t) -> Result<(), HandlerOperationError> {
    if status == OK {
        Ok(())
    } else {
        Err(HandlerOperationError::from_status(status))
    }
}

pub(crate) fn duration_millis_u32(duration: Duration) -> Option<u32> {
    duration.as_millis().try_into().ok()
}

/// The current state reported for a publish-track or publish-fetch handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PublishTrackStatus {
    /// The handler is ready to publish.
    Ok,
    /// No usable session connection is available.
    NotConnected,
    /// The track has not been announced.
    NotAnnounced,
    /// An announce response is pending.
    PendingAnnounceResponse,
    /// The peer rejected authorization for the announcement.
    AnnounceNotAuthorized,
    /// No subscribers currently consume the track.
    NoSubscribers,
    /// The track was unsubscribed.
    Unsubscribed,
    /// Publishing completed with a FIN.
    DoneByFin,
    /// An unannounce is being sent.
    SendingUnannounce,
    /// Subscription parameters changed.
    SubscriptionUpdated,
    /// A subscriber requested a new group.
    NewGroupRequested,
    /// A publish-ok response is pending.
    PendingPublishOk,
    /// Publishing is paused.
    Paused,
    /// A status value not known by this crate version.
    Unknown(u8),
}

impl PublishTrackStatus {
    fn from_native(value: quicr_sys::quicr_publish_track_handler_status_t) -> Self {
        use quicr_sys::*;
        match value {
            value if value == QUICR_PUBLISH_TRACK_HANDLER_STATUS_OK as _ => Self::Ok,
            value if value == QUICR_PUBLISH_TRACK_HANDLER_STATUS_NOT_CONNECTED as _ => {
                Self::NotConnected
            }
            value if value == QUICR_PUBLISH_TRACK_HANDLER_STATUS_NOT_ANNOUNCED as _ => {
                Self::NotAnnounced
            }
            value if value == QUICR_PUBLISH_TRACK_HANDLER_STATUS_PENDING_ANNOUNCE_RESPONSE as _ => {
                Self::PendingAnnounceResponse
            }
            value if value == QUICR_PUBLISH_TRACK_HANDLER_STATUS_ANNOUNCE_NOT_AUTHORIZED as _ => {
                Self::AnnounceNotAuthorized
            }
            value if value == QUICR_PUBLISH_TRACK_HANDLER_STATUS_NO_SUBSCRIBERS as _ => {
                Self::NoSubscribers
            }
            value if value == QUICR_PUBLISH_TRACK_HANDLER_STATUS_UNSUBSCRIBED as _ => {
                Self::Unsubscribed
            }
            value if value == QUICR_PUBLISH_TRACK_HANDLER_STATUS_DONE_BY_FIN as _ => {
                Self::DoneByFin
            }
            value if value == QUICR_PUBLISH_TRACK_HANDLER_STATUS_SENDING_UNANNOUNCE as _ => {
                Self::SendingUnannounce
            }
            value if value == QUICR_PUBLISH_TRACK_HANDLER_STATUS_SUBSCRIPTION_UPDATED as _ => {
                Self::SubscriptionUpdated
            }
            value if value == QUICR_PUBLISH_TRACK_HANDLER_STATUS_NEW_GROUP_REQUESTED as _ => {
                Self::NewGroupRequested
            }
            value if value == QUICR_PUBLISH_TRACK_HANDLER_STATUS_PENDING_PUBLISH_OK as _ => {
                Self::PendingPublishOk
            }
            value if value == QUICR_PUBLISH_TRACK_HANDLER_STATUS_PAUSED as _ => Self::Paused,
            value => Self::Unknown(value),
        }
    }
}

/// The outcome of submitting object data to a publish handler.
///
/// A successful method call can still return a non-[`Self::Ok`] protocol outcome. In contrast,
/// [`HandlerOperationError`] means the operation itself could not be performed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PublishObjectStatus {
    /// The object data was accepted.
    Ok,
    /// The native library encountered an internal failure.
    InternalError,
    /// Publishing this object is not authorized.
    NotAuthorized,
    /// The track has not been announced.
    NotAnnounced,
    /// No subscribers currently consume the track.
    NoSubscribers,
    /// The supplied bytes exceed the declared object payload length.
    ObjectPayloadLengthExceeded,
    /// Starting this object truncated the preceding object.
    PreviousObjectTruncated,
    /// There is no preceding object to continue.
    NoPreviousObject,
    /// The object's declared payload is now complete.
    ObjectDataComplete,
    /// More continuation data is required to complete the object.
    ObjectContinuationDataNeeded,
    /// The supplied data is too large for the operation.
    ObjectDataTooLarge,
    /// The object remains incomplete.
    ObjectDataIncomplete,
    /// The incomplete preceding object requires starting a new group.
    MustStartNewGroup,
    /// The incomplete preceding object requires starting a new track.
    MustStartNewTrack,
    /// Publishing is paused.
    Paused,
    /// A publish-ok response is pending.
    PendingPublishOk,
    /// The target subgroup has been closed.
    SubgroupClosed,
    /// The fetch being served has been closed.
    FetchClosed,
    /// An outcome value not known by this crate version.
    Unknown(u8),
}

impl PublishObjectStatus {
    fn from_native(value: quicr_sys::quicr_publish_object_status_t) -> Self {
        use quicr_sys::*;
        match value {
            value if value == QUICR_PUBLISH_OBJECT_STATUS_OK as _ => Self::Ok,
            value if value == QUICR_PUBLISH_OBJECT_STATUS_INTERNAL_ERROR as _ => {
                Self::InternalError
            }
            value if value == QUICR_PUBLISH_OBJECT_STATUS_NOT_AUTHORIZED as _ => {
                Self::NotAuthorized
            }
            value if value == QUICR_PUBLISH_OBJECT_STATUS_NOT_ANNOUNCED as _ => Self::NotAnnounced,
            value if value == QUICR_PUBLISH_OBJECT_STATUS_NO_SUBSCRIBERS as _ => {
                Self::NoSubscribers
            }
            value if value == QUICR_PUBLISH_OBJECT_STATUS_OBJECT_PAYLOAD_LENGTH_EXCEEDED as _ => {
                Self::ObjectPayloadLengthExceeded
            }
            value if value == QUICR_PUBLISH_OBJECT_STATUS_PREVIOUS_OBJECT_TRUNCATED as _ => {
                Self::PreviousObjectTruncated
            }
            value if value == QUICR_PUBLISH_OBJECT_STATUS_NO_PREVIOUS_OBJECT as _ => {
                Self::NoPreviousObject
            }
            value if value == QUICR_PUBLISH_OBJECT_STATUS_OBJECT_DATA_COMPLETE as _ => {
                Self::ObjectDataComplete
            }
            value if value == QUICR_PUBLISH_OBJECT_STATUS_OBJECT_CONTINUATION_DATA_NEEDED as _ => {
                Self::ObjectContinuationDataNeeded
            }
            value if value == QUICR_PUBLISH_OBJECT_STATUS_OBJECT_DATA_TOO_LARGE as _ => {
                Self::ObjectDataTooLarge
            }
            value if value == QUICR_PUBLISH_OBJECT_STATUS_OBJECT_DATA_INCOMPLETE as _ => {
                Self::ObjectDataIncomplete
            }
            value
                if value
                    == QUICR_PUBLISH_OBJECT_STATUS_PREVIOUS_OBJECT_NOT_COMPLETE_MUST_START_NEW_GROUP
                        as _ =>
            {
                Self::MustStartNewGroup
            }
            value
                if value
                    == QUICR_PUBLISH_OBJECT_STATUS_PREVIOUS_OBJECT_NOT_COMPLETE_MUST_START_NEW_TRACK
                        as _ =>
            {
                Self::MustStartNewTrack
            }
            value if value == QUICR_PUBLISH_OBJECT_STATUS_PAUSED as _ => Self::Paused,
            value if value == QUICR_PUBLISH_OBJECT_STATUS_PENDING_PUBLISH_OK as _ => {
                Self::PendingPublishOk
            }
            value if value == QUICR_PUBLISH_OBJECT_STATUS_SUBGROUP_CLOSED as _ => {
                Self::SubgroupClosed
            }
            value if value == QUICR_PUBLISH_OBJECT_STATUS_FETCH_CLOSED as _ => Self::FetchClosed,
            value => Self::Unknown(value),
        }
    }
}

/// An owning RAII handle for publishing one track.
///
/// Construction is detached. Register the handler with
/// [`SessionManager::add_handler`](crate::SessionManager::add_handler), or temporarily bind it with
/// [`Self::bind`] when serving an incoming publish request. Dropping attempts native destruction;
/// use [`Self::close`] when destruction failures must be observed.
pub struct PublishTrackHandler {
    pub(crate) inner: Arc<PublishInner>,
}

/// Internal shared ownership for a native publish-track handler.
#[doc(hidden)]
pub struct PublishInner {
    /// The native handler pointer.
    pub raw: *mut quicr_sys::quicr_publish_track_handler_t,
    callbacks: ManuallyDrop<Box<PublishCallbackState>>,
    destroyed: bool,
}

unsafe impl Send for PublishInner {}
unsafe impl Sync for PublishInner {}

/// Receives publish-track notifications.
///
/// Notifications may be concurrent and may run synchronously while native locks are held. Do not
/// re-enter operations on the same handler or destroy it from a callback. A panic aborts the
/// process because unwinding across the native boundary is invalid.
pub trait PublishTrackCallbacks: Send + Sync + 'static {
    /// Reports a transition in the handler's publish state.
    fn status_changed(&self, _status: PublishTrackStatus) {}
    /// Delivers a point-in-time metrics sample.
    fn metrics_sampled(&self, _metrics: PublishTrackMetrics) {}
    /// Reports cancellation of the identified subgroup.
    fn subgroup_cancelled(&self, _group_id: u64, _subgroup_id: u64) {}
}

/// Initial settings for a [`PublishTrackHandler`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishTrackOptions {
    /// The transport mode used for objects unless changed later.
    pub track_mode: TrackMode,
    /// The track's publisher priority; lower numeric values have higher priority.
    pub publisher_priority: u8,
    /// The default object priority; lower numeric values have higher priority.
    pub publish_object_priority: u8,
    /// The default object time-to-live.
    ///
    /// The value is passed to the native API in milliseconds and must fit in a `u32`.
    pub default_ttl: Duration,
    /// The largest location already available when the handler is created.
    pub largest_location: Location,
}

pub(crate) struct NoCallbacks;

impl PublishTrackCallbacks for NoCallbacks {}

struct PublishCallbackState {
    callbacks: Box<dyn PublishTrackCallbacks>,
}

impl PublishTrackHandler {
    /// Creates a detached publish handler without callbacks.
    ///
    /// The handler does not become publishable until it is registered or bound.
    pub fn new(
        full_track_name: &FullTrackName,
        options: PublishTrackOptions,
    ) -> Result<Self, HandlerCreateError> {
        Self::new_with_callbacks(full_track_name, options, NoCallbacks)
    }

    /// Creates a detached publish handler with callbacks.
    ///
    /// Callback delivery may begin synchronously when the handler is later registered or bound;
    /// see [`PublishTrackCallbacks`] for callback restrictions.
    pub fn new_with_callbacks(
        full_track_name: &FullTrackName,
        options: PublishTrackOptions,
        callbacks: impl PublishTrackCallbacks,
    ) -> Result<Self, HandlerCreateError> {
        let PublishTrackOptions {
            track_mode,
            publisher_priority,
            publish_object_priority,
            default_ttl,
            largest_location,
        } = options;
        let full_name = full_track_name
            .to_native()
            .map_err(|error| HandlerCreateError::from_status(error.status()))?;
        let default_ttl =
            duration_millis_u32(default_ttl).ok_or(HandlerCreateError::InvalidArgument)?;
        let location = quicr_sys::quicr_location_t {
            group: largest_location.group,
            object: largest_location.object,
        };

        let mut callback_state = Box::new(PublishCallbackState {
            callbacks: Box::new(callbacks),
        });
        let native_callbacks = quicr_sys::quicr_publish_track_handler_callbacks_t {
            user_data: (&mut *callback_state as *mut PublishCallbackState).cast(),
            status_changed: Some(publish_status_changed),
            metrics_sampled: Some(publish_metrics_sampled),
            subgroup_cancelled: Some(publish_subgroup_cancelled),
        };

        let mut raw = ptr::null_mut();
        let status = unsafe {
            quicr_sys::quicr_publish_track_handler_create(
                &native_callbacks,
                full_name.raw,
                track_mode.native(),
                publisher_priority,
                publish_object_priority,
                default_ttl,
                &location,
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
            inner: Arc::new(PublishInner {
                raw,
                callbacks: ManuallyDrop::new(callback_state),
                destroyed: false,
            }),
        })
    }

    /// Explicitly destroys the native handler.
    ///
    /// This fails with [`HandlerOperationError::Busy`] while shared ownership remains, including
    /// ownership retained by a session registration. On any failure, [`CloseError`] preserves the
    /// handler so the caller can remove the registration and retry. Dropping is the best-effort
    /// RAII alternative when the result is not needed.
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

    /// Returns whether the handler can currently accept object data.
    pub fn can_publish(&self) -> bool {
        unsafe { quicr_sys::quicr_publish_track_handler_can_publish(self.inner.raw) }
    }

    /// Returns the handler's current publish state.
    pub fn status(&self) -> Result<PublishTrackStatus, HandlerOperationError> {
        let mut status = 0;
        let result = unsafe {
            quicr_sys::quicr_publish_track_handler_get_status(self.inner.raw, &mut status)
        };

        if result != OK {
            return Err(HandlerOperationError::from_status(result));
        }

        Ok(PublishTrackStatus::from_native(status))
    }

    /// Returns the track's publisher priority.
    ///
    /// Lower numeric values have higher priority.
    pub fn publisher_priority(&self) -> Result<u8, HandlerOperationError> {
        let mut priority = 0;
        let status = unsafe {
            quicr_sys::quicr_publish_track_handler_get_publisher_priority(
                self.inner.raw,
                &mut priority,
            )
        };
        operation(status)?;

        Ok(priority)
    }

    /// Sets the track's publisher priority.
    ///
    /// Lower numeric values have higher priority.
    pub fn set_publisher_priority(&mut self, priority: u8) -> Result<(), HandlerOperationError> {
        operation(unsafe {
            quicr_sys::quicr_publish_track_handler_set_publisher_priority(self.inner.raw, priority)
        })
    }

    /// Returns the default object priority.
    ///
    /// Lower numeric values have higher priority.
    pub fn publish_object_priority(&self) -> Result<u8, HandlerOperationError> {
        let mut priority = 0;
        let status = unsafe {
            quicr_sys::quicr_publish_track_handler_get_publish_object_priority(
                self.inner.raw,
                &mut priority,
            )
        };
        operation(status)?;

        Ok(priority)
    }

    /// Sets the default object priority.
    ///
    /// Lower numeric values have higher priority.
    pub fn set_publish_object_priority(
        &mut self,
        priority: u8,
    ) -> Result<(), HandlerOperationError> {
        operation(unsafe {
            quicr_sys::quicr_publish_track_handler_set_publish_object_priority(
                self.inner.raw,
                priority,
            )
        })
    }

    /// Returns the default object time-to-live.
    ///
    /// The native value has millisecond precision.
    pub fn default_ttl(&self) -> Result<Duration, HandlerOperationError> {
        let mut ttl = 0;
        let status = unsafe {
            quicr_sys::quicr_publish_track_handler_get_default_ttl(self.inner.raw, &mut ttl)
        };
        operation(status)?;

        Ok(Duration::from_millis(ttl.into()))
    }

    /// Sets the default object time-to-live.
    ///
    /// `ttl` is converted to whole milliseconds and must fit in a `u32`; otherwise
    /// [`HandlerOperationError::InvalidArgument`] is returned.
    pub fn set_default_ttl(&mut self, ttl: Duration) -> Result<(), HandlerOperationError> {
        let ttl = duration_millis_u32(ttl).ok_or(HandlerOperationError::InvalidArgument)?;

        operation(unsafe {
            quicr_sys::quicr_publish_track_handler_set_default_ttl(self.inner.raw, ttl)
        })
    }

    /// Returns the default transport mode used for objects.
    pub fn default_track_mode(&self) -> Result<TrackMode, HandlerOperationError> {
        let mut mode = 0;
        let status = unsafe {
            quicr_sys::quicr_publish_track_handler_get_default_track_mode(self.inner.raw, &mut mode)
        };
        operation(status)?;

        TrackMode::from_native(mode).ok_or(HandlerOperationError::InternalError)
    }

    /// Sets the default transport mode used for subsequent objects.
    pub fn set_default_track_mode(&mut self, mode: TrackMode) -> Result<(), HandlerOperationError> {
        operation(unsafe {
            quicr_sys::quicr_publish_track_handler_set_default_track_mode(
                self.inner.raw,
                mode.native(),
            )
        })
    }

    /// Submits object data using the handler's default stream properties.
    ///
    /// The payload length sent to the native library is always `data.len()`, replacing the value
    /// in `headers`. The returned [`PublishObjectStatus`] describes whether the data was accepted.
    pub fn publish_object(
        &mut self,
        headers: &ObjectHeaders,
        data: &[u8],
    ) -> Result<PublishObjectStatus, HandlerOperationError> {
        self.publish_object_with_properties(headers, data, None)
    }

    /// Submits object data with optional stream-header properties.
    ///
    /// The payload length sent to the native library is always `data.len()`, replacing the value
    /// in `headers`. `data` and `properties` are borrowed only for this call.
    pub fn publish_object_with_properties(
        &mut self,
        headers: &ObjectHeaders,
        data: &[u8],
        properties: Option<&StreamHeaderProperties>,
    ) -> Result<PublishObjectStatus, HandlerOperationError> {
        let mut headers = headers.clone();
        headers.payload_length = data.len() as u64;
        let headers = headers
            .native()
            .ok_or(HandlerOperationError::InvalidArgument)?;
        let data = quicr_sys::quicr_byte_span_t {
            data: data.as_ptr(),
            size: data.len(),
        };
        let properties = properties.copied().map(StreamHeaderProperties::native);

        let mut outcome = 0;
        let result = unsafe {
            quicr_sys::quicr_publish_track_handler_publish_object(
                self.inner.raw,
                &headers.raw,
                data,
                properties.as_ref().map_or(ptr::null(), |value| value),
                &mut outcome,
            )
        };

        operation(result)?;
        Ok(PublishObjectStatus::from_native(outcome))
    }

    /// Ends one subgroup.
    ///
    /// `completed` indicates whether all intended objects for the subgroup were published.
    pub fn end_subgroup(
        &mut self,
        group_id: u64,
        subgroup_id: u64,
        completed: bool,
    ) -> Result<(), HandlerOperationError> {
        let status = unsafe {
            quicr_sys::quicr_publish_track_handler_end_subgroup(
                self.inner.raw,
                group_id,
                subgroup_id,
                completed,
            )
        };
        operation(status)
    }

    /// Ends every open subgroup.
    ///
    /// `completed` indicates whether all intended objects for each subgroup were published.
    pub fn end_all_subgroups(&mut self, completed: bool) -> Result<(), HandlerOperationError> {
        let status = unsafe {
            quicr_sys::quicr_publish_track_handler_end_all_subgroups(self.inner.raw, completed)
        };
        operation(status)
    }

    /// Binds this handler to an incoming publish request on `session`.
    ///
    /// The returned [`BoundPublishTrack`] is an RAII guard that mutably borrows the handler and
    /// unbinds it on drop. Call [`BoundPublishTrack::finish`] to observe unbind errors and
    /// optionally send `PUBLISH_DONE`. `source_id` and `request_id` are protocol identifiers;
    /// `ephemeral` selects an ephemeral binding.
    pub fn bind<'a>(
        &'a mut self,
        session: &'a Session,
        source_id: u64,
        request_id: u64,
        ephemeral: bool,
    ) -> Result<BoundPublishTrack<'a>, HandlerOperationError> {
        let status = session
            .with_raw(|session| unsafe {
                quicr_sys::quicr_session_bind_publish_track_handler(
                    session,
                    source_id,
                    request_id,
                    self.inner.raw,
                    ephemeral,
                )
            })
            .map_err(|_| HandlerOperationError::NotFound)?;
        operation(status)?;

        Ok(BoundPublishTrack {
            session,
            handler: self,
            source_id,
            bound: true,
        })
    }
}

/// An RAII guard for a publish-track binding.
///
/// The guard dereferences to [`PublishTrackHandler`]. Dropping it performs a best-effort unbind
/// without sending `PUBLISH_DONE`; use [`Self::finish`] when the result or completion signal
/// matters.
pub struct BoundPublishTrack<'a> {
    session: &'a Session,
    handler: &'a mut PublishTrackHandler,
    source_id: u64,
    bound: bool,
}

impl BoundPublishTrack<'_> {
    /// Unbinds the handler and optionally sends `PUBLISH_DONE`.
    ///
    /// If unbinding fails, normal guard drop makes one additional best-effort unbind without
    /// `PUBLISH_DONE`.
    pub fn finish(mut self, send_publish_done: bool) -> Result<(), HandlerOperationError> {
        self.unbind(send_publish_done)?;
        self.bound = false;

        Ok(())
    }

    fn unbind(&self, send_publish_done: bool) -> Result<(), HandlerOperationError> {
        let raw = self.handler.inner.raw;
        let status = self
            .session
            .with_raw(|session| unsafe {
                quicr_sys::quicr_session_unbind_publish_track_handler(
                    session,
                    self.source_id,
                    raw,
                    send_publish_done,
                )
            })
            .map_err(|_| HandlerOperationError::NotFound)?;

        operation(status)
    }
}

impl Deref for BoundPublishTrack<'_> {
    type Target = PublishTrackHandler;

    fn deref(&self) -> &Self::Target {
        self.handler
    }
}

impl DerefMut for BoundPublishTrack<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.handler
    }
}

impl Drop for BoundPublishTrack<'_> {
    fn drop(&mut self) {
        if self.bound {
            let _ = self.unbind(false);
        }
    }
}

impl Drop for PublishInner {
    fn drop(&mut self) {
        if self.destroyed {
            return;
        }
        unsafe { quicr_sys::quicr_publish_track_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
    }
}

impl PublishInner {
    fn try_destroy(mut self) -> Result<(), (Self, HandlerOperationError)> {
        unsafe { quicr_sys::quicr_publish_track_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
        Ok(())
    }
}

unsafe extern "C" fn publish_status_changed(
    _handler: *mut quicr_sys::quicr_publish_track_handler_t,
    status: quicr_sys::quicr_publish_track_handler_status_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let state = unsafe { &*user_data.cast::<PublishCallbackState>() };
        state
            .callbacks
            .status_changed(PublishTrackStatus::from_native(status));
    });
}

unsafe extern "C" fn publish_metrics_sampled(
    _handler: *mut quicr_sys::quicr_publish_track_handler_t,
    metrics: *const quicr_sys::quicr_publish_track_metrics_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let metrics = unsafe { metrics.as_ref() }
            .copied()
            .expect("libquicr invoked a metrics callback with null metrics");
        let state = unsafe { &*user_data.cast::<PublishCallbackState>() };
        state.callbacks.metrics_sampled(metrics.into());
    });
}

unsafe extern "C" fn publish_subgroup_cancelled(
    _handler: *mut quicr_sys::quicr_publish_track_handler_t,
    group_id: u64,
    subgroup_id: u64,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let state = unsafe { &*user_data.cast::<PublishCallbackState>() };
        state.callbacks.subgroup_cancelled(group_id, subgroup_id);
    });
}

/// The current state reported for a subscribe-track or fetch handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SubscribeTrackStatus {
    /// The subscription or fetch is active.
    Ok,
    /// No usable session connection is available.
    NotConnected,
    /// The handler encountered an unspecified error.
    Error,
    /// The peer rejected authorization for the request.
    NotAuthorized,
    /// The track is not subscribed.
    NotSubscribed,
    /// A response from the peer is pending.
    PendingResponse,
    /// An unsubscribe is being sent.
    SendingUnsubscribe,
    /// Delivery is paused.
    Paused,
    /// A new group was requested.
    NewGroupRequested,
    /// The request was cancelled.
    Cancelled,
    /// Delivery completed with a FIN.
    DoneByFin,
    /// Delivery ended with a stream reset.
    DoneByReset,
    /// A status value not known by this crate version.
    Unknown(u8),
}

impl SubscribeTrackStatus {
    fn from_native(value: quicr_sys::quicr_subscribe_track_handler_status_t) -> Self {
        use quicr_sys::*;
        match value {
            value if value == QUICR_SUBSCRIBE_TRACK_HANDLER_STATUS_OK as _ => Self::Ok,
            value if value == QUICR_SUBSCRIBE_TRACK_HANDLER_STATUS_NOT_CONNECTED as _ => {
                Self::NotConnected
            }
            value if value == QUICR_SUBSCRIBE_TRACK_HANDLER_STATUS_ERROR as _ => Self::Error,
            value if value == QUICR_SUBSCRIBE_TRACK_HANDLER_STATUS_NOT_AUTHORIZED as _ => {
                Self::NotAuthorized
            }
            value if value == QUICR_SUBSCRIBE_TRACK_HANDLER_STATUS_NOT_SUBSCRIBED as _ => {
                Self::NotSubscribed
            }
            value if value == QUICR_SUBSCRIBE_TRACK_HANDLER_STATUS_PENDING_RESPONSE as _ => {
                Self::PendingResponse
            }
            value if value == QUICR_SUBSCRIBE_TRACK_HANDLER_STATUS_SENDING_UNSUBSCRIBE as _ => {
                Self::SendingUnsubscribe
            }
            value if value == QUICR_SUBSCRIBE_TRACK_HANDLER_STATUS_PAUSED as _ => Self::Paused,
            value if value == QUICR_SUBSCRIBE_TRACK_HANDLER_STATUS_NEW_GROUP_REQUESTED as _ => {
                Self::NewGroupRequested
            }
            value if value == QUICR_SUBSCRIBE_TRACK_HANDLER_STATUS_CANCELLED as _ => {
                Self::Cancelled
            }
            value if value == QUICR_SUBSCRIBE_TRACK_HANDLER_STATUS_DONE_BY_FIN as _ => {
                Self::DoneByFin
            }
            value if value == QUICR_SUBSCRIBE_TRACK_HANDLER_STATUS_DONE_BY_RESET as _ => {
                Self::DoneByReset
            }
            value => Self::Unknown(value),
        }
    }
}

/// Receives subscribe-track notifications and object data.
///
/// Borrowed data is valid only for the callback. Notifications may be concurrent and may run
/// synchronously while native locks are held. Do not re-enter operations on the same handler or
/// destroy it from a callback. A panic aborts the process.
pub trait SubscribeTrackCallbacks: Send + Sync + 'static {
    /// Reports a transition in the handler's subscription or fetch state.
    fn status_changed(&self, _status: SubscribeTrackStatus) {}
    /// Delivers a point-in-time metrics sample.
    fn metrics_sampled(&self, _metrics: SubscribeTrackMetrics) {}
    /// Delivers object payload bytes and optional stream properties.
    ///
    /// `data` is borrowed from the native callback and is valid only until this method returns.
    /// Copy it before retaining or sending it to work that outlives the callback. `headers` and
    /// `properties` are Rust-owned values.
    fn object_received(
        &self,
        _headers: ObjectHeaders,
        _data: &[u8],
        _properties: Option<StreamHeaderProperties>,
    ) {
    }
    /// Delivers an object status encoded in `headers`, without payload bytes.
    fn object_status_received(&self, _headers: ObjectHeaders) {}
    /// Reports that a subgroup ended.
    ///
    /// `reset` is `true` when the subgroup ended by reset rather than normal completion.
    fn subgroup_ended(&self, _group_id: u64, _subgroup_id: u64, _reset: bool) {}
    /// Delivers one object datagram.
    ///
    /// `data` is borrowed from the native callback and is valid only until this method returns.
    fn datagram_received(&self, _data: &[u8]) {}
}

/// Receives subscribe-track callbacks plus raw forwarding notifications.
///
/// The same concurrency, borrowing, re-entry, and panic rules as [`SubscribeTrackCallbacks`]
/// apply.
pub trait ForwardingSubscribeTrackCallbacks: SubscribeTrackCallbacks {
    /// Reports the start of a forwarded subgroup.
    ///
    /// `priority` is present when the peer supplied one. `properties` is a Rust-owned copy of
    /// optional stream-header properties.
    fn subgroup_started(
        &self,
        _group_id: u64,
        _subgroup_id: u64,
        _priority: Option<u8>,
        _properties: Option<StreamHeaderProperties>,
    ) {
    }
    /// Delivers raw bytes forwarded for a subgroup stream.
    ///
    /// `data` is borrowed from the native callback and is valid only until this method returns.
    fn stream_bytes_forwarded(&self, _group_id: u64, _subgroup_id: u64, _data: &[u8]) {}
}

impl SubscribeTrackCallbacks for NoCallbacks {}
impl ForwardingSubscribeTrackCallbacks for NoCallbacks {}

/// Initial settings for a [`SubscribeTrackHandler`] or [`ForwardingSubscribeTrackHandler`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscribeTrackOptions {
    /// The request priority; lower numeric values have higher priority.
    pub priority: u8,
    /// The requested group delivery order, or `None` to leave it unspecified.
    pub group_order: Option<GroupOrder>,
    /// An optional subscription filter.
    pub filter: Option<Filter>,
}

struct SubscribeCallbackState {
    callbacks: SubscribeCallbacks,
}

enum SubscribeCallbacks {
    Standard(Box<dyn SubscribeTrackCallbacks>),
    Forwarding(Box<dyn ForwardingSubscribeTrackCallbacks>),
}

impl SubscribeCallbackState {
    fn status_changed(&self, status: SubscribeTrackStatus) {
        match &self.callbacks {
            SubscribeCallbacks::Standard(callbacks) => callbacks.status_changed(status),
            SubscribeCallbacks::Forwarding(callbacks) => callbacks.status_changed(status),
        }
    }

    fn metrics_sampled(&self, metrics: SubscribeTrackMetrics) {
        match &self.callbacks {
            SubscribeCallbacks::Standard(callbacks) => callbacks.metrics_sampled(metrics),
            SubscribeCallbacks::Forwarding(callbacks) => callbacks.metrics_sampled(metrics),
        }
    }

    fn object_received(
        &self,
        headers: ObjectHeaders,
        data: &[u8],
        properties: Option<StreamHeaderProperties>,
    ) {
        match &self.callbacks {
            SubscribeCallbacks::Standard(callbacks) => {
                callbacks.object_received(headers, data, properties);
            }
            SubscribeCallbacks::Forwarding(callbacks) => {
                callbacks.object_received(headers, data, properties);
            }
        }
    }

    fn object_status_received(&self, headers: ObjectHeaders) {
        match &self.callbacks {
            SubscribeCallbacks::Standard(callbacks) => callbacks.object_status_received(headers),
            SubscribeCallbacks::Forwarding(callbacks) => {
                callbacks.object_status_received(headers);
            }
        }
    }

    fn subgroup_ended(&self, group_id: u64, subgroup_id: u64, reset: bool) {
        match &self.callbacks {
            SubscribeCallbacks::Standard(callbacks) => {
                callbacks.subgroup_ended(group_id, subgroup_id, reset);
            }
            SubscribeCallbacks::Forwarding(callbacks) => {
                callbacks.subgroup_ended(group_id, subgroup_id, reset);
            }
        }
    }

    fn datagram_received(&self, data: &[u8]) {
        match &self.callbacks {
            SubscribeCallbacks::Standard(callbacks) => callbacks.datagram_received(data),
            SubscribeCallbacks::Forwarding(callbacks) => callbacks.datagram_received(data),
        }
    }

    fn subgroup_started(
        &self,
        group_id: u64,
        subgroup_id: u64,
        priority: Option<u8>,
        properties: Option<StreamHeaderProperties>,
    ) {
        if let SubscribeCallbacks::Forwarding(callbacks) = &self.callbacks {
            callbacks.subgroup_started(group_id, subgroup_id, priority, properties);
        }
    }

    fn stream_bytes_forwarded(&self, group_id: u64, subgroup_id: u64, data: &[u8]) {
        if let SubscribeCallbacks::Forwarding(callbacks) = &self.callbacks {
            callbacks.stream_bytes_forwarded(group_id, subgroup_id, data);
        }
    }
}

/// An owning RAII handle for subscribing to one track.
///
/// Construction is detached; use
/// [`SessionManager::add_handler`](crate::SessionManager::add_handler) to register it. The session
/// retains shared ownership until
/// [`SessionManager::remove_handler`](crate::SessionManager::remove_handler) succeeds or the
/// session is removed. Dropping attempts native destruction; use [`Self::close`] to observe
/// failures.
pub struct SubscribeTrackHandler {
    pub(crate) inner: Arc<SubscribeInner>,
}

/// A subscribe-track handler that also exposes raw stream-forwarding callbacks.
///
/// It has the same registration and RAII lifecycle as [`SubscribeTrackHandler`] and dereferences
/// to that type for common operations.
pub struct ForwardingSubscribeTrackHandler {
    handler: SubscribeTrackHandler,
}

/// Internal shared ownership for a native subscribe-track handler.
#[doc(hidden)]
pub struct SubscribeInner {
    /// The native handler pointer.
    pub raw: *mut quicr_sys::quicr_subscribe_track_handler_t,
    callbacks: ManuallyDrop<Box<SubscribeCallbackState>>,
    destroyed: bool,
}

unsafe impl Send for SubscribeInner {}
unsafe impl Sync for SubscribeInner {}

impl SubscribeTrackHandler {
    /// Creates a detached subscribe handler without callbacks.
    pub fn new(
        full_track_name: &FullTrackName,
        options: SubscribeTrackOptions,
    ) -> Result<Self, HandlerCreateError> {
        Self::new_with_callbacks(full_track_name, options, NoCallbacks)
    }

    /// Creates a detached subscribe handler with callbacks.
    ///
    /// Callback delivery may begin synchronously when the handler is later registered; see
    /// [`SubscribeTrackCallbacks`] for concurrency, re-entry, borrowing, and panic constraints.
    pub fn new_with_callbacks(
        full_track_name: &FullTrackName,
        options: SubscribeTrackOptions,
        callbacks: impl SubscribeTrackCallbacks,
    ) -> Result<Self, HandlerCreateError> {
        let SubscribeTrackOptions {
            priority,
            group_order,
            filter,
        } = options;
        let full_name = full_track_name
            .to_native()
            .map_err(|error| HandlerCreateError::from_status(error.status()))?;
        let filter = filter.map(Filter::native);

        let mut callback_state = Box::new(SubscribeCallbackState {
            callbacks: SubscribeCallbacks::Standard(Box::new(callbacks)),
        });
        let native_callbacks = quicr_sys::quicr_subscribe_track_handler_callbacks_t {
            user_data: (&mut *callback_state as *mut SubscribeCallbackState).cast(),
            status_changed: Some(subscribe_status_changed),
            metrics_sampled: Some(subscribe_metrics_sampled),
            object_received: Some(object_received),
            object_status_received: Some(object_status_received),
            subgroup_ended: Some(subgroup_ended),
            datagram_received: Some(datagram_received),
        };

        let mut raw = ptr::null_mut();
        let status = unsafe {
            quicr_sys::quicr_subscribe_track_handler_create(
                &native_callbacks,
                full_name.raw,
                priority,
                group_order.map_or(
                    quicr_sys::QUICR_GROUP_ORDER_UNSPECIFIED as _,
                    GroupOrder::native,
                ),
                filter.as_ref().map_or(ptr::null(), |value| value),
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
            inner: Arc::new(SubscribeInner {
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

    /// Returns the handler's current subscription state.
    pub fn status(&self) -> Result<SubscribeTrackStatus, HandlerOperationError> {
        let mut status = 0;
        let result = unsafe {
            quicr_sys::quicr_subscribe_track_handler_get_status(self.inner.raw, &mut status)
        };

        if result != OK {
            return Err(HandlerOperationError::from_status(result));
        }

        Ok(SubscribeTrackStatus::from_native(status))
    }

    /// Returns the subscriber priority used for future subscription updates.
    ///
    /// Lower numeric values have higher priority.
    pub fn subscriber_priority(&self) -> Result<u8, HandlerOperationError> {
        let mut priority = 0;
        let status = unsafe {
            quicr_sys::quicr_subscribe_track_handler_get_subscriber_priority(
                self.inner.raw,
                &mut priority,
            )
        };
        operation(status)?;

        Ok(priority)
    }

    /// Sets the subscriber priority used for future subscription updates.
    ///
    /// Lower numeric values have higher priority.
    pub fn set_subscriber_priority(&self, priority: u8) -> Result<(), HandlerOperationError> {
        operation(unsafe {
            quicr_sys::quicr_subscribe_track_handler_set_subscriber_priority(
                self.inner.raw,
                priority,
            )
        })
    }

    /// Pauses object delivery for this subscription.
    pub fn pause(&mut self) -> Result<(), HandlerOperationError> {
        let status = unsafe { quicr_sys::quicr_subscribe_track_handler_pause(self.inner.raw) };
        operation(status)
    }

    /// Resumes object delivery for this subscription.
    pub fn resume(&mut self) -> Result<(), HandlerOperationError> {
        let status = unsafe { quicr_sys::quicr_subscribe_track_handler_resume(self.inner.raw) };
        operation(status)
    }

    /// Requests delivery beginning with `group_id`.
    pub fn request_new_group(&mut self, group_id: u64) -> Result<(), HandlerOperationError> {
        let status = unsafe {
            quicr_sys::quicr_subscribe_track_handler_request_new_group(self.inner.raw, group_id)
        };
        operation(status)
    }

    /// Enables or disables support for peer-driven new-group requests.
    pub fn support_new_group_requests(
        &mut self,
        supported: bool,
    ) -> Result<(), HandlerOperationError> {
        let status = unsafe {
            quicr_sys::quicr_subscribe_track_handler_support_new_group_request(
                self.inner.raw,
                supported,
            )
        };
        operation(status)
    }
}

impl ForwardingSubscribeTrackHandler {
    /// Creates a detached forwarding subscribe handler without callbacks.
    pub fn new(
        full_track_name: &FullTrackName,
        options: SubscribeTrackOptions,
    ) -> Result<Self, HandlerCreateError> {
        Self::new_with_callbacks(full_track_name, options, NoCallbacks)
    }

    /// Creates a detached forwarding subscribe handler with callbacks.
    ///
    /// Callback delivery may begin synchronously when the handler is later registered; see
    /// [`ForwardingSubscribeTrackCallbacks`] for callback restrictions.
    pub fn new_with_callbacks(
        full_track_name: &FullTrackName,
        options: SubscribeTrackOptions,
        callbacks: impl ForwardingSubscribeTrackCallbacks,
    ) -> Result<Self, HandlerCreateError> {
        let SubscribeTrackOptions {
            priority,
            group_order,
            filter,
        } = options;
        let full_name = full_track_name
            .to_native()
            .map_err(|error| HandlerCreateError::from_status(error.status()))?;
        let filter = filter.map(Filter::native);

        let mut callback_state = Box::new(SubscribeCallbackState {
            callbacks: SubscribeCallbacks::Forwarding(Box::new(callbacks)),
        });
        let track_callbacks = quicr_sys::quicr_subscribe_track_handler_callbacks_t {
            user_data: (&mut *callback_state as *mut SubscribeCallbackState).cast(),
            status_changed: Some(subscribe_status_changed),
            metrics_sampled: Some(subscribe_metrics_sampled),
            object_received: Some(object_received),
            object_status_received: Some(object_status_received),
            subgroup_ended: Some(subgroup_ended),
            datagram_received: Some(datagram_received),
        };
        let native_callbacks = quicr_sys::quicr_forwarding_subscribe_track_handler_callbacks_t {
            track_callbacks,
            subgroup_started: Some(subgroup_started),
            stream_bytes_forwarded: Some(stream_bytes_forwarded),
        };

        let mut raw = ptr::null_mut();
        let status = unsafe {
            quicr_sys::quicr_forwarding_subscribe_track_handler_create(
                &native_callbacks,
                full_name.raw,
                priority,
                group_order.map_or(
                    quicr_sys::QUICR_GROUP_ORDER_UNSPECIFIED as _,
                    GroupOrder::native,
                ),
                filter.as_ref().map_or(ptr::null(), |value| value),
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
            handler: SubscribeTrackHandler {
                inner: Arc::new(SubscribeInner {
                    raw,
                    callbacks: ManuallyDrop::new(callback_state),
                    destroyed: false,
                }),
            },
        })
    }

    /// Explicitly destroys the native handler.
    ///
    /// A session registration must first be removed. On failure, [`CloseError`] preserves this
    /// handler so removal and close can be retried.
    pub fn close(self) -> Result<(), CloseError<Self>> {
        self.handler.close().map_err(|error| {
            let (handler, source) = error.into_parts();
            CloseError::new(Self { handler }, source)
        })
    }

    /// Explicitly destroys the native handler, returning it unchanged on failure.
    ///
    /// Use [`Self::close`] when the failure reason is needed.
    pub fn try_close(self) -> Result<(), Self> {
        self.close().map_err(CloseError::into_handler)
    }
}

impl Deref for ForwardingSubscribeTrackHandler {
    type Target = SubscribeTrackHandler;

    fn deref(&self) -> &Self::Target {
        &self.handler
    }
}

impl DerefMut for ForwardingSubscribeTrackHandler {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handler
    }
}

impl From<ForwardingSubscribeTrackHandler> for SubscribeTrackHandler {
    fn from(handler: ForwardingSubscribeTrackHandler) -> Self {
        handler.handler
    }
}

impl Drop for SubscribeInner {
    fn drop(&mut self) {
        if self.destroyed {
            return;
        }
        unsafe { quicr_sys::quicr_subscribe_track_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
    }
}

impl SubscribeInner {
    fn try_destroy(mut self) -> Result<(), (Self, HandlerOperationError)> {
        unsafe { quicr_sys::quicr_subscribe_track_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
        Ok(())
    }
}

unsafe extern "C" fn subscribe_status_changed(
    _handler: *mut quicr_sys::quicr_subscribe_track_handler_t,
    status: quicr_sys::quicr_subscribe_track_handler_status_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        unsafe { callback_state(user_data) }
            .status_changed(SubscribeTrackStatus::from_native(status));
    });
}

unsafe extern "C" fn subscribe_metrics_sampled(
    _handler: *mut quicr_sys::quicr_subscribe_track_handler_t,
    metrics: *const quicr_sys::quicr_subscribe_track_metrics_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let metrics = unsafe { metrics.as_ref() }
            .copied()
            .expect("libquicr invoked a metrics callback with null metrics");
        unsafe { callback_state(user_data) }.metrics_sampled(metrics.into());
    });
}

unsafe extern "C" fn object_received(
    headers: *const quicr_sys::quicr_object_headers_t,
    data: quicr_sys::quicr_byte_span_t,
    properties: *const quicr_sys::quicr_stream_header_properties_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let Some(headers) = (unsafe {
            headers
                .as_ref()
                .and_then(|value| ObjectHeaders::from_native(value))
        }) else {
            return;
        };
        let data = if data.size == 0 {
            &[]
        } else if data.data.is_null() {
            return;
        } else {
            unsafe { slice::from_raw_parts(data.data, data.size) }
        };
        let properties = unsafe {
            properties
                .as_ref()
                .and_then(|value| StreamHeaderProperties::from_native(value))
        };
        unsafe { callback_state(user_data) }.object_received(headers, data, properties);
    });
}

unsafe extern "C" fn object_status_received(
    headers: *const quicr_sys::quicr_object_headers_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let Some(headers) = (unsafe {
            headers
                .as_ref()
                .and_then(|value| ObjectHeaders::from_native(value))
        }) else {
            return;
        };
        unsafe { callback_state(user_data) }.object_status_received(headers);
    });
}

unsafe extern "C" fn subgroup_ended(
    group_id: u64,
    subgroup_id: u64,
    reset: bool,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        unsafe { callback_state(user_data) }.subgroup_ended(group_id, subgroup_id, reset);
    });
}

unsafe extern "C" fn datagram_received(data: quicr_sys::quicr_byte_span_t, user_data: *mut c_void) {
    abort_on_panic(|| {
        let data = if data.size == 0 {
            &[]
        } else if data.data.is_null() {
            return;
        } else {
            unsafe { slice::from_raw_parts(data.data, data.size) }
        };
        unsafe { callback_state(user_data) }.datagram_received(data);
    });
}

unsafe extern "C" fn subgroup_started(
    group_id: u64,
    subgroup_id: u64,
    has_priority: bool,
    priority: u8,
    properties: *const quicr_sys::quicr_stream_header_properties_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let properties = unsafe {
            properties
                .as_ref()
                .and_then(|properties| StreamHeaderProperties::from_native(properties))
        };
        unsafe { callback_state(user_data) }.subgroup_started(
            group_id,
            subgroup_id,
            has_priority.then_some(priority),
            properties,
        );
    });
}

unsafe extern "C" fn stream_bytes_forwarded(
    group_id: u64,
    subgroup_id: u64,
    data: quicr_sys::quicr_byte_span_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        if data.size > 0 && data.data.is_null() {
            return;
        }
        let data = if data.size == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(data.data, data.size) }
        };
        unsafe { callback_state(user_data) }.stream_bytes_forwarded(group_id, subgroup_id, data);
    });
}

unsafe fn callback_state<'a>(user_data: *mut c_void) -> &'a SubscribeCallbackState {
    unsafe { &*user_data.cast() }
}

fn abort_on_panic(function: impl FnOnce()) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(function)).is_err() {
        std::process::abort();
    }
}

/// A sealed marker implemented by handlers accepted by session-manager operations.
///
/// Handlers are created detached. Passing one to
/// [`SessionManager::add_handler`](crate::SessionManager::add_handler) registers its native
/// resource and causes the session to retain shared ownership. Call
/// [`SessionManager::remove_handler`](crate::SessionManager::remove_handler) before explicit close;
/// removing the session also releases its registrations. This trait is sealed and cannot be
/// implemented outside this crate.
pub trait TrackHandler: sealed::Sealed {}

impl TrackHandler for PublishTrackHandler {}
impl TrackHandler for SubscribeTrackHandler {}
impl TrackHandler for ForwardingSubscribeTrackHandler {}
impl TrackHandler for FetchTrackHandler {}
impl TrackHandler for PublishNamespaceHandler {}
impl TrackHandler for SubscribeNamespaceHandler {}
impl TrackHandler for TrackStatusHandler {}

/// Internal shared ownership retained for a session registration.
#[doc(hidden)]
pub enum Registration {
    /// A publish-track registration.
    Publish(Arc<PublishInner>),
    /// A subscribe-track or forwarding-subscribe registration.
    Subscribe(Arc<SubscribeInner>),
    /// A fetch registration.
    Fetch(Arc<fetch::Inner>),
    /// A publish-namespace registration.
    PublishNamespace(Arc<namespace::PublishNamespaceInner>),
    /// A subscribe-namespace registration.
    SubscribeNamespace(Arc<namespace::SubscribeNamespaceInner>),
    /// A track-status registration.
    TrackStatus(Arc<track_status::Inner>),
}

impl Registration {
    pub(crate) fn key(&self) -> (*const c_void, bool) {
        match self {
            Self::Publish(inner) => (inner.raw.cast(), true),
            Self::Subscribe(inner) => (inner.raw.cast(), false),
            Self::Fetch(inner) => (inner.raw.cast(), false),
            Self::PublishNamespace(inner) => (inner.raw.cast(), true),
            Self::SubscribeNamespace(inner) => (inner.raw.cast(), false),
            Self::TrackStatus(inner) => (inner.raw.cast(), false),
        }
    }

    pub(crate) fn try_release(self) -> Result<(), Self> {
        let shared = match &self {
            Self::Publish(inner) => Arc::strong_count(inner) > 1,
            Self::Subscribe(inner) => Arc::strong_count(inner) > 1,
            Self::Fetch(inner) => Arc::strong_count(inner) > 1,
            Self::PublishNamespace(inner) => Arc::strong_count(inner) > 1,
            Self::SubscribeNamespace(inner) => Arc::strong_count(inner) > 1,
            Self::TrackStatus(inner) => Arc::strong_count(inner) > 1,
        };
        if shared {
            return Ok(());
        }

        match self {
            Self::Publish(inner) => PublishTrackHandler { inner }
                .close()
                .map_err(|error| Self::Publish(error.into_handler().inner)),
            Self::Subscribe(inner) => SubscribeTrackHandler { inner }
                .close()
                .map_err(|error| Self::Subscribe(error.into_handler().inner)),
            Self::Fetch(inner) => FetchTrackHandler { inner }
                .close()
                .map_err(|error| Self::Fetch(error.into_handler().inner)),
            Self::PublishNamespace(inner) => PublishNamespaceHandler { inner }
                .close()
                .map_err(|error| Self::PublishNamespace(error.into_handler().inner)),
            Self::SubscribeNamespace(inner) => SubscribeNamespaceHandler { inner }
                .close()
                .map_err(|error| Self::SubscribeNamespace(error.into_handler().inner)),
            Self::TrackStatus(inner) => TrackStatusHandler { inner }
                .close()
                .map_err(|error| Self::TrackStatus(error.into_handler().inner)),
        }
    }
}

mod sealed {
    use super::Registration;

    pub trait Sealed {
        fn registration(&self) -> Registration;
    }
}

impl sealed::Sealed for PublishTrackHandler {
    fn registration(&self) -> Registration {
        Registration::Publish(Arc::clone(&self.inner))
    }
}

impl sealed::Sealed for SubscribeTrackHandler {
    fn registration(&self) -> Registration {
        Registration::Subscribe(Arc::clone(&self.inner))
    }
}

impl sealed::Sealed for ForwardingSubscribeTrackHandler {
    fn registration(&self) -> Registration {
        Registration::Subscribe(Arc::clone(&self.handler.inner))
    }
}

impl sealed::Sealed for TrackStatusHandler {
    fn registration(&self) -> Registration {
        Registration::TrackStatus(Arc::clone(&self.inner))
    }
}

impl sealed::Sealed for FetchTrackHandler {
    fn registration(&self) -> Registration {
        Registration::Fetch(Arc::clone(&self.inner))
    }
}

impl sealed::Sealed for PublishNamespaceHandler {
    fn registration(&self) -> Registration {
        Registration::PublishNamespace(Arc::clone(&self.inner))
    }
}

impl sealed::Sealed for SubscribeNamespaceHandler {
    fn registration(&self) -> Registration {
        Registration::SubscribeNamespace(Arc::clone(&self.inner))
    }
}

pub(crate) fn registration<H: TrackHandler>(handler: &H) -> Registration {
    sealed::Sealed::registration(handler)
}

pub(crate) unsafe fn goaway_registration(
    registration: &Registration,
    session: *mut quicr_sys::quicr_session_t,
    new_session_uri: *const std::ffi::c_char,
    timeout_ms: u64,
) -> quicr_sys::quicr_status_t {
    unsafe {
        match registration {
            Registration::Publish(handler) => {
                quicr_sys::quicr_session_goaway_publish_track_handler(
                    session,
                    new_session_uri,
                    timeout_ms,
                    handler.raw,
                )
            }
            Registration::Subscribe(handler) => {
                quicr_sys::quicr_session_goaway_subscribe_track_handler(
                    session,
                    new_session_uri,
                    timeout_ms,
                    handler.raw,
                )
            }
            Registration::Fetch(handler) => quicr_sys::quicr_session_goaway_fetch_track_handler(
                session,
                new_session_uri,
                timeout_ms,
                handler.raw,
            ),
            Registration::PublishNamespace(handler) => {
                quicr_sys::quicr_session_goaway_publish_namespace_handler(
                    session,
                    new_session_uri,
                    timeout_ms,
                    handler.raw,
                )
            }
            Registration::SubscribeNamespace(handler) => {
                quicr_sys::quicr_session_goaway_subscribe_namespace_handler(
                    session,
                    new_session_uri,
                    timeout_ms,
                    handler.raw,
                )
            }
            Registration::TrackStatus(handler) => {
                quicr_sys::quicr_session_goaway_track_status_handler(
                    session,
                    new_session_uri,
                    timeout_ms,
                    handler.raw,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::{
        ForwardingSubscribeTrackCallbacks, ForwardingSubscribeTrackHandler, HandlerCreateError,
        HandlerOperationError, PublishObjectStatus, PublishTrackHandler, PublishTrackOptions,
        PublishTrackStatus, SubscribeTrackCallbacks, SubscribeTrackHandler, SubscribeTrackOptions,
        SubscribeTrackStatus,
    };
    use crate::{FullTrackName, GroupOrder, Location, TrackMode, TrackNamespace};

    struct Callbacks;

    impl SubscribeTrackCallbacks for Callbacks {}
    impl ForwardingSubscribeTrackCallbacks for Callbacks {}

    fn full_track_name() -> FullTrackName {
        FullTrackName::new(TrackNamespace::new(["test"]).unwrap(), "track")
    }

    fn publish_options(publish_object_priority: u8) -> PublishTrackOptions {
        PublishTrackOptions {
            track_mode: TrackMode::Stream,
            publisher_priority: 127,
            publish_object_priority,
            default_ttl: Duration::from_secs(5),
            largest_location: Location::default(),
        }
    }

    fn subscribe_options() -> SubscribeTrackOptions {
        SubscribeTrackOptions {
            priority: 127,
            group_order: Some(GroupOrder::Ascending),
            filter: None,
        }
    }

    #[test]
    fn creates_detached_publish_handler() {
        let handler = PublishTrackHandler::new(&full_track_name(), publish_options(127)).unwrap();

        assert!(!handler.can_publish());
        assert!(handler.status().is_ok());
        assert!(handler.try_close().is_ok());
    }

    #[test]
    fn close_preserves_handler_and_failure_reason() {
        let handler = PublishTrackHandler::new(&full_track_name(), publish_options(127)).unwrap();
        let retained = Arc::clone(&handler.inner);

        let error = handler.close().unwrap_err();
        assert_eq!(error.error(), HandlerOperationError::Busy);

        let handler = error.into_handler();
        drop(retained);
        assert!(handler.close().is_ok());
    }

    #[test]
    fn publish_settings_roundtrip() {
        let mut handler =
            PublishTrackHandler::new(&full_track_name(), publish_options(126)).unwrap();

        assert_eq!(handler.publisher_priority().unwrap(), 127);
        assert_eq!(handler.publish_object_priority().unwrap(), 126);
        assert_eq!(handler.default_ttl().unwrap(), Duration::from_secs(5));
        assert_eq!(handler.default_track_mode().unwrap(), TrackMode::Stream);

        handler.set_publisher_priority(10).unwrap();
        handler.set_publish_object_priority(11).unwrap();
        handler.set_default_ttl(Duration::from_millis(12)).unwrap();
        handler.set_default_track_mode(TrackMode::Datagram).unwrap();

        assert_eq!(handler.publisher_priority().unwrap(), 10);
        assert_eq!(handler.publish_object_priority().unwrap(), 11);
        assert_eq!(handler.default_ttl().unwrap(), Duration::from_millis(12));
        assert_eq!(handler.default_track_mode().unwrap(), TrackMode::Datagram);
    }

    #[test]
    fn rejects_publish_ttl_larger_than_c_api_range() {
        let mut options = publish_options(127);
        options.default_ttl = Duration::ZERO;
        let mut handler = PublishTrackHandler::new(&full_track_name(), options).unwrap();

        assert_eq!(
            handler.set_default_ttl(Duration::from_millis(u64::from(u32::MAX) + 1)),
            Err(HandlerOperationError::InvalidArgument)
        );
    }

    #[test]
    fn preserves_public_operation_statuses() {
        assert_eq!(
            HandlerOperationError::from_status(quicr_sys::QUICR_STATUS_NOT_FOUND as _),
            HandlerOperationError::NotFound
        );
        assert_eq!(
            HandlerOperationError::from_status(quicr_sys::QUICR_STATUS_NOT_APPLIED as _),
            HandlerOperationError::NotApplied
        );
    }

    #[test]
    fn preserves_unknown_native_statuses() {
        assert_eq!(
            PublishTrackStatus::from_native(u8::MAX),
            PublishTrackStatus::Unknown(u8::MAX)
        );
        assert_eq!(
            SubscribeTrackStatus::from_native(u8::MAX),
            SubscribeTrackStatus::Unknown(u8::MAX)
        );
        assert_eq!(
            PublishObjectStatus::from_native(u8::MAX),
            PublishObjectStatus::Unknown(u8::MAX)
        );
    }

    #[test]
    fn categorizes_handler_creation_failures() {
        assert_eq!(
            HandlerCreateError::from_status(quicr_sys::QUICR_STATUS_INVALID_ARGUMENT as _),
            HandlerCreateError::InvalidArgument
        );
        assert_eq!(
            HandlerCreateError::from_status(quicr_sys::QUICR_STATUS_OUT_OF_MEMORY as _),
            HandlerCreateError::OutOfMemory
        );
        assert_eq!(
            HandlerCreateError::from_status(quicr_sys::QUICR_STATUS_INTERNAL_ERROR as _),
            HandlerCreateError::InternalError
        );
    }

    #[test]
    fn creates_detached_subscribe_handler() {
        let handler = SubscribeTrackHandler::new_with_callbacks(
            &full_track_name(),
            subscribe_options(),
            Callbacks,
        )
        .unwrap();

        assert!(handler.status().is_ok());
        assert_eq!(handler.subscriber_priority().unwrap(), 127);
        handler.set_subscriber_priority(42).unwrap();
        assert_eq!(handler.subscriber_priority().unwrap(), 42);
        assert!(handler.try_close().is_ok());
    }

    #[test]
    fn creates_detached_forwarding_handler() {
        let handler = ForwardingSubscribeTrackHandler::new_with_callbacks(
            &full_track_name(),
            subscribe_options(),
            Callbacks,
        )
        .unwrap();

        assert!(handler.status().is_ok());
        assert!(handler.try_close().is_ok());
    }
}
