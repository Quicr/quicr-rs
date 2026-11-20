// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{ffi::c_void, mem::ManuallyDrop, ptr, sync::Arc};

use crate::{
    FullTrackName, Location, ProtocolError, error::get_protocol_error,
    extensions::NativeTrackExtensions,
};

use super::{
    CloseError, HandlerCreateError, HandlerOperationError, NoCallbacks, OK, abort_on_panic,
};

/// The current state of a [`TrackStatusHandler`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TrackStatusHandlerStatus {
    /// The track-status request has not been sent.
    NotRequested,
    /// A response from the peer is pending.
    PendingResponse,
    /// A successful response is available.
    Ok,
    /// The peer returned an error response.
    Error,
    /// The request completed with a FIN.
    DoneByFin,
    /// The request ended with a stream reset.
    DoneByReset,
    /// No usable session connection is available.
    NotConnected,
    /// A status value not known by this crate version.
    Unknown(u8),
}

impl TrackStatusHandlerStatus {
    fn from_native(value: quicr_sys::quicr_track_status_handler_status_t) -> Self {
        use quicr_sys::*;
        match value {
            value if value == QUICR_TRACK_STATUS_HANDLER_STATUS_NOT_REQUESTED as _ => {
                Self::NotRequested
            }
            value if value == QUICR_TRACK_STATUS_HANDLER_STATUS_PENDING_RESPONSE as _ => {
                Self::PendingResponse
            }
            value if value == QUICR_TRACK_STATUS_HANDLER_STATUS_OK as _ => Self::Ok,
            value if value == QUICR_TRACK_STATUS_HANDLER_STATUS_ERROR as _ => Self::Error,
            value if value == QUICR_TRACK_STATUS_HANDLER_STATUS_DONE_BY_FIN as _ => Self::DoneByFin,
            value if value == QUICR_TRACK_STATUS_HANDLER_STATUS_DONE_BY_RESET as _ => {
                Self::DoneByReset
            }
            value if value == QUICR_TRACK_STATUS_HANDLER_STATUS_NOT_CONNECTED as _ => {
                Self::NotConnected
            }
            value => Self::Unknown(value),
        }
    }
}

/// Receives track-status handler notifications.
///
/// Notifications may be concurrent and may run synchronously while native locks are held. Do not
/// re-enter operations on the same handler or destroy it from a callback. A panic aborts the
/// process because unwinding across the native boundary is invalid.
pub trait TrackStatusHandlerCallbacks: Send + Sync + 'static {
    /// Reports a transition in the track-status request state.
    fn status_changed(&self, _status: TrackStatusHandlerStatus) {}
}

impl TrackStatusHandlerCallbacks for NoCallbacks {}

struct CallbackState {
    callbacks: Box<dyn TrackStatusHandlerCallbacks>,
}

/// An owning RAII handle for requesting the status of one track.
///
/// Construction is detached; register the handler with
/// [`SessionManager::add_handler`](crate::SessionManager::add_handler). The session retains shared
/// ownership until removal, so remove it before calling [`Self::close`].
pub struct TrackStatusHandler {
    pub(crate) inner: Arc<Inner>,
}

/// Internal shared ownership for a native track-status handler.
#[doc(hidden)]
pub struct Inner {
    /// The native handler pointer.
    pub raw: *mut quicr_sys::quicr_track_status_track_handler_t,
    callbacks: ManuallyDrop<Box<CallbackState>>,
    destroyed: bool,
}

unsafe impl Send for Inner {}
unsafe impl Sync for Inner {}

impl TrackStatusHandler {
    /// Creates a detached track-status handler without callbacks.
    pub fn new(full_track_name: &FullTrackName) -> Result<Self, HandlerCreateError> {
        Self::new_with_callbacks(full_track_name, NoCallbacks)
    }

    /// Creates a detached track-status handler with callbacks.
    ///
    /// Callback delivery may begin synchronously when the handler is later registered; see
    /// [`TrackStatusHandlerCallbacks`] for callback restrictions.
    pub fn new_with_callbacks(
        full_track_name: &FullTrackName,
        callbacks: impl TrackStatusHandlerCallbacks,
    ) -> Result<Self, HandlerCreateError> {
        let full_name = full_track_name
            .to_native()
            .map_err(|error| HandlerCreateError::from_status(error.status()))?;

        let mut callback_state = Box::new(CallbackState {
            callbacks: Box::new(callbacks),
        });
        let native_callbacks = quicr_sys::quicr_track_status_handler_callbacks_t {
            user_data: (&mut *callback_state as *mut CallbackState).cast(),
            status_changed: Some(status_changed),
        };

        let mut raw = ptr::null_mut();
        let status = unsafe {
            quicr_sys::quicr_track_status_handler_create(&native_callbacks, full_name.raw, &mut raw)
        };

        if status != OK {
            return Err(HandlerCreateError::from_status(status));
        }
        if raw.is_null() {
            return Err(HandlerCreateError::InternalError);
        }

        Ok(Self {
            inner: Arc::new(Inner {
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

    /// Returns the request's current state.
    pub fn status(&self) -> Result<TrackStatusHandlerStatus, HandlerOperationError> {
        let mut status = 0;
        let result = unsafe {
            quicr_sys::quicr_track_status_handler_get_status(self.inner.raw, &mut status)
        };
        if result != OK {
            return Err(HandlerOperationError::from_status(result));
        }
        Ok(TrackStatusHandlerStatus::from_native(status))
    }

    /// Returns the successful track-status response, if one is available.
    ///
    /// `Ok(None)` means no response is currently available; inspect [`Self::status`] to
    /// distinguish a pending request from an error or completed request.
    pub fn response(&self) -> Result<Option<TrackStatus>, HandlerOperationError> {
        let mut extensions =
            NativeTrackExtensions::empty().map_err(|_| HandlerOperationError::InternalError)?;
        let mut response: quicr_sys::quicr_track_status_response_t = unsafe { std::mem::zeroed() };
        let mut has_response = false;

        let result = unsafe {
            quicr_sys::quicr_track_status_handler_get_response(
                self.inner.raw,
                &mut has_response,
                &mut response,
                extensions.as_mut_ptr(),
            )
        };
        if result != OK {
            return Err(HandlerOperationError::from_status(result));
        }
        if !has_response {
            return Ok(None);
        }

        let largest_location = response.has_largest_location.then_some(Location {
            group: response.largest_location.group,
            object: response.largest_location.object,
        });
        Ok(Some(TrackStatus {
            largest_location,
            track_properties: extensions
                .into_value()
                .map_err(|_| HandlerOperationError::InternalError)?,
        }))
    }

    /// Returns the peer-provided protocol error, if one is available.
    pub fn error(&self) -> Result<Option<ProtocolError>, HandlerOperationError> {
        unsafe {
            get_protocol_error(|code, reason, size| {
                quicr_sys::quicr_track_status_handler_get_error(self.inner.raw, code, reason, size)
            })
        }
        .map_err(|_| HandlerOperationError::InternalError)
    }
}

/// A successful response to a track-status request.
///
/// This is an alias for [`crate::TrackStatusResponse`].
pub type TrackStatus = crate::TrackStatusResponse;

impl Drop for Inner {
    fn drop(&mut self) {
        if self.destroyed {
            return;
        }
        unsafe { quicr_sys::quicr_track_status_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
    }
}

impl Inner {
    fn try_destroy(mut self) -> Result<(), (Self, HandlerOperationError)> {
        unsafe { quicr_sys::quicr_track_status_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
        Ok(())
    }
}

unsafe extern "C" fn status_changed(
    _handler: *mut quicr_sys::quicr_track_status_track_handler_t,
    status: quicr_sys::quicr_track_status_handler_status_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let state = unsafe { &*user_data.cast::<CallbackState>() };
        state
            .callbacks
            .status_changed(TrackStatusHandlerStatus::from_native(status));
    });
}

#[cfg(test)]
mod tests {
    use super::{TrackStatusHandler, TrackStatusHandlerStatus};
    use crate::{FullTrackName, TrackNamespace};

    #[test]
    fn creates_detached_handler() {
        let name = FullTrackName::new(TrackNamespace::new(["test"]).unwrap(), "track");
        let handler = TrackStatusHandler::new(&name).unwrap();
        assert!(handler.status().is_ok());
    }

    #[test]
    fn preserves_unknown_native_status() {
        assert_eq!(
            TrackStatusHandlerStatus::from_native(u8::MAX),
            TrackStatusHandlerStatus::Unknown(u8::MAX)
        );
    }
}
