// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{ffi::c_void, mem::ManuallyDrop, ptr, slice, sync::Arc};

use crate::{
    FetchEndLocation, FullTrackName, GroupOrder, Location, ObjectHeaders, StreamHeaderProperties,
};

use super::{
    CloseError, HandlerCreateError, HandlerOperationError, NoCallbacks, OK,
    SubscribeTrackCallbacks, SubscribeTrackStatus, abort_on_panic, operation,
};

struct CallbackState {
    callbacks: Box<dyn SubscribeTrackCallbacks>,
}

/// An owning RAII handle for fetching a bounded range of one track.
///
/// Construction is detached; register the handler with
/// [`SessionManager::add_handler`](crate::SessionManager::add_handler). The session retains shared
/// ownership until removal, so remove it before calling [`Self::close`]. Incoming data is
/// delivered through [`SubscribeTrackCallbacks`].
pub struct FetchTrackHandler {
    pub(crate) inner: Arc<Inner>,
}

/// Internal shared ownership for a native fetch handler.
#[doc(hidden)]
pub struct Inner {
    /// The native handler pointer.
    pub raw: *mut quicr_sys::quicr_fetch_track_handler_t,
    callbacks: ManuallyDrop<Box<CallbackState>>,
    destroyed: bool,
}

unsafe impl Send for Inner {}
unsafe impl Sync for Inner {}

/// Initial settings for a [`FetchTrackHandler`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchTrackOptions {
    /// The fetch priority; lower numeric values have higher priority.
    pub priority: u8,
    /// The inclusive first location requested.
    pub start: Location,
    /// The fetch's inclusive end location.
    pub end: FetchEndLocation,
    /// The requested group delivery order.
    pub group_order: GroupOrder,
}

impl FetchTrackHandler {
    /// Creates a detached fetch handler without callbacks.
    pub fn new(
        full_track_name: &FullTrackName,
        options: FetchTrackOptions,
    ) -> Result<Self, HandlerCreateError> {
        Self::new_with_callbacks(full_track_name, options, NoCallbacks)
    }

    /// Creates a detached fetch handler with callbacks.
    ///
    /// Callback delivery may begin synchronously when the handler is later registered.
    /// [`SubscribeTrackCallbacks`] documents concurrency, re-entry, borrowed-data, and panic
    /// constraints.
    pub fn new_with_callbacks(
        full_track_name: &FullTrackName,
        options: FetchTrackOptions,
        callbacks: impl SubscribeTrackCallbacks,
    ) -> Result<Self, HandlerCreateError> {
        let FetchTrackOptions {
            priority,
            start,
            end,
            group_order,
        } = options;
        let full_name = full_track_name
            .to_native()
            .map_err(|error| HandlerCreateError::from_status(error.status()))?;
        let start = quicr_sys::quicr_location_t {
            group: start.group,
            object: start.object,
        };
        let end = quicr_sys::quicr_fetch_end_location_t {
            group: end.group,
            has_object: end.object.is_some(),
            object: end.object.unwrap_or_default(),
        };

        let mut callback_state = Box::new(CallbackState {
            callbacks: Box::new(callbacks),
        });
        let native_callbacks = quicr_sys::quicr_fetch_track_handler_callbacks_t {
            user_data: (&mut *callback_state as *mut CallbackState).cast(),
            status_changed: Some(status_changed),
            metrics_sampled: Some(metrics_sampled),
            object_received: Some(object_received),
            object_status_received: Some(object_status_received),
            subgroup_ended: Some(subgroup_ended),
            datagram_received: Some(datagram_received),
        };

        let mut raw = ptr::null_mut();
        let status = unsafe {
            quicr_sys::quicr_fetch_track_handler_create(
                &native_callbacks,
                full_name.raw,
                priority,
                &start,
                &end,
                group_order.native(),
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

    /// Returns the fetch handler's current state.
    pub fn status(&self) -> Result<SubscribeTrackStatus, HandlerOperationError> {
        let mut status = 0;
        let result =
            unsafe { quicr_sys::quicr_fetch_track_handler_get_status(self.inner.raw, &mut status) };
        if result != OK {
            return Err(HandlerOperationError::from_status(result));
        }
        Ok(SubscribeTrackStatus::from_native(status))
    }

    /// Returns this fetch handler's subscriber priority.
    ///
    /// Lower numeric values have higher priority.
    pub fn subscriber_priority(&self) -> Result<u8, HandlerOperationError> {
        let mut priority = 0;
        let status = unsafe {
            quicr_sys::quicr_fetch_track_handler_get_subscriber_priority(
                self.inner.raw,
                &mut priority,
            )
        };
        operation(status)?;

        Ok(priority)
    }

    /// Sets this fetch handler's subscriber priority.
    ///
    /// Lower numeric values have higher priority. An already-sent fetch request is unchanged.
    pub fn set_subscriber_priority(&self, priority: u8) -> Result<(), HandlerOperationError> {
        operation(unsafe {
            quicr_sys::quicr_fetch_track_handler_set_subscriber_priority(self.inner.raw, priority)
        })
    }

    /// Pauses object delivery for this fetch.
    pub fn pause(&mut self) -> Result<(), HandlerOperationError> {
        operation(unsafe { quicr_sys::quicr_fetch_track_handler_pause(self.inner.raw) })
    }

    /// Resumes object delivery for this fetch.
    pub fn resume(&mut self) -> Result<(), HandlerOperationError> {
        operation(unsafe { quicr_sys::quicr_fetch_track_handler_resume(self.inner.raw) })
    }

    /// Requests delivery beginning with `group_id`.
    pub fn request_new_group(&mut self, group_id: u64) -> Result<(), HandlerOperationError> {
        operation(unsafe {
            quicr_sys::quicr_fetch_track_handler_request_new_group(self.inner.raw, group_id)
        })
    }

    /// Enables or disables support for peer-driven new-group requests.
    pub fn support_new_group_requests(
        &mut self,
        supported: bool,
    ) -> Result<(), HandlerOperationError> {
        operation(unsafe {
            quicr_sys::quicr_fetch_track_handler_support_new_group_request(
                self.inner.raw,
                supported,
            )
        })
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if self.destroyed {
            return;
        }
        unsafe { quicr_sys::quicr_fetch_track_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
    }
}

impl Inner {
    fn try_destroy(mut self) -> Result<(), (Self, HandlerOperationError)> {
        unsafe { quicr_sys::quicr_fetch_track_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
        Ok(())
    }
}

unsafe extern "C" fn status_changed(
    _handler: *mut quicr_sys::quicr_fetch_track_handler_t,
    status: quicr_sys::quicr_fetch_track_handler_status_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        unsafe { callback_state(user_data) }
            .callbacks
            .status_changed(SubscribeTrackStatus::from_native(status));
    });
}

unsafe extern "C" fn metrics_sampled(
    _handler: *mut quicr_sys::quicr_fetch_track_handler_t,
    metrics: *const quicr_sys::quicr_subscribe_track_metrics_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let metrics = unsafe { metrics.as_ref() }
            .copied()
            .expect("libquicr invoked a metrics callback with null metrics");
        unsafe { callback_state(user_data) }
            .callbacks
            .metrics_sampled(metrics.into());
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
                .and_then(|headers| ObjectHeaders::from_native(headers))
        }) else {
            return;
        };
        let Some(data) = (unsafe { byte_span(data) }) else {
            return;
        };
        let properties = unsafe {
            properties
                .as_ref()
                .and_then(|properties| StreamHeaderProperties::from_native(properties))
        };
        unsafe { callback_state(user_data) }
            .callbacks
            .object_received(headers, data, properties);
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
                .and_then(|headers| ObjectHeaders::from_native(headers))
        }) else {
            return;
        };
        unsafe { callback_state(user_data) }
            .callbacks
            .object_status_received(headers);
    });
}

unsafe extern "C" fn subgroup_ended(
    group_id: u64,
    subgroup_id: u64,
    reset: bool,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        unsafe { callback_state(user_data) }
            .callbacks
            .subgroup_ended(group_id, subgroup_id, reset);
    });
}

unsafe extern "C" fn datagram_received(data: quicr_sys::quicr_byte_span_t, user_data: *mut c_void) {
    abort_on_panic(|| {
        let Some(data) = (unsafe { byte_span(data) }) else {
            return;
        };
        unsafe { callback_state(user_data) }
            .callbacks
            .datagram_received(data);
    });
}

unsafe fn byte_span<'a>(span: quicr_sys::quicr_byte_span_t) -> Option<&'a [u8]> {
    if span.size == 0 {
        return Some(&[]);
    }
    if span.data.is_null() {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(span.data, span.size) })
}

unsafe fn callback_state<'a>(user_data: *mut c_void) -> &'a CallbackState {
    unsafe { &*user_data.cast() }
}

#[cfg(test)]
mod tests {
    use super::{FetchTrackHandler, FetchTrackOptions};
    use crate::{FetchEndLocation, FullTrackName, GroupOrder, Location, TrackNamespace};

    #[test]
    fn creates_detached_handler() {
        let name = FullTrackName::new(TrackNamespace::new(["test"]).unwrap(), "track");
        let handler = FetchTrackHandler::new(
            &name,
            FetchTrackOptions {
                priority: 127,
                start: Location::default(),
                end: FetchEndLocation {
                    group: 10,
                    object: None,
                },
                group_order: GroupOrder::Ascending,
            },
        )
        .unwrap();
        assert!(handler.status().is_ok());
        assert_eq!(handler.subscriber_priority().unwrap(), 127);
        handler.set_subscriber_priority(42).unwrap();
        assert_eq!(handler.subscriber_priority().unwrap(), 42);
    }
}
