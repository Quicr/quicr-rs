// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{
    ffi::c_void,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
    ptr,
    sync::Arc,
    time::Duration,
};

use crate::{FullTrackName, GroupOrder, ObjectHeaders, PublishTrackMetrics, Session};

use super::{
    CloseError, HandlerCreateError, HandlerOperationError, NoCallbacks, OK, PublishObjectStatus,
    PublishTrackCallbacks, PublishTrackStatus, abort_on_panic, duration_millis_u32, operation,
};

struct CallbackState {
    callbacks: Box<dyn PublishTrackCallbacks>,
}

/// An owning RAII handle for serving an incoming fetch request.
///
/// Construction is detached. Bind it to the requesting [`Session`] with [`Self::bind`]; the
/// resulting [`BoundPublishFetch`] controls the binding lifetime. Dropping attempts native
/// destruction, while [`Self::close`] reports destruction failures.
pub struct PublishFetchHandler {
    inner: Arc<Inner>,
}

struct Inner {
    raw: *mut quicr_sys::quicr_publish_fetch_handler_t,
    callbacks: ManuallyDrop<Box<CallbackState>>,
    destroyed: bool,
}

unsafe impl Send for Inner {}
unsafe impl Sync for Inner {}

/// Initial settings for a [`PublishFetchHandler`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishFetchOptions {
    /// The response priority; lower numeric values have higher priority.
    pub priority: u8,
    /// The protocol request identifier for the fetch being served.
    pub request_id: u64,
    /// The group order used for the response.
    pub group_order: GroupOrder,
    /// The default object time-to-live.
    ///
    /// The value is passed to the native API in milliseconds and must fit in a `u32`.
    pub default_ttl: Duration,
}

impl PublishFetchHandler {
    /// Creates a detached publish-fetch handler without callbacks.
    pub fn new(
        full_track_name: &FullTrackName,
        options: PublishFetchOptions,
    ) -> Result<Self, HandlerCreateError> {
        Self::new_with_callbacks(full_track_name, options, NoCallbacks)
    }

    /// Creates a detached publish-fetch handler with callbacks.
    ///
    /// Callback delivery may begin synchronously when the handler is bound; see
    /// [`PublishTrackCallbacks`] for concurrency, re-entry, and panic constraints.
    pub fn new_with_callbacks(
        full_track_name: &FullTrackName,
        options: PublishFetchOptions,
        callbacks: impl PublishTrackCallbacks,
    ) -> Result<Self, HandlerCreateError> {
        let PublishFetchOptions {
            priority,
            request_id,
            group_order,
            default_ttl,
        } = options;
        let full_name = full_track_name
            .to_native()
            .map_err(|error| HandlerCreateError::from_status(error.status()))?;
        let default_ttl =
            duration_millis_u32(default_ttl).ok_or(HandlerCreateError::InvalidArgument)?;

        let mut callback_state = Box::new(CallbackState {
            callbacks: Box::new(callbacks),
        });
        let native_callbacks = quicr_sys::quicr_publish_fetch_handler_callbacks_t {
            user_data: (&mut *callback_state as *mut CallbackState).cast(),
            status_changed: Some(status_changed),
            metrics_sampled: Some(metrics_sampled),
            subgroup_cancelled: Some(subgroup_cancelled),
        };

        let mut raw = ptr::null_mut();
        let status = unsafe {
            quicr_sys::quicr_publish_fetch_handler_create(
                &native_callbacks,
                full_name.raw,
                priority,
                request_id,
                group_order.native(),
                default_ttl,
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
    /// This fails with [`HandlerOperationError::Busy`] while it is bound or otherwise shared. On
    /// failure, [`CloseError`] preserves the handler for unbinding and retry. Dropping is the
    /// best-effort RAII alternative.
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

    /// Returns whether the handler can currently accept response object data.
    pub fn can_publish(&self) -> bool {
        unsafe { quicr_sys::quicr_publish_fetch_handler_can_publish(self.inner.raw) }
    }

    /// Returns the handler's current publish state.
    pub fn status(&self) -> Result<PublishTrackStatus, HandlerOperationError> {
        let mut status = 0;
        let result = unsafe {
            quicr_sys::quicr_publish_fetch_handler_get_status(self.inner.raw, &mut status)
        };
        if result != OK {
            return Err(HandlerOperationError::from_status(result));
        }
        Ok(PublishTrackStatus::from_native(status))
    }

    /// Submits one object's data to the fetch response.
    ///
    /// The payload length sent to the native library is always `data.len()`, replacing the value
    /// in `headers`. `data` is borrowed only for this call. The returned
    /// [`PublishObjectStatus`] describes whether the data was accepted.
    pub fn publish_object(
        &mut self,
        headers: &ObjectHeaders,
        data: &[u8],
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
        let mut outcome = 0;
        let result = unsafe {
            quicr_sys::quicr_publish_fetch_handler_publish_object(
                self.inner.raw,
                &headers.raw,
                data,
                &mut outcome,
            )
        };
        operation(result)?;
        Ok(PublishObjectStatus::from_native(outcome))
    }

    /// Binds this handler to its incoming fetch request on `session`.
    ///
    /// The returned [`BoundPublishFetch`] mutably borrows the handler and unbinds on drop. Call
    /// [`BoundPublishFetch::finish`] to observe any unbind failure.
    pub fn bind<'a>(
        &'a mut self,
        session: &'a Session,
    ) -> Result<BoundPublishFetch<'a>, HandlerOperationError> {
        let status = session
            .with_raw(|session| unsafe {
                quicr_sys::quicr_session_bind_publish_fetch_handler(session, self.inner.raw)
            })
            .map_err(|_| HandlerOperationError::NotFound)?;
        operation(status)?;

        Ok(BoundPublishFetch {
            session,
            handler: self,
            bound: true,
        })
    }
}

/// An RAII guard for a publish-fetch binding.
///
/// The guard dereferences to [`PublishFetchHandler`]. Dropping performs a best-effort unbind; use
/// [`Self::finish`] when the unbind result matters.
pub struct BoundPublishFetch<'a> {
    session: &'a Session,
    handler: &'a mut PublishFetchHandler,
    bound: bool,
}

impl BoundPublishFetch<'_> {
    /// Unbinds the publish-fetch handler and returns any unbind error.
    ///
    /// If this call fails, normal guard drop makes one additional best-effort unbind.
    pub fn finish(mut self) -> Result<(), HandlerOperationError> {
        self.unbind()?;
        self.bound = false;
        Ok(())
    }

    fn unbind(&self) -> Result<(), HandlerOperationError> {
        let raw = self.handler.inner.raw;
        let status = self
            .session
            .with_raw(|session| unsafe {
                quicr_sys::quicr_session_unbind_publish_fetch_handler(session, raw)
            })
            .map_err(|_| HandlerOperationError::NotFound)?;
        operation(status)
    }
}

impl Deref for BoundPublishFetch<'_> {
    type Target = PublishFetchHandler;

    fn deref(&self) -> &Self::Target {
        self.handler
    }
}

impl DerefMut for BoundPublishFetch<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.handler
    }
}

impl Drop for BoundPublishFetch<'_> {
    fn drop(&mut self) {
        if self.bound {
            let _ = self.unbind();
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if self.destroyed {
            return;
        }
        unsafe { quicr_sys::quicr_publish_fetch_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
    }
}

impl Inner {
    fn try_destroy(mut self) -> Result<(), (Self, HandlerOperationError)> {
        unsafe { quicr_sys::quicr_publish_fetch_handler_destroy(self.raw) };
        self.destroyed = true;
        unsafe { ManuallyDrop::drop(&mut self.callbacks) };
        Ok(())
    }
}

unsafe extern "C" fn status_changed(
    _handler: *mut quicr_sys::quicr_publish_fetch_handler_t,
    status: quicr_sys::quicr_publish_fetch_handler_status_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let state = unsafe { &*user_data.cast::<CallbackState>() };
        state
            .callbacks
            .status_changed(PublishTrackStatus::from_native(status));
    });
}

unsafe extern "C" fn metrics_sampled(
    _handler: *mut quicr_sys::quicr_publish_fetch_handler_t,
    metrics: *const quicr_sys::quicr_publish_track_metrics_t,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let metrics: PublishTrackMetrics = unsafe { metrics.as_ref() }
            .copied()
            .expect("libquicr invoked a metrics callback with null metrics")
            .into();
        let state = unsafe { &*user_data.cast::<CallbackState>() };
        state.callbacks.metrics_sampled(metrics);
    });
}

unsafe extern "C" fn subgroup_cancelled(
    _handler: *mut quicr_sys::quicr_publish_fetch_handler_t,
    group_id: u64,
    subgroup_id: u64,
    user_data: *mut c_void,
) {
    abort_on_panic(|| {
        let state = unsafe { &*user_data.cast::<CallbackState>() };
        state.callbacks.subgroup_cancelled(group_id, subgroup_id);
    });
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{PublishFetchHandler, PublishFetchOptions};
    use crate::{FullTrackName, GroupOrder, TrackNamespace};

    #[test]
    fn creates_detached_handler() {
        let name = FullTrackName::new(TrackNamespace::new(["test"]).unwrap(), "track");
        let handler = PublishFetchHandler::new(
            &name,
            PublishFetchOptions {
                priority: 127,
                request_id: 1,
                group_order: GroupOrder::Ascending,
                default_ttl: Duration::from_secs(5),
            },
        )
        .unwrap();

        assert!(!handler.can_publish());
        assert!(handler.status().is_ok());
    }
}
