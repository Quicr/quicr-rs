// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{
    ffi::{CString, c_char},
    ptr::{self, NonNull},
    sync::Arc,
    time::Duration,
};

use crate::{
    ErrorCode, Filter, GroupOrder, Location, SubscribeTrackHandler, TrackExtensions,
    TrackNamespace, handler::HandlerOperationError, track_name::NativeTrackNamespace,
};

/// A callback response.
///
/// A callback must construct and return this value before the callback returns. The binding
/// currently supports only [`Reply::Immediate`]; the wrapper reserves space for a future deferred
/// responder without promising that libquicr can defer any particular callback.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
#[non_exhaustive]
pub enum Reply<T, E> {
    /// A success or error that is applied while the callback is returning.
    Immediate(Result<T, E>),
}

impl<T, E> Reply<T, E> {
    /// Wraps an immediately available callback result.
    pub fn immediate(result: Result<T, E>) -> Self {
        Self::Immediate(result)
    }

    /// Constructs an immediate successful reply.
    pub fn ok(value: T) -> Self {
        Self::Immediate(Ok(value))
    }

    /// Constructs an immediate error reply.
    pub fn err(error: E) -> Self {
        Self::Immediate(Err(error))
    }

    /// Consumes the reply and returns its success-or-error result.
    pub fn into_result(self) -> Result<T, E> {
        match self {
            Self::Immediate(result) => result,
        }
    }

    /// Borrows the success-or-error result contained by this reply.
    pub fn as_result(&self) -> &Result<T, E> {
        match self {
            Self::Immediate(result) => result,
        }
    }
}

impl<T, E> From<Result<T, E>> for Reply<T, E> {
    fn from(result: Result<T, E>) -> Self {
        Self::immediate(result)
    }
}

/// Optional routing information attached to a redirect error.
///
/// Each field is independently optional. Which combinations are meaningful depends on the
/// callback being answered. Namespace-list callbacks reject redirects containing
/// [`track_name`](Self::track_name). Strings must not contain an interior NUL byte.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Redirect {
    /// A new connection URI, if the peer should reconnect elsewhere.
    pub uri: Option<String>,
    /// A replacement track namespace, if routing changes at namespace granularity.
    pub track_namespace: Option<TrackNamespace>,
    /// A replacement track name, represented as protocol bytes rather than UTF-8 text.
    pub track_name: Option<Vec<u8>>,
}

/// A rejected callback reply with a typed protocol error code.
///
/// Use [`ReplyError::new`] for non-redirect codes and [`ReplyError::redirect`] for redirect codes.
/// Constructors validate code/category combinations and strings before the error crosses the FFI
/// boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplyError<C> {
    code: C,
    reason: Option<String>,
    redirect: Option<Redirect>,
}

/// Indicates that a reply error cannot be represented safely or validly.
///
/// This includes mismatched redirect codes, unsupported outbound codes, and strings containing an
/// interior NUL byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidReplyError;

impl std::fmt::Display for InvalidReplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid reply error")
    }
}

impl std::error::Error for InvalidReplyError {}

/// Behavior required of an error-code type used by [`ReplyError`].
pub trait ReplyCode: Copy {
    /// Returns whether this code requires [`ReplyError::redirect`].
    fn is_redirect(self) -> bool;

    /// Returns the native internal-error code used when reply conversion fails.
    fn internal_error_code() -> u64;

    /// Returns whether this code may be sent to the peer.
    ///
    /// The default accepts every value. Implementations can reject values that are meaningful
    /// only when received, such as an unknown native code.
    fn is_valid_outbound(self) -> bool {
        true
    }
}

impl<C: ReplyCode> ReplyError<C> {
    /// Constructs a non-redirect error.
    ///
    /// Returns [`InvalidReplyError`] if `code` is a redirect code or is not valid outbound.
    pub fn new(code: C) -> Result<Self, InvalidReplyError> {
        if code.is_redirect() || !code.is_valid_outbound() {
            return Err(InvalidReplyError);
        }

        Ok(Self {
            code,
            reason: None,
            redirect: None,
        })
    }

    pub(crate) fn known(code: C) -> Self {
        debug_assert!(!code.is_redirect() && code.is_valid_outbound());
        Self {
            code,
            reason: None,
            redirect: None,
        }
    }

    /// Constructs a redirect error with validated routing details.
    ///
    /// Returns [`InvalidReplyError`] unless `code` is a redirect code, or when a string in
    /// `redirect` contains an interior NUL byte.
    pub fn redirect(code: C, redirect: Redirect) -> Result<Self, InvalidReplyError> {
        if !code.is_redirect() || !redirect_strings_valid(&redirect) {
            return Err(InvalidReplyError);
        }

        Ok(Self {
            code,
            reason: None,
            redirect: Some(redirect),
        })
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

    /// Returns the protocol error code.
    pub fn code(&self) -> C {
        self.code
    }

    /// Returns the optional human-readable reason.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Returns redirect routing details, if this is a redirect error.
    pub fn redirect_details(&self) -> Option<&Redirect> {
        self.redirect.as_ref()
    }
}

fn redirect_strings_valid(redirect: &Redirect) -> bool {
    redirect
        .uri
        .as_deref()
        .map(CString::new)
        .transpose()
        .is_ok()
}

pub(crate) struct NativeReplyErrorBacking {
    reason: Option<CString>,
    redirect: Option<Box<quicr_sys::quicr_redirect_t>>,
    _uri: Option<CString>,
    _track_namespace: Option<NativeTrackNamespace>,
    _track_name: Option<Vec<u8>>,
    _track_name_span: Option<Box<quicr_sys::quicr_byte_span_t>>,
}

unsafe impl Send for NativeReplyErrorBacking {}

impl NativeReplyErrorBacking {
    pub(crate) fn new<C>(error: &ReplyError<C>) -> Result<Self, ()> {
        let reason = error
            .reason
            .as_deref()
            .map(CString::new)
            .transpose()
            .map_err(|_| ())?;

        let mut uri = None;
        let mut track_namespace = None;
        let mut track_name = None;
        let mut track_name_span = None;

        let redirect = if let Some(value) = &error.redirect {
            uri = value
                .uri
                .as_deref()
                .map(CString::new)
                .transpose()
                .map_err(|_| ())?;

            track_namespace = match &value.track_namespace {
                Some(namespace) => Some(namespace.to_native().map_err(|_| ())?),
                None => None,
            };

            track_name = value.track_name.clone();
            track_name_span = track_name.as_ref().map(|value| {
                Box::new(quicr_sys::quicr_byte_span_t {
                    data: value.as_ptr(),
                    size: value.len(),
                })
            });

            Some(Box::new(quicr_sys::quicr_redirect_t {
                connect_uri: uri.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
                track_namespace: track_namespace
                    .as_ref()
                    .map_or(ptr::null(), |value| value.raw.cast_const()),
                track_name: track_name_span
                    .as_ref()
                    .map_or(ptr::null(), |value| &**value),
            }))
        } else {
            None
        };

        Ok(Self {
            reason,
            redirect,
            _uri: uri,
            _track_namespace: track_namespace,
            _track_name: track_name,
            _track_name_span: track_name_span,
        })
    }

    pub(crate) fn reason_ptr(&self) -> *const c_char {
        self.reason
            .as_ref()
            .map_or(ptr::null(), |value| value.as_ptr())
    }

    pub(crate) fn redirect_ptr(&self) -> *const quicr_sys::quicr_redirect_t {
        self.redirect.as_ref().map_or(ptr::null(), |value| &**value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
/// Error codes for request-oriented callbacks.
pub enum RequestErrorCode {
    /// The endpoint could not process the request because of an internal failure.
    InternalError,
    /// The requester is not authorized.
    Unauthorized,
    /// The request timed out.
    Timeout,
    /// The requested operation is not supported.
    NotSupported,
    /// The authorization token is malformed.
    MalformedAuthToken,
    /// The authorization token has expired.
    ExpiredAuthToken,
    /// The requested resource does not exist.
    DoesNotExist,
    /// The requested object range is invalid.
    InvalidRange,
    /// The track name or description is malformed.
    MalformedTrack,
    /// A subscription for the same request already exists.
    DuplicateSubscription,
    /// The endpoint is no longer interested in the request.
    Uninterested,
    /// The requested namespace prefix overlaps an incompatible subscription.
    PrefixOverlap,
    /// A joining fetch references an invalid request identifier.
    InvalidJoiningRequestId,
    /// The requester should retry using redirect details.
    Redirect,
    /// The endpoint is going away and is not accepting the request.
    GoingAway,
}

impl RequestErrorCode {
    pub(crate) fn native(self) -> quicr_sys::quicr_request_error_code_t {
        match self {
            Self::InternalError => quicr_sys::QUICR_REQUEST_ERROR_INTERNAL_ERROR as _,
            Self::Unauthorized => quicr_sys::QUICR_REQUEST_ERROR_UNAUTHORIZED as _,
            Self::Timeout => quicr_sys::QUICR_REQUEST_ERROR_TIMEOUT as _,
            Self::NotSupported => quicr_sys::QUICR_REQUEST_ERROR_NOT_SUPPORTED as _,
            Self::MalformedAuthToken => quicr_sys::QUICR_REQUEST_ERROR_MALFORMED_AUTH_TOKEN as _,
            Self::ExpiredAuthToken => quicr_sys::QUICR_REQUEST_ERROR_EXPIRED_AUTH_TOKEN as _,
            Self::DoesNotExist => quicr_sys::QUICR_REQUEST_ERROR_DOES_NOT_EXIST as _,
            Self::InvalidRange => quicr_sys::QUICR_REQUEST_ERROR_INVALID_RANGE as _,
            Self::MalformedTrack => quicr_sys::QUICR_REQUEST_ERROR_MALFORMED_TRACK as _,
            Self::DuplicateSubscription => {
                quicr_sys::QUICR_REQUEST_ERROR_DUPLICATE_SUBSCRIPTION as _
            }
            Self::Uninterested => quicr_sys::QUICR_REQUEST_ERROR_UNINTERESTED as _,
            Self::PrefixOverlap => quicr_sys::QUICR_REQUEST_ERROR_PREFIX_OVERLAP as _,
            Self::InvalidJoiningRequestId => {
                quicr_sys::QUICR_REQUEST_ERROR_INVALID_JOINING_REQUEST_ID as _
            }
            Self::Redirect => quicr_sys::QUICR_REQUEST_ERROR_REDIRECT as _,
            Self::GoingAway => quicr_sys::QUICR_REQUEST_ERROR_GOING_AWAY as _,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
/// Error codes for an incoming publish request.
pub enum PublishErrorCode {
    /// The endpoint could not process the publish because of an internal failure.
    InternalError,
    /// Incoming publishes are not supported.
    NotSupported,
    /// The publisher is not authorized.
    NotAuthorized,
    /// The publish was rejected for an application-defined reason.
    Rejected,
}

impl PublishErrorCode {
    pub(crate) fn native(self) -> quicr_sys::quicr_publish_error_code_t {
        match self {
            Self::InternalError => quicr_sys::QUICR_PUBLISH_ERROR_INTERNAL_ERROR as _,
            Self::NotSupported => quicr_sys::QUICR_PUBLISH_ERROR_NOT_SUPPORTED as _,
            Self::NotAuthorized => quicr_sys::QUICR_PUBLISH_ERROR_NOT_AUTHORIZED as _,
            Self::Rejected => quicr_sys::QUICR_PUBLISH_ERROR_REJECTED as _,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
/// Error codes for an incoming namespace publication.
pub enum PublishNamespaceErrorCode {
    /// The endpoint could not process the namespace because of an internal failure.
    InternalError,
    /// The publisher should use redirect details.
    Redirect,
}

impl PublishNamespaceErrorCode {
    pub(crate) fn native(self) -> quicr_sys::quicr_publish_namespace_error_code_t {
        match self {
            Self::InternalError => quicr_sys::QUICR_PUBLISH_NAMESPACE_ERROR_INTERNAL_ERROR as _,
            Self::Redirect => quicr_sys::QUICR_PUBLISH_NAMESPACE_ERROR_REDIRECT as _,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
/// Error codes for an incoming fetch.
pub enum FetchErrorCode {
    /// The requested object range is invalid.
    InvalidRange,
    /// No objects satisfy the fetch.
    NoObjects,
    /// The endpoint could not process the fetch because of an internal failure.
    InternalError,
    /// The requester should retry using redirect details.
    Redirect,
}

impl FetchErrorCode {
    pub(crate) fn native(self) -> quicr_sys::quicr_fetch_error_code_t {
        match self {
            Self::InvalidRange => quicr_sys::QUICR_FETCH_ERROR_INVALID_RANGE as _,
            Self::NoObjects => quicr_sys::QUICR_FETCH_ERROR_NO_OBJECTS as _,
            Self::InternalError => quicr_sys::QUICR_FETCH_ERROR_INTERNAL_ERROR as _,
            Self::Redirect => quicr_sys::QUICR_FETCH_ERROR_REDIRECT as _,
        }
    }
}

/// A request rejection returned by request-oriented callbacks.
pub type RequestError = ReplyError<RequestErrorCode>;
/// A rejection returned by a publish callback.
pub type PublishError = ReplyError<PublishErrorCode>;
/// A rejection returned by a publish-namespace callback.
pub type PublishNamespaceError = ReplyError<PublishNamespaceErrorCode>;
/// A rejection returned by a fetch callback.
pub type FetchError = ReplyError<FetchErrorCode>;
/// A general session-level callback rejection.
pub type SessionError = ReplyError<ErrorCode>;

impl ReplyCode for RequestErrorCode {
    fn is_redirect(self) -> bool {
        self == Self::Redirect
    }

    fn internal_error_code() -> u64 {
        Self::InternalError.native() as u64
    }
}

impl ReplyCode for PublishErrorCode {
    fn is_redirect(self) -> bool {
        false
    }

    fn internal_error_code() -> u64 {
        Self::InternalError.native() as u64
    }
}

impl ReplyCode for PublishNamespaceErrorCode {
    fn is_redirect(self) -> bool {
        self == Self::Redirect
    }

    fn internal_error_code() -> u64 {
        Self::InternalError.native() as u64
    }
}

impl ReplyCode for FetchErrorCode {
    fn is_redirect(self) -> bool {
        self == Self::Redirect
    }

    fn internal_error_code() -> u64 {
        Self::InternalError.native() as u64
    }
}

impl ReplyCode for ErrorCode {
    fn is_redirect(self) -> bool {
        self == Self::Redirect
    }

    fn internal_error_code() -> u64 {
        Self::InternalError.native()
    }

    fn is_valid_outbound(self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

/// Status information returned for a track.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrackStatusResponse {
    /// The largest known object location, or `None` when no location is advertised.
    pub largest_location: Option<Location>,
    /// Protocol extensions describing the track.
    pub track_properties: TrackExtensions,
}

/// Acceptance details returned from a subscribe callback.
pub struct SubscribeResponse {
    /// Current status of the subscribed track.
    pub track_status: TrackStatusResponse,
    /// Whether the publication was initiated by the publisher.
    pub is_publisher_initiated: bool,
    /// Optional lifetime of the subscription.
    ///
    /// Values that cannot be represented as native milliseconds cause reply conversion to fail
    /// with an internal-error response.
    pub expires: Option<Duration>,
}

/// Acceptance details returned from a fetch callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchResponse {
    /// The largest object location the publisher expects the fetch to include.
    pub largest_location: Option<Location>,
    /// The publisher's default order for delivering groups.
    pub publisher_default_group_order: GroupOrder,
}

/// Optional attributes returned when accepting a publish.
///
/// A `None` field leaves that attribute unspecified. Durations are converted to native
/// milliseconds and must fit in `u64`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PublishOkAttributes {
    /// Subscriber priority to apply to the accepted publish.
    pub subscriber_priority: Option<u8>,
    /// Group delivery order to request.
    pub group_order: Option<GroupOrder>,
    /// Object filter to apply.
    pub filter: Option<Filter>,
    /// Whether forwarding is enabled.
    pub forward: Option<bool>,
    /// Delivery timeout for a subgroup.
    pub subgroup_delivery_timeout: Option<Duration>,
    /// Delivery timeout for an object.
    pub object_delivery_timeout: Option<Duration>,
    /// Request identifier used for new-group requests.
    pub new_group_request_id: Option<u64>,
}

/// Acceptance response for an incoming publish.
///
/// The response transfers a clone-backed native reference to [`handler`](Self::handler). The
/// session manager retains the handler while the accepted publish remains active and retires it
/// when completion, unsubscription, session removal, or manager teardown is observed. Exact
/// callback timing remains controlled by libquicr.
pub struct PublishResponse {
    /// Attributes to apply to the accepted publish.
    pub attributes: PublishOkAttributes,
    /// Handler that receives the published track.
    pub handler: SubscribeTrackHandler,
}

impl PublishResponse {
    /// Constructs an acceptance response with default [`PublishOkAttributes`].
    pub fn new(handler: impl Into<SubscribeTrackHandler>) -> Self {
        Self {
            attributes: PublishOkAttributes::default(),
            handler: handler.into(),
        }
    }

    pub(crate) fn into_native(self) -> Result<NativePublishResponse, HandlerOperationError> {
        let attributes = self.attributes;
        let mut raw = std::ptr::null_mut();

        check(unsafe {
            quicr_sys::quicr_publish_response_create(self.handler.inner.raw, &mut raw)
        })?;

        let raw = NonNull::new(raw).ok_or(HandlerOperationError::InternalError)?;

        let response = NativePublishResponse {
            raw,
            handler: Some(self.handler),
        };

        if let Some(priority) = attributes.subscriber_priority {
            check(unsafe {
                quicr_sys::quicr_publish_response_set_subscriber_priority(
                    response.raw.as_ptr(),
                    priority,
                )
            })?;
        }

        if let Some(group_order) = attributes.group_order {
            check(unsafe {
                quicr_sys::quicr_publish_response_set_group_order(
                    response.raw.as_ptr(),
                    group_order.native(),
                )
            })?;
        }

        if let Some(filter) = attributes.filter {
            let filter = filter.native();
            check(unsafe {
                quicr_sys::quicr_publish_response_set_filter(response.raw.as_ptr(), &filter)
            })?;
        }

        if let Some(forward) = attributes.forward {
            check(unsafe {
                quicr_sys::quicr_publish_response_set_forward(response.raw.as_ptr(), forward)
            })?;
        }

        if let Some(timeout) = attributes.subgroup_delivery_timeout {
            let timeout = duration_millis(timeout)?;
            check(unsafe {
                quicr_sys::quicr_publish_response_set_subgroup_delivery_timeout(
                    response.raw.as_ptr(),
                    timeout,
                )
            })?;
        }

        if let Some(timeout) = attributes.object_delivery_timeout {
            let timeout = duration_millis(timeout)?;
            check(unsafe {
                quicr_sys::quicr_publish_response_set_object_delivery_timeout(
                    response.raw.as_ptr(),
                    timeout,
                )
            })?;
        }

        if let Some(request_id) = attributes.new_group_request_id {
            check(unsafe {
                quicr_sys::quicr_publish_response_set_new_group_request_id(
                    response.raw.as_ptr(),
                    request_id,
                )
            })?;
        }

        Ok(response)
    }
}

pub(crate) struct NativePublishResponse {
    raw: NonNull<quicr_sys::quicr_publish_response_t>,
    handler: Option<SubscribeTrackHandler>,
}

unsafe impl Send for NativePublishResponse {}

impl NativePublishResponse {
    pub(crate) fn as_ptr(&self) -> *const quicr_sys::quicr_publish_response_t {
        self.raw.as_ptr()
    }

    pub(crate) fn handler(&self) -> SubscribeTrackHandler {
        let handler = self
            .handler
            .as_ref()
            .expect("native publish response handler was already taken");
        SubscribeTrackHandler {
            inner: Arc::clone(&handler.inner),
        }
    }
}

impl Drop for NativePublishResponse {
    fn drop(&mut self) {
        unsafe { quicr_sys::quicr_publish_response_destroy(self.raw.as_ptr()) };
    }
}

fn check(status: quicr_sys::quicr_status_t) -> Result<(), HandlerOperationError> {
    if status == quicr_sys::QUICR_STATUS_OK as _ {
        Ok(())
    } else {
        Err(HandlerOperationError::from_status(status))
    }
}

fn duration_millis(duration: Duration) -> Result<u64, HandlerOperationError> {
    duration
        .as_millis()
        .try_into()
        .map_err(|_| HandlerOperationError::InvalidArgument)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        ErrorCode, FetchError, FetchErrorCode, FullTrackName, GroupOrder, Redirect, SessionError,
        SubscribeTrackHandler, SubscribeTrackOptions, TrackNamespace,
    };

    use super::{PublishResponse, Reply};

    #[test]
    fn immediate_reply_preserves_result() {
        assert_eq!(Reply::<_, ()>::ok(42).into_result(), Ok(42));
        assert_eq!(
            Reply::<(), _>::err("rejected").into_result(),
            Err("rejected")
        );
        assert_eq!(Reply::<_, &str>::from(Ok(7)).as_result(), &Ok(7),);
    }

    #[test]
    fn native_publish_response_retains_handler_callbacks() {
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

        let response = PublishResponse::new(handler).into_native().unwrap();
        assert_eq!(Arc::strong_count(&inner), 2);

        drop(response);
        assert_eq!(Arc::strong_count(&inner), 1);
    }

    #[test]
    fn rejects_invalid_reply_strings() {
        assert!(
            FetchError::new(FetchErrorCode::InternalError)
                .unwrap()
                .with_reason("bad\0reason")
                .is_err()
        );
        assert!(
            FetchError::redirect(
                FetchErrorCode::Redirect,
                Redirect {
                    uri: Some("moq://bad\0uri".into()),
                    ..Redirect::default()
                },
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_invalid_non_redirect_construction() {
        assert!(FetchError::new(FetchErrorCode::Redirect).is_err());
        assert!(SessionError::new(ErrorCode::Redirect).is_err());
        assert!(SessionError::new(ErrorCode::Unknown(9_999)).is_err());
    }
}
