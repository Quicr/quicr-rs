// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::fmt;

/// Protocol error code received from or sent to a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorCode {
    /// An unspecified internal implementation failure.
    InternalError,
    /// The requester is not authorized.
    Unauthorized,
    /// The operation exceeded its time limit.
    Timeout,
    /// The requested operation or feature is unsupported.
    NotSupported,
    /// The authorization token is malformed.
    MalformedAuthToken,
    /// The authorization token has expired.
    ExpiredAuthToken,
    /// The endpoint is shutting down or no longer accepting work.
    GoingAway,
    /// The requested resource does not exist.
    DoesNotExist,
    /// The requested object range is invalid.
    InvalidRange,
    /// The track name or track metadata is malformed.
    MalformedTrack,
    /// An equivalent subscription already exists.
    DuplicateSubscription,
    /// The endpoint is no longer interested in the request.
    Uninterested,
    /// A namespace prefix overlaps another registered prefix.
    PrefixOverlap,
    /// A joining fetch refers to an invalid request identifier.
    InvalidJoiningRequestId,
    /// The request should be redirected.
    Redirect,
    /// A protocol code not recognized by this crate.
    ///
    /// The contained numeric value is preserved for round-tripping.
    Unknown(u64),
}

impl ErrorCode {
    pub(crate) fn from_native(value: quicr_sys::quicr_error_code_t) -> Self {
        match value {
            value if value == quicr_sys::QUICR_ERROR_INTERNAL_ERROR as u64 => Self::InternalError,
            value if value == quicr_sys::QUICR_ERROR_UNAUTHORIZED as u64 => Self::Unauthorized,
            value if value == quicr_sys::QUICR_ERROR_TIMEOUT as u64 => Self::Timeout,
            value if value == quicr_sys::QUICR_ERROR_NOT_SUPPORTED as u64 => Self::NotSupported,
            value if value == quicr_sys::QUICR_ERROR_MALFORMED_AUTH_TOKEN as u64 => {
                Self::MalformedAuthToken
            }
            value if value == quicr_sys::QUICR_ERROR_EXPIRED_AUTH_TOKEN as u64 => {
                Self::ExpiredAuthToken
            }
            value if value == quicr_sys::QUICR_ERROR_GOING_AWAY as u64 => Self::GoingAway,
            value if value == quicr_sys::QUICR_ERROR_DOES_NOT_EXIST as u64 => Self::DoesNotExist,
            value if value == quicr_sys::QUICR_ERROR_INVALID_RANGE as u64 => Self::InvalidRange,
            value if value == quicr_sys::QUICR_ERROR_MALFORMED_TRACK as u64 => Self::MalformedTrack,
            value if value == quicr_sys::QUICR_ERROR_DUPLICATE_SUBSCRIPTION as u64 => {
                Self::DuplicateSubscription
            }
            value if value == quicr_sys::QUICR_ERROR_UNINTERESTED as u64 => Self::Uninterested,
            value if value == quicr_sys::QUICR_ERROR_PREFIX_OVERLAP as u64 => Self::PrefixOverlap,
            value if value == quicr_sys::QUICR_ERROR_INVALID_JOINING_REQUEST_ID as u64 => {
                Self::InvalidJoiningRequestId
            }
            value if value == quicr_sys::QUICR_ERROR_REDIRECT as u64 => Self::Redirect,
            value => Self::Unknown(value),
        }
    }

    pub(crate) fn native(self) -> quicr_sys::quicr_error_code_t {
        match self {
            Self::InternalError => quicr_sys::QUICR_ERROR_INTERNAL_ERROR as _,
            Self::Unauthorized => quicr_sys::QUICR_ERROR_UNAUTHORIZED as _,
            Self::Timeout => quicr_sys::QUICR_ERROR_TIMEOUT as _,
            Self::NotSupported => quicr_sys::QUICR_ERROR_NOT_SUPPORTED as _,
            Self::MalformedAuthToken => quicr_sys::QUICR_ERROR_MALFORMED_AUTH_TOKEN as _,
            Self::ExpiredAuthToken => quicr_sys::QUICR_ERROR_EXPIRED_AUTH_TOKEN as _,
            Self::GoingAway => quicr_sys::QUICR_ERROR_GOING_AWAY as _,
            Self::DoesNotExist => quicr_sys::QUICR_ERROR_DOES_NOT_EXIST as _,
            Self::InvalidRange => quicr_sys::QUICR_ERROR_INVALID_RANGE as _,
            Self::MalformedTrack => quicr_sys::QUICR_ERROR_MALFORMED_TRACK as _,
            Self::DuplicateSubscription => quicr_sys::QUICR_ERROR_DUPLICATE_SUBSCRIPTION as _,
            Self::Uninterested => quicr_sys::QUICR_ERROR_UNINTERESTED as _,
            Self::PrefixOverlap => quicr_sys::QUICR_ERROR_PREFIX_OVERLAP as _,
            Self::InvalidJoiningRequestId => quicr_sys::QUICR_ERROR_INVALID_JOINING_REQUEST_ID as _,
            Self::Redirect => quicr_sys::QUICR_ERROR_REDIRECT as _,
            Self::Unknown(value) => value as _,
        }
    }
}

/// Protocol-level failure with an optional peer-provided explanation.
///
/// [`reason`](Self::reason) is owned UTF-8 text. Invalid UTF-8 received from
/// the native library is replaced lossily with the Unicode replacement
/// character.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolError {
    /// Machine-readable protocol error code.
    pub code: ErrorCode,
    /// Human-readable explanation, or an empty string if none was supplied.
    pub reason: String,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.reason.is_empty() {
            write!(formatter, "protocol error {:?}", self.code)
        } else {
            write!(formatter, "protocol error {:?}: {}", self.code, self.reason)
        }
    }
}

impl std::error::Error for ProtocolError {}

pub(crate) unsafe fn get_protocol_error(
    get: impl Fn(
        *mut quicr_sys::quicr_error_code_t,
        *mut std::ffi::c_char,
        *mut usize,
    ) -> quicr_sys::quicr_status_t,
) -> Result<Option<ProtocolError>, ()> {
    let mut code = 0;
    let mut size = 0;
    let status = get(&mut code, std::ptr::null_mut(), &mut size);
    if status as u32 == quicr_sys::QUICR_STATUS_NOT_FOUND {
        return Ok(None);
    }
    if status as u32 != quicr_sys::QUICR_STATUS_OK
        && status as u32 != quicr_sys::QUICR_STATUS_BUFFER_TOO_SMALL
    {
        return Err(());
    }

    let reason = if size == 0 {
        String::new()
    } else {
        let mut bytes = vec![0_u8; size];
        let status = get(&mut code, bytes.as_mut_ptr().cast(), &mut size);
        if status as u32 != quicr_sys::QUICR_STATUS_OK {
            return Err(());
        }
        let length = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..length]).into_owned()
    };
    Ok(Some(ProtocolError {
        code: ErrorCode::from_native(code),
        reason,
    }))
}

#[cfg(test)]
mod tests {
    use super::ErrorCode;

    #[test]
    fn going_away_roundtrips() {
        let code = ErrorCode::from_native(ErrorCode::GoingAway.native());

        assert_eq!(code, ErrorCode::GoingAway);
    }
}
