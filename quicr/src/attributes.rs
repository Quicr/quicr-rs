// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{fmt, slice, time::Duration};

use crate::{
    FetchEndLocation, Filter, FilterKind, FullTrackName, GroupOrder, Location, TrackExtensions,
};

const OK: quicr_sys::quicr_status_t = quicr_sys::QUICR_STATUS_OK as _;

/// Indicates that callback attributes could not be copied or validated.
///
/// This is returned for missing native data, unknown enum discriminants,
/// inconsistent filters, or malformed byte spans.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributeError;

impl fmt::Display for AttributeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid callback attributes")
    }
}

impl std::error::Error for AttributeError {}

/// Operation encoded by an [`AuthorizationToken`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenAliasType {
    /// Deletes the referenced token alias.
    Delete,
    /// Registers the token value under an alias.
    Register,
    /// Uses a previously registered alias.
    UseAlias,
    /// Carries and uses the token value directly.
    UseValue,
}

/// Owned authorization-token data copied from an inbound callback.
///
/// Token values are arbitrary bytes, not UTF-8 text. The custom [`Debug`]
/// implementation redacts [`value`](Self::value).
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizationToken {
    /// Alias operation represented by this token.
    pub alias_type: TokenAliasType,
    /// Token alias, when supplied by the peer.
    pub alias: Option<u64>,
    /// Protocol-defined token type, when supplied by the peer.
    pub token_type: Option<u64>,
    /// Owned, opaque token bytes.
    pub value: Vec<u8>,
}

impl fmt::Debug for AuthorizationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationToken")
            .field("alias_type", &self.alias_type)
            .field("alias", &self.alias)
            .field("token_type", &self.token_type)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Owned attributes of an inbound publish request.
///
/// All callback-scoped native data, including names, tokens, and extension
/// values, is copied into this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishAttributes {
    /// Full name of the published track.
    pub track_full_name: FullTrackName,
    /// Session-scoped alias assigned to the track.
    pub track_alias: u64,
    /// Authorization tokens supplied with the request.
    pub auth_tokens: Vec<AuthorizationToken>,
    /// Requested publication lifetime, if present.
    ///
    /// The protocol value has millisecond precision.
    pub expires: Option<Duration>,
    /// Largest object known to the publisher, if advertised.
    pub largest_object: Option<Location>,
    /// Whether objects should be forwarded immediately.
    pub forward: bool,
    /// Publisher's default order for groups.
    pub default_publisher_group_order: GroupOrder,
    /// Whether the publisher supports dynamically requested groups.
    pub dynamic_groups: bool,
    /// Publisher priority; lower protocol values represent higher priority.
    pub publisher_priority: u8,
    /// Maximum cache retention duration, if advertised.
    ///
    /// The protocol value has millisecond precision.
    pub max_cache_duration: Option<Duration>,
    /// Delivery timeout, if advertised.
    ///
    /// The protocol value has millisecond precision.
    pub delivery_timeout: Option<Duration>,
    /// Owned mutable and immutable track properties.
    pub track_properties: TrackExtensions,
}

impl PublishAttributes {
    pub(crate) unsafe fn copy_from_raw(
        raw: *const quicr_sys::quicr_publish_attributes_t,
    ) -> Result<Self, AttributeError> {
        if raw.is_null() {
            return Err(AttributeError);
        }

        let track_full_name = unsafe {
            FullTrackName::copy_from_raw(quicr_sys::quicr_publish_attributes_full_track_name(raw))
        }
        .ok_or(AttributeError)?;

        let token_count = unsafe { quicr_sys::quicr_publish_attributes_auth_token_count(raw) };
        let mut auth_tokens = Vec::with_capacity(token_count);

        for index in 0..token_count {
            let mut token: quicr_sys::quicr_token_t = unsafe { std::mem::zeroed() };
            if unsafe { quicr_sys::quicr_publish_attributes_auth_token(raw, index, &mut token) }
                != OK
            {
                return Err(AttributeError);
            }

            auth_tokens.push(copy_token(token)?);
        }

        let expires = optional_duration(|value| unsafe {
            quicr_sys::quicr_publish_attributes_expires(raw, value)
        });

        let mut largest_object = quicr_sys::quicr_location_t {
            group: 0,
            object: 0,
        };
        let has_largest_object =
            unsafe { quicr_sys::quicr_publish_attributes_largest_object(raw, &mut largest_object) };

        let mut group_order = 0;
        if unsafe { quicr_sys::quicr_publish_attributes_group_order(raw, &mut group_order) } != OK {
            return Err(AttributeError);
        }

        let track_extensions = unsafe {
            TrackExtensions::copy_from_raw(quicr_sys::quicr_publish_attributes_track_extensions(
                raw,
            ))
        }
        .map_err(|_| AttributeError)?;

        Ok(Self {
            track_full_name,
            track_alias: unsafe { quicr_sys::quicr_publish_attributes_track_alias(raw) },
            auth_tokens,
            expires,
            largest_object: has_largest_object.then_some(Location {
                group: largest_object.group,
                object: largest_object.object,
            }),
            forward: unsafe { quicr_sys::quicr_publish_attributes_forward(raw) },
            default_publisher_group_order: GroupOrder::from_native(group_order)
                .ok_or(AttributeError)?,
            dynamic_groups: unsafe { quicr_sys::quicr_publish_attributes_dynamic_groups(raw) },
            publisher_priority: unsafe {
                quicr_sys::quicr_publish_attributes_publisher_priority(raw)
            },
            max_cache_duration: optional_duration(|value| unsafe {
                quicr_sys::quicr_publish_attributes_max_cache_duration(raw, value)
            }),
            delivery_timeout: optional_duration(|value| unsafe {
                quicr_sys::quicr_publish_attributes_delivery_timeout(raw, value)
            }),
            track_properties: track_extensions,
        })
    }
}

/// Attributes of an inbound namespace-publish request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishNamespaceAttributes {
    /// Peer-assigned request identifier.
    pub request_id: u64,
}

impl PublishNamespaceAttributes {
    pub(crate) unsafe fn copy_from_raw(
        raw: *const quicr_sys::quicr_publish_namespace_attributes_t,
    ) -> Result<Self, AttributeError> {
        let raw = unsafe { raw.as_ref() }.ok_or(AttributeError)?;

        Ok(Self {
            request_id: raw.request_id,
        })
    }
}

/// Attributes of an inbound fetch with an explicit object range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandaloneFetchAttributes {
    /// Fetch priority; lower protocol values represent higher priority.
    pub priority: u8,
    /// Requested group order, or `None` when the peer left it unspecified.
    pub group_order: Option<GroupOrder>,
    /// Publisher's default group order.
    pub publisher_default_group_order: GroupOrder,
    /// Inclusive first object location.
    pub start_location: Location,
    /// Inclusive last location; its object may be omitted to include the group.
    pub end_location: FetchEndLocation,
}

impl StandaloneFetchAttributes {
    pub(crate) unsafe fn copy_from_raw(
        raw: *const quicr_sys::quicr_standalone_fetch_attributes_t,
    ) -> Result<Self, AttributeError> {
        let raw = unsafe { raw.as_ref() }.ok_or(AttributeError)?;

        Ok(Self {
            priority: raw.priority,
            group_order: GroupOrder::optional_from_native(raw.group_order)
                .map_err(|_| AttributeError)?,
            publisher_default_group_order: GroupOrder::from_native(
                raw.publisher_default_group_order,
            )
            .ok_or(AttributeError)?,
            start_location: Location {
                group: raw.start_location.group,
                object: raw.start_location.object,
            },
            end_location: FetchEndLocation {
                group: raw.end_location.group,
                object: raw
                    .end_location
                    .has_object
                    .then_some(raw.end_location.object),
            },
        })
    }
}

/// Attributes of an inbound fetch joined to another request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoiningFetchAttributes {
    /// Fetch priority; lower protocol values represent higher priority.
    pub priority: u8,
    /// Requested group order, or `None` when the peer left it unspecified.
    pub group_order: Option<GroupOrder>,
    /// Publisher's default group order.
    pub publisher_default_group_order: GroupOrder,
    /// Identifier of the subscription or fetch being joined.
    pub joining_request_id: u64,
    /// Whether [`joining_start`](Self::joining_start) is a relative group offset.
    pub relative: bool,
    /// Relative group offset when [`relative`](Self::relative) is `true`, or
    /// absolute starting group otherwise.
    pub joining_start: u64,
}

impl JoiningFetchAttributes {
    pub(crate) unsafe fn copy_from_raw(
        raw: *const quicr_sys::quicr_joining_fetch_attributes_t,
    ) -> Result<Self, AttributeError> {
        let raw = unsafe { raw.as_ref() }.ok_or(AttributeError)?;

        Ok(Self {
            priority: raw.priority,
            group_order: GroupOrder::optional_from_native(raw.group_order)
                .map_err(|_| AttributeError)?,
            publisher_default_group_order: GroupOrder::from_native(
                raw.publisher_default_group_order,
            )
            .ok_or(AttributeError)?,
            joining_request_id: raw.joining_request_id,
            relative: raw.relative,
            joining_start: raw.joining_start,
        })
    }
}

/// Owned attributes of an inbound subscription request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscribeAttributes {
    /// Subscription priority; lower protocol values represent higher priority.
    pub priority: u8,
    /// Requested group order, or `None` when the peer left it unspecified.
    pub group_order: Option<GroupOrder>,
    /// Publisher's default group order.
    pub publisher_default_group_order: GroupOrder,
    /// Maximum object delivery delay.
    ///
    /// The protocol value has millisecond precision.
    pub delivery_timeout: Duration,
    /// Requested subscription lifetime.
    ///
    /// The protocol value has millisecond precision.
    pub expires: Duration,
    /// Object or track selection filter, if supplied.
    pub filter: Option<Filter>,
    /// Whether objects should be forwarded immediately.
    pub forward: bool,
    /// Identifier of a dynamic new-group request, if present.
    pub new_group_request_id: Option<u64>,
    /// Whether the publisher initiated this subscription.
    pub is_publisher_initiated: bool,
    /// Starting object location reported for the subscription.
    pub start_location: Location,
    /// Time allowed to rendezvous with a publisher.
    ///
    /// The protocol value has millisecond precision.
    pub rendezvous_timeout: Duration,
}

impl SubscribeAttributes {
    pub(crate) unsafe fn copy_from_raw(
        raw: *const quicr_sys::quicr_subscribe_attributes_t,
    ) -> Result<Self, AttributeError> {
        if raw.is_null() {
            return Err(AttributeError);
        }

        let mut group_order = 0;
        let has_group_order =
            unsafe { quicr_sys::quicr_subscribe_attributes_group_order(raw, &mut group_order) };

        let mut publisher_group_order = 0;
        if unsafe {
            quicr_sys::quicr_subscribe_attributes_publisher_group_order(
                raw,
                &mut publisher_group_order,
            )
        } != OK
        {
            return Err(AttributeError);
        }

        let mut filter: quicr_sys::quicr_filter_t = unsafe { std::mem::zeroed() };
        if unsafe { quicr_sys::quicr_subscribe_attributes_filter(raw, &mut filter) } != OK {
            return Err(AttributeError);
        }

        let filter = Filter::from_native(filter).map_err(|_| AttributeError)?;

        let start = unsafe { quicr_sys::quicr_subscribe_attributes_start_location(raw) };

        Ok(Self {
            priority: unsafe { quicr_sys::quicr_subscribe_attributes_priority(raw) },
            group_order: has_group_order
                .then(|| GroupOrder::from_native(group_order))
                .flatten()
                .ok_or_if(has_group_order, AttributeError)?,
            publisher_default_group_order: GroupOrder::from_native(publisher_group_order)
                .ok_or(AttributeError)?,
            delivery_timeout: Duration::from_millis(unsafe {
                quicr_sys::quicr_subscribe_attributes_delivery_timeout(raw)
            }),
            expires: Duration::from_millis(unsafe {
                quicr_sys::quicr_subscribe_attributes_expires(raw)
            }),
            filter,
            forward: unsafe { quicr_sys::quicr_subscribe_attributes_forward(raw) },
            new_group_request_id: optional_u64(|value| unsafe {
                quicr_sys::quicr_subscribe_attributes_new_group_request_id(raw, value)
            }),
            is_publisher_initiated: unsafe {
                quicr_sys::quicr_subscribe_attributes_is_publisher_initiated(raw)
            },
            start_location: Location {
                group: start.group,
                object: start.object,
            },
            rendezvous_timeout: Duration::from_millis(unsafe {
                quicr_sys::quicr_subscribe_attributes_rendezvous_timeout(raw)
            }),
        })
    }
}

/// Attributes of an inbound namespace-subscription request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscribeNamespaceAttributes {
    /// Peer-assigned request identifier.
    pub request_id: u64,
    /// Declared filter kind, or `None` when no filter was supplied.
    pub filter_type: Option<FilterKind>,
    /// Parsed filter, required to agree with [`filter_type`](Self::filter_type).
    pub filter: Option<Filter>,
}

impl SubscribeNamespaceAttributes {
    pub(crate) unsafe fn copy_from_raw(
        raw: *const quicr_sys::quicr_subscribe_namespace_attributes_t,
    ) -> Result<Self, AttributeError> {
        if raw.is_null() {
            return Err(AttributeError);
        }

        let mut filter_type = 0;
        if unsafe {
            quicr_sys::quicr_subscribe_namespace_attributes_filter_type(raw, &mut filter_type)
        } != OK
        {
            return Err(AttributeError);
        }

        let filter_type = FilterKind::from_native(filter_type).map_err(|_| AttributeError)?;

        let mut filter: quicr_sys::quicr_filter_t = unsafe { std::mem::zeroed() };
        if unsafe { quicr_sys::quicr_subscribe_namespace_attributes_filter(raw, &mut filter) } != OK
        {
            return Err(AttributeError);
        }

        let filter = Filter::from_native(filter).map_err(|_| AttributeError)?;

        if filter_type != filter.as_ref().map(Filter::kind) {
            return Err(AttributeError);
        }

        Ok(Self {
            request_id: unsafe { quicr_sys::quicr_subscribe_namespace_attributes_request_id(raw) },
            filter_type,
            filter,
        })
    }
}

fn copy_token(token: quicr_sys::quicr_token_t) -> Result<AuthorizationToken, AttributeError> {
    let alias_type = match token.alias_type {
        value if value == quicr_sys::QUICR_TOKEN_ALIAS_TYPE_DELETE as _ => TokenAliasType::Delete,
        value if value == quicr_sys::QUICR_TOKEN_ALIAS_TYPE_REGISTER as _ => {
            TokenAliasType::Register
        }
        value if value == quicr_sys::QUICR_TOKEN_ALIAS_TYPE_USE_ALIAS as _ => {
            TokenAliasType::UseAlias
        }
        value if value == quicr_sys::QUICR_TOKEN_ALIAS_TYPE_USE_VALUE as _ => {
            TokenAliasType::UseValue
        }
        _ => return Err(AttributeError),
    };

    let value = if token.token_value.size == 0 {
        Vec::new()
    } else if token.token_value.data.is_null() {
        return Err(AttributeError);
    } else {
        unsafe { slice::from_raw_parts(token.token_value.data, token.token_value.size) }.to_vec()
    };

    Ok(AuthorizationToken {
        alias_type,
        alias: token.has_token_alias.then_some(token.token_alias),
        token_type: token.has_token_type.then_some(token.token_type),
        value,
    })
}

fn optional_u64(function: impl FnOnce(*mut u64) -> bool) -> Option<u64> {
    let mut value = 0;
    function(&mut value).then_some(value)
}

fn optional_duration(function: impl FnOnce(*mut u64) -> bool) -> Option<Duration> {
    optional_u64(function).map(Duration::from_millis)
}

trait OptionExt<T> {
    fn ok_or_if(self, condition: bool, error: AttributeError) -> Result<Option<T>, AttributeError>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_or_if(self, condition: bool, error: AttributeError) -> Result<Option<T>, AttributeError> {
        if condition && self.is_none() {
            Err(error)
        } else {
            Ok(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthorizationToken, TokenAliasType, copy_token};

    #[test]
    fn authorization_token_debug_is_redacted() {
        let token = AuthorizationToken {
            alias_type: TokenAliasType::UseValue,
            alias: None,
            token_type: Some(1),
            value: b"secret-token".to_vec(),
        };
        let debug = format!("{token:?}");
        assert!(!debug.contains("secret-token"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn authorization_token_copies_optional_fields_and_bytes() {
        let value = b"token";
        let token = quicr_sys::quicr_token_t {
            alias_type: quicr_sys::QUICR_TOKEN_ALIAS_TYPE_REGISTER as _,
            token_alias: 7,
            has_token_alias: true,
            token_type: 9,
            has_token_type: true,
            token_value: quicr_sys::quicr_byte_span_t {
                data: value.as_ptr(),
                size: value.len(),
            },
        };

        assert_eq!(
            copy_token(token).unwrap(),
            AuthorizationToken {
                alias_type: TokenAliasType::Register,
                alias: Some(7),
                token_type: Some(9),
                value: value.to_vec(),
            }
        );
    }

    #[test]
    fn authorization_token_rejects_invalid_native_values() {
        let invalid_alias = quicr_sys::quicr_token_t {
            alias_type: u64::MAX,
            ..unsafe { std::mem::zeroed() }
        };
        assert!(copy_token(invalid_alias).is_err());

        let invalid_value = quicr_sys::quicr_token_t {
            alias_type: quicr_sys::QUICR_TOKEN_ALIAS_TYPE_USE_VALUE as _,
            token_value: quicr_sys::quicr_byte_span_t {
                data: std::ptr::null(),
                size: 1,
            },
            ..unsafe { std::mem::zeroed() }
        };
        assert!(copy_token(invalid_value).is_err());
    }
}
