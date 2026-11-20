// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{collections::BTreeMap, ptr, slice, time::Duration};

/// Object extensions grouped by numeric extension type.
///
/// Each type can carry multiple ordered values. Values are owned arbitrary
/// bytes and are not interpreted as UTF-8.
pub type Extensions = BTreeMap<u64, Vec<Vec<u8>>>;

/// Absolute object location within a track.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Location {
    /// Group identifier.
    pub group: u64,
    /// Object identifier within the group.
    pub object: u64,
}

/// Inclusive end location for a fetch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FetchEndLocation {
    /// Final group identifier.
    pub group: u64,
    /// Final object in the group, or `None` to include the group without an
    /// explicit object bound.
    pub object: Option<u64>,
}

/// Ordering in which groups are delivered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GroupOrder {
    /// Delivers lower group identifiers first.
    Ascending,
    /// Delivers higher group identifiers first.
    Descending,
}

impl GroupOrder {
    pub(crate) fn native(self) -> quicr_sys::quicr_group_order_t {
        match self {
            Self::Ascending => quicr_sys::QUICR_GROUP_ORDER_ASCENDING as _,
            Self::Descending => quicr_sys::QUICR_GROUP_ORDER_DESCENDING as _,
        }
    }

    pub(crate) fn from_native(value: quicr_sys::quicr_group_order_t) -> Option<Self> {
        match value {
            value if value == quicr_sys::QUICR_GROUP_ORDER_ASCENDING as _ => Some(Self::Ascending),
            value if value == quicr_sys::QUICR_GROUP_ORDER_DESCENDING as _ => {
                Some(Self::Descending)
            }
            _ => None,
        }
    }

    pub(crate) fn optional_from_native(
        value: quicr_sys::quicr_group_order_t,
    ) -> Result<Option<Self>, ()> {
        if value == quicr_sys::QUICR_GROUP_ORDER_UNSPECIFIED as _ {
            return Ok(None);
        }

        Self::from_native(value).map(Some).ok_or(())
    }
}

/// QUIC delivery mode for a track's objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TrackMode {
    /// Delivers each object in a QUIC datagram.
    Datagram,
    /// Delivers objects over QUIC streams.
    Stream,
}

/// Encoding rule for a subgroup identifier in a stream header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SubgroupIdType {
    /// Uses subgroup identifier zero.
    Zero,
    /// Derives the subgroup identifier from the first object.
    FirstObject,
    /// Encodes the subgroup identifier explicitly.
    Explicit,
    /// Uses the protocol's reserved subgroup-ID mode.
    Reserved,
}

/// Flags and subgroup-ID encoding reported for an object stream header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamHeaderProperties {
    /// Whether the stream header carries extensions.
    pub extensions: bool,
    /// How the subgroup identifier is represented.
    pub subgroup_id_type: SubgroupIdType,
    /// Whether the stream marks the end of its group.
    pub end_of_group: bool,
    /// Whether the stream uses the default priority.
    pub default_priority: bool,
    /// Whether this header describes the subgroup's first object.
    pub first_object: bool,
}

impl StreamHeaderProperties {
    pub(crate) fn native(self) -> quicr_sys::quicr_stream_header_properties_t {
        let subgroup_id_mode = match self.subgroup_id_type {
            SubgroupIdType::Zero => quicr_sys::QUICR_SUBGROUP_ID_TYPE_IS_ZERO,
            SubgroupIdType::FirstObject => quicr_sys::QUICR_SUBGROUP_ID_TYPE_SET_FROM_FIRST_OBJECT,
            SubgroupIdType::Explicit => quicr_sys::QUICR_SUBGROUP_ID_TYPE_EXPLICIT,
            SubgroupIdType::Reserved => quicr_sys::QUICR_SUBGROUP_ID_TYPE_RESERVED,
        };
        quicr_sys::quicr_stream_header_properties_t {
            extensions: self.extensions,
            subgroup_id_mode: subgroup_id_mode as _,
            end_of_group: self.end_of_group,
            default_priority: self.default_priority,
            first_object: self.first_object,
        }
    }

    pub(crate) unsafe fn from_native(
        properties: &quicr_sys::quicr_stream_header_properties_t,
    ) -> Option<Self> {
        let subgroup_id_type = match properties.subgroup_id_mode {
            value if value == quicr_sys::QUICR_SUBGROUP_ID_TYPE_IS_ZERO as _ => {
                SubgroupIdType::Zero
            }
            value if value == quicr_sys::QUICR_SUBGROUP_ID_TYPE_SET_FROM_FIRST_OBJECT as _ => {
                SubgroupIdType::FirstObject
            }
            value if value == quicr_sys::QUICR_SUBGROUP_ID_TYPE_EXPLICIT as _ => {
                SubgroupIdType::Explicit
            }
            value if value == quicr_sys::QUICR_SUBGROUP_ID_TYPE_RESERVED as _ => {
                SubgroupIdType::Reserved
            }
            _ => return None,
        };
        Some(Self {
            extensions: properties.extensions,
            subgroup_id_type,
            end_of_group: properties.end_of_group,
            default_priority: properties.default_priority,
            first_object: properties.first_object,
        })
    }
}

impl TrackMode {
    pub(crate) fn native(self) -> quicr_sys::quicr_track_mode_t {
        match self {
            Self::Datagram => quicr_sys::QUICR_TRACK_MODE_DATAGRAM as _,
            Self::Stream => quicr_sys::QUICR_TRACK_MODE_STREAM as _,
        }
    }

    pub(crate) fn from_native(value: quicr_sys::quicr_track_mode_t) -> Option<Self> {
        match value {
            value if value == quicr_sys::QUICR_TRACK_MODE_DATAGRAM as _ => Some(Self::Datagram),
            value if value == quicr_sys::QUICR_TRACK_MODE_STREAM as _ => Some(Self::Stream),
            _ => None,
        }
    }
}

/// Availability or terminal status represented by object metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum ObjectStatus {
    /// The object is available and may carry payload bytes.
    #[default]
    Available,
    /// The requested object does not exist.
    DoesNotExist,
    /// Marks the end of a group.
    EndOfGroup,
    /// Marks the end of the track.
    EndOfTrack,
    /// Marks the end of a subgroup.
    EndOfSubgroup,
}

impl ObjectStatus {
    pub(crate) fn native(self) -> quicr_sys::quicr_object_status_t {
        match self {
            Self::Available => quicr_sys::QUICR_OBJECT_STATUS_AVAILABLE as _,
            Self::DoesNotExist => quicr_sys::QUICR_OBJECT_STATUS_DOES_NOT_EXIST as _,
            Self::EndOfGroup => quicr_sys::QUICR_OBJECT_STATUS_END_OF_GROUP as _,
            Self::EndOfTrack => quicr_sys::QUICR_OBJECT_STATUS_END_OF_TRACK as _,
            Self::EndOfSubgroup => quicr_sys::QUICR_OBJECT_STATUS_END_OF_SUBGROUP as _,
        }
    }

    pub(crate) fn from_native(status: quicr_sys::quicr_object_status_t) -> Option<Self> {
        match status {
            value if value == quicr_sys::QUICR_OBJECT_STATUS_AVAILABLE as _ => {
                Some(Self::Available)
            }
            value if value == quicr_sys::QUICR_OBJECT_STATUS_DOES_NOT_EXIST as _ => {
                Some(Self::DoesNotExist)
            }
            value if value == quicr_sys::QUICR_OBJECT_STATUS_END_OF_GROUP as _ => {
                Some(Self::EndOfGroup)
            }
            value if value == quicr_sys::QUICR_OBJECT_STATUS_END_OF_TRACK as _ => {
                Some(Self::EndOfTrack)
            }
            value if value == quicr_sys::QUICR_OBJECT_STATUS_END_OF_SUBGROUP as _ => {
                Some(Self::EndOfSubgroup)
            }
            _ => None,
        }
    }
}

/// Owned metadata associated with an object or object-status notification.
///
/// [`Default`] describes an available zero-length object at location `(0, 0)`
/// with no optional metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObjectHeaders {
    /// Group identifier.
    pub group_id: u64,
    /// Object identifier within the group.
    pub object_id: u64,
    /// Subgroup identifier.
    pub subgroup_id: u64,
    /// Declared payload size, in bytes.
    pub payload_length: u64,
    /// Object availability or terminal status.
    pub status: ObjectStatus,
    /// Object priority, if explicitly present.
    ///
    /// Lower protocol values represent higher priority.
    pub priority: Option<u8>,
    /// Object time-to-live, if present.
    ///
    /// Native conversion stores whole milliseconds in a `u16`; sub-millisecond
    /// precision is truncated and values above `u16::MAX` milliseconds cannot
    /// be represented.
    pub ttl: Option<Duration>,
    /// Explicit transport mode, or `None` to use the track's mode.
    pub track_mode: Option<TrackMode>,
    /// Mutable object extensions, if the extension block was present.
    ///
    /// `None` and `Some(Extensions::new())` respectively preserve absent and
    /// present-but-empty extension blocks.
    pub extensions: Option<Extensions>,
    /// Immutable object extensions, with the same presence semantics as
    /// [`extensions`](Self::extensions).
    pub immutable_extensions: Option<Extensions>,
}

impl ObjectHeaders {
    pub(crate) fn native(&self) -> Option<NativeObjectHeaders> {
        let extensions = self
            .extensions
            .as_ref()
            .map(|extensions| Box::new(NativeExtensions::new(extensions)));
        let immutable_extensions = self
            .immutable_extensions
            .as_ref()
            .map(|extensions| Box::new(NativeExtensions::new(extensions)));
        let mut headers = unsafe { std::mem::zeroed() };
        unsafe { quicr_sys::quicr_object_headers_init(&mut headers) };
        headers.group_id = self.group_id;
        headers.object_id = self.object_id;
        headers.subgroup_id = self.subgroup_id;
        headers.payload_length = self.payload_length;
        headers.status = self.status.native();
        if let Some(priority) = self.priority {
            headers.has_priority = true;
            headers.priority = priority;
        }
        if let Some(ttl) = self.ttl {
            headers.has_ttl = true;
            headers.ttl = ttl.as_millis().try_into().ok()?;
        }
        if let Some(track_mode) = self.track_mode {
            headers.has_track_mode = true;
            headers.track_mode = track_mode.native();
        }
        headers.extensions = extensions
            .as_ref()
            .map_or(ptr::null(), |extensions| &extensions.raw);
        headers.immutable_extensions = immutable_extensions
            .as_ref()
            .map_or(ptr::null(), |extensions| &extensions.raw);
        Some(NativeObjectHeaders {
            raw: headers,
            _extensions: extensions,
            _immutable_extensions: immutable_extensions,
        })
    }

    pub(crate) unsafe fn from_native(headers: &quicr_sys::quicr_object_headers_t) -> Option<Self> {
        Some(Self {
            group_id: headers.group_id,
            object_id: headers.object_id,
            subgroup_id: headers.subgroup_id,
            payload_length: headers.payload_length,
            status: ObjectStatus::from_native(headers.status)?,
            priority: headers.has_priority.then_some(headers.priority),
            ttl: headers
                .has_ttl
                .then_some(Duration::from_millis(headers.ttl.into())),
            track_mode: if !headers.has_track_mode {
                None
            } else if headers.track_mode == quicr_sys::QUICR_TRACK_MODE_DATAGRAM as _ {
                Some(TrackMode::Datagram)
            } else if headers.track_mode == quicr_sys::QUICR_TRACK_MODE_STREAM as _ {
                Some(TrackMode::Stream)
            } else {
                return None;
            },
            extensions: unsafe { copy_extensions(headers.extensions)? },
            immutable_extensions: unsafe { copy_extensions(headers.immutable_extensions)? },
        })
    }
}

pub(crate) struct NativeObjectHeaders {
    pub raw: quicr_sys::quicr_object_headers_t,
    _extensions: Option<Box<NativeExtensions>>,
    _immutable_extensions: Option<Box<NativeExtensions>>,
}

struct NativeExtensions {
    raw: quicr_sys::quicr_extensions_t,
    _values: Vec<Vec<quicr_sys::quicr_byte_span_t>>,
    _entries: Vec<quicr_sys::quicr_extension_entry_t>,
}

impl NativeExtensions {
    fn new(extensions: &Extensions) -> Self {
        let values: Vec<Vec<_>> = extensions
            .values()
            .map(|values| {
                values
                    .iter()
                    .map(|value| quicr_sys::quicr_byte_span_t {
                        data: value.as_ptr(),
                        size: value.len(),
                    })
                    .collect()
            })
            .collect();
        let entries: Vec<_> = extensions
            .iter()
            .zip(&values)
            .map(
                |((&extension_type, _), values)| quicr_sys::quicr_extension_entry_t {
                    type_: extension_type,
                    values: values.as_ptr(),
                    count: values.len(),
                },
            )
            .collect();
        let raw = quicr_sys::quicr_extensions_t {
            entries: entries.as_ptr(),
            count: entries.len(),
        };
        Self {
            raw,
            _values: values,
            _entries: entries,
        }
    }
}

unsafe fn copy_extensions(raw: *const quicr_sys::quicr_extensions_t) -> Option<Option<Extensions>> {
    let Some(raw) = (unsafe { raw.as_ref() }) else {
        return Some(None);
    };
    if raw.count > 0 && raw.entries.is_null() {
        return None;
    }

    let entries = if raw.count == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(raw.entries, raw.count) }
    };
    let mut extensions = Extensions::new();
    for entry in entries {
        if entry.count > 0 && entry.values.is_null() {
            return None;
        }
        let values = if entry.count == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(entry.values, entry.count) }
        };
        let mut copied = Vec::with_capacity(values.len());
        for value in values {
            if value.size > 0 && value.data.is_null() {
                return None;
            }
            copied.push(if value.size == 0 {
                Vec::new()
            } else {
                unsafe { slice::from_raw_parts(value.data, value.size) }.to_vec()
            });
        }
        extensions.insert(entry.type_, copied);
    }
    Some(Some(extensions))
}

#[cfg(test)]
mod tests {
    use super::ObjectHeaders;

    #[test]
    fn object_headers_preserve_extensions() {
        let mut headers = ObjectHeaders::default();
        headers
            .extensions
            .get_or_insert_default()
            .insert(2, vec![b"one".to_vec(), b"two".to_vec()]);
        headers
            .immutable_extensions
            .get_or_insert_default()
            .insert(4, vec![b"fixed".to_vec()]);

        let native = headers.native().unwrap();
        let copied = unsafe { ObjectHeaders::from_native(&native.raw) }.unwrap();

        assert_eq!(copied, headers);
    }

    #[test]
    fn object_headers_preserve_absent_and_present_empty_extensions() {
        let absent = ObjectHeaders::default();
        let absent = absent.native().unwrap();
        let copied = unsafe { ObjectHeaders::from_native(&absent.raw) }.unwrap();
        assert_eq!(copied.extensions, None);
        assert_eq!(copied.immutable_extensions, None);

        let present = ObjectHeaders {
            extensions: Some(Default::default()),
            immutable_extensions: Some(Default::default()),
            ..ObjectHeaders::default()
        };
        let present = present.native().unwrap();
        let copied = unsafe { ObjectHeaders::from_native(&present.raw) }.unwrap();
        assert_eq!(copied.extensions, Some(Default::default()));
        assert_eq!(copied.immutable_extensions, Some(Default::default()));
    }

    #[test]
    fn rejects_ttl_outside_native_range() {
        let headers = ObjectHeaders {
            ttl: Some(std::time::Duration::from_millis(u16::MAX as u64 + 1)),
            ..ObjectHeaders::default()
        };

        assert!(headers.native().is_none());
    }
}
