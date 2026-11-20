// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::fmt;

use crate::Location;

/// Invalid or unrecognized native filter data.
///
/// This includes unknown discriminants and absolute ranges whose end group
/// would overflow `u64`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilterError;

impl fmt::Display for FilterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid filter")
    }
}

impl std::error::Error for FilterError {}

/// Top-level category of a [`Filter`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilterKind {
    /// An object-range subscription filter.
    Subscription,
    /// A track-property selection filter.
    Track,
}

/// Selects the starting point or range of objects for a subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionFilter {
    /// Starts at the beginning of the next group.
    NextGroupStart,
    /// Starts at the largest currently available object.
    LargestObject,
    /// Starts at the specified absolute object location.
    AbsoluteStart(Location),
    /// Selects an inclusive range starting at an absolute location.
    AbsoluteRange {
        /// Inclusive first object.
        start: Location,
        /// Number of groups after `start.group` containing the inclusive end.
        ///
        /// The range is invalid if adding this delta overflows `u64`.
        end_group_delta: u64,
    },
}

/// Selects tracks by a protocol extension property.
///
/// [`Default`] sets every numeric field to zero.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrackFilter {
    /// Protocol extension type whose property is matched.
    pub property_type: u64,
    /// Maximum number of tracks that may be selected.
    pub max_tracks_selected: u64,
    /// Selection timeout in protocol-defined units.
    pub timeout: u64,
}

/// Subscription-object or track-selection filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Filter {
    /// Selects an object start or range.
    Subscription(SubscriptionFilter),
    /// Selects tracks by property.
    Track(TrackFilter),
}

impl Filter {
    /// Returns this filter's top-level category.
    pub fn kind(&self) -> FilterKind {
        match self {
            Self::Subscription(_) => FilterKind::Subscription,
            Self::Track(_) => FilterKind::Track,
        }
    }

    pub(crate) fn native(self) -> quicr_sys::quicr_filter_t {
        let mut filter: quicr_sys::quicr_filter_t = unsafe { std::mem::zeroed() };
        match self {
            Self::Subscription(subscription) => {
                filter.type_ = quicr_sys::QUICR_FILTER_TYPE_SUBSCRIPTION_FILTER as _;
                filter.__bindgen_anon_1.subscription = subscription.native();
            }
            Self::Track(track) => {
                filter.type_ = quicr_sys::QUICR_FILTER_TYPE_TRACK_FILTER as _;
                filter.__bindgen_anon_1.track = track.native();
            }
        }
        filter
    }

    pub(crate) fn from_native(raw: quicr_sys::quicr_filter_t) -> Result<Option<Self>, FilterError> {
        match raw.type_ {
            value if value == quicr_sys::QUICR_FILTER_TYPE_NONE as _ => Ok(None),
            value if value == quicr_sys::QUICR_FILTER_TYPE_SUBSCRIPTION_FILTER as _ => {
                let raw = unsafe { raw.__bindgen_anon_1.subscription };
                Ok(Some(Self::Subscription(SubscriptionFilter::from_native(
                    raw,
                )?)))
            }
            value if value == quicr_sys::QUICR_FILTER_TYPE_TRACK_FILTER as _ => {
                let raw = unsafe { raw.__bindgen_anon_1.track };
                Ok(Some(Self::Track(TrackFilter {
                    property_type: raw.property_type,
                    max_tracks_selected: raw.max_tracks_selected,
                    timeout: raw.timeout,
                })))
            }
            _ => Err(FilterError),
        }
    }
}

impl SubscriptionFilter {
    fn native(self) -> quicr_sys::quicr_subscription_filter_t {
        let (filter_type, start, end_group_delta) = match self {
            Self::NextGroupStart => (
                quicr_sys::QUICR_SUBSCRIPTION_FILTER_TYPE_NEXT_GROUP_START,
                Location::default(),
                0,
            ),
            Self::LargestObject => (
                quicr_sys::QUICR_SUBSCRIPTION_FILTER_TYPE_LARGEST_OBJECT,
                Location::default(),
                0,
            ),
            Self::AbsoluteStart(start) => (
                quicr_sys::QUICR_SUBSCRIPTION_FILTER_TYPE_ABSOLUTE_START,
                start,
                0,
            ),
            Self::AbsoluteRange {
                start,
                end_group_delta,
            } => (
                quicr_sys::QUICR_SUBSCRIPTION_FILTER_TYPE_ABSOLUTE_RANGE,
                start,
                end_group_delta,
            ),
        };
        quicr_sys::quicr_subscription_filter_t {
            type_: filter_type as _,
            start_location: quicr_sys::quicr_location_t {
                group: start.group,
                object: start.object,
            },
            end_group_delta,
        }
    }

    fn from_native(raw: quicr_sys::quicr_subscription_filter_t) -> Result<Self, FilterError> {
        let start = Location {
            group: raw.start_location.group,
            object: raw.start_location.object,
        };

        match raw.type_ {
            value if value == quicr_sys::QUICR_SUBSCRIPTION_FILTER_TYPE_NEXT_GROUP_START as _ => {
                Ok(Self::NextGroupStart)
            }
            value if value == quicr_sys::QUICR_SUBSCRIPTION_FILTER_TYPE_LARGEST_OBJECT as _ => {
                Ok(Self::LargestObject)
            }
            value if value == quicr_sys::QUICR_SUBSCRIPTION_FILTER_TYPE_ABSOLUTE_START as _ => {
                Ok(Self::AbsoluteStart(start))
            }
            value if value == quicr_sys::QUICR_SUBSCRIPTION_FILTER_TYPE_ABSOLUTE_RANGE as _ => {
                start
                    .group
                    .checked_add(raw.end_group_delta)
                    .ok_or(FilterError)?;

                Ok(Self::AbsoluteRange {
                    start,
                    end_group_delta: raw.end_group_delta,
                })
            }
            _ => Err(FilterError),
        }
    }
}

impl TrackFilter {
    fn native(self) -> quicr_sys::quicr_track_filter_t {
        quicr_sys::quicr_track_filter_t {
            property_type: self.property_type,
            max_tracks_selected: self.max_tracks_selected,
            timeout: self.timeout,
        }
    }
}

impl FilterKind {
    pub(crate) fn from_native(
        value: quicr_sys::quicr_filter_type_t,
    ) -> Result<Option<Self>, FilterError> {
        match value {
            value if value == quicr_sys::QUICR_FILTER_TYPE_NONE as _ => Ok(None),
            value if value == quicr_sys::QUICR_FILTER_TYPE_SUBSCRIPTION_FILTER as _ => {
                Ok(Some(Self::Subscription))
            }
            value if value == quicr_sys::QUICR_FILTER_TYPE_TRACK_FILTER as _ => {
                Ok(Some(Self::Track))
            }
            _ => Err(FilterError),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Location;

    use super::{Filter, SubscriptionFilter, TrackFilter};

    #[test]
    fn filters_roundtrip_through_native() {
        let filters = [
            Filter::Subscription(SubscriptionFilter::AbsoluteRange {
                start: Location {
                    group: 3,
                    object: 4,
                },
                end_group_delta: 5,
            }),
            Filter::Track(TrackFilter {
                property_type: 6,
                max_tracks_selected: 7,
                timeout: 8,
            }),
        ];

        for filter in filters {
            assert_eq!(Filter::from_native(filter.native()).unwrap(), Some(filter));
        }
    }

    #[test]
    fn rejects_unknown_filter_discriminants() {
        let mut raw: quicr_sys::quicr_filter_t = unsafe { std::mem::zeroed() };
        raw.type_ = u64::MAX;

        assert!(Filter::from_native(raw).is_err());
    }

    #[test]
    fn rejects_overflowing_absolute_range() {
        let filter = Filter::Subscription(SubscriptionFilter::AbsoluteRange {
            start: Location {
                group: u64::MAX,
                object: 0,
            },
            end_group_delta: 1,
        });

        assert!(Filter::from_native(filter.native()).is_err());
    }
}
