// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{collections::BTreeMap, fmt, ptr::NonNull, slice};

const OK: quicr_sys::quicr_status_t = quicr_sys::QUICR_STATUS_OK as _;

/// Failure while creating, copying, or populating native track extensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtensionError;

impl fmt::Display for ExtensionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("track extension operation failed")
    }
}

impl std::error::Error for ExtensionError {}

/// Owned mutable and immutable track-extension values.
///
/// Extension types and values are protocol-defined. Values are arbitrary
/// bytes, not UTF-8 strings. Each type has at most one value in each
/// mutability class, and iteration is ordered by numeric extension type.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrackExtensions {
    mutable: BTreeMap<u64, Vec<u8>>,
    immutable: BTreeMap<u64, Vec<u8>>,
}

impl TrackExtensions {
    /// Creates an empty extension collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces a mutable extension.
    ///
    /// This is an alias for [`insert`](Self::insert). Returns the previous
    /// owned value for the type, if any.
    pub fn add(&mut self, extension_type: u64, value: impl Into<Vec<u8>>) -> Option<Vec<u8>> {
        self.insert(extension_type, value)
    }

    /// Inserts an owned mutable extension value.
    ///
    /// Returns the previous owned value for the type, if any.
    pub fn insert(&mut self, extension_type: u64, value: impl Into<Vec<u8>>) -> Option<Vec<u8>> {
        self.mutable.insert(extension_type, value.into())
    }

    /// Adds or replaces an immutable extension.
    ///
    /// This is an alias for [`insert_immutable`](Self::insert_immutable).
    /// Returns the previous owned value for the type, if any.
    pub fn add_immutable(
        &mut self,
        extension_type: u64,
        value: impl Into<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        self.insert_immutable(extension_type, value)
    }

    /// Inserts an owned immutable extension value.
    ///
    /// Returns the previous owned value for the type, if any.
    pub fn insert_immutable(
        &mut self,
        extension_type: u64,
        value: impl Into<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        self.immutable.insert(extension_type, value.into())
    }

    /// Borrows the mutable value for `extension_type`.
    pub fn get(&self, extension_type: u64) -> Option<&[u8]> {
        self.mutable.get(&extension_type).map(Vec::as_slice)
    }

    /// Borrows the immutable value for `extension_type`.
    pub fn get_immutable(&self, extension_type: u64) -> Option<&[u8]> {
        self.immutable.get(&extension_type).map(Vec::as_slice)
    }

    /// Removes and returns the mutable value for `extension_type`.
    pub fn remove(&mut self, extension_type: u64) -> Option<Vec<u8>> {
        self.mutable.remove(&extension_type)
    }

    /// Removes and returns the immutable value for `extension_type`.
    pub fn remove_immutable(&mut self, extension_type: u64) -> Option<Vec<u8>> {
        self.immutable.remove(&extension_type)
    }

    /// Returns the number of mutable extensions.
    pub fn len(&self) -> usize {
        self.mutable.len()
    }

    /// Returns the number of immutable extensions.
    pub fn immutable_len(&self) -> usize {
        self.immutable.len()
    }

    /// Returns `true` when there are no mutable extensions.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` when there are no immutable extensions.
    pub fn is_immutable_empty(&self) -> bool {
        self.immutable_len() == 0
    }

    /// Iterates over mutable extensions in ascending type order.
    ///
    /// Values are borrowed from this collection.
    pub fn iter(&self) -> TrackExtensionsIter<'_> {
        TrackExtensionsIter(self.mutable.iter())
    }

    /// Iterates over immutable extensions in ascending type order.
    ///
    /// Values are borrowed from this collection.
    pub fn immutable_iter(&self) -> TrackExtensionsIter<'_> {
        TrackExtensionsIter(self.immutable.iter())
    }

    pub(crate) unsafe fn copy_from_raw(
        raw: *const quicr_sys::quicr_track_extensions_t,
    ) -> Result<Self, ExtensionError> {
        let Some(raw) = NonNull::new(raw.cast_mut()) else {
            return Ok(Self::new());
        };
        let mut copied = Self::new();

        for immutable in [false, true] {
            let count = if immutable {
                unsafe { quicr_sys::quicr_track_extensions_immutable_count(raw.as_ptr()) }
            } else {
                unsafe { quicr_sys::quicr_track_extensions_count(raw.as_ptr()) }
            };
            for index in 0..count {
                let (extension_type, value) =
                    unsafe { read_entry(raw.as_ptr(), index, immutable)? };
                if immutable {
                    copied.add_immutable(extension_type, value);
                } else {
                    copied.add(extension_type, value);
                }
            }
        }

        Ok(copied)
    }
}

impl<'a> IntoIterator for &'a TrackExtensions {
    /// A mutable extension type and its borrowed binary value.
    type Item = (u64, &'a [u8]);
    /// Iterator returned for a borrowed extension collection.
    type IntoIter = TrackExtensionsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub(crate) struct NativeTrackExtensions {
    raw: NonNull<quicr_sys::quicr_track_extensions_t>,
}

unsafe impl Send for NativeTrackExtensions {}

impl NativeTrackExtensions {
    pub(crate) fn new(extensions: &TrackExtensions) -> Result<Self, ExtensionError> {
        let mut raw = std::ptr::null_mut();
        let status = unsafe { quicr_sys::quicr_track_extensions_create(&mut raw) };
        if status != OK {
            return Err(ExtensionError);
        }
        let native = Self {
            raw: NonNull::new(raw).ok_or(ExtensionError)?,
        };

        for (&extension_type, value) in &extensions.mutable {
            add_native(native.raw.as_ptr(), extension_type, value, false)?;
        }

        for (&extension_type, value) in &extensions.immutable {
            add_native(native.raw.as_ptr(), extension_type, value, true)?;
        }

        Ok(native)
    }

    pub(crate) fn empty() -> Result<Self, ExtensionError> {
        Self::new(&TrackExtensions::new())
    }

    pub(crate) fn as_ptr(&self) -> *const quicr_sys::quicr_track_extensions_t {
        self.raw.as_ptr()
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut quicr_sys::quicr_track_extensions_t {
        self.raw.as_ptr()
    }

    pub(crate) fn into_value(self) -> Result<TrackExtensions, ExtensionError> {
        unsafe { TrackExtensions::copy_from_raw(self.as_ptr()) }
    }
}

impl Drop for NativeTrackExtensions {
    fn drop(&mut self) {
        unsafe { quicr_sys::quicr_track_extensions_destroy(self.raw.as_ptr()) };
    }
}

/// Borrowing iterator over track extensions in ascending type order.
pub struct TrackExtensionsIter<'a>(std::collections::btree_map::Iter<'a, u64, Vec<u8>>);

impl<'a> Iterator for TrackExtensionsIter<'a> {
    type Item = (u64, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|(&extension_type, value)| (extension_type, value.as_slice()))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl ExactSizeIterator for TrackExtensionsIter<'_> {}

unsafe fn read_entry<'a>(
    extensions: *const quicr_sys::quicr_track_extensions_t,
    index: usize,
    immutable: bool,
) -> Result<(u64, &'a [u8]), ExtensionError> {
    let mut extension_type = 0;
    let mut value = quicr_sys::quicr_byte_span_t {
        data: std::ptr::null(),
        size: 0,
    };
    let status = unsafe {
        if immutable {
            quicr_sys::quicr_track_extensions_immutable_entry(
                extensions,
                index,
                &mut extension_type,
                &mut value,
            )
        } else {
            quicr_sys::quicr_track_extensions_entry(
                extensions,
                index,
                &mut extension_type,
                &mut value,
            )
        }
    };
    if status != OK || (value.size > 0 && value.data.is_null()) {
        return Err(ExtensionError);
    }
    let value = if value.size == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(value.data, value.size) }
    };
    Ok((extension_type, value))
}

fn add_native(
    extensions: *mut quicr_sys::quicr_track_extensions_t,
    extension_type: u64,
    value: &[u8],
    immutable: bool,
) -> Result<(), ExtensionError> {
    let value = quicr_sys::quicr_byte_span_t {
        data: value.as_ptr(),
        size: value.len(),
    };

    let status = unsafe {
        if immutable {
            quicr_sys::quicr_track_extensions_add_immutable(extensions, extension_type, value)
        } else {
            quicr_sys::quicr_track_extensions_add(extensions, extension_type, value)
        }
    };

    (status == OK).then_some(()).ok_or(ExtensionError)
}

#[cfg(test)]
mod tests {
    use super::{NativeTrackExtensions, TrackExtensions};

    #[test]
    fn owns_mutable_and_immutable_values() {
        let mut extensions = TrackExtensions::new();
        extensions.add(2, b"mutable".to_vec());
        extensions.add_immutable(4, b"immutable".to_vec());

        assert_eq!(
            extensions.iter().collect::<Vec<_>>(),
            vec![(2, b"mutable".as_slice())]
        );
        assert_eq!(
            extensions.immutable_iter().collect::<Vec<_>>(),
            vec![(4, b"immutable".as_slice())]
        );
    }

    #[test]
    fn replacing_a_key_keeps_one_value() {
        let mut extensions = TrackExtensions::new();
        extensions.add(2, b"first".to_vec());
        assert_eq!(
            extensions.add(2, b"second".to_vec()),
            Some(b"first".to_vec())
        );

        assert_eq!(extensions.len(), 1);
        assert_eq!(
            extensions.iter().collect::<Vec<_>>(),
            vec![(2, b"second".as_slice())]
        );
    }

    #[test]
    fn roundtrips_through_temporary_native_storage() {
        let mut extensions = TrackExtensions::new();
        extensions.add(2, vec![0, 1, 255]);
        extensions.add_immutable(4, vec![255, 0, 2]);

        let native = NativeTrackExtensions::new(&extensions).unwrap();
        let copied = unsafe { TrackExtensions::copy_from_raw(native.as_ptr()) }.unwrap();

        assert_eq!(copied, extensions);
    }
}
