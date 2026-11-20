// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

use std::{fmt, ptr};

/// Hierarchical namespace portion of a full track name.
///
/// Entries are owned arbitrary bytes, not UTF-8 strings. Empty entries and
/// interior NUL bytes are preserved. A namespace contains at most
/// [`MAX_ENTRIES`](Self::MAX_ENTRIES) entries.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TrackNamespace {
    entries: Vec<Vec<u8>>,
}

impl TrackNamespace {
    /// Maximum number of namespace entries accepted by [`new`](Self::new).
    pub const MAX_ENTRIES: usize = 32;

    /// Copies namespace entries into a new owned namespace.
    ///
    /// # Errors
    ///
    /// Returns [`TrackNamespaceError`] if more than [`MAX_ENTRIES`](Self::MAX_ENTRIES)
    /// entries are provided.
    pub fn new<I, E>(entries: I) -> Result<Self, TrackNamespaceError>
    where
        I: IntoIterator<Item = E>,
        E: AsRef<[u8]>,
    {
        let entries: Vec<_> = entries
            .into_iter()
            .map(|entry| entry.as_ref().to_vec())
            .collect();

        if entries.len() > Self::MAX_ENTRIES {
            return Err(TrackNamespaceError {
                entries: entries.len(),
            });
        }

        Ok(Self { entries })
    }

    /// Iterates over borrowed binary namespace entries in their original order.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.entries.iter().map(Vec::as_slice)
    }

    /// Returns the number of namespace entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the namespace has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn to_native(&self) -> Result<NativeTrackNamespace, NativeNameError> {
        let entries: Vec<_> = self
            .entries()
            .map(|entry| quicr_sys::quicr_byte_span_t {
                data: entry.as_ptr(),
                size: entry.len(),
            })
            .collect();
        let mut raw = ptr::null_mut();
        let status = unsafe {
            quicr_sys::quicr_track_namespace_create(entries.as_ptr(), entries.len(), &mut raw)
        };
        NativeNameError::check(status, raw)?;

        Ok(NativeTrackNamespace { raw })
    }

    pub(crate) unsafe fn copy_from_raw(
        raw: *const quicr_sys::quicr_track_namespace_t,
    ) -> Option<Self> {
        if raw.is_null() {
            return None;
        }
        let count = unsafe { quicr_sys::quicr_track_namespace_count(raw) };
        let mut entries = Vec::with_capacity(count);
        for index in 0..count {
            let mut entry = quicr_sys::quicr_byte_span_t {
                data: ptr::null(),
                size: 0,
            };
            let status = unsafe { quicr_sys::quicr_track_namespace_entry(raw, index, &mut entry) };
            if status != quicr_sys::QUICR_STATUS_OK as _ || (entry.size > 0 && entry.data.is_null())
            {
                return None;
            }
            entries.push(if entry.size == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(entry.data, entry.size) }.to_vec()
            });
        }
        Self::new(entries).ok()
    }
}

/// Complete track identity consisting of a namespace and terminal name.
///
/// Both namespace entries and the terminal name are owned binary values; no
/// UTF-8 validation or normalization is performed.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FullTrackName {
    namespace: TrackNamespace,
    name: Vec<u8>,
}

impl FullTrackName {
    /// Creates a full name by taking ownership of `namespace` and copying
    /// the binary terminal `name`.
    pub fn new(namespace: TrackNamespace, name: impl AsRef<[u8]>) -> Self {
        Self {
            namespace,
            name: name.as_ref().to_vec(),
        }
    }

    /// Borrows this name's namespace.
    pub fn namespace(&self) -> &TrackNamespace {
        &self.namespace
    }

    /// Borrows the terminal track name as uninterpreted bytes.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    pub(crate) unsafe fn copy_from_raw(
        raw: *const quicr_sys::quicr_full_track_name_t,
    ) -> Option<Self> {
        if raw.is_null() {
            return None;
        }
        let count = unsafe { quicr_sys::quicr_full_track_name_namespace_count(raw) };
        let mut entries = Vec::with_capacity(count);
        for index in 0..count {
            let mut entry = quicr_sys::quicr_byte_span_t {
                data: ptr::null(),
                size: 0,
            };
            let status =
                unsafe { quicr_sys::quicr_full_track_name_namespace_entry(raw, index, &mut entry) };
            if status != quicr_sys::QUICR_STATUS_OK as _ || (entry.size > 0 && entry.data.is_null())
            {
                return None;
            }
            entries.push(if entry.size == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(entry.data, entry.size) }.to_vec()
            });
        }
        let name = unsafe { quicr_sys::quicr_full_track_name_track_name(raw) };
        if name.size > 0 && name.data.is_null() {
            return None;
        }
        let name = if name.size == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(name.data, name.size) }.to_vec()
        };
        Some(Self::new(TrackNamespace::new(entries).ok()?, name))
    }

    pub(crate) fn to_native(&self) -> Result<NativeFullTrackName, NativeNameError> {
        let namespace = self.namespace.to_native()?;
        let track_name = quicr_sys::quicr_byte_span_t {
            data: self.name.as_ptr(),
            size: self.name.len(),
        };
        let mut full_name = ptr::null_mut();
        let status = unsafe {
            quicr_sys::quicr_full_track_name_create(namespace.raw, track_name, &mut full_name)
        };

        NativeNameError::check(status, full_name)?;

        Ok(NativeFullTrackName { raw: full_name })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeNameError {
    status: quicr_sys::quicr_status_t,
}

impl NativeNameError {
    fn check<T>(status: quicr_sys::quicr_status_t, value: *mut T) -> Result<(), Self> {
        if status != quicr_sys::QUICR_STATUS_OK as _ {
            return Err(Self { status });
        }

        if value.is_null() {
            return Err(Self {
                status: quicr_sys::QUICR_STATUS_INTERNAL_ERROR as _,
            });
        }

        Ok(())
    }

    pub(crate) fn status(self) -> quicr_sys::quicr_status_t {
        self.status
    }
}

pub(crate) struct NativeTrackNamespace {
    pub raw: *mut quicr_sys::quicr_track_namespace_t,
}

impl Drop for NativeTrackNamespace {
    fn drop(&mut self) {
        unsafe { quicr_sys::quicr_track_namespace_destroy(self.raw) };
    }
}

pub(crate) struct NativeFullTrackName {
    pub raw: *mut quicr_sys::quicr_full_track_name_t,
}

impl Drop for NativeFullTrackName {
    fn drop(&mut self) {
        unsafe { quicr_sys::quicr_full_track_name_destroy(self.raw) };
    }
}

/// Error returned when a namespace exceeds the protocol entry limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrackNamespaceError {
    entries: usize,
}

impl TrackNamespaceError {
    /// Returns the rejected number of namespace entries.
    pub fn entries(&self) -> usize {
        self.entries
    }
}

impl fmt::Display for TrackNamespaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "track namespace has {} entries; at most {} are allowed",
            self.entries,
            TrackNamespace::MAX_ENTRIES
        )
    }
}

impl std::error::Error for TrackNamespaceError {}

#[cfg(test)]
mod tests {
    use super::{FullTrackName, NativeNameError, TrackNamespace};

    #[test]
    fn preserves_binary_name_parts() {
        let namespace = TrackNamespace::new([b"conference".as_slice(), &[0, 1, 2]]).unwrap();
        let full_name = FullTrackName::new(namespace, [0xff, 0x00]);

        assert_eq!(
            full_name.namespace().entries().collect::<Vec<_>>(),
            vec![b"conference".as_slice(), &[0, 1, 2]]
        );
        assert_eq!(full_name.name(), &[0xff, 0x00]);
    }

    #[test]
    fn rejects_more_than_32_namespace_entries() {
        let error = TrackNamespace::new([[0]; 33]).unwrap_err();
        assert_eq!(error.entries(), 33);
    }

    #[test]
    fn preserves_native_creation_statuses() {
        let error = NativeNameError::check::<quicr_sys::quicr_track_namespace_t>(
            quicr_sys::QUICR_STATUS_OUT_OF_MEMORY as _,
            std::ptr::null_mut(),
        )
        .unwrap_err();

        assert_eq!(
            error.status(),
            quicr_sys::QUICR_STATUS_OUT_OF_MEMORY as quicr_sys::quicr_status_t
        );
    }

    #[test]
    fn treats_success_with_null_output_as_internal_error() {
        let error = NativeNameError::check::<quicr_sys::quicr_track_namespace_t>(
            quicr_sys::QUICR_STATUS_OK as _,
            std::ptr::null_mut(),
        )
        .unwrap_err();

        assert_eq!(
            error.status(),
            quicr_sys::QUICR_STATUS_INTERNAL_ERROR as quicr_sys::quicr_status_t
        );
    }
}
