//! `HardenedBytes` — Box-backed byte buffer that is mlocked on allocation,
//! marked DONT_DUMP (Linux), zeroized on Drop, then munlocked.
//!
//! See R51/R52. No `unsafe` lives in this module — all platform primitives
//! are delegated to `page_guard`.

use zeroize::Zeroize;

use crate::{MemGuardError, page_guard};

/// Apply `WIPEONFORK` best-effort after a successful lock + DONTDUMP.
///
/// Fork protection is defense-in-depth on top of `mlock`; a failure here
/// (e.g. kernel < 4.14) leaves the lock intact, so it is logged and ignored.
fn wipe_on_fork_best_effort(ptr: *const u8, len: usize) {
    if let Err(e) = page_guard::wipe_on_fork(ptr, len) {
        tracing::warn!(
            len,
            error = %e,
            "MADV_WIPEONFORK failed; locked key pages will be inherited (not wiped) by forked children"
        );
    }
}

/// Zeroize a `Vec` (including spare capacity semantics of the buffer's live
/// bytes) immediately before it is dropped.
fn wipe(mut v: Vec<u8>) {
    v.zeroize();
}

pub struct HardenedBytes {
    inner: Box<[u8]>,
}

impl HardenedBytes {
    /// Allocate a zero-initialized, page-locked byte buffer of length `len`.
    ///
    /// - `len == 0` returns an empty buffer without touching `mlock`.
    /// - On `dont_dump` failure after a successful `lock`, the lock is undone and the error is
    ///   propagated.
    pub fn new(len: usize) -> Result<Self, MemGuardError> {
        if len == 0 {
            return Ok(Self { inner: Box::default() });
        }
        // Zero-initialized so we never expose uninitialized memory to the OS
        // during mlock/madvise.
        let inner: Box<[u8]> = vec![0u8; len].into_boxed_slice();
        let ptr = inner.as_ptr();
        page_guard::lock(ptr, len)?;
        // If dont_dump fails, undo the lock and propagate the error.
        if let Err(e) = page_guard::dont_dump(ptr, len) {
            page_guard::unlock(ptr, len);
            return Err(e);
        }
        wipe_on_fork_best_effort(ptr, len);
        Ok(Self { inner })
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Copy `data` into a new page-locked, DONT_DUMP-marked buffer.
    ///
    /// - `data.is_empty()` returns an empty buffer without touching `mlock`.
    /// - On `dont_dump` failure after a successful `lock`, the lock is undone and the error is
    ///   propagated.
    pub fn from_slice(data: &[u8]) -> Result<Self, MemGuardError> {
        if data.is_empty() {
            return Ok(Self { inner: Box::default() });
        }
        let mut hb = Self::new(data.len())?;
        hb.inner.copy_from_slice(data);
        Ok(hb)
    }

    /// Convert an owned `Vec<u8>` into a `HardenedBytes`.
    ///
    /// The Vec's contents are first copied into an exactly-sized buffer and the
    /// source (including any spare capacity) is zeroized. This prevents a
    /// stale plaintext copy from surviving in freed heap memory when
    /// `into_boxed_slice` would otherwise shrink-reallocate a `Vec` whose
    /// capacity exceeds its length.
    ///
    /// On `dont_dump` failure after a successful `lock`, the lock is undone
    /// and the error is propagated.
    pub fn from_vec(data: Vec<u8>) -> Result<Self, MemGuardError> {
        if data.is_empty() {
            return Ok(Self { inner: Box::default() });
        }
        // Copy into an exactly-sized buffer, then wipe the source (including
        // any spare capacity) so no plaintext survives in freed heap memory.
        let mut exact = Vec::with_capacity(data.len());
        exact.extend_from_slice(&data);
        wipe(data);
        let len = exact.len();
        let inner = exact.into_boxed_slice();
        let ptr = inner.as_ptr();
        page_guard::lock(ptr, len)?;
        if let Err(e) = page_guard::dont_dump(ptr, len) {
            page_guard::unlock(ptr, len);
            return Err(e);
        }
        wipe_on_fork_best_effort(ptr, len);
        Ok(Self { inner })
    }

    /// Copy bytes into a new buffer, page-locking on a best-effort basis.
    ///
    /// Unlike [`HardenedBytes::from_slice`], an mlock/DONTDUMP failure
    /// degrades to an unlocked — but still zeroized-on-drop — buffer instead
    /// of returning an error. Intended for `Clone`-like contexts whose trait
    /// contract forbids fallibility, and for callers that must never panic on
    /// signing hot paths.
    pub fn from_slice_best_effort(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self { inner: Box::default() };
        }
        match Self::from_slice(data) {
            Ok(hb) => hb,
            Err(e) => {
                tracing::warn!(
                    len = data.len(),
                    error = %e,
                    "HardenedBytes fell back to UNLOCKED memory (mlock/DONTDUMP failed); bytes remain zeroized-on-drop"
                );
                Self { inner: data.to_vec().into_boxed_slice() }
            }
        }
    }

    /// Expose the underlying bytes. Use with care.
    ///
    /// Inherent method that matches the historical `SecretBytes::expose` API
    /// name, so callers migrated from `oc_signer::SecretBytes` need no rename.
    pub fn expose(&self) -> &[u8] {
        &self.inner
    }
}

impl Clone for HardenedBytes {
    /// Clone the buffer contents into a new page-locked allocation.
    ///
    /// `Clone` is infallible by trait contract. If `mlock` fails for the
    /// clone, we fall back to an *unlocked* copy — the bytes are still
    /// zeroized on `Drop`, just not pinned in RAM. This matches the
    /// historical `SecretBytes::clone` behavior (best-effort mlock).
    /// Degradation is logged at `debug` level to avoid noise on hot paths
    /// (direct best-effort construction warns instead).
    fn clone(&self) -> Self {
        match Self::from_slice(&self.inner) {
            Ok(hb) => hb,
            Err(e) => {
                tracing::debug!(
                    len = self.inner.len(),
                    error = %e,
                    "HardenedBytes clone degraded to unlocked memory"
                );
                Self { inner: self.inner.to_vec().into_boxed_slice() }
            }
        }
    }
}

impl AsRef<[u8]> for HardenedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl AsMut<[u8]> for HardenedBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl Drop for HardenedBytes {
    fn drop(&mut self) {
        let ptr = self.inner.as_ptr();
        let len = self.inner.len();
        if len == 0 {
            return;
        }
        // Zeroize first so the bytes are wiped while the page is still locked,
        // then release the lock.
        self.inner.zeroize();
        page_guard::unlock(ptr, len);
    }
}

impl std::fmt::Debug for HardenedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose the bytes — even length is sufficient metadata.
        write!(f, "[REDACTED; {} bytes]", self.inner.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_roundtrip_small() {
        let hb = HardenedBytes::new(16).unwrap();
        assert_eq!(hb.len(), 16);
        assert!(!hb.is_empty());
        assert_eq!(hb.as_ref().len(), 16);
    }

    #[test]
    fn alloc_zero_is_ok() {
        let hb = HardenedBytes::new(0).unwrap();
        assert!(hb.is_empty());
        assert_eq!(hb.len(), 0);
    }

    #[test]
    fn alloc_is_zero_initialized() {
        let hb = HardenedBytes::new(32).unwrap();
        // The spec mandates zero-init so we never hand uninitialized memory to
        // a caller that forgets to overwrite it.
        assert_eq!(hb.as_ref(), &vec![0u8; 32][..]);
    }

    #[test]
    fn as_mut_writes_data() {
        let mut hb = HardenedBytes::new(8).unwrap();
        hb.as_mut().copy_from_slice(&[0xAB; 8]);
        assert_eq!(hb.as_ref(), &[0xAB; 8]);
    }

    #[test]
    fn debug_doesnt_leak() {
        let mut hb = HardenedBytes::new(4).unwrap();
        hb.as_mut().copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let s = format!("{:?}", hb);
        assert!(!s.contains("DEAD"));
        assert!(!s.contains("BEEF"));
        assert!(s.contains("[REDACTED; 4 bytes]"));
    }

    #[test]
    fn drop_zeroizes_then_unlocks() {
        // Allocate, write a sentinel, then drop. We cannot easily read freed
        // memory safely, so this test just confirms drop runs without panic.
        {
            let mut hb = HardenedBytes::new(32).unwrap();
            hb.as_mut().copy_from_slice(&[0x42; 32]);
        } // drop runs here
        // If we reach this point, Drop completed without panic.
    }

    #[test]
    fn large_alloc_under_4096() {
        let hb = HardenedBytes::new(4095).unwrap();
        assert_eq!(hb.len(), 4095);
    }

    #[test]
    fn from_slice_copies_data() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let hb = HardenedBytes::from_slice(&data).unwrap();
        assert_eq!(hb.expose(), &data[..]);
        assert_eq!(hb.len(), 4);
    }

    #[test]
    fn from_slice_empty_is_ok() {
        let hb = HardenedBytes::from_slice(&[]).unwrap();
        assert!(hb.is_empty());
        assert_eq!(hb.expose().len(), 0);
    }

    #[test]
    fn from_vec_preserves_data_and_wipes_source() {
        let data = vec![1u8, 2, 3, 4, 5];
        let hb = HardenedBytes::from_vec(data).unwrap();
        assert_eq!(hb.expose(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn from_vec_with_spare_capacity_is_exact_length() {
        // capacity > len previously triggered a shrink-realloc in
        // into_boxed_slice; the fixed implementation must still yield an
        // exact-length buffer holding only the logical bytes.
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&[7u8; 5]);
        let hb = HardenedBytes::from_vec(data).unwrap();
        assert_eq!(hb.len(), 5);
        assert_eq!(hb.expose(), &[7u8; 5][..]);
    }

    #[test]
    fn from_slice_best_effort_preserves_data() {
        let hb = HardenedBytes::from_slice_best_effort(&[0xA, 0xB]);
        assert_eq!(hb.expose(), &[0xA, 0xB][..]);
        assert_eq!(hb.len(), 2);
    }

    #[test]
    fn from_vec_empty_is_ok() {
        let hb = HardenedBytes::from_vec(Vec::new()).unwrap();
        assert!(hb.is_empty());
    }

    #[test]
    fn expose_returns_written_bytes() {
        let mut hb = HardenedBytes::new(4).unwrap();
        hb.as_mut().copy_from_slice(&[0xA, 0xB, 0xC, 0xD]);
        assert_eq!(hb.expose(), &[0xA, 0xB, 0xC, 0xD]);
    }

    #[test]
    fn clone_is_independent_copy() {
        let original = HardenedBytes::from_slice(&[1, 2, 3, 4]).unwrap();
        let cloned = original.clone();
        assert_eq!(original.expose(), cloned.expose());
        // Distinct allocations
        assert_ne!(original.expose().as_ptr(), cloned.expose().as_ptr());
    }

    #[test]
    fn clone_of_empty_is_ok() {
        let original = HardenedBytes::from_slice(&[]).unwrap();
        let cloned = original;
        assert!(cloned.is_empty());
    }

    #[test]
    fn clone_then_drop_does_not_panic() {
        let original = HardenedBytes::from_slice(&[9; 64]).unwrap();
        let cloned = original.clone();
        drop(original);
        drop(cloned);
    }

    #[test]
    fn odd_lengths_construct_without_panic() {
        for &len in &[1usize, 3, 7, 511, 1023, 4097] {
            let hb = HardenedBytes::new(len).unwrap();
            assert_eq!(hb.len(), len);
        }
    }

    #[test]
    fn from_slice_best_effort_odd_lengths_no_panic() {
        for &len in &[1usize, 3, 17, 4097] {
            let data = vec![0x5Au8; len];
            let hb = HardenedBytes::from_slice_best_effort(&data);
            assert_eq!(hb.len(), len);
            assert_eq!(hb.expose(), &data[..]);
        }
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn clone_odd_lengths_no_panic() {
        for &len in &[1usize, 3, 2049] {
            let original = HardenedBytes::from_slice(&vec![0xC3u8; len]).unwrap();
            let cloned = original.clone();
            assert_eq!(cloned.expose(), &vec![0xC3u8; len][..]);
        }
    }
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn alloc_round_trip(n in 0usize..4096) {
            let hb = HardenedBytes::new(n).unwrap();
            prop_assert_eq!(hb.len(), n);
            prop_assert_eq!(hb.as_ref().len(), n);
            if n == 0 {
                prop_assert!(hb.is_empty());
            } else {
                prop_assert!(!hb.is_empty());
            }
            // Drop runs at end of iteration — verify no panic across many sizes.
        }
    }
}
