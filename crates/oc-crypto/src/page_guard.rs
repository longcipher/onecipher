//! Cross-platform memory page guards.
//!
//! - `lock`   : `mlock` on Unix, `VirtualLock` on Windows.
//! - `unlock` : `munlock` on Unix, `VirtualUnlock` on Windows (best-effort).
//! - `dont_dump`: `madvise(MADV_DONTDUMP)` on Linux; no-op elsewhere (returns Ok).
//!
//! All `unsafe` in `oc-crypto` is confined to this module. The crate root uses
//! `#![deny(unsafe_code)]` (see `lib.rs` for why we did not use `forbid`); the
//! `#![allow(unsafe_code)]` inner attribute below relaxes the lint here only.

#![allow(unsafe_code)]

use crate::MemGuardError;

/// Lock a region of memory so it cannot be swapped to disk.
///
/// - Unix: `mlock(2)`. On non-zero return, captures `errno` via `std::io::Error::last_os_error()`
///   and returns `MlockFailed`.
/// - Windows: `VirtualLock`. On zero return, returns `VirtualLockFailed`.
///
/// Calling with `len == 0` is a no-op success.
pub fn lock(addr: *const u8, len: usize) -> Result<(), MemGuardError> {
    if len == 0 {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let ret = unsafe { libc::mlock(addr.cast::<libc::c_void>(), len) };
        if ret != 0 {
            return Err(MemGuardError::MlockFailed(std::io::Error::last_os_error()));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let ret = unsafe { windows_sys::Win32::System::Memory::VirtualLock(addr as *const _, len) };
        if ret == 0 {
            return Err(MemGuardError::VirtualLockFailed(std::io::Error::last_os_error()));
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = addr;
        // No platform primitive available; surface an error rather than silently
        // pretending the page is locked.
        Err(MemGuardError::MlockFailed(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "mlock not available on this platform",
        )))
    }
}

/// Mark a region of memory as non-dumpable in core files.
///
/// - Linux: `madvise(MADV_DONTDUMP)`.
/// - All other platforms: no-op success (no equivalent primitive).
pub fn dont_dump(addr: *const u8, len: usize) -> Result<(), MemGuardError> {
    if len == 0 {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        // `madvise(2)` (unlike `mlock`) requires the address to be
        // **page-aligned** on all current kernels; unaligned heap pointers
        // (a plain `Box<[u8]>` is only aligned to its element type) are
        // rejected with EINVAL. Round the range down to the containing page
        // and extend the length to the end of the original range — the
        // kernel rounds down internally anyway, so this is semantically
        // identical on kernels that accept unaligned addresses.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let page_mask = page_size - 1;
        let base = (addr as usize) & !page_mask;
        let end = (addr as usize).saturating_add(len);
        let aligned_len = end.saturating_sub(base);
        let ret =
            unsafe { libc::madvise(base as *mut libc::c_void, aligned_len, libc::MADV_DONTDUMP) };
        if ret != 0 {
            return Err(MemGuardError::MadviseFailed(std::io::Error::last_os_error()));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = addr;
        Ok(())
    }
}

/// Unlock a previously locked region of memory. Best-effort: errors are ignored.
///
/// - Unix: `munlock(2)`.
/// - Windows: `VirtualUnlock`.
///
/// Calling with `len == 0` is a no-op.
pub fn unlock(addr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    #[cfg(unix)]
    {
        // Best-effort — ignore the return code.
        let _ = unsafe { libc::munlock(addr.cast::<libc::c_void>(), len) };
    }
    #[cfg(windows)]
    {
        // Best-effort — ignore the return code.
        let _ = unsafe { windows_sys::Win32::System::Memory::VirtualUnlock(addr as *const _, len) };
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = addr;
    }
}
