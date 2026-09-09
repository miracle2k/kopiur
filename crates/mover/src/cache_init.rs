//! Explicit cache-only initialization, using the pinned mover image itself.
//!
//! The initial contract is deliberately narrow: a fresh, empty, root-owned
//! ordinary emptyDir. No recursive traversal/chown, no symlink following, and no
//! support for reusing a persistent cache with an unknown ownership lifecycle.

use std::io;

/// Prepare the fixed cache directory for the effective mover UID/GID. The Job
/// must mount only cache into this init container and gate its root privilege.
#[cfg(target_os = "linux")]
pub fn prepare(uid: u32, gid: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    if uid == u32::MAX || gid == u32::MAX {
        return Err(io::Error::other(
            "cache ownership requires a valid UID and GID",
        ));
    }
    let cache = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(kopiur_kopia::env::DEFAULT_CACHE_DIR)?;
    let metadata = cache.metadata()?;
    if metadata.uid() != 0 || metadata.gid() != 0 {
        return Err(io::Error::other(
            "cache initializer only accepts a fresh root:root emptyDir; refusing existing ownership",
        ));
    }
    // Inspect through the held descriptor, not a path that can be swapped for
    // a symlink. No other container starts until initialization has completed.
    let descriptor = format!("/proc/self/fd/{}", cache.as_raw_fd());
    if std::fs::read_dir(descriptor)?.next().transpose()?.is_some() {
        return Err(io::Error::other(
            "cache initializer refuses non-empty cache roots; no recursive ownership changes are permitted",
        ));
    }
    // UID 0 is valid for an explicitly namespace-authorized root mover. Keeping
    // a fresh cache root-owned never grants the initializer a source mount.
    // chmod while we still own the directory, then chown last. CHOWN is the only
    // added capability; the syscall touches precisely this opened root inode.
    cache.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    // SAFETY: a live file descriptor and validated numeric IDs; fchown does not
    // retain references or follow any path/symlink.
    if unsafe { libc::fchown(cache.as_raw_fd(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let result = cache.metadata()?;
    if result.uid() != uid || result.gid() != gid || result.mode() & 0o7777 != 0o700 {
        return Err(io::Error::other(
            "cache root ownership/mode verification failed",
        ));
    }
    Ok(())
}

/// Cache initialization is only supported inside the Linux mover image.
#[cfg(not(target_os = "linux"))]
pub fn prepare(_uid: u32, _gid: u32) -> io::Result<()> {
    Err(io::Error::other("cache initialization requires Linux"))
}
