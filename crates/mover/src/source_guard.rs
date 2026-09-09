//! Fail-closed process protection for Direct PVC RW publication.
//!
//! CSI receives RW, while the container bind mount must be RO. In mountinfo the
//! per-mount options (before ` - `) describe that bind mount; the superblock can
//! correctly remain RW. Never confuse those two fields. This is process-level
//! protection, not an immutable block-device or crash-consistency guarantee.

use std::io;
use std::path::{Path, PathBuf};

use crate::workspec::Operation;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// Check the two independent guard markers and then the actual kernel mount.
/// Legacy operations without either marker keep their existing behavior.
/// The checks apply identically to non-root and namespace-authorized root movers:
/// UID 0 cannot substitute for a read-only mount or skip its verification.
pub fn preflight(operation: &Operation, required_mount: Option<&Path>) -> io::Result<()> {
    let guarded = matches!(operation, Operation::Snapshot(op) if op.require_read_only_source);
    if guarded != required_mount.is_some() {
        return Err(invalid(
            "work-spec read-only guard and --require-read-only-source must both be present",
        ));
    }
    let Some(mount) = required_mount else {
        return Ok(());
    };
    let Operation::Snapshot(op) = operation else {
        return Err(invalid("read-only source protection requires a Snapshot"));
    };
    if op.stdin.is_some() {
        return Err(invalid(
            "read-only PVC source protection cannot guard a stream",
        ));
    }
    verify_source_mount(mount)?;
    let root = mount.canonicalize()?;
    let source = Path::new(&op.source_path).canonicalize()?;
    if !source.starts_with(&root) {
        return Err(invalid(
            "snapshot source resolves outside its guarded PVC mount",
        ));
    }
    verify_cache_writable(Path::new(kopiur_kopia::env::DEFAULT_CACHE_DIR))
}

/// Inspect Linux's actual per-mount flags. A writable nested mount is rejected
/// as well, even if the source root itself is RO (bind mounts need not recurse).
pub fn verify_source_mount(source: &Path) -> io::Result<()> {
    validate_source_mount_path(source)?;
    let canonical = source.canonicalize()?;
    if canonical != source {
        return Err(invalid(
            "source mount must be canonical and must not be a symlink",
        ));
    }
    verify_mountinfo(&std::fs::read_to_string("/proc/self/mountinfo")?, source)
}

/// Refuse mounts that could obscure kernel inspection, executable/configuration
/// files, cache, or API credentials. Both parent and child overlaps are unsafe:
/// `/var` would place the writable cache inside the source just as surely as
/// mounting the source underneath `/var/cache/kopia` would hide source bytes.
pub fn validate_source_mount_path(source: &Path) -> io::Result<()> {
    if !source.is_absolute()
        || source
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(invalid(
            "source mount must be an absolute path without parent traversal",
        ));
    }
    for protected in [
        "/proc",
        "/sys",
        "/dev",
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/run",
        "/var/run",
        kopiur_kopia::env::DEFAULT_CACHE_DIR,
    ] {
        let protected = Path::new(protected);
        if source.starts_with(protected) || protected.starts_with(source) {
            return Err(invalid(format!(
                "source mount overlaps reserved path {}",
                protected.display()
            )));
        }
    }
    Ok(())
}

fn decode_mount_path(encoded: &str) -> io::Result<PathBuf> {
    let mut bytes = Vec::with_capacity(encoded.len());
    let mut input = encoded.bytes();
    while let Some(byte) = input.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        let escape = [input.next(), input.next(), input.next()];
        let decoded = match escape {
            [Some(b'0'), Some(b'4'), Some(b'0')] => b' ',
            [Some(b'0'), Some(b'1'), Some(b'1')] => b'\t',
            [Some(b'0'), Some(b'1'), Some(b'2')] => b'\n',
            [Some(b'1'), Some(b'3'), Some(b'4')] => b'\\',
            _ => return Err(invalid("invalid mountinfo path escape")),
        };
        bytes.push(decoded);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(std::ffi::OsString::from_vec(bytes).into())
    }
    #[cfg(not(unix))]
    {
        Ok(String::from_utf8(bytes)
            .map_err(|_| invalid("non-UTF8 mount path"))?
            .into())
    }
}

/// Pure parser used by startup and tests. Require an exact source mount entry;
/// a read-only ancestor alone does not prove the requested PVC was mounted.
pub fn verify_mountinfo(mountinfo: &str, source: &Path) -> io::Result<()> {
    let mut found = false;
    for line in mountinfo.lines() {
        let (mount, filesystem) = line
            .split_once(" - ")
            .ok_or_else(|| invalid("malformed mountinfo entry"))?;
        let fields: Vec<_> = mount.split_ascii_whitespace().collect();
        if fields.len() < 6 || filesystem.split_ascii_whitespace().count() < 3 {
            return Err(invalid("truncated mountinfo entry"));
        }
        let path = decode_mount_path(fields[4])?;
        if !path.starts_with(source) {
            continue;
        }
        found |= path == source;
        let options: Vec<_> = fields[5].split(',').collect();
        if !options.contains(&"ro") || options.contains(&"rw") {
            return Err(invalid(format!(
                "source contains a writable mount at {}",
                path.display()
            )));
        }
    }
    if !found {
        return Err(invalid("source has no exact read-only mountinfo entry"));
    }
    Ok(())
}

/// Disposable E2E diagnostic only: require the kernel to return EROFS, rather
/// than accepting a permissions-based denial that could mask a writable mount.
pub fn verify_write_refused(source: &Path) -> io::Result<()> {
    verify_source_mount(source)?;
    let probe = source.join(format!(".kopiur-ro-probe-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Err(error) if error.raw_os_error() == Some(libc::EROFS) => Ok(()),
        Err(error) => Err(invalid(format!(
            "write probe expected EROFS, received {error}"
        ))),
        Ok(file) => {
            drop(file);
            std::fs::remove_file(&probe)?;
            Err(invalid("source unexpectedly accepted a write probe"))
        }
    }
}

/// Test the actual emptyDir under the mover's effective identity. Its writability
/// without fsGroup is cluster/runtime dependent and cannot be assumed universally.
pub fn verify_cache_writable(cache: &Path) -> io::Result<()> {
    let probe = cache.join(format!(".kopiur-cache-probe-{}", std::process::id()));
    let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&probe)
        .map_err(|e| invalid(format!("cache is not writable without fsGroup: {e}; configure cache ownership InitContainer in an authorized namespace")))?;
    drop(file);
    std::fs::remove_file(probe)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, options: &str) -> String {
        format!("42 1 0:1 / {path} {options} - ext4 /dev/sda rw,relatime\n")
    }

    #[test]
    fn mismatched_independent_guard_markers_fail_before_filesystem_or_kopia() {
        let operation = |guard: bool| {
            Operation::Snapshot(
                serde_json::from_value(serde_json::json!({
                    "sourcePath": "/does-not-exist",
                    "requireReadOnlySource": guard,
                }))
                .unwrap(),
            )
        };
        preflight(&operation(false), None).unwrap();
        assert!(
            preflight(&operation(true), None)
                .unwrap_err()
                .to_string()
                .contains("both be present")
        );
        assert!(
            preflight(&operation(false), Some(Path::new("/does-not-exist")))
                .unwrap_err()
                .to_string()
                .contains("both be present")
        );
    }

    #[test]
    fn read_only_bind_on_read_write_superblock_is_safe() {
        verify_mountinfo(&entry("/pvc/data", "ro,relatime"), Path::new("/pvc/data")).unwrap();
    }

    #[test]
    fn reserved_mount_paths_and_parent_traversal_are_refused() {
        for source in [
            "/",
            "/proc",
            "/proc/self/mountinfo",
            "/var",
            "/var/cache",
            "/var/cache/kopia/source",
            "/var/run/secrets",
            "/usr/local/bin",
            "/pvc/../proc",
            "relative",
        ] {
            assert!(
                validate_source_mount_path(Path::new(source)).is_err(),
                "must reject {source}"
            );
        }
        validate_source_mount_path(Path::new("/pvc/app-data")).unwrap();
        validate_source_mount_path(Path::new("/data")).unwrap();
    }

    #[test]
    fn writable_root_or_descendant_fails_closed() {
        for mounts in [
            entry("/pvc/data", "rw,relatime"),
            entry("/pvc/data", "ro") + &entry("/pvc/data/nested", "rw"),
            entry("/pvc", "ro"),
            "malformed".into(),
            entry("/pvc/data", "ro,rw"),
        ] {
            assert!(verify_mountinfo(&mounts, Path::new("/pvc/data")).is_err());
        }
    }

    #[test]
    fn escaped_paths_and_component_boundaries_are_respected() {
        let mounts = entry("/pvc/my\\040data", "ro") + &entry("/pvc/my\\040data-other", "rw");
        verify_mountinfo(&mounts, Path::new("/pvc/my data")).unwrap();
        assert!(verify_mountinfo(&entry("/pvc/bad\\999", "ro"), Path::new("/pvc/bad")).is_err());
    }

    #[test]
    fn cache_probe_cleans_up_and_does_not_clobber_existing_files() {
        let cache = tempfile::tempdir().unwrap();
        verify_cache_writable(cache.path()).unwrap();
        assert_eq!(cache.path().read_dir().unwrap().count(), 0);
        let probe = cache
            .path()
            .join(format!(".kopiur-cache-probe-{}", std::process::id()));
        std::fs::write(&probe, "existing").unwrap();
        assert!(verify_cache_writable(cache.path()).is_err());
        assert_eq!(std::fs::read_to_string(probe).unwrap(), "existing");
    }
}
