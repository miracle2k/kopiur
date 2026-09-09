# Disposable HCloud RW-publication validation

This drill validates the Direct PVC compatibility mode against HCloud CSI using
throwaway data. It is separate from the repository's kind-only `crates/e2e`
suite. Never aim that suite at a production context.

Use this drill only with explicit authorization to create a disposable namespace
and HCloud volumes in the selected cluster. Install the new CRDs, controller,
webhook and mover images first. Every image must contain the same feature
revision. The mover image must be pullable in a fresh namespace, or already
available on its selected node. The harness does not borrow image-pull Secrets.

```sh
uv run scripts/validate-hcloud-rw-publication.py \
  --context k7 \
  --acknowledge-disposable-cluster-writes
```

The script exclusively creates a randomly named `kopiur-rwpub-*` namespace and
checks its UID before cleanup. It creates a private MinIO instance on an
`emptyDir`, a namespaced Repository, newly generated credentials, two 10 GiB
HCloud PVCs for source and restore, and a separate RWOP negative fixture. Nothing
uses a production Repository, source PVC, application Pod or credential. Its
source model is an ordinary PVC reference throughout; Pod identity is used only
to check existing Direct node colocation.

The namespace explicitly grants Kopiur's privileged-mover permission and uses
Baseline Pod Security for the cache initializer and scratch restore. Source
fixture setup runs as root only inside the disposable holder Pod to create
ownership, permission and ACL test cases. Compatibility backup movers remain
non-root with no added capabilities. The cache initializer must mount only its
cache. Root fixture setup and scratch-restore settings must never be copied to a
production compatibility backup policy.

The drill checks:

1. A live holder publishes the HCloud RWO source RW. The compatibility mover is
   placed on the same node and reaches Running.
2. Both the generated Job and admitted Pod retain one ordinary mover container,
   no host privileges, no Pod `fsGroup` or `fsGroupChangePolicy`, RW PVC
   publication and an RO source `volumeMount`.
   Server dry runs first accept valid Job/Pod controls, then require the installed
   source-protection policy to reject a writable source, an injected `fsGroup`,
   a sidecar and an initializer source mount. Those adversarial objects never
   persist or mount any volume.
3. Executing `kopiur-mover verify-source-mount PATH --write-probe` inside the
   actual mover verifies Linux mount information and requires a deliberate
   create attempt to fail with `EROFS`. Production startup uses the mount check
   without the deliberate write attempt. Only run the write probe against
   disposable data: an incorrectly writable mount would receive a temporary
   marker, which the diagnostic attempts to remove before reporting failure.
4. The holder writes an existing marker while the backup runs, preserving its
   bytes and restoring its original mtime so the preservation comparison remains
   meaningful. Replacing the holder Pod does not invalidate the mover's PVC
   mount. A 32 MiB random payload and upload throttle keep the first mover alive
   long enough to check this.
5. Source marker contents, UID/GID, modes, POSIX ACLs, user xattrs and nanosecond
   mtimes match before and after each backup. Reads may update atime, so it is
   deliberately excluded. A separate whole-source inventory includes the PVC
   root, unchanged ext4 `lost+found`, and seed marker, so root-level ownership or
   mode changes are detected too. The second run receives fresh random payload bytes
   before recording its own baseline, preventing repository deduplication from
   bypassing the live runtime checks.
6. Ordinary `emptyDir` works without `fsGroup`. A second run explicitly uses
   `cache.ownership: InitContainer`, mover UID/GID 1000 and supplemental group
   65532, and checks that the initializer has only a cache mount and no
   credential environment. Its resolved arguments are recorded as evidence.
7. The completed snapshot restores into a fresh scratch HCloud PVC; the restored
   marker tree matches the source bytes, UID/GID, modes and nanosecond mtimes.
   The restore deliberately uses the separately gated root restore option to
   reproduce file ownership, with `ignorePermissionErrors: false` so failures
   cannot be hidden. Kopia 0.23.1 does not store or restore POSIX ACLs or xattrs:
   its [snapshot manifest](https://github.com/kopia/kopia/blob/v0.23.1/snapshot/manifest.go#L114-L125)
   has no fields for them and its [restore attributes implementation](https://github.com/kopia/kopia/blob/v0.23.1/snapshot/restore/local_fs_output.go#L249-L290)
   applies ownership, mode and times only. The report explicitly records
   `restoreXattrDifferences` and this limitation. All source ACLs/xattrs must still
   match exactly before and after each backup; a default SELinux label appearing
   on scratch storage is not evidence that Kopia restored that label.
8. An RWOP compatibility source is rejected before any mover Job exists.
9. Cleanup suspends only the disposable repository and stops its catalog scan
   Job, preventing rediscovery from recreating Snapshot CRs during deletion.
   It removes temporary Kopiur resources while MinIO remains available for
   finalizers, then deletes the namespace and verifies deletion. It never strips
   finalizers or force-deletes a PVC. A cleanup failure names the exact namespace
   that needs inspection. The selected StorageClass must use `Delete` reclaim
   policy, and cleanup also waits for the disposable PVs to disappear.

Credential-free JSON evidence is written under `target/hcloud-validation/`,
including successful assertions, marker manifests and runtime proof. The script
does not print submitted Secret data or raw `kubectl` error output, because API
validation errors can echo submitted values. Do not add general Pod/environment
dumps or repository logs to debug this drill. Use object names, phases, container
waiting reasons and events that do not contain credentials.

CSI publication RW does not give the mover process write access: the mover's
read-only mount is the process boundary. It does not make the backend immutable
or protect against a privileged node administrator, and it does not turn a live
database directory into a consistent database backup.

Passing rendering and unit tests alone is not a substitute for this drill. Record
the tested CSI version, StorageClass, image revision and evidence path when
claiming HCloud validation. Do not update a production filesystem policy until
the disposable source-preservation and scratch-restore checks succeed.

## Recorded validation: 2026-09-09

K7 passed **51 assertions** with HCloud CSI **v2.22.1**, StorageClass
`hcloud-volumes`, `fsGroupPolicy: File`, Kopia **0.23.1**, and runtime revision
[`8faf9da`](https://github.com/miracle2k/kopiur/commit/8faf9da2f1b2fa9940be801e193a2471e172958f).
The [sanitized evidence](results/hcloud-k7-2026-09-09.json) records image digests,
runtime proof, cache-initializer settings, comparison digests and each assertion.

Both ordinary `emptyDir` and cache-only initialization at UID/GID 1000 passed.
The mover's write attempts returned `EROFS`, the holder remained writable and
could be replaced during backup, and both whole-PVC inventories remained exactly
unchanged. Scratch contents, ownership, modes and nanosecond mtimes matched with
permission errors enforced; the ACL/xattr restore limitation above is recorded
explicitly. RWOP was rejected before a mover Job existed.

Cleanup completed after pausing the disposable repository's catalog scan, which
had rediscovered two retained test snapshots. This intervention is recorded in
the evidence; the harness now pauses discovery before deleting its resources.
All temporary namespace resources and HCloud PVs were deleted without stripping
finalizers. No production source or repository credentials were used by the drill.
