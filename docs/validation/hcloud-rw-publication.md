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
   deliberately excluded. The second run receives fresh random payload bytes
   before recording its own baseline, preventing repository deduplication from
   bypassing the live runtime checks.
6. Ordinary `emptyDir` works without `fsGroup`. A second run explicitly uses
   `cache.ownership: InitContainer`, mover UID/GID 1000 and supplemental group
   65532, and checks that the initializer has only a cache mount and no
   credential environment. Its resolved arguments are recorded as evidence.
7. The completed snapshot restores into a fresh scratch HCloud PVC; the restored
   marker tree matches the source bytes and metadata. The restore deliberately
   uses the separately gated root restore option to reproduce file ownership.
8. An RWOP compatibility source is rejected before any mover Job exists.
9. Cleanup removes temporary Kopiur resources while MinIO remains available for
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
