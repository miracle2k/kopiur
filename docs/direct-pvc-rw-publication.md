# Direct PVC RW-publication compatibility

This opt-in mode backs up ordinary files on a live `ReadWriteOnce` PVC when a
CSI driver accepts a second same-node RW publication but rejects a second RO
publication. It retains the PVC source model and existing Direct colocation.
No driver detection enables it automatically.

**CSI publication RW != mover process write access.** Kubernetes publishes the
PVC writable to the Pod, while the mover receives a read-only container mount.
This is strong process-level protection, not a hardware-level immutable source.
The application can still write. Live database consistency, privileged node
administrators and arbitrary CSI implementations are outside this guarantee.

Preserving the live source does not imply that Kopia archives every attribute.
The pinned Kopia 0.23.1 does not store POSIX ACLs or extended attributes in its
[snapshot entries](https://github.com/kopia/kopia/blob/v0.23.1/snapshot/manifest.go#L114-L125);
its [restore implementation](https://github.com/kopia/kopia/blob/v0.23.1/snapshot/restore/local_fs_output.go#L249-L290)
restores ownership, permission modes and timestamps. Compatibility backups leave
source ACLs/xattrs unchanged, but cannot recover those attributes from Kopia.
The validation drill checks source preservation including ACLs/xattrs separately
from scratch restoration of contents, UID/GID, modes and nanosecond mtimes.

| Mode | PVC publication | Mover mount | Pod fsGroup |
| --- | --- | --- | --- |
| Ordinary Direct | RO | RO | Existing defaults |
| RW-publication compatibility | RW | RO | Forbidden |
| Writable Direct | RW | RW | Existing defaults; `acknowledgeLiveMutation` required |

When `pvcPublicationReadOnly` is absent, its value resolves to the existing
`readOnly` value. Existing policies keep their behavior. Compatibility mode
cannot be combined with `readOnly: false` or `acknowledgeLiveMutation`.

## Installation and policy

Install the CRDs and matching controller, webhook and mover images. A cluster
administrator must install the mandatory fail-closed admission policy and binding:

```sh
kubectl apply --server-side -f deploy/admission/rw-publication.yaml
```

Helm users can enable `rwPublicationAdmission.enabled`. It defaults off because
these are cluster-scoped resources, including for a namespaced installation.
The controller requires read access to the two named admission objects and
verifies their exact specs before creating a compatibility Job. The generated
cluster-role grants only `get` on those names; mover RBAC is unchanged. A
namespaced installation needs an administrator-supplied ClusterRoleBinding for
that check and the existing namespace/colocation discovery permissions.

```yaml
apiVersion: kopiur.home-operations.com/v1alpha1
kind: SnapshotPolicy
metadata:
  name: app-files
spec:
  repository:
    name: object-store
  copyMethod: Direct
  sources:
    - pvc:
        name: app-data
      readOnly: true
      pvcPublicationReadOnly: false
      acknowledgeReadWritePublication: true
  mover:
    securityContext:
      runAsUser: 1000
      runAsGroup: 1000
    podSecurityContext:
      supplementalGroups: [1000]
```

Choose the UID/GID from known application permissions. Kopiur never guesses file
ownership or rewrites source permissions to make a backup succeed. Ensure all
included files/directories are readable; exclude unrelated root-only filesystem
maintenance directories such as `lost+found` through normal file exclusions.

Initial support is limited to one literal PVC source, `copyMethod: Direct`,
logical read-only access, a bound filesystem PVC with exactly `ReadWriteOnce`,
and an S3, Azure Blob, GCS or B2 repository. Selectors, NFS, streams, Clone,
Snapshot, RWOP, filesystem repositories and other repository types are rejected.
Direct colocation is required; `Disabled` is rejected and an unknown source node
blocks launch. The mover continues using its PVC if an application Pod is replaced.

## Security context and cache

Compatibility resolution starts with `podSecurityContext: {}` and the ordinary
hardened container baseline. Repository defaults, inherited workload/PVC-consumer
settings and explicit policy settings merge normally. An effective `fsGroup` or
`fsGroupChangePolicy` fails the Snapshot before Job creation, regardless of which
layer supplied it. Kopiur does not silently remove either field. This prevents
kubelet from recursively changing the live volume before Kopia starts.
Effective `seLinuxOptions` and `seLinuxChangePolicy` are also rejected to prevent
live-source relabeling and xattr changes.

UID, GID and supplemental groups are allowed because they affect process
identity. The main mover must keep `runAsNonRoot: true`,
`allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, no added
capabilities, and `RuntimeDefault` seccomp. Root/privileged source movers are
forbidden even in a namespace that permits privileged movers.

Only an ordinary `emptyDir` cache is initially supported. The mover checks actual
cache writability without `fsGroup` before invoking Kopia. A writable `emptyDir`
was observed on K7, but this is not assumed for every runtime or cluster.
Sized ephemeral PVC caches, persistent caches, a cache StorageClass and
filesystem repository volumes are unsupported in this mode.

If cache preparation is needed, explicitly add:

```yaml
mover:
  cache:
    ownership: InitContainer
```

This option is initially per-policy only. Repository-wide cache ownership and
other mover roles reject it. The namespace must explicitly carry the annotation
`kopiur.home-operations.com/privileged-movers: "true"` and permit the root init
container under Pod Security Admission. Restricted Pod Security rejects it;
Kopiur never changes namespace security settings automatically.

The initializer uses the same Kopiur image as the mover, drops all capabilities
and adds only `CHOWN`, denies escalation and has a read-only root filesystem.
It opens a fresh root-owned cache directory without following symlinks, rejects
nonempty/existing ownership, chmods only that root to `0700`, and changes only
that inode to the resolved mover UID/GID. It never recursively traverses cache
content. It mounts only the cache: no source, restore target, credentials,
work spec or service-account token. API access is projected into the main mover
explicitly so Kubernetes cannot automatically mount it into the initializer.

## Admission and runtime protection

Compatibility Jobs disable common Istio, Linkerd, Consul and Vault injection
where supported. The mandatory admission guard rejects sidecars, extra init or
ephemeral containers, source aliases, writable source mounts, host paths, host
namespaces, mount propagation, weakened container hardening and Pod ownership
settings after mutating admission has run. It also checks the cache initializer
and its namespace gate. Labels and the independent startup argument identify
protected Jobs/Pods; updates cannot remove their protection. Administrators must
keep this guard installed throughout the Job lifecycle.

Before any Kopia invocation, the mover compares its work-spec marker with the
independent Job startup argument, then reads `/proc/self/mountinfo`. It requires
an exact RO source mount and rejects writable nested mounts. Per-mount flags are
checked rather than superblock flags: the CSI superblock can correctly remain RW
while the mover's bind mount is RO. Missing or contradictory proof fails closed.

Validate new cluster/driver combinations on disposable data first. The
[HCloud validation drill](validation/hcloud-rw-publication.md) tests source
content/metadata preservation, cache preparation, holder replacement and a
scratch restore. Unit/rendering tests alone do not establish these properties on
a CSI driver.
