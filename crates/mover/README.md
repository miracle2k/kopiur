# kopiur-mover

The per-`Snapshot`/`Restore` Job binary that drives `kopia` inside a pod — and the
pure data library that defines its contract with the controller.

## Role in the workspace

The mover is primarily a **binary** (`main.rs`): a statically-linked
musl/distroless Rust executable (~8 MB) that ships in an image alongside the
`kopia` binary (ADR §4.10). At runtime it:

1. reads its [`workspec::MoverWorkSpec`] from a mounted JSON file written by the
   controller as a `ConfigMap`;
2. invokes `kopia --json` (via [`kopiur-kopia`](../kopia)) for the long-running
   snapshot / restore / delete / bootstrap operation;
3. `PATCH`es progress and a terminal [`status::StatusUpdate`] onto the target
   CR's status subresource;
4. on failure writes a structured [`status::FailureBlock`] and exits non-zero.

But the mover's **pure data modules are exposed as a library** so the controller
can construct a [`workspec::MoverWorkSpec`] — the controller↔mover JSON contract
(ADR §4.10) — and unit-test that construction without a cluster or a kopia
subprocess. Only the cluster-free layers are public:

- [`workspec`] — the work-spec contract (operation, resolved identity, repository
  connect info, target ref, options). Round-trips losslessly through serde_json.
- [`status`] — the pure `kopia`-result → CR-status mapping ([`status::StatusUpdate`],
  [`status::FailureBlock`], [`status::MoverPhase`]).
- [`bootstrap`] — the repository connect-vs-create decision ([`bootstrap::BootstrapResult`],
  [`bootstrap::should_attempt_create`]).
- [`env`](mod@crate::env) — the mover's environment-variable contract.

The kube `PATCH` path lives in `main.rs` and is intentionally _not_ part of the
library surface.

## The contract: `MoverWorkSpec`

The spec carries **resolved values only** — identity already rendered, repository
connect info concrete (ADR §4.2). The mover never re-derives anything; it executes
exactly what the controller decided. Both the [`workspec::Operation`] selector and
the [`workspec::RepositoryConnect`] backend selector are **externally-tagged
enums** (`{ "snapshot": {...} }`, `{ "filesystem": {...} }`), mirroring the api
crate's enum discipline: a new operation or backend cannot compile until every
`match` handles it. Credentials are _not_ in the spec — they arrive as env vars
from a mounted Secret, so they never land in a ConfigMap.

## Key types

| Type                                                                         | What it is                                                          |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| [`workspec::MoverWorkSpec`]                                                  | The full controller→mover JSON contract                             |
| [`workspec::Operation`]                                                      | Snapshot / Restore / SnapshotDelete / BootstrapRepository           |
| [`workspec::RepositoryConnect`]                                              | Serializable backend selector (mirrors `kopiur_kopia::ConnectSpec`) |
| [`workspec::ResolvedIdentity`]                                               | The pinned `username@hostname:path` identity                        |
| [`status::StatusUpdate`] / [`status::FailureBlock`] / [`status::MoverPhase`] | Pure result → CR-status mapping                                     |
| [`bootstrap::BootstrapResult`]                                               | Outcome of a repository bootstrap run                               |

## Example

Construct a backup `MoverWorkSpec` the way the controller does and round-trip it
through serde_json, confirming the externally-tagged wire shape:

```rust
use std::collections::BTreeMap;
use kopiur_mover::workspec::*;

let spec = MoverWorkSpec {
    version: 1,
    operation: Operation::Snapshot(SnapshotOp {
        require_read_only_source: false,
        stdin: None,
        source_path: "/data".into(),
        tags: BTreeMap::new(),
        policy: Default::default(),
        fail_fast: None,
        upload_limit_mb: None,
        description: None,
    }),
    identity: ResolvedIdentity {
        username: "mydb".into(),
        hostname: "prod".into(),
        source_path: "/data".into(),
    },
    repository: RepositoryConnect::Filesystem { path: "/repo".into() },
    target_ref: TargetRef {
        api_version: "kopiur.home-operations.com/v1alpha1".into(),
        kind: "Snapshot".into(),
        name: "mydb-20260601".into(),
        namespace: "prod".into(),
    },
    hook_plan: HookPlanSummary::default(),
    options: MoverOptions::default(),
    cache: kopiur_kopia::CacheTuning::default(),
    throttle: Default::default(),
};

// Round-trips through serde_json unchanged.
let json = serde_json::to_string(&spec).unwrap();
let back: MoverWorkSpec = serde_json::from_str(&json).unwrap();
assert_eq!(back, spec);

// Externally tagged on the wire (camelCase keys).
let v: serde_json::Value = serde_json::to_value(&spec).unwrap();
assert_eq!(v["operation"]["snapshot"]["sourcePath"], "/data");
assert_eq!(v["repository"]["filesystem"]["path"], "/repo");
assert_eq!(spec.operation.kind_str(), "Snapshot");
```

The actual `kopia` invocation and the kube `PATCH` happen in the binary against a
real repository and cluster, so they are not runnable doctests.

## Direct PVC RW-publication protection

Explicit compatibility Jobs publish the source PVC RW to CSI and mount it RO in
the mover. **CSI publication RW != mover process write access.** The main mover
defaults to non-root. An explicitly configured root identity uses the existing
`kopiur.home-operations.com/privileged-movers=true` namespace gate. Root still
receives the RO source mount, no added capabilities, no privilege escalation,
and RuntimeDefault seccomp; it does not bypass the kernel mount preflight.
Pod `fsGroup` and `fsGroupChangePolicy` are
rejected before Job creation, because kubelet could otherwise rewrite the live
source's ownership and modes before this binary ever runs.

The work spec's `requireReadOnlySource` marker and independent
`--require-read-only-source PATH` argument must agree. Before any Kopia command or
credential staging, the mover verifies an exact RO source mount in
`/proc/self/mountinfo`, rejects any writable nested mount, and checks that its
cache is writable under the actual process identity. It checks per-mount flags;
the underlying filesystem superblock correctly remains RW for the application.
Protected system, credential, and cache paths cannot be used as source mounts.

Optional `cache-init --uid UID --gid GID` runs in the same pinned image. It receives
only the ordinary emptyDir cache at `/var/cache/kopia`, with no env, source,
repository, work spec, or service-account credentials. It accepts only an empty
root:root cache root, opens it without following symlinks, chmods that inode to
0700, then uses its sole added CHOWN capability to assign the effective mover
UID/GID, including UID 0 when the main mover deliberately runs as root. Reused
caches fail closed. This root init container requires the deliberate
namespace privilege gate; Pod-wide fsGroup remains absent. API credentials are
explicitly projected only into the main mover, with automatic token mounts off.

Admission validates the final Job/Pod shape and forbids injected containers or
altered source mounts; common sidecar injectors also receive opt-out annotations.
The RO bind mount is strong process-level protection, not immutable hardware,
application consistency, or a guarantee against a cluster administrator.

For a disposable-volume test, `kopiur-mover verify-source-mount PATH --write-probe`
verifies mountinfo and then requires an attempted create to fail with `EROFS`.
Production startup never attempts to write the source.

## See also

- [ADR-0003](../../docs/adr/0003-kopiur-rust-operator.md) — §4.10 (mover pods &
  failure handling, the work-spec contract) and §5.4 (kopia interaction).
