#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Explicitly authorized, namespace-isolated HCloud Direct-publication drill.

This is deliberately separate from the kind-only repository e2e harness. It
never discovers a production source or borrows an existing repository/Secret.
Every write is confined to a namespace this process creates exclusively.
"""

import argparse
import copy
import json
import secrets
import subprocess
import sys
import time
from pathlib import Path

API = "kopiur.home-operations.com/v1alpha1"
PYTHON_IMAGE = "python:3.13.7-slim@sha256:5f55cdf0c5d9dc1a415637a5ccc4a9e18663ad203673173b8cda8f8dcacef689"
MINIO_IMAGE = "minio/minio:RELEASE.2025-04-22T22-12-26Z@sha256:a1ea29fa28355559ef137d71fc570e508a214ec84ff8083e39bc5428980b015e"
HARDENED = {
    "allowPrivilegeEscalation": False,
    "capabilities": {"drop": ["ALL"]},
    "seccompProfile": {"type": "RuntimeDefault"},
}

# The fixture owns disposable data only. Its root identity is needed to exercise
# mixed owners and POSIX ACLs, never to make the actual backup mover privileged.
SEED = r"""
import os, pathlib, struct, time
root = pathlib.Path('/data')
if not (root / 'ordinary-files').exists():
    d = root / 'ordinary-files'
    d.mkdir()
    os.chown(d, 65532, 65532)
    os.chmod(d, 0o750)
    (d / 'marker').write_bytes(b'Kopiur disposable HCloud source preservation\n')
    (d / 'app-live-marker').write_bytes(b'app remains writable\n')
    with (d / 'payload').open('wb') as f:
        for _ in range(32):
            f.write(os.urandom(1024 * 1024))
    for p in d.iterdir():
        os.chown(p, 65532, 65532)
        os.chmod(p, 0o640)
        os.setxattr(p, 'user.kopiur-test', b'preserve-this-xattr')
        # Linux POSIX ACL xattr: version 2, owner rw, named uid 2000 r,
        # group r, mask r, other none. No external ACL tools are needed.
        acl = struct.pack('<I', 2) + b''.join(
            struct.pack('<HHI', tag, perm, uid)
            for tag, perm, uid in [(1, 6, 0xffffffff), (2, 4, 2000),
                                    (4, 4, 0xffffffff), (16, 4, 0xffffffff),
                                    (32, 0, 0xffffffff)])
        os.setxattr(p, 'system.posix_acl_access', acl)
        os.utime(p, ns=(1700000000123456789, 1700000000123456789))
    os.utime(d, ns=(1700000000123456789, 1700000000123456789))
    (root / 'seed-complete').touch()
while True:
    time.sleep(30)
"""

INVENTORY = r"""
import hashlib, json, os, pathlib, stat
root = pathlib.Path('/data/ordinary-files')
out = {}
for p in [root, *sorted(root.rglob('*'))]:
    s = p.lstat()
    out[str(p.relative_to(root))] = {
        'uid': s.st_uid, 'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode),
        'mtime_ns': s.st_mtime_ns,
        'xattrs': {k: os.getxattr(p, k).hex() for k in sorted(os.listxattr(p))},
        'sha256': hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None,
    }
print(json.dumps(out, sort_keys=True))
"""

# fsGroup rewrites can start at the volume root, even when every backed-up file
# is readable. Include ext4 lost+found and the seed marker in source-preservation
# checks; restore comparison separately covers the ordinary-files snapshot tree.
WHOLE_SOURCE_INVENTORY = INVENTORY.replace(
    "Path('/data/ordinary-files')", "Path('/data')"
)

APP_WRITE = r"""
import os, pathlib
p = pathlib.Path('/data/ordinary-files/app-live-marker')
s = p.stat()
payload = p.read_bytes()
with p.open('r+b') as f:
    f.write(payload)
    f.flush()
    os.fsync(f.fileno())
os.utime(p, ns=(s.st_atime_ns, s.st_mtime_ns))
print('existing app marker write succeeded; bytes and mtime preserved')
"""

# Credentials stay in this disposable Pod's environment and signed request. They
# are never command arguments, output, existing cluster credentials, or AWS files.
MAKE_BUCKET = r"""
import datetime, hashlib, hmac, os, urllib.request
host = 'minio:9000'
now = datetime.datetime.now(datetime.timezone.utc)
date = now.strftime('%Y%m%d')
stamp = now.strftime('%Y%m%dT%H%M%SZ')
empty = hashlib.sha256(b'').hexdigest()
canonical = f'PUT\n/disposable\n\nhost:{host}\nx-amz-content-sha256:{empty}\nx-amz-date:{stamp}\n\nhost;x-amz-content-sha256;x-amz-date\n{empty}'
scope = f'{date}/us-east-1/s3/aws4_request'
to_sign = f'AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}'
key = ('AWS4' + os.environ['AWS_SECRET_ACCESS_KEY']).encode()
for part in (date, 'us-east-1', 's3', 'aws4_request'):
    key = hmac.new(key, part.encode(), hashlib.sha256).digest()
signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
auth = f"AWS4-HMAC-SHA256 Credential={os.environ['AWS_ACCESS_KEY_ID']}/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}"
request = urllib.request.Request(f'http://{host}/disposable', data=b'', method='PUT',
    headers={'Authorization': auth, 'x-amz-date': stamp, 'x-amz-content-sha256': empty})
with urllib.request.urlopen(request, timeout=30) as response:
    assert response.status == 200
"""


class Drill:
    def __init__(self, args):
        self.args = args
        self.ns = f"kopiur-rwpub-{time.strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3)}"
        self.uid = None
        self.pvs = set()
        self.report = {"namespace": self.ns, "context": args.context, "checks": []}

    def kube(self, *args, body=None, namespaced=True, allow_missing=False):
        command = ["kubectl", "--context", self.args.context, "--request-timeout=30s"]
        if namespaced:
            command += ["-n", self.ns]
        result = subprocess.run(
            command + list(args),
            input=body,
            text=True,
            capture_output=True,
            timeout=65,
            check=False,
        )
        self.last_error = result.stderr
        if result.returncode and not allow_missing:
            # Do not echo kubectl stderr: a validation error can include submitted
            # Secret data. Safe object status summaries are collected separately.
            raise RuntimeError(
                f"kubectl {args[0]} failed (exit {result.returncode}); stderr suppressed"
            )
        return result.stdout if result.returncode == 0 else None

    def get(self, kind, name=None, namespaced=True):
        args = (
            ["get", kind]
            + ([name] if name else [])
            + ["--ignore-not-found", "-o", "json"]
        )
        raw = self.kube(*args, namespaced=namespaced)
        return json.loads(raw) if raw else None

    def create(self, kind, name, spec=None, api=API, **extra):
        obj = {
            "apiVersion": api,
            "kind": kind,
            "metadata": {"name": name, "namespace": self.ns},
            **extra,
        }
        if spec is not None:
            obj["spec"] = spec
        self.kube("create", "-f", "-", body=json.dumps(obj))
        return obj

    def check(self, condition, description):
        if not condition:
            raise AssertionError(description)
        self.report["checks"].append(description)
        print(f"PASS {description}", flush=True)

    def wait(self, description, predicate, timeout=600):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(2)
        raise TimeoutError(description)

    def phase(self, kind, name, expected="Succeeded"):
        def complete():
            obj = self.get(kind, name)
            phase = (obj or {}).get("status", {}).get("phase")
            if phase in {"Failed", "Error"} and phase != expected:
                raise RuntimeError(f"{kind}/{name} phase={phase}")
            return obj if phase == expected else None

        return self.wait(f"{kind}/{name} did not reach {expected}", complete)

    def ready(self, name):
        return self.wait(
            f"Pod/{name} not ready",
            lambda: next(
                (
                    p
                    for p in [(self.get("pod", name) or {})]
                    if any(
                        c.get("type") == "Ready" and c.get("status") == "True"
                        for c in p.get("status", {}).get("conditions", [])
                    )
                ),
                None,
            ),
        )

    def exec_python(self, pod, program):
        return self.kube("exec", "-i", pod, "--", "python", "-", body=program)

    def pvc(self, name, access="ReadWriteOnce"):
        self.create(
            "PersistentVolumeClaim",
            name,
            {
                "accessModes": [access],
                "volumeMode": "Filesystem",
                "storageClassName": self.args.storage_class,
                "resources": {"requests": {"storage": "10Gi"}},
            },
            api="v1",
        )

    def fixture_pod(self, name, claim="source", script=SEED, node=None):
        sc = copy.deepcopy(HARDENED)
        sc.update(
            {
                "runAsUser": 0,
                "runAsGroup": 0,
                "runAsNonRoot": False,
                "capabilities": {
                    "drop": ["ALL"],
                    "add": ["CHOWN", "FOWNER", "DAC_OVERRIDE"],
                },
            }
        )
        spec = {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {},
            "terminationGracePeriodSeconds": 1,
            "containers": [
                {
                    "name": "fixture",
                    "image": PYTHON_IMAGE,
                    "command": ["python", "-c", script],
                    "securityContext": sc,
                    "resources": {
                        "requests": {"cpu": "20m", "memory": "64Mi"},
                        "limits": {"cpu": "500m", "memory": "192Mi"},
                    },
                    "volumeMounts": [{"name": "data", "mountPath": "/data"}],
                }
            ],
            "volumes": [
                {"name": "data", "persistentVolumeClaim": {"claimName": claim}}
            ],
        }
        if node:
            spec["nodeSelector"] = {"kubernetes.io/hostname": node}
        self.create("Pod", name, spec, api="v1")
        return self.ready(name)

    def admission_probes(self, job, initializer):
        """Dry-run real admission against the disposable source; persist nothing."""
        for kind in ("Job", "Pod"):
            template = job["spec"]["template"]
            original_metadata = (
                job["metadata"] if kind == "Job" else template["metadata"]
            )
            metadata = {
                key: copy.deepcopy(original_metadata[key])
                for key in ("labels", "annotations")
                if key in original_metadata
            }
            metadata.update(
                {"name": f"admission-{kind.lower()}-control", "namespace": self.ns}
            )
            spec = copy.deepcopy(job["spec"] if kind == "Job" else template["spec"])
            # Job selectors/UID labels are generated by Kubernetes; a dry-run new
            # Job needs its own generated selector rather than the original UID.
            if kind == "Job":
                spec.pop("selector", None)
                for key in (
                    "controller-uid",
                    "batch.kubernetes.io/controller-uid",
                    "job-name",
                    "batch.kubernetes.io/job-name",
                ):
                    spec["template"]["metadata"].get("labels", {}).pop(key, None)
            obj = {
                "apiVersion": "batch/v1" if kind == "Job" else "v1",
                "kind": kind,
                "metadata": metadata,
                "spec": spec,
            }
            self.kube("create", "--dry-run=server", "-f", "-", body=json.dumps(obj))
            self.check(True, f"admission: valid {kind} accepted (dry run)")

            mutations = ["writable-source", "fs-group", "sidecar"]
            if initializer:
                mutations.append("initializer-source-alias")
            for mutation in mutations:
                altered = copy.deepcopy(obj)
                altered["metadata"]["name"] = f"admission-{kind.lower()}-{mutation}"
                pod_spec = (
                    altered["spec"]["template"]["spec"]
                    if kind == "Job"
                    else altered["spec"]
                )
                if mutation == "writable-source":
                    next(
                        m
                        for m in pod_spec["containers"][0]["volumeMounts"]
                        if m["name"] == "source"
                    )["readOnly"] = False
                elif mutation == "fs-group":
                    pod_spec.setdefault("securityContext", {})["fsGroup"] = 65532
                elif mutation == "sidecar":
                    sidecar = copy.deepcopy(pod_spec["containers"][0])
                    sidecar["name"] = "injected-sidecar"
                    pod_spec["containers"].append(sidecar)
                else:
                    pod_spec["initContainers"][0]["volumeMounts"].append(
                        {
                            "name": "source",
                            "mountPath": "/unexpected-source",
                            "readOnly": True,
                        }
                    )
                result = self.kube(
                    "create",
                    "--dry-run=server",
                    "-f",
                    "-",
                    body=json.dumps(altered),
                    allow_missing=True,
                )
                self.check(
                    result is None and "kopiur-rw-publication" in self.last_error,
                    f"admission: {kind} {mutation} rejected by source-protection policy (dry run)",
                )

    def provision(self):
        admission = self.get(
            "validatingadmissionpolicy", "kopiur-rw-publication", namespaced=False
        )
        binding = self.get(
            "validatingadmissionpolicybinding",
            "kopiur-rw-publication",
            namespaced=False,
        )
        self.check(
            admission is not None
            and binding is not None
            and "Deny" in binding["spec"].get("validationActions", []),
            "source-protection admission policy and Deny binding are installed",
        )
        self.report["admissionGeneration"] = admission["metadata"]["generation"]
        driver = self.get("csidriver", "csi.hetzner.cloud", namespaced=False)
        self.report["csiDriver"] = driver.get("spec") if driver else None
        self.report["csiImages"] = self.kube(
            "get",
            "daemonset",
            "hcloud-csi-node",
            "-n",
            "kube-system",
            "-o",
            "jsonpath={.spec.template.spec.containers[*].image}",
            namespaced=False,
        ).split()
        sc = self.get("storageclass", self.args.storage_class, namespaced=False)
        self.check(
            sc and sc.get("provisioner") == "csi.hetzner.cloud",
            "explicit StorageClass uses HCloud CSI",
        )
        self.check(
            sc.get("reclaimPolicy", "Delete") == "Delete",
            "disposable StorageClass deletes dynamically provisioned volumes",
        )
        # Create, never apply: an accidental name collision cannot adopt an
        # existing namespace. The UID is checked again before any cleanup.
        namespace = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": self.ns,
                "labels": {
                    "kopiur-rwpub-drill": "true",
                    "pod-security.kubernetes.io/enforce": "baseline",
                },
                "annotations": {"kopiur.home-operations.com/privileged-movers": "true"},
            },
        }
        self.kube("create", "-f", "-", body=json.dumps(namespace), namespaced=False)
        self.uid = self.get("namespace", self.ns, namespaced=False)["metadata"]["uid"]
        self.report["namespaceUID"] = self.uid
        print(f"Created disposable namespace {self.ns}", flush=True)
        self.create(
            "Secret",
            "disposable-credentials",
            api="v1",
            type="Opaque",
            stringData={
                "AWS_ACCESS_KEY_ID": secrets.token_hex(12),
                "AWS_SECRET_ACCESS_KEY": secrets.token_urlsafe(32),
                "KOPIA_PASSWORD": secrets.token_urlsafe(32),
            },
        )
        secret_ref = lambda key: {
            "secretKeyRef": {"name": "disposable-credentials", "key": key}
        }
        self.create(
            "Pod",
            "minio",
            {
                "automountServiceAccountToken": False,
                "restartPolicy": "Never",
                "containers": [
                    {
                        "name": "minio",
                        "image": MINIO_IMAGE,
                        "args": ["server", "/data"],
                        "securityContext": {
                            **HARDENED,
                            "runAsUser": 1000,
                            "runAsGroup": 1000,
                            "runAsNonRoot": True,
                        },
                        "env": [
                            {"name": "HOME", "value": "/tmp"},
                            {
                                "name": "MINIO_ROOT_USER",
                                "valueFrom": secret_ref("AWS_ACCESS_KEY_ID"),
                            },
                            {
                                "name": "MINIO_ROOT_PASSWORD",
                                "valueFrom": secret_ref("AWS_SECRET_ACCESS_KEY"),
                            },
                        ],
                        "resources": {
                            "requests": {"cpu": "50m", "memory": "128Mi"},
                            "limits": {"cpu": "1000m", "memory": "512Mi"},
                        },
                        "readinessProbe": {
                            "httpGet": {"path": "/minio/health/ready", "port": 9000}
                        },
                        "volumeMounts": [{"name": "data", "mountPath": "/data"}],
                    }
                ],
                "volumes": [{"name": "data", "emptyDir": {"sizeLimit": "1Gi"}}],
            },
            api="v1",
            metadata={
                "name": "minio",
                "namespace": self.ns,
                "labels": {"app": "minio"},
            },
        )
        self.create(
            "Service",
            "minio",
            {
                "selector": {"app": "minio"},
                "ports": [{"port": 9000, "targetPort": 9000}],
            },
            api="v1",
        )
        self.ready("minio")
        self.create(
            "Pod",
            "bucket-create",
            {
                "automountServiceAccountToken": False,
                "restartPolicy": "Never",
                "containers": [
                    {
                        "name": "bucket-create",
                        "image": PYTHON_IMAGE,
                        "command": ["python", "-c", MAKE_BUCKET],
                        "securityContext": HARDENED,
                        "envFrom": [{"secretRef": {"name": "disposable-credentials"}}],
                    }
                ],
            },
            api="v1",
        )
        self.phase("pod", "bucket-create")
        self.create(
            "Repository",
            "disposable",
            {
                "backend": {
                    "s3": {
                        "bucket": "disposable",
                        "region": "us-east-1",
                        "endpoint": f"minio.{self.ns}.svc.cluster.local:9000",
                        "tls": {"disableTls": True},
                        "auth": {"secretRef": {"name": "disposable-credentials"}},
                    }
                },
                "encryption": {
                    "passwordSecretRef": {
                        "name": "disposable-credentials",
                        "key": "KOPIA_PASSWORD",
                    }
                },
                "create": {"enabled": True},
                "maintenance": {"enabled": False},
                "moverDefaults": {
                    "sourceColocation": {"mode": "Auto"},
                    "throttle": {"uploadBytesPerSecond": 262144},
                    "ttlSecondsAfterFinished": 3600,
                },
            },
        )
        self.phase("repository", "disposable", "Ready")
        self.pvc("source")
        holder = self.fixture_pod("holder")
        self.node = holder["spec"]["nodeName"]
        self.report["holderNode"] = self.node
        self.wait(
            "fixture seed did not finish",
            lambda: (
                self.exec_python(
                    "holder",
                    "import pathlib; print(pathlib.Path('/data/seed-complete').exists())",
                )
                == "True\n"
            ),
        )
        self.before = json.loads(self.exec_python("holder", INVENTORY))
        self.report["sourceBefore"] = self.before
        self.source_before = json.loads(
            self.exec_python("holder", WHOLE_SOURCE_INVENTORY)
        )
        self.report["wholeSourceBefore"] = self.source_before

    def backup(self, name, initializer=False, replace_holder=False):
        if initializer:
            # Fresh bytes keep this second run uploading long enough for runtime
            # checks; repository deduplication would otherwise finish immediately.
            self.exec_python(
                "holder",
                "import os, pathlib\np = pathlib.Path('/data/ordinary-files/payload')\ns = p.stat()\np.write_bytes(os.urandom(32 * 1024 * 1024))\nos.utime(p, ns=(s.st_atime_ns, s.st_mtime_ns))\n",
            )
            self.before = json.loads(self.exec_python("holder", INVENTORY))
            self.report["sourceBeforeInitializedCache"] = self.before
            self.source_before = json.loads(
                self.exec_python("holder", WHOLE_SOURCE_INVENTORY)
            )
            self.report["wholeSourceBeforeInitializedCache"] = self.source_before
        source = {
            "pvc": {"name": "source"},
            "readOnly": True,
            "pvcPublicationReadOnly": False,
            "acknowledgeReadWritePublication": True,
        }
        mover = {"ttlSecondsAfterFinished": 3600}
        if initializer:
            mover.update(
                {
                    "cache": {"ownership": "InitContainer"},
                    "securityContext": {"runAsUser": 1000, "runAsGroup": 1000},
                    "podSecurityContext": {"supplementalGroups": [65532]},
                }
            )
        self.create(
            "SnapshotPolicy",
            name,
            {
                "repository": {"kind": "Repository", "name": "disposable"},
                "copyMethod": "Direct",
                "sources": [source],
                "mover": mover,
                "retention": {"keepLatest": 5},
                "defaultDeletionPolicy": "Retain",
            },
        )
        self.create(
            "Snapshot", name, {"policyRef": {"name": name}, "deletionPolicy": "Retain"}
        )
        job = self.wait(f"{name} Job missing", lambda: self.get("job", name))
        self.admission_probes(job, initializer)
        spec = job["spec"]["template"]["spec"]
        self.check(
            not any(
                k in spec.get("securityContext", {})
                for k in ("fsGroup", "fsGroupChangePolicy")
            ),
            f"{name}: no Pod fsGroup or fsGroupChangePolicy",
        )
        self.check(
            len(spec["containers"]) == 1,
            f"{name}: exactly one ordinary mover container",
        )
        source_volume = next(v for v in spec["volumes"] if v["name"] == "source")
        mount = next(
            v for v in spec["containers"][0]["volumeMounts"] if v["name"] == "source"
        )
        self.check(
            # Kubernetes omits its false-valued Go bool when serializing a PVC
            # publication. Missing here means RW; policy opt-in remains explicit.
            source_volume["persistentVolumeClaim"].get("readOnly", False) is False
            and mount.get("readOnly") is True,
            f"{name}: RW PVC publication and RO mover mount",
        )
        self.check(
            not any(spec.get(k, False) for k in ("hostNetwork", "hostPID", "hostIPC"))
            and not any("hostPath" in v for v in spec["volumes"]),
            f"{name}: no host privileges or paths",
        )
        inits = spec.get("initContainers", [])
        self.check(
            len(inits) == int(initializer), f"{name}: expected cache initializer count"
        )
        if initializer:
            self.check(
                [v["name"] for v in inits[0].get("volumeMounts", [])] == ["kopia-cache"]
                and not inits[0].get("envFrom")
                and not inits[0].get("env"),
                f"{name}: cache initializer sees cache only and no credentials",
            )
            self.report["cacheInitializer"] = {
                k: inits[0].get(k)
                for k in ("image", "args", "securityContext", "volumeMounts")
            }
        pod = self.wait(
            f"{name} Pod missing",
            lambda: next(
                iter(
                    [
                        p
                        for p in self.get("pods").get("items", [])
                        if p["metadata"].get("labels", {}).get("job-name") == name
                    ]
                ),
                None,
            ),
        )
        pod_name = pod["metadata"]["name"]
        self.ready(pod_name)
        admitted = self.get("pod", pod_name)
        self.report.setdefault("moverImages", {})[name] = {
            "image": admitted["spec"]["containers"][0]["image"],
            "imageID": admitted["status"]["containerStatuses"][0].get("imageID"),
        }
        self.check(
            admitted["spec"]["nodeName"] == self.node,
            f"{name}: mover colocated with live holder",
        )
        self.check(
            len(admitted["spec"]["containers"]) == 1,
            f"{name}: no admitted sidecar injection",
        )
        admitted_spec = admitted["spec"]
        self.check(
            not any(
                k in admitted_spec.get("securityContext", {})
                for k in ("fsGroup", "fsGroupChangePolicy")
            )
            and next(v for v in admitted_spec["volumes"] if v["name"] == "source")[
                "persistentVolumeClaim"
            ].get("readOnly", False)
            is False
            and next(
                v
                for v in admitted_spec["containers"][0]["volumeMounts"]
                if v["name"] == "source"
            ).get("readOnly")
            is True,
            f"{name}: admitted Pod retains safe source mount and fsGroup exclusion",
        )
        if initializer:
            args = inits[0].get("args", [])
            self.check(
                "--uid" in args
                and args[args.index("--uid") + 1] == "1000"
                and "--gid" in args
                and args[args.index("--gid") + 1] == "1000"
                and inits[0]["image"] == spec["containers"][0]["image"],
                f"{name}: same-image cache initializer targets effective mover UID/GID 1000",
            )
        proof = self.kube(
            "exec",
            pod_name,
            "-c",
            "mover",
            "--",
            "/usr/local/bin/kopiur-mover",
            "verify-source-mount",
            mount["mountPath"],
            "--write-probe",
        )
        self.report.setdefault("runtimeProof", {})[name] = proof.strip()
        self.check(True, f"{name}: actual mover write attempt refused with EROFS")
        print(self.exec_python("holder", APP_WRITE).strip(), flush=True)
        if replace_holder:
            self.kube("delete", "pod", "holder", "--wait=false")
            self.wait(
                "old holder not deleted", lambda: self.get("pod", "holder") is None
            )
            self.fixture_pod("holder", node=self.node)
            self.check(
                self.get("pod", pod_name)["status"]["phase"] == "Running",
                f"{name}: mover survived holder Pod replacement",
            )
            self.kube(
                "exec",
                pod_name,
                "-c",
                "mover",
                "--",
                "/usr/local/bin/kopiur-mover",
                "verify-source-mount",
                mount["mountPath"],
                "--write-probe",
            )
        self.phase("snapshot", name)
        self.check(
            True, f"{name}: snapshot succeeded with writable cache and no fsGroup"
        )
        after = json.loads(self.exec_python("holder", INVENTORY))
        self.check(
            after == self.before,
            f"{name}: source bytes, UID/GID, modes, ACLs, xattrs and mtimes unchanged",
        )
        whole_after = json.loads(self.exec_python("holder", WHOLE_SOURCE_INVENTORY))
        self.report.setdefault("wholeSourceAfter", {})[name] = whole_after
        self.check(
            whole_after == self.source_before,
            f"{name}: complete source including PVC root, lost+found and seed marker unchanged",
        )

    def restore(self):
        self.create(
            "Restore",
            "scratch-restore",
            {
                "source": {"snapshotRef": {"name": "initialized-cache"}},
                "target": {
                    "pvc": {
                        "name": "scratch",
                        "capacity": "10Gi",
                        "storageClassName": self.args.storage_class,
                        "accessModes": ["ReadWriteOnce"],
                    }
                },
                "mover": {
                    "privilegedMode": True,
                    "securityContext": {
                        "runAsUser": 0,
                        "runAsGroup": 0,
                        "runAsNonRoot": False,
                        "capabilities": {"add": ["CHOWN", "FOWNER", "DAC_OVERRIDE"]},
                    },
                },
            },
        )
        self.phase("restore", "scratch-restore")
        self.fixture_pod(
            "scratch-check", claim="scratch", script="import time; time.sleep(3600)"
        )
        restored = json.loads(self.exec_python("scratch-check", INVENTORY))
        self.report["restored"] = restored
        self.check(
            restored == self.before,
            "scratch restore preserves fixture bytes and metadata",
        )

    def rwop_negative(self):
        self.pvc("rwop", "ReadWriteOncePod")
        self.create(
            "SnapshotPolicy",
            "rwop-refused",
            {
                "repository": {"kind": "Repository", "name": "disposable"},
                "copyMethod": "Direct",
                "sources": [
                    {
                        "pvc": {"name": "rwop"},
                        "readOnly": True,
                        "pvcPublicationReadOnly": False,
                        "acknowledgeReadWritePublication": True,
                    }
                ],
                "defaultDeletionPolicy": "Retain",
            },
        )
        self.create(
            "Snapshot",
            "rwop-refused",
            {"policyRef": {"name": "rwop-refused"}, "deletionPolicy": "Retain"},
        )
        obj = self.phase("snapshot", "rwop-refused", "Failed")
        self.report["rwopStatus"] = obj.get("status")
        self.check(
            self.get("job", "rwop-refused") is None,
            "RWOP rejected before any mover Job exists",
        )

    def cleanup(self):
        if self.uid is None:
            return
        namespace = self.get("namespace", self.ns, namespaced=False)
        if namespace is None:
            return
        if namespace["metadata"]["uid"] != self.uid:
            raise RuntimeError("namespace UID changed; refusing cleanup")
        self.pvs.update(
            p["spec"]["volumeName"]
            for p in (self.get("pvc") or {}).get("items", [])
            if p.get("spec", {}).get("volumeName")
        )
        self.report["disposablePVs"] = sorted(self.pvs)
        # Keep MinIO alive until Kopiur finalizers finish. Retain snapshots avoid
        # unnecessary object-store deletes; destroying MinIO then drops this
        # independent disposable repository and all its temporary credentials.
        self.kube("delete", "restore,snapshot,snapshotpolicy", "--all", "--wait=false")
        self.wait(
            "Kopiur cleanup did not finish",
            lambda: all(
                not (self.get(kind) or {}).get("items")
                for kind in ("restores", "snapshots", "snapshotpolicies")
            ),
        )
        self.kube("delete", "namespace", self.ns, "--wait=false", namespaced=False)
        self.wait(
            "disposable namespace cleanup did not finish",
            lambda: self.get("namespace", self.ns, namespaced=False) is None,
        )
        self.wait(
            "disposable HCloud PV cleanup did not finish",
            lambda: all(
                self.get("pv", name, namespaced=False) is None for name in self.pvs
            ),
        )
        self.check(
            True,
            "temporary namespace, Jobs, Pods, PVCs, Snapshots and credentials deleted",
        )

    def save(self):
        destination = Path(self.args.report_dir) / f"{self.ns}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(self.report, indent=2, sort_keys=True) + "\n")
        print(f"Credential-free evidence: {destination}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--storage-class", default="hcloud-volumes")
    parser.add_argument("--report-dir", default="target/hcloud-validation")
    parser.add_argument(
        "--acknowledge-disposable-cluster-writes",
        action="store_true",
        required=True,
        help="explicitly authorize isolated throwaway namespace/PVC writes",
    )
    args = parser.parse_args()
    drill = Drill(args)
    failure = None
    try:
        drill.provision()
        drill.backup("ordinary-cache", replace_holder=True)
        drill.backup("initialized-cache", initializer=True)
        drill.restore()
        drill.rwop_negative()
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 -- cleanup must run for every failure
        failure = f"{type(error).__name__}: {error}"
        drill.report["failure"] = failure
        print(f"FAIL {failure}", file=sys.stderr, flush=True)
    finally:
        try:
            drill.cleanup()
        except Exception as error:  # noqa: BLE001 -- report cleanup failure without secret-bearing tracebacks
            drill.report["cleanupFailure"] = str(error)
            failure = failure or str(error)
            print(
                f"CLEANUP FAILED for {drill.ns}; inspect this namespace only: {error}",
                file=sys.stderr,
            )
        drill.save()
    return 1 if failure else 0


if __name__ == "__main__":
    sys.exit(main())
