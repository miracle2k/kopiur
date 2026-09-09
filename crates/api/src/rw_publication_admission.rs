//! Admission protection for live-PVC RW-publication movers, after ALL mutating
//! admission has run and before kubelet can see fsGroup or mount the volume.
//!
//! Rendering and a process mountinfo preflight cannot stop kubelet from changing
//! source ownership if a Pod injector adds fsGroup. This fail-closed Kubernetes
//! ValidatingAdmissionPolicy supplies that earlier boundary. The controller checks
//! the installed policy and binding against these same specs before creating a
//! compatibility Job; codegen emits the raw and Helm install artifacts from here.
//!
//! Kubernetes v1 policy reference:
//! <https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/>

use k8s_openapi::api::admissionregistration::v1::{
    ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding,
};
use serde_json::{Value, json};

/// Fixed cluster-scoped name of both mandatory admission objects.
pub const POLICY_NAME: &str = "kopiur-rw-publication";
/// Independent marker used by the renderer and admission matching.
pub const RW_PUBLICATION_LABEL: &str = "kopiur.home-operations.com/rw-publication";
/// Runtime preflight flag, also used to select admission even if an injector drops
/// the label. Updates inspect oldObject too, so deleting both markers cannot opt a
/// protected Job/Pod out of validation.
pub const REQUIRED_READ_ONLY_SOURCE_ARG: &str = "--require-read-only-source";

fn marked_object(object: &str) -> String {
    // matchConditions cannot reference composition variables. dyn() keeps one
    // policy valid for both Job and Pod schemas; each branch reads its own shape.
    let pod = format!(
        "(request.resource.resource == 'jobs' ? dyn({object}).spec.template : dyn({object}))"
    );
    // The work-spec and physical split are independent selection signals. A
    // webhook stripping our Pod label and CLI args must not accidentally exempt
    // the unsafe publication from admission. Gate the physical shape on managed-by
    // because ordinary third-party Pods also sometimes use RW publication + RO mounts.
    let managed = format!(
        "((has({object}.metadata.labels) && 'app.kubernetes.io/managed-by' in {object}.metadata.labels && \
         {object}.metadata.labels['app.kubernetes.io/managed-by'] == 'kopiur') || \
         (has({pod}.metadata.labels) && 'app.kubernetes.io/managed-by' in {pod}.metadata.labels && \
         {pod}.metadata.labels['app.kubernetes.io/managed-by'] == 'kopiur'))"
    );
    format!(
        "({object} != null && ((has({object}.metadata.labels) && \
         '{RW_PUBLICATION_LABEL}' in {object}.metadata.labels && \
         {object}.metadata.labels['{RW_PUBLICATION_LABEL}'] == 'true') || \
         (has({pod}.metadata.labels) && '{RW_PUBLICATION_LABEL}' in {pod}.metadata.labels && \
         {pod}.metadata.labels['{RW_PUBLICATION_LABEL}'] == 'true') || \
         {pod}.spec.containers.exists(c, has(c.args) && \
         '{REQUIRED_READ_ONLY_SOURCE_ARG}' in c.args) || \
         {pod}.spec.containers.exists(c, has(c.env) && c.env.exists(e, \
         e.name == 'KOPIUR_WORK_SPEC' && has(e.value) && e.value.contains('\"requireReadOnlySource\":true'))) || \
         ({managed} && has({pod}.spec.volumes) && {pod}.spec.volumes.exists(v, \
         has(v.persistentVolumeClaim) && (!has(v.persistentVolumeClaim.readOnly) || !v.persistentVolumeClaim.readOnly) && \
         {pod}.spec.containers.exists(c, has(c.volumeMounts) && c.volumeMounts.exists(m, \
         m.name == v.name && has(m.readOnly) && m.readOnly))))))"
    )
}

fn variable(name: &str, expression: &str) -> Value {
    json!({"name": name, "expression": expression})
}

fn validation(expression: &str, message: &str) -> Value {
    json!({"expression": expression, "message": message, "reason": "Forbidden"})
}

/// The mandatory fail-closed policy. Only explicitly marked compatibility Jobs
/// and Pods are affected, including attempts to add ephemeral debug containers.
/// Empty selectors and Equivalent match policy are explicit because the API
/// server defaults them; this keeps installed-spec comparison exact.
pub fn policy() -> ValidatingAdmissionPolicy {
    serde_json::from_value(json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY_NAME},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "matchPolicy": "Equivalent", "namespaceSelector": {}, "objectSelector": {},
                "resourceRules": [
                    {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                     "resources": ["pods", "pods/ephemeralcontainers"], "scope": "Namespaced"},
                    {"apiGroups": ["batch"], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                     "resources": ["jobs"], "scope": "Namespaced"}
                ]
            },
            "matchConditions": [{
                "name": "rw-publication-current-or-previous",
                "expression": format!("{} || {}", marked_object("object"), marked_object("oldObject"))
            }],
            "variables": [
                variable("pod", "request.resource.resource == 'jobs' ? dyn(object).spec.template : dyn(object)"),
                variable("ps", "variables.pod.spec"),
                variable("mover", "variables.ps.containers[0]"),
                variable("sc", "variables.mover.securityContext"),
                variable("privilegedNamespace", &format!("namespaceObject != null && has(namespaceObject.metadata.annotations) && '{0}' in namespaceObject.metadata.annotations && namespaceObject.metadata.annotations['{0}'] == 'true'", crate::consts::PRIVILEGED_MOVERS_ANNOTATION)),
                variable("nonRoot", "has(variables.sc.runAsNonRoot) ? variables.sc.runAsNonRoot : (has(variables.ps.securityContext) && has(variables.ps.securityContext.runAsNonRoot) && variables.ps.securityContext.runAsNonRoot)"),
                variable("sourceVolumes", "variables.ps.volumes.filter(v, v.name == 'source')"),
                variable("sourceMounts", "variables.mover.volumeMounts.filter(m, m.name == 'source')"),
                variable("cacheVolumes", "variables.ps.volumes.filter(v, v.name == 'kopia-cache')"),
                variable("uid", "has(variables.sc.runAsUser) ? variables.sc.runAsUser : (has(variables.ps.securityContext) && has(variables.ps.securityContext.runAsUser) ? variables.ps.securityContext.runAsUser : 65532)"),
                variable("gid", "has(variables.sc.runAsGroup) ? variables.sc.runAsGroup : (has(variables.ps.securityContext) && has(variables.ps.securityContext.runAsGroup) ? variables.ps.securityContext.runAsGroup : 65532)")
            ],
            "validations": validations()
        }
    })).expect("the checked-in RW-publication policy has a valid Kubernetes v1 shape")
}

fn validations() -> Vec<Value> {
    vec![
        validation(
            &format!(
                "has(variables.pod.metadata.labels) && '{RW_PUBLICATION_LABEL}' in variables.pod.metadata.labels && variables.pod.metadata.labels['{RW_PUBLICATION_LABEL}'] == 'true'"
            ),
            "RW-publication protection requires its Pod label; the marker cannot be removed by injection or update",
        ),
        validation(
            "size(variables.ps.containers) == 1 && variables.mover.name == 'mover' && (!has(variables.ps.ephemeralContainers) || size(variables.ps.ephemeralContainers) == 0)",
            "RW-publication movers require exactly one main mover and forbid sidecar or ephemeral container injection",
        ),
        validation(
            "!has(variables.ps.securityContext) || (!has(variables.ps.securityContext.fsGroup) && !has(variables.ps.securityContext.fsGroupChangePolicy))",
            "RW-publication Pod fsGroup and fsGroupChangePolicy are forbidden: kubelet must never rewrite the live source",
        ),
        validation(
            "!has(variables.sc.seLinuxOptions) && (!has(variables.ps.securityContext) || (!has(variables.ps.securityContext.seLinuxOptions) && !has(variables.ps.securityContext.seLinuxChangePolicy))) && (!has(variables.ps.initContainers) || variables.ps.initContainers.all(i, !has(i.securityContext) || !has(i.securityContext.seLinuxOptions)))",
            "RW-publication SELinux options and change policies are forbidden: kubelet must never relabel live source metadata before the mover starts",
        ),
        validation(
            "(!has(variables.ps.hostNetwork) || !variables.ps.hostNetwork) && (!has(variables.ps.hostPID) || !variables.ps.hostPID) && (!has(variables.ps.hostIPC) || !variables.ps.hostIPC) && (!has(variables.ps.shareProcessNamespace) || !variables.ps.shareProcessNamespace) && has(variables.ps.automountServiceAccountToken) && !variables.ps.automountServiceAccountToken",
            "RW-publication movers forbid host namespaces and automatic service-account mounts; API credentials belong only in the main mover",
        ),
        validation(
            "has(variables.sc.allowPrivilegeEscalation) && !variables.sc.allowPrivilegeEscalation && (!has(variables.sc.privileged) || !variables.sc.privileged) && has(variables.sc.capabilities) && has(variables.sc.capabilities.drop) && 'ALL' in variables.sc.capabilities.drop && (!has(variables.sc.capabilities.add) || size(variables.sc.capabilities.add) == 0) && has(variables.sc.seccompProfile) && variables.sc.seccompProfile.type == 'RuntimeDefault' && (!has(variables.sc.procMount) || variables.sc.procMount == 'Default')",
            "RW-publication main mover must retain no escalation, privileged false, drop ALL, no added capabilities, and RuntimeDefault seccomp",
        ),
        validation(
            // Root reads still traverse the same read-only mount and mountinfo
            // preflight. Namespace opt-in authorizes identity only, never an
            // exception to any source or container-hardening rule above/below.
            // Inspect both layers just like requires_privilege_resolved, so a
            // conflicting Pod root setting cannot bypass the established gate.
            "variables.privilegedNamespace || (variables.nonRoot && variables.uid > 0 && (!has(variables.ps.securityContext) || ((!has(variables.ps.securityContext.runAsUser) || variables.ps.securityContext.runAsUser != 0) && (!has(variables.ps.securityContext.runAsNonRoot) || variables.ps.securityContext.runAsNonRoot))))",
            "Root or disabled non-root protection on the main mover requires the namespace's explicit kopiur.home-operations.com/privileged-movers=true annotation",
        ),
        validation(
            // Kubernetes' Go PVCVolumeSource.readOnly is a non-pointer bool
            // with omitempty. An explicitly rendered false disappears before
            // CEL evaluates admission; absence therefore means publication RW.
            // The container mount's true remains mandatory in the next rule.
            "size(variables.sourceVolumes) == 1 && has(variables.sourceVolumes[0].persistentVolumeClaim) && (!has(variables.sourceVolumes[0].persistentVolumeClaim.readOnly) || !variables.sourceVolumes[0].persistentVolumeClaim.readOnly) && variables.ps.volumes.filter(v, has(v.persistentVolumeClaim)).size() == 1",
            "RW-publication requires exactly one writable PVC publication named source; additional PVC aliases are forbidden",
        ),
        validation(
            "size(variables.sourceMounts) == 1 && has(variables.sourceMounts[0].readOnly) && variables.sourceMounts[0].readOnly && !has(variables.sourceMounts[0].subPath) && !has(variables.sourceMounts[0].subPathExpr) && variables.mover.volumeMounts.all(m, !has(m.mountPropagation) || m.mountPropagation == 'None') && (!has(variables.mover.volumeDevices) || size(variables.mover.volumeDevices) == 0)",
            "RW-publication source must remain a read-only filesystem mount without subpaths, propagation, or raw volume devices",
        ),
        validation(
            &format!(
                "(!has(variables.mover.command) || size(variables.mover.command) == 0) && has(variables.mover.args) && size(variables.mover.args) == 2 && variables.mover.args[0] == '{REQUIRED_READ_ONLY_SOURCE_ARG}' && variables.mover.args[1] == variables.sourceMounts[0].mountPath && !has(variables.mover.lifecycle)"
            ),
            "RW-publication mover must run its normal entrypoint with the independent source mount preflight; startup overrides are forbidden",
        ),
        validation(
            "variables.sourceMounts[0].mountPath.startsWith('/') && variables.sourceMounts[0].mountPath != '/' && !variables.sourceMounts[0].mountPath.endsWith('/') && !variables.sourceMounts[0].mountPath.contains('//') && !variables.sourceMounts[0].mountPath.matches('(^|/)[.][.]?(/|$)') && ['/proc', '/sys', '/dev', '/etc', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/run', '/var/run', '/var/cache/kopia'].all(p, variables.sourceMounts[0].mountPath != p && !variables.sourceMounts[0].mountPath.startsWith(p + '/') && !p.startsWith(variables.sourceMounts[0].mountPath + '/'))",
            "RW-publication source mount path must be canonical and disjoint from procfs, system paths, executable paths, credentials, and cache",
        ),
        validation(
            "size(variables.cacheVolumes) == 1 && has(variables.cacheVolumes[0].emptyDir) && (!has(variables.cacheVolumes[0].emptyDir.medium) || variables.cacheVolumes[0].emptyDir.medium == '') && !has(variables.cacheVolumes[0].emptyDir.sizeLimit) && variables.mover.volumeMounts.filter(m, m.name == 'kopia-cache').size() == 1 && variables.mover.volumeMounts.exists(m, m.name == 'kopia-cache' && m.mountPath == '/var/cache/kopia' && (!has(m.readOnly) || !m.readOnly) && !has(m.subPath) && !has(m.subPathExpr))",
            "RW-publication initially supports only an ordinary emptyDir cache mounted writable at /var/cache/kopia",
        ),
        validation(
            "variables.ps.volumes.all(v, (v.name == 'source' && has(v.persistentVolumeClaim)) || (v.name == 'kopia-cache' && has(v.emptyDir)) || has(v.projected))",
            "RW-publication Pods permit only the source PVC, emptyDir cache, and projected credential volumes; host paths, repository volumes, and alternate source paths are forbidden",
        ),
        // A projected volume is intrinsically read-only, but could still hide
        // /proc/self/mountinfo with a forged file or replace an executable. Limit
        // injected projections to credential paths; source/cache already have one
        // fixed mount each. Runtime mountinfo must always come from real procfs.
        validation(
            "variables.mover.volumeMounts.all(m, m.name == 'source' || m.name == 'kopia-cache' || (variables.ps.volumes.exists(v, v.name == m.name && has(v.projected)) && has(m.readOnly) && m.readOnly && m.mountPath.startsWith('/var/run/secrets/') && !m.mountPath.endsWith('/') && !m.mountPath.contains('//') && !m.mountPath.matches('(^|/)[.][.]?(/|$)') && !has(m.subPath) && !has(m.subPathExpr)))",
            "Additional RW-publication mover mounts must be read-only projected credentials below /var/run/secrets, without subpaths; procfs, source, cache, and executable overlays are forbidden",
        ),
        validation(
            "!has(variables.ps.initContainers) || size(variables.ps.initContainers) == 0 || (size(variables.ps.initContainers) == 1 && variables.ps.initContainers.all(i, i.name == 'cache-init' && i.image == variables.mover.image && (!has(i.command) || size(i.command) == 0) && has(i.args) && i.args == ['cache-init', '--uid', string(variables.uid), '--gid', string(variables.gid)] && !has(i.restartPolicy) && !has(i.lifecycle) && !has(i.livenessProbe) && !has(i.readinessProbe) && !has(i.startupProbe)))",
            "Only the Kopiur cache-init entrypoint may initialize cache ownership, using the main mover image and effective UID/GID; sidecar initializers are forbidden",
        ),
        validation(
            "!has(variables.ps.initContainers) || variables.ps.initContainers.all(i, has(i.volumeMounts) && size(i.volumeMounts) == 1 && i.volumeMounts[0].name == 'kopia-cache' && i.volumeMounts[0].mountPath == '/var/cache/kopia' && (!has(i.volumeMounts[0].readOnly) || !i.volumeMounts[0].readOnly) && !has(i.volumeMounts[0].subPath) && !has(i.volumeMounts[0].subPathExpr) && (!has(i.volumeMounts[0].mountPropagation) || i.volumeMounts[0].mountPropagation == 'None') && (!has(i.volumeDevices) || size(i.volumeDevices) == 0) && (!has(i.env) || size(i.env) == 0) && (!has(i.envFrom) || size(i.envFrom) == 0))",
            "Cache-init must mount only the cache, with no source, credentials, config, env, volume devices, or mount propagation",
        ),
        validation(
            "!has(variables.ps.initContainers) || variables.ps.initContainers.all(i, has(i.securityContext) && i.securityContext.runAsUser == 0 && i.securityContext.runAsGroup == 0 && !i.securityContext.runAsNonRoot && !i.securityContext.allowPrivilegeEscalation && (!has(i.securityContext.privileged) || !i.securityContext.privileged) && i.securityContext.readOnlyRootFilesystem && i.securityContext.capabilities.drop == ['ALL'] && i.securityContext.capabilities.add == ['CHOWN'] && i.securityContext.seccompProfile.type == 'RuntimeDefault' && (!has(i.securityContext.procMount) || i.securityContext.procMount == 'Default'))",
            "Cache-init requires root with only CHOWN, drop ALL, no escalation, a read-only root filesystem, and RuntimeDefault seccomp",
        ),
        validation(
            "!has(variables.ps.initContainers) || size(variables.ps.initContainers) == 0 || variables.privilegedNamespace",
            "Root cache initialization requires the namespace's explicit kopiur.home-operations.com/privileged-movers=true annotation",
        ),
    ]
}

/// A cluster-wide Deny binding. The policy itself selects only compatibility
/// movers; no namespace selector may silently exempt a workload namespace.
pub fn binding() -> ValidatingAdmissionPolicyBinding {
    serde_json::from_value(json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": POLICY_NAME},
        "spec": {"policyName": POLICY_NAME, "validationActions": ["Deny"]}
    }))
    .expect("the RW-publication binding has a valid Kubernetes v1 shape")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cel::{Context, Program, Value as CelValue};
    use std::collections::HashMap;

    fn pod() -> Value {
        json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "compatibility", "namespace": "test", "labels": {RW_PUBLICATION_LABEL: "true"}},
            "spec": {
                "automountServiceAccountToken": false,
                "securityContext": {},
                "containers": [{
                    "name": "mover", "image": "kopiur-mover:test",
                    "args": [REQUIRED_READ_ONLY_SOURCE_ARG, "/pvc/app-data"],
                    "securityContext": crate::common::hardened_security_context(),
                    "volumeMounts": [
                        {"name": "source", "mountPath": "/pvc/app-data", "readOnly": true},
                        {"name": "kopia-cache", "mountPath": "/var/cache/kopia"}
                    ]
                }],
                "volumes": [
                    {"name": "source", "persistentVolumeClaim": {"claimName": "app-data", "readOnly": false}},
                    {"name": "kopia-cache", "emptyDir": {}}
                ]
            }
        })
    }

    fn init() -> Value {
        json!({
            "name": "cache-init", "image": "kopiur-mover:test",
            "args": ["cache-init", "--uid", "65532", "--gid", "65532"],
            "volumeMounts": [{"name": "kopia-cache", "mountPath": "/var/cache/kopia"}],
            "securityContext": {
                "runAsUser": 0, "runAsGroup": 0, "runAsNonRoot": false,
                "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
                "capabilities": {"drop": ["ALL"], "add": ["CHOWN"]},
                "seccompProfile": {"type": "RuntimeDefault"}
            }
        })
    }

    /// Evaluate the SAME emitted CEL strings, including match conditions and
    /// composition variables. This tests mutation rejection hermetically; the
    /// disposable Kubernetes suite additionally type-checks them server-side.
    fn denials(object: Value, old: Value, namespace_gate: bool) -> Vec<String> {
        denials_in_namespace(
            object,
            old,
            json!({"metadata": {"annotations": {
                crate::consts::PRIVILEGED_MOVERS_ANNOTATION: namespace_gate.to_string()
            }}}),
        )
    }

    fn denials_in_namespace(object: Value, old: Value, namespace: Value) -> Vec<String> {
        let resource = if object["kind"] == "Job" {
            "jobs"
        } else {
            "pods"
        };
        let mut ctx = Context::default();
        ctx.add_variable("object", object).unwrap();
        ctx.add_variable("oldObject", old).unwrap();
        ctx.add_variable("request", json!({"resource": {"resource": resource}}))
            .unwrap();
        ctx.add_variable("namespaceObject", namespace).unwrap();
        let spec = policy().spec.unwrap();
        for condition in spec.match_conditions.unwrap() {
            match Program::compile(&condition.expression)
                .unwrap()
                .execute(&ctx)
            {
                Ok(CelValue::Bool(true)) => {}
                Ok(CelValue::Bool(false)) => return Vec::new(),
                other => return vec![format!("match condition failed closed: {other:?}")],
            }
        }
        let mut variables: HashMap<String, CelValue> = HashMap::new();
        for variable in spec.variables.unwrap() {
            ctx.add_variable_from_value("variables", variables.clone());
            match Program::compile(&variable.expression)
                .unwrap()
                .execute(&ctx)
            {
                Ok(value) => {
                    variables.insert(variable.name, value);
                }
                Err(error) => {
                    return vec![format!(
                        "variable {} failed closed: {error:?}",
                        variable.name
                    )];
                }
            }
        }
        ctx.add_variable_from_value("variables", variables);
        spec.validations
            .unwrap()
            .into_iter()
            .filter_map(|validation| {
                let result = Program::compile(&validation.expression)
                    .unwrap()
                    .execute(&ctx);
                (result != Ok(CelValue::Bool(true)))
                    .then(|| format!("{}: {result:?}", validation.message.unwrap()))
            })
            .collect()
    }

    fn assert_rejected(object: Value, message: &str) {
        let denials = denials(object, Value::Null, true);
        assert!(
            denials.iter().any(|d| d.contains(message)),
            "expected {message:?}, got {denials:?}"
        );
    }

    #[test]
    fn valid_compatibility_pods_and_jobs_pass_with_or_without_gated_init() {
        for initializer in [false, true] {
            let mut pod = pod();
            if initializer {
                pod["spec"]["initContainers"] = json!([init()]);
            }
            let job = json!({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"labels": {RW_PUBLICATION_LABEL: "true"}}, "spec": {"template": {"metadata": pod["metadata"], "spec": pod["spec"]}}});
            for object in [pod, job] {
                assert_eq!(denials(object, Value::Null, true), Vec::<String>::new());
            }
        }
    }

    #[test]
    fn root_main_identity_is_namespace_gated_with_or_without_cache_init() {
        assert!(
            denials(pod(), Value::Null, false).is_empty(),
            "default stays non-root"
        );
        for initializer in [false, true] {
            let mut pod = pod();
            let sc = &mut pod["spec"]["containers"][0]["securityContext"];
            sc["runAsUser"] = json!(0);
            sc["runAsGroup"] = json!(0);
            sc["runAsNonRoot"] = json!(false);
            if initializer {
                let mut init = init();
                init["args"] = json!(["cache-init", "--uid", "0", "--gid", "0"]);
                pod["spec"]["initContainers"] = json!([init]);
            }
            let job = json!({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"labels": {RW_PUBLICATION_LABEL: "true"}}, "spec": {"template": {"metadata": pod["metadata"], "spec": pod["spec"]}}});
            for object in [pod, job] {
                assert!(denials(object.clone(), Value::Null, true).is_empty());
                assert!(
                    denials(object.clone(), Value::Null, false)
                        .iter()
                        .any(|d| d.contains("main mover requires the namespace's explicit"))
                );
                for namespace in [
                    Value::Null,
                    json!({"metadata": {}}),
                    json!({"metadata": {"annotations": {}}}),
                ] {
                    assert!(
                        denials_in_namespace(object.clone(), Value::Null, namespace)
                            .iter()
                            .any(|d| d.contains("main mover requires the namespace's explicit"))
                    );
                }
            }
        }
    }

    #[test]
    fn inherited_root_and_removed_non_root_protection_cannot_bypass_namespace_gate() {
        for psc in [json!({"runAsUser": 0}), json!({"runAsNonRoot": false})] {
            let mut changed = pod();
            changed["spec"]["securityContext"] = psc;
            // Match the generic controller gate even if a container context
            // would override the Pod's request for root identity.
            changed["spec"]["containers"][0]["securityContext"]["runAsUser"] = json!(1000);
            assert!(!denials(changed.clone(), Value::Null, false).is_empty());
            assert!(denials(changed, Value::Null, true).is_empty());
        }
        for non_root in [None, Some(false)] {
            let mut changed = pod();
            let sc = changed["spec"]["containers"][0]["securityContext"]
                .as_object_mut()
                .unwrap();
            sc.remove("runAsNonRoot");
            if let Some(value) = non_root {
                sc.insert("runAsNonRoot".into(), json!(value));
            }
            assert!(!denials(changed.clone(), Value::Null, false).is_empty());
            assert!(denials(changed, Value::Null, true).is_empty());
        }
    }

    #[test]
    fn gated_root_identity_never_waives_source_or_container_safety() {
        let mut root = pod();
        root["spec"]["containers"][0]["securityContext"]["runAsUser"] = json!(0);
        root["spec"]["containers"][0]["securityContext"]["runAsNonRoot"] = json!(false);
        for (field, value, message) in [
            ("privileged", json!(true), "privileged false"),
            ("allowPrivilegeEscalation", json!(true), "no escalation"),
            (
                "capabilities",
                json!({"drop": ["ALL"], "add": ["CHOWN"]}),
                "no added capabilities",
            ),
            ("capabilities", json!({"drop": []}), "drop ALL"),
            (
                "seccompProfile",
                json!({"type": "Unconfined"}),
                "RuntimeDefault",
            ),
            ("procMount", json!("Unmasked"), "no escalation"),
            (
                "seLinuxOptions",
                json!({"level": "s0:c100,c200"}),
                "must never relabel",
            ),
        ] {
            let mut changed = root.clone();
            changed["spec"]["containers"][0]["securityContext"][field] = value;
            assert_rejected(changed, message);
        }
        for (field, value, message) in [
            ("fsGroup", json!(0), "must never rewrite"),
            (
                "fsGroupChangePolicy",
                json!("OnRootMismatch"),
                "must never rewrite",
            ),
            (
                "seLinuxChangePolicy",
                json!("Recursive"),
                "must never relabel",
            ),
        ] {
            let mut changed = root.clone();
            changed["spec"]["securityContext"][field] = value;
            assert_rejected(changed, message);
        }
        root["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = json!(false);
        assert_rejected(root, "read-only filesystem mount");
    }

    #[test]
    fn kubernetes_omits_false_pvc_publication_without_changing_writable_semantics() {
        for initializer in [false, true] {
            let mut pod = pod();
            // API-server Go serialization uses omitempty for this non-pointer
            // bool, even when the controller submitted an explicit false.
            pod["spec"]["volumes"][0]["persistentVolumeClaim"]
                .as_object_mut()
                .unwrap()
                .remove("readOnly");
            if initializer {
                pod["spec"]["initContainers"] = json!([init()]);
            }
            let job = json!({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"labels": {RW_PUBLICATION_LABEL: "true"}}, "spec": {"template": {"metadata": pod["metadata"], "spec": pod["spec"]}}});
            for object in [pod, job] {
                assert_eq!(denials(object, Value::Null, true), Vec::<String>::new());
            }
        }
        let mut unsafe_mount = pod();
        unsafe_mount["spec"]["volumes"][0]["persistentVolumeClaim"]
            .as_object_mut()
            .unwrap()
            .remove("readOnly");
        unsafe_mount["spec"]["containers"][0]["volumeMounts"][0]
            .as_object_mut()
            .unwrap()
            .remove("readOnly");
        assert_rejected(unsafe_mount, "read-only filesystem mount");
    }

    #[test]
    fn physical_split_selection_handles_omitted_false_publication_after_injection() {
        let mut pod = pod();
        pod["metadata"]["labels"] = json!({"app.kubernetes.io/managed-by": "kopiur"});
        pod["spec"]["containers"][0]
            .as_object_mut()
            .unwrap()
            .remove("args");
        pod["spec"]["volumes"][0]["persistentVolumeClaim"]
            .as_object_mut()
            .unwrap()
            .remove("readOnly");
        assert_rejected(pod, "Pod label");
    }

    #[test]
    fn ordinary_movers_are_outside_the_admission_policy() {
        for publication in [true, false] {
            let mut pod = pod();
            pod["metadata"]["labels"] = json!({});
            pod["spec"]["containers"][0]
                .as_object_mut()
                .unwrap()
                .remove("args");
            pod["spec"]["securityContext"] =
                json!({"fsGroup": 65532, "fsGroupChangePolicy": "OnRootMismatch"});
            pod["spec"]["volumes"][0]["persistentVolumeClaim"]["readOnly"] = json!(publication);
            pod["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = json!(publication);
            assert!(denials(pod, Value::Null, false).is_empty());
        }
    }

    #[test]
    fn removal_of_markers_and_injected_source_write_access_fail_closed() {
        let original = pod();
        let mut changed = original.clone();
        changed["metadata"]["labels"] = json!({});
        assert_rejected(changed.clone(), "Pod label"); // Independent CLI marker selects it.
        changed["spec"]["containers"][0]
            .as_object_mut()
            .unwrap()
            .remove("args");
        assert!(!denials(changed, original, true).is_empty()); // oldObject retains selection.
        let mut changed = pod();
        changed["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = json!(false);
        assert_rejected(changed, "read-only filesystem mount");
        let mut changed = pod();
        changed["spec"]["containers"][0]["args"] = json!([]);
        assert_rejected(changed, "independent source mount preflight");
        let mut changed = pod();
        changed["spec"]["volumes"].as_array_mut().unwrap().push(json!({"name": "source-alias", "persistentVolumeClaim": {"claimName": "app-data", "readOnly": false}}));
        assert_rejected(changed, "additional PVC aliases");
        let mut changed = pod();
        changed["spec"]["containers"][0]["volumeMounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "source", "mountPath": "/writable-alias", "readOnly": false}));
        assert_rejected(changed, "read-only filesystem mount");
    }

    #[test]
    fn work_spec_and_managed_split_still_select_pods_when_label_and_cli_are_removed() {
        let mut stripped = pod();
        stripped["metadata"]["labels"] = json!({});
        stripped["spec"]["containers"][0]
            .as_object_mut()
            .unwrap()
            .remove("args");
        let mut work_spec_marker = stripped.clone();
        // Even if the source mount was also altered, the independent serialized
        // guard remains an admission selector before kubelet sees this Pod.
        work_spec_marker["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = json!(false);
        work_spec_marker["spec"]["containers"][0]["env"] = json!([{
            "name": "KOPIUR_WORK_SPEC", "value": "{\"operation\":{\"snapshot\":{\"requireReadOnlySource\":true}}}"
        }]);
        assert_rejected(work_spec_marker, "Pod label");

        stripped["metadata"]["labels"] = json!({"app.kubernetes.io/managed-by": "kopiur"});
        // Do not key physical-shape selection on the volume's original name.
        stripped["spec"]["containers"][0]["volumeMounts"][0]["name"] = json!("renamed-source");
        stripped["spec"]["volumes"][0]["name"] = json!("renamed-source");
        assert_rejected(stripped, "Pod label");
    }

    #[test]
    fn unmarked_third_party_split_mounts_do_not_opt_into_kopiur_validation() {
        let mut pod = pod();
        pod["metadata"]["labels"] = json!({"app.kubernetes.io/managed-by": "other"});
        pod["spec"]["containers"][0]
            .as_object_mut()
            .unwrap()
            .remove("args");
        assert!(denials(pod, Value::Null, false).is_empty());
    }

    #[test]
    fn projected_volumes_cannot_spoof_mountinfo_or_overlay_source_cache_and_binaries() {
        let mut baseline = pod();
        baseline["spec"]["volumes"].as_array_mut().unwrap().push(json!({
            "name": "projection", "projected": {"sources": [{"configMap": {"name": "synthetic-fixture"}}]}
        }));
        for path in [
            "/proc/self",
            "/proc/self/mountinfo",
            "/pvc/app-data/nested",
            "/var/cache/kopia/overlay",
            "/usr/local/bin",
            "/var/run/secrets/../mountinfo",
            "/var/run/secrets//token",
        ] {
            let mut pod = baseline.clone();
            pod["spec"]["containers"][0]["volumeMounts"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "name": "projection", "mountPath": path, "readOnly": true
                }));
            assert_rejected(pod, "projected credentials below /var/run/secrets");
        }
        baseline["spec"]["containers"][0]["volumeMounts"].as_array_mut().unwrap().push(json!({
            "name": "projection", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": true
        }));
        assert!(denials(baseline.clone(), Value::Null, true).is_empty());
        baseline["spec"]["containers"][0]["volumeMounts"][2]["subPath"] = json!("token");
        assert_rejected(baseline, "without subpaths");
    }

    #[test]
    fn post_injection_fsgroup_sidecars_host_access_and_privilege_are_refused() {
        for field in ["fsGroup", "fsGroupChangePolicy"] {
            let mut pod = pod();
            pod["spec"]["securityContext"][field] = if field == "fsGroup" {
                json!(1000)
            } else {
                json!("OnRootMismatch")
            };
            assert_rejected(pod, "kubelet must never rewrite");
        }
        for field in [
            "hostNetwork",
            "hostPID",
            "hostIPC",
            "shareProcessNamespace",
            "automountServiceAccountToken",
        ] {
            let mut pod = pod();
            pod["spec"][field] = json!(true);
            assert_rejected(pod, "forbid host namespaces");
        }
        let mut changed = pod();
        changed["spec"]["containers"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "sidecar", "image": "injected:test"}));
        assert_rejected(changed, "forbid sidecar or ephemeral");
        let mut changed = pod();
        changed["spec"]["ephemeralContainers"] =
            json!([{"name": "debug", "image": "injected:test"}]);
        assert_rejected(changed, "forbid sidecar or ephemeral");
        let mut changed = pod();
        changed["spec"]["containers"][0]["securityContext"]["capabilities"]["add"] =
            json!(["SYS_ADMIN"]);
        assert_rejected(changed, "no added capabilities");
        let mut changed = pod();
        changed["spec"]["volumes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "host", "hostPath": {"path": "/"}}));
        assert_rejected(changed, "host paths");
    }

    #[test]
    fn source_path_cannot_hide_mountinfo_credentials_binaries_or_cache() {
        for path in [
            "/",
            "/proc",
            "/proc/self",
            "/etc",
            "/usr",
            "/var",
            "/var/run/token",
            "/var/cache/kopia",
            "/var/cache/kopia/source",
            "/data/../proc",
            "/data//source",
        ] {
            let mut pod = pod();
            pod["spec"]["containers"][0]["volumeMounts"][0]["mountPath"] = json!(path);
            pod["spec"]["containers"][0]["args"][1] = json!(path);
            assert_rejected(pod, "source mount path");
        }
    }

    #[test]
    fn injected_selinux_settings_cannot_relabel_source_metadata() {
        let mut changed = pod();
        changed["spec"]["securityContext"]["seLinuxChangePolicy"] = json!("Recursive");
        assert_rejected(changed, "must never relabel");
        let mut changed = pod();
        changed["spec"]["securityContext"]["seLinuxOptions"] = json!({"level": "s0:c100,c200"});
        assert_rejected(changed, "must never relabel");
        let mut changed = pod();
        changed["spec"]["containers"][0]["securityContext"]["seLinuxOptions"] =
            json!({"level": "s0:c100,c200"});
        assert_rejected(changed, "must never relabel");
    }

    #[test]
    fn init_is_namespace_gated_cache_only_and_uses_the_effective_identity() {
        let mut baseline = pod();
        baseline["spec"]["initContainers"] = json!([init()]);
        assert!(
            denials(baseline.clone(), Value::Null, false)
                .iter()
                .any(|d| d.contains("namespace's explicit"))
        );
        let mut changed = baseline.clone();
        changed["spec"]["initContainers"][0]["volumeMounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "source", "mountPath": "/source"}));
        assert_rejected(changed, "must mount only the cache");
        let mut changed = baseline.clone();
        // No real secret values, names, or reads are used by this test.
        changed["spec"]["initContainers"][0]["envFrom"] =
            json!([{"configMapRef": {"name": "unexpected-config"}}]);
        assert_rejected(changed, "no source, credentials, config");
        let mut changed = baseline.clone();
        changed["spec"]["initContainers"][0]["securityContext"]["capabilities"]["add"] =
            json!(["CHOWN", "FOWNER"]);
        assert_rejected(changed, "only CHOWN");
        let mut changed = baseline.clone();
        changed["spec"]["containers"][0]["securityContext"]["runAsUser"] = json!(1000);
        changed["spec"]["containers"][0]["securityContext"]["runAsGroup"] = json!(1001);
        assert_rejected(changed.clone(), "effective UID/GID");
        changed["spec"]["initContainers"][0]["args"] =
            json!(["cache-init", "--uid", "1000", "--gid", "1001"]);
        assert!(denials(changed, Value::Null, true).is_empty());
    }
}
