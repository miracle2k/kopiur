//! Direct PVC RW-publication is a deliberately narrow compatibility boundary.
//! These checks run at admission and again before reconciliation renders a Job.
//! CSI sees RW, but the mover sees RO; no permission to mutate the source follows
//! from the backend publication acknowledgement.

use crate::common::{CacheDefaults, MoverSpec, resolve_mover_for_rw_publication};
use crate::error::{ValidationError, ValidationResult};
use crate::snapshot_policy::{
    CopyMethod, SnapshotPolicySpec, policy_requests_rw_publication, source_read_only,
    source_requests_rw_publication,
};
use k8s_openapi::api::core::v1::{PodSecurityContext, SecurityContext};

fn invalid(field: impl Into<String>, reason: impl Into<String>) -> ValidationError {
    ValidationError::InvalidFieldValue {
        field: field.into(),
        reason: reason.into(),
    }
}

/// Reject cache initialization in unsupported mover roles and repository defaults.
/// Initially it is per-policy only, so opt-in cannot create root initializers on
/// bootstrap, restore, maintenance, or other movers as an inheritance side effect.
pub fn validate_cache_ownership_scope(
    cache: Option<&CacheDefaults>,
    field: &str,
) -> ValidationResult {
    if cache.is_some_and(|c| c.ownership.is_some()) {
        return Err(invalid(
            format!("{field}.ownership"),
            "cache ownership initialization is initially supported only on a Direct PVC \
             RW-publication compatibility SnapshotPolicy's mover.cache; repository-wide \
             defaults and other mover roles are unsupported",
        ));
    }
    Ok(())
}

/// Enforce the initial emptyDir-only support boundary on the FINAL effective cache.
/// Cache PVC ownership has a different lifecycle and is intentionally not inferred
/// from a request for a safe read-only source mount.
pub fn validate_rw_publication_cache(cache: Option<&CacheDefaults>) -> ValidationResult {
    if cache.is_some_and(|c| !c.is_ordinary_empty_dir()) {
        return Err(invalid(
            "spec.mover.cache",
            "Direct PVC RW-publication compatibility initially supports only an ordinary \
             emptyDir cache, optionally with ownership: InitContainer; capacity, \
             storageClassName, ephemeral PVC caches, and persistent caches are unsupported",
        ));
    }
    Ok(())
}

/// Reject forbidden effective settings without erasing any merged values. The
/// caller must invoke this after repository defaults and inherited workload/PVC
/// consumer contexts have been merged, before any Job is created. Root identity
/// is governed by the existing namespace privilege gate, independently of these
/// source-preservation rules: UID 0 never permits added capabilities, writable
/// source mounts, or kubelet ownership/relabeling changes.
pub fn validate_rw_publication_security_context(
    sc: &SecurityContext,
    psc: Option<&PodSecurityContext>,
) -> Vec<ValidationError> {
    let mut errs = Vec::new();
    if psc.is_some_and(|p| p.fs_group.is_some()) {
        errs.push(invalid(
            "spec.mover.podSecurityContext.fsGroup",
            "effective fsGroup is forbidden with RW PVC publication: kubelet could \
             recursively change ownership and modes on the LIVE source before the mover \
             starts; remove it from repository defaults, inherited workload context, and \
             policy settings; use runAsUser/runAsGroup/supplementalGroups for source access",
        ));
    }
    if psc.is_some_and(|p| p.fs_group_change_policy.is_some()) {
        errs.push(invalid(
            "spec.mover.podSecurityContext.fsGroupChangePolicy",
            "effective fsGroupChangePolicy is forbidden with RW PVC publication, even \
             without fsGroup; remove it from every security-context layer",
        ));
    }
    // SELinux labeling is another kubelet-side volume mutation that happens
    // before our mountinfo preflight can run. Preserving source metadata includes
    // its labels/xattrs, so this initial mode accepts process identity only.
    if sc.se_linux_options.is_some()
        || psc.is_some_and(|p| p.se_linux_options.is_some() || p.se_linux_change_policy.is_some())
    {
        errs.push(invalid(
            "spec.mover.securityContext.seLinuxOptions / spec.mover.podSecurityContext.seLinuxOptions / spec.mover.podSecurityContext.seLinuxChangePolicy",
            "effective seLinuxOptions and seLinuxChangePolicy are forbidden with RW PVC \
             publication: kubelet could relabel the LIVE source before the mover starts; \
             remove them from repository defaults, inherited context, and policy settings",
        ));
    }
    let drops_all = sc
        .capabilities
        .as_ref()
        .and_then(|c| c.drop.as_ref())
        .is_some_and(|drop| drop.iter().any(|cap| cap == "ALL"));
    let runtime_default = sc
        .seccomp_profile
        .as_ref()
        .is_some_and(|p| p.type_ == "RuntimeDefault");
    let adds_capabilities = sc
        .capabilities
        .as_ref()
        .and_then(|c| c.add.as_ref())
        .is_some_and(|add| !add.is_empty());
    // Do not use requires_privilege_resolved here: it intentionally includes
    // root/disabled non-root identity, which the caller gates by namespace.
    // These privileges remain forbidden even in an opted-in namespace.
    if sc.privileged == Some(true)
        || adds_capabilities
        || sc.allow_privilege_escalation != Some(false)
        || sc.proc_mount.as_deref().is_some_and(|p| p != "Default")
        || !drops_all
        || !runtime_default
    {
        errs.push(invalid(
            "spec.mover.securityContext",
            "RW-publication compatibility requires privileged: false, \
             allowPrivilegeEscalation: false, capabilities.drop: \
             [ALL], no added capabilities, and seccompProfile.type: RuntimeDefault",
        ));
    }
    errs
}

/// Validate the spec-only compatibility requirements. The controller additionally
/// checks the resolved object-store backend, final cache/context, source PVC's RWO
/// access mode, and required same-node Direct colocation.
pub fn validate_rw_publication_policy(spec: &SnapshotPolicySpec) -> Vec<ValidationError> {
    if !policy_requests_rw_publication(spec) {
        return Vec::new();
    }
    let mut errs = Vec::new();
    if spec.copy_method != CopyMethod::Direct {
        errs.push(invalid(
            "spec.copyMethod",
            "RW-publication compatibility requires copyMethod: Direct; Snapshot and Clone \
             copy methods are unsupported",
        ));
    }
    if spec.sources.len() != 1 || spec.sources[0].pvc.is_none() {
        errs.push(invalid(
            "spec.sources",
            "RW-publication compatibility requires exactly one literal PVC source; \
             pvcSelector, NFS, stream, and multiple sources are unsupported",
        ));
    }
    for (i, source) in spec.sources.iter().enumerate() {
        if !source_requests_rw_publication(source) {
            continue;
        }
        if !source_read_only(source) {
            errs.push(invalid(
                format!("spec.sources[{i}].readOnly"),
                "RW-publication compatibility requires readOnly: true on the mover mount; \
                 existing writable Direct sources must omit the publication controls and \
                 continue to acknowledgeLiveMutation",
            ));
        }
        if source.pvc_publication_read_only != Some(false) {
            errs.push(invalid(
                format!("spec.sources[{i}].pvcPublicationReadOnly"),
                "acknowledgeReadWritePublication requires explicit pvcPublicationReadOnly: false",
            ));
        }
        if source.acknowledge_read_write_publication != Some(true) {
            errs.push(invalid(
                format!("spec.sources[{i}].acknowledgeReadWritePublication"),
                "pvcPublicationReadOnly: false requires explicit acknowledgeReadWritePublication: true; \
                 CSI publishes RW while the mover's source mount remains RO",
            ));
        }
        if source.acknowledge_live_mutation.is_some() {
            errs.push(invalid(
                format!("spec.sources[{i}].acknowledgeLiveMutation"),
                "acknowledgeLiveMutation cannot be combined with RW-publication compatibility: \
                 this mode forbids live-source mutation; remove the field",
            ));
        }
    }
    if let Some(mover) = &spec.mover {
        errs.extend(validate_rw_publication_explicit_mover(mover));
    }
    errs
}

fn validate_rw_publication_explicit_mover(mover: &MoverSpec) -> Vec<ValidationError> {
    let resolved = resolve_mover_for_rw_publication(
        None,
        mover.security_context.as_ref(),
        mover.pod_security_context.as_ref(),
        mover.resources.as_ref(),
        mover.cache.as_ref(),
        mover.ttl_seconds_after_finished,
    );
    let mut errs = validate_rw_publication_security_context(
        &resolved.security_context,
        resolved.pod_security_context.as_ref(),
    );
    if let Err(e) = validate_rw_publication_cache(mover.cache.as_ref()) {
        errs.push(e);
    }
    errs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        CacheOwnership, CacheVolumeMode, MOVER_NONROOT_ID, MoverDefaults, merge_context_pair,
        resolve_mover,
    };
    use crate::snapshot_policy::{SnapshotPolicy, Source, source_pvc_publication_read_only};
    use crate::validate::{validate_backup_config, validate_mover, validate_source};
    use kube::CustomResourceExt;
    use serde_json::json;

    fn policy() -> SnapshotPolicySpec {
        crate::testutil::from_yaml(
            r#"
repository: {kind: Repository, name: object-store}
copyMethod: Direct
sources:
  - pvc: {name: app-data}
    readOnly: true
    pvcPublicationReadOnly: false
    acknowledgeReadWritePublication: true
"#,
        )
    }

    fn errors(spec: &SnapshotPolicySpec) -> String {
        let errors = validate_backup_config(spec);
        assert!(!errors.is_empty(), "expected rejected compatibility policy");
        format!("{errors:?}")
    }

    #[test]
    fn ordinary_direct_and_writable_direct_preserve_publication_and_acknowledgement() {
        for read_only in [None, Some(true), Some(false)] {
            let source = Source {
                pvc: policy().sources[0].pvc.clone(),
                read_only,
                ..Default::default()
            };
            assert_eq!(source_read_only(&source), read_only.unwrap_or(true));
            assert_eq!(
                source_pvc_publication_read_only(&source),
                read_only.unwrap_or(true)
            );
            assert!(!source_requests_rw_publication(&source));
            let wire = serde_json::to_value(&source).unwrap();
            assert!(wire.get("pvcPublicationReadOnly").is_none());
            assert!(wire.get("acknowledgeReadWritePublication").is_none());

            let mut spec = policy();
            spec.sources = vec![source];
            if read_only == Some(false) {
                assert!(errors(&spec).contains("acknowledgeLiveMutation"));
                spec.sources[0].acknowledge_live_mutation = Some(true);
            }
            assert!(validate_backup_config(&spec).is_empty());
        }
    }

    #[test]
    fn compatibility_has_distinct_writable_publication_and_read_only_process_mount() {
        let mut spec = policy();
        assert!(validate_backup_config(&spec).is_empty());
        assert!(source_read_only(&spec.sources[0]));
        assert!(!source_pvc_publication_read_only(&spec.sources[0]));
        // Logical readOnly's established default is sufficient; the publication
        // override and acknowledgement are still required explicitly.
        spec.sources[0].read_only = None;
        assert!(validate_backup_config(&spec).is_empty());
        assert!(source_read_only(&spec.sources[0]));
        assert!(!source_pvc_publication_read_only(&spec.sources[0]));
    }

    #[test]
    fn publication_default_is_not_materialized_by_crd_schema() {
        let schema = serde_json::to_value(SnapshotPolicy::crd()).unwrap();
        let source = &schema["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
            ["properties"]["sources"]["items"]["properties"];
        assert_eq!(source["readOnly"]["default"], true);
        assert_eq!(source["pvcPublicationReadOnly"]["type"], "boolean");
        assert!(source["pvcPublicationReadOnly"].get("default").is_none());
        assert!(
            source["acknowledgeReadWritePublication"]
                .get("default")
                .is_none()
        );
    }

    #[test]
    fn compatibility_rejects_non_direct_and_multiple_sources() {
        for copy_method in [CopyMethod::Snapshot, CopyMethod::Clone] {
            let mut spec = policy();
            spec.copy_method = copy_method;
            assert!(errors(&spec).contains("copyMethod"));
        }
        let mut spec = policy();
        spec.sources.push(spec.sources[0].clone());
        assert!(errors(&spec).contains("exactly one literal PVC"));
    }

    #[test]
    fn compatibility_rejects_non_literal_sources() {
        for shape in [
            json!({"pvcSelector": {"labelSelector": {"matchLabels": {"app": "a"}}}}),
            json!({"nfs": {"server": "nas.example", "path": "/export"}}),
            json!({"stream": {"fileName": "dump.sql", "workloadExec": {
                "podSelector": {"matchLabels": {"app": "a"}}, "command": ["dump"]
            }}}),
        ] {
            let mut value = shape;
            value["readOnly"] = json!(true);
            value["pvcPublicationReadOnly"] = json!(false);
            value["acknowledgeReadWritePublication"] = json!(true);
            let source: Source = serde_json::from_value(value).unwrap();
            assert!(validate_source(&source).is_err());
            let mut spec = policy();
            spec.sources = vec![source];
            assert!(errors(&spec).contains("literal PVC"));
        }
    }

    #[test]
    fn compatibility_requires_both_explicit_controls_and_forbids_live_mutation() {
        for ack in [None, Some(false)] {
            let mut spec = policy();
            spec.sources[0].acknowledge_read_write_publication = ack;
            assert!(errors(&spec).contains("acknowledgeReadWritePublication"));
            assert!(policy_requests_rw_publication(&spec));
        }
        for publication in [None, Some(true)] {
            let mut spec = policy();
            spec.sources[0].pvc_publication_read_only = publication;
            assert!(errors(&spec).contains("explicit pvcPublicationReadOnly: false"));
            assert!(policy_requests_rw_publication(&spec));
        }
        for ack in [Some(false), Some(true)] {
            let mut spec = policy();
            spec.sources[0].acknowledge_live_mutation = ack;
            assert!(errors(&spec).contains("cannot be combined"));
        }
        let mut spec = policy();
        spec.sources[0].read_only = Some(false);
        assert!(errors(&spec).contains("requires readOnly: true"));
        spec.sources[0].acknowledge_live_mutation = Some(true);
        assert!(errors(&spec).contains("requires readOnly: true"));
    }

    #[test]
    fn read_only_publication_cannot_weaken_writable_source_semantics() {
        let mut spec = policy();
        let source = &mut spec.sources[0];
        source.read_only = Some(false);
        source.pvc_publication_read_only = Some(true);
        source.acknowledge_read_write_publication = None;
        source.acknowledge_live_mutation = Some(true);
        assert!(errors(&spec).contains("cannot honor readOnly: false"));
    }

    #[test]
    fn dedicated_baseline_is_empty_and_legacy_baseline_retains_fsgroup() {
        let compatibility = resolve_mover_for_rw_publication(None, None, None, None, None, None);
        assert_eq!(
            compatibility.pod_security_context,
            Some(PodSecurityContext::default())
        );
        assert!(
            validate_rw_publication_security_context(
                &compatibility.security_context,
                compatibility.pod_security_context.as_ref(),
            )
            .is_empty()
        );
        let legacy = resolve_mover(None, None, None, None, None, None);
        assert_eq!(legacy.security_context, compatibility.security_context);
        let pod = legacy.pod_security_context.unwrap();
        assert_eq!(pod.fs_group, Some(MOVER_NONROOT_ID));
        assert_eq!(
            pod.fs_group_change_policy.as_deref(),
            Some("OnRootMismatch")
        );
    }

    #[test]
    fn compatibility_merge_preserves_identity_supplemental_groups_and_hardening() {
        let defaults = MoverDefaults {
            security_context: Some(SecurityContext {
                run_as_user: Some(2000),
                run_as_group: Some(2001),
                ..Default::default()
            }),
            ..Default::default()
        };
        let inherited = PodSecurityContext {
            run_as_user: Some(1000),
            run_as_group: Some(1001),
            supplemental_groups: Some(vec![3000]),
            ..Default::default()
        };
        let explicit = SecurityContext {
            run_as_group: Some(1002),
            ..Default::default()
        };
        let (sc, psc) = merge_context_pair(None, Some(&inherited), Some(&explicit), None);
        let resolved = resolve_mover_for_rw_publication(
            Some(&defaults),
            sc.as_ref(),
            psc.as_ref(),
            None,
            None,
            None,
        );
        assert_eq!(resolved.security_context.run_as_user, Some(1000));
        assert_eq!(resolved.security_context.run_as_group, Some(1002));
        assert_eq!(resolved.security_context.run_as_non_root, Some(true));
        assert_eq!(
            resolved.security_context.allow_privilege_escalation,
            Some(false)
        );
        let pod = resolved.pod_security_context.as_ref().unwrap();
        assert_eq!(pod.supplemental_groups, Some(vec![3000]));
        assert!(pod.fs_group.is_none());
        assert!(pod.fs_group_change_policy.is_none());
        assert!(
            validate_rw_publication_security_context(&resolved.security_context, Some(pod))
                .is_empty()
        );
    }

    #[test]
    fn forbidden_ownership_settings_survive_every_merge_layer_and_are_rejected() {
        for forbidden in [
            PodSecurityContext {
                fs_group: Some(1000),
                ..Default::default()
            },
            PodSecurityContext {
                fs_group_change_policy: Some("OnRootMismatch".into()),
                ..Default::default()
            },
        ] {
            let defaults = MoverDefaults {
                pod_security_context: Some(forbidden.clone()),
                ..Default::default()
            };
            for (repo, inherited, explicit) in [
                (Some(&defaults), None, None),
                (None, Some(&forbidden), None),
                (None, None, Some(&forbidden)),
            ] {
                let (sc, psc) = merge_context_pair(None, inherited, None, explicit);
                let resolved = resolve_mover_for_rw_publication(
                    repo,
                    sc.as_ref(),
                    psc.as_ref(),
                    None,
                    None,
                    None,
                );
                assert_eq!(
                    resolved.pod_security_context.as_ref(),
                    Some(&forbidden),
                    "must reject, never silently delete"
                );
                assert!(
                    !validate_rw_publication_security_context(
                        &resolved.security_context,
                        resolved.pod_security_context.as_ref()
                    )
                    .is_empty()
                );
            }
            let mut spec = policy();
            spec.mover = Some(MoverSpec {
                pod_security_context: Some(forbidden),
                ..Default::default()
            });
            assert!(errors(&spec).contains("fsGroup"));
        }
    }

    #[test]
    fn compatibility_rejects_weakened_hardening_even_in_privileged_namespaces() {
        for security in [
            json!({"privileged": true}),
            json!({"allowPrivilegeEscalation": true}),
            json!({"capabilities": {"add": ["SYS_ADMIN"]}}),
            json!({"capabilities": {"drop": []}}),
            json!({"seccompProfile": {"type": "Unconfined"}}),
            json!({"procMount": "Unmasked"}),
        ] {
            let mut spec = policy();
            spec.mover = Some(MoverSpec {
                security_context: Some(serde_json::from_value(security).unwrap()),
                ..Default::default()
            });
            assert!(errors(&spec).contains("RW-publication compatibility requires"));
        }
    }

    #[test]
    fn root_identity_is_left_to_the_existing_namespace_privilege_gate() {
        for context in [
            json!({"securityContext": {"runAsUser": 0, "runAsGroup": 0}}),
            json!({"securityContext": {"runAsNonRoot": false}}),
            json!({"podSecurityContext": {"runAsUser": 0, "runAsGroup": 0}}),
            json!({"podSecurityContext": {"runAsNonRoot": false}}),
            json!({"privilegedMode": true}),
        ] {
            let mover: MoverSpec = serde_json::from_value(context).unwrap();
            let resolved = resolve_mover_for_rw_publication(
                None,
                mover.security_context.as_ref(),
                mover.pod_security_context.as_ref(),
                None,
                None,
                None,
            );
            assert!(crate::common::requires_privilege_resolved(
                Some(&resolved.security_context),
                resolved.pod_security_context.as_ref(),
                mover.privileged_mode,
            ));
            let mut spec = policy();
            spec.mover = Some(mover);
            assert!(validate_backup_config(&spec).is_empty());
        }
    }

    #[test]
    fn effective_selinux_settings_cannot_relabel_the_live_source() {
        for psc in [
            json!({"seLinuxOptions": {"level": "s0:c100,c200"}}),
            json!({"seLinuxChangePolicy": "Recursive"}),
        ] {
            let psc: PodSecurityContext = serde_json::from_value(psc).unwrap();
            let defaults = MoverDefaults {
                pod_security_context: Some(psc.clone()),
                ..Default::default()
            };
            for (repo, recipe) in [(Some(&defaults), None), (None, Some(&psc))] {
                let resolved =
                    resolve_mover_for_rw_publication(repo, None, recipe, None, None, None);
                assert_eq!(resolved.pod_security_context.as_ref(), Some(&psc));
                assert!(
                    format!(
                        "{:?}",
                        validate_rw_publication_security_context(
                            &resolved.security_context,
                            resolved.pod_security_context.as_ref()
                        )
                    )
                    .contains("seLinux")
                );
            }
        }
        let mut spec = policy();
        spec.mover = Some(
            serde_json::from_value(
                json!({"securityContext": {"seLinuxOptions": {"level": "s0:c100,c200"}}}),
            )
            .unwrap(),
        );
        assert!(errors(&spec).contains("seLinux"));
    }

    #[test]
    fn compatibility_cache_is_explicitly_empty_dir_only() {
        assert!(validate_rw_publication_cache(None).is_ok());
        for ownership in [None, Some(CacheOwnership::InitContainer)] {
            let cache = CacheDefaults {
                ownership,
                ..Default::default()
            };
            assert!(validate_rw_publication_cache(Some(&cache)).is_ok());
            let mut spec = policy();
            spec.mover = Some(MoverSpec {
                cache: Some(cache),
                ..Default::default()
            });
            assert!(validate_backup_config(&spec).is_empty());
            for unsupported in [
                CacheDefaults {
                    ownership,
                    capacity: Some("1Gi".into()),
                    ..Default::default()
                },
                CacheDefaults {
                    ownership,
                    storage_class_name: Some("standard".into()),
                    ..Default::default()
                },
                CacheDefaults {
                    ownership,
                    mode: Some(CacheVolumeMode::Persistent),
                    ..Default::default()
                },
            ] {
                assert!(validate_rw_publication_cache(Some(&unsupported)).is_err());
                spec.mover.as_mut().unwrap().cache = Some(unsupported);
                assert!(errors(&spec).contains("ordinary emptyDir"));
            }
        }
    }

    #[test]
    fn cache_initializer_is_privilege_gated_and_rejected_in_other_mover_roles() {
        let mover = MoverSpec {
            cache: Some(CacheDefaults {
                ownership: Some(CacheOwnership::InitContainer),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(mover.requires_privilege());
        assert!(validate_mover(&mover, "Restore mover").is_err());
        assert!(
            validate_cache_ownership_scope(mover.cache.as_ref(), "spec.moverDefaults.cache")
                .is_err()
        );
        let mut ordinary = policy();
        ordinary.sources[0].pvc_publication_read_only = None;
        ordinary.sources[0].acknowledge_read_write_publication = None;
        ordinary.mover = Some(mover);
        assert!(errors(&ordinary).contains("initially supported only"));
    }
}
