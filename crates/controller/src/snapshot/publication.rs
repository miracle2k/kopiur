//! Safety boundary for the explicit live-PVC RW publication mode.
//!
//! A read-only container bind mount does not stop kubelet from applying fsGroup
//! to a writable CSI publication. Validate the final merged context before any
//! Job exists; do not repair an unsafe context by deleting its ownership fields.

use k8s_openapi::api::core::v1::PersistentVolumeClaim;
use kopiur_api::SnapshotPolicy;
use kopiur_api::backend::Backend;
use kopiur_api::common::{CacheOwnership, ResolvedMover, SourceColocationMode};
use kube::{Api, ResourceExt};

use crate::error::{Error, Result};
use crate::jobs::CacheOwnershipTarget;

pub(super) fn validate_source_pin(
    policy: &SnapshotPolicy,
    pin: Option<&kopiur_api::snapshot::SnapshotSourceRef>,
    namespace: &str,
) -> Result<()> {
    let Some(pin) = pin else {
        return Ok(());
    };
    let kopiur_api::snapshot::SnapshotSourceTarget::Pvc(target) = &pin.target;
    if pin.source_index != 0
        || pin.group.is_some()
        || target.namespace != namespace
        || policy
            .spec
            .sources
            .first()
            .and_then(|s| s.pvc.as_ref())
            .is_none_or(|p| p.name != target.name)
    {
        return Err(Error::Validation("RW-publication compatibility cannot override its single literal PVC through Snapshot.spec.source; the pinned source must name that same PVC and namespace".into()));
    }
    Ok(())
}

pub(super) fn validate_effective(
    policy: &SnapshotPolicy,
    backend: &Backend,
    mover: &ResolvedMover,
) -> Result<Option<CacheOwnershipTarget>> {
    // Check the concrete opt-in at the consumer boundary too. The API helper
    // deliberately recognizes malformed opt-ins, so they cannot fall back to
    // the legacy resolver with its default fsGroup.
    if !policy.spec.sources.first().is_some_and(|source| {
        source.pvc_publication_read_only == Some(false)
            && source.acknowledge_read_write_publication == Some(true)
    }) {
        return Err(Error::Validation("RW publication requires explicit pvcPublicationReadOnly: false and acknowledgeReadWritePublication: true".into()));
    }
    let mut errors = kopiur_api::validate::validate_backup_config(&policy.spec);
    errors.extend(
        kopiur_api::validate::validate_rw_publication_security_context(
            &mover.security_context,
            mover.pod_security_context.as_ref(),
        ),
    );
    if let Err(e) = kopiur_api::validate::validate_rw_publication_cache(mover.cache.as_ref()) {
        errors.push(e);
    }
    if !errors.is_empty() {
        return Err(Error::Validation(
            errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }
    match backend {
        Backend::S3(_) | Backend::Azure(_) | Backend::Gcs(_) | Backend::B2(_) => {}
        Backend::Filesystem(_) | Backend::Sftp(_) | Backend::WebDav(_)
        | Backend::Rclone(_) | Backend::Gdrive(_) => return Err(Error::Validation(
            "Direct PVC RW-publication compatibility requires an object-store repository (S3, Azure, GCS or B2); filesystem and other repository backends are unsupported".into(),
        )),
    }
    if mover.source_colocation == SourceColocationMode::Disabled {
        return Err(Error::Validation("RW-publication compatibility requires Direct source colocation; sourceColocation.mode: Disabled is forbidden".into()));
    }
    match mover.cache.as_ref().and_then(|c| c.ownership) {
        None => Ok(None),
        Some(CacheOwnership::InitContainer) => {
            let uid = kopiur_api::common::effective_run_as_user(
                Some(&mover.security_context),
                mover.pod_security_context.as_ref(),
            );
            let gid = kopiur_api::common::effective_run_as_group(
                Some(&mover.security_context),
                mover.pod_security_context.as_ref(),
            );
            // Missing overrides resolve to the controlled image's USER, never
            // to a guess about ownership on the live source volume.
            let uid = uid.unwrap_or(kopiur_api::common::MOVER_NONROOT_ID);
            let gid = gid.unwrap_or(kopiur_api::common::MOVER_NONROOT_ID);
            match (u32::try_from(uid).ok(), u32::try_from(gid).ok()) {
                (Some(uid), Some(gid)) if uid < u32::MAX && gid < u32::MAX => Ok(Some(CacheOwnershipTarget { uid, gid })),
                _ => Err(Error::Validation("cache ownership: InitContainer requires valid effective mover UID/GID; source file ownership is never guessed".into())),
            }
        }
    }
}

/// Bound PVC status is checked too: an unheld RWOP claim must not pass just
/// because the normal colocation resolver allows it to schedule freely.
pub(super) fn validate_claim(pvc: &PersistentVolumeClaim) -> Result<()> {
    let valid_modes = |modes: Option<&Vec<String>>| {
        modes.is_some_and(|m| m.len() == 1 && m[0] == "ReadWriteOnce")
    };
    let spec = pvc
        .spec
        .as_ref()
        .ok_or_else(|| Error::Validation("source PVC has no spec".into()))?;
    if !valid_modes(spec.access_modes.as_ref())
        || !valid_modes(pvc.status.as_ref().and_then(|s| s.access_modes.as_ref()))
        || spec
            .volume_mode
            .as_deref()
            .is_some_and(|v| v != "Filesystem")
    {
        return Err(Error::Validation("RW-publication compatibility requires a bound ReadWriteOnce filesystem PVC; ReadWriteOncePod, shared, block, and unknown access modes are refused".into()));
    }
    Ok(())
}

pub(super) async fn validate_live_claim(
    client: &kube::Client,
    ns: &str,
    claim: &str,
) -> Result<()> {
    let pvc = Api::<PersistentVolumeClaim>::namespaced(client.clone(), ns)
        .get(claim)
        .await?;
    validate_claim(&pvc)
}

/// The existing namespace privilege grant governs both a root main mover and
/// cache-only initialization. Unlike the legacy namespaced-install fallback,
/// failure to read the namespace cannot count as an explicit grant for RW
/// publication. This changes no ordinary mover's privilege-gate behavior.
pub(super) async fn namespace_allows_privileged_movers(
    client: &kube::Client,
    ns: &str,
) -> Result<bool> {
    let namespace = Api::<k8s_openapi::api::core::v1::Namespace>::all(client.clone())
        .get(ns)
        .await?;
    Ok(namespace
        .annotations()
        .get(kopiur_api::consts::PRIVILEGED_MOVERS_ANNOTATION)
        .is_some_and(|v| v == "true"))
}

/// Runtime mount checks happen too late to prevent kubelet ownership changes.
/// Require the exact fail-closed admission contract before creating the Job.
/// Reading these two named objects adds no privilege to the mover itself.
pub(super) async fn require_admission_protection(client: &kube::Client) -> Result<()> {
    use k8s_openapi::api::admissionregistration::v1::{
        ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding,
    };
    use kopiur_api::rw_publication_admission::{POLICY_NAME, binding, policy};
    let live_policy = Api::<ValidatingAdmissionPolicy>::all(client.clone())
        .get(POLICY_NAME)
        .await?;
    let live_binding = Api::<ValidatingAdmissionPolicyBinding>::all(client.clone())
        .get(POLICY_NAME)
        .await?;
    if live_policy.spec != policy().spec
        || live_binding.spec != binding().spec
        || live_policy.metadata.deletion_timestamp.is_some()
        || live_binding.metadata.deletion_timestamp.is_some()
    {
        return Err(Error::Validation("RW-publication compatibility requires the unmodified kopiur-rw-publication admission policy and Deny binding shipped with this controller; install deploy/admission/rw-publication.yaml".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rwop_and_unknown_access_never_pass_even_when_unheld() {
        for modes in [
            json!(["ReadWriteOncePod"]),
            json!(["ReadWriteMany"]),
            json!([]),
            json!(["ReadWriteOnce", "ReadWriteOncePod"]),
        ] {
            let pvc = serde_json::from_value(
                json!({"spec": {"accessModes": modes}, "status": {"accessModes": modes}}),
            )
            .unwrap();
            assert!(validate_claim(&pvc).is_err());
        }
        let mut pvc: PersistentVolumeClaim = serde_json::from_value(json!({"spec": {"accessModes": ["ReadWriteOnce"]}, "status": {"accessModes": ["ReadWriteOnce"]}})).unwrap();
        assert!(validate_claim(&pvc).is_ok());
        pvc.spec.as_mut().unwrap().volume_mode = Some("Block".into());
        assert!(validate_claim(&pvc).is_err());
    }

    fn policy() -> SnapshotPolicy {
        serde_json::from_value(json!({"metadata": {"name": "backup"}, "spec": {
            "repository": {"name": "object-store"}, "copyMethod": "Direct",
            "sources": [{"pvc": {"name": "data"}, "readOnly": true, "pvcPublicationReadOnly": false, "acknowledgeReadWritePublication": true}]
        }})).unwrap()
    }

    #[test]
    fn source_pin_cannot_redirect_compatibility_away_from_its_literal_pvc() {
        use kopiur_api::snapshot::{PvcTargetRef, SnapshotSourceRef, SnapshotSourceTarget};
        let mut pin = SnapshotSourceRef {
            source_index: 0,
            target: SnapshotSourceTarget::Pvc(PvcTargetRef {
                name: "data".into(),
                namespace: "ns".into(),
            }),
            group: None,
        };
        assert!(validate_source_pin(&policy(), Some(&pin), "ns").is_ok());
        assert!(validate_source_pin(&policy(), Some(&pin), "other-ns").is_err());
        let SnapshotSourceTarget::Pvc(target) = &mut pin.target;
        target.name = "different-claim".into();
        assert!(validate_source_pin(&policy(), Some(&pin), "ns").is_err());
    }

    #[test]
    fn effective_repository_context_and_cache_are_checked_and_identity_drives_init() {
        use kopiur_api::common::*;
        let policy = policy();
        let backend = serde_json::from_value(json!({"s3": {"bucket": "test"}})).unwrap();
        let mut mover = resolve_mover_for_rw_publication(None, None, None, None, None, None);
        assert!(
            validate_effective(&policy, &backend, &mover)
                .unwrap()
                .is_none()
        );
        mover.cache = Some(CacheDefaults {
            ownership: Some(CacheOwnership::InitContainer),
            ..Default::default()
        });
        let default_target = validate_effective(&policy, &backend, &mover)
            .unwrap()
            .unwrap();
        assert_eq!((default_target.uid, default_target.gid), (65532, 65532));
        mover.security_context.run_as_user = Some(1000);
        mover.security_context.run_as_group = Some(2000);
        let target = validate_effective(&policy, &backend, &mover)
            .unwrap()
            .unwrap();
        assert_eq!((target.uid, target.gid), (1000, 2000));
        // Root is a process identity, not permission to weaken source mounts.
        // The caller applies the existing namespace grant before Job creation.
        mover.security_context.run_as_user = Some(0);
        mover.security_context.run_as_group = Some(0);
        mover.security_context.run_as_non_root = Some(false);
        let target = validate_effective(&policy, &backend, &mover)
            .unwrap()
            .unwrap();
        assert_eq!((target.uid, target.gid), (0, 0));
        assert!(requires_privilege_resolved(
            Some(&mover.security_context),
            mover.pod_security_context.as_ref(),
            None,
        ));
        mover.pod_security_context.as_mut().unwrap().fs_group = Some(999);
        assert!(
            validate_effective(&policy, &backend, &mover)
                .unwrap_err()
                .to_string()
                .contains("fsGroup")
        );
        mover.pod_security_context.as_mut().unwrap().fs_group = None;
        mover.cache.as_mut().unwrap().capacity = Some("1Gi".into());
        assert!(validate_effective(&policy, &backend, &mover).is_err());
        mover.cache = None;
        let filesystem = serde_json::from_value(json!({"filesystem": {"path": "/repo"}})).unwrap();
        assert!(validate_effective(&policy, &filesystem, &mover).is_err());
    }

    fn namespace_client(status: u16, body: serde_json::Value) -> kube::Client {
        use kube::client::Body;
        let svc = tower::service_fn(move |req: http::Request<Body>| {
            let body = body.to_string();
            async move {
                assert_eq!(req.method(), http::Method::GET);
                assert_eq!(req.uri().path(), "/api/v1/namespaces/test-ns");
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(Body::from(body.into_bytes()))
                        .unwrap(),
                )
            }
        });
        kube::Client::new(svc, "default")
    }

    #[tokio::test]
    async fn compatibility_root_and_init_require_an_explicit_existing_namespace_grant() {
        for value in [None, Some("false"), Some("TRUE"), Some("true")] {
            let annotations =
                value.map(|v| json!({kopiur_api::consts::PRIVILEGED_MOVERS_ANNOTATION: v}));
            let client = namespace_client(
                200,
                json!({
                    "apiVersion": "v1", "kind": "Namespace",
                    "metadata": {"name": "test-ns", "annotations": annotations}
                }),
            );
            assert_eq!(
                namespace_allows_privileged_movers(&client, "test-ns")
                    .await
                    .unwrap(),
                value == Some("true"),
            );
        }
        // The ordinary mover's historical 403 fallback must never turn an
        // unreadable namespace into an explicit grant for RW publication.
        for (status, reason) in [(403, "Forbidden"), (404, "NotFound")] {
            let client = namespace_client(
                status,
                json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Failure",
                    "message": reason, "reason": reason, "code": status
                }),
            );
            assert!(
                namespace_allows_privileged_movers(&client, "test-ns")
                    .await
                    .is_err()
            );
        }
    }
}
