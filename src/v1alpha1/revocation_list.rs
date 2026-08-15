//! `MCPGRevocationList` v1alpha1 — cluster-scoped revocation
//! catalogue. Maps onto the on-disk revocation-list format the
//! gateway consumes.
//!
//! The operator treats one resource named
//! [`crate::CLUSTER_DEFAULT_REVOCATION_LIST`] as authoritative;
//! other instances are advisory and don't propagate to gateway
//! pods. Operators that need per-tenant revocations should
//! consolidate into the canonical list via CI rather than
//! shipping multiple resources.

use std::collections::BTreeSet;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::conditions::Condition;

/// Cluster-wide list of revoked plugin SHA-256 hashes. Materialised
/// into per-namespace `mcpg-revocation-list` ConfigMaps that
/// gateway pods mount under the path declared in
/// `plugins.trust.revocation_list_path`.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcpg.dev",
    version = "v1alpha1",
    kind = "MCPGRevocationList",
    plural = "mcpgrevocationlists",
    derive = "PartialEq",
    derive = "Default",
    status = "MCPGRevocationListStatus",
    shortname = "mcpgrl",
    printcolumn = r#"{"name":"Entries","type":"integer","jsonPath":".status.observedRevocations"}"#,
    printcolumn = r#"{"name":"Materialised","type":"integer","jsonPath":".status.materialisedNamespaces"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
/// Cluster-scoped revocation list. The operator fans this out
/// into every namespace running a gateway as a per-namespace
/// `<gateway>-revocations` ConfigMap, mounted read-only into
/// the gateway pod at `/etc/mcpg/revocations/`. Gateway pods
/// enforce at plugin-load time — a list update plus a pod roll
/// is the full revocation cycle.
#[serde(rename_all = "camelCase")]
pub struct MCPGRevocationListSpec {
    /// Format version. Currently `1`. Unknown versions cause the
    /// admission webhook to reject the resource.
    #[serde(default = "default_format_version")]
    pub version: u8,

    /// RFC3339 audit-only timestamp. The operator does not gate
    /// freshness on this — it's surfaced in operator logs +
    /// status for incident-response correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<chrono::DateTime<chrono::Utc>>,

    /// One entry per revoked plugin artefact. Operators consolidate
    /// into a single entry per SHA-256 hash; duplicates are
    /// rejected at admission.
    #[serde(default)]
    pub revocations: Vec<RevocationEntry>,
}

fn default_format_version() -> u8 {
    1
}

/// One revoked artefact. The hash MUST be the SHA-256 of the
/// verified cdylib bytes (post-cosign-extract), not the OCI
/// manifest digest — operators want to revoke a specific
/// compiled artefact, even if it's been published under multiple
/// tags or registries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RevocationEntry {
    /// Lower-case hex, exactly 64 chars. Operators SHOULD ship
    /// lowercase to match `mcpg-plugin hash` output. The
    /// admission webhook normalises uppercase to lowercase.
    pub artifact_sha256: String,

    /// Free-form reason. Surfaced in the gateway's load-time
    /// error message + audit event. Empty / whitespace-only
    /// reasons are rejected at admission.
    pub reason: String,

    /// RFC3339 timestamp the entry was issued. Audit-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Observed state for `MCPGRevocationList`. `materialised_namespaces`
/// counts the per-namespace ConfigMaps the operator has fanned
/// the list out into; `content_hash` lets ops detect rollout drift
/// across consumer namespaces.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MCPGRevocationListStatus {
    /// Standard `metav1.Condition[]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Number of entries the operator last observed in spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_revocations: Option<i64>,

    /// Count of namespaces that have a materialised
    /// `mcpg-revocation-list` ConfigMap mirroring this resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub materialised_namespaces: Option<i64>,

    /// Plugin names (cluster-scoped `MCPGPlugin` resources) the
    /// operator has flagged as `revokedBySha = true` due to
    /// matches against this list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugins_blocked: Vec<String>,

    /// SHA-256 fingerprint of the rendered ConfigMap content
    /// (`revocations.json` key). Lets ops verify rollout status
    /// without reading every namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl MCPGRevocationListSpec {
    /// Returns the set of `(artifact_sha256)` strings, normalised
    /// to lowercase. The admission webhook uses this for
    /// duplicate-entry detection; the controller uses it for
    /// per-plugin revocation lookup.
    pub fn unique_hashes(&self) -> BTreeSet<String> {
        self.revocations
            .iter()
            .map(|e| e.artifact_sha256.to_ascii_lowercase())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn crd_metadata_correct() {
        let crd = MCPGRevocationList::crd();
        assert_eq!(crd.spec.group, "mcpg.dev");
        assert_eq!(crd.spec.scope, "Cluster");
        assert_eq!(crd.spec.names.kind, "MCPGRevocationList");
        assert_eq!(crd.spec.names.plural, "mcpgrevocationlists");
    }

    #[test]
    fn version_defaults_to_1() {
        let yaml = "revocations: []\n";
        let spec: MCPGRevocationListSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.version, 1);
    }

    #[test]
    fn unique_hashes_normalises_case() {
        let spec = MCPGRevocationListSpec {
            version: 1,
            issued_at: None,
            revocations: vec![
                RevocationEntry {
                    artifact_sha256: "ABCD1234".repeat(8),
                    reason: "test".into(),
                    revoked_at: None,
                },
                RevocationEntry {
                    artifact_sha256: "abcd1234".repeat(8),
                    reason: "duplicate (different case)".into(),
                    revoked_at: None,
                },
            ],
        };
        let unique = spec.unique_hashes();
        assert_eq!(unique.len(), 1);
        assert!(unique.contains(&"abcd1234".repeat(8)));
    }

    #[test]
    fn revocation_entry_camel_case_in_yaml() {
        let entry = RevocationEntry {
            artifact_sha256: "f1c5".repeat(16),
            reason: "test".into(),
            revoked_at: None,
        };
        let yaml = serde_yaml::to_string(&entry).unwrap();
        assert!(yaml.contains("artifactSha256:"), "got: {yaml}");
    }

    #[test]
    fn status_fields_omitted_when_empty() {
        let status = MCPGRevocationListStatus::default();
        let yaml = serde_yaml::to_string(&status).unwrap();
        assert!(!yaml.contains("conditions:"), "got: {yaml}");
        assert!(!yaml.contains("pluginsBlocked:"), "got: {yaml}");
    }
}
