//! `MCPGPlugin` v1alpha1 — single signed plugin artefact.
//!
//! Cluster-scoped — the same plugin bytes are byte-identical
//! across every namespace, so storing once cluster-wide
//! deduplicates. Tenant `MCPGPluginSet` resources reference
//! plugins by name (cross-scope read; admission validates RBAC).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::conditions::Condition;

/// Single OCI-published, signed plugin artefact + the trust
/// policy under which the operator verifies it.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcpg.dev",
    version = "v1alpha1",
    kind = "MCPGPlugin",
    plural = "mcpgplugins",
    derive = "PartialEq",
    derive = "Default",
    status = "MCPGPluginStatus",
    shortname = "mcpgp",
    printcolumn = r#"{"name":"Plugin","type":"string","jsonPath":".spec.pluginId"}"#,
    printcolumn = r#"{"name":"Version","type":"string","jsonPath":".spec.version"}"#,
    printcolumn = r#"{"name":"Class","type":"string","jsonPath":".spec.pluginClass"}"#,
    printcolumn = r#"{"name":"Verified","type":"string","jsonPath":".status.conditions[?(@.type=='Verified')].status"}"#,
    printcolumn = r#"{"name":"Revoked","type":"boolean","jsonPath":".status.revokedBySha"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct MCPGPluginSpec {
    /// Plugin id matching the descriptor's id (e.g.
    /// `dev.mcpg.identity.workload`). Must equal the descriptor
    /// embedded in the OCI artefact; the operator verifies on
    /// pull.
    pub plugin_id: String,

    /// Plugin version. Should match the OCI tag's semver
    /// component when the operator can extract it; admission
    /// rejects mismatches.
    pub version: String,

    /// Plugin class — advisory routing hint. The operator
    /// re-checks this against the descriptor.
    /// Values follow `mcpg_plugin_protocol::PluginClass`.
    /// Examples: `identity_provider`, `policy_engine`,
    /// `credential_issuer`, `audit_sink`, `cluster`,
    /// `backend`, `transport`.
    pub plugin_class: String,

    /// OCI artefact reference + optional in-cluster mirror.
    pub oci: OciImageRef,

    /// Trust policy: signing key, cosign identity, SLSA
    /// provenance source. The operator must be able to verify
    /// every layer before mounting the plugin into a gateway pod.
    pub trust: PluginTrust,
}

/// Where the operator pulls a plugin from. Tag-form is allowed
/// for development; production manifests should pin a digest
/// (`...@sha256:...`) so the trust pipeline gates against an
/// immutable artefact.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OciImageRef {
    /// Full OCI ref, e.g.
    /// `ghcr.io/mcpg-dev/source-code/plugins/identity-workload:1.2.3-linux-amd64`
    /// (tag) or `...@sha256:abcd...` (digest pin — recommended
    /// for production).
    pub image: String,

    /// Optional pull-secret reference (in the operator's
    /// namespace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_secret_ref: Option<crate::v1alpha1::LocalObjectReference>,

    /// Pull through an in-cluster mirror (a future
    /// `MCPGPluginMirror` resource). When set, the operator
    /// translates the upstream `image` URL through the mirror's
    /// pathPrefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror_ref: Option<crate::v1alpha1::LocalObjectReference>,
}

/// Three-layer trust policy. Every layer is fail-closed and runs
/// in this order at reconcile time:
/// 1. Ed25519 (`signing_key_ref`) — mandatory.
/// 2. Cosign keyless (`cosign_identity`) — optional but
///    enabled-by-default in operator-shipped fixtures.
/// 3. SLSA L3 in-toto (`slsa_provenance`) — optional, gated
///    on the operator's supply-chain posture.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PluginTrust {
    /// Ed25519 public key the operator verifies the cdylib's
    /// `mcpg-plugin sign` signature against. Mandatory in v1alpha1;
    /// signature verification is the baseline trust gate that
    /// every plugin must pass.
    pub signing_key_ref: SigningKeyRef,

    /// Cosign keyless identity. Operator verifies the OCI
    /// manifest's sigstore signature against this identity.
    /// Optional in v1alpha1 — operators with cosign trust
    /// configured here run an extra verification layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cosign_identity: Option<CosignIdentity>,

    /// SLSA L3 provenance verification. Optional in v1alpha1 —
    /// operators with SLSA-enforced supply chains gate on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slsa_provenance: Option<SlsaProvenance>,
}

/// Pointer to the Ed25519 public-key Secret. The Secret must
/// live in the operator's namespace (so a tenant can't supply
/// their own trust anchor); per-plugin keys are supported but
/// most operators point everything at one shared release key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SigningKeyRef {
    /// Secret name in the operator's namespace.
    pub secret_name: String,
    /// Secret key holding the Ed25519 public key bytes (raw
    /// 32 bytes, base64-decoded by the operator at load time).
    /// Default: `release.pub`.
    #[serde(default = "default_signing_key_field")]
    pub key: String,
}

fn default_signing_key_field() -> String {
    "release.pub".into()
}

/// Cosign keyless trust anchor. The operator runs `cosign verify`
/// against the OCI manifest using sigstore-rs and accepts only
/// signatures whose certificate subject matches the regex AND
/// whose OIDC issuer matches `oidc_issuer` exactly.
///
/// Verification is bound to the manifest digest the operator's own
/// pull resolved, so `status.cosignVerified` describes the artefact
/// that was loaded — not whatever the tag pointed at when the
/// signature was looked up. This holds through `oci.mirrorRef`: the
/// signature is still checked upstream, at the digest the mirror
/// served.
///
/// The regex MUST be anchored with `^` and `$`; the admission
/// webhook rejects unanchored patterns because they
/// accept attacker-controlled prefixes/suffixes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CosignIdentity {
    /// Regex matching the OIDC subject baked into the cosign
    /// certificate. Example:
    /// `^https://github\.com/mcpg-dev/source-code/`.
    pub certificate_identity_regexp: String,

    /// OIDC issuer the cosign cert chains back to.
    /// Example: `https://token.actions.githubusercontent.com`.
    pub oidc_issuer: String,
}

/// SLSA L3 in-toto attestation pin. Caller stores the
/// `*.intoto.jsonl` provenance file in a ConfigMap; the
/// operator verifies that the file pins exactly the
/// `source_uri` + `source_tag` recorded here. Anything else is
/// admission-rejected.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SlsaProvenance {
    /// Name of a ConfigMap (in the operator's namespace) holding
    /// the `*.intoto.jsonl` provenance file under
    /// `data.provenance.intoto.jsonl`.
    pub config_map_name: String,

    /// Source URI the provenance must be pinned to. Example:
    /// `github.com/mcpg-dev/source-code`.
    pub source_uri: String,

    /// Source tag the provenance must record. Example: `v1.2.3`.
    pub source_tag: String,
}

/// Observed state for a `MCPGPlugin`. Boolean fields are
/// reported as `Option<bool>` so absent ⇒ "not yet evaluated"
/// vs. `Some(false)` ⇒ "evaluated, refused". Operators reading
/// status should treat absence as "not Ready" rather than
/// defaulting to `false`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MCPGPluginStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// SHA-256 of the verified cdylib bytes (lower-case hex).
    /// Operators check this against the cluster
    /// `MCPGRevocationList`; revoked entries flip
    /// `revoked_by_sha = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_digest: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_valid: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cosign_verified: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slsa_verified: Option<bool>,

    /// True when [`Self::resolved_digest`] matches an entry in
    /// the cluster `MCPGRevocationList`. The operator refuses
    /// to materialise the plugin into any
    /// `MCPGPluginSet` while this is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by_sha: Option<bool>,

    /// Name of the operator-managed Secret holding the verified
    /// bytes (in the operator's namespace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artefact_secret_name: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pulled_at: Option<chrono::DateTime<chrono::Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_time: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn crd_is_cluster_scoped() {
        let crd = MCPGPlugin::crd();
        assert_eq!(crd.spec.scope, "Cluster");
        assert_eq!(crd.spec.names.kind, "MCPGPlugin");
        assert_eq!(crd.spec.names.plural, "mcpgplugins");
    }

    #[test]
    fn signing_key_ref_default_field() {
        let yaml = "secretName: my-trust\n";
        let s: SigningKeyRef = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(s.key, "release.pub");
    }

    #[test]
    fn oci_ref_serialises_camelcase() {
        let r = OciImageRef {
            image: "ghcr.io/foo:v1@sha256:abc".into(),
            pull_secret_ref: Some(crate::v1alpha1::LocalObjectReference {
                name: "ghcr".into(),
            }),
            mirror_ref: None,
        };
        let yaml = serde_yaml::to_string(&r).unwrap();
        assert!(yaml.contains("pullSecretRef:"), "got: {yaml}");
        assert!(!yaml.contains("mirrorRef:"), "got: {yaml}");
    }

    #[test]
    fn spec_full_serde_roundtrip() {
        let spec = MCPGPluginSpec {
            plugin_id: "dev.mcpg.identity.workload".into(),
            version: "1.2.3".into(),
            plugin_class: "identity_provider".into(),
            oci: OciImageRef {
                image: "ghcr.io/mcpg-dev/source-code/plugins/identity-workload:1.2.3-linux-amd64@sha256:abcd".into(),
                pull_secret_ref: None,
                mirror_ref: None,
            },
            trust: PluginTrust {
                signing_key_ref: SigningKeyRef {
                    secret_name: "release-trust".into(),
                    key: "release.pub".into(),
                },
                cosign_identity: Some(CosignIdentity {
                    certificate_identity_regexp: "^https://github.com/mcpg-dev/".into(),
                    oidc_issuer: "https://token.actions.githubusercontent.com".into(),
                }),
                slsa_provenance: None,
            },
        };
        let yaml = serde_yaml::to_string(&spec).unwrap();
        let back: MCPGPluginSpec = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(spec, back);
    }
}
