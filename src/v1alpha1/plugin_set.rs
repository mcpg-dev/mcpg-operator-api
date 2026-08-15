//! `MCPGPluginSet` v1alpha1 — namespace-scoped bundle of
//! `MCPGPlugin` references with per-plugin runtime config.
//!
//! Tenants reference plugin sets from their `MCPGGateway`
//! resources via `spec.pluginSetRef`. The plugin set names
//! cluster-scoped `MCPGPlugin` resources (cross-scope read; the
//! operator validates RBAC + readiness at admission and at
//! reconcile time).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::conditions::Condition;
use crate::v1alpha1::LocalObjectReference;

#[derive(CustomResource, Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcpg.dev",
    version = "v1alpha1",
    kind = "MCPGPluginSet",
    plural = "mcpgpluginsets",
    namespaced,
    derive = "PartialEq",
    derive = "Default",
    status = "MCPGPluginSetStatus",
    shortname = "mcpgps",
    printcolumn = r#"{"name":"Plugins","type":"integer","jsonPath":".status.resolvedEntries"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct MCPGPluginSetSpec {
    /// One entry per plugin the set installs. Order is
    /// preserved in the rendered gateway config (some plugin
    /// chains are order-sensitive — e.g. identity → policy).
    pub entries: Vec<MCPGPluginSetEntry>,

    /// Per-plugin capability grants. Keyed by plugin id; values
    /// are subsets of the plugin descriptor's
    /// `required_capabilities`. The operator's admission
    /// webhook validates the subset relationship.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capability_grants: BTreeMap<String, Vec<String>>,
}

/// One plugin in a `MCPGPluginSet`. Order in the spec is the
/// order the gateway sees in its boot config — order-sensitive
/// chains (identity → policy → audit) must rely on this.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MCPGPluginSetEntry {
    /// Plugin id — e.g. `dev.mcpg.identity.workload`. Must
    /// match the referenced `MCPGPlugin.spec.pluginId`; the
    /// admission webhook flags mismatches.
    pub id: String,

    /// Reference to a cluster-scoped `MCPGPlugin`. Operator
    /// validates the plugin exists + is in `Ready` status before
    /// allowing the set to converge.
    pub plugin_ref: LocalObjectReference,

    /// Whether this entry is active. Disabled entries pass
    /// through to status (so operators see what's configured)
    /// but the operator skips them when rendering the gateway
    /// config + materialising plugin Secrets.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Whether the plugin is enforced (default) or runs in
    /// shadow mode. Shadow plugins evaluate, log, and emit
    /// metrics, but their Deny/Challenge decisions are mapped
    /// to Allow before reaching the request flow. Operators
    /// use this to roll out a new policy plugin in observation
    /// mode before promoting to enforce.
    ///
    /// Maps to `PluginEntryConfig.enforce` in the gateway boot
    /// config. Defaults to `true` — pre-1.0 we bias toward
    /// fail-closed: operators must explicitly opt in to shadow
    /// mode.
    #[serde(default = "default_true")]
    pub enforce: bool,

    /// Inline plugin runtime config — passes through verbatim
    /// to the gateway's `plugins[].config`. Schema
    /// varies per plugin; the operator does not validate it
    /// (the gateway's own boot-time validators do). The
    /// `preserve_object` schema annotation marks this field
    /// `x-kubernetes-preserve-unknown-fields` so the API server
    /// keeps the arbitrary nested config intact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::schema_helpers::preserve_object")]
    pub config: Option<serde_json::Value>,
}

fn default_true() -> bool {
    true
}

/// Materialised view of `MCPGPluginSetSpec.capability_grants`.
/// Used internally by the operator + tests; users author grants
/// as a `BTreeMap` on the spec side.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityGrant {
    /// Plugin id the grant applies to.
    pub plugin_id: String,
    /// Capabilities the operator allows the plugin to consume.
    pub capabilities: Vec<String>,
}

/// Observed state for `MCPGPluginSet`. `resolved_entries` ==
/// `total_entries` is the canonical Ready signal; partial
/// failures land in `failed_entries` so operators can read
/// the per-entry reason without grepping logs.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MCPGPluginSetStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Number of entries the operator successfully resolved
    /// (referenced `MCPGPlugin` exists + Ready + not revoked).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_entries: Option<i64>,

    /// Total entries in spec — `resolved_entries` should equal
    /// this when the set is `Ready`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_entries: Option<i64>,

    /// SHA-256 of the rendered config (entries + per-entry
    /// configs + grants). Lets dependent gateways detect
    /// "plugin set changed → roll pods" without diffing the
    /// full spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_hash: Option<String>,

    /// Per-entry resolution errors (referenced plugin missing,
    /// revoked, capability grant out of bounds, etc.). Empty
    /// when the set is `Ready`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_entries: Vec<FailedEntry>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// One per-entry resolution failure surfaced into status.
/// `reason` is a stable enum so consumers can branch on it;
/// `message` is free-text human detail.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FailedEntry {
    /// Plugin id the failure pertains to.
    pub id: String,
    /// Camel-case enum reason: `PluginNotFound`,
    /// `PluginNotReady`, `PluginRevoked`, `PluginIdMismatch`,
    /// `ArtefactSecretMissing`. (Capability-grant violations are
    /// rejected at admission, not surfaced here.)
    pub reason: String,
    /// Free-text human-readable detail.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn crd_is_namespaced() {
        let crd = MCPGPluginSet::crd();
        assert_eq!(crd.spec.scope, "Namespaced");
    }

    #[test]
    fn entry_enabled_defaults_to_true() {
        let yaml = r#"
id: dev.mcpg.identity.workload
pluginRef:
  name: identity-workload-1.2.3-linux-amd64
"#;
        let entry: MCPGPluginSetEntry = serde_yaml::from_str(yaml).unwrap();
        assert!(entry.enabled);
    }

    #[test]
    fn capability_grants_serialise_camelcase() {
        let mut grants = BTreeMap::new();
        grants.insert(
            "dev.mcpg.identity.workload".to_string(),
            vec!["transport_listen".into()],
        );
        let spec = MCPGPluginSetSpec {
            entries: vec![],
            capability_grants: grants,
        };
        let yaml = serde_yaml::to_string(&spec).unwrap();
        assert!(yaml.contains("capabilityGrants:"), "got: {yaml}");
    }
}
