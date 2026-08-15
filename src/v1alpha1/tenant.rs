//! `MCPGTenant` v1alpha1 — declarative tenant boundary.
//!
//! Turns the operator's *implicit, PluginSet-triggered* tenant isolation
//! (`crate`-side: `rbac::ensure_tenant_secret_binding`, fired wherever a
//! `MCPGPluginSet` happens to exist) into a *declarative, governed*
//! boundary. A cluster-admin declares:
//!
//! - the namespaces a tenant owns,
//! - which cluster `MCPGPlugin`s those namespaces may reference,
//! - hard quotas on the MCPG resources the tenant may create.
//!
//! Cluster-scoped: only a cluster-admin defines tenant boundaries — a
//! tenant must not be able to grant itself more namespaces or raise its
//! own quota. Namespaces are **exclusively owned** (a namespace belongs
//! to at most one `MCPGTenant`, enforced at admission).
//!
//! ## Division of labour
//!
//! `MCPGTenant` is overwhelmingly an operator / control-plane concern;
//! the gateway runtime never learns the word "tenant".
//!
//! - **Admission webhook (synchronous):** plugin allowlist, namespace
//!   exclusivity, per-gateway replica cap. Anything a tenant could abuse
//!   to escalate must be a synchronous gate.
//! - **Reconcile (eventual):** per-namespace Secret-write `RoleBinding`
//!   (drives the existing `rbac.rs` path, now with finalizer cleanup),
//!   namespace labelling, and a generated `ResourceQuota` per owned
//!   namespace — the race-safe count-quota enforcement (the webhook
//!   count-check is only a nicer error message; K8s' `ResourceQuota`
//!   admission holds the apiserver-side lock).
//! - **Gateway config:** when `identityAttribute` is set, the operator
//!   stamps a consistent `$identity.attributes.<key> == "<value>"`
//!   predicate so a tenant's gateways and `MCPGRoute`s share one
//!   identity boundary. Reuses the existing `tool_access` rendering — no
//!   ABI / protocol / dispatch change.
//!
//! Opt-in: clusters with no `MCPGTenant` keep the implicit
//! PluginSet-triggered RBAC unchanged.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::conditions::Condition;

/// Declarative, cluster-admin-owned tenant boundary.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcpg.dev",
    version = "v1alpha1",
    kind = "MCPGTenant",
    plural = "mcpgtenants",
    derive = "PartialEq",
    derive = "Default",
    status = "MCPGTenantStatus",
    shortname = "mcpgt",
    printcolumn = r#"{"name":"Namespaces","type":"integer","jsonPath":".status.boundNamespaces[*]"}"#,
    printcolumn = r#"{"name":"Gateways","type":"integer","jsonPath":".status.observed.gateways"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
/// Cluster-scoped tenant boundary referencing existing namespaces.
#[serde(rename_all = "camelCase")]
pub struct MCPGTenantSpec {
    /// Namespaces this tenant owns. Per-namespace RBAC, the generated
    /// `ResourceQuota`, the plugin allowlist, and the replica cap apply
    /// to exactly these. Namespaces are EXCLUSIVELY owned — a namespace
    /// may belong to at most one `MCPGTenant` (admission rejects
    /// overlap). The operator does **not** create these namespaces; it
    /// references existing ones.
    pub namespaces: Vec<String>,

    /// Plugin allowlist. `MCPGPluginSet`s in this tenant's namespaces
    /// may only reference cluster `MCPGPlugin`s matching one of these.
    ///
    /// - Empty list = **deny-all** (a tenant must explicitly opt in).
    /// - A single entry `{name: "*"}` = any cluster plugin.
    ///
    /// Each entry matches when EITHER its `name` equals the plugin's
    /// resource name / capability id, OR the plugin's OCI `image`
    /// starts with `registryPrefix`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_plugins: Vec<AllowedPlugin>,

    /// Hard quotas, enforced synchronously (replica cap at admission;
    /// counts via a generated per-namespace `ResourceQuota`). Unset =
    /// no quota.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quotas: Option<TenantQuotas>,

    /// Optional. The identity attribute the operator stamps into the
    /// gateway's runtime `tool_access` policy so a tenant's gateways and
    /// routes share one identity boundary. When unset, `MCPGTenant`
    /// performs no gateway-config rendering at all (pure RBAC + admission
    /// object).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_attribute: Option<TenantIdentityAttribute>,
}

/// One plugin-allowlist matcher. At least one of `name` /
/// `registryPrefix` should be set; an entry with neither matches
/// nothing (and is rejected at admission).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AllowedPlugin {
    /// Match by the `MCPGPlugin` resource name or the plugin
    /// capability id (e.g. `identity-workload` or
    /// `dev.mcpg.identity.workload`). The literal `*` matches any
    /// plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Match when the referenced plugin's OCI `image` starts with this
    /// prefix (e.g. `ghcr.io/mcpg-dev/source-code/plugins/`).
    ///
    /// A literal `starts_with` on the resolved image, so the prefix must
    /// carry every path segment of the references it is meant to admit.
    /// This is an ALLOWLIST, so a prefix that stops matching fails CLOSED
    /// (the plugin is denied) — unlike MCPGPluginMirror's
    /// `upstream.namespace`, where the same drift fails open.
    ///
    /// If the base a plugin is published under gains or loses a path
    /// segment — `ghcr.io/mcpg-dev/source-code/plugins/` is five
    /// segments, `ghcr.io/mcpg-dev/plugins/` is four — every MCPGTenant
    /// in the cluster needs this field updated in the same change, or
    /// its tenants lose access to first-party plugins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_prefix: Option<String>,
}

impl AllowedPlugin {
    /// True when this matcher admits a plugin with the given resource
    /// name + capability id + (optional, resolved) OCI image.
    pub fn matches(&self, resource_name: &str, plugin_id: &str, image: Option<&str>) -> bool {
        if let Some(name) = &self.name
            && (name == "*" || name == resource_name || name == plugin_id)
        {
            return true;
        }
        if let (Some(prefix), Some(img)) = (&self.registry_prefix, image)
            && !prefix.is_empty()
            && img.starts_with(prefix.as_str())
        {
            return true;
        }
        false
    }
}

/// Hard caps on the MCPG resources a tenant may create. `None` on any
/// field = unlimited for that resource.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantQuotas {
    /// Max `MCPGGateway`s per owned namespace (count quota →
    /// `ResourceQuota`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_gateways: Option<i64>,
    /// Max `MCPGPluginSet`s per owned namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_plugin_sets: Option<i64>,
    /// Max `MCPGRoute`s per owned namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_routes: Option<i64>,
    /// Per-gateway replica ceiling. A *field* constraint (not a count),
    /// so it has no admission race and is webhook-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_replicas_per_gateway: Option<i64>,
}

/// The identity attribute stamped into a tenant's gateway `tool_access`
/// rules (`$identity.attributes.<key> == "<value>"`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantIdentityAttribute {
    /// Attribute key. Conventionally `tenant`.
    pub key: String,
    /// Attribute value identifying this tenant (e.g. the tenant name).
    pub value: String,
}

/// Observed state for `MCPGTenant`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MCPGTenantStatus {
    /// Standard `metav1.Condition[]`. Notable types:
    /// - `Ready` — RBAC + `ResourceQuota` materialised for all bound
    ///   namespaces.
    /// - `NamespacesBound` — every `spec.namespaces` exists and is
    ///   labelled `mcpg.dev/tenant=<name>`.
    /// - `QuotaWithinLimits` — `False` (soft signal, not a gate) when an
    ///   owned namespace already holds more resources than the quota
    ///   allows; the generated `ResourceQuota` still admits the existing
    ///   objects and blocks only new ones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Namespaces the operator successfully bound (exist + labelled +
    /// RBAC/quota applied). A subset of `spec.namespaces` when some are
    /// missing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bound_namespaces: Vec<String>,

    /// Observed counts across owned namespaces. Observability only —
    /// **never** the enforcement point for quota (that's the generated
    /// `ResourceQuota`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<TenantObservedCounts>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// Aggregate counts of MCPG resources across a tenant's owned
/// namespaces. Surfaced for ops visibility into quota headroom.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TenantObservedCounts {
    #[serde(default)]
    pub gateways: i64,
    #[serde(default)]
    pub plugin_sets: i64,
    #[serde(default)]
    pub routes: i64,
}

impl MCPGTenantSpec {
    /// True when `namespace` is one of this tenant's owned namespaces.
    pub fn owns_namespace(&self, namespace: &str) -> bool {
        self.namespaces.iter().any(|n| n == namespace)
    }

    /// Namespaces owned by BOTH this tenant and `other` — the
    /// exclusivity violation set (empty = no overlap). Sorted + deduped.
    pub fn overlapping_namespaces(&self, other: &MCPGTenantSpec) -> Vec<String> {
        let mut out: Vec<String> = self
            .namespaces
            .iter()
            .filter(|n| other.namespaces.iter().any(|o| o == *n))
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Whether a plugin (by resource name + capability id + optional
    /// resolved image) is permitted by the allowlist.
    ///
    /// An empty allowlist denies everything — a tenant must explicitly
    /// opt in. `{name: "*"}` admits any plugin.
    pub fn plugin_allowed(
        &self,
        resource_name: &str,
        plugin_id: &str,
        image: Option<&str>,
    ) -> bool {
        self.allowed_plugins
            .iter()
            .any(|a| a.matches(resource_name, plugin_id, image))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    fn sample_yaml() -> &'static str {
        // A representative tenant spec.
        r#"
namespaces:
  - payments
  - payments-staging
allowedPlugins:
  - name: identity-workload
  - name: dev.mcpg.policy.cedar
  - registryPrefix: ghcr.io/mcpg-dev/plugins/
quotas:
  maxGateways: 5
  maxPluginSets: 10
  maxRoutes: 50
  maxReplicasPerGateway: 20
identityAttribute:
  key: tenant
  value: team-payments
"#
    }

    #[test]
    fn crd_metadata_correct() {
        let crd = MCPGTenant::crd();
        assert_eq!(crd.spec.group, "mcpg.dev");
        assert_eq!(crd.spec.scope, "Cluster");
        assert_eq!(crd.spec.names.kind, "MCPGTenant");
        assert_eq!(crd.spec.names.plural, "mcpgtenants");
    }

    #[test]
    fn parses_documented_example() {
        let spec: MCPGTenantSpec = serde_yaml::from_str(sample_yaml()).unwrap();
        assert_eq!(spec.namespaces, vec!["payments", "payments-staging"]);
        assert_eq!(spec.allowed_plugins.len(), 3);
        let q = spec.quotas.as_ref().unwrap();
        assert_eq!(q.max_gateways, Some(5));
        assert_eq!(q.max_replicas_per_gateway, Some(20));
        let id = spec.identity_attribute.as_ref().unwrap();
        assert_eq!(id.key, "tenant");
        assert_eq!(id.value, "team-payments");
    }

    #[test]
    fn camel_case_wire_keys() {
        let spec: MCPGTenantSpec = serde_yaml::from_str(sample_yaml()).unwrap();
        let v = serde_json::to_value(&spec).unwrap();
        assert!(v.get("allowedPlugins").is_some(), "got: {v}");
        assert_eq!(v["quotas"]["maxReplicasPerGateway"], 20);
        assert_eq!(v["identityAttribute"]["key"], "tenant");
        // registryPrefix preserved camelCase
        assert_eq!(
            v["allowedPlugins"][2]["registryPrefix"],
            "ghcr.io/mcpg-dev/plugins/"
        );
    }

    #[test]
    fn owns_namespace_matches_declared() {
        let spec: MCPGTenantSpec = serde_yaml::from_str(sample_yaml()).unwrap();
        assert!(spec.owns_namespace("payments"));
        assert!(spec.owns_namespace("payments-staging"));
        assert!(!spec.owns_namespace("fraud"));
    }

    #[test]
    fn overlap_detects_shared_namespace() {
        let a = MCPGTenantSpec {
            namespaces: vec!["a".into(), "shared".into()],
            ..Default::default()
        };
        let b = MCPGTenantSpec {
            namespaces: vec!["shared".into(), "b".into()],
            ..Default::default()
        };
        assert_eq!(a.overlapping_namespaces(&b), vec!["shared"]);
        let c = MCPGTenantSpec {
            namespaces: vec!["c".into()],
            ..Default::default()
        };
        assert!(a.overlapping_namespaces(&c).is_empty());
    }

    #[test]
    fn empty_allowlist_denies_everything() {
        let spec = MCPGTenantSpec {
            namespaces: vec!["x".into()],
            ..Default::default()
        };
        assert!(!spec.plugin_allowed("identity-workload", "dev.mcpg.identity.workload", None));
    }

    #[test]
    fn wildcard_allowlist_admits_any() {
        let spec = MCPGTenantSpec {
            allowed_plugins: vec![AllowedPlugin {
                name: Some("*".into()),
                registry_prefix: None,
            }],
            ..Default::default()
        };
        assert!(spec.plugin_allowed("anything", "any.id", None));
    }

    #[test]
    fn allowlist_matches_by_resource_name_or_id() {
        let spec: MCPGTenantSpec = serde_yaml::from_str(sample_yaml()).unwrap();
        // by resource name
        assert!(spec.plugin_allowed("identity-workload", "dev.mcpg.identity.workload", None));
        // by capability id
        assert!(spec.plugin_allowed("cedar-1.0.0-amd64", "dev.mcpg.policy.cedar", None));
        // neither name/id nor prefix → denied
        assert!(!spec.plugin_allowed("rogue", "dev.evil.exfil", Some("docker.io/evil/x:1")));
    }

    #[test]
    fn allowlist_matches_by_registry_prefix() {
        let spec: MCPGTenantSpec = serde_yaml::from_str(sample_yaml()).unwrap();
        assert!(spec.plugin_allowed(
            "some-resource",
            "dev.third.party",
            Some("ghcr.io/mcpg-dev/plugins/third-party:1.0")
        ));
        // prefix mismatch
        assert!(!spec.plugin_allowed(
            "some-resource",
            "dev.third.party",
            Some("docker.io/mcpg-dev/plugins/third-party:1.0")
        ));
    }

    #[test]
    fn allowed_plugin_with_neither_field_matches_nothing() {
        let a = AllowedPlugin::default();
        assert!(!a.matches("x", "y", Some("z")));
    }
}
