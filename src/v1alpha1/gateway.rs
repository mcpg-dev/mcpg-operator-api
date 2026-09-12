//! `MCPGGateway` v1alpha1 — namespace-scoped gateway
//! deployment plus optional `pluginSetRef` and
//! `revocationListRef` references into the plugin lifecycle.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::conditions::Condition;

/// Desired state for a tenant's `MCPGGateway`.
///
/// The operator's gateway controller renders this into a
/// Deployment + Service + ConfigMap (+ optional Ingress,
/// NetworkPolicy, PDB, ServiceMonitor) and reconciles them into
/// the gateway's namespace. Every field maps either directly to
/// a Kubernetes shape or to a gateway-config key that lands in
/// the rendered ConfigMap.
///
/// Cross-cutting fields (`pluginSetRef`, `revocationListRef`)
/// pull in resources from the cluster-level plugin lifecycle —
/// see [`crate::v1alpha1::MCPGPluginSet`] and
/// [`crate::v1alpha1::MCPGRevocationList`].
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcpg.dev",
    version = "v1alpha1",
    kind = "MCPGGateway",
    plural = "mcpggateways",
    namespaced,
    status = "MCPGGatewayStatus",
    shortname = "mcpgw",
    derive = "PartialEq",
    derive = "Default",
    printcolumn = r#"{"name":"Image","type":"string","jsonPath":".spec.image.tag"}"#,
    printcolumn = r#"{"name":"Replicas","type":"integer","jsonPath":".spec.replicas"}"#,
    printcolumn = r#"{"name":"Plugins","type":"string","jsonPath":".spec.pluginSetRef.name"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Available","type":"string","jsonPath":".status.conditions[?(@.type=='Available')].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct MCPGGatewaySpec {
    pub image: GatewayImage,

    #[serde(default = "default_replicas")]
    pub replicas: i32,

    #[schemars(schema_with = "crate::schema_helpers::preserve_object")]
    pub config: serde_json::Value,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<GatewayResourceRequirements>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<GatewayService>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<GatewayIngress>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_pull_secrets: Vec<LocalObjectReference>,

    /// Secrets in the gateway's namespace projected into the gateway
    /// container as `envFrom`, in list order; every key becomes an
    /// environment variable. Later sources win on collision per
    /// Kubernetes `envFrom` semantics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_from_secrets: Vec<LocalObjectReference>,

    /// Secrets in the gateway's namespace mounted read-only into the
    /// gateway container, one file per key under `mountPath`. Unlike
    /// `envFromSecrets`, a mounted Secret follows the object: kubelet
    /// rewrites the files when the Secret changes, so a value the gateway
    /// reads from disk (`${secret.NAME}`) can rotate without a pod restart.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_mounts: Vec<SecretMount>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<GatewayWorkloadIdentity>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduling: Option<GatewayScheduling>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes: Option<GatewayProbes>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_policy: Option<GatewayNetworkPolicy>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_disruption_budget: Option<PodDisruptionBudgetSpec>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autoscaling: Option<HorizontalAutoscaler>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring: Option<GatewayMonitoring>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pod_annotations: BTreeMap<String, String>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pod_labels: BTreeMap<String, String>,

    // ── Plugin-lifecycle references ──────────────────────────
    /// Reference to a `MCPGPluginSet` in the same namespace.
    /// When set, the gateway pod's projected volume includes the
    /// resolved per-plugin Secrets, and `plugins[]` in the
    /// rendered config is sourced from the set. Optional —
    /// gateways without a plugin set boot with whatever lives in
    /// `spec.config.plugins[]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_set_ref: Option<PluginSetRef>,

    /// Reference to a cluster-scoped `MCPGRevocationList`. Defaults
    /// to the operator's `cluster-default` resource when unset.
    /// The operator materialises the revocation list into the
    /// gateway's namespace and mounts it; gateway pods enforce
    /// at plugin-load time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_list_ref: Option<RevocationListRef>,

    /// Reference to a cluster-scoped `MCPGCluster`. When set, the
    /// operator renders that backend's `cluster:` config block into
    /// this gateway's config (and folds the cluster's config-hash
    /// into the pod-roll trigger), so every replica binds the same
    /// coordinator. When unset the gateway runs `single_node`
    /// (in-process) — correct only for a single replica.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_ref: Option<ClusterRef>,

    /// Soft-tenancy allow-list: namespaces permitted to attach an
    /// `MCPGRoute` to this gateway. A route in a namespace NOT listed
    /// here is rejected at admission (and ignored by the route
    /// controller). Empty/unset ⇒ this gateway accepts no external
    /// routes (routes in the gateway's own namespace are always
    /// allowed). This is the platform team's explicit opt-in to which
    /// tenant namespaces may share the gateway.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_route_namespaces: Vec<String>,

    /// Managed-fleet (mcpg.cloud) routing + identity. Present only on
    /// Cloud-provisioned gateways; absent for self-host, where a CR renders
    /// byte-identical to before. Consumed by the deploy-spine HTTPRoute
    /// renderer + the resource-metadata injector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<GatewayCloud>,
}

fn default_replicas() -> i32 {
    1
}

impl MCPGGatewaySpec {
    /// The maximum replica count this gateway can actually reach, plus the
    /// spec path responsible for it (for error messages). When autoscaling is
    /// enabled the HPA's upper bound is the real ceiling — the rendered
    /// Deployment drops its static `replicas`, and the `maxReplicas`
    /// defaulting here mirrors the operator's HPA renderer — otherwise the
    /// static `spec.replicas`. Shared by the admission guards and the
    /// multi-replica child renderers (PDB, topology spread) so "is this
    /// gateway multi-replica?" has one answer.
    pub fn effective_replica_ceiling(&self) -> (i32, &'static str) {
        match self.autoscaling.as_ref().filter(|a| a.enabled) {
            Some(a) => {
                let min = a.min_replicas.unwrap_or(1).max(1);
                let max = a
                    .max_replicas
                    .unwrap_or_else(|| self.replicas.max(min))
                    .max(min);
                (max, "spec.autoscaling.maxReplicas")
            }
            None => (self.replicas, "spec.replicas"),
        }
    }
}

/// Managed-fleet routing + identity (host-per-instance). Inert when absent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayCloud {
    /// Tenant/org slug — billing + console grouping.
    pub org_slug: String,
    /// Globally-unique instance slug — the public DNS label addressing the
    /// gateway at `{instanceSlug}.mcpg.cloud/mcp`. Drives the HTTPRoute host
    /// match + per-instance resource naming.
    pub instance_slug: String,
    /// Canonical external URL (`https://{instanceSlug}.mcpg.cloud/mcp`). The
    /// operator injects this into `governance.access.resource_metadata.resource`
    /// so OAuth resource-indicator validation works; never trusted from a
    /// published config.
    pub external_url: String,
    /// Additional customer-owned hostnames (CNAME -> the instance edge); each
    /// gets its own HTTPRoute host match + TLS certificate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_domains: Vec<String>,
}

// ── Plugin-lifecycle reference types ────────────────────────

/// Same-namespace reference to a `MCPGPluginSet`. Cross-namespace
/// plugin sets are deliberately not supported — set-to-gateway
/// scoping is what gives the operator a clean tenancy boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PluginSetRef {
    /// `MCPGPluginSet` resource name, in the same namespace as
    /// the gateway.
    pub name: String,
}

/// Reference to a cluster-scoped `MCPGRevocationList`. Multiple
/// gateways can point at the same list; the operator fans the
/// resolved list out into each consumer namespace.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RevocationListRef {
    /// Cluster-scoped `MCPGRevocationList` resource name.
    pub name: String,
}

/// Reference to a cluster-scoped `MCPGCluster`. Multiple gateways
/// (across namespaces) can bind the same coordinator.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterRef {
    /// Cluster-scoped `MCPGCluster` resource name.
    pub name: String,
}

/// Generic name + optional namespace reference. Used for fields
/// that can either default to the parent CRD's namespace or
/// reach into another (e.g. when admins want a shared
/// configuration object).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NamespacedReference {
    pub name: String,
    /// Defaults to the parent CRD's namespace when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

// ── Sub-shapes ──────────────────────────────────────────────

/// Container image coordinates for the rendered gateway pod.
/// All three fields default at reconcile time — `repository`
/// from operator config, `tag` from the chart's appVersion,
/// `pullPolicy` to `IfNotPresent`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayImage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_policy: Option<String>,
}

/// Maps directly to `core/v1.ResourceRequirements`. We carry our
/// own type rather than depending on `k8s-openapi` here because
/// `operator-api` is `k8s-openapi`-version-agnostic — see the
/// crate-level docs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayResourceRequirements {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub requests: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub limits: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayService {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayIngress {
    pub ingress_class_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<GatewayIngressHost>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls: Vec<GatewayIngressTls>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayIngressHost {
    pub host: String,
    pub paths: Vec<GatewayIngressPath>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayIngressPath {
    pub path: String,
    pub path_type: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayIngressTls {
    pub hosts: Vec<String>,
    pub secret_name: String,
}

/// One-of: pick exactly one cloud provider. The operator
/// translates the chosen variant into the right ServiceAccount
/// annotations / projected-volume mounts at render time.
/// Multiple variants set simultaneously is an admission error.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayWorkloadIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws: Option<AwsWorkloadIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp: Option<GcpWorkloadIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure: Option<AzureWorkloadIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe: Option<SpiffeWorkloadIdentity>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AwsWorkloadIdentity {
    pub iam_role_arn: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GcpWorkloadIdentity {
    pub google_service_account: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AzureWorkloadIdentity {
    pub client_id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SpiffeWorkloadIdentity {
    pub trust_domain: String,
    pub svid: String,
}

/// Pod-scheduling pass-through fields. Each maps directly to
/// the matching `PodSpec` field; the operator does not interpret
/// them. `tolerations` and `affinity` are
/// `x-kubernetes-preserve-unknown-fields` so we don't have to
/// version-shift the operator's `k8s-openapi` dependency every
/// time upstream adds a knob.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayScheduling {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub node_selector: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(schema_with = "crate::schema_helpers::preserve_array_of_objects")]
    pub tolerations: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::schema_helpers::preserve_object")]
    pub affinity: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub topology_spread_constraints: Vec<TopologySpread>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_class_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termination_grace_period_seconds: Option<i64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TopologySpread {
    pub max_skew: i32,
    pub topology_key: String,
    pub when_unsatisfiable: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub label_selector_match_labels: BTreeMap<String, String>,
}

/// Optional per-probe overrides. When `None`, the operator's
/// rendered Deployment uses the chart defaults (which target
/// `/healthz` + `/readyz` on the management port).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayProbes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness: Option<GatewayProbe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<GatewayProbe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup: Option<GatewayProbe>,
}

/// Per-probe knobs. Maps directly to `core/v1.Probe` minus the
/// handler — handler is always HTTP GET on the management port
/// for the gateway (see the rendered Deployment template).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayProbe {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_delay_seconds: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_seconds: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_threshold: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success_threshold: Option<i32>,
}

/// Toggles whether the operator renders a NetworkPolicy alongside
/// the gateway Deployment. The default policy denies all
/// ingress/egress except the gateway listen port +
/// management traffic; `extraIngressFrom` / `extraEgressTo`
/// supply caller-specific exceptions (e.g. database egress).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayNetworkPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(schema_with = "crate::schema_helpers::preserve_array_of_objects")]
    pub extra_ingress_from: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(schema_with = "crate::schema_helpers::preserve_array_of_objects")]
    pub extra_egress_to: Vec<serde_json::Value>,
}

/// Wraps `policy/v1.PodDisruptionBudgetSpec`. Both threshold
/// fields are int-or-string to mirror the upstream API; pass
/// either `"50%"` or `2`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PodDisruptionBudgetSpec {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::schema_helpers::int_or_string")]
    pub min_available: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::schema_helpers::int_or_string")]
    pub max_unavailable: Option<serde_json::Value>,
}

/// Optional HPA shape. When `enabled = true` the operator renders
/// an `autoscaling/v2.HorizontalPodAutoscaler` targeting the
/// gateway Deployment. Disabled by default — `replicas` is the
/// canonical knob for most users.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HorizontalAutoscaler {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_replicas: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_replicas: Option<i32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<HorizontalAutoscalerMetric>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HorizontalAutoscalerMetric {
    pub r#type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::schema_helpers::preserve_object")]
    pub resource: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::schema_helpers::preserve_object")]
    pub pods: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::schema_helpers::preserve_object")]
    pub object: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::schema_helpers::preserve_object")]
    pub external: Option<serde_json::Value>,
}

/// Toggles ServiceMonitor + PrometheusRule rendering. Both
/// require the cluster to have the Prometheus Operator CRDs
/// installed; the operator will skip rendering if the API
/// group is absent (and surface a degraded status).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayMonitoring {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_monitor: Option<ServiceMonitorSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prometheus_rule: Option<PrometheusRuleSpec>,
}

/// Knobs for the rendered ServiceMonitor. `interval` /
/// `scrapeTimeout` follow Prometheus duration syntax (`30s`,
/// `1m`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceMonitorSpec {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrape_timeout: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// Knobs for the rendered PrometheusRule. `severity` is
/// stamped on every alert in the rendered group; defaults to
/// `warning`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PrometheusRuleSpec {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

/// A Secret mounted as files: `name` is the Secret, `mountPath` the
/// directory the container sees its keys under (one file per key).
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretMount {
    pub name: String,
    pub mount_path: String,
}

/// Same shape as `core/v1.LocalObjectReference`. Used wherever
/// the spec needs to point at another in-namespace resource —
/// imagePullSecrets, plugin refs, etc.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LocalObjectReference {
    pub name: String,
}

// ── Status ──────────────────────────────────────────────────

/// Observed state for `MCPGGateway`. `conditions` is the
/// authoritative readiness signal; the hash fields let
/// operators verify "the right plugin set / revocation list
/// has actually been folded in".
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MCPGGatewayStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_replicas: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_replicas: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available_replicas: Option<i32>,

    /// SHA-256 of the rendered config — flips on any spec change
    /// that propagates to the pod template. Operators watch this
    /// to confirm "operator has applied my edit".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,

    /// Resolved hash of the active `MCPGPluginSet` — non-null when
    /// `spec.pluginSetRef` is set + the set is `Ready`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_set_hash: Option<String>,

    /// Hash of the active `MCPGRevocationList`'s materialised
    /// content. Lets operators verify "every gateway is on the
    /// same revocation rev" cluster-wide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_list_hash: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_time: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn crd_metadata_has_v1alpha1() {
        let crd = MCPGGateway::crd();
        assert_eq!(crd.spec.group, "mcpg.dev");
        assert!(
            crd.spec.versions.iter().any(|v| v.name == "v1alpha1"),
            "expected v1alpha1 in {:?}",
            crd.spec
                .versions
                .iter()
                .map(|v| &v.name)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn plugin_set_ref_optional_in_yaml() {
        let yaml = "image: {}\nconfig: null\n";
        let s: MCPGGatewaySpec = serde_yaml::from_str(yaml).unwrap();
        assert!(s.plugin_set_ref.is_none());
    }

    fn ceiling_spec(replicas: i32, autoscaling: Option<HorizontalAutoscaler>) -> MCPGGatewaySpec {
        MCPGGatewaySpec {
            replicas,
            autoscaling,
            ..Default::default()
        }
    }

    #[test]
    fn ceiling_is_static_replicas_without_autoscaling() {
        let (c, f) = ceiling_spec(3, None).effective_replica_ceiling();
        assert_eq!((c, f), (3, "spec.replicas"));
        // Disabled autoscaling falls back to static replicas too.
        let (c, f) = ceiling_spec(
            3,
            Some(HorizontalAutoscaler {
                enabled: false,
                max_replicas: Some(99),
                ..Default::default()
            }),
        )
        .effective_replica_ceiling();
        assert_eq!((c, f), (3, "spec.replicas"));
    }

    #[test]
    fn ceiling_is_hpa_max_when_autoscaling_enabled() {
        // The HPA ceiling — not the static replicas — is what bounds a cap.
        let (c, f) = ceiling_spec(
            1,
            Some(HorizontalAutoscaler {
                enabled: true,
                min_replicas: Some(2),
                max_replicas: Some(20),
                ..Default::default()
            }),
        )
        .effective_replica_ceiling();
        assert_eq!((c, f), (20, "spec.autoscaling.maxReplicas"));
    }

    #[test]
    fn hpa_ceiling_defaults_like_the_renderer_when_max_omitted() {
        // max omitted → max(replicas, min); here replicas=4, min=2 → 4.
        let (c, _) = ceiling_spec(
            4,
            Some(HorizontalAutoscaler {
                enabled: true,
                min_replicas: Some(2),
                max_replicas: None,
                ..Default::default()
            }),
        )
        .effective_replica_ceiling();
        assert_eq!(c, 4);
    }

    #[test]
    fn plugin_set_ref_serialises_when_set() {
        let s = MCPGGatewaySpec {
            image: GatewayImage::default(),
            replicas: 1,
            config: serde_json::Value::Null,
            plugin_set_ref: Some(PluginSetRef {
                name: "payments-plugins".into(),
            }),
            ..Default::default()
        };
        let yaml = serde_yaml::to_string(&s).unwrap();
        assert!(yaml.contains("pluginSetRef:"), "got: {yaml}");
        assert!(yaml.contains("payments-plugins"), "got: {yaml}");
    }

    #[test]
    fn env_from_secrets_defaults_empty_in_yaml() {
        let yaml = "image: {}\nconfig: null\n";
        let s: MCPGGatewaySpec = serde_yaml::from_str(yaml).unwrap();
        assert!(s.env_from_secrets.is_empty());
        // Empty list is elided on the way back out.
        let out = serde_yaml::to_string(&s).unwrap();
        assert!(!out.contains("envFromSecrets"), "got: {out}");
    }

    #[test]
    fn env_from_secrets_roundtrips_in_order() {
        let s = MCPGGatewaySpec {
            image: GatewayImage::default(),
            replicas: 1,
            config: serde_json::Value::Null,
            env_from_secrets: vec![
                LocalObjectReference {
                    name: "mcpg-cluster-coordination".into(),
                },
                LocalObjectReference {
                    name: "tenant-extra-env".into(),
                },
            ],
            ..Default::default()
        };
        let yaml = serde_yaml::to_string(&s).unwrap();
        assert!(yaml.contains("envFromSecrets:"), "got: {yaml}");
        let back: MCPGGatewaySpec = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.env_from_secrets, s.env_from_secrets);
        assert_eq!(back.env_from_secrets[0].name, "mcpg-cluster-coordination");
        assert_eq!(back.env_from_secrets[1].name, "tenant-extra-env");
    }
}
