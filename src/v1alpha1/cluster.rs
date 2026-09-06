//! `MCPGCluster` v1alpha1 — cluster-scoped coordination-backend
//! binding. One `MCPGCluster` describes a shared cluster
//! coordinator (Redis / NATS-JetStream, or the
//! in-process `single_node` default) that one or more
//! `MCPGGateway`s bind to via `spec.clusterRef`.
//!
//! ## Why a CRD (vs. inline `spec.config.cluster`)
//!
//! A multi-replica gateway needs a shared coordinator for sessions,
//! leases, pub/sub and idempotency state. Putting the coordinator
//! config inline on every gateway means (a) duplicating the backend
//! address/credentials across N gateways and (b) no single place to
//! see "which gateways share a cluster." `MCPGCluster` centralises
//! that: the operator renders the backend's `cluster:` block **and**
//! ensures the matching `dev.mcpg.cluster.<kind>` cdylib entry is
//! present in the gateway's plugin list, so a gateway author only
//! writes `clusterRef: { name: prod-cluster }`.
//!
//! ## Relationship to the gateway's own config schema
//!
//! The rendered output is the gateway's
//! [`ClusterConfig`](https://docs/configuration.md) shape:
//! `cluster: { kind: <backend>, <flattened per-kind fields> }`. The
//! operator is otherwise schema-blind — the gateway's
//! `validate_config_pre_boot` remains the source of truth for the
//! per-kind fields, so new backend knobs don't force an operator
//! release.
//!
//! Cluster-scoped (like [`MCPGRevocationList`]): a coordinator is
//! shared infrastructure, and gateways in different namespaces
//! routinely bind the same backend.
//!
//! [`MCPGRevocationList`]: crate::v1alpha1::MCPGRevocationList
//! [`ClusterConfig`]: https://mcpg.dev/docs/gateway/clustering

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::conditions::Condition;
use crate::v1alpha1::gateway::{GatewayResourceRequirements, LocalObjectReference};

/// Env var (projected from the generated coordination Secret) whose value
/// is the state-encryption key. The managed `cluster:` block names it in
/// `state_encryption_key_env`. Matches the Helm chart's convention.
pub const MANAGED_STATE_KEY_ENV: &str = "MCPG_CLUSTER_STATE_KEY";

/// Env var (projected from the generated coordination Secret) carrying the
/// NATS auth token. The managed block references it as
/// `auth.token: ${env.MCPG_CLUSTER_NATS_TOKEN}` and the provisioned NATS
/// server reads the same value into its `authorization.token`.
pub const MANAGED_NATS_TOKEN_ENV: &str = "MCPG_CLUSTER_NATS_TOKEN";

/// Env var (projected from the generated coordination Secret) carrying the
/// coordinator CA certificate PEM, filled by the controller from the
/// cert-manager-issued Secret. The managed TLS block references it as
/// `tls.ca_cert: ${env.MCPG_CLUSTER_NATS_CA}`; the gateway's config-load
/// substitution inlines the PEM, which the nats plugin trusts as its root.
pub const MANAGED_NATS_CA_ENV: &str = "MCPG_CLUSTER_NATS_CA";

/// Downward-API env var the operator always stamps on gateway pods
/// (`metadata.name`). The managed block uses it as the per-replica
/// coordinator `node.id` (`node.id: ${env.POD_NAME}`) — a pod name is a
/// valid single NATS subject token (only `[a-z0-9-]`).
pub const MANAGED_NODE_ID_ENV: &str = "POD_NAME";

/// Pinned default NATS server image for a managed coordinator. Mirrors the
/// version the platform/gateway Helm charts vendor
/// (`helm/charts/mcpg/charts/nats`, appVersion 2.10.25).
pub const DEFAULT_MANAGED_NATS_IMAGE: &str = "nats:2.10.25-alpine";

/// Default JetStream file-store PVC size for a managed coordinator.
pub const DEFAULT_MANAGED_STORAGE_SIZE: &str = "10Gi";

/// The NATS client port the provisioned Service exposes and gateways dial.
pub const MANAGED_NATS_CLIENT_PORT: i32 = 4222;

/// Client Service name for a managed coordinator — the FQDN gateways dial.
pub fn managed_nats_service_name(cluster: &str) -> String {
    format!("{cluster}-nats")
}
/// Headless Service name (StatefulSet stable network identity + JetStream).
pub fn managed_nats_headless_service_name(cluster: &str) -> String {
    format!("{cluster}-nats-headless")
}
/// StatefulSet name for a managed coordinator.
pub fn managed_nats_statefulset_name(cluster: &str) -> String {
    format!("{cluster}-nats")
}
/// ConfigMap name holding the rendered `nats-server.conf`.
pub fn managed_nats_config_name(cluster: &str) -> String {
    format!("{cluster}-nats-config")
}
/// cert-manager `Certificate` + its issued TLS Secret name.
pub fn managed_nats_tls_secret_name(cluster: &str) -> String {
    format!("{cluster}-nats-tls")
}
/// Generated coordination Secret (NATS token + state key [+ CA]) — the
/// source lives in the operator namespace; the gateway controller copies
/// it into each bound gateway's namespace for `envFrom` projection.
pub fn managed_coordination_secret_name(cluster: &str) -> String {
    format!("{cluster}-coordination")
}

/// Supported cluster-coordination backends. Mirrors the gateway's
/// `ClusterConfig::plugin_id` mapping — keep the two in sync when a
/// new backend ships.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClusterBackend {
    /// In-process coordinator. No external dependency, no cdylib;
    /// suitable only for single-replica gateways. The default.
    #[default]
    SingleNode,
    /// Redis / Valkey (`dev.mcpg.cluster.redis`).
    Redis,
    /// NATS JetStream (`dev.mcpg.cluster.nats`).
    Nats,
}

impl ClusterBackend {
    /// The `kind:` string the gateway's `ClusterConfig` expects.
    pub fn config_kind(self) -> &'static str {
        match self {
            Self::SingleNode => "single_node",
            Self::Redis => "redis",
            Self::Nats => "nats",
        }
    }

    /// The cluster cdylib plugin id the gateway must load for this
    /// backend, or `None` for the built-in `single_node` coordinator.
    pub fn plugin_id(self) -> Option<&'static str> {
        match self {
            Self::SingleNode => None,
            Self::Redis => Some("dev.mcpg.cluster.redis"),
            Self::Nats => Some("dev.mcpg.cluster.nats"),
        }
    }

    /// True for the in-process default (no external backend, no
    /// cdylib, not valid for multi-replica gateways).
    pub fn is_single_node(self) -> bool {
        matches!(self, Self::SingleNode)
    }
}

/// Cluster-coordination backend binding.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcpg.dev",
    version = "v1alpha1",
    kind = "MCPGCluster",
    plural = "mcpgclusters",
    derive = "PartialEq",
    derive = "Default",
    status = "MCPGClusterStatus",
    shortname = "mcpgc",
    printcolumn = r#"{"name":"Backend","type":"string","jsonPath":".spec.backend"}"#,
    printcolumn = r#"{"name":"Gateways","type":"integer","jsonPath":".status.boundGateways"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
/// Cluster-scoped coordination-backend binding. Gateways reference
/// it via `spec.clusterRef`; the operator injects the rendered
/// `cluster:` config block (and the matching cluster cdylib entry)
/// into each bound gateway's config.
#[serde(rename_all = "camelCase")]
pub struct MCPGClusterSpec {
    /// Which coordination backend this cluster provides.
    #[serde(default)]
    pub backend: ClusterBackend,

    /// Per-backend configuration, rendered verbatim into the
    /// gateway's `cluster:` block alongside `kind:` (the gateway
    /// flattens these — e.g. `url`, `key_prefix` for redis;
    /// `servers`, `bucket` for nats). Schema-blind: the gateway's
    /// own validator is the source of truth. Ignored for
    /// `single_node`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, serde_json::Value>,

    /// Optional reference to the cluster cdylib's OCI source via a
    /// cluster-scoped `MCPGPlugin`. When set, the operator requires
    /// the named plugin to be `Ready` (verified + not revoked)
    /// before binding — so a coordinator can't come up against an
    /// unverified cluster plugin. When unset, the operator assumes
    /// the gateway's `pluginSetRef` already supplies the
    /// `dev.mcpg.cluster.<backend>` cdylib and only renders the
    /// `cluster:` config block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_ref: Option<LocalObjectReference>,

    /// Optional secret references whose keys are surfaced to the
    /// gateway as `${cluster.<key>}` config-substitution values —
    /// e.g. a Redis password or NATS credentials file. The operator
    /// projects these into the gateway pod the same way plugin
    /// Secrets are projected; the gateway resolves the `cred://`
    /// reference at config-load time. Keeps backend credentials out
    /// of the (world-readable) `MCPGCluster` spec.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_refs: Vec<ClusterCredentialRef>,

    /// Managed coordinator: when set, the operator PROVISIONS the NATS
    /// coordinator itself (StatefulSet + Services + generated
    /// credentials) instead of the caller pointing `backend`/`config`
    /// at an existing one. `backend` is then implicitly `nats` and the
    /// `cluster:` block is operator-generated — admission rejects a
    /// spec that also sets `backend`/`config` alongside `managed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed: Option<ManagedCoordinator>,
}

/// A self-provisioned NATS JetStream coordinator. Present ⇒ the cluster
/// controller renders and owns the NATS StatefulSet + Services + a
/// generated token/state-key Secret in the operator namespace, and the
/// injected `cluster:` block points bound gateways at the rendered
/// Service. Single managed NATS + token auth is the v1 posture (no
/// per-tenant NATS accounts).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedCoordinator {
    /// NATS server image. Defaults to [`DEFAULT_MANAGED_NATS_IMAGE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// JetStream file-store volume knobs (the coordinator keeps lease /
    /// KV / stream state on this PVC).
    #[serde(default)]
    pub storage: ManagedStorage,

    /// Optional in-cluster TLS via cert-manager. With an `issuerRef` the
    /// controller renders a `Certificate`, the NATS server terminates
    /// TLS, and the injected block sets `require_tls: true` + carries the
    /// CA. Without it the coordinator is plaintext in-cluster and the
    /// block sets `allow_insecure_transport: true` (a warning is
    /// surfaced).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<ManagedCoordinatorTls>,

    /// NATS replica count. v1 supports single-node JetStream only: any
    /// value is CAPPED at 1 when rendering the StatefulSet (clustered
    /// NATS quorum config is out of scope), with a warning event when a
    /// larger value is requested. The field is retained for forward
    /// compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<u8>,

    /// Resource requests/limits for the NATS container. Defaults to a
    /// modest request when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<GatewayResourceRequirements>,
}

/// JetStream file-store volume knobs for a managed coordinator.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedStorage {
    /// PVC size (`volumeClaimTemplate`). Defaults to
    /// [`DEFAULT_MANAGED_STORAGE_SIZE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    /// StorageClass for the PVC. Unset ⇒ the cluster default class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class_name: Option<String>,
}

/// Managed-coordinator TLS configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedCoordinatorTls {
    /// cert-manager issuer the controller points the NATS server
    /// `Certificate` at. Unset ⇒ plaintext in-cluster coordinator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_ref: Option<ManagedIssuerRef>,
}

/// Reference to a cert-manager `Issuer` / `ClusterIssuer`. Mirrors
/// cert-manager's own `issuerRef` shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedIssuerRef {
    /// Issuer resource name.
    pub name: String,
    /// `Issuer` (namespaced, in the operator namespace) or
    /// `ClusterIssuer`. Defaults to `Issuer`.
    #[serde(default = "default_issuer_kind")]
    pub kind: String,
    /// API group. Defaults to `cert-manager.io`.
    #[serde(default = "default_issuer_group")]
    pub group: String,
}

impl Default for ManagedIssuerRef {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: default_issuer_kind(),
            group: default_issuer_group(),
        }
    }
}

fn default_issuer_kind() -> String {
    "Issuer".to_owned()
}
fn default_issuer_group() -> String {
    "cert-manager.io".to_owned()
}

/// A backend credential projected into bound gateway pods. The
/// `secretName` lives in the operator's namespace (same trust
/// boundary as plugin signing keys); `key` selects the entry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterCredentialRef {
    /// Logical name the gateway config references (e.g. `password`).
    /// Surfaced as `cred://cluster/<name>` to the gateway.
    pub name: String,
    /// Secret name in the operator namespace.
    pub secret_name: String,
    /// Key within the Secret. Defaults to `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// Observed state for `MCPGCluster`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MCPGClusterStatus {
    /// Standard `metav1.Condition[]`. The operator sets `Ready=True`
    /// when the backend is bindable (plugin verified when
    /// `pluginRef` is set; always for `single_node`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// The resolved cluster cdylib plugin id (`None`/absent for
    /// `single_node`). Surfaced so ops can confirm the backend
    /// mapping without reading the spec enum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<String>,

    /// Count of `MCPGGateway`s currently bound to this cluster via
    /// `spec.clusterRef`. Lets ops see blast radius before editing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_gateways: Option<i64>,

    /// SHA-256 of the rendered `cluster:` config block. Bound
    /// gateways fold this into their pod-roll hash, so a cluster
    /// config edit rolls every bound gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,

    /// True once the operator provisioned the managed NATS coordinator
    /// (generated Secret present + StatefulSet has its ready replica).
    /// Absent for a point-at-existing (non-managed) cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_ready: Option<bool>,

    /// Ready replicas of the provisioned NATS StatefulSet. Absent for a
    /// non-managed cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nats_ready_replicas: Option<i32>,

    /// Name of the generated coordination Secret (NATS token + state
    /// key [+ CA]) in the operator namespace. Absent for a non-managed
    /// cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordination_secret: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl MCPGClusterSpec {
    /// The backend this cluster effectively provides. A `managed`
    /// coordinator is always NATS regardless of the (rejected-at-
    /// admission) `backend` field, so every readiness / bindability /
    /// single-node check keys off this, not the raw enum.
    pub fn effective_backend(&self) -> ClusterBackend {
        if self.managed.is_some() {
            ClusterBackend::Nats
        } else {
            self.backend
        }
    }

    /// True when this cluster resolves to the in-process `single_node`
    /// coordinator (never for a managed cluster).
    pub fn is_effectively_single_node(&self) -> bool {
        self.effective_backend().is_single_node()
    }

    /// Rendered StatefulSet replica count for a managed coordinator,
    /// capped at 1 (v1 renders single-node JetStream only). `None` when
    /// not managed.
    pub fn managed_nats_replicas(&self) -> Option<i32> {
        self.managed
            .as_ref()
            .map(|m| m.replicas.unwrap_or(1).clamp(1, 1) as i32)
    }

    /// True when a managed coordinator requested more replicas than v1
    /// renders (the controller caps at 1 and warns).
    pub fn managed_replicas_capped(&self) -> bool {
        self.managed
            .as_ref()
            .and_then(|m| m.replicas)
            .is_some_and(|r| r > 1)
    }

    /// True when a managed coordinator asks for cert-manager TLS.
    pub fn managed_tls_enabled(&self) -> bool {
        self.managed
            .as_ref()
            .and_then(|m| m.tls.as_ref())
            .and_then(|t| t.issuer_ref.as_ref())
            .is_some_and(|r| !r.name.trim().is_empty())
    }

    /// Render the `cluster:` block, dispatching to the managed renderer
    /// when a coordinator is provisioned. `cluster_name` +
    /// `operator_namespace` derive the provisioned Service FQDN; both are
    /// ignored for the point-at-existing (non-managed) path.
    pub fn render_cluster_block_with(
        &self,
        cluster_name: &str,
        operator_namespace: &str,
    ) -> serde_json::Value {
        if self.managed.is_some() {
            self.render_managed_cluster_block(cluster_name, operator_namespace)
        } else {
            self.render_cluster_block()
        }
    }

    /// Render the operator-generated `cluster:` block for a managed NATS
    /// coordinator. Pure: the token / state-key / CA are delivered by env
    /// (`${env.*}`, projected from the generated Secret), and the
    /// per-replica `node.id` is the gateway pod name — so the block is a
    /// function of the spec + naming alone. TLS (issuerRef set) sets
    /// `require_tls: true` + an env-delivered CA; plaintext sets
    /// `allow_insecure_transport: true`.
    pub fn render_managed_cluster_block(
        &self,
        cluster_name: &str,
        operator_namespace: &str,
    ) -> serde_json::Value {
        let tls = self.managed_tls_enabled();
        let scheme = if tls { "tls" } else { "nats" };
        let fqdn = format!(
            "{scheme}://{}.{operator_namespace}.svc.cluster.local:{MANAGED_NATS_CLIENT_PORT}",
            managed_nats_service_name(cluster_name),
        );
        let mut map = serde_json::Map::new();
        map.insert("kind".to_owned(), serde_json::json!("nats"));
        map.insert("servers".to_owned(), serde_json::json!([fqdn]));
        map.insert(
            "state_encryption_key_env".to_owned(),
            serde_json::json!(MANAGED_STATE_KEY_ENV),
        );
        map.insert(
            "auth".to_owned(),
            serde_json::json!({
                "method": "token",
                "token": format!("${{env.{MANAGED_NATS_TOKEN_ENV}}}"),
            }),
        );
        map.insert(
            "node".to_owned(),
            serde_json::json!({ "id": format!("${{env.{MANAGED_NODE_ID_ENV}}}") }),
        );
        // Single-node JetStream file store (the StatefulSet's PVC).
        map.insert(
            "jetstream".to_owned(),
            serde_json::json!({ "replicas": 1, "storage": "file" }),
        );
        if tls {
            map.insert(
                "tls".to_owned(),
                serde_json::json!({
                    "require_tls": true,
                    "ca_cert": format!("${{env.{MANAGED_NATS_CA_ENV}}}"),
                }),
            );
        } else {
            // Plaintext in-cluster: relax the gateway transport guard and
            // the nats plugin's TLS-by-default requirement.
            map.insert(
                "allow_insecure_transport".to_owned(),
                serde_json::json!(true),
            );
            map.insert(
                "tls".to_owned(),
                serde_json::json!({ "require_tls": false }),
            );
        }
        serde_json::Value::Object(map)
    }

    /// Render the gateway `cluster:` config block this cluster maps
    /// to: `{ "kind": <backend>, <flattened per-kind config> }`.
    /// Used by both the cluster controller (hash) and the gateway
    /// controller (config merge), so the two never diverge.
    pub fn render_cluster_block(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "kind".to_owned(),
            serde_json::Value::String(self.backend.config_kind().to_owned()),
        );
        if !self.backend.is_single_node() {
            for (k, v) in &self.config {
                map.insert(k.clone(), v.clone());
            }
        }
        serde_json::Value::Object(map)
    }

    /// Mirror of the gateway's `ClusterConfig::validate_transport_security`
    /// for the operator plane: a non-`single_node` coordinator over a
    /// plaintext transport should be rejected at admission so the operator
    /// surfaces a clear error instead of CrashLooping the bound gateway pods.
    /// Returns `Some(reason)` when the rendered coordinator would be plaintext
    /// and the `allow_insecure_transport: true` opt-out is NOT present in
    /// `spec.config`. Per-kind classification matches the gateway guard
    /// (scheme tests trim leading whitespace).
    pub fn insecure_transport_reason(&self) -> Option<String> {
        if self.backend.is_single_node() {
            return None;
        }
        let opted_out = self
            .config
            .get("allow_insecure_transport")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if opted_out {
            return None;
        }
        match self.backend {
            ClusterBackend::Redis => self
                .config
                .get("url")
                .and_then(serde_json::Value::as_str)
                .filter(|u| u.trim_start().starts_with("redis://"))
                .map(|_| {
                    "the redis `url` uses the plaintext `redis://` scheme (use `rediss://`)"
                        .to_owned()
                }),
            ClusterBackend::Nats => self
                .config
                .get("tls")
                .and_then(|t| t.get("require_tls"))
                .and_then(serde_json::Value::as_bool)
                .filter(|require_tls| !require_tls)
                .map(|_| "nats `tls.require_tls` is set to `false` (plaintext)".to_owned()),
            ClusterBackend::SingleNode => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn crd_metadata_correct() {
        let crd = MCPGCluster::crd();
        assert_eq!(crd.spec.group, "mcpg.dev");
        assert_eq!(crd.spec.scope, "Cluster");
        assert_eq!(crd.spec.names.kind, "MCPGCluster");
        assert_eq!(crd.spec.names.plural, "mcpgclusters");
    }

    #[test]
    fn backend_defaults_to_single_node() {
        let spec: MCPGClusterSpec = serde_yaml::from_str("{}").unwrap();
        assert_eq!(spec.backend, ClusterBackend::SingleNode);
        assert!(spec.backend.is_single_node());
        assert_eq!(spec.backend.plugin_id(), None);
    }

    #[test]
    fn backend_serialises_snake_case() {
        let spec: MCPGClusterSpec =
            serde_yaml::from_str("backend: redis\nconfig:\n  url: redis://r:6379\n").unwrap();
        assert_eq!(spec.backend, ClusterBackend::Redis);
        assert_eq!(spec.backend.config_kind(), "redis");
        assert_eq!(spec.backend.plugin_id(), Some("dev.mcpg.cluster.redis"));
        let yaml = serde_yaml::to_string(&spec).unwrap();
        assert!(yaml.contains("backend: redis"), "got: {yaml}");
    }

    #[test]
    fn render_cluster_block_flattens_config() {
        let spec: MCPGClusterSpec = serde_yaml::from_str(
            "backend: redis\nconfig:\n  url: redis://r:6379\n  keyPrefix: mcpg\n",
        )
        .unwrap();
        let block = spec.render_cluster_block();
        assert_eq!(block["kind"], "redis");
        assert_eq!(block["url"], "redis://r:6379");
        // keys pass through verbatim (gateway validates casing).
        assert_eq!(block["keyPrefix"], "mcpg");
    }

    #[test]
    fn render_cluster_block_single_node_drops_config() {
        // single_node ignores any stray config — the gateway's
        // built-in coordinator takes no params.
        let spec = MCPGClusterSpec {
            backend: ClusterBackend::SingleNode,
            config: {
                let mut m = BTreeMap::new();
                m.insert("url".to_owned(), serde_json::json!("ignored"));
                m
            },
            plugin_ref: None,
            credential_refs: vec![],
            managed: None,
        };
        let block = spec.render_cluster_block();
        assert_eq!(block["kind"], "single_node");
        assert!(
            block.get("url").is_none(),
            "single_node must not carry config"
        );
    }

    #[test]
    fn all_backends_map_to_a_kind_and_plugin() {
        for b in [ClusterBackend::Redis, ClusterBackend::Nats] {
            assert!(!b.config_kind().is_empty());
            assert!(b.plugin_id().is_some(), "{b:?} must have a cdylib id");
            assert!(!b.is_single_node());
        }
    }

    #[test]
    fn credential_ref_camel_case() {
        let cr = ClusterCredentialRef {
            name: "password".into(),
            secret_name: "redis-creds".into(),
            key: None,
        };
        let yaml = serde_yaml::to_string(&cr).unwrap();
        assert!(yaml.contains("secretName:"), "got: {yaml}");
    }

    fn managed_spec() -> MCPGClusterSpec {
        serde_yaml::from_str("managed: {}\n").unwrap()
    }

    #[test]
    fn managed_defaults_backend_to_nats() {
        let spec = managed_spec();
        // The raw enum stays at its serde default; the effective backend
        // is NATS so single-node checks never reject a managed cluster.
        assert_eq!(spec.backend, ClusterBackend::SingleNode);
        assert_eq!(spec.effective_backend(), ClusterBackend::Nats);
        assert!(!spec.is_effectively_single_node());
        assert_eq!(
            spec.effective_backend().plugin_id(),
            Some("dev.mcpg.cluster.nats")
        );
    }

    #[test]
    fn managed_block_plaintext_shape() {
        let block = managed_spec().render_managed_cluster_block("prod", "mcpg-system");
        assert_eq!(block["kind"], "nats");
        assert_eq!(
            block["servers"][0],
            "nats://prod-nats.mcpg-system.svc.cluster.local:4222"
        );
        assert_eq!(block["state_encryption_key_env"], "MCPG_CLUSTER_STATE_KEY");
        assert_eq!(block["auth"]["method"], "token");
        assert_eq!(block["auth"]["token"], "${env.MCPG_CLUSTER_NATS_TOKEN}");
        assert_eq!(block["node"]["id"], "${env.POD_NAME}");
        assert_eq!(block["jetstream"]["storage"], "file");
        // Plaintext in-cluster: transport guard relaxed, no CA.
        assert_eq!(block["allow_insecure_transport"], true);
        assert_eq!(block["tls"]["require_tls"], false);
        assert!(block["tls"].get("ca_cert").is_none());
    }

    #[test]
    fn managed_block_tls_shape() {
        let spec: MCPGClusterSpec =
            serde_yaml::from_str("managed:\n  tls:\n    issuerRef:\n      name: mcpg-internal\n")
                .unwrap();
        assert!(spec.managed_tls_enabled());
        let block = spec.render_managed_cluster_block("prod", "mcpg-system");
        assert_eq!(
            block["servers"][0],
            "tls://prod-nats.mcpg-system.svc.cluster.local:4222"
        );
        assert_eq!(block["tls"]["require_tls"], true);
        // CA delivered via env so the block stays pure; the gateway's
        // config-load substitution inlines the PEM.
        assert_eq!(block["tls"]["ca_cert"], "${env.MCPG_CLUSTER_NATS_CA}");
        assert!(block.get("allow_insecure_transport").is_none());
    }

    #[test]
    fn managed_block_flattens_to_valid_nats_plugin_config() {
        // The flattened block (minus the gateway-only named fields) must be
        // the shape the nats cluster plugin accepts: servers + node.id +
        // token auth + jetstream. Guards the operator/plugin contract.
        let block = managed_spec().render_managed_cluster_block("c", "mcpg-system");
        let obj = block.as_object().unwrap();
        assert!(obj.contains_key("servers"));
        assert_eq!(block["node"]["id"], "${env.POD_NAME}");
        assert_eq!(block["auth"]["method"], "token");
    }

    #[test]
    fn managed_replicas_capped_at_one() {
        let spec: MCPGClusterSpec = serde_yaml::from_str("managed:\n  replicas: 3\n").unwrap();
        assert_eq!(spec.managed_nats_replicas(), Some(1));
        assert!(spec.managed_replicas_capped());
        let single: MCPGClusterSpec = serde_yaml::from_str("managed: {}\n").unwrap();
        assert_eq!(single.managed_nats_replicas(), Some(1));
        assert!(!single.managed_replicas_capped());
        // Non-managed → no managed replica count.
        let plain: MCPGClusterSpec = serde_yaml::from_str("backend: single_node\n").unwrap();
        assert_eq!(plain.managed_nats_replicas(), None);
    }

    #[test]
    fn render_dispatches_on_managed() {
        // Non-managed goes through the flatten path…
        let plain: MCPGClusterSpec =
            serde_yaml::from_str("backend: redis\nconfig:\n  url: rediss://r:6379\n").unwrap();
        assert_eq!(
            plain.render_cluster_block_with("x", "mcpg-system")["kind"],
            "redis"
        );
        // …managed goes through the generated-nats path.
        assert_eq!(
            managed_spec().render_cluster_block_with("x", "mcpg-system")["kind"],
            "nats"
        );
    }

    #[test]
    fn managed_naming_helpers() {
        assert_eq!(managed_nats_service_name("prod"), "prod-nats");
        assert_eq!(
            managed_nats_headless_service_name("prod"),
            "prod-nats-headless"
        );
        assert_eq!(managed_nats_config_name("prod"), "prod-nats-config");
        assert_eq!(managed_nats_tls_secret_name("prod"), "prod-nats-tls");
        assert_eq!(
            managed_coordination_secret_name("prod"),
            "prod-coordination"
        );
    }

    #[test]
    fn managed_field_optional_in_yaml() {
        let spec: MCPGClusterSpec = serde_yaml::from_str("backend: single_node\n").unwrap();
        assert!(spec.managed.is_none());
        let out = serde_yaml::to_string(&spec).unwrap();
        assert!(!out.contains("managed"), "got: {out}");
    }
}
