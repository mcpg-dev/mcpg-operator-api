//! `MCPGCluster` v1alpha1 — cluster-scoped coordination-backend
//! binding. One `MCPGCluster` describes a shared cluster
//! coordinator (Redis / NATS-JetStream / Consul / etcd, or the
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
use crate::v1alpha1::gateway::LocalObjectReference;

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
    /// HashiCorp Consul (`dev.mcpg.cluster.consul`).
    Consul,
    /// etcd v3 (`dev.mcpg.cluster.etcd`).
    Etcd,
}

impl ClusterBackend {
    /// The `kind:` string the gateway's `ClusterConfig` expects.
    pub fn config_kind(self) -> &'static str {
        match self {
            Self::SingleNode => "single_node",
            Self::Redis => "redis",
            Self::Nats => "nats",
            Self::Consul => "consul",
            Self::Etcd => "etcd",
        }
    }

    /// The cluster cdylib plugin id the gateway must load for this
    /// backend, or `None` for the built-in `single_node` coordinator.
    pub fn plugin_id(self) -> Option<&'static str> {
        match self {
            Self::SingleNode => None,
            Self::Redis => Some("dev.mcpg.cluster.redis"),
            Self::Nats => Some("dev.mcpg.cluster.nats"),
            Self::Consul => Some("dev.mcpg.cluster.consul"),
            Self::Etcd => Some("dev.mcpg.cluster.etcd"),
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

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl MCPGClusterSpec {
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
    /// (scheme tests trim leading whitespace; etcd treats anything not
    /// `https://` as plaintext).
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
            ClusterBackend::Consul => self
                .config
                .get("address")
                .and_then(serde_json::Value::as_str)
                .filter(|a| a.trim_start().starts_with("http://"))
                .map(|_| {
                    "the consul `address` uses the plaintext `http://` scheme (use `https://`)"
                        .to_owned()
                }),
            ClusterBackend::Etcd => self
                .config
                .get("endpoints")
                .and_then(serde_json::Value::as_array)
                .filter(|eps| {
                    eps.iter()
                        .filter_map(serde_json::Value::as_str)
                        .any(|e| !e.trim_start().starts_with("https://"))
                })
                .map(|_| {
                    "an etcd `endpoint` is not an `https://` URL (a plaintext `http://` or \
                     scheme-less `host:port` endpoint connects in clear; use `https://`)"
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
        for b in [
            ClusterBackend::Redis,
            ClusterBackend::Nats,
            ClusterBackend::Consul,
            ClusterBackend::Etcd,
        ] {
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
}
