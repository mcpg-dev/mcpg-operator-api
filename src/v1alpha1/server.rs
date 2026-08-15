//! `MCPGServer` v1alpha1 — an in-cluster MCP server workload the
//! operator provisions and (optionally) auto-federates into a gateway.
//!
//! The registry-sync feature federates servers that are already
//! reachable over HTTP. `MCPGServer` covers the other half of a
//! registry entry: **installable** servers (`packages[]` of type `oci`)
//! that must first run somewhere. One `MCPGServer` declares the
//! container image; the operator renders a Deployment + Service, and —
//! when `federate` is set — the gateway controller composes a
//! `mcp.federations[]` entry pointing at the Service, so the server's
//! tools appear in the gateway catalog with the same governance as any
//! other federation.
//!
//! ## Trust model
//!
//! The image is an operator-declared workload, not registry data: the
//! registry is a statement of existence, never a trust grant, so
//! nothing auto-creates `MCPGServer` objects from registry listings.
//! Optional `verify.cosignIdentity` gates reconcile on a cosign keyless
//! signature over the image (digest-pinned refs recommended).
//!
//! ## Federation scope
//!
//! `federate.gatewayRef` must point at a gateway in the **same
//! namespace** — a server workload is namespace-local infrastructure.
//! Cross-namespace exposure composes with `MCPGRoute` (soft tenancy)
//! on the gateway side.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::conditions::Condition;
use crate::v1alpha1::gateway::{GatewayResourceRequirements, LocalObjectReference};
use crate::v1alpha1::plugin::CosignIdentity;

/// In-cluster MCP server workload with optional gateway auto-federation.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcpg.dev",
    version = "v1alpha1",
    kind = "MCPGServer",
    namespaced,
    plural = "mcpgservers",
    derive = "PartialEq",
    derive = "Default",
    status = "MCPGServerStatus",
    shortname = "mcpgs",
    printcolumn = r#"{"name":"Image","type":"string","jsonPath":".spec.image"}"#,
    printcolumn = r#"{"name":"Gateway","type":"string","jsonPath":".spec.federate.gatewayRef.name"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
/// Namespace-scoped MCP server: the operator runs the container and,
/// when `federate` is set, the gateway imports its capabilities.
#[serde(rename_all = "camelCase")]
pub struct MCPGServerSpec {
    /// Container image serving MCP over streamable HTTP. Digest-pinned
    /// refs (`repo@sha256:…`) are strongly recommended; `verify`
    /// requires one.
    pub image: String,

    /// Replica count. Defaults to 1. MCP servers holding per-session
    /// state should stay at 1 unless they handle their own affinity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,

    /// Container port the MCP endpoint listens on. Defaults to 8080.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,

    /// HTTP path of the MCP endpoint. Defaults to `/mcp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Plain environment variables for the container. Secrets belong in
    /// `envFrom` Secrets referenced by name, not inline values.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,

    /// Secret names whose keys are injected as environment variables
    /// (`envFrom.secretRef`). The Secrets must live in the server's
    /// namespace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_from_secrets: Vec<String>,

    /// CPU/memory requests + limits for the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<GatewayResourceRequirements>,

    /// ServiceAccount the pod runs as. Defaults to the namespace
    /// default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_name: Option<String>,

    /// Pull secrets for private image registries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_pull_secrets: Vec<LocalObjectReference>,

    /// Cosign keyless verification of the image before the workload is
    /// (re)rendered. Requires a digest-pinned `image`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<ServerVerify>,

    /// Auto-federate this server into a gateway in the same namespace.
    /// Omitted = the workload runs but nothing imports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federate: Option<ServerFederate>,
}

/// Image verification posture.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerVerify {
    /// Cosign keyless identity (issuer + subject) the image signature
    /// must match.
    pub cosign_identity: CosignIdentity,
}

/// Gateway auto-federation for a provisioned server.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerFederate {
    /// The gateway that imports this server. Same-namespace only.
    pub gateway_ref: ServerGatewayRef,

    /// Federation name in the gateway config. Defaults to the
    /// `MCPGServer`'s own name. Operator-authored federations in the
    /// gateway's inline config win on collision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Tool-name prefix for the imported capabilities. Defaults to
    /// `<federation name>.`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_prefix: Option<String>,

    /// Raw `governance` block for the synthesized federation (trust
    /// floor + CEL), passed through schema-blind exactly like gateway
    /// `spec.config`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::schema_helpers::preserve_object")]
    pub governance: Option<serde_json::Value>,

    /// Raw `import` block (surface selection) for the synthesized
    /// federation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::schema_helpers::preserve_object")]
    pub import: Option<serde_json::Value>,

    /// Raw `upstream.auth` block for the synthesized federation (e.g.
    /// an `oauth_impersonation` + `cred://` reference).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::schema_helpers::preserve_object")]
    pub auth: Option<serde_json::Value>,
}

/// Same-namespace gateway reference.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerGatewayRef {
    /// `MCPGGateway` resource name in the server's namespace.
    pub name: String,
}

/// Observed state for `MCPGServer`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MCPGServerStatus {
    /// Standard `metav1.Condition[]`. Notable types:
    /// - `Ready` — Deployment reports the requested replicas ready.
    /// - `ImageVerified` — cosign verification outcome (only when
    ///   `spec.verify` is set; verification failure blocks rendering).
    /// - `GatewayBound` — `federate.gatewayRef` resolves to a gateway
    ///   in this namespace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Ready replicas reported by the Deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_replicas: Option<i32>,

    /// In-cluster MCP endpoint the gateway federates
    /// (`http://<svc>.<ns>.svc.cluster.local:<port><path>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// The bound gateway (`<namespace>/<name>`) when `federate` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_gateway: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl MCPGServerSpec {
    /// Effective replica count.
    pub fn replicas(&self) -> i32 {
        self.replicas.unwrap_or(1).max(0)
    }

    /// Effective container port.
    pub fn port(&self) -> i32 {
        self.port.unwrap_or(8080)
    }

    /// Effective MCP endpoint path (always `/`-prefixed).
    pub fn path(&self) -> String {
        let p = self.path.as_deref().unwrap_or("/mcp");
        if p.starts_with('/') {
            p.to_owned()
        } else {
            format!("/{p}")
        }
    }

    /// Federation name for `federate`, defaulting to the object name.
    pub fn federation_name<'a>(&'a self, object_name: &'a str) -> &'a str {
        self.federate
            .as_ref()
            .and_then(|f| f.name.as_deref())
            .unwrap_or(object_name)
    }

    /// In-cluster MCP endpoint URL for the rendered Service.
    pub fn endpoint(&self, service_name: &str, namespace: &str) -> String {
        format!(
            "http://{service_name}.{namespace}.svc.cluster.local:{}{}",
            self.port(),
            self.path()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    fn sample_yaml() -> &'static str {
        r#"
image: ghcr.io/acme/crm-mcp@sha256:1111111111111111111111111111111111111111111111111111111111111111
replicas: 2
port: 9000
path: mcp
env:
  LOG_LEVEL: info
envFromSecrets:
  - crm-mcp-secrets
federate:
  gatewayRef:
    name: main
  toolPrefix: "crm."
  governance:
    minimum_trust: verified
"#
    }

    #[test]
    fn crd_metadata_correct() {
        let crd = MCPGServer::crd();
        assert_eq!(crd.spec.group, "mcpg.dev");
        assert_eq!(crd.spec.scope, "Namespaced");
        assert_eq!(crd.spec.names.kind, "MCPGServer");
        assert_eq!(crd.spec.names.plural, "mcpgservers");
    }

    #[test]
    fn parses_example_shape_with_defaults() {
        let spec: MCPGServerSpec = serde_yaml::from_str(sample_yaml()).unwrap();
        assert_eq!(spec.replicas(), 2);
        assert_eq!(spec.port(), 9000);
        // A bare path is normalized to `/`-prefixed.
        assert_eq!(spec.path(), "/mcp");
        assert_eq!(spec.env_from_secrets, vec!["crm-mcp-secrets"]);
        let fed = spec.federate.as_ref().unwrap();
        assert_eq!(fed.gateway_ref.name, "main");
        assert_eq!(fed.tool_prefix.as_deref(), Some("crm."));
        assert_eq!(
            fed.governance.as_ref().unwrap()["minimum_trust"],
            "verified"
        );
        assert_eq!(spec.federation_name("crm"), "crm");
        assert_eq!(
            spec.endpoint("crm", "team-a"),
            "http://crm.team-a.svc.cluster.local:9000/mcp"
        );
    }

    #[test]
    fn minimal_spec_defaults() {
        let spec: MCPGServerSpec = serde_yaml::from_str("image: ghcr.io/acme/x:1.0.0\n").unwrap();
        assert_eq!(spec.replicas(), 1);
        assert_eq!(spec.port(), 8080);
        assert_eq!(spec.path(), "/mcp");
        assert!(spec.federate.is_none());
        assert!(spec.verify.is_none());
    }

    #[test]
    fn federation_name_override_wins() {
        let mut spec: MCPGServerSpec =
            serde_yaml::from_str("image: ghcr.io/acme/x:1.0.0\n").unwrap();
        spec.federate = Some(ServerFederate {
            gateway_ref: ServerGatewayRef {
                name: "main".into(),
            },
            name: Some("crm-prod".into()),
            ..Default::default()
        });
        assert_eq!(spec.federation_name("crm"), "crm-prod");
    }
}
