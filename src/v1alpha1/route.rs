//! `MCPGRoute` v1alpha1 — soft-multi-tenancy routing into a shared
//! `MCPGGateway`. One `MCPGRoute` lets a tenant team, from their own
//! namespace, declare which tools they expose through a gateway owned
//! by the platform team, plus the identity / policy / audit chains and
//! per-tenant attributes that apply to those tools.
//!
//! ## Tenancy model
//!
//! - **Hard tenancy** = one `MCPGGateway` per tenant (full process
//!   isolation, higher cost). No `MCPGRoute` needed.
//! - **Soft tenancy** = one shared `MCPGGateway`; each tenant owns an
//!   `MCPGRoute` (cheaper, shared pod/process). This CRD is the soft
//!   path. `MCPGRoute` is the **only** CRD permitted to reference a
//!   gateway in another namespace (the platform team's
//!   shared-gateway namespace), and only when that gateway opts in via
//!   [`MCPGGatewaySpec::accepted_route_namespaces`].
//!
//! ## What the shared gateway can actually enforce today
//!
//! The gateway is "one config, one catalog, identity-filtered" — it has
//! no per-route chain-dispatch engine. So the operator fans a route's
//! `match.tools` + `attributes` into the gateway's
//! `governance.policy.tool_access.rules[]` as **tenant-scoped tool
//! access rules** (a CEL predicate binding each tool to the tenant's
//! identity attribute). That is enforceable today and is exactly the
//! multi-tenant pattern the gateway docs recommend.
//!
//! The `identityChain` / `policyChain` / `auditChain` fields are
//! **validated** (every named plugin must exist in the gateway's
//! plugin set) and recorded, but **per-route chain dispatch is not yet
//! enforced by the gateway runtime** — a route can't today swap the
//! identity/policy/audit chain on a per-tool basis. The route
//! controller surfaces this honestly via the `ChainsEnforced`
//! condition (`False`, reason `PerRouteDispatchUnsupported`) so an
//! operator is never misled into thinking a chain override is active
//! when it isn't. Closing that gap is a gateway-core change:
//! per-request route context → chain selection.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::conditions::Condition;

/// Per-tenant route into a shared gateway.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcpg.dev",
    version = "v1alpha1",
    kind = "MCPGRoute",
    namespaced,
    plural = "mcpgroutes",
    derive = "PartialEq",
    derive = "Default",
    status = "MCPGRouteStatus",
    shortname = "mcpgr",
    printcolumn = r#"{"name":"Gateway","type":"string","jsonPath":".spec.gatewayRef.name"}"#,
    printcolumn = r#"{"name":"Tools","type":"integer","jsonPath":".status.matchedTools"}"#,
    printcolumn = r#"{"name":"Bound","type":"string","jsonPath":".status.conditions[?(@.type=='GatewayBound')].status"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
/// Namespace-scoped route binding a tenant's tools to a shared
/// gateway, with the identity / policy / audit chains and per-tenant
/// attributes that govern them.
#[serde(rename_all = "camelCase")]
pub struct MCPGRouteSpec {
    /// The gateway this route attaches to. For soft tenancy this is a
    /// cross-namespace reference to the platform team's shared gateway;
    /// the gateway must list this route's namespace in
    /// `spec.acceptedRouteNamespaces`.
    pub gateway_ref: GatewayRef,

    /// Which tools this route exposes through the gateway. Each matched
    /// tool gets a tenant-scoped access rule rendered into the
    /// gateway's `governance.policy.tool_access.rules[]`.
    pub r#match: RouteMatch,

    /// Ordered identity-plugin ids that should authenticate requests on
    /// this route. **Validated** against the gateway's plugin set;
    /// per-route dispatch is not yet enforced by the gateway runtime
    /// (see the module docs + the `ChainsEnforced` status condition).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_chain: Vec<String>,

    /// Ordered policy-engine plugin ids for this route. Same
    /// validation + enforcement caveat as `identityChain`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_chain: Vec<String>,

    /// Ordered audit-sink plugin ids for this route. Same validation +
    /// enforcement caveat as `identityChain`. (The shared gateway's
    /// audit sink may template `attributes` into its output — e.g. a
    /// per-tenant Kafka topic — which IS enforceable today.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_chain: Vec<String>,

    /// Per-tenant metadata. `attributes.tenant` is special: it's the
    /// identity attribute the rendered tool-access CEL rules key on
    /// (`$identity.attributes.tenant == "<value>"`), so the shared
    /// gateway only exposes this route's tools to that tenant's
    /// callers. All attributes are also available to audit sinks for
    /// per-tenant labelling.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

/// Reference to the gateway a route attaches to. `namespace` is
/// required for the soft-tenancy cross-namespace case and may be
/// omitted only when the route lives in the gateway's own namespace.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayRef {
    /// `MCPGGateway` resource name.
    pub name: String,
    /// Gateway namespace. Defaults to the route's own namespace when
    /// unset; soft tenancy sets this to the shared-gateway namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// What a route selects on. Today: a list of tool capability ids. (A
/// future revision may add path / header selectors; the gateway's
/// catalog is keyed by tool id, so id-matching is what's enforceable
/// now.)
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteMatch {
    /// Tools this route exposes. Each must correspond to a binding the
    /// gateway actually serves (validated at admission).
    #[serde(default)]
    pub tools: Vec<RouteToolRef>,
}

/// A single tool a route exposes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteToolRef {
    /// Tool capability id (e.g. `orders.list`).
    pub id: String,
}

/// Observed state for `MCPGRoute`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MCPGRouteStatus {
    /// Standard `metav1.Condition[]`. Notable types:
    /// - `Ready` — route accepted + tool-access rules rendered.
    /// - `GatewayBound` — the referenced gateway exists and accepts
    ///   this route's namespace.
    /// - `ChainsEnforced` — `True` only if the gateway runtime applies
    ///   the route's identity/policy/audit chains per-route. Today this
    ///   is `False` (reason `PerRouteDispatchUnsupported`): the chains
    ///   are validated but not dispatched per-route. The tool-access
    ///   scoping in `Ready` still applies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Number of `match.tools` entries the operator rendered into the
    /// gateway's tool-access policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_tools: Option<i64>,

    /// The resolved `<namespace>/<name>` of the bound gateway. Lets ops
    /// see the cross-namespace binding without parsing the ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_gateway: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl MCPGRouteSpec {
    /// The tenant key these tools are scoped to — `attributes.tenant`
    /// when set, else `None` (an un-scoped route exposes its tools to
    /// any caller the gateway already admits, which the validator
    /// warns about).
    pub fn tenant(&self) -> Option<&str> {
        self.attributes.get("tenant").map(String::as_str)
    }

    /// Resolve the bound gateway namespace, defaulting to the route's
    /// own namespace when `gatewayRef.namespace` is unset.
    pub fn gateway_namespace<'a>(&'a self, route_namespace: &'a str) -> &'a str {
        self.gateway_ref
            .namespace
            .as_deref()
            .unwrap_or(route_namespace)
    }

    /// Every distinct plugin id named across the three chains — the set
    /// the route controller checks against the gateway's plugin set.
    pub fn all_chain_plugins(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self
            .identity_chain
            .iter()
            .chain(&self.policy_chain)
            .chain(&self.audit_chain)
            .map(String::as_str)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    fn sample_yaml() -> &'static str {
        // A representative shared-gateway route spec.
        r#"
gatewayRef:
  name: shared-gateway
  namespace: shared-gateway
match:
  tools:
    - id: orders.list
    - id: orders.get
    - id: orders.create
identityChain:
  - dev.mcpg.identity.workload
policyChain:
  - dev.mcpg.policy.cedar
auditChain:
  - dev.mcpg.builtin.audit
attributes:
  tenant: payments
  region: us-east-1
"#
    }

    #[test]
    fn crd_metadata_correct() {
        let crd = MCPGRoute::crd();
        assert_eq!(crd.spec.group, "mcpg.dev");
        assert_eq!(crd.spec.scope, "Namespaced");
        assert_eq!(crd.spec.names.kind, "MCPGRoute");
        assert_eq!(crd.spec.names.plural, "mcpgroutes");
    }

    #[test]
    fn parses_soft_tenancy_example_shape() {
        let spec: MCPGRouteSpec = serde_yaml::from_str(sample_yaml()).unwrap();
        assert_eq!(spec.gateway_ref.name, "shared-gateway");
        assert_eq!(
            spec.gateway_ref.namespace.as_deref(),
            Some("shared-gateway")
        );
        assert_eq!(spec.r#match.tools.len(), 3);
        assert_eq!(spec.r#match.tools[0].id, "orders.list");
        assert_eq!(spec.identity_chain, vec!["dev.mcpg.identity.workload"]);
        assert_eq!(spec.tenant(), Some("payments"));
    }

    #[test]
    fn match_renders_camel_case() {
        let spec: MCPGRouteSpec = serde_yaml::from_str(sample_yaml()).unwrap();
        let v = serde_json::to_value(&spec).unwrap();
        // `match` is a reserved word; serde rename keeps the wire key.
        assert!(v.get("match").is_some(), "got: {v}");
        assert_eq!(v["gatewayRef"]["name"], "shared-gateway");
        assert_eq!(v["identityChain"][0], "dev.mcpg.identity.workload");
    }

    #[test]
    fn gateway_namespace_defaults_to_route_namespace() {
        let spec = MCPGRouteSpec {
            gateway_ref: GatewayRef {
                name: "g".into(),
                namespace: None,
            },
            ..Default::default()
        };
        assert_eq!(spec.gateway_namespace("my-ns"), "my-ns");
        let spec2 = MCPGRouteSpec {
            gateway_ref: GatewayRef {
                name: "g".into(),
                namespace: Some("shared".into()),
            },
            ..Default::default()
        };
        assert_eq!(spec2.gateway_namespace("my-ns"), "shared");
    }

    #[test]
    fn all_chain_plugins_dedups_across_chains() {
        let spec = MCPGRouteSpec {
            identity_chain: vec!["a".into(), "shared".into()],
            policy_chain: vec!["b".into()],
            audit_chain: vec!["shared".into(), "c".into()],
            ..Default::default()
        };
        assert_eq!(spec.all_chain_plugins(), vec!["a", "b", "c", "shared"]);
    }

    #[test]
    fn tenant_none_when_attribute_absent() {
        let spec = MCPGRouteSpec::default();
        assert_eq!(spec.tenant(), None);
    }
}
