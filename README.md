# mcpg-operator-api

> Rust types for the `mcpg.dev` Custom Resource Definitions served by the MCPG Kubernetes operator.

This crate is the schema half of the MCPG operator: the `CustomResource`-derived
Rust structs for every `mcpg.dev/v1alpha1` kind, the shared status-condition
vocabulary they all use, and the `schemars` helpers that make their generated
OpenAPI schemas acceptable to the Kubernetes apiserver. It deliberately contains
no controllers, no reconcile logic, and no `kube::Client` usage — those live in
the `mcpg-operator` binary crate, and so does CRD YAML generation, which needs a
concrete `k8s-openapi` Kubernetes version this library refuses to pin. Depend on
this crate when you want to construct, read, or validate MCPG custom resources
from your own Rust code: a GitOps templating tool, an integration-test harness,
or a controller of your own that watches gateways.

## What's here

The group is `mcpg.dev` (exported as `API_GROUP`) and `v1alpha1` is the storage
version. Being pre-1.0, breaking spec changes are applied in place rather than
minting a new API version, and there is no conversion webhook.

- `v1alpha1` — one module per kind, each re-exporting the CRD root, its `Spec`,
  its `Status`, and the supporting field types:

  | Kind | Scope | Short name | Module |
  |---|---|---|---|
  | `MCPGGateway` | Namespaced | `mcpgw` | `v1alpha1::gateway` |
  | `MCPGPluginSet` | Namespaced | `mcpgps` | `v1alpha1::plugin_set` |
  | `MCPGRoute` | Namespaced | `mcpgr` | `v1alpha1::route` |
  | `MCPGServer` | Namespaced | `mcpgs` | `v1alpha1::server` |
  | `MCPGPlugin` | Cluster | `mcpgp` | `v1alpha1::plugin` |
  | `MCPGCluster` | Cluster | `mcpgc` | `v1alpha1::cluster` |
  | `MCPGRevocationList` | Cluster | `mcpgrl` | `v1alpha1::revocation_list` |
  | `MCPGPluginMirror` | Cluster | `mcpgm` | `v1alpha1::plugin_mirror` |
  | `MCPGTenant` | Cluster | `mcpgt` | `v1alpha1::tenant` |

- `conditions` — `Condition`, whose serde shape matches `metav1.Condition`
  exactly so `kubectl`, Kustomize, and Argo CD interpret it correctly; the
  `Condition::ready_true` / `Condition::ready_false` constructors;
  `set_condition`, which updates in place and preserves `lastTransitionTime`
  when the status has not changed; and the stable string vocabularies in
  `conditions::types` (`Ready`, `Reconciling`, `Degraded`, `Progressing`,
  `Available`, `Failed`) and `conditions::reasons` (`Reconciled`,
  `DependencyPending`, `PermanentError`, and peers).
- `schema_helpers` — `preserve_object`, `preserve_array_of_objects`, and
  `int_or_string`, applied through `#[schemars(schema_with = "…")]` to fields
  whose inner shape the apiserver must not try to validate.
  `MCPGGateway.spec.config` is one of them: it carries the gateway's own boot
  config, whose schema lives with the gateway, not here.
- Top-level constants: `API_GROUP`, `CLUSTER_DEFAULT_REVOCATION_LIST` — the
  cluster-scoped `MCPGRevocationList` the operator treats as authoritative — and
  `DEFAULT_OPERATOR_NAMESPACE`.

## Used by

- `mcpg-operator` — the operator binary. Its controllers, admission validators,
  and reconcilers are written against these types, and its `crdgen` binary turns
  them into the CRD YAML the Helm chart ships.
- Third-party Rust clients that construct or read MCPG custom resources
  programmatically: GitOps templating, integration-test harnesses, and
  cluster-inventory tooling.

## Usage

```toml
[dependencies]
mcpg-operator-api = "<version>"
kube = { version = "3", features = ["client", "runtime", "derive"] }
# This crate declares k8s-openapi without a version feature on purpose —
# your binary crate chooses the Kubernetes version.
k8s-openapi = { version = "0.27", features = ["v1_32"] }
```

```rust
use kube::{Api, Client};
use mcpg_operator_api::conditions::types::READY;
use mcpg_operator_api::v1alpha1::MCPGGateway;

/// Names of the gateways in `namespace` whose status reports `Ready=True`.
pub async fn ready_gateways(client: Client, namespace: &str) -> kube::Result<Vec<String>> {
    let api: Api<MCPGGateway> = Api::namespaced(client, namespace);
    let mut ready = Vec::new();

    for gateway in api.list(&Default::default()).await? {
        let is_ready = gateway.status.as_ref().is_some_and(|status| {
            status
                .conditions
                .iter()
                .any(|c| c.r#type == READY && c.status == "True")
        });
        if is_ready {
            ready.push(gateway.metadata.name.clone().unwrap_or_default());
        }
    }

    Ok(ready)
}
```

Every kind carries `status.conditions[]` in the same shape, so `Ready=True`
polling is generic across all nine.

## Build / test

The crate is Rust edition 2024, so it needs a toolchain that supports it.
`k8s-openapi` needs a Kubernetes version chosen by the top-level crate — select
one when building this library on its own:

```bash
K8S_OPENAPI_ENABLED_VERSION=1.32 cargo build -p mcpg-operator-api
cargo test -p mcpg-operator-api
```

The tests pin `v1_32` through a dev-dependency, so they need no environment
variable.

CRD YAML is generated from these types by the operator crate, which supplies the
concrete `k8s-openapi` version:

```bash
# One stream of every CRD to stdout:
cargo run -p mcpg-operator --bin crdgen

# One file per kind, written to a directory:
cargo run -p mcpg-operator --bin crdgen -- --split-by-kind helm/charts/mcpg-operator/crds/
```

To add a kind, declare it under `src/v1alpha1/` with
`#[derive(CustomResource, Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]`,
re-export it from `src/v1alpha1/mod.rs`, and add it to the emit list in the
operator's `crdgen` binary.

## Licence

BUSL-1.1. See [LICENSE](LICENSE).

## See also

- <https://mcpg.dev/docs/reference/operator-crds> — field-level reference for
  every kind in this crate.
- <https://mcpg.dev/docs/self-hosting/kubernetes-operator> — how the operator
  consumes these resources.
- <https://mcpg.dev/docs/reference/configuration> — the gateway config schema
  that `MCPGGateway.spec.config` carries.
