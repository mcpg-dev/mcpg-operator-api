//! `MCPGPluginMirror` v1alpha1 — in-cluster OCI mirror declaration
//! for air-gapped plugin pulls.
//!
//! An air-gapped cluster can't reach `ghcr.io`. The sync station
//! pre-mirrors plugin artefacts into an in-cluster registry (Harbor /
//! Quay / `distribution`), and an `MCPGPluginMirror` tells the operator
//! how to **rewrite** an upstream OCI reference onto that mirror. A
//! `MCPGPlugin` opts in by setting `spec.oci.mirrorRef`; the operator
//! then pulls from the mirror instead of the public registry — and
//! never falls back to the public registry (fail-closed).
//!
//! ## What it is (and isn't)
//!
//! It is a **rewrite rule + endpoint descriptor**, not the registry
//! itself (Harbor runs separately) and not a pull-through cache
//! (images must be pre-mirrored by the sync station). Given an
//! upstream ref:
//!
//! ```text
//! ghcr.io/mcpg-dev/source-code/plugins/identity-workload:1.2.3@sha256:abcd…
//! ```
//!
//! and a mirror with `upstream {registry: ghcr.io, namespace:
//! mcpg-dev/source-code}`, `endpoint.service {namespace: oci-mirror,
//! name: harbor, port: 80, pathPrefix: /v2/mirror}`, the operator
//! rewrites it to:
//!
//! ```text
//! harbor.oci-mirror.svc.cluster.local:80/v2/mirror/plugins/identity-workload:1.2.3@sha256:abcd…
//! ```
//!
//! The **tag and `@sha256:` digest pin are preserved** — so the
//! content-addressed identity the operator verifies (Ed25519 / cosign /
//! SLSA) is unchanged by the rewrite. cosign cert-identity + SLSA
//! source-URI checks still validate against the **upstream** repo (the
//! attestation is bound to where it was built, not where it's served
//! from), so a mirror can't launder an unsigned artefact.
//!
//! Cluster-scoped (like [`MCPGCluster`]): a mirror is shared
//! infrastructure that plugins in any namespace reference.
//!
//! [`MCPGCluster`]: crate::v1alpha1::MCPGCluster

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::conditions::Condition;

/// In-cluster OCI mirror for air-gapped plugin pulls.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "mcpg.dev",
    version = "v1alpha1",
    kind = "MCPGPluginMirror",
    plural = "mcpgpluginmirrors",
    derive = "PartialEq",
    derive = "Default",
    status = "MCPGPluginMirrorStatus",
    shortname = "mcpgm",
    printcolumn = r#"{"name":"Upstream","type":"string","jsonPath":".spec.upstream.registry"}"#,
    printcolumn = r#"{"name":"Reachable","type":"string","jsonPath":".status.reachable"}"#,
    printcolumn = r#"{"name":"Proxied","type":"integer","jsonPath":".status.proxiedReferences"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
/// Cluster-scoped OCI mirror. `MCPGPlugin.spec.oci.mirrorRef` points
/// here; the operator rewrites the upstream ref onto this mirror's
/// endpoint before pulling.
#[serde(rename_all = "camelCase")]
pub struct MCPGPluginMirrorSpec {
    /// Where the mirror registry lives in-cluster.
    pub endpoint: MirrorEndpoint,

    /// The public registry + namespace this mirror stands in for. Only
    /// plugin refs whose `image` starts with `<registry>/<namespace>`
    /// are rewritten; a ref pointing elsewhere is left untouched (and
    /// the air-gap admission gate, when enforced, rejects it).
    pub upstream: MirrorUpstream,

    /// Optional pull credentials for the mirror (a
    /// `kubernetes.io/dockerconfigjson` Secret in the operator
    /// namespace). When set, the operator pulls from the mirror with
    /// these instead of the plugin's own `oci.pullSecretRef`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<MirrorAuth>,

    /// Optional reachability re-check cadence (informational; e.g.
    /// `1h`). The operator re-reconciles the mirror on its normal
    /// resync regardless — this is a hint for future scheduled probes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resync_interval: Option<String>,
}

/// In-cluster Service hosting the mirror registry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MirrorEndpoint {
    pub service: MirrorService,
    /// When true, the operator treats the mirror as plain-HTTP /
    /// self-signed (added to the OCI client's insecure-registry list).
    /// In-cluster mirrors on `:80` are the common case.
    #[serde(default)]
    pub insecure: bool,
}

/// Service coordinates for the mirror registry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MirrorService {
    pub namespace: String,
    pub name: String,
    /// Service port the registry listens on (e.g. `80`).
    pub port: u16,
    /// Optional path prefix the mirror serves repositories under
    /// (e.g. `/v2/mirror`). Joined between the registry host and the
    /// upstream repository path. Leading/trailing slashes are
    /// normalised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
}

impl MirrorService {
    /// The in-cluster registry host (`<name>.<namespace>.svc.cluster.local:<port>`).
    pub fn host(&self) -> String {
        format!(
            "{}.{}.svc.cluster.local:{}",
            self.name, self.namespace, self.port
        )
    }
}

/// The public registry + namespace a mirror stands in for.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MirrorUpstream {
    /// Registry hostname, e.g. `ghcr.io`.
    pub registry: String,
    /// Namespace/org path under the registry, e.g.
    /// `mcpg-dev/source-code`. The repository segment after this
    /// prefix is preserved verbatim on the mirror.
    ///
    /// MUST be the upstream reference's FULL path prefix — every segment
    /// between the registry host and the repository name. Multi-segment
    /// values are expected, and matching is a literal `starts_with` on
    /// `<registry>/<namespace>/`.
    ///
    /// A partial or stale value is not rejected: the rewrite reports
    /// "not applicable" and the pull falls through to the upstream
    /// registry, which in an air-gapped cluster fails with no pointer
    /// back to this field. Two ways to get it wrong:
    /// - Too short — `mcpg-dev` does NOT match
    ///   `ghcr.io/mcpg-dev/source-code/plugins/audit:1.0.0`; the value
    ///   has to be `mcpg-dev/source-code`.
    /// - Stale after an upstream move — publishing under a base with one
    ///   fewer path segment (`ghcr.io/mcpg-dev/plugins/audit`, four
    ///   segments instead of five) leaves every already-deployed
    ///   MCPGPluginMirror carrying the old `mcpg-dev/source-code` and
    ///   mirroring nothing. Such a move must update this field on every
    ///   MCPGPluginMirror in the cluster.
    pub namespace: String,
}

/// Mirror pull credentials.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MirrorAuth {
    pub secret_ref: MirrorSecretRef,
}

/// Reference to a `dockerconfigjson` Secret in the operator namespace.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MirrorSecretRef {
    pub secret_name: String,
    /// Key within the Secret. Defaults to `.dockerconfigjson` when
    /// unset (the standard key for `kubernetes.io/dockerconfigjson`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// Observed state for `MCPGPluginMirror`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MCPGPluginMirrorStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Whether the operator could reach the mirror's `/v2/` endpoint at
    /// last reconcile. `false` (with a `Ready=False` condition) means
    /// plugin pulls through this mirror will fail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,

    /// Count of `MCPGPlugin`s currently referencing this mirror via
    /// `oci.mirrorRef`. Blast-radius signal for ops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxied_references: Option<i64>,

    /// The resolved in-cluster registry host
    /// (`<name>.<namespace>.svc.cluster.local:<port>`), surfaced so ops
    /// can confirm the rewrite target without parsing the spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_host: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// Outcome of rewriting an upstream OCI ref through a mirror.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MirrorRewrite {
    /// The ref matched this mirror's upstream and was rewritten.
    Rewritten(String),
    /// The ref does not start with this mirror's `<registry>/<namespace>`
    /// — left untouched (the caller decides whether that's an error
    /// under air-gap enforcement).
    NotApplicable,
}

impl MCPGPluginMirrorSpec {
    /// Rewrite an upstream OCI `image` reference onto this mirror.
    ///
    /// Matches when `image` starts with `<upstream.registry>/<upstream.namespace>/`.
    /// The repository segment after that prefix — plus the `:tag` and/or
    /// `@sha256:digest` — is preserved and re-homed under the mirror
    /// host (+ optional pathPrefix). Returns [`MirrorRewrite::NotApplicable`]
    /// when the ref points at a different registry/namespace.
    ///
    /// Pure (no I/O) so the rewrite is unit-testable; the controller
    /// layers Secret resolution + the pull on top.
    pub fn rewrite(&self, image: &str) -> MirrorRewrite {
        let prefix = format!(
            "{}/{}/",
            self.upstream.registry.trim_end_matches('/'),
            self.upstream.namespace.trim_matches('/')
        );
        let Some(repo_and_ref) = image.strip_prefix(&prefix) else {
            return MirrorRewrite::NotApplicable;
        };

        let host = self.endpoint.service.host();
        let path = match self.endpoint.service.path_prefix.as_deref() {
            Some(p) => {
                let p = p.trim_matches('/');
                if p.is_empty() {
                    String::new()
                } else {
                    format!("/{p}")
                }
            }
            None => String::new(),
        };
        MirrorRewrite::Rewritten(format!("{host}{path}/{repo_and_ref}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    fn mirror(path_prefix: Option<&str>) -> MCPGPluginMirrorSpec {
        MCPGPluginMirrorSpec {
            endpoint: MirrorEndpoint {
                service: MirrorService {
                    namespace: "oci-mirror".into(),
                    name: "harbor".into(),
                    port: 80,
                    path_prefix: path_prefix.map(String::from),
                },
                insecure: true,
            },
            upstream: MirrorUpstream {
                registry: "ghcr.io".into(),
                namespace: "mcpg-dev/source-code".into(),
            },
            auth: None,
            resync_interval: None,
        }
    }

    #[test]
    fn crd_metadata_correct() {
        let crd = MCPGPluginMirror::crd();
        assert_eq!(crd.spec.group, "mcpg.dev");
        assert_eq!(crd.spec.scope, "Cluster");
        assert_eq!(crd.spec.names.kind, "MCPGPluginMirror");
        assert_eq!(crd.spec.names.plural, "mcpgpluginmirrors");
    }

    #[test]
    fn rewrite_preserves_repo_tag_and_digest() {
        let m = mirror(Some("/v2/mirror"));
        let out =
            m.rewrite("ghcr.io/mcpg-dev/source-code/plugins/identity-workload:1.2.3@sha256:abcd");
        assert_eq!(
            out,
            MirrorRewrite::Rewritten(
                "harbor.oci-mirror.svc.cluster.local:80/v2/mirror/plugins/identity-workload:1.2.3@sha256:abcd"
                    .into()
            )
        );
    }

    #[test]
    fn rewrite_without_path_prefix() {
        let m = mirror(None);
        let out = m.rewrite("ghcr.io/mcpg-dev/source-code/plugins/audit:0.1.0");
        assert_eq!(
            out,
            MirrorRewrite::Rewritten(
                "harbor.oci-mirror.svc.cluster.local:80/plugins/audit:0.1.0".into()
            )
        );
    }

    #[test]
    fn rewrite_normalises_path_prefix_slashes() {
        // Operator may write "v2/mirror/" or "/v2/mirror" — same result.
        for pp in ["v2/mirror", "/v2/mirror", "v2/mirror/", "/v2/mirror/"] {
            let m = mirror(Some(pp));
            let MirrorRewrite::Rewritten(out) = m.rewrite("ghcr.io/mcpg-dev/source-code/p/x:1")
            else {
                panic!("expected rewrite for {pp}");
            };
            assert_eq!(
                out, "harbor.oci-mirror.svc.cluster.local:80/v2/mirror/p/x:1",
                "path_prefix={pp}"
            );
        }
    }

    #[test]
    fn rewrite_not_applicable_for_other_registry() {
        let m = mirror(Some("/v2/mirror"));
        // Different registry.
        assert_eq!(
            m.rewrite("docker.io/library/redis:7"),
            MirrorRewrite::NotApplicable
        );
        // Same registry, different namespace.
        assert_eq!(
            m.rewrite("ghcr.io/other-org/plugins/x:1"),
            MirrorRewrite::NotApplicable
        );
    }

    #[test]
    fn host_is_cluster_local() {
        let m = mirror(None);
        assert_eq!(
            m.endpoint.service.host(),
            "harbor.oci-mirror.svc.cluster.local:80"
        );
    }

    #[test]
    fn spec_round_trips_documented_yaml() {
        let yaml = r#"
endpoint:
  service:
    namespace: oci-mirror
    name: harbor
    port: 80
    pathPrefix: /v2/mirror
  insecure: true
upstream:
  registry: ghcr.io
  namespace: mcpg-dev/source-code
auth:
  secretRef:
    secretName: mirror-pull
    key: .dockerconfigjson
resyncInterval: 1h
"#;
        let spec: MCPGPluginMirrorSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.upstream.registry, "ghcr.io");
        assert_eq!(spec.endpoint.service.port, 80);
        assert_eq!(
            spec.auth.as_ref().unwrap().secret_ref.secret_name,
            "mirror-pull"
        );
        assert_eq!(spec.resync_interval.as_deref(), Some("1h"));
    }
}
