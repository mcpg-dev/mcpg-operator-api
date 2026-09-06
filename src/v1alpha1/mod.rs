//! `v1alpha1` types — the initial (and only) version of the operator
//! API. Pre-1.0 the schema evolves in place: breaking spec changes are
//! applied directly to `v1alpha1` rather than minting a new API
//! version, and there is no conversion webhook.
//!
//! Kinds:
//! - `MCPGGateway` — gateway Deployment/Service/ConfigMap, with
//!   `pluginSetRef`, `revocationListRef`, `clusterRef` wiring.
//! - `MCPGPlugin` (cluster-scoped) — single signed plugin artefact.
//! - `MCPGPluginSet` (namespace-scoped) — bundle of plugins.
//! - `MCPGRevocationList` (cluster-scoped) — plugin SHA-256 revocations.
//! - `MCPGCluster` (cluster-scoped) — coordination-backend binding.
//! - `MCPGRoute` (namespace-scoped) — soft-tenancy route into a
//!   shared gateway.
//! - `MCPGPluginMirror` (cluster-scoped) — in-cluster OCI mirror for
//!   air-gapped plugin pulls.
//! - `MCPGTenant` (cluster-scoped) — declarative tenant boundary
//!   (owned namespaces, plugin allowlist, quotas).
//! - `MCPGServer` (namespace-scoped) — in-cluster MCP server workload
//!   with optional gateway auto-federation.

pub mod cluster;
pub mod gateway;
pub mod plugin;
pub mod plugin_mirror;
pub mod plugin_set;
pub mod revocation_list;
pub mod route;
pub mod server;
pub mod tenant;

pub use gateway::{
    AwsWorkloadIdentity, AzureWorkloadIdentity, ClusterRef, GatewayCloud, GatewayImage,
    GatewayIngress, GatewayIngressHost, GatewayIngressPath, GatewayIngressTls, GatewayMonitoring,
    GatewayNetworkPolicy, GatewayProbe, GatewayProbes, GatewayResourceRequirements,
    GatewayScheduling, GatewayService, GatewayWorkloadIdentity, GcpWorkloadIdentity,
    HorizontalAutoscaler, HorizontalAutoscalerMetric, LocalObjectReference, MCPGGateway,
    MCPGGatewaySpec, MCPGGatewayStatus, NamespacedReference, PluginSetRef, PodDisruptionBudgetSpec,
    PrometheusRuleSpec, RevocationListRef, ServiceMonitorSpec, SpiffeWorkloadIdentity,
    TopologySpread,
};

pub use plugin::{
    CosignIdentity, MCPGPlugin, MCPGPluginSpec, MCPGPluginStatus, OciImageRef, PluginTrust,
    SigningKeyRef, SlsaProvenance,
};

pub use plugin_set::{
    CapabilityGrant, FailedEntry, MCPGPluginSet, MCPGPluginSetEntry, MCPGPluginSetSpec,
    MCPGPluginSetStatus,
};

pub use revocation_list::{
    MCPGRevocationList, MCPGRevocationListSpec, MCPGRevocationListStatus, RevocationEntry,
};

pub use cluster::{
    ClusterBackend, ClusterCredentialRef, DEFAULT_MANAGED_NATS_IMAGE, DEFAULT_MANAGED_STORAGE_SIZE,
    MANAGED_NATS_CA_ENV, MANAGED_NATS_CLIENT_PORT, MANAGED_NATS_TOKEN_ENV, MANAGED_NODE_ID_ENV,
    MANAGED_STATE_KEY_ENV, MCPGCluster, MCPGClusterSpec, MCPGClusterStatus, ManagedCoordinator,
    ManagedCoordinatorTls, ManagedIssuerRef, ManagedStorage, managed_coordination_secret_name,
    managed_nats_config_name, managed_nats_headless_service_name, managed_nats_service_name,
    managed_nats_statefulset_name, managed_nats_tls_secret_name,
};

pub use route::{GatewayRef, MCPGRoute, MCPGRouteSpec, MCPGRouteStatus, RouteMatch, RouteToolRef};

pub use plugin_mirror::{
    MCPGPluginMirror, MCPGPluginMirrorSpec, MCPGPluginMirrorStatus, MirrorAuth, MirrorEndpoint,
    MirrorRewrite, MirrorSecretRef, MirrorService, MirrorUpstream,
};

pub use tenant::{
    AllowedPlugin, MCPGTenant, MCPGTenantSpec, MCPGTenantStatus, TenantIdentityAttribute,
    TenantObservedCounts, TenantQuotas,
};

pub use server::{
    MCPGServer, MCPGServerSpec, MCPGServerStatus, ServerFederate, ServerGatewayRef, ServerVerify,
};
