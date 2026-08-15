//! Custom Resource Definition types for the MCPG Kubernetes operator.
//!
//! Group: `mcpg.dev`. Storage version: `v1alpha1`. We are pre-1.0,
//! so older alpha versions are dropped wholesale rather than
//! served-via-conversion-webhook — bumping the CRD version is the
//! signal to operators that the API has changed.
//!
//! See <https://mcpg.dev/docs/reference/operator-crds> for the
//! field-level reference.

pub mod conditions;
pub mod schema_helpers;
pub mod v1alpha1;

/// API group for every MCPG operator CRD.
pub const API_GROUP: &str = "mcpg.dev";

/// Operator-canonical revocation list name (cluster-scoped). The
/// operator treats this single resource as authoritative; other
/// `MCPGRevocationList` resources are advisory.
pub const CLUSTER_DEFAULT_REVOCATION_LIST: &str = "cluster-default";

/// Default operator namespace.
pub const DEFAULT_OPERATOR_NAMESPACE: &str = "mcpg-system";
