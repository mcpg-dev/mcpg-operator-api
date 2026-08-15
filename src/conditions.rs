//! Standard `metav1.Condition[]` helpers used by every CRD's status.
//!
//! Every status uses the same vocabulary so clients can write
//! generic "wait for Ready=True" logic across kinds.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One status condition. Serde shape matches K8s
/// `metav1.Condition` exactly so generic tooling (kubectl,
/// kustomize, Argo CD) interprets it correctly.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// `Ready`, `Reconciling`, `Available`, `Degraded`,
    /// `Progressing`, `Failed`, plus per-CRD types.
    pub r#type: String,

    /// `"True"`, `"False"`, or `"Unknown"`. K8s convention is to
    /// keep this as a string (not a bool) so `Unknown` is
    /// representable.
    pub status: String,

    /// CamelCase enum the operator defines per controller.
    /// E.g. `AllReplicasAvailable`, `DependencyPending`,
    /// `SignatureMismatch`.
    pub reason: String,

    /// Free-text human-readable detail. May be empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,

    /// RFC3339 timestamp of the most recent transition.
    pub last_transition_time: DateTime<Utc>,

    /// `metadata.generation` the controller had observed when
    /// it set this condition. Lets clients detect stale status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

impl Condition {
    /// Build a `True` condition with `reason` set.
    pub fn ready_true(reason: impl Into<String>) -> Self {
        Self::new("Ready", "True", reason, "", None)
    }

    /// Build a `False` condition with reason + message.
    pub fn ready_false(reason: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new("Ready", "False", reason, message, None)
    }

    /// Build a condition of the given type.
    pub fn new(
        ty: impl Into<String>,
        status: impl Into<String>,
        reason: impl Into<String>,
        message: impl Into<String>,
        observed_generation: Option<i64>,
    ) -> Self {
        Self {
            r#type: ty.into(),
            status: status.into(),
            reason: reason.into(),
            message: message.into(),
            last_transition_time: Utc::now(),
            observed_generation,
        }
    }
}

/// Standard condition type names (re-used across CRDs).
pub mod types {
    /// Desired state achieved + observed by all controllers in
    /// the dependency chain.
    pub const READY: &str = "Ready";
    /// A reconcile is currently running.
    pub const RECONCILING: &str = "Reconciling";
    /// Last reconcile failed but existing state still serving.
    pub const DEGRADED: &str = "Degraded";
    /// Applied but waiting for downstream (pods rolling, peer
    /// convergence, etc.).
    pub const PROGRESSING: &str = "Progressing";
    /// Gateway-only — at least one pod ready and serving.
    pub const AVAILABLE: &str = "Available";
    /// Applied state is unrecoverable; manual intervention needed.
    pub const FAILED: &str = "Failed";
}

/// Standard `reason` enum values (CamelCase by K8s convention).
///
/// These are the canonical reasons every operator controller
/// uses on `Condition.reason`. Operators reading status branch
/// on these strings, so they are a stable vocabulary.
pub mod reasons {
    /// Reconcile loop converged. Use when status flips Ready=True.
    pub const RECONCILED: &str = "Reconciled";
    /// Gateway-only: every replica in `.status.readyReplicas`.
    pub const ALL_REPLICAS_AVAILABLE: &str = "AllReplicasAvailable";
    /// At least one pod is Ready, but not the full replica set yet.
    pub const PODS_READY: &str = "PodsReady";
    /// Reconcile is making forward progress (intermediate).
    pub const PROGRESSING: &str = "Progressing";
    /// Recoverable error — caller should retry. Triggers
    /// exponential backoff via `BackoffMap`.
    pub const TRANSIENT_ERROR: &str = "TransientError";
    /// Spec is broken in a way the operator cannot fix on its
    /// own (admission was bypassed, plugin descriptor mismatch,
    /// etc). Manual intervention required.
    pub const PERMANENT_ERROR: &str = "PermanentError";
    /// A referenced resource exists but isn't Ready yet — the
    /// reconcile loop is just waiting on the dependency.
    pub const DEPENDENCY_PENDING: &str = "DependencyPending";
    /// A referenced resource is missing entirely. Dashboards
    /// alert on this differently from `DependencyPending`
    /// because missing usually means a misconfigured ref.
    pub const DEPENDENCY_MISSING: &str = "DependencyMissing";
    /// Admission webhook denied the spec. Surfaced for
    /// historical visibility — apiserver returns the same
    /// reason on `kubectl apply` so users mostly see this in
    /// the apiserver response, not on status.
    pub const ADMISSION_REJECTED: &str = "AdmissionRejected";
    /// Server-side apply rejected the rendered child resource
    /// (e.g. webhook on the child kind denied it).
    pub const APPLY_FAILED: &str = "ApplyFailed";
}

/// Set or update a condition on a `Vec<Condition>`. If a condition
/// of the same `type` already exists, updates it in place
/// (preserving `lastTransitionTime` if status didn't change);
/// otherwise appends.
pub fn set_condition(conditions: &mut Vec<Condition>, mut new: Condition) {
    if let Some(existing) = conditions.iter_mut().find(|c| c.r#type == new.r#type) {
        if existing.status == new.status {
            // Same status: keep the existing transition time but
            // refresh reason / message / observedGeneration.
            new.last_transition_time = existing.last_transition_time;
        }
        *existing = new;
    } else {
        conditions.push(new);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_true_helper_sets_fields() {
        let c = Condition::ready_true(reasons::RECONCILED);
        assert_eq!(c.r#type, "Ready");
        assert_eq!(c.status, "True");
        assert_eq!(c.reason, "Reconciled");
        assert!(c.message.is_empty());
    }

    #[test]
    fn set_condition_replaces_in_place() {
        let mut conds = vec![Condition::ready_false("Pending", "")];
        let original_time = conds[0].last_transition_time;
        std::thread::sleep(std::time::Duration::from_millis(2));

        // Same status: transition time should be preserved.
        set_condition(
            &mut conds,
            Condition::ready_false("StillPending", "more details"),
        );
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0].reason, "StillPending");
        assert_eq!(conds[0].last_transition_time, original_time);

        // Status flip: transition time updates.
        set_condition(&mut conds, Condition::ready_true("Reconciled"));
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0].status, "True");
        assert!(conds[0].last_transition_time > original_time);
    }

    #[test]
    fn set_condition_appends_when_type_new() {
        let mut conds = vec![Condition::ready_true("Reconciled")];
        set_condition(
            &mut conds,
            Condition::new(types::AVAILABLE, "True", reasons::PODS_READY, "", None),
        );
        assert_eq!(conds.len(), 2);
        assert!(conds.iter().any(|c| c.r#type == types::AVAILABLE));
    }
}
