//! `schemars` helpers that inject K8s-CRD extensions absent from
//! the default schema output.
//!
//! Why these exist: kube-rs's `CustomResource` derive runs
//! schemars to generate the CRD's OpenAPI v3 schema. schemars 1.x
//! emits `serde_json::Value` fields as `{}` (no type), which
//! Kubernetes 1.29+ rejects with errors of the form
//! `properties[X].type: Required value: must not be empty for
//! specified object fields`. The fix is to attach the
//! `x-kubernetes-preserve-unknown-fields: true` extension so the
//! apiserver knows the field is arbitrary by design — same
//! behaviour as `kubectl explain` showing `<map[string]string>`
//! for a `runtime.RawExtension`.
//!
//! Use these via the `#[schemars(schema_with = "...")]` attribute
//! on the field. Example:
//!
//! ```ignore
//! #[serde(default, skip_serializing_if = "Option::is_none")]
//! #[schemars(schema_with = "mcpg_operator_api::schema_helpers::preserve_object")]
//! pub config: Option<serde_json::Value>,
//! ```

use schemars::Schema;

/// Schema for an object field whose properties are not statically
/// known. Use on `serde_json::Value` / `Option<serde_json::Value>`
/// fields where the inner shape is determined by an external
/// schema (e.g. the gateway's own boot config — its schema lives
/// in `apps/gateway/src/config/mod.rs`, not here).
pub fn preserve_object(_: &mut schemars::SchemaGenerator) -> Schema {
    serde_json::from_value(serde_json::json!({
        "type": "object",
        "x-kubernetes-preserve-unknown-fields": true,
    }))
    .expect("static schema literal is always valid")
}

/// Schema for an array of arbitrary objects. Use on
/// `Vec<serde_json::Value>` fields.
pub fn preserve_array_of_objects(_: &mut schemars::SchemaGenerator) -> Schema {
    serde_json::from_value(serde_json::json!({
        "type": "array",
        "items": {
            "type": "object",
            "x-kubernetes-preserve-unknown-fields": true,
        },
    }))
    .expect("static schema literal is always valid")
}

/// Schema for K8s's int-or-string union type. Used on PDB
/// `minAvailable` / `maxUnavailable` and HPA targets, where the
/// value is either an integer (count) or a percentage string
/// (e.g. `"50%"`).
pub fn int_or_string(_: &mut schemars::SchemaGenerator) -> Schema {
    serde_json::from_value(serde_json::json!({
        "x-kubernetes-int-or-string": true,
    }))
    .expect("static schema literal is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::SchemaGenerator;

    fn schema_to_json(s: Schema) -> serde_json::Value {
        serde_json::to_value(s).unwrap()
    }

    #[test]
    fn preserve_object_emits_xkube_extension() {
        let mut generator = SchemaGenerator::default();
        let schema = preserve_object(&mut generator);
        let v = schema_to_json(schema);
        assert_eq!(v["type"], "object");
        assert_eq!(v["x-kubernetes-preserve-unknown-fields"], true);
    }

    #[test]
    fn preserve_array_of_objects_marks_items() {
        let mut generator = SchemaGenerator::default();
        let schema = preserve_array_of_objects(&mut generator);
        let v = schema_to_json(schema);
        assert_eq!(v["type"], "array");
        assert_eq!(v["items"]["type"], "object");
        assert_eq!(v["items"]["x-kubernetes-preserve-unknown-fields"], true);
    }

    #[test]
    fn int_or_string_emits_only_xkube_extension() {
        let mut generator = SchemaGenerator::default();
        let schema = int_or_string(&mut generator);
        let v = schema_to_json(schema);
        assert_eq!(v["x-kubernetes-int-or-string"], true);
    }
}
