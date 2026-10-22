//! JSON Schema validation for service requests and responses.
//!
//! Schemas are self-contained: external `$ref`s are not resolved (no network or
//! file access), so a published schema cannot make a security server fetch
//! anything.

use jsonschema::Validator;
use serde_json::Value;

use crate::{Error, Result};

/// Largest schema accepted, serialised.
pub const MAX_SCHEMA_BYTES: usize = 64 * 1024;
/// How many violations are reported back.
const MAX_REPORTED: usize = 5;

pub struct CompiledSchema {
    validator: Validator,
}

impl CompiledSchema {
    pub fn compile(schema: &Value) -> Result<Self> {
        let size = serde_json::to_vec(schema)?.len();
        if size > MAX_SCHEMA_BYTES {
            return Err(Error::Verify(format!(
                "schema is {size} bytes, the limit is {MAX_SCHEMA_BYTES}"
            )));
        }
        let validator = jsonschema::validator_for(schema)
            .map_err(|e| Error::Verify(format!("invalid JSON Schema: {e}")))?;
        Ok(Self { validator })
    }

    /// `Ok(())` if `instance` conforms, otherwise up to five readable violations.
    pub fn check(&self, instance: &Value) -> std::result::Result<(), Vec<String>> {
        let errors: Vec<String> = self
            .validator
            .iter_errors(instance)
            .take(MAX_REPORTED)
            .map(|e| {
                let path = e.instance_path().to_string();
                if path.is_empty() {
                    format!("(root): {e}")
                } else {
                    format!("{path}: {e}")
                }
            })
            .collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn check_bytes(&self, body: &[u8]) -> std::result::Result<(), Vec<String>> {
        match serde_json::from_slice::<Value>(body) {
            Ok(v) => self.check(&v),
            Err(e) => Err(vec![format!("body is not valid JSON: {e}")]),
        }
    }
}

/// Is this a JSON media type (`application/json`, `application/problem+json`, ...)?
pub fn is_json_content_type(ct: &str) -> bool {
    let essence = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    essence == "application/json" || essence.ends_with("+json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tin_schema() -> CompiledSchema {
        CompiledSchema::compile(&json!({
            "type": "object",
            "required": ["tin"],
            "additionalProperties": false,
            "properties": { "tin": { "type": "string", "pattern": "^[0-9]{10}$" } }
        }))
        .unwrap()
    }

    #[test]
    fn accepts_and_rejects() {
        let s = tin_schema();
        assert!(s.check(&json!({ "tin": "2000123456" })).is_ok());
        let e = s.check(&json!({ "tin": "abc", "extra": 1 })).unwrap_err();
        assert!(e.len() >= 2, "{e:?}");
        assert!(s.check_bytes(b"not json").unwrap_err()[0].contains("not valid JSON"));
        assert!(s.check(&json!({})).unwrap_err()[0].contains("tin"));
    }

    #[test]
    fn bad_schemas_are_refused() {
        assert!(CompiledSchema::compile(&json!({ "type": "nonsense" })).is_err());
        let huge = json!({ "description": "x".repeat(MAX_SCHEMA_BYTES) });
        assert!(CompiledSchema::compile(&huge).is_err());
    }

    #[test]
    fn external_references_are_not_followed() {
        // must fail to compile rather than try to fetch anything
        assert!(
            CompiledSchema::compile(&json!({ "$ref": "http://127.0.0.1:1/never.json" })).is_err()
        );
        assert!(CompiledSchema::compile(&json!({ "$ref": "file:///etc/passwd" })).is_err());
    }

    #[test]
    fn content_types() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("Application/JSON; charset=utf-8"));
        assert!(is_json_content_type("application/problem+json"));
        assert!(!is_json_content_type("text/plain"));
    }
}
