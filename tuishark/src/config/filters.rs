use serde::{Deserialize, Serialize};

/// A saved filter preset from configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterPreset {
    /// Display name for the preset.
    pub name: String,
    /// Filter expression (same syntax as the filter bar).
    pub expression: String,
    /// Optional description shown in the picker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_preset() {
        let toml = r#"
name = "TCP"
expression = "proto == tcp"
"#;
        let preset: FilterPreset = toml::from_str(toml).unwrap();
        assert_eq!(preset.name, "TCP");
        assert_eq!(preset.expression, "proto == tcp");
        assert!(preset.description.is_none());
    }

    #[test]
    fn preset_with_description() {
        let toml = r#"
name = "Web traffic"
expression = "proto == http or proto == https"
description = "HTTP and HTTPS packets"
"#;
        let preset: FilterPreset = toml::from_str(toml).unwrap();
        assert_eq!(preset.description, Some("HTTP and HTTPS packets".into()));
    }
}
