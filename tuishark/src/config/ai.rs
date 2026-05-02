use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiConfig {
    pub enabled: bool,
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub timeout_ms: u64,
    pub max_raw_bytes: usize,
    pub cache_size: usize,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "http://localhost:8100/v1".into(),
            api_key: String::new(),
            model: "mistralai/Ministral-3-8B-Instruct-2512".into(),
            timeout_ms: 30_000,
            max_raw_bytes: 512,
            cache_size: 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values() {
        let config = AiConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.base_url, "http://localhost:8100/v1");
        assert_eq!(config.api_key, "");
        assert_eq!(config.timeout_ms, 30_000);
        assert_eq!(config.max_raw_bytes, 512);
        assert_eq!(config.cache_size, 32);
    }

    #[test]
    fn partial_toml_fills_defaults() {
        let toml = r#"
enabled = true
model = "gpt-4"
"#;
        let config: AiConfig = toml::from_str(toml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.model, "gpt-4");
        assert_eq!(config.base_url, "http://localhost:8100/v1");
        assert_eq!(config.timeout_ms, 30_000);
        assert_eq!(config.cache_size, 32);
    }

    #[test]
    fn full_toml_parses() {
        let toml = r#"
enabled = true
base_url = "https://api.example.com/v1"
api_key = "sk-test"
model = "custom-model"
timeout_ms = 60000
max_raw_bytes = 1024
cache_size = 64
"#;
        let config: AiConfig = toml::from_str(toml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.base_url, "https://api.example.com/v1");
        assert_eq!(config.api_key, "sk-test");
        assert_eq!(config.model, "custom-model");
        assert_eq!(config.timeout_ms, 60_000);
        assert_eq!(config.max_raw_bytes, 1024);
        assert_eq!(config.cache_size, 64);
    }

    #[test]
    fn empty_toml_uses_defaults() {
        let config: AiConfig = toml::from_str("").unwrap();
        assert!(!config.enabled);
        assert_eq!(config.cache_size, 32);
    }

    #[test]
    fn top_level_config_with_ai_section() {
        use crate::config::Config;
        let toml = r#"
[ai]
enabled = true
model = "test-model"
cache_size = 16
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.ai.enabled);
        assert_eq!(config.ai.model, "test-model");
        assert_eq!(config.ai.cache_size, 16);
        assert!(config.display.auto_scroll);
    }

    #[test]
    fn config_without_ai_section_uses_defaults() {
        use crate::config::Config;
        let config: Config = toml::from_str("").unwrap();
        assert!(!config.ai.enabled);
        assert_eq!(config.ai.cache_size, 32);
    }
}
