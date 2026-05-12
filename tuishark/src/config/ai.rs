use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    pub prompt_file: Option<String>,
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
            prompt_file: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiPromptConfig {
    pub system: String,
    pub whole_packet: String,
    pub field: String,
}

impl Default for AiPromptConfig {
    fn default() -> Self {
        Self {
            system: DEFAULT_SYSTEM_PROMPT.into(),
            whole_packet: DEFAULT_WHOLE_PACKET_PROMPT.into(),
            field: DEFAULT_FIELD_PROMPT.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct PromptFile {
    prompts: AiPromptConfig,
}

impl Default for PromptFile {
    fn default() -> Self {
        Self { prompts: AiPromptConfig::default() }
    }
}

pub const DEFAULT_SYSTEM_PROMPT: &str = "\
You are a network packet analysis tutor embedded in TuiShark.\n\
Explain only from the supplied packet context.\n\
Be accurate, concise, and educational.\n\
Prefer protocol facts over speculation.\n\
If information is missing or ambiguous, say what cannot be determined.\n\
Do not invent payload contents that are not present in the supplied fields or bytes.\n\
Connect general networking knowledge to the concrete selected packet.\n\
Structure the answer for a terminal UI.\n\
Do not use markdown formatting — no asterisks, no headers, no backticks.\n\
Use plain text with line breaks and indentation for structure.";

pub const DEFAULT_WHOLE_PACKET_PROMPT: &str = "\
Explain this packet at a high level for someone learning networking.\n\
\n\
Answer these questions:\n\
1. What protocol stack and packet type does this represent?\n\
2. What are the source and destination endpoints?\n\
3. What important flags, codes, ports, lengths, or header fields stand out?\n\
4. What does this packet likely mean in the flow?\n\
5. Are there any warnings, anomalies, retransmissions, resets, fragmentation, \
truncation, private/public address notes, or security-relevant observations?";

pub const DEFAULT_FIELD_PROMPT: &str = "\
Explain the selected packet field for someone learning networking.\n\
\n\
Cover:\n\
1. What this field means generally.\n\
2. How to interpret this packet's value.\n\
3. How this field relates to the current packet and connection.\n\
4. Whether the value is normal, suspicious, or context-dependent.";

impl AiPromptConfig {
    pub fn load(prompt_file: Option<&str>) -> Self {
        let path = match prompt_file {
            Some(p) => {
                let expanded = if p == "~" {
                    dirs::home_dir().unwrap_or_else(|| PathBuf::from(p))
                } else if let Some(rest) = p.strip_prefix("~/") {
                    dirs::home_dir()
                        .map(|h| h.join(rest))
                        .unwrap_or_else(|| PathBuf::from(p))
                } else {
                    PathBuf::from(p)
                };
                expanded
            }
            None => return Self::default(),
        };

        match std::fs::read_to_string(&path) {
            Ok(contents) => match toml::from_str::<PromptFile>(&contents) {
                Ok(pf) => pf.prompts,
                Err(e) => {
                    eprintln!("[tuishark] failed to parse prompt file {}: {e}", path.display());
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    pub fn render_whole_packet(&self, packet_context_json: &str) -> String {
        let prompt = &self.whole_packet;
        if prompt.contains("{packet_context_json}") {
            prompt.replace("{packet_context_json}", packet_context_json)
        } else {
            format!("{prompt}\n\nPacket context:\n{packet_context_json}")
        }
    }

    pub fn render_field(&self, field_context_json: &str, packet_context_json: &str) -> String {
        let prompt = &self.field;
        let mut result = prompt.clone();
        let has_placeholders = result.contains("{selected_field_context_json}")
            || result.contains("{packet_context_json}");
        if has_placeholders {
            result = result.replace("{selected_field_context_json}", field_context_json);
            result = result.replace("{packet_context_json}", packet_context_json);
            result
        } else {
            format!(
                "{prompt}\n\nSelected field context:\n{field_context_json}\n\n\
                 Full packet context:\n{packet_context_json}"
            )
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
    fn ai_after_filter_array() {
        use crate::config::Config;
        let toml = r#"
[theme]
flavor = "latte"

[[filter]]
name = "TCP only"
expression = "proto == tcp"

[[filter]]
name = "DNS"
expression = "proto == dns"

[ai]
enabled = true
base_url = "http://localhost:8100/v1"
model = "test-model"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.ai.enabled, "ai.enabled should be true after [[filter]] array");
        assert_eq!(config.ai.model, "test-model");
        assert_eq!(config.filters.len(), 2);
    }

    #[test]
    fn config_without_ai_section_uses_defaults() {
        use crate::config::Config;
        let config: Config = toml::from_str("").unwrap();
        assert!(!config.ai.enabled);
        assert_eq!(config.ai.cache_size, 32);
    }

    #[test]
    fn prompt_config_defaults() {
        let prompts = AiPromptConfig::default();
        assert!(prompts.system.contains("network packet analysis tutor"));
        assert!(prompts.whole_packet.contains("protocol stack"));
        assert!(prompts.field.contains("selected packet field"));
    }

    #[test]
    fn prompt_config_load_missing_file() {
        let prompts = AiPromptConfig::load(Some("/nonexistent/path.toml"));
        assert!(prompts.system.contains("network packet analysis tutor"));
    }

    #[test]
    fn prompt_config_load_none() {
        let prompts = AiPromptConfig::load(None);
        assert!(prompts.system.contains("network packet analysis tutor"));
    }

    #[test]
    fn prompt_file_partial_override() {
        let toml_str = r#"
[prompts]
system = "Custom system prompt"
"#;
        let pf: PromptFile = toml::from_str(toml_str).unwrap();
        assert_eq!(pf.prompts.system, "Custom system prompt");
        assert!(pf.prompts.whole_packet.contains("protocol stack"));
        assert!(pf.prompts.field.contains("selected packet field"));
    }

    #[test]
    fn prompt_file_full_override() {
        let toml_str = r#"
[prompts]
system = "sys"
whole_packet = "wp {packet_context_json}"
field = "f {selected_field_context_json} {packet_context_json}"
"#;
        let pf: PromptFile = toml::from_str(toml_str).unwrap();
        assert_eq!(pf.prompts.system, "sys");
        assert_eq!(pf.prompts.whole_packet, "wp {packet_context_json}");
    }

    #[test]
    fn render_whole_packet_with_placeholder() {
        let prompts = AiPromptConfig {
            system: "s".into(),
            whole_packet: "Analyze: {packet_context_json}".into(),
            field: "f".into(),
        };
        let rendered = prompts.render_whole_packet("{\"test\":1}");
        assert_eq!(rendered, "Analyze: {\"test\":1}");
    }

    #[test]
    fn render_whole_packet_without_placeholder() {
        let prompts = AiPromptConfig {
            system: "s".into(),
            whole_packet: "Analyze this.".into(),
            field: "f".into(),
        };
        let rendered = prompts.render_whole_packet("{\"test\":1}");
        assert!(rendered.contains("Packet context:"));
        assert!(rendered.contains("{\"test\":1}"));
    }

    #[test]
    fn render_field_with_placeholders() {
        let prompts = AiPromptConfig {
            system: "s".into(),
            whole_packet: "w".into(),
            field: "Field: {selected_field_context_json}\nPacket: {packet_context_json}".into(),
        };
        let rendered = prompts.render_field("{\"f\":1}", "{\"p\":1}");
        assert!(rendered.contains("{\"f\":1}"));
        assert!(rendered.contains("{\"p\":1}"));
        assert!(!rendered.contains("{selected_field_context_json}"));
    }

    #[test]
    fn prompt_file_with_prompt_file_config() {
        let toml = r#"
enabled = true
prompt_file = "~/.config/tuishark/ai-prompts.toml"
"#;
        let config: AiConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.prompt_file, Some("~/.config/tuishark/ai-prompts.toml".into()));
    }
}
