pub mod ai;
pub mod columns;
pub mod filters;
pub mod keys;
pub mod theme;

use serde::{Deserialize, Serialize};

use ai::AiConfig;
use columns::ColumnConfig;
use filters::FilterPreset;
use keys::KeyConfig;
use theme::ThemeConfig;

/// Top-level configuration loaded from `~/.config/tuishark/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub theme: ThemeConfig,
    pub keys: KeyConfig,
    pub columns: ColumnConfig,
    pub display: DisplayConfig,
    pub capture: CaptureConfig,
    pub export: ExportConfig,
    #[serde(rename = "filter")]
    pub filters: Vec<FilterPreset>,
    pub ai: AiConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: ThemeConfig::default(),
            keys: KeyConfig::default(),
            columns: ColumnConfig::default(),
            display: DisplayConfig::default(),
            capture: CaptureConfig::default(),
            export: ExportConfig::default(),
            filters: Vec::new(),
            ai: AiConfig::default(),
        }
    }
}

/// Display preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DisplayConfig {
    /// Timestamp format in the packet table: "relative", "absolute", or "epoch".
    pub timestamp_format: TimestampFormat,
    /// Whether to use uppercase hex digits in the hex dump.
    pub hex_uppercase: bool,
    /// Whether to auto-scroll during live capture.
    pub auto_scroll: bool,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            timestamp_format: TimestampFormat::Relative,
            hex_uppercase: true,
            auto_scroll: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimestampFormat {
    Relative,
    Absolute,
    Epoch,
}

/// Capture defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureConfig {
    /// Default interface name (empty = show picker).
    pub default_interface: String,
    /// Enable promiscuous mode.
    pub promiscuous: bool,
    /// Capture snap length in bytes.
    pub snap_length: u32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            default_interface: String::new(),
            promiscuous: true,
            snap_length: 65535,
        }
    }
}

/// Export defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExportConfig {
    /// Default export format.
    pub default_format: ExportFormatDefault,
    /// Default output directory for exports.
    pub default_directory: String,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            default_format: ExportFormatDefault::Csv,
            default_directory: ".".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormatDefault {
    Csv,
    Json,
    Text,
}

impl Config {
    /// Resolve the config file path, falling back to the original user's
    /// config directory when running under sudo.
    fn config_path() -> Option<std::path::PathBuf> {
        let primary = dirs::config_dir().map(|d| d.join("tuishark").join("config.toml"));
        if let Some(ref p) = primary {
            if p.exists() {
                return primary;
            }
        }
        // Under sudo, HOME points to /root — try the invoking user's config
        if let Ok(user) = std::env::var("SUDO_USER") {
            let fallback = std::path::PathBuf::from(format!(
                "/home/{user}/.config/tuishark/config.toml"
            ));
            if fallback.exists() {
                return Some(fallback);
            }
        }
        primary
    }

    /// Load configuration from the default path (`~/.config/tuishark/config.toml`).
    /// Returns default config if the file doesn't exist or can't be parsed.
    pub fn load() -> Self {
        let Some(path) = Self::config_path() else {
            return Self::default();
        };
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(&path) {
            Ok(contents) => match toml::from_str(&contents) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Warning: invalid config file {}: {e}", path.display());
                    Self::default()
                }
            },
            Err(e) => {
                eprintln!("Warning: cannot read config file {}: {e}", path.display());
                Self::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_serializes() {
        let config = Config::default();
        let toml = toml::to_string_pretty(&config).unwrap();
        assert!(toml.contains("hex_uppercase"));
        assert!(toml.contains("promiscuous"));
    }

    #[test]
    fn empty_toml_parses_to_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.display.hex_uppercase);
        assert_eq!(config.display.timestamp_format, TimestampFormat::Relative);
        assert!(config.filters.is_empty());
    }

    #[test]
    fn partial_toml_fills_defaults() {
        let toml = r#"
[display]
hex_uppercase = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(!config.display.hex_uppercase);
        assert!(config.display.auto_scroll); // default preserved
        assert!(config.capture.promiscuous); // default preserved
    }

    #[test]
    fn filters_parse() {
        let toml = r#"
[[filter]]
name = "HTTP only"
expression = "proto == http"

[[filter]]
name = "DNS"
expression = "proto == dns"
description = "Show only DNS traffic"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.filters.len(), 2);
        assert_eq!(config.filters[0].name, "HTTP only");
        assert_eq!(config.filters[1].description, Some("Show only DNS traffic".into()));
    }

    #[test]
    fn invalid_toml_returns_default() {
        // Config::load() handles errors internally, but we can test deserialization
        let result: Result<Config, _> = toml::from_str("invalid {{{");
        assert!(result.is_err());
    }

    #[test]
    fn timestamp_format_serde() {
        let toml = r#"
[display]
timestamp_format = "absolute"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.display.timestamp_format, TimestampFormat::Absolute);
    }
}
