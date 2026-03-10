use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Available columns in the packet table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Column {
    No,
    Time,
    Source,
    Destination,
    Protocol,
    Length,
    Info,
}

impl Column {
    pub const ALL: &[Column] = &[
        Column::No,
        Column::Time,
        Column::Source,
        Column::Destination,
        Column::Protocol,
        Column::Length,
        Column::Info,
    ];

    pub fn header(&self) -> &'static str {
        match self {
            Column::No => "No.",
            Column::Time => "Time",
            Column::Source => "Source",
            Column::Destination => "Destination",
            Column::Protocol => "Proto",
            Column::Length => "Len",
            Column::Info => "Info",
        }
    }

    pub fn default_width(&self) -> u16 {
        match self {
            Column::No => 6,
            Column::Time => 16,
            Column::Source => 39,
            Column::Destination => 39,
            Column::Protocol => 8,
            Column::Length => 6,
            Column::Info => 0, // Min(20) — flexible
        }
    }
}

/// Column display configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ColumnConfig {
    /// Ordered list of visible columns.
    pub visible: Vec<Column>,
    /// Optional width overrides per column.
    #[serde(default)]
    pub widths: HashMap<Column, u16>,
}

impl Default for ColumnConfig {
    fn default() -> Self {
        Self {
            visible: Column::ALL.to_vec(),
            widths: HashMap::new(),
        }
    }
}

impl ColumnConfig {
    /// Get the width for a column, using the override or the default.
    pub fn width(&self, col: &Column) -> u16 {
        self.widths.get(col).copied().unwrap_or_else(|| col.default_width())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_all_columns() {
        let config = ColumnConfig::default();
        assert_eq!(config.visible.len(), 7);
        assert_eq!(config.visible[0], Column::No);
        assert_eq!(config.visible[6], Column::Info);
    }

    #[test]
    fn custom_visibility() {
        let toml = r#"visible = ["source", "destination", "protocol"]"#;
        let config: ColumnConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.visible.len(), 3);
        assert_eq!(config.visible[0], Column::Source);
    }

    #[test]
    fn width_override() {
        let mut config = ColumnConfig::default();
        config.widths.insert(Column::Source, 30);
        assert_eq!(config.width(&Column::Source), 30);
        assert_eq!(config.width(&Column::No), 6); // default
    }

    #[test]
    fn serde_roundtrip() {
        let config = ColumnConfig::default();
        let toml = toml::to_string(&config).unwrap();
        let parsed: ColumnConfig = toml::from_str(&toml).unwrap();
        assert_eq!(parsed.visible.len(), config.visible.len());
    }
}
