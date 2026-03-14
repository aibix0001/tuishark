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
    // Link-layer metadata (optional, not in default set)
    PfAction,
    PfDirection,
    PfInterface,
    PfRule,
    PfReason,
    EncSpi,
    EncFlags,
}

impl Column {
    /// Default visible columns (standard packet table).
    pub const ALL: &[Column] = &[
        Column::No,
        Column::Time,
        Column::Source,
        Column::Destination,
        Column::Protocol,
        Column::Length,
        Column::Info,
    ];

    /// Link-layer metadata columns (pflog/enc — not in default visible set).
    pub const LINK_META: &[Column] = &[
        Column::PfAction,
        Column::PfDirection,
        Column::PfInterface,
        Column::PfRule,
        Column::PfReason,
        Column::EncSpi,
        Column::EncFlags,
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
            Column::PfAction => "Action",
            Column::PfDirection => "Dir",
            Column::PfInterface => "Interface",
            Column::PfRule => "Rule#",
            Column::PfReason => "Reason",
            Column::EncSpi => "SPI",
            Column::EncFlags => "Flags",
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
            Column::PfAction => 8,
            Column::PfDirection => 5,
            Column::PfInterface => 12,
            Column::PfRule => 6,
            Column::PfReason => 14,
            Column::EncSpi => 12,
            Column::EncFlags => 10,
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

    #[test]
    fn link_meta_columns_not_in_default() {
        let config = ColumnConfig::default();
        for col in Column::LINK_META {
            assert!(!config.visible.contains(col));
        }
    }

    #[test]
    fn serde_pf_columns() {
        let toml = r#"visible = ["pfaction", "pfdirection", "pfinterface", "pfrule", "pfreason", "encspi", "encflags"]"#;
        let config: ColumnConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.visible.len(), 7);
        assert_eq!(config.visible[0], Column::PfAction);
        assert_eq!(config.visible[1], Column::PfDirection);
        assert_eq!(config.visible[2], Column::PfInterface);
        assert_eq!(config.visible[3], Column::PfRule);
        assert_eq!(config.visible[4], Column::PfReason);
        assert_eq!(config.visible[5], Column::EncSpi);
        assert_eq!(config.visible[6], Column::EncFlags);
        // Round-trip
        let serialized = toml::to_string(&config).unwrap();
        let parsed: ColumnConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(parsed.visible, config.visible);
    }
}
