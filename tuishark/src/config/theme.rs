use serde::{Deserialize, Serialize};

/// Theme configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ThemeConfig {
    /// Catppuccin flavor: "mocha", "macchiato", "frappe", or "latte".
    pub flavor: CatppuccinFlavor,
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self {
            flavor: CatppuccinFlavor::Mocha,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CatppuccinFlavor {
    Mocha,
    Macchiato,
    Frappe,
    Latte,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flavor_serde_roundtrip() {
        let config = ThemeConfig { flavor: CatppuccinFlavor::Frappe };
        let toml = toml::to_string(&config).unwrap();
        assert!(toml.contains("frappe"));
        let parsed: ThemeConfig = toml::from_str(&toml).unwrap();
        assert_eq!(parsed.flavor, CatppuccinFlavor::Frappe);
    }

    #[test]
    fn all_flavors_deserialize() {
        for flavor in ["mocha", "macchiato", "frappe", "latte"] {
            let toml = format!("flavor = \"{flavor}\"");
            let config: ThemeConfig = toml::from_str(&toml).unwrap();
            assert_eq!(format!("{:?}", config.flavor).to_lowercase(), flavor);
        }
    }
}
