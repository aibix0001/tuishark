use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_RECENT: usize = 10;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RecentFiles {
    pub files: Vec<RecentEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentEntry {
    pub path: PathBuf,
    pub timestamp: u64, // Unix epoch seconds
}

impl RecentFiles {
    /// Load recent files from config. Returns empty list on any error.
    pub fn load() -> Self {
        let Some(path) = Self::config_path() else {
            return Self::default();
        };
        let Ok(data) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        serde_json::from_str(&data).unwrap_or_default()
    }

    /// Save recent files to config. Silently ignores errors.
    pub fn save(&self) {
        let Some(dir) = Self::config_dir() else {
            return;
        };
        let _ = std::fs::create_dir_all(&dir);
        let Some(path) = Self::config_path() else {
            return;
        };
        if let Ok(data) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, data);
        }
    }

    /// Add a file path to the recent list (moves to front if already present).
    pub fn add(&mut self, path: &Path) {
        let canonical = std::fs::canonicalize(path)
            .unwrap_or_else(|_| path.to_path_buf());

        // Remove existing entry for same path
        self.files.retain(|e| e.path != canonical);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.files.insert(0, RecentEntry {
            path: canonical,
            timestamp: now,
        });

        self.files.truncate(MAX_RECENT);
    }

    fn config_dir() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("tuishark"))
    }

    fn config_path() -> Option<PathBuf> {
        Self::config_dir().map(|d| d.join("recent.json"))
    }
}
