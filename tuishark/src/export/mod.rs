pub mod csv;
pub mod json;
pub mod text;

use std::fmt;

/// Export format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Csv,
    Json,
    Text,
}

impl ExportFormat {
    pub const ALL: [ExportFormat; 3] = [ExportFormat::Csv, ExportFormat::Json, ExportFormat::Text];

    pub fn extension(self) -> &'static str {
        match self {
            ExportFormat::Csv => "csv",
            ExportFormat::Json => "json",
            ExportFormat::Text => "txt",
        }
    }
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportFormat::Csv => write!(f, "CSV"),
            ExportFormat::Json => write!(f, "JSON"),
            ExportFormat::Text => write!(f, "Plain Text"),
        }
    }
}

/// Export step in the dialog flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportStep {
    FormatSelect,
    FilenameInput,
}

/// Convert days since Unix epoch to (year, month, day).
/// Civil days algorithm — used by export timestamps and filename generation.
pub(crate) fn epoch_days_to_date(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}
