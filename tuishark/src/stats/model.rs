/// Shared types for the statistics module.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsTab {
    ProtocolHierarchy,
    Conversations,
    Endpoints,
    IoGraph,
}

impl StatsTab {
    pub const ALL: &[StatsTab] = &[
        StatsTab::ProtocolHierarchy,
        StatsTab::Conversations,
        StatsTab::Endpoints,
        StatsTab::IoGraph,
    ];

    pub fn next(self) -> Self {
        match self {
            StatsTab::ProtocolHierarchy => StatsTab::Conversations,
            StatsTab::Conversations => StatsTab::Endpoints,
            StatsTab::Endpoints => StatsTab::IoGraph,
            StatsTab::IoGraph => StatsTab::ProtocolHierarchy,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            StatsTab::ProtocolHierarchy => StatsTab::IoGraph,
            StatsTab::Conversations => StatsTab::ProtocolHierarchy,
            StatsTab::Endpoints => StatsTab::Conversations,
            StatsTab::IoGraph => StatsTab::Endpoints,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            StatsTab::ProtocolHierarchy => "Protocol Hierarchy",
            StatsTab::Conversations => "Conversations",
            StatsTab::Endpoints => "Endpoints",
            StatsTab::IoGraph => "I/O Graph",
        }
    }

    pub fn index(self) -> usize {
        match self {
            StatsTab::ProtocolHierarchy => 0,
            StatsTab::Conversations => 1,
            StatsTab::Endpoints => 2,
            StatsTab::IoGraph => 3,
        }
    }

    pub fn from_index(i: usize) -> Option<Self> {
        Self::ALL.get(i).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_cycle() {
        let tab = StatsTab::ProtocolHierarchy;
        assert_eq!(tab.next().next().next().next(), tab);
        assert_eq!(tab.prev().prev().prev().prev(), tab);
    }

    #[test]
    fn tab_index_roundtrip() {
        for tab in StatsTab::ALL {
            assert_eq!(StatsTab::from_index(tab.index()), Some(*tab));
        }
    }
}
