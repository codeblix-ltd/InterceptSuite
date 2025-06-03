use crate::library::{ProxyConfig, ProxyStats};

#[derive(Debug, Clone)]
pub enum Message {
    // Library management
    LibraryLoaded(Result<std::sync::Arc<crate::library::InterceptLibrary>, String>),

    // Navigation
    TabSelected(Tab),    // Configuration
    ConfigLoaded(Result<ProxyConfig, String>),
    BindAddressSelected(String),
    PortChanged(String),
    LogFileChanged(String),
    VerboseModeToggled(bool),
    LoadConfig,
    SaveConfig,
    ConfigSaved,
    ConfigSaveError(String),

    // Statistics
    StatsLoaded(Result<ProxyStats, String>),
    LoadStats,

    // System information
    SystemIpsLoaded(Result<Vec<String>, String>),
    LoadSystemIps,    // Proxy control
    StartProxy,
    StopProxy,
    ProxyStarted,
    ProxyStopped,
    ProxyError(String),
    ProxyStartError(String),
    ProxyStopError(String),

    // Interception
    InterceptEnabledToggled(bool),
    InterceptDirectionChanged(InterceptDirection),
    ForwardIntercept,
    DropIntercept,    InterceptDataReceived {
        connection_id: i32,
        packet_id: i32,
        direction: String,
        src_ip: String,
        dst_ip: String,
        dst_port: i32,
        data: Vec<u8>,
    },
    InterceptDataEdited(String), // For editing the intercepted data
    InterceptDataClear,          // For clearing current intercept
    // History management
    ClearHistory,
    ExportHistory,
    HistoryItemSelected(usize),
    HistoryTableArrowKey(i32), // +1 for down, -1 for up
    DataViewTabSelected(crate::ui::state::DataViewTab),
    PaneResized(iced::widget::pane_grid::ResizeEvent),// Connections management
    ClearConnections,
    ExportConnections,
    ConnectionSelected(usize),
    RefreshConnections,
    ViewConnectionDetails(usize),
    TerminateConnection(usize),

    // Connection events from DLL
    ConnectionEvent {
        client_ip: String,
        client_port: i32,
        target_host: String,
        target_port: i32,
        connection_id: i32,
    },    DisconnectEvent {
        connection_id: i32,
        reason: String,
    },    // Log event from DLL for proxy history
    LogEvent {
        timestamp: String,
        connection_id: i32,
        packet_id: i32,
        src_ip: String,
        dst_ip: String,
        dst_port: i32,
        message_type: String,
        data: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tab {
    Intercept,
    ProxyHistory,
    Settings,
    Connections,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InterceptDirection {
    None = 0,
    ClientToServer = 1,
    ServerToClient = 2,
    Both = 3,
}

impl InterceptDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            InterceptDirection::None => "None",
            InterceptDirection::ClientToServer => "Client → Server",
            InterceptDirection::ServerToClient => "Server → Client",
            InterceptDirection::Both => "Both Directions",
        }
    }

    pub fn from_index(index: usize) -> Self {
        match index {
            0 => InterceptDirection::None,
            1 => InterceptDirection::ClientToServer,
            2 => InterceptDirection::ServerToClient,
            3 => InterceptDirection::Both,
            _ => InterceptDirection::None,
        }
    }
}
