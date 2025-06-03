use crate::library::{ProxyConfig, ProxyStats};
use crate::ui::messages::{InterceptDirection, Tab};
use std::collections::VecDeque;
use std::sync::Arc;
use chrono::{DateTime, Utc};

#[derive(Debug)]
pub struct AppState {
    // Library status
    pub library_status: String,
    pub library: Option<Arc<crate::library::InterceptLibrary>>,

    // UI state
    pub current_tab: Tab,
    pub current_data_view_tab: DataViewTab,

    // Configuration
    pub current_config: ProxyConfig,
    pub config_inputs: ConfigInputs,
    pub config_status: String,

    // Statistics
    pub stats: Option<ProxyStats>,
    pub stats_status: String,

    // System information
    pub system_ips: Vec<String>,
    pub ips_status: String,

    // Proxy state
    pub proxy_running: bool,
    pub proxy_status: String,

    // Intercept state
    pub intercept_state: InterceptState,

    // History and connections
    pub history: VecDeque<HistoryEntry>,
    pub connections: VecDeque<ConnectionEntry>,    // UI state
    pub selected_history_item: Option<usize>,
    pub selected_connection: Option<usize>,
    pub pane_state: iced::widget::pane_grid::State<PaneContent>,
}

#[derive(Debug)]
pub struct ConfigInputs {
    pub selected_bind_address: Option<String>,
    pub available_ips: Vec<String>,
    pub port: String,
    pub log_file: String,
    pub verbose_mode: bool,
}

#[derive(Debug)]
pub struct InterceptState {
    pub enabled: bool,
    pub direction: InterceptDirection,
    pub current_intercept: Option<InterceptData>,
    pub pending_action: bool,
    pub edited_data: String, // For editing intercepted data as text
}

#[derive(Debug, Clone)]
pub struct InterceptData {
    pub connection_id: i32,
    pub packet_id: i32,
    pub direction: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: i32,
    pub data: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub id: usize,
    pub connection_id: i32,
    pub packet_id: i32,
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: i32,
    pub message_type: String,
    pub data_text: Option<String>,     // Text data (from log events)
    pub data_bytes: Option<Vec<u8>>,   // Raw bytes (from intercept events)
    pub modified_data: Option<Vec<u8>>, // Modified data (if any)
    pub modified: bool,
}

impl HistoryEntry {
    // Helper method to get data as displayable string
    pub fn get_data_as_string(&self) -> String {
        if let Some(text) = &self.data_text {
            // Return text data directly
            text.clone()
        } else if let Some(bytes) = &self.data_bytes {
            // Try to convert bytes to string, fall back to hex if not valid UTF-8
            match String::from_utf8(bytes.clone()) {
                Ok(text) => text,
                Err(_) => {
                    let hex_data: Vec<String> = bytes.iter().take(500).map(|b| format!("{:02x}", b)).collect();
                    let hex_text = hex_data.join(" ");
                    if bytes.len() > 500 {
                        format!("{}... (truncated, {} total bytes)", hex_text, bytes.len())
                    } else {
                        hex_text
                    }
                }
            }
        } else {
            "(no data)".to_string()
        }
    }

    // Helper method to get data as bytes for modification
    pub fn get_data_as_bytes(&self) -> Vec<u8> {
        if let Some(text) = &self.data_text {
            text.as_bytes().to_vec()
        } else if let Some(bytes) = &self.data_bytes {
            bytes.clone()
        } else {
            Vec::new()
        }
    }

    // Helper method to get data size
    pub fn get_data_size(&self) -> usize {
        if let Some(text) = &self.data_text {
            text.len()
        } else if let Some(bytes) = &self.data_bytes {
            bytes.len()
        } else {
            0
        }
    }
}

#[derive(Debug, Clone)]
pub enum PaneContent {
    HistoryTable,
    DataView,
}

#[derive(Debug, Clone)]
pub struct ConnectionEntry {
    pub id: usize,
    pub connection_id: i32,
    pub timestamp: DateTime<Utc>,
    pub event: String,
    pub src_ip: String,
    pub src_port: i32,
    pub dst_ip: String,
    pub dst_port: i32,
    pub status: String,
    // Additional fields needed by the connections tab
    pub process_name: String,
    pub process_id: u32,
    pub local_address: String,
    pub remote_address: String,
    pub protocol: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DataViewTab {
    Original,
    Modified,
    // Additional tabs can be added here in the future
    // Examples might include:
    // Decoded,
    // Formatted,
    // Hex,
}

impl Default for DataViewTab {
    fn default() -> Self {
        DataViewTab::Original
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            library_status: "".to_string(),
            library: None,
            current_tab: Tab::Intercept,
            current_data_view_tab: DataViewTab::Original,            current_config: ProxyConfig {
                bind_address: "127.0.0.1".to_string(),
                port: 4444,
                log_file: "tls_proxy.log".to_string(),
                verbose_mode: true, // Changed to true for better visibility of all messages
            },            config_inputs: ConfigInputs {
                selected_bind_address: Some("127.0.0.1".to_string()),
                available_ips: vec!["127.0.0.1".to_string()],
                port: "4444".to_string(),
                log_file: "tls_proxy.log".to_string(),
                verbose_mode: true, // Changed to true for better visibility of all messages
            },config_status: "".to_string(),

            stats: None,
            stats_status: "".to_string(),

            system_ips: Vec::new(),
            ips_status: "".to_string(),

            proxy_running: false,
            proxy_status: "Stopped".to_string(),            intercept_state: InterceptState {
                enabled: false,
                direction: InterceptDirection::None,
                current_intercept: None,
                pending_action: false,
                edited_data: String::new(),
            },history: VecDeque::new(),
            connections: VecDeque::new(),            selected_history_item: None,
            selected_connection: None,
            pane_state: Self::create_default_pane_state(),
        }
    }
}

impl AppState {    // Helper method to create a default pane state configuration
    fn create_default_pane_state() -> iced::widget::pane_grid::State<PaneContent> {
        iced::widget::pane_grid::State::with_configuration(
            iced::widget::pane_grid::Configuration::Split {
                axis: iced::widget::pane_grid::Axis::Horizontal,
                ratio: 0.6,
                a: Box::new(iced::widget::pane_grid::Configuration::Pane(PaneContent::HistoryTable)),
                b: Box::new(iced::widget::pane_grid::Configuration::Pane(PaneContent::DataView)),
            }
        )
    }

    // Reset pane state if it becomes corrupted
    pub fn reset_pane_state(&mut self) {
        self.pane_state = Self::create_default_pane_state();
    }

    pub fn handle_config_loaded(&mut self, result: Result<ProxyConfig, String>) {
        match result {
            Ok(config) => {
                self.config_status = "".to_string();
                self.current_config = config.clone();

                // Set the selected bind address from config
                self.config_inputs.selected_bind_address = Some(config.bind_address.clone());

                // Add the config bind address to available IPs if not already present
                if !self.config_inputs.available_ips.contains(&config.bind_address) {
                    self.config_inputs.available_ips.push(config.bind_address);
                }

                self.config_inputs.port = config.port.to_string();
                self.config_inputs.log_file = config.log_file;
                self.config_inputs.verbose_mode = config.verbose_mode;
            }
            Err(e) => {
                self.config_status = format!("Failed to load config: {}", e);
            }
        }
    }    pub fn handle_stats_loaded(&mut self, result: Result<ProxyStats, String>) {
        match result {
            Ok(stats) => {
                self.stats_status = "".to_string();
                self.stats = Some(stats);
            }
            Err(e) => {
                self.stats_status = format!("Failed to load stats: {}", e);
                self.stats = None;
            }
        }
    }    pub fn handle_system_ips_loaded(&mut self, result: Result<Vec<String>, String>) {
        match result {
            Ok(ips) => {
                self.ips_status = "".to_string();
                self.system_ips = ips.clone();

                // Update available IPs for dropdown, preserving any currently selected IP
                self.config_inputs.available_ips = ips;

                // If no IP is currently selected, default to first available (usually 127.0.0.1)
                if self.config_inputs.selected_bind_address.is_none() && !self.config_inputs.available_ips.is_empty() {
                    self.config_inputs.selected_bind_address = Some(self.config_inputs.available_ips[0].clone());
                }
            }
            Err(e) => {
                self.ips_status = format!("Failed to load IPs: {}", e);
                self.system_ips.clear();
                // Keep a fallback localhost option
                self.config_inputs.available_ips = vec!["127.0.0.1".to_string()];
                if self.config_inputs.selected_bind_address.is_none() {
                    self.config_inputs.selected_bind_address = Some("127.0.0.1".to_string());
                }
            }
        }
    }pub fn build_config_from_inputs(&self) -> Result<ProxyConfig, String> {
        let port = self.config_inputs.port
            .parse::<u16>()
            .map_err(|_| "Invalid port number")?;

        let bind_address = self.config_inputs.selected_bind_address
            .as_ref()
            .ok_or("No bind address selected")?;

        if self.config_inputs.log_file.is_empty() {
            return Err("Log file path cannot be empty".to_string());
        }

        Ok(ProxyConfig {
            bind_address: bind_address.clone(),
            port,
            log_file: self.config_inputs.log_file.clone(),
            verbose_mode: self.config_inputs.verbose_mode,
        })
    }    pub fn add_history_entry(&mut self, entry: HistoryEntry) {
        // Always add the entry as a new row - each packet state should be visible
        println!("Adding new history entry: conn={}, packet={}, type={}, modified={}",
            entry.connection_id, entry.packet_id, entry.message_type, entry.modified);

        // Keep only the last 1000 entries to prevent memory bloat
        if self.history.len() >= 1000 {
            self.history.pop_front();
        }
        self.history.push_back(entry);
    }

    pub fn add_connection_entry(&mut self, entry: ConnectionEntry) {
        // Keep only the last 500 connections to prevent memory bloat
        if self.connections.len() >= 500 {
            self.connections.pop_front();
        }
        self.connections.push_back(entry);
    }

    pub fn get_status_text(&self) -> String {
        if self.proxy_running {
            format!("Proxy running on {}:{}",
                   self.current_config.bind_address,
                   self.current_config.port)
        } else {
            "Proxy stopped".to_string()
        }
    }

    pub fn get_connection_stats(&self) -> (usize, usize) {
        let active_connections = self.connections
            .iter()
            .filter(|c| c.status == "Connected")
            .count();
        let total_connections = self.connections.len();
        (active_connections, total_connections)
    }
}
