use iced::{Application, Command, Element, Theme};
use std::sync::Arc;
use std::sync::mpsc;
use std::sync::Mutex;
use std::ffi::CStr;
use std::os::raw::c_char;

use crate::library::InterceptLibrary;
use crate::ui::{Message, AppState, styles};
use crate::ui::views::view as main_view;
use crate::ui::state::{ConnectionEntry, HistoryEntry};

// Global sender for sending messages from callbacks to the main application
static CALLBACK_SENDER: Mutex<Option<mpsc::Sender<Message>>> = Mutex::new(None);

unsafe extern "C" fn connection_callback(
    client_ip: *const c_char,
    client_port: i32,
    target_host: *const c_char,
    target_port: i32,
    connection_id: i32,
) {
    if client_ip.is_null() || target_host.is_null() {
        return;
    }

    let client_ip_str = CStr::from_ptr(client_ip).to_string_lossy().to_string();
    let target_host_str = CStr::from_ptr(target_host).to_string_lossy().to_string();

    let message = Message::ConnectionEvent {
        client_ip: client_ip_str,
        client_port,
        target_host: target_host_str,
        target_port,
        connection_id,
    };

    if let Ok(sender_guard) = CALLBACK_SENDER.lock() {
        if let Some(sender) = sender_guard.as_ref() {
            let _ = sender.send(message);
        }
    }
}

unsafe extern "C" fn disconnect_callback(connection_id: i32, reason: *const c_char) {
    let reason_str = if reason.is_null() {
        "Unknown".to_string()
    } else {
        CStr::from_ptr(reason).to_string_lossy().to_string()
    };

    let message = Message::DisconnectEvent {
        connection_id,
        reason: reason_str,
    };

    if let Ok(sender_guard) = CALLBACK_SENDER.lock() {
        if let Some(sender) = sender_guard.as_ref() {
            let _ = sender.send(message);
        }
    }
}

unsafe extern "C" fn log_callback(
    timestamp: *const c_char,
    connection_id: i32,
    packet_id: i32,
    src_ip: *const c_char,
    dst_ip: *const c_char,
    dst_port: i32,
    message_type: *const c_char,
    data: *const c_char,
) {
    if timestamp.is_null() || src_ip.is_null() || dst_ip.is_null() ||
       message_type.is_null() || data.is_null() {
        return;
    }

    let timestamp_str = CStr::from_ptr(timestamp).to_string_lossy().to_string();
    let src_ip_str = CStr::from_ptr(src_ip).to_string_lossy().to_string();
    let dst_ip_str = CStr::from_ptr(dst_ip).to_string_lossy().to_string();
    let message_type_str = CStr::from_ptr(message_type).to_string_lossy().to_string();
    let data_str = CStr::from_ptr(data).to_string_lossy().to_string();

    let message = Message::LogEvent {
        timestamp: timestamp_str,
        connection_id,
        packet_id,
        src_ip: src_ip_str,
        dst_ip: dst_ip_str,
        dst_port,
        message_type: message_type_str,
        data: data_str,
    };

    if let Ok(sender_guard) = CALLBACK_SENDER.lock() {
        if let Some(sender) = sender_guard.as_ref() {
            let _ = sender.send(message);
        }
    }
}

unsafe extern "C" fn intercept_callback(
    connection_id: i32,
    direction: *const c_char,
    src_ip: *const c_char,
    dst_ip: *const c_char,
    dst_port: i32,
    data: *const u8,
    data_length: i32,
    packet_id: i32,
) {
    if direction.is_null() || src_ip.is_null() || dst_ip.is_null() || data.is_null() {
        return;
    }

    let direction_str = CStr::from_ptr(direction).to_string_lossy().to_string();
    let src_ip_str = CStr::from_ptr(src_ip).to_string_lossy().to_string();
    let dst_ip_str = CStr::from_ptr(dst_ip).to_string_lossy().to_string();

    // Convert the raw data to a Vec<u8>
    let data_vec = if data_length > 0 {
        std::slice::from_raw_parts(data, data_length as usize).to_vec()
    } else {
        Vec::new()
    };

    let message = Message::InterceptDataReceived {
        connection_id,
        packet_id,
        direction: direction_str,
        src_ip: src_ip_str,
        dst_ip: dst_ip_str,
        dst_port,
        data: data_vec,
    };

    if let Ok(sender_guard) = CALLBACK_SENDER.lock() {
        if let Some(sender) = sender_guard.as_ref() {
            let _ = sender.send(message);
        }
    }
}

#[derive(Debug)]
pub struct InterceptApp {
    pub library: Option<Arc<InterceptLibrary>>,
    pub state: AppState,
}

impl Default for InterceptApp {
    fn default() -> Self {
        Self {
            library: None,
            state: AppState::default(),
        }
    }
}

impl Application for InterceptApp {
    type Message = Message;
    type Theme = Theme;
    type Executor = iced::executor::Default;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        let app = Self::default();

        // Load library on startup
        let command = Command::perform(
            async {
                match InterceptLibrary::new() {
                    Ok(lib) => Ok(Arc::new(lib)),
                    Err(e) => Err(e.to_string()),
                }
            },
            Message::LibraryLoaded,
        );

        (app, command)
    }

    fn title(&self) -> String {
        "TLS Intercept Suite - Rust GUI".to_string()
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {            Message::LibraryLoaded(result) => {
                match result {
                    Ok(lib) => {
                        self.state.library_status = "".to_string();
                        self.library = Some(lib.clone());
                        self.state.library = Some(lib.clone()); // Sync state

                        // Set up the callback channel
                        let (sender, _receiver) = mpsc::channel();

                        // Store sender in global mutex for callbacks to use
                        if let Ok(mut sender_guard) = CALLBACK_SENDER.lock() {
                            *sender_guard = Some(sender);
                        }                        // Register callbacks with the DLL
                        lib.set_connection_callback(connection_callback);
                        lib.set_disconnect_callback(disconnect_callback);
                        lib.set_log_callback(log_callback);
                        lib.set_intercept_callback(intercept_callback);

                        println!("Registered connection, disconnect, log, and intercept callbacks with DLL");

                        // Auto-load initial data
                        return Command::batch([
                            Command::perform(async {}, |_| Message::LoadConfig),
                            Command::perform(async {}, |_| Message::LoadStats),
                            Command::perform(async {}, |_| Message::LoadSystemIps),
                        ]);
                    }
                    Err(e) => {
                        self.state.library_status = format!("Failed to load library: {}", e);
                        self.library = None;
                        self.state.library = None; // Sync state
                    }
                }
            }
              Message::TabSelected(tab) => {
                self.state.current_tab = tab;
            }

            Message::ConfigLoaded(result) => {
                self.state.handle_config_loaded(result);
            }

            Message::StatsLoaded(result) => {
                self.state.handle_stats_loaded(result);
            }

            Message::SystemIpsLoaded(result) => {
                self.state.handle_system_ips_loaded(result);
            }            Message::BindAddressSelected(value) => {
                self.state.config_inputs.selected_bind_address = Some(value);
            }

            Message::PortChanged(value) => {
                self.state.config_inputs.port = value;
            }

            Message::LogFileChanged(value) => {
                self.state.config_inputs.log_file = value;
            }

            Message::VerboseModeToggled(value) => {
                self.state.config_inputs.verbose_mode = value;
            }

            Message::LoadConfig => {
                if let Some(lib) = &self.library {
                    let lib = lib.clone();
                    return Command::perform(
                        async move {
                            lib.get_config().map_err(|e| e.to_string())
                        },
                        Message::ConfigLoaded,
                    );
                }
            }

            Message::LoadStats => {
                if let Some(lib) = &self.library {
                    let lib = lib.clone();
                    return Command::perform(
                        async move {
                            lib.get_stats().map_err(|e| e.to_string())
                        },
                        Message::StatsLoaded,
                    );
                }
            }

            Message::LoadSystemIps => {
                if let Some(lib) = &self.library {
                    let lib = lib.clone();
                    return Command::perform(
                        async move {
                            lib.get_system_ips().map_err(|e| e.to_string())
                        },
                        Message::SystemIpsLoaded,
                    );
                }
            }

            Message::SaveConfig => {
                if let Some(lib) = &self.library {
                    let config = self.state.build_config_from_inputs();
                    if let Ok(config) = config {
                        let lib = lib.clone();
                        return Command::perform(
                            async move {
                                lib.set_config(&config).map_err(|e| e.to_string())
                            },
                            |result| match result {
                                Ok(_) => Message::ConfigSaved,
                                Err(e) => Message::ConfigSaveError(e),
                            },
                        );
                    } else {
                        self.state.config_status = format!("✗ Invalid configuration: {}", config.unwrap_err());
                    }
                }
            }            Message::ConfigSaved => {
                // Configuration saved successfully - no status message needed
            }

            Message::ConfigSaveError(error) => {
                self.state.config_status = format!("Failed to save config: {}", error);
            }            // Proxy control messages
            Message::StartProxy => {
                if let Some(library) = &self.state.library {
                    self.state.proxy_status = "Starting proxy...".to_string();
                    let library_clone = Arc::clone(library);
                    return Command::perform(
                        async move {
                            match library_clone.start_proxy() {
                                Ok(()) => Message::ProxyStarted,
                                Err(e) => Message::ProxyStartError(e.to_string()),
                            }
                        },
                        |result| result,
                    );
                } else {
                    self.state.proxy_status = "✗ Library not loaded".to_string();
                }
            }            Message::StopProxy => {
                if let Some(library) = &self.state.library {
                    self.state.proxy_status = "Stopping proxy...".to_string();
                    let library_clone = Arc::clone(library);
                    return Command::perform(
                        async move {
                            library_clone.stop_proxy();
                            Message::ProxyStopped
                        },
                        |result| result,
                    );
                } else {
                    self.state.proxy_status = "✗ Library not loaded".to_string();
                }
            }

            Message::ProxyStarted => {
                self.state.proxy_running = true;
                self.state.proxy_status = "Running".to_string();
            }

            Message::ProxyStartError(error) => {
                self.state.proxy_running = false;
                self.state.proxy_status = format!("✗ Failed to start: {}", error);
            }

            Message::ProxyStopped => {
                self.state.proxy_running = false;
                self.state.proxy_status = "Stopped".to_string();
            }

            Message::ProxyStopError(error) => {
                // Even if stop failed, consider proxy as stopped
                self.state.proxy_running = false;
                self.state.proxy_status = format!("Stopped (with error: {})", error);
            }            // Intercept messages
            Message::InterceptEnabledToggled(enabled) => {
                self.state.intercept_state.enabled = enabled;

                // Call the DLL function to actually enable/disable interception
                if let Some(library) = &self.library {
                    println!("Setting intercept enabled: {}", enabled);

                    // Enable verbose mode when intercept is on to ensure we see all messages
                    if enabled {
                        // Get current config
                        if let Ok(mut config) = library.get_config() {
                            // Enable verbose mode if not already enabled
                            if !config.verbose_mode {
                                config.verbose_mode = true;
                                let _ = library.set_config(&config);
                                println!("Enabled verbose mode to support interception");
                            }
                        }
                    }

                    // Set intercept enabled state in DLL
                    library.set_intercept_enabled(enabled);

                    // Register callback if needed
                    library.set_intercept_callback(intercept_callback);

                    // If we have a direction setting, make sure it's applied
                    library.set_intercept_direction(self.state.intercept_state.direction as i32);

                    println!("Intercept direction set to: {}",
                             self.state.intercept_state.direction.as_str());
                }
            }

            Message::InterceptDirectionChanged(direction) => {
                self.state.intercept_state.direction = direction;
                // Call the DLL function to actually set the intercept direction
                if let Some(library) = &self.library {
                    library.set_intercept_direction(direction as i32);
                }
            }            Message::InterceptDataReceived {
                connection_id,
                packet_id,
                direction,
                src_ip,
                dst_ip,
                dst_port,
                data,
            } => {
                // Add enhanced logging for intercepted data
                println!("INTERCEPT: Received data for connection {} (packet {}), direction '{}', size {} bytes",
                    connection_id, packet_id, direction, data.len());

                // Check if we already have an entry for this packet (from LogEvent)
                let has_existing_entry = self.state.history.iter().any(|entry| {
                    entry.connection_id == connection_id && entry.packet_id == packet_id
                });                // If no existing entry, create one immediately so user can see intercepted data
                if !has_existing_entry {
                    let message_type = format!("Intercepted ({})", direction);
                    let history_entry = HistoryEntry {
                        id: self.state.history.len(),
                        connection_id,
                        packet_id,
                        timestamp: chrono::Utc::now(),
                        src_ip: src_ip.clone(),
                        dst_ip: dst_ip.clone(),
                        dst_port,
                        message_type,
                        data_text: None,              // No text data for intercept events
                        data_bytes: Some(data.clone()), // Store as raw bytes
                        modified_data: None,
                        modified: false,
                    };

                    println!("Adding new intercepted history entry for conn={}, packet={}", connection_id, packet_id);
                    self.state.add_history_entry(history_entry);
                } else {
                    println!("Found existing history entry for conn={}, packet={}, will update it", connection_id, packet_id);
                }

                // Create a stable clone of the data to work with
                let data_for_intercept = data.clone();

                // Now create intercept data object
                let intercept_data = crate::ui::state::InterceptData {
                    connection_id,
                    packet_id,
                    direction: direction.clone(),
                    src_ip: src_ip.clone(),
                    dst_ip: dst_ip.clone(),
                    dst_port,
                    data: data_for_intercept,
                    timestamp: chrono::Utc::now(),
                };

                // Convert data to string for editing (assuming UTF-8, fallback to hex if invalid)
                let data_as_string = String::from_utf8(data.clone())
                    .unwrap_or_else(|_| {
                        // If not valid UTF-8, show as hex
                        data.iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ")
                    });

                // Log detailed message about the interception
                println!("Intercepted {} bytes ({} direction) from {}:{} to {}:{} (connection {})",
                    data.len(),
                    direction,
                    src_ip,
                    "unknown",
                    dst_ip,
                    dst_port,
                    connection_id);

                // Store the intercept data and set up for editing
                self.state.intercept_state.current_intercept = Some(intercept_data);
                self.state.intercept_state.edited_data = data_as_string;
                self.state.intercept_state.pending_action = true;

                // Switch to intercept tab to make sure user sees the intercept
                if self.state.current_tab != crate::ui::messages::Tab::Intercept {
                    self.state.current_tab = crate::ui::messages::Tab::Intercept;
                }
            }

            Message::InterceptDataEdited(new_data) => {
                self.state.intercept_state.edited_data = new_data;
            }

            Message::InterceptDataClear => {
                self.state.intercept_state.current_intercept = None;
                self.state.intercept_state.edited_data.clear();
                self.state.intercept_state.pending_action = false;
            }

            Message::ForwardIntercept => {
                if let (Some(intercept_data), Some(library)) =
                    (&self.state.intercept_state.current_intercept, &self.library) {

                    // Extract connection ID for logging
                    let connection_id = intercept_data.connection_id;                    // Convert edited data back to bytes - handle different formats
                    let data_to_send = if self.state.intercept_state.edited_data.trim().is_empty() {
                        // If edited data is empty, use original data
                        intercept_data.data.clone()
                    } else if self.state.intercept_state.edited_data.contains(' ') {
                        // Assume hex format if contains spaces
                        let parsed_data = self.state.intercept_state.edited_data
                            .split_whitespace()
                            .filter_map(|hex_str| u8::from_str_radix(hex_str, 16).ok())
                            .collect::<Vec<u8>>();

                        if parsed_data.is_empty() {
                            // If hex parsing failed, try as UTF-8 string instead
                            self.state.intercept_state.edited_data.as_bytes().to_vec()
                        } else {
                            parsed_data
                        }
                    } else {
                        // Assume UTF-8 string
                        self.state.intercept_state.edited_data.as_bytes().to_vec()
                    };                    // Log exactly what's being sent
                    println!("===== INTERCEPT FORWARD DEBUG =====");
                    println!("Original data ({} bytes): {:?}",
                        intercept_data.data.len(),
                        String::from_utf8_lossy(&intercept_data.data[..std::cmp::min(intercept_data.data.len(), 50)]));
                    println!("Edited data: '{}'", self.state.intercept_state.edited_data);
                    println!("Data to send ({} bytes): {:?}",
                        data_to_send.len(),
                        String::from_utf8_lossy(&data_to_send[..std::cmp::min(data_to_send.len(), 50)]));
                    println!("=====================================");

                    // Create a stable reference to the data to ensure it stays valid during the call
                    let data_to_send_ref = data_to_send.as_slice();                    // Determine the correct action based on whether data was modified
                    // Compare the data_to_send with the original data to see if it was actually changed
                    let data_was_modified = if self.state.intercept_state.edited_data.trim().is_empty() {
                        false // No edits made
                    } else {
                        data_to_send != intercept_data.data // Compare byte arrays
                    };

                    let action = if data_was_modified {
                        2 // INTERCEPT_ACTION_MODIFY - use modified data
                    } else {
                        0 // INTERCEPT_ACTION_FORWARD - use original data
                    };

                    println!("Data was modified: {}, using action: {}", data_was_modified, action);
                    library.respond_to_intercept(
                        connection_id,
                        action,
                        Some(data_to_send_ref),
                    );                    // Update the existing entry in history using packet_id as the unique identifier
                    if let Some(existing_entry) = self.state.history.iter_mut().find(|entry| {
                        entry.connection_id == intercept_data.connection_id &&
                        entry.packet_id == intercept_data.packet_id
                    }) {
                        println!("Updating existing history entry (conn={}, packet={}) to show forwarded action",
                            intercept_data.connection_id, intercept_data.packet_id);

                        // Update the existing entry to show it was forwarded
                        existing_entry.modified = data_was_modified;
                        if data_was_modified {
                            existing_entry.modified_data = Some(data_to_send.clone());
                        }
                        existing_entry.message_type = format!("Forwarded-{}", intercept_data.direction);
                        existing_entry.timestamp = chrono::Utc::now();
                    } else {
                        println!("Warning: Could not find existing history entry to update for conn={}, packet={}",
                            intercept_data.connection_id, intercept_data.packet_id);
                    }

                    // Clear the intercept state after forwarding
                    self.state.intercept_state.current_intercept = None;
                    self.state.intercept_state.edited_data.clear();
                    self.state.intercept_state.pending_action = false;
                }
            }

            Message::DropIntercept => {
                if let (Some(intercept_data), Some(library)) =
                    (&self.state.intercept_state.current_intercept, &self.library) {

                    // Get connection ID for logging
                    let connection_id = intercept_data.connection_id;
                      // Log what's being dropped
                    println!("Dropping intercepted data ({} bytes) for connection {}",
                        intercept_data.data.len(), connection_id);                    // According to include/tls_proxy.h: INTERCEPT_ACTION_DROP = 1
                    library.respond_to_intercept(
                        connection_id,
                        1, // 1 = INTERCEPT_ACTION_DROP
                        None,
                    );                    // Update the existing entry in history using packet_id as the unique identifier
                    if let Some(existing_entry) = self.state.history.iter_mut().find(|entry| {
                        entry.connection_id == intercept_data.connection_id &&
                        entry.packet_id == intercept_data.packet_id
                    }) {
                        println!("Updating existing history entry (conn={}, packet={}) to show dropped action",
                            intercept_data.connection_id, intercept_data.packet_id);

                        // Update the existing entry to show it was dropped
                        existing_entry.modified = true; // Mark as modified since it was dropped
                        existing_entry.message_type = format!("Dropped-{}", intercept_data.direction);
                        existing_entry.timestamp = chrono::Utc::now();
                    } else {
                        println!("Warning: Could not find existing history entry to update for conn={}, packet={}",
                            intercept_data.connection_id, intercept_data.packet_id);
                    }

                    // Clear the intercept state
                    self.state.intercept_state.current_intercept = None;
                    self.state.intercept_state.edited_data.clear();
                    self.state.intercept_state.pending_action = false;
                }
            }// History and connections management
            Message::ClearHistory => {
                self.state.history.clear();
            }

            Message::ExportHistory => {
                // TODO: Implement history export
            }

            Message::HistoryItemSelected(index) => {
                self.state.selected_history_item = Some(index);
            }

            Message::HistoryTableArrowKey(direction) => {
                if !self.state.history.is_empty() {
                    let current_selection = self.state.selected_history_item.unwrap_or(0);
                    let new_selection = if direction > 0 {
                        // Down arrow - move to next item
                        (current_selection + 1).min(self.state.history.len() - 1)
                    } else {
                        // Up arrow - move to previous item
                        current_selection.saturating_sub(1)
                    };
                    self.state.selected_history_item = Some(new_selection);
                }
            }            Message::DataViewTabSelected(tab) => {
                // Only allow switching to Modified tab if the selected entry is actually modified
                if tab == crate::ui::state::DataViewTab::Modified {
                    if let Some(selected_index) = self.state.selected_history_item {
                        if let Some(entry) = self.state.history.get(selected_index) {
                            if entry.modified {
                                self.state.current_data_view_tab = tab;
                            }
                            // If not modified, stay on current tab (don't switch)
                        }
                    }
                } else {
                    // Always allow switching to Original tab
                    self.state.current_data_view_tab = tab;
                }
            }

            Message::ClearConnections => {
                self.state.connections.clear();
            }

            Message::ExportConnections => {
                // TODO: Implement connections export
            }

            Message::RefreshConnections => {
                // Refresh connections - could trigger a reload from DLL
                // For now, this is handled automatically by callbacks
            }

            Message::ConnectionSelected(index) => {
                self.state.selected_connection = Some(index);
            }

            Message::ViewConnectionDetails(_index) => {
                // TODO: Implement connection details view
            }

            Message::TerminateConnection(_index) => {
                // TODO: Implement connection termination
            }

            // Connection events from DLL callbacks
            Message::ConnectionEvent {
                client_ip,
                client_port,
                target_host,
                target_port,
                connection_id,
            } => {                let connection_entry = ConnectionEntry {
                    id: connection_id as usize,
                    timestamp: chrono::Local::now().into(),
                    event: "Connected".to_string(),
                    connection_id: connection_id,
                    src_ip: client_ip.clone(),
                    src_port: client_port,
                    dst_ip: target_host.clone(),
                    dst_port: target_port,
                    status: "Connected".to_string(),
                    process_name: "Unknown".to_string(),
                    process_id: 0,
                    local_address: format!("{}:{}", client_ip, client_port),
                    remote_address: format!("{}:{}", target_host, target_port),
                    protocol: "TCP".to_string(),
                };
                self.state.add_connection_entry(connection_entry);
            }            Message::DisconnectEvent {
                connection_id,
                reason,
            } => {                let connection_entry = ConnectionEntry {
                    id: connection_id as usize,
                    timestamp: chrono::Local::now().into(),
                    event: "Disconnected".to_string(),
                    connection_id: connection_id,
                    src_ip: "".to_string(),
                    src_port: 0,
                    dst_ip: reason.clone(),
                    dst_port: 0,
                    status: "Disconnected".to_string(),
                    process_name: "Unknown".to_string(),
                    process_id: 0,
                    local_address: "".to_string(),
                    remote_address: reason,
                    protocol: "TCP".to_string(),
                };
                self.state.add_connection_entry(connection_entry);
            }            Message::LogEvent {
                timestamp,
                connection_id,
                packet_id,
                src_ip,
                dst_ip,
                dst_port,
                message_type,
                data,
            } => {
                // Parse the timestamp string into a DateTime
                let timestamp_dt = match chrono::DateTime::parse_from_str(
                    &format!("{} +0000", timestamp), // Assuming UTC
                    "%Y-%m-%d %H:%M:%S %z"
                ) {
                    Ok(dt) => dt.with_timezone(&chrono::Utc),
                    Err(_) => chrono::Utc::now(), // Fallback to current time if parsing fails
                };                // Store data as text since it comes from log callback as string
                let data_text = data.clone();// Determine if this is client-to-server or server-to-client
                let is_client_to_server = message_type.contains("Client→Server");
                let is_server_to_client = message_type.contains("Server→Client");                // Enhanced logging to help debug
                println!("[LOG EVENT] Conn: {} | Packet: {} | {} | {} → {}:{} | {} | {} chars",
                    connection_id,
                    packet_id,
                    timestamp,
                    src_ip,
                    dst_ip,
                    dst_port,
                    message_type,
                    data_text.len());

                // Create a history entry from the log event
                let message_type_clean = message_type.trim().to_string();                // Skip adding history entries for forwarded/dropped intercept actions
                // since we handle those manually in ForwardIntercept/DropIntercept handlers
                let is_intercept_action = message_type_clean.contains("Forwarded") ||
                                         message_type_clean.contains("Dropped");                // Check if we already have an entry for this connection_id + packet_id combination
                // This prevents duplicate entries when both intercept and log callbacks are triggered
                let has_existing_entry = self.state.history.iter().any(|entry| {
                    entry.connection_id == connection_id && entry.packet_id == packet_id
                });

                // Only add to history if either:
                // 1. It's a client-to-server message, or
                // 2. It's a server-to-client message and verbose mode is enabled, or
                // 3. The message type doesn't contain directional markers
                // AND it's not an intercept action (forwarded/dropped)
                // AND we don't already have an entry for this packet
                let should_add_to_history = !is_intercept_action &&
                                           !has_existing_entry &&
                                           (is_client_to_server ||
                                           (is_server_to_client && self.state.config_inputs.verbose_mode) ||
                                           (!is_client_to_server && !is_server_to_client));                if should_add_to_history {
                    let history_entry = HistoryEntry {
                        id: self.state.history.len(),
                        connection_id,
                        packet_id,
                        timestamp: timestamp_dt,
                        src_ip,
                        dst_ip,
                        dst_port,
                        message_type: message_type_clean,
                        data_text: Some(data_text),  // Store as text
                        data_bytes: None,            // No byte data for log events
                        modified_data: None,
                        modified: false,
                    };self.state.add_history_entry(history_entry);                } else {
                    if is_intercept_action {
                        println!("Skipping history entry for intercept action '{}' (handled manually)", message_type_clean);
                    } else if has_existing_entry {
                        println!("Skipping duplicate history entry for conn={}, packet={} (already exists)", connection_id, packet_id);
                    } else {
                        println!("Skipping history entry for server-to-client message (verbose mode off)");
                    }
                }
            }            Message::PaneResized(event) => {
                self.state.pane_state.resize(event.split, event.ratio);
            }

            _ => {
                // Handle other messages as needed
            }
        }

        Command::none()
    }    fn view(&self) -> Element<Message> {
        main_view(&self.state)
    }

    fn theme(&self) -> Theme {
        styles::create_dark_theme()
    }    fn subscription(&self) -> iced::Subscription<Message> {
        use iced::event::{self, Event};
        use iced::keyboard::{Key, self};

        let callback_subscription = if self.library.is_some() {
            // Create a custom subscription for callback channel messages
            struct CallbackMessages;

            iced::subscription::channel(
                std::any::TypeId::of::<CallbackMessages>(),
                100, // Capacity
                |mut output| async move {
                    // Create a thread for handling callback messages
                    std::thread::spawn(move || {
                        // Create a local channel
                        let (sender, receiver) = mpsc::channel();

                        // Replace the global channel
                        if let Ok(mut guard) = CALLBACK_SENDER.lock() {
                            *guard = Some(sender);
                        }

                        // Process messages from the DLL callbacks
                        while let Ok(message) = receiver.recv() {
                            if output.try_send(message).is_err() {
                                // Queue is full or closed
                                break;
                            }
                        }
                    });

                    // This keeps the subscription alive
                    loop {
                        iced::futures::future::pending::<()>().await;
                    }
                },
            )
        } else {
            iced::Subscription::none()
        };

        let is_proxy_history_tab = self.state.current_tab == crate::ui::messages::Tab::ProxyHistory;
        let keyboard_subscription = if is_proxy_history_tab {
            event::listen().map(|event| {
                match event {
                    Event::Keyboard(keyboard::Event::KeyPressed {
                        key: Key::Named(keyboard::key::Named::ArrowDown),
                        ..
                    }) => Message::HistoryTableArrowKey(1),
                    Event::Keyboard(keyboard::Event::KeyPressed {
                        key: Key::Named(keyboard::key::Named::ArrowUp),
                        ..
                    }) => Message::HistoryTableArrowKey(-1),
                    _ => Message::TabSelected(crate::ui::messages::Tab::ProxyHistory), // No-op message
                }
            })
        } else {
            iced::Subscription::none()
        };

        iced::Subscription::batch([callback_subscription, keyboard_subscription])
    }
}
