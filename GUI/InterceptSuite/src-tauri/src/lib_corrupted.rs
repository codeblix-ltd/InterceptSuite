// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

use std::ffi::{CString, CStr};
use std::os::raw::{c_char, c_int};
use std::sync::{Arc, Mutex, Once};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use libloading::{Library, Symbol};
use serde::{Serialize, Deserialize};
use anyhow::{Result, Context};
use tauri::{AppHandle, Emitter};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProxySettings {
    #[serde(rename = "listenPort")]
    pub listen_port: i32,
    #[serde(rename = "targetHost")]
    pub target_host: String,
    #[serde(rename = "enableLogging")]
    pub enable_logging: bool,
    #[serde(rename = "logFilePath")]
    pub log_file_path: String,
}

// Define ProxyHistoryEntry for storing proxy log data
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProxyHistoryEntry {
    pub id: String,
    pub timestamp: String,
    pub connection_id: i32,
    pub packet_id: i32,  // Hidden in UI but used for tracking
    pub packet_key: String,  // Unique key for deduplication
    pub source_ip: String,
    pub destination_ip: String,
    pub destination_port: i32,
    pub message_type: String,
    pub data: String,  // Raw message data that will be displayed in the bottom panel
    pub modified: bool,  // Indicates if packet was modified in Intercept tab
    pub edited_data: Option<String>,  // Optional edited data if packet was modified
}



#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkInterface {
    pub value: String,
    pub label: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectionEvent {
    pub id: String,
    pub timestamp: String,
    pub event: String,
    #[serde(rename = "connectionId")]
    pub connection_id: i32,
    #[serde(rename = "sourceIp")]
    pub source_ip: String,
    #[serde(rename = "sourcePort")]
    pub source_port: i32,
    #[serde(rename = "destinationIp")]
    pub destination_ip: String,
    #[serde(rename = "destinationPort")]
    pub destination_port: i32,
}

// Function pointer types for the DLL - matching actual C API
type StartProxyFn = unsafe extern "C" fn() -> c_int;
type StopProxyFn = unsafe extern "C" fn();
type SetConfigFn = unsafe extern "C" fn(*const c_char, c_int, *const c_char, c_int) -> c_int;
type GetSystemIpsFn = unsafe extern "C" fn(*mut c_char, c_int) -> c_int;

// Define the proxy_config_t struct to match the C structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    bind_addr: [c_char; 64],
    port: c_int,
    log_file: [c_char; 256],
    verbose_mode: c_int,
    is_running: c_int,
}

// Add serialization for frontend
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProxyConfigResponse {
    pub bind_addr: String,
    pub port: i32,
    pub log_file: String,
    pub verbose_mode: bool,
    pub is_running: bool,
}

// Define the function type for get_proxy_config
type GetProxyConfigFn = unsafe extern "C" fn() -> ProxyConfig;

// Callback function types
type LogCallbackFn = unsafe extern "C" fn(*const c_char, c_int, c_int, *const c_char, *const c_char, c_int, *const c_char, *const c_char);
type StatusCallbackFn = unsafe extern "C" fn(*const c_char);
type ConnectionCallbackFn = unsafe extern "C" fn(*const c_char, c_int, *const c_char, c_int, c_int);
type StatsCallbackFn = unsafe extern "C" fn(c_int, c_int, c_int);
type DisconnectCallbackFn = unsafe extern "C" fn(c_int, *const c_char);
type InterceptCallbackFn = unsafe extern "C" fn(c_int, *const c_char, *const c_char, *const c_char, c_int, *const u8, c_int, c_int);

// Callback setter function types
type SetLogCallbackFn = unsafe extern "C" fn(LogCallbackFn);
type SetStatusCallbackFn = unsafe extern "C" fn(StatusCallbackFn);
type SetConnectionCallbackFn = unsafe extern "C" fn(ConnectionCallbackFn);
type SetStatsCallbackFn = unsafe extern "C" fn(StatsCallbackFn);
type SetDisconnectCallbackFn = unsafe extern "C" fn(DisconnectCallbackFn);
type SetInterceptCallbackFn = unsafe extern "C" fn(InterceptCallbackFn);

// Interception control function types
type SetInterceptEnabledFn = unsafe extern "C" fn(c_int);
type SetInterceptDirectionFn = unsafe extern "C" fn(c_int);
type RespondToInterceptFn = unsafe extern "C" fn(c_int, c_int, *const u8, c_int);

#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptStatus {
    pub is_enabled: c_int,
    pub direction: c_int,
}

// Add serialization for frontend
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InterceptStatusResponse {
    pub is_enabled: bool,
    pub direction: String,
}

// Define the function type for get_intercept_config
type GetInterceptConfigFn = unsafe extern "C" fn() -> InterceptStatus;

pub struct InterceptLibrary {
    #[allow(dead_code)]
    library: Library,

    // Core functions matching actual C API
    start_proxy: StartProxyFn,
    stop_proxy: StopProxyFn,
    set_config: SetConfigFn,
    get_system_ips: GetSystemIpsFn,
    get_proxy_config: GetProxyConfigFn,
    get_intercept_config: GetInterceptConfigFn, // Add the new function

    // Callback setters
    set_log_callback: SetLogCallbackFn,
    set_status_callback: SetStatusCallbackFn,
    set_connection_callback: SetConnectionCallbackFn,
    set_stats_callback: SetStatsCallbackFn,
    set_disconnect_callback: SetDisconnectCallbackFn,
    set_intercept_callback: SetInterceptCallbackFn,

    // Interception control
    set_intercept_enabled: SetInterceptEnabledFn,
    set_intercept_direction: SetInterceptDirectionFn,
    respond_to_intercept: RespondToInterceptFn,
}

impl InterceptLibrary {
    pub fn new() -> Result<Self> {
        let library_name = if cfg!(target_os = "windows") {
            "Intercept.dll"
        } else if cfg!(target_os = "macos") {
            "libIntercept.dylib"
        } else {
            "libIntercept.so"
        };

        // Try multiple paths for the library
        let possible_paths = vec![
            library_name.to_string(),
            format!(".//{}", library_name),
            format!("../{}", library_name),
            format!("../../{}", library_name),
            format!("../../../{}", library_name),
        ];

        let mut library = None;
        let mut last_error = String::new();

        for path in possible_paths {
            match unsafe { Library::new(&path) } {
                Ok(lib) => {
                    library = Some(lib);
                    break;
                }
                Err(e) => {
                    last_error = format!("Failed to load {}: {}", path, e);
                }
            }
        }

        let library = library.ok_or_else(|| anyhow::anyhow!("Failed to load library: {}", last_error))?;

        unsafe {
            // Core functions
            let start_proxy: Symbol<StartProxyFn> = library
                .get(b"start_proxy")
                .context("Failed to get start_proxy")?;
            let start_proxy = std::mem::transmute(start_proxy.into_raw());

            let stop_proxy: Symbol<StopProxyFn> = library
                .get(b"stop_proxy")
                .context("Failed to get stop_proxy")?;
            let stop_proxy = std::mem::transmute(stop_proxy.into_raw());

            let set_config: Symbol<SetConfigFn> = library
                .get(b"set_config")
                .context("Failed to get set_config")?;
            let set_config = std::mem::transmute(set_config.into_raw());

            let get_system_ips: Symbol<GetSystemIpsFn> = library
                .get(b"get_system_ips")
                .context("Failed to get get_system_ips")?;
            let get_system_ips = std::mem::transmute(get_system_ips.into_raw());

            // Load get_proxy_config function
            let get_proxy_config: Symbol<GetProxyConfigFn> = library
                .get(b"get_proxy_config")
                .context("Failed to get get_proxy_config")?;
            let get_proxy_config = std::mem::transmute(get_proxy_config.into_raw());

            // Load get_intercept_config function
            let get_intercept_config: Symbol<GetInterceptConfigFn> = library
                .get(b"get_intercept_config")
                .context("Failed to get get_intercept_config")?;
            let get_intercept_config = std::mem::transmute(get_intercept_config.into_raw());

            // Callback setters
            let set_log_callback: Symbol<SetLogCallbackFn> = library
                .get(b"set_log_callback")
                .context("Failed to get set_log_callback")?;
            let set_log_callback = std::mem::transmute(set_log_callback.into_raw());

            let set_status_callback: Symbol<SetStatusCallbackFn> = library
                .get(b"set_status_callback")
                .context("Failed to get set_status_callback")?;
            let set_status_callback = std::mem::transmute(set_status_callback.into_raw());

            let set_connection_callback: Symbol<SetConnectionCallbackFn> = library
                .get(b"set_connection_callback")
                .context("Failed to get set_connection_callback")?;
            let set_connection_callback = std::mem::transmute(set_connection_callback.into_raw());

            let set_stats_callback: Symbol<SetStatsCallbackFn> = library
                .get(b"set_stats_callback")
                .context("Failed to get set_stats_callback")?;
            let set_stats_callback = std::mem::transmute(set_stats_callback.into_raw());

            let set_disconnect_callback: Symbol<SetDisconnectCallbackFn> = library
                .get(b"set_disconnect_callback")
                .context("Failed to get set_disconnect_callback")?;
            let set_disconnect_callback = std::mem::transmute(set_disconnect_callback.into_raw());

            let set_intercept_callback: Symbol<SetInterceptCallbackFn> = library
                .get(b"set_intercept_callback")
                .context("Failed to get set_intercept_callback")?;
            let set_intercept_callback = std::mem::transmute(set_intercept_callback.into_raw());

            // Interception control
            let set_intercept_enabled: Symbol<SetInterceptEnabledFn> = library
                .get(b"set_intercept_enabled")
                .context("Failed to get set_intercept_enabled")?;
            let set_intercept_enabled = std::mem::transmute(set_intercept_enabled.into_raw());

            let set_intercept_direction: Symbol<SetInterceptDirectionFn> = library
                .get(b"set_intercept_direction")
                .context("Failed to get set_intercept_direction")?;
            let set_intercept_direction = std::mem::transmute(set_intercept_direction.into_raw());

            let respond_to_intercept: Symbol<RespondToInterceptFn> = library
                .get(b"respond_to_intercept")
                .context("Failed to get respond_to_intercept")?;
            let respond_to_intercept = std::mem::transmute(respond_to_intercept.into_raw());

            Ok(InterceptLibrary {
                library,
                start_proxy,
                stop_proxy,
                set_config,
                get_system_ips,
                get_proxy_config,
                get_intercept_config,
                set_log_callback,
                set_status_callback,
                set_connection_callback,
                set_stats_callback,
                set_disconnect_callback,
                set_intercept_callback,
                set_intercept_enabled,
                set_intercept_direction,
                respond_to_intercept,
            })
        }
    }

    pub fn set_log_callback(&self, callback: LogCallbackFn) -> Result<()> {
        unsafe { (self.set_log_callback)(callback) };
        Ok(())
    }

    pub fn set_status_callback(&self, callback: StatusCallbackFn) -> Result<()> {
        unsafe { (self.set_status_callback)(callback) };
        Ok(())
    }

    pub fn set_connection_callback(&self, callback: ConnectionCallbackFn) -> Result<()> {
        unsafe { (self.set_connection_callback)(callback) };
        Ok(())
    }

    pub fn set_stats_callback(&self, callback: StatsCallbackFn) -> Result<()> {
        unsafe { (self.set_stats_callback)(callback) };
        Ok(())
    }

    pub fn set_disconnect_callback(&self, callback: DisconnectCallbackFn) -> Result<()> {
        unsafe { (self.set_disconnect_callback)(callback) };
        Ok(())
    }

    pub fn get_proxy_config(&self) -> Result<ProxyConfigResponse> {
        let config = unsafe { (self.get_proxy_config)() };

        // Convert C char arrays to Rust strings
        let bind_addr = unsafe {
            CStr::from_ptr(config.bind_addr.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        let log_file = unsafe {
            CStr::from_ptr(config.log_file.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        Ok(ProxyConfigResponse {
            bind_addr,
            port: config.port,
            log_file,
            verbose_mode: config.verbose_mode != 0,
            is_running: config.is_running != 0,
        })
    }

    pub fn set_intercept_callback(&self, callback: InterceptCallbackFn) -> Result<()> {
        unsafe { (self.set_intercept_callback)(callback) };
        Ok(())
    }

    pub fn set_intercept_enabled(&self, enabled: bool) -> Result<()> {
        unsafe { (self.set_intercept_enabled)(if enabled { 1 } else { 0 }) };
        Ok(())
    }

    pub fn set_intercept_direction(&self, direction: i32) -> Result<()> {
        unsafe { (self.set_intercept_direction)(direction) };
        Ok(())
    }

    pub fn respond_to_intercept(&self, connection_id: i32, action: i32, data: &[u8]) -> Result<()> {
        println!("RUST LIB: respond_to_intercept called with:");
        println!("  connection_id: {}", connection_id);
        println!("  action: {}", action);
        println!("  data length: {}", data.len());
        println!("  data bytes: {:?}", data);
        println!("  data as hex: {}", data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));

        unsafe {
            println!("RUST LIB: Calling C function with connection_id: {}, action: {}, data_ptr: {:p}, data_len: {}",
                     connection_id, action, data.as_ptr(), data.len());

            (self.respond_to_intercept)(
                connection_id,
                action,
                data.as_ptr(),
                data.len() as c_int
            );

            println!("RUST LIB: C function call completed");
        };
        Ok(())
    }

    pub fn start_proxy(&self) -> Result<()> {
        let result = unsafe { (self.start_proxy)() };
        if result != 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to start proxy"))
        }
    }

    pub fn stop_proxy(&self) -> Result<()> {
        unsafe { (self.stop_proxy)() };
        Ok(())
    }

    pub fn set_config(&self, bind_addr: &str, port: i32, log_file: &str, verbose_mode: bool) -> Result<()> {
        let bind_addr_cstr = CString::new(bind_addr)
            .map_err(|e| anyhow::anyhow!("Invalid bind address: {}", e))?;
        let log_file_cstr = CString::new(log_file)
            .map_err(|e| anyhow::anyhow!("Invalid log file path: {}", e))?;

        let result = unsafe {
            (self.set_config)(
                bind_addr_cstr.as_ptr(),
                port,
                log_file_cstr.as_ptr(),
                if verbose_mode { 1 } else { 0 },
            )
        };

        if result != 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to set proxy configuration"))
        }
    }

    pub fn get_system_ips(&self) -> Result<Vec<String>> {
        let mut buffer = vec![0u8; 4096];
        let result = unsafe {
            (self.get_system_ips)(buffer.as_mut_ptr() as *mut c_char, buffer.len() as c_int)
        };

        if result > 0 {
            let ip_list = unsafe { CStr::from_ptr(buffer.as_ptr() as *const c_char) }
                .to_string_lossy()
                .to_string();

            let ips: Vec<String> = ip_list
                .split(';')
                .map(|ip| ip.trim().to_string())
                .filter(|ip| !ip.is_empty())
                .collect();

            Ok(ips)
        } else {
            Err(anyhow::anyhow!("Failed to get system IPs"))
        }
    }

    pub fn get_intercept_config(&self) -> Result<InterceptStatusResponse> {
        let status = unsafe { (self.get_intercept_config)() };

        // Convert direction integer to string
        let direction_str = match status.direction {
            0 => "None",
            1 => "Client->Server",
            2 => "Server->Client",
            3 => "Both",
            _ => "Unknown",
        };

        Ok(InterceptStatusResponse {
            is_enabled: status.is_enabled != 0,
            direction: direction_str.to_string(),
        })
    }
}

// Global library instance
static INIT: Once = Once::new();
static mut INTERCEPT_LIB: Option<Arc<Mutex<InterceptLibrary>>> = None;

// Global settings storage
static mut PROXY_SETTINGS: Option<Arc<Mutex<ProxySettings>>> = None;
static SETTINGS_INIT: Once = Once::new();

// Global app handle storage for events
static mut APP_HANDLE: Option<AppHandle> = None;
static APP_HANDLE_INIT: Once = Once::new();

// Connection tracking and storage
static mut CONNECTION_COUNTER: i32 = 0;
static mut CONNECTION_STORAGE: Option<Arc<Mutex<Vec<ConnectionEvent>>>> = None;
static CONNECTION_STORAGE_INIT: Once = Once::new();

// Proxy history storage
static mut PROXY_HISTORY_COUNTER: i32 = 0;
static mut PROXY_HISTORY_STORAGE: Option<Arc<Mutex<Vec<ProxyHistoryEntry>>>> = None;
static PROXY_HISTORY_STORAGE_INIT: Once = Once::new();

// Duplicate tracking storage for log entries
static mut PROCESSED_PACKETS: Option<Arc<Mutex<std::collections::HashSet<String>>>> = None;
static PROCESSED_PACKETS_INIT: Once = Once::new();

// Intercepted data storage
static mut INTERCEPTED_DATA_STORAGE: Option<Arc<Mutex<Vec<InterceptedData>>>> = None;
static INTERCEPTED_DATA_STORAGE_INIT: Once = Once::new();

// Define InterceptedData for storing intercepted packet information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InterceptedData {
    pub connection_id: i32,
    pub direction: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: i32,
    pub data_length: i32,
    pub packet_id: i32,
    pub data: String, // Hex string representation of binary data
    pub timestamp: String,
}

fn get_library() -> Result<Arc<Mutex<InterceptLibrary>>, String> {
    unsafe {
        INIT.call_once(|| {
            match InterceptLibrary::new() {
                Ok(lib) => {
                    INTERCEPT_LIB = Some(Arc::new(Mutex::new(lib)));
                }
                Err(e) => {
                    eprintln!("Failed to initialize InterceptLibrary: {}", e);
                }
            }
        });

        INTERCEPT_LIB
            .as_ref()
            .cloned()
            .ok_or_else(|| "Failed to initialize library".to_string())
    }
}

fn get_settings() -> Arc<Mutex<ProxySettings>> {
    unsafe {
        SETTINGS_INIT.call_once(|| {
            let default_settings = ProxySettings {
                listen_port: 4444,
                target_host: "127.0.0.1".to_string(),
                enable_logging: false,
                log_file_path: "tls_proxy.log".to_string(),
            };
            PROXY_SETTINGS = Some(Arc::new(Mutex::new(default_settings)));
        });

        PROXY_SETTINGS.as_ref().unwrap().clone()
    }
}

fn get_connection_storage() -> Arc<Mutex<Vec<ConnectionEvent>>> {
    unsafe {
        CONNECTION_STORAGE_INIT.call_once(|| {
            CONNECTION_STORAGE = Some(Arc::new(Mutex::new(Vec::new())));
        });

        CONNECTION_STORAGE.as_ref().unwrap().clone()
    }
}

fn get_proxy_history_storage() -> Arc<Mutex<Vec<ProxyHistoryEntry>>> {
    unsafe {
        PROXY_HISTORY_STORAGE_INIT.call_once(|| {
            PROXY_HISTORY_STORAGE = Some(Arc::new(Mutex::new(Vec::new())));
        });

        PROXY_HISTORY_STORAGE.as_ref().unwrap().clone()
    }
}

fn get_processed_packets() -> Arc<Mutex<std::collections::HashSet<String>>> {
    unsafe {
        PROCESSED_PACKETS_INIT.call_once(|| {
            PROCESSED_PACKETS = Some(Arc::new(Mutex::new(std::collections::HashSet::new())));
        });

        PROCESSED_PACKETS.as_ref().unwrap().clone()
    }
}

fn get_intercepted_data_storage() -> Arc<Mutex<Vec<InterceptedData>>> {
    unsafe {
        INTERCEPTED_DATA_STORAGE_INIT.call_once(|| {
            INTERCEPTED_DATA_STORAGE = Some(Arc::new(Mutex::new(Vec::new())));
        });

        INTERCEPTED_DATA_STORAGE.as_ref().unwrap().clone()
    }
}

fn set_app_handle(app_handle: AppHandle) {
    unsafe {
        APP_HANDLE_INIT.call_once(|| {
            APP_HANDLE = Some(app_handle);
        });
    }
}

fn get_app_handle() -> Option<&'static AppHandle> {
    unsafe { APP_HANDLE.as_ref() }
}

fn generate_connection_id() -> String {
    unsafe {
        CONNECTION_COUNTER += 1;
        format!("conn_{}", CONNECTION_COUNTER)
    }
}

fn generate_history_id() -> String {
    unsafe {
        PROXY_HISTORY_COUNTER += 1;
        format!("history_{}", PROXY_HISTORY_COUNTER)
    }
}

fn store_connection_event(event: ConnectionEvent) {
    if let Ok(mut connections) = get_connection_storage().lock() {
        connections.push(event);

        // Optional: Limit the number of stored connections to prevent memory issues
        // Keep only the last 10000 connections
        if connections.len() > 10000 {
            connections.remove(0);
        }
    }
}

fn store_proxy_history_entry(entry: ProxyHistoryEntry) {
    if let Ok(mut history) = get_proxy_history_storage().lock() {
        history.push(entry);

        // Limit the number of stored entries to prevent memory issues
        // Keep only the last 10000 entries
        if history.len() > 10000 {
            history.remove(0);
        }
    }
}

// Function to update proxy history entry with edited data
fn update_proxy_history_entry_with_edit(packet_id: i32, edited_data: String) {
    if let Ok(mut history) = get_proxy_history_storage().lock() {
        // Find the entry with matching packet_id and update it
        if let Some(entry) = history.iter_mut().find(|e| e.packet_id == packet_id) {
            entry.modified = true;
            entry.edited_data = Some(edited_data);
        }
    }
}

// Callback function implementations
unsafe extern "C" fn connection_callback(
    source_ip: *const c_char,
    source_port: c_int,
    dest_ip: *const c_char,
    dest_port: c_int,
    connection_id: c_int,
) {
    let source_ip_str = if !source_ip.is_null() {
        CStr::from_ptr(source_ip).to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };

    let dest_ip_str = if !dest_ip.is_null() {
        CStr::from_ptr(dest_ip).to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };

    let event = ConnectionEvent {
        id: generate_connection_id(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event: "connected".to_string(),
        connection_id,
        source_ip: source_ip_str,
        source_port: source_port,
        destination_ip: dest_ip_str,
        destination_port: dest_port,
    };

    // Store in memory
    store_connection_event(event.clone());

    // Emit to frontend
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("connection-event", &event) {
            eprintln!("Failed to emit connection event: {}", e);
        }
    }
}

unsafe extern "C" fn disconnect_callback(connection_id: c_int, reason: *const c_char) {
    let reason_str = if !reason.is_null() {
        CStr::from_ptr(reason).to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };

    let event = ConnectionEvent {
        id: generate_connection_id(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event: "disconnected".to_string(),
        connection_id,
        source_ip: "".to_string(),
        source_port: 0,
        destination_ip: reason_str,
        destination_port: 0,
    };

    // Store in memory
    store_connection_event(event.clone());

    // Emit to frontend
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("connection-event", &event) {
            eprintln!("Failed to emit disconnect event: {}", e);
        }
    }
}

// Callback for handling log events from the native library
// Status callback for receiving status messages from C library
unsafe extern "C" fn status_callback(status: *const c_char) {
    // Check for null pointers
    if status.is_null() {
        return;
    }

    let status_str = CStr::from_ptr(status).to_string_lossy().to_string();
    println!("Status from C library: {}", status_str);

    // Emit to frontend as a notification if we have an app handle
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("status-message", &status_str) {
            eprintln!("Failed to emit status message event: {}", e);
        }
    }
}

unsafe extern "C" fn log_callback(
    timestamp: *const c_char,
    connection_id: c_int,
    packet_id: c_int,
    src_ip: *const c_char,
    dst_ip: *const c_char,
    dst_port: c_int,
    message_type: *const c_char,
    data: *const c_char,
) {
    // Check for null pointers
    if timestamp.is_null() || src_ip.is_null() || dst_ip.is_null() ||
       message_type.is_null() || data.is_null() {
        return;
    }

    // Convert C strings to Rust strings
    let timestamp_str = CStr::from_ptr(timestamp).to_string_lossy().to_string();
    let src_ip_str = CStr::from_ptr(src_ip).to_string_lossy().to_string();
    let dst_ip_str = CStr::from_ptr(dst_ip).to_string_lossy().to_string();
    let message_type_str = CStr::from_ptr(message_type).to_string_lossy().to_string();
    let data_str = CStr::from_ptr(data).to_string_lossy().to_string();

    // Create a unique key for this packet to detect duplicates
    // Use connection_id, packet_id, and a hash of the data to identify unique packets
    let mut hasher = DefaultHasher::new();
    data_str.hash(&mut hasher);
    let data_hash = hasher.finish();

    let packet_key = format!("{}:{}:{}", connection_id, packet_id, data_hash);

    // Check if we've already processed this packet
    let processed_packets = get_processed_packets();
    if let Ok(mut packets) = processed_packets.lock() {
        if packets.contains(&packet_key) {
            // We've already processed this packet, skip it
            return;
        }
        // Mark this packet as processed
        packets.insert(packet_key.clone());

        // Limit the size of the processed packets set to prevent memory issues
        if packets.len() > 50000 {
            packets.clear(); // Clear old entries when it gets too large
        }
    }

    // Create history entry
    let entry = ProxyHistoryEntry {
        id: generate_history_id(),
        timestamp: timestamp_str,
        connection_id,
        packet_id: packet_id.clone(),
        packet_key,
        source_ip: src_ip_str,
        destination_ip: dst_ip_str,
        destination_port: dst_port,
        message_type: message_type_str,
        data: data_str,
        modified: false,  // Initialize as not modified
        edited_data: None,  // No edited data initially
    };

    // Store in memory
    store_proxy_history_entry(entry.clone());

    // Note: We don't emit real-time events here to avoid duplicates
    // Frontend will periodically fetch from memory storage which is deduplicated
}

// Intercept callback handler function
unsafe extern "C" fn intercept_callback(
    connection_id: c_int,
    direction: *const c_char,
    src_ip: *const c_char,
    dst_ip: *const c_char,
    dst_port: c_int,
    data: *const u8,
    data_length: c_int,
    packet_id: c_int,
) {
    eprintln!("INTERCEPT CALLBACK CALLED: conn_id={}, packet_id={}, data_length={}", connection_id, packet_id, data_length);

    // Check for null pointers
    if direction.is_null() || src_ip.is_null() || dst_ip.is_null() {
        eprintln!("Received null pointer(s) in intercept_callback");
        return;
    }

    // Convert C strings to Rust strings
    let direction_str = CStr::from_ptr(direction).to_string_lossy().to_string();
    let src_ip_str = CStr::from_ptr(src_ip).to_string_lossy().to_string();
    let dst_ip_str = CStr::from_ptr(dst_ip).to_string_lossy().to_string();

    // Convert binary data to a printable format (similar to log_callback)
    let data_str = if data.is_null() || data_length <= 0 {
        String::new()
    } else {
        // Create a slice from the raw pointer - SAFETY: We've checked data is not null and length > 0
        let data_slice = std::slice::from_raw_parts(data, data_length as usize);

        // For now, just show as hex dump (can be improved for different data types)
        // This approach is simpler than base64 and similar to log_callback
        let mut hex_string = String::with_capacity(data_length as usize * 3);
        for byte in data_slice.iter().take(8192) { // Limit size for very large packets
            hex_string.push_str(&format!("{:02x} ", byte));
        }
        if data_length > 8192 {
            hex_string.push_str("[truncated...]");
        }
        hex_string
    };

    // Create intercepted data object
    let intercepted_data = InterceptedData {
        connection_id,
        direction: direction_str,
        src_ip: src_ip_str,
        dst_ip: dst_ip_str,
        dst_port,
        data_length: data_length,
        packet_id,
        data: data_str, // Now using simple hex format instead of base64
        timestamp: chrono::Local::now().to_rfc3339(),
    };

    // Store data in memory
    if let Ok(mut storage) = get_intercepted_data_storage().lock() {
        storage.push(intercepted_data.clone());
    } else {
        eprintln!("Failed to store intercepted data");
    }

    // Send to frontend via event
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("intercepted-packet", &intercepted_data) {
            eprintln!("Failed to emit intercepted packet event: {}", e);
        }
    } else {
        eprintln!("App handle not available for intercepted packet event");
    }
}

// Tauri command implementations
#[tauri::command]
async fn get_proxy_settings() -> Result<ProxySettings, String> {
    let settings = get_settings();
    let settings = settings.lock().map_err(|e| format!("Failed to acquire settings lock: {}", e))?;
    Ok(settings.clone())
}

#[tauri::command]
async fn save_proxy_settings(settings: ProxySettings) -> Result<(), String> {
    println!("Saving proxy settings: {:?}", settings);

    // Store settings in memory
    let settings_store = get_settings();
    {
        let mut stored_settings = settings_store.lock().map_err(|e| format!("Failed to acquire settings lock: {}", e))?;
        *stored_settings = settings.clone();
    }

    // Apply settings to the C library
    let lib = get_library()?;
    let lib = lib.lock().map_err(|e| format!("Failed to acquire library lock: {}", e))?;

    println!("Calling set_config with: bind address: {}, port: {}", settings.target_host, settings.listen_port);

    lib.set_config(
        &settings.target_host,
        settings.listen_port as i32,
        &settings.log_file_path,
        settings.enable_logging
    ).map_err(|e| format!("Failed to set proxy configuration: {}", e))?;

    Ok(())
}
#[tauri::command]
async fn cmd_start_proxy() -> Result<(), String> {
    let lib = get_library()?;
    let lib = lib.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;

    // Set up callbacks before starting proxy
    lib.set_connection_callback(connection_callback)
        .map_err(|e| format!("Failed to set connection callback: {}", e))?;

    lib.set_disconnect_callback(disconnect_callback)
        .map_err(|e| format!("Failed to set disconnect callback: {}", e))?;

    lib.set_log_callback(log_callback)
        .map_err(|e| format!("Failed to set log callback: {}", e))?;

    lib.set_status_callback(status_callback)
        .map_err(|e| format!("Failed to set status callback: {}", e))?;

    // Set up intercept callback before starting proxy
    lib.set_intercept_callback(intercept_callback)
        .map_err(|e| format!("Failed to set intercept callback: {}", e))?;

    // Explicitly disable intercept functionality initially (can be enabled by user)
    lib.set_intercept_enabled(false)
        .map_err(|e| format!("Failed to disable intercept functionality: {}", e))?;

    lib.start_proxy()
        .map_err(|e| format!("Failed to start proxy: {}", e))?;

    Ok(())
}

#[tauri::command]
async fn initialize_callbacks(app_handle: AppHandle) -> Result<(), String> {
    set_app_handle(app_handle);
    Ok(())
}

#[tauri::command]
async fn cmd_stop_proxy() -> Result<(), String> {
    let lib = get_library()?;
    let lib = lib.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;

    lib.stop_proxy()
        .map_err(|e| format!("Failed to stop proxy: {}", e))
}

#[tauri::command]
async fn get_network_interfaces() -> Result<Vec<NetworkInterface>, String> {
    println!("Refreshing network interfaces...");

    let lib = get_library()?;
    let lib = lib.lock().map_err(|e| format!("Failed to acquire library lock: {}", e))?;

    let mut interfaces = Vec::new();

    // Add default entries
    interfaces.push(NetworkInterface {
        value: "localhost".to_string(),
        label: "localhost (127.0.0.1)".to_string(),
    });
    interfaces.push(NetworkInterface {
        value: "127.0.0.1".to_string(),
        label: "127.0.0.1 (localhost)".to_string(),
    });
    interfaces.push(NetworkInterface {
        value: "0.0.0.0".to_string(),
        label: "0.0.0.0 (all interfaces)".to_string(),
    });

    // Try to get system IPs by calling get_system_ips
    println!("Calling get_system_ips from C library...");
    match lib.get_system_ips() {
        Ok(ips) => {
            println!("Successfully retrieved {} system IPs: {:?}", ips.len(), ips);
            for ip in ips {
                if !ip.is_empty() && ip != "127.0.0.1" && ip != "localhost" && ip != "0.0.0.0" {
                    interfaces.push(NetworkInterface {
                        value: ip.clone(),
                        label: format!("{} (discovered)", ip),
                    });
                    println!("Added discovered IP: {}", ip);
                }
            }
        }
        Err(e) => {
            println!("Failed to get system IPs: {}", e);
            // Continue with default interfaces even if system IP discovery fails
        }
    }

    println!("Returning {} total network interfaces ", interfaces.len());
    Ok(interfaces)
}



#[tauri::command]
async fn get_connections() -> Result<Vec<ConnectionEvent>, String> {
    let storage = get_connection_storage();
    let connections = storage.lock().map_err(|e| format!("Failed to acquire connections lock: {}", e))?;
    Ok(connections.clone())
}

#[tauri::command]
async fn clear_connections() -> Result<(), String> {
    let storage = get_connection_storage();
    let mut connections = storage.lock().map_err(|e| format!("Failed to acquire connections lock: {}", e))?;
    connections.clear();
    Ok(())
}

#[tauri::command]
async fn clear_selected_connections(event_ids: Vec<String>) -> Result<(), String> {
    let storage = get_connection_storage();
    let mut connections = storage.lock().map_err(|e| format!("Failed to acquire connections lock: {}", e))?;

    // Remove events that match the provided event IDs (the unique 'id' field, not 'connection_id')
    connections.retain(|conn| !event_ids.contains(&conn.id));

    Ok(())
}

#[tauri::command]
async fn update_proxy_history_entry(packet_id: i32, edited_data: String) -> Result<(), String> {
    update_proxy_history_entry_with_edit(packet_id, edited_data);
    Ok(())
}

// Callback function implementations
unsafe extern "C" fn connection_callback(
    source_ip: *const c_char,
    source_port: c_int,
    dest_ip: *const c_char,
    dest_port: c_int,
    connection_id: c_int,
) {
    let source_ip_str = if !source_ip.is_null() {
        CStr::from_ptr(source_ip).to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };

    let dest_ip_str = if !dest_ip.is_null() {
        CStr::from_ptr(dest_ip).to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };

    let event = ConnectionEvent {
        id: generate_connection_id(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event: "connected".to_string(),
        connection_id,
        source_ip: source_ip_str,
        source_port: source_port,
        destination_ip: dest_ip_str,
        destination_port: dest_port,
    };

    // Store in memory
    store_connection_event(event.clone());

    // Emit to frontend
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("connection-event", &event) {
            eprintln!("Failed to emit connection event: {}", e);
        }
    }
}

unsafe extern "C" fn disconnect_callback(connection_id: c_int, reason: *const c_char) {
    let reason_str = if !reason.is_null() {
        CStr::from_ptr(reason).to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };

    let event = ConnectionEvent {
        id: generate_connection_id(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event: "disconnected".to_string(),
        connection_id,
        source_ip: "".to_string(),
        source_port: 0,
        destination_ip: reason_str,
        destination_port: 0,
    };

    // Store in memory
    store_connection_event(event.clone());

    // Emit to frontend
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("connection-event", &event) {
            eprintln!("Failed to emit disconnect event: {}", e);
        }
    }
}

// Callback for handling log events from the native library
// Status callback for receiving status messages from C library
unsafe extern "C" fn status_callback(status: *const c_char) {
    // Check for null pointers
    if status.is_null() {
        return;
    }

    let status_str = CStr::from_ptr(status).to_string_lossy().to_string();
    println!("Status from C library: {}", status_str);

    // Emit to frontend as a notification if we have an app handle
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("status-message", &status_str) {
            eprintln!("Failed to emit status message event: {}", e);
        }
    }
}

unsafe extern "C" fn log_callback(
    timestamp: *const c_char,
    connection_id: c_int,
    packet_id: c_int,
    src_ip: *const c_char,
    dst_ip: *const c_char,
    dst_port: c_int,
    message_type: *const c_char,
    data: *const c_char,
) {
    // Check for null pointers
    if timestamp.is_null() || src_ip.is_null() || dst_ip.is_null() ||
       message_type.is_null() || data.is_null() {
        return;
    }

    // Convert C strings to Rust strings
    let timestamp_str = CStr::from_ptr(timestamp).to_string_lossy().to_string();
    let src_ip_str = CStr::from_ptr(src_ip).to_string_lossy().to_string();
    let dst_ip_str = CStr::from_ptr(dst_ip).to_string_lossy().to_string();
    let message_type_str = CStr::from_ptr(message_type).to_string_lossy().to_string();
    let data_str = CStr::from_ptr(data).to_string_lossy().to_string();

    // Create a unique key for this packet to detect duplicates
    // Use connection_id, packet_id, and a hash of the data to identify unique packets
    let mut hasher = DefaultHasher::new();
    data_str.hash(&mut hasher);
    let data_hash = hasher.finish();

    let packet_key = format!("{}:{}:{}", connection_id, packet_id, data_hash);

    // Check if we've already processed this packet
    let processed_packets = get_processed_packets();
    if let Ok(mut packets) = processed_packets.lock() {
        if packets.contains(&packet_key) {
            // We've already processed this packet, skip it
            return;
        }
        // Mark this packet as processed
        packets.insert(packet_key.clone());

        // Limit the size of the processed packets set to prevent memory issues
        if packets.len() > 50000 {
            packets.clear(); // Clear old entries when it gets too large
        }
    }

    // Create history entry
    let entry = ProxyHistoryEntry {
        id: generate_history_id(),
        timestamp: timestamp_str,
        connection_id,
        packet_id: packet_id.clone(),
        packet_key,
        source_ip: src_ip_str,
        destination_ip: dst_ip_str,
        destination_port: dst_port,
        message_type: message_type_str,
        data: data_str,
        modified: false,  // Initialize as not modified
        edited_data: None,  // No edited data initially
    };

    // Store in memory
    store_proxy_history_entry(entry.clone());

    // Note: We don't emit real-time events here to avoid duplicates
    // Frontend will periodically fetch from memory storage which is deduplicated
}

// Intercept callback handler function
unsafe extern "C" fn intercept_callback(
    connection_id: c_int,
    direction: *const c_char,
    src_ip: *const c_char,
    dst_ip: *const c_char,
    dst_port: c_int,
    data: *const u8,
    data_length: c_int,
    packet_id: c_int,
) {
    eprintln!("INTERCEPT CALLBACK CALLED: conn_id={}, packet_id={}, data_length={}", connection_id, packet_id, data_length);

    // Check for null pointers
    if direction.is_null() || src_ip.is_null() || dst_ip.is_null() {
        eprintln!("Received null pointer(s) in intercept_callback");
        return;
    }

    // Convert C strings to Rust strings
    let direction_str = CStr::from_ptr(direction).to_string_lossy().to_string();
    let src_ip_str = CStr::from_ptr(src_ip).to_string_lossy().to_string();
    let dst_ip_str = CStr::from_ptr(dst_ip).to_string_lossy().to_string();

    // Convert binary data to a printable format (similar to log_callback)
    let data_str = if data.is_null() || data_length <= 0 {
        String::new()
    } else {
        // Create a slice from the raw pointer - SAFETY: We've checked data is not null and length > 0
        let data_slice = std::slice::from_raw_parts(data, data_length as usize);

        // For now, just show as hex dump (can be improved for different data types)
        // This approach is simpler than base64 and similar to log_callback
        let mut hex_string = String::with_capacity(data_length as usize * 3);
        for byte in data_slice.iter().take(8192) { // Limit size for very large packets
            hex_string.push_str(&format!("{:02x} ", byte));
        }
        if data_length > 8192 {
            hex_string.push_str("[truncated...]");
        }
        hex_string
    };

    // Create intercepted data object
    let intercepted_data = InterceptedData {
        connection_id,
        direction: direction_str,
        src_ip: src_ip_str,
        dst_ip: dst_ip_str,
        dst_port,
        data_length: data_length,
        packet_id,
        data: data_str, // Now using simple hex format instead of base64
        timestamp: chrono::Local::now().to_rfc3339(),
    };

    // Store data in memory
    if let Ok(mut storage) = get_intercepted_data_storage().lock() {
        storage.push(intercepted_data.clone());
    } else {
        eprintln!("Failed to store intercepted data");
    }

    // Send to frontend via event
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("intercepted-packet", &intercepted_data) {
            eprintln!("Failed to emit intercepted packet event: {}", e);
        }
    } else {
        eprintln!("App handle not available for intercepted packet event");
    }
}

// Tauri command implementations
#[tauri::command]
async fn get_proxy_settings() -> Result<ProxySettings, String> {
    let settings = get_settings();
    let settings = settings.lock().map_err(|e| format!("Failed to acquire settings lock: {}", e))?;
    Ok(settings.clone())
}

#[tauri::command]
async fn save_proxy_settings(settings: ProxySettings) -> Result<(), String> {
    println!("Saving proxy settings: {:?}", settings);

    // Store settings in memory
    let settings_store = get_settings();
    {
        let mut stored_settings = settings_store.lock().map_err(|e| format!("Failed to acquire settings lock: {}", e))?;
        *stored_settings = settings.clone();
    }

    // Apply settings to the C library
    let lib = get_library()?;
    let lib = lib.lock().map_err(|e| format!("Failed to acquire library lock: {}", e))?;

    println!("Calling set_config with: bind address: {}, port: {}", settings.target_host, settings.listen_port);

    lib.set_config(
        &settings.target_host,
        settings.listen_port as i32,
        &settings.log_file_path,
        settings.enable_logging
    ).map_err(|e| format!("Failed to set proxy configuration: {}", e))?;

    Ok(())
}
#[tauri::command]
async fn cmd_start_proxy() -> Result<(), String> {
    let lib = get_library()?;
    let lib = lib.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;

    // Set up callbacks before starting proxy
    lib.set_connection_callback(connection_callback)
        .map_err(|e| format!("Failed to set connection callback: {}", e))?;

    lib.set_disconnect_callback(disconnect_callback)
        .map_err(|e| format!("Failed to set disconnect callback: {}", e))?;

    lib.set_log_callback(log_callback)
        .map_err(|e| format!("Failed to set log callback: {}", e))?;

    lib.set_status_callback(status_callback)
        .map_err(|e| format!("Failed to set status callback: {}", e))?;

    // Set up intercept callback before starting proxy
    lib.set_intercept_callback(intercept_callback)
        .map_err(|e| format!("Failed to set intercept callback: {}", e))?;

    // Explicitly disable intercept functionality initially (can be enabled by user)
    lib.set_intercept_enabled(false)
        .map_err(|e| format!("Failed to disable intercept functionality: {}", e))?;

    lib.start_proxy()
        .map_err(|e| format!("Failed to start proxy: {}", e))?;

    Ok(())
}

#[tauri::command]
async fn initialize_callbacks(app_handle: AppHandle) -> Result<(), String> {
    set_app_handle(app_handle);
    Ok(())
}

#[tauri::command]
async fn cmd_stop_proxy() -> Result<(), String> {
    let lib = get_library()?;
    let lib = lib.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;

    lib.stop_proxy()
        .map_err(|e| format!("Failed to stop proxy: {}", e))
}

#[tauri::command]
async fn get_network_interfaces() -> Result<Vec<NetworkInterface>, String> {
    println!("Refreshing network interfaces...");

    let lib = get_library()?;
    let lib = lib.lock().map_err(|e| format!("Failed to acquire library lock: {}", e))?;

    let mut interfaces = Vec::new();

    // Add default entries
    interfaces.push(NetworkInterface {
        value: "localhost".to_string(),
        label: "localhost (127.0.0.1)".to_string(),
    });
    interfaces.push(NetworkInterface {
        value: "127.0.0.1".to_string(),
        label: "127.0.0.1 (localhost)".to_string(),
    });
    interfaces.push(NetworkInterface {
        value: "0.0.0.0".to_string(),
        label: "0.0.0.0 (all interfaces)".to_string(),
    });

    // Try to get system IPs by calling get_system_ips
    println!("Calling get_system_ips from C library...");
    match lib.get_system_ips() {
        Ok(ips) => {
            println!("Successfully retrieved {} system IPs: {:?}", ips.len(), ips);
            for ip in ips {
                if !ip.is_empty() && ip != "127.0.0.1" && ip != "localhost" && ip != "0.0.0.0" {
                    interfaces.push(NetworkInterface {
                        value: ip.clone(),
                        label: format!("{} (discovered)", ip),
                    });
                    println!("Added discovered IP: {}", ip);
                }
            }
        }
        Err(e) => {
            println!("Failed to get system IPs: {}", e);
            // Continue with default interfaces even if system IP discovery fails
        }
    }

    println!("Returning {} total network interfaces ", interfaces.len());
    Ok(interfaces)
}



#[tauri::command]
async fn get_connections() -> Result<Vec<ConnectionEvent>, String> {
    let storage = get_connection_storage();
    let connections = storage.lock().map_err(|e| format!("Failed to acquire connections lock: {}", e))?;
    Ok(connections.clone())
}

#[tauri::command]
async fn clear_connections() -> Result<(), String> {
    let storage = get_connection_storage();
    let mut connections = storage.lock().map_err(|e| format!("Failed to acquire connections lock: {}", e))?;
    connections.clear();
    Ok(())
}

#[tauri::command]
async fn clear_selected_connections(event_ids: Vec<String>) -> Result<(), String> {
    let storage = get_connection_storage();
    let mut connections = storage.lock().map_err(|e| format!("Failed to acquire connections lock: {}", e))?;

    // Remove events that match the provided event IDs (the unique 'id' field, not 'connection_id')
    connections.retain(|conn| !event_ids.contains(&conn.id));

    Ok(())
}

#[tauri::command]
async fn update_proxy_history_entry(packet_id: i32, edited_data: String) -> Result<(), String> {
    update_proxy_history_entry_with_edit(packet_id, edited_data);
    Ok(())
}

// Callback function implementations
unsafe extern "C" fn connection_callback(
    source_ip: *const c_char,
    source_port: c_int,
    dest_ip: *const c_char,
    dest_port: c_int,
    connection_id: c_int,
) {
    let source_ip_str = if !source_ip.is_null() {
        CStr::from_ptr(source_ip).to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };

    let dest_ip_str = if !dest_ip.is_null() {
        CStr::from_ptr(dest_ip).to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };

    let event = ConnectionEvent {
        id: generate_connection_id(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event: "connected".to_string(),
        connection_id,
        source_ip: source_ip_str,
        source_port: source_port,
        destination_ip: dest_ip_str,
        destination_port: dest_port,
    };

    // Store in memory
    store_connection_event(event.clone());

    // Emit to frontend
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("connection-event", &event) {
            eprintln!("Failed to emit connection event: {}", e);
        }
    }
}

unsafe extern "C" fn disconnect_callback(connection_id: c_int, reason: *const c_char) {
    let reason_str = if !reason.is_null() {
        CStr::from_ptr(reason).to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };

    let event = ConnectionEvent {
        id: generate_connection_id(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event: "disconnected".to_string(),
        connection_id,
        source_ip: "".to_string(),
        source_port: 0,
        destination_ip: reason_str,
        destination_port: 0,
    };

    // Store in memory
    store_connection_event(event.clone());

    // Emit to frontend
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("connection-event", &event) {
            eprintln!("Failed to emit disconnect event: {}", e);
        }
    }
}

// Callback for handling log events from the native library
// Status callback for receiving status messages from C library
unsafe extern "C" fn status_callback(status: *const c_char) {
    // Check for null pointers
    if status.is_null() {
        return;
    }

    let status_str = CStr::from_ptr(status).to_string_lossy().to_string();
    println!("Status from C library: {}", status_str);

    // Emit to frontend as a notification if we have an app handle
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("status-message", &status_str) {
            eprintln!("Failed to emit status message event: {}", e);
        }
    }
}

unsafe extern "C" fn log_callback(
    timestamp: *const c_char,
    connection_id: c_int,
    packet_id: c_int,
    src_ip: *const c_char,
    dst_ip: *const c_char,
    dst_port: c_int,
    message_type: *const c_char,
    data: *const c_char,
) {
    // Check for null pointers
    if timestamp.is_null() || src_ip.is_null() || dst_ip.is_null() ||
       message_type.is_null() || data.is_null() {
        return;
    }

    // Convert C strings to Rust strings
    let timestamp_str = CStr::from_ptr(timestamp).to_string_lossy().to_string();
    let src_ip_str = CStr::from_ptr(src_ip).to_string_lossy().to_string();
    let dst_ip_str = CStr::from_ptr(dst_ip).to_string_lossy().to_string();
    let message_type_str = CStr::from_ptr(message_type).to_string_lossy().to_string();
    let data_str = CStr::from_ptr(data).to_string_lossy().to_string();

    // Create a unique key for this packet to detect duplicates
    // Use connection_id, packet_id, and a hash of the data to identify unique packets
    let mut hasher = DefaultHasher::new();
    data_str.hash(&mut hasher);
    let data_hash = hasher.finish();

    let packet_key = format!("{}:{}:{}", connection_id, packet_id, data_hash);

    // Check if we've already processed this packet
    let processed_packets = get_processed_packets();
    if let Ok(mut packets) = processed_packets.lock() {
        if packets.contains(&packet_key) {
            // We've already processed this packet, skip it
            return;
        }
        // Mark this packet as processed
        packets.insert(packet_key.clone());

        // Limit the size of the processed packets set to prevent memory issues
        if packets.len() > 50000 {
            packets.clear(); // Clear old entries when it gets too large
        }
    }

    // Create history entry
    let entry = ProxyHistoryEntry {
        id: generate_history_id(),
        timestamp: timestamp_str,
        connection_id,
        packet_id: packet_id.clone(),
        packet_key,
        source_ip: src_ip_str,
        destination_ip: dst_ip_str,
        destination_port: dst_port,
        message_type: message_type_str,
        data: data_str,
        modified: false,  // Initialize as not modified
        edited_data: None,  // No edited data initially
    };

    // Store in memory
    store_proxy_history_entry(entry.clone());

    // Note: We don't emit real-time events here to avoid duplicates
    // Frontend will periodically fetch from memory storage which is deduplicated
}

// Intercept callback handler function
unsafe extern "C" fn intercept_callback(
    connection_id: c_int,
    direction: *const c_char,
    src_ip: *const c_char,
    dst_ip: *const c_char,
    dst_port: c_int,
    data: *const u8,
    data_length: c_int,
    packet_id: c_int,
) {
    eprintln!("INTERCEPT CALLBACK CALLED: conn_id={}, packet_id={}, data_length={}", connection_id, packet_id, data_length);

    // Check for null pointers
    if direction.is_null() || src_ip.is_null() || dst_ip.is_null() {
        eprintln!("Received null pointer(s) in intercept_callback");
        return;
    }

    // Convert C strings to Rust strings
    let direction_str = CStr::from_ptr(direction).to_string_lossy().to_string();
    let src_ip_str = CStr::from_ptr(src_ip).to_string_lossy().to_string();
    let dst_ip_str = CStr::from_ptr(dst_ip).to_string_lossy().to_string();

    // Convert binary data to a printable format (similar to log_callback)
    let data_str = if data.is_null() || data_length <= 0 {
        String::new()
    } else {
        // Create a slice from the raw pointer - SAFETY: We've checked data is not null and length > 0
        let data_slice = std::slice::from_raw_parts(data, data_length as usize);

        // For now, just show as hex dump (can be improved for different data types)
        // This approach is simpler than base64 and similar to log_callback
        let mut hex_string = String::with_capacity(data_length as usize * 3);
        for byte in data_slice.iter().take(8192) { // Limit size for very large packets
            hex_string.push_str(&format!("{:02x} ", byte));
        }
        if data_length > 8192 {
            hex_string.push_str("[truncated...]");
        }
        hex_string
    };

    // Create intercepted data object
    let intercepted_data = InterceptedData {
        connection_id,
        direction: direction_str,
        src_ip: src_ip_str,
        dst_ip: dst_ip_str,
        dst_port,
        data_length: data_length,
        packet_id,
        data: data_str, // Now using simple hex format instead of base64
        timestamp: chrono::Local::now().to_rfc3339(),
    };

    // Store data in memory
    if let Ok(mut storage) = get_intercepted_data_storage().lock() {
        storage.push(intercepted_data.clone());
    } else {
        eprintln!("Failed to store intercepted data");
    }

    // Send to frontend via event
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("intercepted-packet", &intercepted_data) {
            eprintln!("Failed to emit intercepted packet event: {}", e);
        }
    } else {
        eprintln!("App handle not available for intercepted packet event");
    }
}

// Tauri command implementations
#[tauri::command]
async fn get_proxy_settings() -> Result<ProxySettings, String> {
    let settings = get_settings();
    let settings = settings.lock().map_err(|e| format!("Failed to acquire settings lock: {}", e))?;
    Ok(settings.clone())
}

#[tauri::command]
async fn save_proxy_settings(settings: ProxySettings) -> Result<(), String> {
    println!("Saving proxy settings: {:?}", settings);

    // Store settings in memory
    let settings_store = get_settings();
    {
        let mut stored_settings = settings_store.lock().map_err(|e| format!("Failed to acquire settings lock: {}", e))?;
        *stored_settings = settings.clone();
    }

    // Apply settings to the C library
    let lib = get_library()?;
    let lib = lib.lock().map_err(|e| format!("Failed to acquire library lock: {}", e))?;

    println!("Calling set_config with: bind address: {}, port: {}", settings.target_host, settings.listen_port);

    lib.set_config(
        &settings.target_host,
        settings.listen_port as i32,
        &settings.log_file_path,
        settings.enable_logging
    ).map_err(|e| format!("Failed to set proxy configuration: {}", e))?;

    Ok(())
}
#[tauri::command]
async fn cmd_start_proxy() -> Result<(), String> {
    let lib = get_library()?;
    let lib = lib.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;

    // Set up callbacks before starting proxy
    lib.set_connection_callback(connection_callback)
        .map_err(|e| format!("Failed to set connection callback: {}", e))?;

    lib.set_disconnect_callback(disconnect_callback)
        .map_err(|e| format!("Failed to set disconnect callback: {}", e))?;

    lib.set_log_callback(log_callback)
        .map_err(|e| format!("Failed to set log callback: {}", e))?;

    lib.set_status_callback(status_callback)
        .map_err(|e| format!("Failed to set status callback: {}", e))?;

    // Set up intercept callback before starting proxy
    lib.set_intercept_callback(intercept_callback)
        .map_err(|e| format!("Failed to set intercept callback: {}", e))?;

    // Explicitly disable intercept functionality initially (can be enabled by user)
    lib.set_intercept_enabled(false)
        .map_err(|e| format!("Failed to disable intercept functionality: {}", e))?;

    lib.start_proxy()
        .map_err(|e| format!("Failed to start proxy: {}", e))?;

    Ok(())
}

#[tauri::command]
async fn initialize_callbacks(app_handle: AppHandle) -> Result<(), String> {
    set_app_handle(app_handle);
    Ok(())
}

#[tauri::command]
async fn cmd_stop_proxy() -> Result<(), String> {
    let lib = get_library()?;
    let lib = lib.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;

    lib.stop_proxy()
        .map_err(|e| format!("Failed to stop proxy: {}", e))
}

#[tauri::command]
async fn get_network_interfaces() -> Result<Vec<NetworkInterface>, String> {
    println!("Refreshing network interfaces...");

    let lib = get_library()?;
    let lib = lib.lock().map_err(|e| format!("Failed to acquire library lock: {}", e))?;

    let mut interfaces = Vec::new();

    // Add default entries
    interfaces.push(NetworkInterface {
        value: "localhost".to_string(),
        label: "localhost (127.0.0.1)".to_string(),
    });
    interfaces.push(NetworkInterface {
        value: "127.0.0.1".to_string(),
        label: "127.0.0.1 (localhost)".to_string(),
    });
    interfaces.push(NetworkInterface {
        value: "0.0.0.0".to_string(),
        label: "0.0.0.0 (all interfaces)".to_string(),
    });

    // Try to get system IPs by calling get_system_ips
    println!("Calling get_system_ips from C library...");
    match lib.get_system_ips() {
        Ok(ips) => {
            println!("Successfully retrieved {} system IPs: {:?}", ips.len(), ips);
            for ip in ips {
                if !ip.is_empty() && ip != "127.0.0.1" && ip != "localhost" && ip != "0.0.0.0" {
                    interfaces.push(NetworkInterface {
                        value: ip.clone(),
                        label: format!("{} (discovered)", ip),
                    });
                    println!("Added discovered IP: {}", ip);
                }
            }
        }
        Err(e) => {
            println!("Failed to get system IPs: {}", e);
            // Continue with default interfaces even if system IP discovery fails
        }
    }

    println!("Returning {} total network interfaces ", interfaces.len());
    Ok(interfaces)
}



#[tauri::command]
async fn get_connections() -> Result<Vec<ConnectionEvent>, String> {
    let storage = get_connection_storage();
    let connections = storage.lock().map_err(|e| format!("Failed to acquire connections lock: {}", e))?;
    Ok(connections.clone())
}

#[tauri::command]
async fn clear_connections() -> Result<(), String> {
    let storage = get_connection_storage();
    let mut connections = storage.lock().map_err(|e| format!("Failed to acquire connections lock: {}", e))?;
    connections.clear();
    Ok(())
}

#[tauri::command]
async fn clear_selected_connections(event_ids: Vec<String>) -> Result<(), String> {
    let storage = get_connection_storage();
    let mut connections = storage.lock().map_err(|e| format!("Failed to acquire connections lock: {}", e))?;

    // Remove events that match the provided event IDs (the unique 'id' field, not 'connection_id')
    connections.retain(|conn| !event_ids.contains(&conn.id));

    Ok(())
}

#[tauri::command]
async fn update_proxy_history_entry(packet_id: i32, edited_data: String) -> Result<(), String> {
    update_proxy_history_entry_with_edit(packet_id, edited_data);
    Ok(())
}

// Callback function implementations
unsafe extern "C" fn connection_callback(
    source_ip: *const c_char,
    source_port: c_int,
    dest_ip: *const c_char,
    dest_port: c_int,
    connection_id: c_int,
) {
    let source_ip_str = if !source_ip.is_null() {
        CStr::from_ptr(source_ip).to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };

    let dest_ip_str = if !dest_ip.is_null() {
        CStr::from_ptr(dest_ip).to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };

    let event = ConnectionEvent {
        id: generate_connection_id(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event: "connected".to_string(),
        connection_id,
        source_ip: source_ip_str,
        source_port: source_port,
        destination_ip: dest_ip_str,
        destination_port: dest_port,
    };

    // Store in memory
    store_connection_event(event.clone());

    // Emit to frontend
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("connection-event", &event) {
            eprintln!("Failed to emit connection event: {}", e);
        }
    }
}

unsafe extern "C" fn disconnect_callback(connection_id: c_int, reason: *const c_char) {
    let reason_str = if !reason.is_null() {
        CStr::from_ptr(reason).to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };

    let event = ConnectionEvent {
        id: generate_connection_id(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event: "disconnected".to_string(),
        connection_id,
        source_ip: "".to_string(),
        source_port: 0,
        destination_ip: reason_str,
        destination_port: 0,
    };

    // Store in memory
    store_connection_event(event.clone());

    // Emit to frontend
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("connection-event", &event) {
            eprintln!("Failed to emit disconnect event: {}", e);
        }
    }
}

// Callback for handling log events from the native library
// Status callback for receiving status messages from C library
unsafe extern "C" fn status_callback(status: *const c_char) {
    // Check for null pointers
    if status.is_null() {
        return;
    }

    let status_str = CStr::from_ptr(status).to_string_lossy().to_string();
    println!("Status from C library: {}", status_str);

    // Emit to frontend as a notification if we have an app handle
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("status-message", &status_str) {
            eprintln!("Failed to emit status message event: {}", e);
        }
    }
}

unsafe extern "C" fn log_callback(
    timestamp: *const c_char,
    connection_id: c_int,
    packet_id: c_int,
    src_ip: *const c_char,
    dst_ip: *const c_char,
    dst_port: c_int,
    message_type: *const c_char,
    data: *const c_char,
) {
    // Check for null pointers
    if timestamp.is_null() || src_ip.is_null() || dst_ip.is_null() ||
       message_type.is_null() || data.is_null() {
        return;
    }

    // Convert C strings to Rust strings
    let timestamp_str = CStr::from_ptr(timestamp).to_string_lossy().to_string();
    let src_ip_str = CStr::from_ptr(src_ip).to_string_lossy().to_string();
    let dst_ip_str = CStr::from_ptr(dst_ip).to_string_lossy().to_string();
    let message_type_str = CStr::from_ptr(message_type).to_string_lossy().to_string();
    let data_str = CStr::from_ptr(data).to_string_lossy().to_string();

    // Create a unique key for this packet to detect duplicates
    // Use connection_id, packet_id, and a hash of the data to identify unique packets
    let mut hasher = DefaultHasher::new();
    data_str.hash(&mut hasher);
    let data_hash = hasher.finish();

    let packet_key = format!("{}:{}:{}", connection_id, packet_id, data_hash);

    // Check if we've already processed this packet
    let processed_packets = get_processed_packets();
    if let Ok(mut packets) = processed_packets.lock() {
        if packets.contains(&packet_key) {
            // We've already processed this packet, skip it
            return;
        }
        // Mark this packet as processed
        packets.insert(packet_key.clone());

        // Limit the size of the processed packets set to prevent memory issues
        if packets.len() > 50000 {
            packets.clear(); // Clear old entries when it gets too large
        }
    }

    // Create history entry
    let entry = ProxyHistoryEntry {
        id: generate_history_id(),
        timestamp: timestamp_str,
        connection_id,
        packet_id: packet_id.clone(),
        packet_key,
        source_ip: src_ip_str,
        destination_ip: dst_ip_str,
        destination_port: dst_port,
        message_type: message_type_str,
        data: data_str,
        modified: false,  // Initialize as not modified
        edited_data: None,  // No edited data initially
    };

    // Store in memory
    store_proxy_history_entry(entry.clone());

    // Note: We don't emit real-time events here to avoid duplicates
    // Frontend will periodically fetch from memory storage which is deduplicated
}

// Intercept callback handler function
unsafe extern "C" fn intercept_callback(
    connection_id: c_int,
    direction: *const c_char,
    src_ip: *const c_char,
    dst_ip: *const c_char,
    dst_port: c_int,
    data: *const u8,
    data_length: c_int,
    packet_id: c_int,
) {
    eprintln!("INTERCEPT CALLBACK CALLED: conn_id={}, packet_id={}, data_length={}", connection_id, packet_id, data_length);

    // Check for null pointers
    if direction.is_null() || src_ip.is_null() || dst_ip.is_null() {
        eprintln!("Received null pointer(s) in intercept_callback");
        return;
    }

    // Convert C strings to Rust strings
    let direction_str = CStr::from_ptr(direction).to_string_lossy().to_string();
    let src_ip_str = CStr::from_ptr(src_ip).to_string_lossy().to_string();
    let dst_ip_str = CStr::from_ptr(dst_ip).to_string_lossy().to_string();

    // Convert binary data to a printable format (similar to log_callback)
    let data_str = if data.is_null() || data_length <= 0 {
        String::new()
    } else {
        // Create a slice from the raw pointer - SAFETY: We've checked data is not null and length > 0
        let data_slice = std::slice::from_raw_parts(data, data_length as usize);

        // For now, just show as hex dump (can be improved for different data types)
        // This approach is simpler than base64 and similar to log_callback
        let mut hex_string = String::with_capacity(data_length as usize * 3);
        for byte in data_slice.iter().take(8192) { // Limit size for very large packets
            hex_string.push_str(&format!("{:02x} ", byte));
        }
        if data_length > 8192 {
            hex_string.push_str("[truncated...]");
        }
        hex_string
    };

    // Create intercepted data object
    let intercepted_data = InterceptedData {
        connection_id,
        direction: direction_str,
        src_ip: src_ip_str,
        dst_ip: dst_ip_str,
        dst_port,
        data_length: data_length,
        packet_id,
        data: data_str, // Now using simple hex format instead of base64
        timestamp: chrono::Local::now().to_rfc3339(),
    };

    // Store data in memory
    if let Ok(mut storage) = get_intercepted_data_storage().lock() {
        storage.push(intercepted_data.clone());
    } else {
        eprintln!("Failed to lock intercepted data storage");
    }

    // Send to frontend via event
    if let Some(app_handle) = get_app_handle() {
        if let Err(e) = app_handle.emit("intercepted-packet", &intercepted_data) {
            eprintln!("Failed to emit intercepted packet event: {}", e);
        }
    } else {
        eprintln!("App handle not available for intercepted packet event");
    }
}