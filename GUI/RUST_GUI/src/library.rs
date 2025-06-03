use anyhow::{anyhow, Result};
use libloading::{Library, Symbol};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

// Function pointer types matching the native library
type GetProxyConfigFn = unsafe extern "C" fn(*mut c_char, *mut c_int, *mut c_char, *mut c_int) -> c_int;
type GetProxyStatsFn = unsafe extern "C" fn(*mut c_int, *mut c_int) -> c_int;
type GetSystemIpsFn = unsafe extern "C" fn(*mut c_char, c_int) -> c_int;
type SetConfigFn = unsafe extern "C" fn(*const c_char, c_int, *const c_char, c_int) -> c_int;
type StartProxyFn = unsafe extern "C" fn() -> c_int;
type StopProxyFn = unsafe extern "C" fn();

// Callback function types
pub type ConnectionCallbackFn = unsafe extern "C" fn(*const c_char, c_int, *const c_char, c_int, c_int);
pub type DisconnectCallbackFn = unsafe extern "C" fn(c_int, *const c_char);

pub type LogCallbackFn = unsafe extern "C" fn(
    *const c_char, // timestamp
    c_int,         // connection_id
    c_int,         // packet_id
    *const c_char, // src_ip
    *const c_char, // dst_ip
    c_int,         // dst_port
    *const c_char, // message_type
    *const c_char, // data
);

pub type InterceptCallbackFn = unsafe extern "C" fn(
    c_int,         // connection_id
    *const c_char, // direction
    *const c_char, // src_ip
    *const c_char, // dst_ip
    c_int,         // dst_port
    *const u8,     // data
    c_int,         // data_length
    c_int,         // packet_id
);

// Callback setter function types
type SetConnectionCallbackFn = unsafe extern "C" fn(ConnectionCallbackFn);
type SetDisconnectCallbackFn = unsafe extern "C" fn(DisconnectCallbackFn);
type SetLogCallbackFn = unsafe extern "C" fn(LogCallbackFn);
type SetInterceptCallbackFn = unsafe extern "C" fn(InterceptCallbackFn);

// Intercept control function types
type SetInterceptEnabledFn = unsafe extern "C" fn(c_int);
type SetInterceptDirectionFn = unsafe extern "C" fn(c_int);
type RespondToInterceptFn = unsafe extern "C" fn(c_int, c_int, *const u8, c_int);

pub struct InterceptLibrary {
    _lib: Library,
    get_proxy_config: Symbol<'static, GetProxyConfigFn>,
    get_proxy_stats: Symbol<'static, GetProxyStatsFn>,
    get_system_ips: Symbol<'static, GetSystemIpsFn>,
    set_config: Symbol<'static, SetConfigFn>,
    start_proxy: Symbol<'static, StartProxyFn>,
    stop_proxy: Symbol<'static, StopProxyFn>,
    set_connection_callback: Symbol<'static, SetConnectionCallbackFn>,
    set_disconnect_callback: Symbol<'static, SetDisconnectCallbackFn>,
    set_log_callback: Symbol<'static, SetLogCallbackFn>,
    set_intercept_callback: Symbol<'static, SetInterceptCallbackFn>,
    set_intercept_enabled: Symbol<'static, SetInterceptEnabledFn>,
    set_intercept_direction: Symbol<'static, SetInterceptDirectionFn>,
    respond_to_intercept: Symbol<'static, RespondToInterceptFn>,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub bind_address: String,
    pub port: u16,
    pub log_file: String,
    pub verbose_mode: bool,
}

#[derive(Debug, Clone)]
pub struct ProxyStats {
    pub connections: i32,
    pub bytes_transferred: i32,
}

impl InterceptLibrary {
    pub fn new() -> Result<Self> {
        let library_path = if cfg!(target_os = "windows") {
            "Intercept.dll"
        } else if cfg!(target_os = "linux") {
            "./build/libIntercept.so"
        } else if cfg!(target_os = "macos") {
            "./build/libIntercept.dylib"
        } else {
            return Err(anyhow!("Unsupported platform"));
        };

        unsafe {
            let lib = Library::new(library_path)
                .map_err(|e| anyhow!("Failed to load library {}: {}", library_path, e))?;

            let get_proxy_config: Symbol<GetProxyConfigFn> = lib
                .get(b"get_proxy_config")
                .map_err(|e| anyhow!("Failed to load get_proxy_config: {}", e))?;

            let get_proxy_stats: Symbol<GetProxyStatsFn> = lib
                .get(b"get_proxy_stats")
                .map_err(|e| anyhow!("Failed to load get_proxy_stats: {}", e))?;

            let get_system_ips: Symbol<GetSystemIpsFn> = lib
                .get(b"get_system_ips")
                .map_err(|e| anyhow!("Failed to load get_system_ips: {}", e))?;            let set_config: Symbol<SetConfigFn> = lib
                .get(b"set_config")
                .map_err(|e| anyhow!("Failed to load set_config: {}", e))?;

            let start_proxy: Symbol<StartProxyFn> = lib
                .get(b"start_proxy")
                .map_err(|e| anyhow!("Failed to load start_proxy: {}", e))?;            let stop_proxy: Symbol<StopProxyFn> = lib
                .get(b"stop_proxy")
                .map_err(|e| anyhow!("Failed to load stop_proxy: {}", e))?;

            let set_connection_callback: Symbol<SetConnectionCallbackFn> = lib
                .get(b"set_connection_callback")
                .map_err(|e| anyhow!("Failed to load set_connection_callback: {}", e))?;            let set_disconnect_callback: Symbol<SetDisconnectCallbackFn> = lib
                .get(b"set_disconnect_callback")
                .map_err(|e| anyhow!("Failed to load set_disconnect_callback: {}", e))?;            let set_log_callback: Symbol<SetLogCallbackFn> = lib
                .get(b"set_log_callback")
                .map_err(|e| anyhow!("Failed to load set_log_callback: {}", e))?;

            let set_intercept_callback: Symbol<SetInterceptCallbackFn> = lib
                .get(b"set_intercept_callback")
                .map_err(|e| anyhow!("Failed to load set_intercept_callback: {}", e))?;

            let set_intercept_enabled: Symbol<SetInterceptEnabledFn> = lib
                .get(b"set_intercept_enabled")
                .map_err(|e| anyhow!("Failed to load set_intercept_enabled: {}", e))?;

            let set_intercept_direction: Symbol<SetInterceptDirectionFn> = lib
                .get(b"set_intercept_direction")
                .map_err(|e| anyhow!("Failed to load set_intercept_direction: {}", e))?;

            let respond_to_intercept: Symbol<RespondToInterceptFn> = lib
                .get(b"respond_to_intercept")
                .map_err(|e| anyhow!("Failed to load respond_to_intercept: {}", e))?;            // Extend the lifetime of the symbols to 'static by transmuting
            let get_proxy_config = std::mem::transmute(get_proxy_config);
            let get_proxy_stats = std::mem::transmute(get_proxy_stats);
            let get_system_ips = std::mem::transmute(get_system_ips);
            let set_config = std::mem::transmute(set_config);
            let start_proxy = std::mem::transmute(start_proxy);
            let stop_proxy = std::mem::transmute(stop_proxy);
            let set_connection_callback = std::mem::transmute(set_connection_callback);
            let set_disconnect_callback = std::mem::transmute(set_disconnect_callback);
            let set_log_callback = std::mem::transmute(set_log_callback);
            let set_intercept_callback = std::mem::transmute(set_intercept_callback);
            let set_intercept_enabled = std::mem::transmute(set_intercept_enabled);
            let set_intercept_direction = std::mem::transmute(set_intercept_direction);            let respond_to_intercept = std::mem::transmute(respond_to_intercept);

            Ok(Self {
                _lib: lib,
                get_proxy_config,
                get_proxy_stats,
                get_system_ips,
                set_config,
                start_proxy,
                stop_proxy,
                set_connection_callback,
                set_disconnect_callback,
                set_log_callback,
                set_intercept_callback,
                set_intercept_enabled,
                set_intercept_direction,
                respond_to_intercept,
            })
        }
    }

    pub fn get_config(&self) -> Result<ProxyConfig> {
        unsafe {
            let mut bind_addr = vec![0u8; 256];
            let mut port: c_int = 0;
            let mut log_file = vec![0u8; 512];
            let mut verbose: c_int = 0;

            let result = (self.get_proxy_config)(
                bind_addr.as_mut_ptr() as *mut c_char,
                &mut port,
                log_file.as_mut_ptr() as *mut c_char,
                &mut verbose,
            );

            if result != 0 {
                let bind_address = CStr::from_ptr(bind_addr.as_ptr() as *const c_char)
                    .to_string_lossy()
                    .to_string();
                let log_file_str = CStr::from_ptr(log_file.as_ptr() as *const c_char)
                    .to_string_lossy()
                    .to_string();

                Ok(ProxyConfig {
                    bind_address,
                    port: port as u16,
                    log_file: log_file_str,
                    verbose_mode: verbose != 0,
                })
            } else {
                Err(anyhow!("Failed to get proxy configuration"))
            }
        }
    }

    pub fn get_stats(&self) -> Result<ProxyStats> {
        unsafe {
            let mut connections: c_int = 0;
            let mut bytes_transferred: c_int = 0;

            let result = (self.get_proxy_stats)(&mut connections, &mut bytes_transferred);

            if result != 0 {
                Ok(ProxyStats {
                    connections,
                    bytes_transferred,
                })
            } else {
                Err(anyhow!("Failed to get proxy statistics"))
            }
        }
    }

    pub fn get_system_ips(&self) -> Result<Vec<String>> {
        unsafe {
            let mut ip_buffer = vec![0u8; 1024];
            let result = (self.get_system_ips)(ip_buffer.as_mut_ptr() as *mut c_char, 1024);

            if result > 0 {
                let ip_str = CStr::from_ptr(ip_buffer.as_ptr() as *const c_char)
                    .to_string_lossy()
                    .to_string();                // Split the semicolon-separated IPs
                let ips: Vec<String> = ip_str
                    .split(';')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                Ok(ips)
            } else {
                Err(anyhow!("Failed to get system IPs"))
            }
        }
    }    pub fn set_config(&self, config: &ProxyConfig) -> Result<()> {
        unsafe {
            let bind_addr = CString::new(config.bind_address.as_str())
                .map_err(|e| anyhow!("Invalid bind address: {}", e))?;
            let log_file = CString::new(config.log_file.as_str())
                .map_err(|e| anyhow!("Invalid log file path: {}", e))?;

            let result = (self.set_config)(
                bind_addr.as_ptr(),
                config.port as c_int,
                log_file.as_ptr(),
                if config.verbose_mode { 1 } else { 0 },
            );

            if result != 0 {
                Ok(())
            } else {
                Err(anyhow!("Failed to set proxy configuration"))
            }
        }
    }

    pub fn start_proxy(&self) -> Result<()> {
        unsafe {
            let result = (self.start_proxy)();
            if result != 0 {
                Ok(())
            } else {
                Err(anyhow!("Failed to start proxy"))
            }
        }
    }

    pub fn stop_proxy(&self) {
        unsafe {
            (self.stop_proxy)();
        }
    }

    pub fn set_connection_callback(&self, callback: ConnectionCallbackFn) {
        unsafe {
            (self.set_connection_callback)(callback);
        }
    }    pub fn set_disconnect_callback(&self, callback: DisconnectCallbackFn) {
        unsafe {
            (self.set_disconnect_callback)(callback);
        }
    }    pub fn set_log_callback(&self, callback: LogCallbackFn) {
        unsafe {
            (self.set_log_callback)(callback);
        }
    }

    pub fn set_intercept_callback(&self, callback: InterceptCallbackFn) {
        unsafe {
            (self.set_intercept_callback)(callback);
        }
    }

    pub fn set_intercept_enabled(&self, enabled: bool) {
        unsafe {
            (self.set_intercept_enabled)(if enabled { 1 } else { 0 });
        }
    }

    pub fn set_intercept_direction(&self, direction: i32) {
        unsafe {
            (self.set_intercept_direction)(direction);
        }
    }    pub fn respond_to_intercept(&self, connection_id: i32, action: i32, modified_data: Option<&[u8]>) {
        unsafe {
            if let Some(data) = modified_data {
                // Ensure we have valid data to work with
                if !data.is_empty() {
                    // Make sure data is properly aligned and valid
                    println!("Responding with action {} for connection {} with {} bytes of data",
                        action, connection_id, data.len());

                    // Ensure data pointer is valid
                    let data_ptr = data.as_ptr();
                    (self.respond_to_intercept)(connection_id, action, data_ptr, data.len() as c_int);
                } else {
                    println!("Warning: Empty data provided to respond_to_intercept, using null pointer instead");
                    (self.respond_to_intercept)(connection_id, action, std::ptr::null(), 0);
                }
            } else {
                println!("Responding with action {} for connection {} with no data (null pointer)",
                    action, connection_id);
                (self.respond_to_intercept)(connection_id, action, std::ptr::null(), 0);
            }
        }
    }
}

impl std::fmt::Debug for InterceptLibrary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterceptLibrary")
            .field("_lib", &"<Library>")
            .field("get_proxy_config", &"<Function>")
            .field("get_proxy_stats", &"<Function>")
            .field("get_system_ips", &"<Function>")
            .field("set_config", &"<Function>")
            .field("start_proxy", &"<Function>")
            .field("stop_proxy", &"<Function>")
            .field("set_connection_callback", &"<Function>")
            .field("set_disconnect_callback", &"<Function>")
            .field("set_log_callback", &"<Function>")
            .field("set_intercept_callback", &"<Function>")
            .field("set_intercept_enabled", &"<Function>")
            .field("set_intercept_direction", &"<Function>")
            .field("respond_to_intercept", &"<Function>")
            .finish()
    }
}
