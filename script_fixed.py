"""
TLS MITM Proxy GUI Application
A comprehensive GUI for controlling and monitoring the TLS proxy DLL with real-time callback system
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import ctypes
from ctypes import wintypes, POINTER, c_char_p, c_int, c_bool, c_void_p
import threading
import time
import os
import sys
import subprocess
import socket
from datetime import datetime
import json
import queue
import traceback

# Define callback function types to match the DLL
LOG_CALLBACK = ctypes.WINFUNCTYPE(None, c_char_p, c_char_p, c_char_p, c_int, c_char_p, c_char_p)
STATUS_CALLBACK = ctypes.WINFUNCTYPE(None, c_char_p)
CONNECTION_CALLBACK = ctypes.WINFUNCTYPE(None, c_char_p, c_int, c_char_p, c_int, c_int)
STATS_CALLBACK = ctypes.WINFUNCTYPE(None, c_int, c_int, c_int)
DISCONNECT_CALLBACK = ctypes.WINFUNCTYPE(None, c_int, c_char_p)


class TLSProxyDLL:
    """Wrapper class for the TLS Proxy DLL"""

    def __init__(self, dll_path):
        self.dll_path = dll_path
        self.dll = None
        self.is_loaded = False
        self.log_callback = None
        self.status_callback = None
        self.connection_callback = None
        self.stats_callback = None
        self.disconnect_callback = None

    def find_dll_path(self):
        """Find the first existing DLL path from possible locations"""
        possible_paths = [
            os.path.join(os.path.dirname(__file__), "build", "Release", "tls_proxy.dll"),
            os.path.join(os.path.dirname(__file__), "build", "Debug", "tls_proxy.dll"),
        ]
        print("Attempting to find DLL in the following locations:")
        for path in possible_paths:
            print("  ", path)
        for path in possible_paths:
            if os.path.exists(path):
                print(f"Found DLL at: {path}")
                return os.path.abspath(path)
        print("No DLL found in any of the expected locations.")
        return None

    def load_dll(self):
        """Load the DLL and set up function prototypes"""
        try:
            print("Finding DLL path...")
            # Find DLL path
            dll_path = self.find_dll_path()
            if not dll_path:
                print("DLL not found in any location")
                messagebox.showerror("DLL Load Error", "Could not find tls_proxy.dll in any expected location.")
                return False

            print(f"Loading DLL from: {dll_path}")
            # Add DLL directory to DLL search path (for dependencies)
            if hasattr(os, 'add_dll_directory'):
                os.add_dll_directory(os.path.dirname(dll_path))

            self.dll = ctypes.CDLL(dll_path)
            print("DLL loaded, setting up function prototypes...")

            # Set up function prototypes
            self.dll.start_proxy.restype = c_bool
            self.dll.start_proxy.argtypes = []

            self.dll.stop_proxy.restype = None
            self.dll.stop_proxy.argtypes = []

            self.dll.set_config.restype = c_bool
            self.dll.set_config.argtypes = [c_char_p, c_int, c_char_p]

            self.dll.set_log_callback.restype = None
            self.dll.set_log_callback.argtypes = [LOG_CALLBACK]

            self.dll.set_status_callback.restype = None
            self.dll.set_status_callback.argtypes = [STATUS_CALLBACK]

            self.dll.set_connection_callback.restype = None
            self.dll.set_connection_callback.argtypes = [CONNECTION_CALLBACK]

            self.dll.set_stats_callback.restype = None
            self.dll.set_stats_callback.argtypes = [STATS_CALLBACK]

            self.dll.set_disconnect_callback.restype = None
            self.dll.set_disconnect_callback.argtypes = [DISCONNECT_CALLBACK]

            self.dll.get_system_ips.restype = c_int
            self.dll.get_system_ips.argtypes = [c_char_p, c_int]

            self.dll.get_proxy_config.restype = c_bool
            self.dll.get_proxy_config.argtypes = [c_char_p, POINTER(c_int), c_char_p]

            self.dll.get_proxy_stats.restype = c_bool
            self.dll.get_proxy_stats.argtypes = [POINTER(c_int), POINTER(c_int)]

            print("All function prototypes set up successfully")
            self.is_loaded = True
            return True

        except Exception as e:
            print(f"Exception during DLL loading: {e}")
            traceback.print_exc()
            messagebox.showerror("DLL Load Error", f"Failed to load DLL: {str(e)}")
            return False

    def set_callbacks(self, log_callback, status_callback, connection_callback,
                     stats_callback, disconnect_callback):
        """Set all callback functions"""
        if not self.is_loaded:
            print("Cannot set callbacks: DLL not loaded")
            return False

        try:
            print("Creating callback function wrappers...")
            self.log_callback = LOG_CALLBACK(log_callback)
            self.status_callback = STATUS_CALLBACK(status_callback)
            self.connection_callback = CONNECTION_CALLBACK(connection_callback)
            self.stats_callback = STATS_CALLBACK(stats_callback)
            self.disconnect_callback = DISCONNECT_CALLBACK(disconnect_callback)

            print("Setting callback functions in DLL...")
            self.dll.set_log_callback(self.log_callback)
            print("Log callback set")
            self.dll.set_status_callback(self.status_callback)
            print("Status callback set")
            self.dll.set_connection_callback(self.connection_callback)
            print("Connection callback set")
            self.dll.set_stats_callback(self.stats_callback)
            print("Stats callback set")
            self.dll.set_disconnect_callback(self.disconnect_callback)
            print("Disconnect callback set")
            print("All callbacks set successfully")
            return True
        except Exception as e:
            print(f"Error setting callbacks: {e}")
            traceback.print_exc()
            return False

    def start_proxy(self):
        """Start the proxy server"""
        if not self.is_loaded:
            return False
        try:
            return self.dll.start_proxy()
        except Exception as e:
            print(f"Error starting proxy: {e}")
            return False

    def stop_proxy(self):
        """Stop the proxy server"""
        if not self.is_loaded:
            return
        try:
            self.dll.stop_proxy()
        except Exception as e:
            print(f"Error stopping proxy: {e}")

    def set_config(self, bind_addr, port, log_file):
        """Configure the proxy"""
        if not self.is_loaded:
            return False
        try:
            return self.dll.set_config(
                bind_addr.encode('utf-8') if bind_addr else None,
                port,
                log_file.encode('utf-8') if log_file else None
            )
        except Exception as e:
            print(f"Error setting config: {e}")
            return False

    def get_system_ips(self):
        """Get system IP addresses"""
        if not self.is_loaded:
            return []
        try:
            buffer = ctypes.create_string_buffer(4096)
            count = self.dll.get_system_ips(buffer, 4096)
            if count > 0:
                ip_string = buffer.value.decode('utf-8')
                return [ip.strip() for ip in ip_string.split(';') if ip.strip()]
            return []
        except Exception as e:
            print(f"Error getting system IPs: {e}")
            return []


class TLSProxyGUI:
    """Main GUI application for TLS Proxy control and monitoring"""

    def __init__(self, root):
        self.root = root
        self.root.title("TLS MITM Proxy Control Panel")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)

        # Initialize DLL
        possible_paths = [
            os.path.join(os.path.dirname(__file__), "build", "Debug", "tls_proxy.dll"),
            os.path.join(os.path.dirname(__file__), "build", "Release", "tls_proxy.dll"),
        ]

        dll_path = next((path for path in possible_paths if os.path.exists(path)), possible_paths[0])
        print(f"Trying to load DLL from: {dll_path}")
        self.proxy_dll = TLSProxyDLL(dll_path)

        # Data storage with reduced limits to prevent crashes
        self.log_entries = []
        self.status_messages = []
        self.connection_events = []
        self.max_log_entries = 500  # Reduced from 1000
        self.max_status_messages = 200  # Reduced from 500
        self.max_connection_events = 500  # Reduced from 1000

        # Threading and queues for callback data
        self.log_queue = queue.Queue()
        self.status_queue = queue.Queue()
        self.connection_queue = queue.Queue()
        self.stats_queue = queue.Queue()
        self.disconnect_queue = queue.Queue()
        self.proxy_running = False

        # Statistics
        self.current_connections = 0
        self.total_connections = 0
        self.bytes_transferred = 0

        # Create GUI
        self.create_widgets()
        self.setup_callbacks()

        # Start update timer
        self.update_display()

        # Try to load DLL on startup
        self.load_dll()

    def create_widgets(self):
        """Create all GUI widgets"""
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create tabs
        self.create_proxy_tab()
        self.create_config_tab()
        self.create_connections_tab()
        self.create_logs_tab()

    def create_proxy_tab(self):
        """Create the proxy control and monitoring tab"""
        proxy_frame = ttk.Frame(self.notebook)
        self.notebook.add(proxy_frame, text="Proxy Control")

        # Real-time Statistics panel
        stats_frame = ttk.LabelFrame(proxy_frame, text="Real-time Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(pady=5)

        self.current_connections_var = tk.StringVar(value="Active Connections: 0")
        ttk.Label(stats_grid, textvariable=self.current_connections_var).grid(row=0, column=0, padx=10, pady=2, sticky="w")

        self.total_connections_var = tk.StringVar(value="Total Connections: 0")
        ttk.Label(stats_grid, textvariable=self.total_connections_var).grid(row=0, column=1, padx=10, pady=2, sticky="w")

        self.bytes_var = tk.StringVar(value="Bytes Transferred: 0")
        ttk.Label(stats_grid, textvariable=self.bytes_var).grid(row=1, column=0, columnspan=2, padx=10, pady=2, sticky="w")

    def create_connections_tab(self):
        """Create the connections monitoring tab"""
        connections_frame = ttk.Frame(self.notebook)
        self.notebook.add(connections_frame, text="Connections")

        # Control buttons
        conn_control = ttk.Frame(connections_frame)
        conn_control.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(conn_control, text="Clear", command=self.clear_connections).pack(side=tk.LEFT, padx=5)
        ttk.Button(conn_control, text="Export", command=self.export_connections).pack(side=tk.LEFT, padx=5)

        # Auto-scroll checkbox
        self.auto_scroll_conn_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(conn_control, text="Auto-scroll", variable=self.auto_scroll_conn_var).pack(side=tk.LEFT, padx=10)

        # Connections table
        self.connections_tree = ttk.Treeview(connections_frame,
                                           columns=("timestamp", "event", "conn_id", "src_ip", "src_port", "dst_ip", "dst_port"),
                                           show="headings")

        self.connections_tree.heading("timestamp", text="Timestamp")
        self.connections_tree.heading("event", text="Event")
        self.connections_tree.heading("conn_id", text="Connection ID")
        self.connections_tree.heading("src_ip", text="Source IP")
        self.connections_tree.heading("src_port", text="Source Port")
        self.connections_tree.heading("dst_ip", text="Destination IP")
        self.connections_tree.heading("dst_port", text="Destination Port")

        # Column widths
        self.connections_tree.column("timestamp", width=150)
        self.connections_tree.column("event", width=100)
        self.connections_tree.column("conn_id", width=100)
        self.connections_tree.column("src_ip", width=120)
        self.connections_tree.column("src_port", width=80)
        self.connections_tree.column("dst_ip", width=120)
        self.connections_tree.column("dst_port", width=80)

        # Scrollbars
        conn_v_scroll = ttk.Scrollbar(connections_frame, orient=tk.VERTICAL, command=self.connections_tree.yview)
        conn_h_scroll = ttk.Scrollbar(connections_frame, orient=tk.HORIZONTAL, command=self.connections_tree.xview)
        self.connections_tree.configure(yscrollcommand=conn_v_scroll.set, xscrollcommand=conn_h_scroll.set)

        # Pack
        self.connections_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        conn_v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        conn_h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

    def create_logs_tab(self):
        """Create the logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")

        # Control buttons
        log_control = ttk.Frame(logs_frame)
        log_control.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(log_control, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_control, text="Save Logs", command=self.save_logs).pack(side=tk.LEFT, padx=5)

        # Status indicator
        status_frame = ttk.LabelFrame(logs_frame, text="Status Messages")
        status_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.status_display = scrolledtext.ScrolledText(status_frame, height=10)
        self.status_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Auto-scroll checkbox
        self.auto_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_control, text="Auto-scroll", variable=self.auto_scroll_var).pack(side=tk.LEFT, padx=10)

        # Log table
        self.logs_tree = ttk.Treeview(logs_frame,
                                     columns=("timestamp", "src_ip", "dst_ip", "port", "type", "data"),
                                     show="headings")

        self.logs_tree.heading("timestamp", text="Timestamp")
        self.logs_tree.heading("src_ip", text="Source IP")
        self.logs_tree.heading("dst_ip", text="Destination IP")
        self.logs_tree.heading("port", text="Port")
        self.logs_tree.heading("type", text="Type")
        self.logs_tree.heading("data", text="Data")

        # Column widths
        self.logs_tree.column("timestamp", width=150)
        self.logs_tree.column("src_ip", width=120)
        self.logs_tree.column("dst_ip", width=120)
        self.logs_tree.column("port", width=80)
        self.logs_tree.column("type", width=80)
        self.logs_tree.column("data", width=400)

        # Scrollbars
        logs_v_scroll = ttk.Scrollbar(logs_frame, orient=tk.VERTICAL, command=self.logs_tree.yview)
        logs_h_scroll = ttk.Scrollbar(logs_frame, orient=tk.HORIZONTAL, command=self.logs_tree.xview)
        self.logs_tree.configure(yscrollcommand=logs_v_scroll.set, xscrollcommand=logs_h_scroll.set)

        # Pack
        self.logs_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        logs_v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        logs_h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

    def create_config_tab(self):
        """Create the configuration tab"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="Configuration")

        # Proxy Settings
        proxy_settings_frame = ttk.LabelFrame(config_frame, text="Proxy Settings")
        proxy_settings_frame.pack(fill=tk.X, padx=5, pady=5)

        # Bind address
        bind_frame = ttk.Frame(proxy_settings_frame)
        bind_frame.pack(fill=tk.X, pady=5)

        ttk.Label(bind_frame, text="Bind Address:").pack(side=tk.LEFT)
        self.bind_addr_var = tk.StringVar(value="127.0.0.1")
        self.bind_addr_combo = ttk.Combobox(bind_frame, textvariable=self.bind_addr_var, width=20, state="readonly")
        self.bind_addr_combo.pack(side=tk.LEFT, padx=5)

        # Refresh interfaces button next to bind address
        ttk.Button(bind_frame, text="Refresh Interfaces", command=self.refresh_interfaces).pack(side=tk.LEFT, padx=5)

        # Port
        ttk.Label(bind_frame, text="Port:").pack(side=tk.LEFT, padx=(20, 0))
        self.port_var = tk.StringVar(value="4444")
        ttk.Entry(bind_frame, textvariable=self.port_var, width=10).pack(side=tk.LEFT, padx=5)

        # Apply config button
        ttk.Button(proxy_settings_frame, text="Apply Configuration", command=self.apply_config).pack(pady=10)

        # Proxy Control Buttons
        control_frame = ttk.LabelFrame(config_frame, text="Proxy Control")
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        control_buttons = ttk.Frame(control_frame)
        control_buttons.pack(pady=10)

        self.start_btn = ttk.Button(control_buttons, text="Start Proxy", command=self.start_proxy)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(control_buttons, text="Stop Proxy", command=self.stop_proxy)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Log file settings
        log_frame = ttk.LabelFrame(config_frame, text="Log File Settings")
        log_frame.pack(fill=tk.X, padx=5, pady=5)

        log_file_frame = ttk.Frame(log_frame)
        log_file_frame.pack(fill=tk.X, pady=5)

        ttk.Label(log_file_frame, text="Log File:").pack(side=tk.LEFT)
        self.log_file_var = tk.StringVar(value="tls_proxy.log")
        ttk.Entry(log_file_frame, textvariable=self.log_file_var, width=40).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_file_frame, text="Browse", command=self.browse_log_file).pack(side=tk.LEFT, padx=5)

        # Advanced settings
        advanced_frame = ttk.LabelFrame(config_frame, text="Advanced Settings")
        advanced_frame.pack(fill=tk.X, padx=5, pady=5)

        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(advanced_frame, text="Verbose Mode", variable=self.verbose_var).pack(anchor=tk.W, pady=2)

        self.auto_start_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(advanced_frame, text="Auto-start Proxy", variable=self.auto_start_var).pack(anchor=tk.W, pady=2)

    def setup_callbacks(self):
        """Set up the DLL callback functions"""
        def log_callback(timestamp, src_ip, dst_ip, dst_port, message_type, data):
            """Callback for log entries"""
            try:
                # Use error handling for each decode operation
                try:
                    timestamp_str = timestamp.decode('utf-8') if timestamp else datetime.now().strftime("%H:%M:%S")
                except UnicodeDecodeError:
                    timestamp_str = datetime.now().strftime("%H:%M:%S")

                try:
                    src_ip_str = src_ip.decode('utf-8') if src_ip else ""
                except UnicodeDecodeError:
                    src_ip_str = "[Binary Data]"

                try:
                    dst_ip_str = dst_ip.decode('utf-8') if dst_ip else ""
                except UnicodeDecodeError:
                    dst_ip_str = "[Binary Data]"

                try:
                    message_type_str = message_type.decode('utf-8') if message_type else ""
                except UnicodeDecodeError:
                    message_type_str = "Binary"

                try:
                    data_str = data.decode('utf-8') if data else ""
                except UnicodeDecodeError:
                    # For binary data, try to create a hex representation
                    if data:
                        try:
                            data_str = f"[Binary Data: {data[:20].hex()}...]"
                        except Exception:
                            data_str = "[Binary Data]"
                    else:
                        data_str = ""

                # Add to queue for thread-safe GUI updates
                self.log_queue.put({
                    'timestamp': timestamp_str,
                    'src_ip': src_ip_str,
                    'dst_ip': dst_ip_str,
                    'dst_port': dst_port,
                    'message_type': message_type_str,
                    'data': data_str
                })
            except Exception as e:
                print(f"Error in log callback: {e}")
                traceback.print_exc()

        def status_callback(message):
            """Callback for status messages"""
            try:
                try:
                    message_str = message.decode('utf-8') if message else ""
                except UnicodeDecodeError:
                    # For binary data, try to create a hex representation
                    if message:
                        try:
                            message_str = f"[Binary Data: {message[:20].hex()}...]"
                        except Exception:
                            message_str = "[Binary Data]"
                    else:
                        message_str = ""

                timestamp = datetime.now().strftime("%H:%M:%S")

                # Add to queue for thread-safe GUI updates
                self.status_queue.put(f"[{timestamp}] {message_str}")
            except Exception as e:
                print(f"Error in status callback: {e}")
                traceback.print_exc()

        def connection_callback(client_ip, client_port, server_ip, server_port, connection_id):
            """Callback for new connections"""
            try:
                try:
                    client_ip_str = client_ip.decode('utf-8') if client_ip else ""
                except UnicodeDecodeError:
                    client_ip_str = "[Binary Data]"

                try:
                    server_ip_str = server_ip.decode('utf-8') if server_ip else ""
                except UnicodeDecodeError:
                    server_ip_str = "[Binary Data]"

                timestamp = datetime.now().strftime("%H:%M:%S")

                # Add to queue for thread-safe GUI updates
                self.connection_queue.put({
                    'timestamp': timestamp,
                    'event': 'CONNECT',
                    'connection_id': connection_id,
                    'client_ip': client_ip_str,
                    'client_port': client_port,
                    'server_ip': server_ip_str,
                    'server_port': server_port
                })
            except Exception as e:
                print(f"Error in connection callback: {e}")
                traceback.print_exc()

        def stats_callback(active_connections, total_connections, bytes_transferred):
            """Callback for statistics updates"""
            try:
                # Add to queue for thread-safe GUI updates
                self.stats_queue.put({
                    'active_connections': active_connections,
                    'total_connections': total_connections,
                    'bytes_transferred': bytes_transferred
                })
            except Exception as e:
                print(f"Error in stats callback: {e}")
                traceback.print_exc()

        def disconnect_callback(connection_id, reason):
            """Callback for connection disconnections"""
            try:
                try:
                    reason_str = reason.decode('utf-8') if reason else ""
                except UnicodeDecodeError:
                    # For binary data, try to create a hex representation
                    if reason:
                        try:
                            reason_str = f"[Binary Data: {reason[:20].hex()}...]"
                        except Exception:
                            reason_str = "[Binary Data]"
                    else:
                        reason_str = ""

                timestamp = datetime.now().strftime("%H:%M:%S")

                # Add to queue for thread-safe GUI updates
                self.disconnect_queue.put({
                    'timestamp': timestamp,
                    'event': 'DISCONNECT',
                    'connection_id': connection_id,
                    'reason': reason_str
                })
            except Exception as e:
                print(f"Error in disconnect callback: {e}")
                traceback.print_exc()

        # Store callback functions to prevent garbage collection
        self.log_callback_func = log_callback
        self.status_callback_func = status_callback
        self.connection_callback_func = connection_callback
        self.stats_callback_func = stats_callback
        self.disconnect_callback_func = disconnect_callback

    def load_dll(self):
        """Load DLL and initialize callbacks"""
        try:
            print("Attempting to load DLL...")
            if self.proxy_dll.load_dll():
                print("DLL loaded successfully, setting up callbacks...")

                # Set up all callbacks
                if self.proxy_dll.set_callbacks(
                    self.log_callback_func,
                    self.status_callback_func,
                    self.connection_callback_func,
                    self.stats_callback_func,
                    self.disconnect_callback_func
                ):
                    print("All callbacks set successfully")
                    self.status_queue.put("[SYSTEM] DLL loaded successfully and all callbacks set")
                else:
                    print("Callback setup failed")
                    self.status_queue.put("[SYSTEM] DLL loaded but callback setup failed")

                # Refresh network interfaces
                self.refresh_interfaces()
            else:
                print("DLL loading failed")
                self.status_queue.put("[SYSTEM] DLL loading failed")
        except Exception as e:
            print(f"Exception during DLL loading: {e}")
            traceback.print_exc()
            messagebox.showerror("DLL Load Error", f"Exception during DLL loading: {str(e)}")
            self.status_queue.put("[SYSTEM] DLL loading exception")

    def start_proxy(self):
        """Start the proxy server"""
        if not self.proxy_dll.is_loaded:
            messagebox.showerror("Error", "DLL not loaded")
            return

        # Start in a separate thread to avoid blocking the GUI
        def start_thread():
            if self.proxy_dll.start_proxy():
                self.proxy_running = True
                self.status_queue.put("[SYSTEM] Proxy started successfully")
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", "Failed to start proxy"))

        threading.Thread(target=start_thread, daemon=True).start()

    def stop_proxy(self):
        """Stop the proxy server"""
        if not self.proxy_dll.is_loaded:
            return

        self.proxy_dll.stop_proxy()
        self.proxy_running = False
        self.status_queue.put("[SYSTEM] Proxy stopped")

    def apply_config(self):
        """Apply proxy configuration"""
        if not self.proxy_dll.is_loaded:
            messagebox.showerror("Error", "DLL not loaded")
            return

        try:
            bind_addr = self.bind_addr_var.get()
            port = int(self.port_var.get())
            log_file = self.log_file_var.get()

            if self.proxy_dll.set_config(bind_addr, port, log_file):
                self.status_queue.put(f"[CONFIG] Configuration applied: {bind_addr}:{port}")
            else:
                messagebox.showerror("Error", "Failed to apply configuration")
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")

    def refresh_interfaces(self):
        """Refresh the list of network interfaces"""
        if not self.proxy_dll.is_loaded:
            return

        # Get system IPs
        ip_addresses = self.proxy_dll.get_system_ips()
        print(f"Found IP addresses: {ip_addresses}")

        # Update combo box values
        self.bind_addr_combo['values'] = ip_addresses

        self.status_queue.put(f"[SYSTEM] Found {len(ip_addresses)} network interfaces")

    def clear_connections(self):
        """Clear connection history"""
        self.connection_events.clear()
        for item in self.connections_tree.get_children():
            self.connections_tree.delete(item)

    def clear_logs(self):
        """Clear all logs"""
        self.log_entries.clear()
        self.status_messages.clear()

        # Clear GUI displays
        for item in self.logs_tree.get_children():
            self.logs_tree.delete(item)

        self.status_display.delete(1.0, tk.END)

        self.status_queue.put("[SYSTEM] Logs cleared")

    def export_connections(self):
        """Export connection history to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("Timestamp,Event,Connection ID,Source IP,Source Port,Destination IP,Destination Port\n")
                    for event in self.connection_events:
                        f.write(f"{event['timestamp']},{event['event']},{event.get('connection_id', '')},{event.get('client_ip', '')},{event.get('client_port', '')},{event.get('server_ip', '')},{event.get('server_port', '')}\n")

                self.status_queue.put(f"[SYSTEM] Connection history exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export connections: {str(e)}")

    def save_logs(self):
        """Save logs to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("=== TLS MITM Proxy Logs ===\n\n")
                    f.write("Status Messages:\n")
                    for msg in self.status_messages:
                        f.write(f"{msg}\n")

                    f.write("\nSystem Log Entries:\n")
                    for entry in self.log_entries:
                        f.write(f"{entry['timestamp']} | {entry['src_ip']} | {entry['dst_ip']} | {entry['dst_port']} | {entry['message_type']} | {entry['data']}\n")

                self.status_queue.put(f"[SYSTEM] Logs saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {str(e)}")

    def browse_log_file(self):
        """Browse for log file location"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )

        if filename:
            self.log_file_var.set(filename)

    def update_display(self):
        """Update the GUI display with new data from queues (real-time callback system)"""

        # Process log entries with limits to prevent crashes
        try:
            processed_count = 0
            while processed_count < 10:  # Limit processing to prevent GUI freezing
                entry = self.log_queue.get_nowait()
                processed_count += 1

                # Add to storage
                self.log_entries.append(entry)
                if len(self.log_entries) > self.max_log_entries:
                    self.log_entries.pop(0)

                # Add to treeview
                try:
                    self.logs_tree.insert('', 'end', values=(
                        entry['timestamp'],
                        entry['src_ip'],
                        entry['dst_ip'],
                        entry['dst_port'],
                        entry['message_type'],
                        entry['data'][:100] + "..." if len(entry['data']) > 100 else entry['data']
                    ))

                    # Remove old entries from treeview
                    children = self.logs_tree.get_children()
                    if len(children) > self.max_log_entries:
                        self.logs_tree.delete(children[0])

                    # Auto-scroll
                    if self.auto_scroll_var.get():
                        self.logs_tree.see(self.logs_tree.get_children()[-1])
                except Exception as e:
                    print(f"Error updating logs tree: {e}")

        except queue.Empty:
            pass
        except Exception as e:
            print(f"Error processing log entries: {e}")
            traceback.print_exc()

        # Process status messages with limits
        try:
            processed_count = 0
            while processed_count < 10:  # Limit processing to prevent GUI freezing
                message = self.status_queue.get_nowait()
                processed_count += 1

                # Add to storage
                self.status_messages.append(message)
                if len(self.status_messages) > self.max_status_messages:
                    self.status_messages.pop(0)

                # Add to status display
                try:
                    self.status_display.insert(tk.END, message + "\n")

                    # Auto-scroll
                    self.status_display.see(tk.END)

                    # Limit text widget size
                    lines = self.status_display.get(1.0, tk.END).count('\n')
                    if lines > self.max_status_messages:
                        self.status_display.delete(1.0, "2.0")
                except Exception as e:
                    print(f"Error updating status display: {e}")

        except queue.Empty:
            pass
        except Exception as e:
            print(f"Error processing status messages: {e}")
            traceback.print_exc()

        # Process connection events with limits
        try:
            processed_count = 0
            while processed_count < 10:  # Limit processing to prevent GUI freezing
                event = self.connection_queue.get_nowait()
                processed_count += 1

                # Add to storage
                self.connection_events.append(event)
                if len(self.connection_events) > self.max_connection_events:
                    self.connection_events.pop(0)

                # Add to treeview
                try:
                    self.connections_tree.insert('', 'end', values=(
                        event['timestamp'],
                        event['event'],
                        event['connection_id'],
                        event['client_ip'],
                        event['client_port'],
                        event['server_ip'],
                        event['server_port']
                    ))

                    # Remove old entries from treeview
                    children = self.connections_tree.get_children()
                    if len(children) > self.max_connection_events:
                        self.connections_tree.delete(children[0])

                    # Auto-scroll
                    if self.auto_scroll_conn_var.get():
                        self.connections_tree.see(self.connections_tree.get_children()[-1])
                except Exception as e:
                    print(f"Error updating connections tree: {e}")

        except queue.Empty:
            pass
        except Exception as e:
            print(f"Error processing connection events: {e}")
            traceback.print_exc()

        # Process statistics updates with limits
        try:
            processed_count = 0
            while processed_count < 5:  # Limit stats processing
                stats = self.stats_queue.get_nowait()
                processed_count += 1

                # Update statistics display
                try:
                    self.current_connections = stats['active_connections']
                    self.total_connections = stats['total_connections']
                    self.bytes_transferred = stats['bytes_transferred']

                    self.current_connections_var.set(f"Active Connections: {self.current_connections}")
                    self.total_connections_var.set(f"Total Connections: {self.total_connections}")
                    self.bytes_var.set(f"Bytes Transferred: {self.bytes_transferred:,}")
                except Exception as e:
                    print(f"Error updating statistics: {e}")

        except queue.Empty:
            pass
        except Exception as e:
            print(f"Error processing statistics: {e}")
            traceback.print_exc()

        # Process disconnect events with limits
        try:
            processed_count = 0
            while processed_count < 10:  # Limit disconnect processing
                event = self.disconnect_queue.get_nowait()
                processed_count += 1

                # Add to connection events as a disconnect
                disconnect_event = {
                    'timestamp': event['timestamp'],
                    'event': event['event'],
                    'connection_id': event['connection_id'],
                    'client_ip': '',
                    'client_port': '',
                    'server_ip': event['reason'],  # Put reason in server_ip column
                    'server_port': ''
                }

                # Add to storage
                self.connection_events.append(disconnect_event)
                if len(self.connection_events) > self.max_connection_events:
                    self.connection_events.pop(0)

                # Add to treeview
                try:
                    self.connections_tree.insert('', 'end', values=(
                        disconnect_event['timestamp'],
                        disconnect_event['event'],
                        disconnect_event['connection_id'],
                        disconnect_event['client_ip'],
                        disconnect_event['client_port'],
                        disconnect_event['server_ip'],
                        disconnect_event['server_port']
                    ))

                    # Remove old entries from treeview
                    children = self.connections_tree.get_children()
                    if len(children) > self.max_connection_events:
                        self.connections_tree.delete(children[0])

                    # Auto-scroll
                    if self.auto_scroll_conn_var.get():
                        self.connections_tree.see(self.connections_tree.get_children()[-1])
                except Exception as e:
                    print(f"Error updating connections tree for disconnect: {e}")

        except queue.Empty:
            pass
        except Exception as e:
            print(f"Error processing disconnect events: {e}")
            traceback.print_exc()

        # Schedule next update
        self.root.after(100, self.update_display)  # Update every 100ms


def check_admin_privileges():
    """Check if running with administrator privileges"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def main():
    """Main application entry point"""
    print("Starting TLS MITM Proxy GUI...")
    # Check for administrator privileges
    if not check_admin_privileges():
        messagebox.showwarning(
            "Administrator Recommended",
            "This application may require administrator privileges for optimal functionality.\n"
            "Some features may not work properly without elevated permissions."
        )

    # Create and run the GUI
    root = tk.Tk()
    app = TLSProxyGUI(root)

    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("Application interrupted by user")
    except Exception as e:
        print(f"Application error: {e}")
        messagebox.showerror("Application Error", f"An error occurred: {str(e)}")
    finally:
        # Clean shutdown
        if app.proxy_dll.is_loaded:
            app.proxy_dll.stop_proxy()


if __name__ == "__main__":
    main()
