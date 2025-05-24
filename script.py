#!/usr/bin/env python3
"""
TLS MITM Proxy GUI Application
A comprehensive GUI for controlling and monitoring the TLS proxy DLL
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

# Define callback function types to match the DLL
LOG_CALLBACK = ctypes.WINFUNCTYPE(None, c_char_p, c_char_p, c_char_p, c_int, c_char_p, c_char_p)
STATUS_CALLBACK = ctypes.WINFUNCTYPE(None, c_char_p)

class TLSProxyDLL:
    """Wrapper class for the TLS Proxy DLL"""
    
    def __init__(self, dll_path):
        self.dll_path = dll_path
        self.dll = None
        self.is_loaded = False
        self.log_callback = None
        self.status_callback = None
        
    def load_dll(self):
        """Load the DLL and set up function prototypes"""
        try:
            # Load the DLL
            self.dll = ctypes.CDLL(self.dll_path)
            
            # Set up function prototypes
            self.dll.init_proxy.restype = c_bool
            self.dll.init_proxy.argtypes = []
            
            self.dll.start_proxy.restype = c_bool
            self.dll.start_proxy.argtypes = []
            
            self.dll.stop_proxy.restype = None
            self.dll.stop_proxy.argtypes = []
            
            self.dll.set_config.restype = c_bool
            self.dll.set_config.argtypes = [c_char_p, c_int, c_char_p]
            
            self.dll.enable_windivert.restype = c_bool
            self.dll.enable_windivert.argtypes = []
            
            self.dll.disable_windivert.restype = None
            self.dll.disable_windivert.argtypes = []
            
            self.dll.set_log_callback.restype = None
            self.dll.set_log_callback.argtypes = [LOG_CALLBACK]
            
            self.dll.set_status_callback.restype = None
            self.dll.set_status_callback.argtypes = [STATUS_CALLBACK]
            
            self.dll.get_system_ips.restype = c_int
            self.dll.get_system_ips.argtypes = [c_char_p, c_int]
            
            self.dll.get_proxy_config.restype = c_bool
            self.dll.get_proxy_config.argtypes = [c_char_p, POINTER(c_int), c_char_p]
            
            self.dll.get_proxy_stats.restype = c_bool
            self.dll.get_proxy_stats.argtypes = [POINTER(c_int), POINTER(c_int)]
            
            self.is_loaded = True
            return True
            
        except Exception as e:
            messagebox.showerror("DLL Load Error", f"Failed to load DLL: {str(e)}")
            return False
    
    def set_callbacks(self, log_callback, status_callback):
        """Set the callback functions"""
        if not self.is_loaded:
            return False
            
        try:
            self.log_callback = LOG_CALLBACK(log_callback)
            self.status_callback = STATUS_CALLBACK(status_callback)
            
            self.dll.set_log_callback(self.log_callback)
            self.dll.set_status_callback(self.status_callback)
            return True
        except Exception as e:
            print(f"Error setting callbacks: {e}")
            return False
    
    def init_proxy(self):
        """Initialize the proxy"""
        if not self.is_loaded:
            return False
        try:
            return self.dll.init_proxy()
        except Exception as e:
            print(f"Error initializing proxy: {e}")
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
    
    def enable_windivert(self):
        """Enable WinDivert functionality"""
        if not self.is_loaded:
            return False
        try:
            return self.dll.enable_windivert()
        except Exception as e:
            print(f"Error enabling WinDivert: {e}")
            return False
    
    def disable_windivert(self):
        """Disable WinDivert functionality"""
        if not self.is_loaded:
            return
        try:
            self.dll.disable_windivert()
        except Exception as e:
            print(f"Error disabling WinDivert: {e}")
    
    def get_system_ips(self):
        """Get system IP addresses"""
        if not self.is_loaded:
            return []
        try:
            buffer = ctypes.create_string_buffer(4096)
            count = self.dll.get_system_ips(buffer, 4096)
            if count > 0:
                ip_string = buffer.value.decode('utf-8')
                return [ip.strip() for ip in ip_string.split(',') if ip.strip()]
            return []
        except Exception as e:
            print(f"Error getting system IPs: {e}")
            return []
    
    def get_proxy_config(self):
        """Get current proxy configuration"""
        if not self.is_loaded:
            return None, None, None
        try:
            bind_addr = ctypes.create_string_buffer(256)
            port = c_int()
            log_file = ctypes.create_string_buffer(512)
            
            if self.dll.get_proxy_config(bind_addr, ctypes.byref(port), log_file):
                return (
                    bind_addr.value.decode('utf-8') if bind_addr.value else "",
                    port.value,
                    log_file.value.decode('utf-8') if log_file.value else ""
                )
            return None, None, None
        except Exception as e:
            print(f"Error getting proxy config: {e}")
            return None, None, None
    
    def get_proxy_stats(self):
        """Get proxy statistics"""
        if not self.is_loaded:
            return None, None
        try:
            connections = c_int()
            bytes_transferred = c_int()
            
            if self.dll.get_proxy_stats(ctypes.byref(connections), ctypes.byref(bytes_transferred)):
                return connections.value, bytes_transferred.value
            return None, None
        except Exception as e:
            print(f"Error getting proxy stats: {e}")
            return None, None

class TLSProxyGUI:
    """Main GUI application for TLS Proxy control and monitoring"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("TLS MITM Proxy Control Panel")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Initialize DLL
        dll_path = os.path.join(os.path.dirname(__file__), "build-dll", "Debug", "tls_proxy.dll")
        self.proxy_dll = TLSProxyDLL(dll_path)
        
        # Data storage
        self.log_entries = []
        self.status_messages = []
        self.max_log_entries = 1000
        self.max_status_messages = 500
        
        # Threading
        self.log_queue = queue.Queue()
        self.status_queue = queue.Queue()
        self.proxy_running = False
        self.windivert_enabled = False
        
        # Create GUI
        self.create_widgets()
        self.setup_callbacks()
        
        # Start update timer
        self.update_display()
        
        # Try to load DLL on startup
        self.load_dll()
    
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # Main toolbar
        toolbar = ttk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        # DLL Status
        self.dll_status_var = tk.StringVar(value="DLL: Not Loaded")
        ttk.Label(toolbar, textvariable=self.dll_status_var).pack(side=tk.LEFT, padx=5)
        
        # Load DLL Button
        ttk.Button(toolbar, text="Load DLL", command=self.load_dll).pack(side=tk.LEFT, padx=5)
        
        # Proxy Status
        self.proxy_status_var = tk.StringVar(value="Proxy: Stopped")
        ttk.Label(toolbar, textvariable=self.proxy_status_var).pack(side=tk.LEFT, padx=10)
        
        # WinDivert Status
        self.windivert_status_var = tk.StringVar(value="WinDivert: Disabled")
        ttk.Label(toolbar, textvariable=self.windivert_status_var).pack(side=tk.LEFT, padx=10)
        
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.create_proxy_tab()
        self.create_windivert_tab()
        self.create_logs_tab()
        self.create_config_tab()
    
    def create_proxy_tab(self):
        """Create the proxy control and monitoring tab"""
        proxy_frame = ttk.Frame(self.notebook)
        self.notebook.add(proxy_frame, text="Proxy Control")
        
        # Control panel
        control_frame = ttk.LabelFrame(proxy_frame, text="Proxy Control")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        control_buttons = ttk.Frame(control_frame)
        control_buttons.pack(pady=10)
        
        self.init_btn = ttk.Button(control_buttons, text="Initialize", command=self.init_proxy)
        self.init_btn.pack(side=tk.LEFT, padx=5)
        
        self.start_btn = ttk.Button(control_buttons, text="Start Proxy", command=self.start_proxy)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_buttons, text="Stop Proxy", command=self.stop_proxy)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Configuration panel
        config_frame = ttk.LabelFrame(proxy_frame, text="Quick Configuration")
        config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Bind Address
        addr_frame = ttk.Frame(config_frame)
        addr_frame.pack(fill=tk.X, pady=5)
        ttk.Label(addr_frame, text="Bind Address:").pack(side=tk.LEFT)
        self.bind_addr_var = tk.StringVar(value="127.0.0.1")
        self.bind_addr_combo = ttk.Combobox(addr_frame, textvariable=self.bind_addr_var, width=20)
        self.bind_addr_combo.pack(side=tk.LEFT, padx=5)
        
        # Port
        port_frame = ttk.Frame(config_frame)
        port_frame.pack(fill=tk.X, pady=5)
        ttk.Label(port_frame, text="Port:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="4433")
        ttk.Entry(port_frame, textvariable=self.port_var, width=10).pack(side=tk.LEFT, padx=5)
        
        # Apply config button
        ttk.Button(config_frame, text="Apply Configuration", command=self.apply_config).pack(pady=5)
        
        # Statistics panel
        stats_frame = ttk.LabelFrame(proxy_frame, text="Statistics")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.connections_var = tk.StringVar(value="Connections: 0")
        ttk.Label(stats_frame, textvariable=self.connections_var).pack(pady=5)
        
        self.bytes_var = tk.StringVar(value="Bytes Transferred: 0")
        ttk.Label(stats_frame, textvariable=self.bytes_var).pack(pady=5)
        
        # History table
        history_frame = ttk.LabelFrame(proxy_frame, text="Connection History")
        history_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview for log entries
        self.proxy_tree = ttk.Treeview(history_frame, columns=("timestamp", "src_ip", "dst_ip", "port", "type", "data"), show="headings")
        self.proxy_tree.heading("timestamp", text="Timestamp")
        self.proxy_tree.heading("src_ip", text="Source IP")
        self.proxy_tree.heading("dst_ip", text="Destination IP")
        self.proxy_tree.heading("port", text="Port")
        self.proxy_tree.heading("type", text="Type")
        self.proxy_tree.heading("data", text="Data")
        
        # Column widths
        self.proxy_tree.column("timestamp", width=150)
        self.proxy_tree.column("src_ip", width=120)
        self.proxy_tree.column("dst_ip", width=120)
        self.proxy_tree.column("port", width=80)
        self.proxy_tree.column("type", width=80)
        self.proxy_tree.column("data", width=400)
        
        # Scrollbars
        proxy_v_scroll = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.proxy_tree.yview)
        proxy_h_scroll = ttk.Scrollbar(history_frame, orient=tk.HORIZONTAL, command=self.proxy_tree.xview)
        self.proxy_tree.configure(yscrollcommand=proxy_v_scroll.set, xscrollcommand=proxy_h_scroll.set)
        
        # Pack treeview and scrollbars
        self.proxy_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        proxy_v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        proxy_h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_windivert_tab(self):
        """Create the WinDivert control tab"""
        windivert_frame = ttk.Frame(self.notebook)
        self.notebook.add(windivert_frame, text="WinDivert")
        
        # Control panel
        control_frame = ttk.LabelFrame(windivert_frame, text="WinDivert Control")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        control_buttons = ttk.Frame(control_frame)
        control_buttons.pack(pady=10)
        
        self.enable_windivert_btn = ttk.Button(control_buttons, text="Enable WinDivert", command=self.enable_windivert)
        self.enable_windivert_btn.pack(side=tk.LEFT, padx=5)
        
        self.disable_windivert_btn = ttk.Button(control_buttons, text="Disable WinDivert", command=self.disable_windivert)
        self.disable_windivert_btn.pack(side=tk.LEFT, padx=5)
        
        # WinDivert logs
        logs_frame = ttk.LabelFrame(windivert_frame, text="WinDivert Logs")
        logs_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.windivert_text = scrolledtext.ScrolledText(logs_frame, height=20)
        self.windivert_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_logs_tab(self):
        """Create the system logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="System Logs")
        
        # Control buttons
        log_control = ttk.Frame(logs_frame)
        log_control.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(log_control, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_control, text="Save Logs", command=self.save_logs).pack(side=tk.LEFT, padx=5)
        
        # Auto-scroll checkbox
        self.auto_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_control, text="Auto-scroll", variable=self.auto_scroll_var).pack(side=tk.LEFT, padx=10)
        
        # Status messages display
        status_frame = ttk.LabelFrame(logs_frame, text="Status Messages")
        status_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.status_text = scrolledtext.ScrolledText(status_frame, height=20)
        self.status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_config_tab(self):
        """Create the configuration tab"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="Configuration")
        
        # Network interfaces
        interfaces_frame = ttk.LabelFrame(config_frame, text="Network Interfaces")
        interfaces_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(interfaces_frame, text="Refresh Interfaces", command=self.refresh_interfaces).pack(pady=5)
        
        self.interfaces_tree = ttk.Treeview(interfaces_frame, columns=("ip",), show="headings", height=6)
        self.interfaces_tree.heading("ip", text="Available IP Addresses")
        self.interfaces_tree.pack(fill=tk.X, padx=5, pady=5)
        
        # Certificate settings
        cert_frame = ttk.LabelFrame(config_frame, text="Certificate Settings")
        cert_frame.pack(fill=tk.X, padx=5, pady=5)
        
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
                timestamp_str = timestamp.decode('utf-8') if timestamp else datetime.now().strftime("%H:%M:%S")
                src_ip_str = src_ip.decode('utf-8') if src_ip else ""
                dst_ip_str = dst_ip.decode('utf-8') if dst_ip else ""
                message_type_str = message_type.decode('utf-8') if message_type else ""
                data_str = data.decode('utf-8') if data else ""
                
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
        
        def status_callback(message):
            """Callback for status messages"""
            try:
                message_str = message.decode('utf-8') if message else ""
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                # Add to queue for thread-safe GUI updates
                self.status_queue.put(f"[{timestamp}] {message_str}")
            except Exception as e:
                print(f"Error in status callback: {e}")
        
        self.log_callback_func = log_callback
        self.status_callback_func = status_callback
    
    def load_dll(self):
        """Load the DLL and initialize callbacks"""
        if self.proxy_dll.load_dll():
            self.dll_status_var.set("DLL: Loaded")
            
            # Set up callbacks
            if self.proxy_dll.set_callbacks(self.log_callback_func, self.status_callback_func):
                self.status_queue.put("[SYSTEM] DLL loaded successfully and callbacks set")
            else:
                self.status_queue.put("[SYSTEM] DLL loaded but callback setup failed")
            
            # Refresh network interfaces
            self.refresh_interfaces()
        else:
            self.dll_status_var.set("DLL: Load Failed")
    
    def init_proxy(self):
        """Initialize the proxy"""
        if not self.proxy_dll.is_loaded:
            messagebox.showerror("Error", "DLL not loaded")
            return
        
        if self.proxy_dll.init_proxy():
            self.status_queue.put("[SYSTEM] Proxy initialized successfully")
        else:
            messagebox.showerror("Error", "Failed to initialize proxy")
    
    def start_proxy(self):
        """Start the proxy server"""
        if not self.proxy_dll.is_loaded:
            messagebox.showerror("Error", "DLL not loaded")
            return
        
        # Start in a separate thread to avoid blocking the GUI
        def start_thread():
            if self.proxy_dll.start_proxy():
                self.proxy_running = True
                self.root.after(0, lambda: self.proxy_status_var.set("Proxy: Running"))
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
        self.proxy_status_var.set("Proxy: Stopped")
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
    
    def enable_windivert(self):
        """Enable WinDivert functionality"""
        if not self.proxy_dll.is_loaded:
            messagebox.showerror("Error", "DLL not loaded")
            return
        
        if self.proxy_dll.enable_windivert():
            self.windivert_enabled = True
            self.windivert_status_var.set("WinDivert: Enabled")
            self.status_queue.put("[WINDIVERT] WinDivert enabled")
        else:
            messagebox.showerror("Error", "Failed to enable WinDivert")
    
    def disable_windivert(self):
        """Disable WinDivert functionality"""
        if not self.proxy_dll.is_loaded:
            return
        
        self.proxy_dll.disable_windivert()
        self.windivert_enabled = False
        self.windivert_status_var.set("WinDivert: Disabled")
        self.status_queue.put("[WINDIVERT] WinDivert disabled")
    
    def refresh_interfaces(self):
        """Refresh the list of network interfaces"""
        if not self.proxy_dll.is_loaded:
            return
        
        # Clear existing items
        for item in self.interfaces_tree.get_children():
            self.interfaces_tree.delete(item)
        
        # Get system IPs
        ip_addresses = self.proxy_dll.get_system_ips()
        
        # Update combo box and tree
        self.bind_addr_combo['values'] = ['127.0.0.1', '0.0.0.0'] + ip_addresses
        
        for ip in ip_addresses:
            self.interfaces_tree.insert('', 'end', values=(ip,))
        
        self.status_queue.put(f"[SYSTEM] Found {len(ip_addresses)} network interfaces")
    
    def clear_logs(self):
        """Clear all logs"""
        self.log_entries.clear()
        self.status_messages.clear()
        
        # Clear GUI displays
        for item in self.proxy_tree.get_children():
            self.proxy_tree.delete(item)
        
        self.status_text.delete(1.0, tk.END)
        self.windivert_text.delete(1.0, tk.END)
        
        self.status_queue.put("[SYSTEM] Logs cleared")
    
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
                    
                    f.write("\nConnection Log Entries:\n")
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
        """Update the GUI display with new data from queues"""
        
        # Process log entries
        try:
            while True:
                entry = self.log_queue.get_nowait()
                
                # Add to storage
                self.log_entries.append(entry)
                if len(self.log_entries) > self.max_log_entries:
                    self.log_entries.pop(0)
                
                # Add to treeview
                self.proxy_tree.insert('', 'end', values=(
                    entry['timestamp'],
                    entry['src_ip'],
                    entry['dst_ip'],
                    entry['dst_port'],
                    entry['message_type'],
                    entry['data'][:100] + "..." if len(entry['data']) > 100 else entry['data']
                ))
                
                # Remove old entries from treeview
                children = self.proxy_tree.get_children()
                if len(children) > self.max_log_entries:
                    self.proxy_tree.delete(children[0])
                
                # Auto-scroll
                if self.auto_scroll_var.get():
                    self.proxy_tree.see(self.proxy_tree.get_children()[-1])
                
        except queue.Empty:
            pass
        
        # Process status messages
        try:
            while True:
                message = self.status_queue.get_nowait()
                
                # Add to storage
                self.status_messages.append(message)
                if len(self.status_messages) > self.max_status_messages:
                    self.status_messages.pop(0)
                
                # Add to text widget
                self.status_text.insert(tk.END, message + "\n")
                
                # Auto-scroll
                if self.auto_scroll_var.get():
                    self.status_text.see(tk.END)
                
                # Limit text widget size
                lines = self.status_text.get(1.0, tk.END).count('\n')
                if lines > self.max_status_messages:
                    self.status_text.delete(1.0, "2.0")
                
        except queue.Empty:
            pass
        
        # Update statistics
        if self.proxy_dll.is_loaded:
            connections, bytes_transferred = self.proxy_dll.get_proxy_stats()
            if connections is not None:
                self.connections_var.set(f"Connections: {connections}")
                self.bytes_var.set(f"Bytes Transferred: {bytes_transferred}")
        
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
    
    # Check for administrator privileges
    if not check_admin_privileges():
        messagebox.showwarning(
            "Administrator Required",
            "This application requires administrator privileges for WinDivert functionality.\n"
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
            app.proxy_dll.disable_windivert()

if __name__ == "__main__":
    main()