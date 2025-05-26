using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;

namespace TLS_MITM_WPF;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    // Data models for logs
    public class LogEvent : INotifyPropertyChanged
    {
        private string _timestamp = "";
        private string _sourceIp = "";
        private string _destinationIp = "";
        private int _port;
        private string _type = "";
        private string _data = "";

        public string Timestamp
        {
            get => _timestamp;
            set { _timestamp = value; OnPropertyChanged(nameof(Timestamp)); }
        }

        public string SourceIp
        {
            get => _sourceIp;
            set { _sourceIp = value; OnPropertyChanged(nameof(SourceIp)); }
        }

        public string DestinationIp
        {
            get => _destinationIp;
            set { _destinationIp = value; OnPropertyChanged(nameof(DestinationIp)); }
        }

        public int Port
        {
            get => _port;
            set { _port = value; OnPropertyChanged(nameof(Port)); }
        }

        public string Type
        {
            get => _type;
            set { _type = value; OnPropertyChanged(nameof(Type)); }
        }

        public string Data
        {
            get => _data;
            set { _data = value; OnPropertyChanged(nameof(Data)); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged(string propertyName) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    // Data models for connection events
    public class ConnectionEvent : INotifyPropertyChanged
    {
        private string _timestamp = "";
        private string _event = "";
        private int _connectionId;
        private string _sourceIp = "";
        private int _sourcePort;
        private string _destinationIp = "";
        private int _destinationPort;

        public string Timestamp
        {
            get => _timestamp;
            set { _timestamp = value; OnPropertyChanged(nameof(Timestamp)); }
        }

        public string Event
        {
            get => _event;
            set { _event = value; OnPropertyChanged(nameof(Event)); }
        }

        public int ConnectionId
        {
            get => _connectionId;
            set { _connectionId = value; OnPropertyChanged(nameof(ConnectionId)); }
        }

        public string SourceIp
        {
            get => _sourceIp;
            set { _sourceIp = value; OnPropertyChanged(nameof(SourceIp)); }
        }

        public int SourcePort
        {
            get => _sourcePort;
            set { _sourcePort = value; OnPropertyChanged(nameof(SourcePort)); }
        }

        public string DestinationIp
        {
            get => _destinationIp;
            set { _destinationIp = value; OnPropertyChanged(nameof(DestinationIp)); }
        }

        public int DestinationPort
        {
            get => _destinationPort;
            set { _destinationPort = value; OnPropertyChanged(nameof(DestinationPort)); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged(string propertyName) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    // Collections
    private readonly ObservableCollection<LogEvent> _logEvents = new();
    private readonly ObservableCollection<ConnectionEvent> _connectionEvents = new();
    private readonly ObservableCollection<LogEvent> _historyEvents = new();
    private readonly List<string> _statusMessages = new();

    // Properties for data binding
    private int _activeConnections;
    public int ActiveConnections
    {
        get => _activeConnections;
        set { _activeConnections = value; OnPropertyChanged(nameof(ActiveConnections)); }
    }

    private int _totalConnections;
    public int TotalConnections
    {
        get => _totalConnections;
        set { _totalConnections = value; OnPropertyChanged(nameof(TotalConnections)); }
    }

    private int _bytesSent;
    public int BytesSent
    {
        get => _bytesSent;
        set { _bytesSent = value; OnPropertyChanged(nameof(BytesSent)); }
    }

    private int _bytesReceived;
    public int BytesReceived
    {
        get => _bytesReceived;
        set { _bytesReceived = value; OnPropertyChanged(nameof(BytesReceived)); }
    }

    // DLL interaction
    private bool _proxyDllLoaded = false;
    private bool _proxyRunning = false;

    // Timer for UI updates
    private DispatcherTimer? _updateTimer = null;

    // DLL P/Invoke declarations
    [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool start_proxy();

    [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void stop_proxy();

    [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool set_config(
        [MarshalAs(UnmanagedType.LPStr)] string bind_addr,
        int port,
        [MarshalAs(UnmanagedType.LPStr)] string log_file);

    [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int get_system_ips(
        [MarshalAs(UnmanagedType.LPStr)] StringBuilder buffer,
        int buffer_size);

    [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool get_proxy_config(
        [MarshalAs(UnmanagedType.LPStr)] StringBuilder bind_addr,
        ref int port,
        [MarshalAs(UnmanagedType.LPStr)] StringBuilder log_file);

    [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool get_proxy_stats(
        ref int connections,
        ref int bytes_transferred);

    // Callback function delegates
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void LogCallbackDelegate(
        [MarshalAs(UnmanagedType.LPStr)] string timestamp,
        [MarshalAs(UnmanagedType.LPStr)] string src_ip,
        [MarshalAs(UnmanagedType.LPStr)] string dst_ip,
        int dst_port,
        [MarshalAs(UnmanagedType.LPStr)] string message_type,
        [MarshalAs(UnmanagedType.LPStr)] string data);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void StatusCallbackDelegate([MarshalAs(UnmanagedType.LPStr)] string message);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void ConnectionCallbackDelegate(
        [MarshalAs(UnmanagedType.LPStr)] string client_ip,
        int client_port,
        [MarshalAs(UnmanagedType.LPStr)] string target_host,
        int target_port,
        int connection_id);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void StatsCallbackDelegate(
        int total_connections,
        int active_connections,
        int total_bytes_transferred);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void DisconnectCallbackDelegate(
        int connection_id,
        [MarshalAs(UnmanagedType.LPStr)] string reason);

    [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void set_log_callback(LogCallbackDelegate callback);

    [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void set_status_callback(StatusCallbackDelegate callback);

    [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void set_connection_callback(ConnectionCallbackDelegate callback);

    [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void set_stats_callback(StatsCallbackDelegate callback);

    [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void set_disconnect_callback(DisconnectCallbackDelegate callback);

    // Callback function instances
    private readonly LogCallbackDelegate _logCallback;
    private readonly StatusCallbackDelegate _statusCallback;
    private readonly ConnectionCallbackDelegate _connectionCallback;
    private readonly StatsCallbackDelegate _statsCallback;
    private readonly DisconnectCallbackDelegate _disconnectCallback;

    public event PropertyChangedEventHandler? PropertyChanged;
    protected virtual void OnPropertyChanged(string propertyName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    public MainWindow()
    {
        InitializeComponent();

        // Initialize callbacks
        _logCallback = LogCallback;
        _statusCallback = StatusCallback;
        _connectionCallback = ConnectionCallback;
        _statsCallback = StatsCallback;
        _disconnectCallback = DisconnectCallback;

        // Initialize ListViews
        ConnectionsList.ItemsSource = _connectionEvents;
        LogsList.ItemsSource = _logEvents;
        HistoryList.ItemsSource = _historyEvents;

        // Initialize timer for UI updates
        _updateTimer = new DispatcherTimer();
        _updateTimer.Interval = TimeSpan.FromMilliseconds(100);
        _updateTimer.Tick += UpdateTimer_Tick;
        _updateTimer.Start();

        // Initial navigation selection
        ProxyControlButton.IsEnabled = false;  // Mark as selected

        // Load network interfaces
        RefreshNetworkInterfaces();

        // Try to load DLL automatically
        _ = LoadDllAsync();
    }

    private void UpdateTimer_Tick(object? sender, EventArgs e)
    {
        // Update UI elements with latest data
        if (_proxyDllLoaded && _proxyRunning)
        {
            int connections = 0;
            int bytes = 0;
            if (get_proxy_stats(ref connections, ref bytes))
            {
                TotalConnections = connections;
                ActiveConnections = connections; // In a real app, these might be different
                BytesSent = bytes / 2; // Approximate division for demo
                BytesReceived = bytes / 2; // Approximate division for demo

                // Update UI elements
                ActiveConnectionsText.Text = ActiveConnections.ToString();
                TotalConnectionsText.Text = TotalConnections.ToString();
                BytesSentText.Text = BytesSent.ToString();
                BytesReceivedText.Text = BytesReceived.ToString();
            }
        }
    }

    private async Task LoadDllAsync()
    {
        await Task.Run(() =>
        {
            try
            {
                string? dllPath = FindDllPath();
                if (dllPath == null)
                {
                    Dispatcher.Invoke(() =>
                    {
                        AddStatusMessage("[ERROR] Could not find tls_proxy.dll");
                    });
                    return;
                }                // Add directory for loading dependencies
                string? dllDirectory = Path.GetDirectoryName(dllPath);
                if (dllDirectory != null)
                {
                    AddDllDirectory(dllDirectory);
                }

                // Actually loading the DLL is handled by P/Invoke automatically

                // Try to initialize by setting callbacks
                set_log_callback(_logCallback);
                set_status_callback(_statusCallback);
                set_connection_callback(_connectionCallback);
                set_stats_callback(_statsCallback);
                set_disconnect_callback(_disconnectCallback);

                _proxyDllLoaded = true;

                Dispatcher.Invoke(() =>
                {
                    DllStatusText.Text = "DLL: Loaded";
                    DllStatusText.Foreground = System.Windows.Media.Brushes.Green;
                    AddStatusMessage("[SYSTEM] DLL loaded successfully");
                });
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                {
                    AddStatusMessage($"[ERROR] Failed to load DLL: {ex.Message}");
                });
            }
        });
    }

    // Helper to find DLL in possible locations
    private string? FindDllPath()
    {
        // Try possible paths
        string[] possiblePaths = new[]
        {
            @"d:\Windows TLS\build\Debug\tls_proxy.dll",
            @"d:\Windows TLS\build\Release\tls_proxy.dll",
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tls_proxy.dll"),
            "tls_proxy.dll"
        };

        foreach (string path in possiblePaths)
        {
            if (File.Exists(path))
                return path;
        }

        return null;
    }

    // Helper to add DLL search paths
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool AddDllDirectory(string lpPathName);

    private void RefreshNetworkInterfaces()
    {
        if (!_proxyDllLoaded)
        {
            // Local method
            BindAddressComboBox.Items.Clear();
            try
            {
                // Get all network interfaces with IPv4 addresses
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up)
                    {
                        foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                        {
                            if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                BindAddressComboBox.Items.Add(ip.Address.ToString());
                            }
                        }
                    }
                }

                // Always add loopback
                if (!BindAddressComboBox.Items.Contains("127.0.0.1"))
                {
                    BindAddressComboBox.Items.Add("127.0.0.1");
                }

                if (BindAddressComboBox.Items.Count > 0)
                {
                    BindAddressComboBox.SelectedIndex = 0;
                }
            }
            catch (Exception ex)
            {
                AddStatusMessage($"[ERROR] Failed to enumerate network interfaces: {ex.Message}");

                // Add loopback as fallback
                BindAddressComboBox.Items.Clear();
                BindAddressComboBox.Items.Add("127.0.0.1");
                BindAddressComboBox.SelectedIndex = 0;
            }
            return;
        }

        try
        {
            // Use DLL API
            StringBuilder buffer = new StringBuilder(2048);
            int result = get_system_ips(buffer, buffer.Capacity);            if (result > 0)
            {
                string ipList = buffer.ToString();
                AddStatusMessage($"[DEBUG] Raw IP list from DLL: '{ipList}'");

                // Handle both comma and semicolon separators
                string[] ipAddresses = ipList.Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);

                // Track unique IPs to avoid duplicates
                List<string> uniqueIps = new List<string>();

                BindAddressComboBox.Items.Clear();
                foreach (string ip in ipAddresses)
                {
                    if (!string.IsNullOrWhiteSpace(ip))
                    {
                        string trimmedIp = ip.Trim();
                        if (!uniqueIps.Contains(trimmedIp))
                        {
                            uniqueIps.Add(trimmedIp);
                            BindAddressComboBox.Items.Add(trimmedIp);
                            AddStatusMessage($"[DEBUG] Added IP: '{trimmedIp}'");
                        }
                    }
                }

                // Always ensure loopback is present
                if (!uniqueIps.Contains("127.0.0.1"))
                {
                    BindAddressComboBox.Items.Add("127.0.0.1");
                    AddStatusMessage($"[DEBUG] Added loopback IP");
                }

                if (BindAddressComboBox.Items.Count > 0)
                    BindAddressComboBox.SelectedIndex = 0;

                AddStatusMessage($"[SYSTEM] Found {BindAddressComboBox.Items.Count} network interfaces");
            }
            else
            {
                AddStatusMessage("[ERROR] Failed to get network interfaces from DLL");
                RefreshNetworkInterfaces_Fallback();
            }
        }
        catch (Exception ex)
        {
            AddStatusMessage($"[ERROR] Exception getting network interfaces: {ex.Message}");
            RefreshNetworkInterfaces_Fallback();
        }
    }

    private void RefreshNetworkInterfaces_Fallback()
    {
        // Fallback method using .NET APIs
        BindAddressComboBox.Items.Clear();
        BindAddressComboBox.Items.Add("127.0.0.1");

        try
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (UnicastIPAddressInformation ip in nic.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            BindAddressComboBox.Items.Add(ip.Address.ToString());
                        }
                    }
                }
            }
        }
        catch (Exception)
        {
            // Just use loopback in case of error
        }

        BindAddressComboBox.SelectedIndex = 0;
    }

    private void LogCallback(string timestamp, string src_ip, string dst_ip, int dst_port,
                            string message_type, string data)
    {
        // Need to dispatch to UI thread
        Dispatcher.Invoke(() =>
        {
            var logEvent = new LogEvent
            {
                Timestamp = timestamp,
                SourceIp = src_ip,
                DestinationIp = dst_ip,
                Port = dst_port,
                Type = message_type,
                Data = data
            };

            _historyEvents.Add(logEvent);

            // Trim history if too large
            if (_historyEvents.Count > 1000)
                _historyEvents.RemoveAt(0);

            // Auto-scroll if enabled
            if (AutoScrollCheckBox.IsChecked == true && HistoryList.Items.Count > 0)
            {
                HistoryList.ScrollIntoView(HistoryList.Items[HistoryList.Items.Count - 1]);
            }
        });
    }

    private void StatusCallback(string message)
    {
        // Need to dispatch to UI thread
        Dispatcher.Invoke(() =>
        {
            AddStatusMessage(message);
        });
    }

    private void ConnectionCallback(string client_ip, int client_port, string target_host,
                                   int target_port, int connection_id)
    {
        // Need to dispatch to UI thread
        Dispatcher.Invoke(() =>
        {
            var connectionEvent = new ConnectionEvent
            {
                Timestamp = DateTime.Now.ToString("HH:mm:ss"),
                Event = "Connect",
                ConnectionId = connection_id,
                SourceIp = client_ip,
                SourcePort = client_port,
                DestinationIp = target_host,
                DestinationPort = target_port
            };

            _connectionEvents.Add(connectionEvent);

            // Increment active connections
            ActiveConnections++;

            // Trim history if too large
            if (_connectionEvents.Count > 1000)
                _connectionEvents.RemoveAt(0);

            // Auto-scroll if enabled
            if (ConnectionsList.Items.Count > 0)
            {
                ConnectionsList.ScrollIntoView(ConnectionsList.Items[ConnectionsList.Items.Count - 1]);
            }
        });
    }

    private void StatsCallback(int total_connections, int active_connections, int total_bytes_transferred)
    {
        // Need to dispatch to UI thread
        Dispatcher.Invoke(() =>
        {
            TotalConnections = total_connections;
            ActiveConnections = active_connections;
            BytesSent = total_bytes_transferred / 2; // Approximate division for demo
            BytesReceived = total_bytes_transferred / 2; // Approximate division for demo

            // Update UI elements
            ActiveConnectionsText.Text = ActiveConnections.ToString();
            TotalConnectionsText.Text = TotalConnections.ToString();
            BytesSentText.Text = BytesSent.ToString();
            BytesReceivedText.Text = BytesReceived.ToString();
        });
    }

    private void DisconnectCallback(int connection_id, string reason)
    {
        // Need to dispatch to UI thread
        Dispatcher.Invoke(() =>
        {
            var connectionEvent = new ConnectionEvent
            {
                Timestamp = DateTime.Now.ToString("HH:mm:ss"),
                Event = "Disconnect",
                ConnectionId = connection_id,
                SourceIp = "",
                SourcePort = 0,
                DestinationIp = reason,
                DestinationPort = 0
            };

            _connectionEvents.Add(connectionEvent);

            // Decrement active connections if > 0
            if (ActiveConnections > 0)
                ActiveConnections--;

            // Trim history if too large
            if (_connectionEvents.Count > 1000)
                _connectionEvents.RemoveAt(0);

            // Auto-scroll if enabled
            if (ConnectionsList.Items.Count > 0)
            {
                ConnectionsList.ScrollIntoView(ConnectionsList.Items[ConnectionsList.Items.Count - 1]);
            }
        });
    }

    private void AddStatusMessage(string message)
    {
        _statusMessages.Add(message);

        // Append to text box with timestamp
        string timestamp = DateTime.Now.ToString("HH:mm:ss");
        StatusLogTextBox.AppendText($"[{timestamp}] {message}{Environment.NewLine}");

        // Trim status messages if too many
        if (_statusMessages.Count > 1000)
            _statusMessages.RemoveAt(0);

        // Auto-scroll
        if (AutoScrollCheckBox.IsChecked == true)
            StatusLogTextBox.ScrollToEnd();
    }

    private void NavigationButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button button && button.Tag is string tag)
        {
            // Reset all buttons
            ProxyControlButton.IsEnabled = true;
            ConfigurationButton.IsEnabled = true;
            ConnectionsButton.IsEnabled = true;
            LogsButton.IsEnabled = true;
            ProxyHistoryButton.IsEnabled = true;

            // Mark selected button
            button.IsEnabled = false;

            // Hide all panels
            ProxyControlPanel.Visibility = Visibility.Collapsed;
            ConfigurationPanel.Visibility = Visibility.Collapsed;
            ConnectionsPanel.Visibility = Visibility.Collapsed;
            LogsPanel.Visibility = Visibility.Collapsed;
            ProxyHistoryPanel.Visibility = Visibility.Collapsed;

            // Show the selected panel
            switch (tag)
            {
                case "ProxyControl":
                    ProxyControlPanel.Visibility = Visibility.Visible;
                    break;
                case "Configuration":
                    ConfigurationPanel.Visibility = Visibility.Visible;
                    break;
                case "Connections":
                    ConnectionsPanel.Visibility = Visibility.Visible;
                    break;
                case "Logs":
                    LogsPanel.Visibility = Visibility.Visible;
                    break;
                case "ProxyHistory":
                    ProxyHistoryPanel.Visibility = Visibility.Visible;
                    break;
            }
        }
    }    private void StartProxy_Click(object sender, RoutedEventArgs e)
    {
        // Call our enhanced version with better diagnostics and SOCKS5 configuration hints
        EnhancedStartProxy();
    }

    private void StopProxy_Click(object sender, RoutedEventArgs e)
    {
        if (!_proxyDllLoaded || !_proxyRunning)
            return;

        stop_proxy();
        _proxyRunning = false;
        StatusText.Text = "Stopped";
        StatusText.Foreground = System.Windows.Media.Brushes.Red;
        StartProxyButton.IsEnabled = true;
        StopProxyButton.IsEnabled = false;

        AddStatusMessage("[SYSTEM] Proxy stopped");
    }    // RefreshInterfaces_Click is now implemented in MainWindowPatch.cs

    private void ApplyConfig_Click(object sender, RoutedEventArgs e)
    {
        if (!_proxyDllLoaded)
        {
            MessageBox.Show("DLL not loaded", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        try
        {
            string bindAddr = BindAddressComboBox.SelectedItem?.ToString() ?? "127.0.0.1";
            int port = int.Parse(PortTextBox.Text);
            string logFile = LogFileTextBox.Text;

            if (set_config(bindAddr, port, logFile))
            {
                AddStatusMessage($"[CONFIG] Configuration applied: {bindAddr}:{port}");
            }
            else
            {
                MessageBox.Show("Failed to apply configuration", "Error",
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void BrowseLogFile_Click(object sender, RoutedEventArgs e)
    {
        SaveFileDialog saveFileDialog = new SaveFileDialog
        {
            Filter = "Log files (*.log)|*.log|All files (*.*)|*.*",
            DefaultExt = ".log",
            FileName = "tls_proxy.log"
        };

        if (saveFileDialog.ShowDialog() == true)
        {
            LogFileTextBox.Text = saveFileDialog.FileName;
        }
    }

    private void ClearLogs_Click(object sender, RoutedEventArgs e)
    {
        StatusLogTextBox.Clear();
        _logEvents.Clear();
        _statusMessages.Clear();
        AddStatusMessage("[SYSTEM] Logs cleared");
    }

    private void ExportLogs_Click(object sender, RoutedEventArgs e)
    {
        SaveFileDialog saveFileDialog = new SaveFileDialog
        {
            Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
            DefaultExt = ".txt",
            FileName = $"tls_proxy_logs_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
        };

        if (saveFileDialog.ShowDialog() == true)
        {
            try
            {
                using StreamWriter writer = new StreamWriter(saveFileDialog.FileName);
                writer.WriteLine("=== TLS MITM Proxy Logs ===");
                writer.WriteLine();

                writer.WriteLine("Status Messages:");
                foreach (string message in _statusMessages)
                {
                    writer.WriteLine(message);
                }

                writer.WriteLine();
                writer.WriteLine("Log Entries:");
                foreach (LogEvent entry in _logEvents)
                {
                    writer.WriteLine($"{entry.Timestamp} | {entry.SourceIp} | {entry.DestinationIp} | {entry.Port} | {entry.Type} | {entry.Data}");
                }

                AddStatusMessage($"[SYSTEM] Logs exported to {saveFileDialog.FileName}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export logs: {ex.Message}",
                               "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void ClearConnections_Click(object sender, RoutedEventArgs e)
    {
        _connectionEvents.Clear();
        AddStatusMessage("[SYSTEM] Connection history cleared");
    }

    private void ExportConnections_Click(object sender, RoutedEventArgs e)
    {
        SaveFileDialog saveFileDialog = new SaveFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            DefaultExt = ".csv",
            FileName = $"tls_proxy_connections_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
        };

        if (saveFileDialog.ShowDialog() == true)
        {
            try
            {
                using StreamWriter writer = new StreamWriter(saveFileDialog.FileName);
                writer.WriteLine("Timestamp,Event,ConnectionID,SourceIP,SourcePort,DestinationIP,DestinationPort");

                foreach (ConnectionEvent evt in _connectionEvents)
                {
                    writer.WriteLine($"{evt.Timestamp},{evt.Event},{evt.ConnectionId},{evt.SourceIp},{evt.SourcePort},{evt.DestinationIp},{evt.DestinationPort}");
                }

                AddStatusMessage($"[SYSTEM] Connections exported to {saveFileDialog.FileName}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export connections: {ex.Message}",
                               "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void ClearHistory_Click(object sender, RoutedEventArgs e)
    {
        _historyEvents.Clear();
        AddStatusMessage("[SYSTEM] Proxy history cleared");
    }

    private void ExportHistory_Click(object sender, RoutedEventArgs e)
    {
        SaveFileDialog saveFileDialog = new SaveFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            DefaultExt = ".csv",
            FileName = $"tls_proxy_history_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
        };

        if (saveFileDialog.ShowDialog() == true)
        {
            try
            {
                using StreamWriter writer = new StreamWriter(saveFileDialog.FileName);
                writer.WriteLine("Timestamp,SourceIP,DestinationIP,Port,Type,Data");

                foreach (LogEvent evt in _historyEvents)
                {
                    writer.WriteLine($"{evt.Timestamp},{evt.SourceIp},{evt.DestinationIp},{evt.Port},{evt.Type},{evt.Data}");
                }

                AddStatusMessage($"[SYSTEM] History exported to {saveFileDialog.FileName}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export history: {ex.Message}",
                               "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
    }
