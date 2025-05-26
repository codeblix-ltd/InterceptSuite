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
using System.Windows.Interop;

namespace TLS_MITM_WPF;

public partial class MainWindow : Window, INotifyPropertyChanged, IDisposable
{
    // DLL imports for dark title bar
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

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
    }    // DLL interaction
    private bool _proxyRunning = false;
    private DllManager? _dllManager = null;

    // Timer for UI updates
    private DispatcherTimer? _updateTimer = null;

    public event PropertyChangedEventHandler? PropertyChanged;
    protected virtual void OnPropertyChanged(string propertyName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));    public MainWindow()
    {
        InitializeComponent();

        // Apply dark title bar when window loads
        Loaded += MainWindow_Loaded;

        // Initialize DLL manager with callbacks
        _dllManager = new DllManager(
            LogCallback,
            StatusCallback,
            ConnectionCallback,
            StatsCallback,
            DisconnectCallback
        );

        // Initialize ListViews
        ConnectionsList.ItemsSource = _connectionEvents;
        LogsList.ItemsSource = _logEvents;
        HistoryList.ItemsSource = _historyEvents;        // Initialize timer for UI updates
        _updateTimer = new DispatcherTimer();
        _updateTimer.Interval = TimeSpan.FromMilliseconds(100);
        _updateTimer.Tick += UpdateTimer_Tick;
        _updateTimer.Start();

        // Initial navigation selection
        ProxyControlButton.IsEnabled = false;  // Mark as selected

        // Try to load DLL automatically first, then update network interfaces when DLL is loaded
        _ = LoadDllAndInitializeAsync();
    }    private void UpdateTimer_Tick(object? sender, EventArgs e)
    {
        // Update current time in status bar
        CurrentTimeText.Text = DateTime.Now.ToString("HH:mm:ss");

        // Update UI elements with latest data
        if (_dllManager != null && _dllManager.IsLoaded && _proxyRunning)
        {
            int connections = 0;
            int bytes = 0;
            if (_dllManager.GetProxyStats(ref connections, ref bytes))
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
    }private async Task LoadDllAsync()
    {
        if (_dllManager == null)
        {
            Dispatcher.Invoke(() =>
                AddStatusMessage("[ERROR] DLL Manager not initialized")
            );
            return;
        }

        var result = await _dllManager.LoadDllAsync();

        Dispatcher.Invoke(() =>
        {
            if (result.success)
            {
                DllStatusText.Text = "DLL: Loaded";
                DllStatusText.Foreground = System.Windows.Media.Brushes.Green;
                AddStatusMessage("[SYSTEM] DLL loaded successfully");
            }
            else
            {
                AddStatusMessage($"[ERROR] {result.message}");
            }
        });
    }private async Task LoadDllAndInitializeAsync()
    {
        if (_dllManager == null)
        {
            AddStatusMessage("[ERROR] DLL Manager not initialized");
            return;
        }

        // Load the DLL first
        var result = await _dllManager.LoadDllAsync();

        Dispatcher.Invoke(() =>
        {
            if (result.success)
            {
                DllStatusText.Text = "DLL: Loaded";
                DllStatusText.Foreground = System.Windows.Media.Brushes.Green;
                AddStatusMessage("[SYSTEM] DLL loaded successfully");

                // Now that DLL is loaded, refresh network interfaces
                RefreshNetworkInterfaces();
            }
            else
            {
                DllStatusText.Text = "DLL: Failed to load";
                DllStatusText.Foreground = System.Windows.Media.Brushes.Red;
                AddStatusMessage($"[ERROR] {result.message}");

                // Use fallback method if DLL loading failed
                RefreshNetworkInterfaces_Fallback();
            }
        });
    }    private void RefreshNetworkInterfaces()
    {
        if (_dllManager == null || !_dllManager.IsLoaded)
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
        }        try
        {
            // Use DLL API
            StringBuilder buffer = new StringBuilder(2048);
            int result = _dllManager.GetSystemIps(buffer, buffer.Capacity);

            if (result > 0)
            {
                string ipList = buffer.ToString();
                AddStatusMessage($"[DEBUG] Raw IP list from DLL: '{ipList}'");

                // Handle both comma and semicolon separators
                string[] ipAddresses = ipList.Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);

                BindAddressComboBox.Items.Clear();
                foreach (string ip in ipAddresses)
                {
                    if (!string.IsNullOrWhiteSpace(ip))
                    {
                        string trimmedIp = ip.Trim();
                        BindAddressComboBox.Items.Add(trimmedIp);
                        AddStatusMessage($"[DEBUG] Added IP: '{trimmedIp}'");
                    }
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
    }    private void StopProxy_Click(object sender, RoutedEventArgs e)
    {
        if (_dllManager == null || !_dllManager.IsLoaded || !_dllManager.IsProxyRunning)
            return;

        _dllManager.StopProxy();
        _proxyRunning = false;
        StatusText.Text = "Stopped";
        StatusText.Foreground = System.Windows.Media.Brushes.Red;
        StartProxyButton.IsEnabled = true;
        StopProxyButton.IsEnabled = false;

        AddStatusMessage("[SYSTEM] Proxy stopped");
    }

    // RefreshInterfaces_Click is now implemented in MainWindowPatch.cs

    private void ApplyConfig_Click(object sender, RoutedEventArgs e)
    {
        if (_dllManager == null || !_dllManager.IsLoaded)
        {
            MessageBox.Show("DLL not loaded", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        try
        {
            string bindAddr = BindAddressComboBox.SelectedItem?.ToString() ?? "127.0.0.1";
            int port = int.Parse(PortTextBox.Text);
            string logFile = LogFileTextBox.Text;

            if (_dllManager.SetConfig(bindAddr, port, logFile))
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
    }    private void ExportHistory_Click(object sender, RoutedEventArgs e)
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

    // IDisposable implementation
    private bool _disposed = false;    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                // Dispose managed resources
                _updateTimer?.Stop();
                _updateTimer = null;

                // Clean up the DLL manager - it will handle stopping the proxy safely
                if (_dllManager != null)
                {
                    _dllManager.Dispose();
                    _dllManager = null;
                    _proxyRunning = false; // Update our local state
                }

                // Clear collections
                _logEvents.Clear();
                _connectionEvents.Clear();
                _historyEvents.Clear();
                _statusMessages.Clear();
            }

            // Free unmanaged resources and set large fields to null
            _disposed = true;
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    ~MainWindow()
    {
        Dispose(false);
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        // Make sure to stop the proxy and dispose resources when the window closes
        Dispose();
        base.OnClosing(e);
    }

    // Apply dark title bar to the window
    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        // Apply dark title bar
        ApplyDarkTitleBar();

        // Update window chrome
        UpdateWindowChrome();
    }

    // Apply dark title bar to the window
    private void ApplyDarkTitleBar()
    {
        try
        {
            // Get the window handle
            IntPtr hwnd = new WindowInteropHelper(this).Handle;

            if (hwnd != IntPtr.Zero)
            {
                // Check if we're on Windows 10/11
                if (Environment.OSVersion.Version.Major >= 10)
                {
                    // DWMWA_USE_IMMERSIVE_DARK_MODE = 20
                    int attribute = 20;
                    int value = 1; // 1 = dark mode
                    DwmSetWindowAttribute(hwnd, attribute, ref value, sizeof(int));
                }
            }
        }
        catch (Exception ex)
        {
            // Log the exception or ignore
            Console.WriteLine($"Error setting dark title bar: {ex.Message}");
        }
    }

    // Update window chrome for a better look
    private void UpdateWindowChrome()
    {
        // You could add additional window chrome customizations here if needed
        // like setting custom margins, etc.

        // Force a visual refresh
        InvalidateVisual();
    }
}
