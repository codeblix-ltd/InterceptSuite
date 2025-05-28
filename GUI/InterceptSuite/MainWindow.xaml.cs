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

namespace InterceptSuite;

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

    // Interception state
    private bool _isInterceptionEnabled = false;
    private int _interceptDirection = 0; // 0=None, 1=Client->Server, 2=Server->Client, 3=Both
    private int _currentInterceptConnectionId = -1;
    private string _currentInterceptDirection = "";
    private string _currentInterceptSrcIp = "";
    private string _currentInterceptDstIp = "";
    private int _currentInterceptDstPort = 0;
    private byte[] _currentInterceptData = Array.Empty<byte>();
    private bool _isWaitingForInterceptResponse = false;
    private bool _isInterceptDataModified = false;

    public event PropertyChangedEventHandler? PropertyChanged;
    protected virtual void OnPropertyChanged(string propertyName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));    public MainWindow()
    {
        InitializeComponent();

        // Apply dark title bar when window loads
        Loaded += MainWindow_Loaded;        // Initialize DLL manager with callbacks
        _dllManager = new DllManager(
            ProxyDataCallback, // was LogCallback
            StatusCallback,
            ConnectionCallback,
            StatsCallback,
            DisconnectCallback,
            InterceptCallback
        );

        // Initialize ListViews
        ConnectionsList.ItemsSource = _connectionEvents;
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
            {                DllStatusText.Text = "DLL: Loaded";
                DllStatusText.Foreground = System.Windows.Media.Brushes.Green;
                AddStatusMessage("[SYSTEM] DLL loaded successfully");

                // Now that DLL is loaded, refresh network interfaces and load config
                RefreshNetworkInterfaces();

                // Load existing configuration including verbose mode
                LoadProxyConfigFromDll();
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

    // Rename LogCallback to ProxyDataCallback
    private void ProxyDataCallback(string timestamp, string src_ip, string dst_ip, int dst_port,
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

            _historyEvents.Add(logEvent);            // Trim history if too large
            if (_historyEvents.Count > 1000)
                _historyEvents.RemoveAt(0);

            // Auto-scroll the history list
            if (HistoryList.Items.Count > 0)
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
    }    private void AddStatusMessage(string message)
    {
        _statusMessages.Add(message);

        // Append message to the status bar
        StatusText.Text = message;

        // Trim status messages if too many
        if (_statusMessages.Count > 1000)
            _statusMessages.RemoveAt(0);
    }    private void NavigationButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button button && button.Tag is string tag)
        {
            NavigateToPanel(tag);
        }
    }
    
    private void NavigateToPanel(string panelName)
    {
        // Reset all buttons
        ProxyControlButton.IsEnabled = true;
        InterceptButton.IsEnabled = true;
        ConnectionsButton.IsEnabled = true;
        ProxyHistoryButton.IsEnabled = true;

        // Hide all panels
        ProxyControlPanel.Visibility = Visibility.Collapsed;
        InterceptPanel.Visibility = Visibility.Collapsed;
        ConnectionsPanel.Visibility = Visibility.Collapsed;
        ProxyHistoryPanel.Visibility = Visibility.Collapsed;

        // Show the selected panel and mark button as selected
        switch (panelName)
        {
            case "ProxyControl":
                ProxyControlPanel.Visibility = Visibility.Visible;
                ProxyControlButton.IsEnabled = false;
                break;
            case "Intercept":
                InterceptPanel.Visibility = Visibility.Visible;
                InterceptButton.IsEnabled = false;
                break;
            case "Connections":
                ConnectionsPanel.Visibility = Visibility.Visible;
                ConnectionsButton.IsEnabled = false;
                break;
            case "ProxyHistory":
                ProxyHistoryPanel.Visibility = Visibility.Visible;
                ProxyHistoryButton.IsEnabled = false;
                break;
        }
    }

    private void StartProxy_Click(object sender, RoutedEventArgs e)
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
        }        try
        {            string bindAddr = BindAddressComboBox.SelectedItem?.ToString() ?? "127.0.0.1";
            int port = int.Parse(PortTextBox.Text);
            string logFile = LogFileTextBox.Text;
            bool verboseMode = VerboseModeCheckBox.IsChecked ?? false;            // Now we can pass the verbose mode directly to the DLL
            if (_dllManager.SetConfig(bindAddr, port, logFile, verboseMode))
            {
                AddStatusMessage($"[CONFIG] Configuration applied: {bindAddr}:{port}");
                AddStatusMessage($"[CONFIG] Log file: {logFile}, Verbose mode: {(verboseMode ? "On" : "Off")}");
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
        }    }

    private void BrowseLogFile_Click(object sender, RoutedEventArgs e)
    {
        SaveFileDialog saveFileDialog = new SaveFileDialog
        {
            Filter = "Log files (*.log)|*.log|All files (*.*)|*.*",
            DefaultExt = ".log",
            FileName = LogFileTextBox.Text
        };

        if (saveFileDialog.ShowDialog() == true)
        {
            LogFileTextBox.Text = saveFileDialog.FileName;
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
        base.OnClosing(e);    }

    // Apply dark title bar to the window
    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        // Apply dark title bar
        ApplyDarkTitleBar();

        // Update window chrome
        UpdateWindowChrome();
        
        // Initialize intercept UI
        InitializeInterceptUI();
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

    private void LoadProxyConfigFromDll()
    {
        if (_dllManager == null || !_dllManager.IsLoaded)
        {
            return;
        }

        try
        {
            StringBuilder bindAddrBuffer = new StringBuilder(256);
            StringBuilder logFileBuffer = new StringBuilder(1024);
            int port = 0;
            int verboseMode = 0;

            if (_dllManager.GetProxyConfig(bindAddrBuffer, ref port, logFileBuffer, ref verboseMode))
            {
                // Update UI elements with current config
                string bindAddr = bindAddrBuffer.ToString();
                string logFile = logFileBuffer.ToString();

                // Find and select the bind address if it exists in the dropdown
                int index = BindAddressComboBox.Items.IndexOf(bindAddr);
                if (index >= 0)
                {
                    BindAddressComboBox.SelectedIndex = index;
                }
                else if (BindAddressComboBox.Items.Count > 0)
                {
                    BindAddressComboBox.SelectedIndex = 0;
                }

                // Set port and log file
                PortTextBox.Text = port.ToString();
                LogFileTextBox.Text = logFile;

                // Set verbose mode checkbox
                VerboseModeCheckBox.IsChecked = verboseMode != 0;

                AddStatusMessage($"[CONFIG] Loaded configuration from DLL: {bindAddr}:{port}");
                AddStatusMessage($"[CONFIG] Log file: {logFile}, Verbose mode: {(verboseMode != 0 ? "On" : "Off")}");
            }
        }
        catch (Exception ex)
        {
            AddStatusMessage($"[ERROR] Failed to load configuration: {ex.Message}");
        }
    }    private void HistoryList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (HistoryList.SelectedItem is LogEvent selectedItem)
        {
            // Format the display based on the message type
            if (selectedItem.Type == "Binary")
            {
                //string dataInfo = $"[Binary Data - {GetDataSizeDescription(selectedItem.Data)}]";
                HistoryDataTextBox.Text = $"{selectedItem.Data}";
            }
            else if (selectedItem.Type == "Text")
            {
                //string dataInfo = $"[Text Data - {GetDataSizeDescription(selectedItem.Data)}]";
                HistoryDataTextBox.Text = $"{selectedItem.Data}";
            }
            else if (selectedItem.Type == "Empty")
            {
                HistoryDataTextBox.Text = "[Empty Data]";
            }
            else
            {
                string dataInfo = $"[{selectedItem.Type} - {GetDataSizeDescription(selectedItem.Data)}]";
                HistoryDataTextBox.Text = $"{dataInfo}\n{selectedItem.Data}";
            }
        }
        else
        {
            HistoryDataTextBox.Text = string.Empty;
        }
    }

    // Helper method to format data size information
    private string GetDataSizeDescription(string data)
    {
        if (string.IsNullOrEmpty(data))
            return "0 bytes";

        int length = data.Length;
        bool isTruncated = data.EndsWith("...(truncated)");

        return isTruncated
            ? $"{length} bytes (truncated)"
            : $"{length} bytes";
    }
    
    private void InterceptCallback(int connectionId, string direction, string srcIp, 
                                  string dstIp, int dstPort, byte[] data)
    {
        // Need to dispatch to UI thread
        Dispatcher.Invoke(() =>
        {
            // Store current intercept data
            _currentInterceptConnectionId = connectionId;
            _currentInterceptDirection = direction;
            _currentInterceptSrcIp = srcIp;
            _currentInterceptDstIp = dstIp;
            _currentInterceptDstPort = dstPort;
            _currentInterceptData = data;
            _isWaitingForInterceptResponse = true;
            _isInterceptDataModified = false;
            
            // Update UI
            UpdateInterceptUI();
            
            // Switch to intercept tab automatically
            NavigateToPanel("Intercept");
        });
    }

    private void UpdateInterceptUI()
    {
        if (_isWaitingForInterceptResponse)
        {
            // Update status
            InterceptStatusText.Text = $"Intercepted data from connection {_currentInterceptConnectionId}";
            
            // Update connection info
            ConnectionIdText.Text = _currentInterceptConnectionId.ToString();
            DirectionText.Text = _currentInterceptDirection;
            EndpointText.Text = $"{_currentInterceptSrcIp} → {_currentInterceptDstIp}:{_currentInterceptDstPort}";
            
            // Update data view
            UpdateInterceptDataView();
            
            // Enable action buttons
            ForwardButton.IsEnabled = true;
            DropButton.IsEnabled = true;
            ForwardModifiedButton.IsEnabled = true;
        }
        else
        {
            // Reset UI
            InterceptStatusText.Text = "No intercept pending";
            ConnectionIdText.Text = "-";
            DirectionText.Text = "-";
            EndpointText.Text = "-";
            InterceptDataTextBox.Text = "";
            
            // Disable action buttons
            ForwardButton.IsEnabled = false;
            DropButton.IsEnabled = false;
            ForwardModifiedButton.IsEnabled = false;
        }
    }

    private void UpdateInterceptDataView()
    {
        if (_currentInterceptData.Length == 0)
        {
            InterceptDataTextBox.Text = "";
            return;
        }
        
        if (TextViewRadio.IsChecked == true)
        {
            // Text view - try to display as text
            try
            {
                InterceptDataTextBox.Text = System.Text.Encoding.UTF8.GetString(_currentInterceptData);
            }
            catch
            {
                // Fall back to hex if not valid UTF-8
                InterceptDataTextBox.Text = BitConverter.ToString(_currentInterceptData).Replace("-", " ");
            }
        }
        else if (HexViewRadio.IsChecked == true)
        {
            // Hex view
            InterceptDataTextBox.Text = BitConverter.ToString(_currentInterceptData).Replace("-", " ");
        }
    }

    // Intercept event handlers
    private void InterceptEnabled_Changed(object sender, RoutedEventArgs e)
    {
        if (_dllManager != null && CheckBox.ReferenceEquals(sender, InterceptEnabledCheckBox))
        {
            _isInterceptionEnabled = InterceptEnabledCheckBox.IsChecked == true;
            _dllManager.SetInterceptEnabled(_isInterceptionEnabled);
            
            if (_isInterceptionEnabled)
            {
                AddStatusMessage("Interception enabled");
            }
            else
            {
                AddStatusMessage("Interception disabled");
                // Clear any pending intercept
                if (_isWaitingForInterceptResponse)
                {
                    RespondToCurrentIntercept(0); // Forward
                }
            }
        }
    }

    private void InterceptDirection_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_dllManager != null && ComboBox.ReferenceEquals(sender, InterceptDirectionComboBox))
        {
            var selectedItem = InterceptDirectionComboBox.SelectedItem as ComboBoxItem;
            if (selectedItem?.Tag is string tagValue && int.TryParse(tagValue, out int direction))
            {
                _interceptDirection = direction;
                _dllManager.SetInterceptDirection(direction);
                
                string directionText = direction switch
                {
                    0 => "None",
                    1 => "Client → Server",
                    2 => "Server → Client",
                    3 => "Both directions",
                    _ => "Unknown"
                };
                AddStatusMessage($"Intercept direction set to: {directionText}");
            }
        }
    }

    private void Forward_Click(object sender, RoutedEventArgs e)
    {
        RespondToCurrentIntercept(0); // INTERCEPT_ACTION_FORWARD
    }

    private void Drop_Click(object sender, RoutedEventArgs e)
    {
        RespondToCurrentIntercept(1); // INTERCEPT_ACTION_DROP
    }

    private void ForwardModified_Click(object sender, RoutedEventArgs e)
    {
        RespondToCurrentIntercept(2); // INTERCEPT_ACTION_MODIFY
    }

    private void ViewMode_Changed(object sender, RoutedEventArgs e)
    {
        if (_isWaitingForInterceptResponse)
        {
            UpdateInterceptDataView();
        }
    }

    private void InterceptDataTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _isInterceptDataModified = true;
    }

    private void RespondToCurrentIntercept(int action)
    {
        if (!_isWaitingForInterceptResponse || _dllManager == null)
            return;
        
        byte[]? modifiedData = null;
        
        if (action == 2 && _isInterceptDataModified) // INTERCEPT_ACTION_MODIFY
        {
            try
            {
                if (TextViewRadio.IsChecked == true)
                {
                    // Convert text back to bytes
                    modifiedData = System.Text.Encoding.UTF8.GetBytes(InterceptDataTextBox.Text);
                }
                else if (HexViewRadio.IsChecked == true)
                {
                    // Convert hex string back to bytes
                    string hexText = InterceptDataTextBox.Text.Replace(" ", "").Replace("-", "");
                    modifiedData = new byte[hexText.Length / 2];
                    for (int i = 0; i < modifiedData.Length; i++)
                    {
                        modifiedData[i] = Convert.ToByte(hexText.Substring(i * 2, 2), 16);
                    }
                }
            }
            catch (Exception ex)
            {
                AddStatusMessage($"Error parsing modified data: {ex.Message}");
                return;
            }
        }
        
        _dllManager.RespondToIntercept(_currentInterceptConnectionId, action, modifiedData);
        
        string actionText = action switch
        {
            0 => "forwarded",
            1 => "dropped",
            2 => "forwarded with modifications",
            _ => "processed"
        };
        AddStatusMessage($"Intercepted data {actionText}");
        
        // Reset intercept state
        _isWaitingForInterceptResponse = false;
        _isInterceptDataModified = false;
        UpdateInterceptUI();
    }

    private void InitializeInterceptUI()
    {
        // Set default values
        InterceptDirectionComboBox.SelectedIndex = 0; // None
        TextViewRadio.IsChecked = true;
        
        // Initialize intercept state
        UpdateInterceptUI();
    }
}
