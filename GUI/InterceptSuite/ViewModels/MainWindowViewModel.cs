using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using InterceptSuite.Models;
using InterceptSuite.NativeInterop;
using Avalonia.Collections;
using System.Collections;
using System.Text;
using Avalonia.Threading;
using InterceptSuite.Extensions.APIs.DataViewer;
using Avalonia.Controls;
using Avalonia.Controls.Selection;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Media;
using Avalonia.Layout;
using System.Collections.Concurrent;
using System.Threading;

namespace InterceptSuite.ViewModels
{
    public partial class MainWindowViewModel : ViewModelBase, IDisposable
    {
        private const int INTERCEPT_ACTION_FORWARD = 0;
        private const int INTERCEPT_ACTION_DROP = 1;
        private const int INTERCEPT_ACTION_MODIFY = 2;

        [ObservableProperty]
        private int _selectedTabIndex;

        [ObservableProperty]
        private string _searchQuery = string.Empty;

        [ObservableProperty]
        private bool _autoScrollToBottom = true;

        [ObservableProperty]
        private bool _showLogsTab = false;

        [ObservableProperty]
        private string _proxyStatusMessage = string.Empty;  // For proxy service status (Settings tab)

        [ObservableProperty]
        private string _proxyHistoryStatusMessage = string.Empty;  // For proxy history status

        private ExtensionsViewModel? _extensions;
        public ExtensionsViewModel Extensions => _extensions ??= new ExtensionsViewModel(this);

        private readonly ObservableCollection<ExtensionDataViewerTab> _extensionDataViewerTabs = new();
        public ObservableCollection<ExtensionDataViewerTab> ExtensionDataViewerTabs => _extensionDataViewerTabs;

        private readonly List<ExtensionDataViewerTab> _allRegisteredExtensionTabs = new();

        private void UpdateVisibleTabs()
        {
            _visibleDataViewerTabs.Clear();
            foreach (var tab in _dataViewerTabs.Where(t => t.IsVisible))
            {
                _visibleDataViewerTabs.Add(tab);
            }

            _visibleInterceptDataViewerTabs.Clear();
            foreach (var tab in _interceptDataViewerTabs.Where(t => t.IsVisible))
            {
                _visibleInterceptDataViewerTabs.Add(tab);
            }
        }

        private readonly ObservableCollection<DataViewerTabViewModel> _dataViewerTabs = new();
        private readonly ObservableCollection<DataViewerTabViewModel> _visibleDataViewerTabs = new();
        public ObservableCollection<DataViewerTabViewModel> DataViewerTabs => _visibleDataViewerTabs;

        private readonly ObservableCollection<DataViewerTabViewModel> _interceptDataViewerTabs = new();
        private readonly ObservableCollection<DataViewerTabViewModel> _visibleInterceptDataViewerTabs = new();
        public ObservableCollection<DataViewerTabViewModel> InterceptDataViewerTabs => _visibleInterceptDataViewerTabs;

        private readonly ObservableCollection<LogEntry> _allLogEntries = new();

        private const int LARGE_DATASET_THRESHOLD = 5000;
        private const int BATCH_SIZE = 1000;

        [ObservableProperty]
        private ObservableCollection<LogEntry> _logEntries = new();

        [ObservableProperty]
        private string _logText = string.Empty;

        private readonly ObservableCollection<ConnectionEntry> _allConnectionEntries = new();

        [ObservableProperty]
        private ObservableCollection<ConnectionEntry> _connectionEntries = new();

        [ObservableProperty]
        private AvaloniaList<ConnectionEntry> _selectedConnectionEntries = new();

        private List<ProxyEntry> _allProxyEntries = new();
        private readonly object _proxyEntriesLock = new object();

        private CancellationTokenSource? _proxyFilterCancellation;
        private readonly object _proxyFilterLock = new object();

        [ObservableProperty]
        private ObservableCollection<ProxyEntry> _proxyEntries = new();

        [ObservableProperty]
        private AvaloniaList<ProxyEntry> _selectedProxyEntries = new();

        [ObservableProperty]
        private string _proxySearchQuery = string.Empty;

        [ObservableProperty]
        private string _activeSearchFilter = string.Empty;

        [ObservableProperty]
        private string _activeProxySearchFilter = string.Empty;

        [ObservableProperty]
        private string _activeConnectionSearchFilter = string.Empty;

        private ProxyEntry? _selectedProxyEntry;
        public ProxyEntry? SelectedProxyEntry
        {
            get => _selectedProxyEntry;
            set
            {
                SetProperty(ref _selectedProxyEntry, value);
                ProxyDataViewSelection = 0;
                OnPropertyChanged(nameof(SelectedProxyDataContent));
                UpdateExtensionTabContent();
            }
        }

        [ObservableProperty]
        private int _proxyDataViewSelection = 0;

        public string SelectedProxyDataContent
        {
            get
            {
                if (SelectedProxyEntry == null) return string.Empty;

                return ProxyDataViewSelection == 1 && SelectedProxyEntry.HasEditedData
                    ? SelectedProxyEntry.EditedDataAsString
                    : SelectedProxyEntry.RawDataAsString;
            }
        }

        partial void OnProxyDataViewSelectionChanged(int value)
        {
            OnPropertyChanged(nameof(SelectedProxyDataContent));
            UpdateExtensionTabContent();
        }

        private readonly ObservableCollection<InterceptEntry> _allInterceptEntries = new();

        [ObservableProperty]
        private ObservableCollection<InterceptEntry> _interceptEntries = new();

        [ObservableProperty]
        private AvaloniaList<InterceptEntry> _selectedInterceptEntries = new();

        [ObservableProperty]
        private string _interceptSearchQuery = string.Empty;

        private InterceptEntry? _selectedInterceptEntry;
        public InterceptEntry? SelectedInterceptEntry
        {
            get => _selectedInterceptEntry;
            set
            {
                if (_selectedInterceptEntry != null)
                    _selectedInterceptEntry.PropertyChanged -= OnSelectedInterceptEntryPropertyChanged;

                if (SetProperty(ref _selectedInterceptEntry, value))
                {
                    if (_selectedInterceptEntry != null)
                    {
                        _selectedInterceptEntry.PropertyChanged += OnSelectedInterceptEntryPropertyChanged;
                        _selectedInterceptEntry.SyncEditableData();
                    }
                    UpdateExtensionTabContent();
                }
            }
        }

        private void OnSelectedInterceptEntryPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            // When EditableData changes, update extension tabs immediately with the current data
            if (e.PropertyName == nameof(InterceptEntry.EditableData))
            {
                // Update extension tabs (Hex tab, etc.) with the latest data from memory
                UpdateExtensionTabsOnly();
            }
        }

        private bool _interceptEnabled = false;
        public bool InterceptEnabled
        {
            get => _interceptEnabled;
            set
            {
                if (SetProperty(ref _interceptEnabled, value))
                {
                    OnPropertyChanged(nameof(InterceptButtonText));
                    OnPropertyChanged(nameof(InterceptButtonColor));
                    OnPropertyChanged(nameof(InterceptStatusText));
                }
            }
        }

        public string InterceptButtonText => InterceptEnabled ? "Intercept ON" : "Intercept OFF";
        public string InterceptButtonColor => InterceptEnabled ? "#4CAF50" : "#666666";

        public string InterceptStatusText
        {
            get
            {
                string status = InterceptEnabled ? "Enabled" : "Disabled";
                string direction = InterceptDirection switch
                {
                    0 => "None",
                    1 => "Client→Server",
                    2 => "Server→Client",
                    3 => "Both",
                    _ => "Unknown"
                };
                return $"Status: {status}, Direction: {direction}";
            }
        }

        private int _interceptDirection = 0;
        public int InterceptDirection
        {
            get => _interceptDirection;
            set
            {
                if (SetProperty(ref _interceptDirection, value))
                {
                    SetInterceptDirectionNative(value);
                    OnPropertyChanged(nameof(InterceptStatusText));
                }
            }
        }

        private readonly NativeLibrary? _nativeLibrary;

        public MainWindowViewModel()
        {
            ToggleProxyCommand = new RelayCommand(ToggleProxy);
            RefreshInterfacesCommand = new RelayCommand(RefreshInterfaces);
            SaveConfigCommand = new RelayCommand(SaveConfig);            ExportCertificateCommand = new RelayCommand(OpenExportDialog);
            RegenerateCertificateCommand = new RelayCommand(RegenerateCertificate);
            CancelExportCommand = new RelayCommand(CancelExport);
            ConfirmExportCommand = new RelayCommand(ConfirmExport);

            ToggleInterceptCommand = new RelayCommand(ToggleIntercept);
            ForwardPacketCommand = new RelayCommand<InterceptEntry>(ForwardPacket);
            DropPacketCommand = new RelayCommand<InterceptEntry>(DropPacket);
            SetInterceptDirectionCommand = new RelayCommand<int>(SetInterceptDirection);
            SelectInterceptEntryCommand = new RelayCommand<InterceptEntry>(SelectInterceptEntry);

            ApplyLogSearchCommand = new RelayCommand(() => {
                ActiveSearchFilter = SearchQuery;
                ApplySearchFilter();
            });
            ApplyProxySearchCommand = new RelayCommand(() => {
                ActiveProxySearchFilter = ProxySearchQuery;
                ApplyProxySearchFilter();
            });
            ApplyConnectionSearchCommand = new RelayCommand(() => {
                ActiveConnectionSearchFilter = ConnectionSearchQuery;
                ApplyConnectionSearchFilter();
            });

            InitializeDataViewerTabs();

            try
            {
                _nativeLibrary = NativeLibrary.Instance;
                _nativeLibrary.LogReceived += OnLogReceived;
                _nativeLibrary.ConnectionEstablished += OnConnectionEstablished;
                _nativeLibrary.ConnectionDisconnected += OnConnectionDisconnected;
                _nativeLibrary.ProxyLogReceived += OnProxyLogReceived;
                _nativeLibrary.PacketIntercepted += OnPacketIntercepted;

                LoadSystemIpAddresses();
                LoadProxyConfiguration();

                AutoStartProxyAsync();
                ApplySearchFilter();
                ApplyConnectionSearchFilter();
                ApplyProxySearchFilter();
                ApplyInterceptSearchFilter();

            }
            catch (Exception ex)
            {
                AddLogMessage($"ERROR: Failed to initialize native library: {ex.Message}");
            }
        }

        public async Task InitializeExtensionsAsync()
        {
            try
            {
                await Extensions.EnsureInitializedAsync();
            }
            catch (Exception ex)
            {
                AddLogMessage($"Warning: Failed to auto-load extensions: {ex.Message}");
            }
        }

        private void OnLogReceived(object? sender, string message)
        {
            if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
            {
                AddLogMessage(message);
            }
            else
            {
                Avalonia.Threading.Dispatcher.UIThread.Invoke(() =>
                {
                    AddLogMessage(message);
                });
            }
        }

        private void OnConnectionEstablished(object? sender, (string clientIp, int clientPort, string targetHost, int targetPort, int connectionId) connectionInfo)
        {
            ExecuteOnUIThread(() => AddConnectionEntry(new ConnectionEntry(connectionInfo.clientIp, connectionInfo.clientPort, connectionInfo.targetHost, connectionInfo.targetPort, connectionInfo.connectionId)));
        }

        private void OnConnectionDisconnected(object? sender, (int connectionId, string reason) disconnectionInfo)
        {
            ExecuteOnUIThread(() => AddConnectionEntry(new ConnectionEntry(disconnectionInfo.connectionId, disconnectionInfo.reason)));
        }

        private void OnProxyLogReceived(object? sender, (DateTime timestamp, int connectionId, int packetId, string direction, string srcIp, string dstIp, int dstPort, string protocol, string msgType, byte[] data) logData)
        {
            var entry = new ProxyEntry(logData.timestamp, logData.connectionId, logData.packetId, logData.direction, logData.srcIp, logData.dstIp, logData.dstPort, logData.protocol, logData.msgType, logData.data);
            ExecuteOnUIThread(() => AddProxyEntry(entry));
        }

        private void OnPacketIntercepted(object? sender, (int connectionId, string direction, string srcIp, string dstIp, int dstPort, string protocol, byte[] data, int packetId) interceptData)
        {
            var entry = new InterceptEntry(interceptData.connectionId, interceptData.packetId, interceptData.srcIp, interceptData.dstIp, interceptData.dstPort, interceptData.protocol, "Data", interceptData.data, interceptData.direction, 0);
            ExecuteOnUIThread(() => AddInterceptEntry(entry));
        }

        public void AddLogMessage(string message)
        {
            if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
            {
                AddLogMessageInternal(message);
            }
            else
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() => AddLogMessageInternal(message));
            }
        }        private void AddLogMessageInternal(string message)
        {
            var logEntry = new LogEntry(message);

            _allLogEntries.Add(logEntry);

            ApplySearchFilter();
        }

        private void AddConnectionEntry(ConnectionEntry connectionEntry)
        {
            if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
            {
                AddConnectionEntryInternal(connectionEntry);
            }
            else
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() => AddConnectionEntryInternal(connectionEntry));
            }
        }
          private void AddConnectionEntryInternal(ConnectionEntry connectionEntry)
        {
            _allConnectionEntries.Add(connectionEntry);

            if (string.IsNullOrWhiteSpace(ConnectionSearchQuery))
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    FilteredConnectionEntries.Add(connectionEntry);
                });
            }
            else
            {
                ApplyConnectionSearchFilter();
            }
        }

        private void AddProxyEntry(ProxyEntry proxyEntry)
        {
            ExecuteOnUIThread(() => AddProxyEntryInternal(proxyEntry));
        }

        private void AddProxyEntryInternal(ProxyEntry proxyEntry)
        {
            lock (_proxyEntriesLock)
            {
                proxyEntry.Index = _allProxyEntries.Count + 1;
                _allProxyEntries.Add(proxyEntry);
            }

            if (string.IsNullOrWhiteSpace(ProxySearchQuery))
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    ProxyEntries.Add(proxyEntry);

                    if (ProxyHistoryStatusMessage == "Proxy history cleared")
                    {
                        ProxyHistoryStatusMessage = "";
                    }
                });
            }
            else
            {
                ApplyProxySearchFilter();
            }
        }

        private void AddInterceptEntry(InterceptEntry interceptEntry)
        {
            ExecuteOnUIThread(() => AddInterceptEntryInternal(interceptEntry));
        }

        private void AddInterceptEntryInternal(InterceptEntry interceptEntry)
        {
            _allInterceptEntries.Add(interceptEntry);

            // REMOVED AUTOMATIC LIMITS: No silent data loss
            // All intercepted packets preserved for complete analysis
            // User controls when to clear via Clear functions

            ApplyInterceptSearchFilter();

            if (SelectedInterceptEntry == null)
                SelectedInterceptEntry = interceptEntry;

            OnPropertyChanged(nameof(CurrentInterceptedPacket));
        }

        /// <summary>
        /// Search command
        /// </summary>
        [RelayCommand]
        private void Search()
        {
            ApplySearchFilter();
        }

        // Proxy state
        [ObservableProperty]
        private bool _isProxyRunning = false;

        [ObservableProperty]
        private string _proxyButtonText = "Start Proxy";

        [ObservableProperty]
        private string _proxyButtonColor = "#28A745";

        // Host IP addresses
        [ObservableProperty]
        private ObservableCollection<string> _hostIpAddresses = new();

        [ObservableProperty]
        private int _selectedHostIpIndex = 0;

        // Proxy Configuration Properties
        [ObservableProperty]
        private string _listenPort = "4444";

        [ObservableProperty]
        private bool _verboseMode = true;

        [ObservableProperty]
        private bool _isProxyConfigLoaded = false;

        // Export Certificate Dialog Properties
        [ObservableProperty]
        private bool _isExportDialogVisible = false;

        [ObservableProperty]
        private int _exportType = 0; // 0 = Certificate (DER), 1 = Private Key (PEM)

        // Connection search query
        [ObservableProperty]
        private string _connectionSearchQuery = string.Empty;        // Filtered connection entries (based on search)
        [ObservableProperty]
        private ObservableCollection<ConnectionEntry> _filteredConnectionEntries = new();

        /// <summary>
        /// Toggle proxy command
        /// </summary>
        public ICommand ToggleProxyCommand { get; }

        /// <summary>
        /// Refresh interfaces command
        /// </summary>
        public ICommand RefreshInterfacesCommand { get; }

        /// <summary>
        /// Save configuration command
        /// </summary>
        public ICommand SaveConfigCommand { get; }

        /// <summary>
        /// Export certificate command
        /// </summary>
        public ICommand ExportCertificateCommand { get; }

        /// <summary>
        /// Command to regenerate the CA certificate
        /// </summary>
        public ICommand RegenerateCertificateCommand { get; }

        /// <summary>
        /// Cancel export command
        /// </summary>
        public ICommand CancelExportCommand { get; }        /// <summary>
        /// Confirm export command
        /// </summary>
        public ICommand ConfirmExportCommand { get; }        /// <summary>
        /// Toggle intercept command
        /// </summary>
        public ICommand ToggleInterceptCommand { get; }

        /// <summary>
        /// Forward packet command
        /// </summary>
        public ICommand ForwardPacketCommand { get; }

        /// <summary>
        /// Drop packet command
        /// </summary>
        public ICommand DropPacketCommand { get; }

        /// <summary>
        /// Set intercept direction command
        /// </summary>
        public ICommand SetInterceptDirectionCommand { get; }

        /// <summary>
        /// Select intercept entry command
        /// </summary>
        public ICommand SelectInterceptEntryCommand { get; }

        /// <summary>
        /// Apply log search filter command (triggered by Enter key)
        /// </summary>
        public ICommand ApplyLogSearchCommand { get; }

        /// <summary>
        /// Apply proxy history search filter command (triggered by Enter key)
        /// </summary>
        public ICommand ApplyProxySearchCommand { get; }

        /// <summary>
        /// Apply connection search filter command (triggered by Enter key)
        /// </summary>
        public ICommand ApplyConnectionSearchCommand { get; }

        #region Methods

        private async void ToggleProxy()
        {
            try
            {
                if (_nativeLibrary == null)
                {
                    ProxyStatusMessage = "✗ ERROR: Native library not initialized";
                    return;
                }

                if (IsProxyRunning)
                {
                    ProxyStatusMessage = "Stopping proxy...";

                    // Stop the proxy using a task with timeout to prevent hanging
                    var stopTask = Task.Run(() => _nativeLibrary.StopProxy());
                    var timeoutTask = Task.Delay(TimeSpan.FromSeconds(10));
                    var completedTask = await Task.WhenAny(stopTask, timeoutTask);

                    if (completedTask == timeoutTask)
                    {
                        ProxyStatusMessage = "⚠ WARNING: StopProxy operation timed out";
                    }
                    else
                    {
                        ProxyStatusMessage = "✓ Proxy stopped successfully";
                    }

                    IsProxyRunning = false;
                    UpdateProxyButtonState();
                }
                else
                {
                    ProxyStatusMessage = "Starting proxy...";

                    // Start the proxy
                    var startResult = _nativeLibrary.StartProxy();

                    if (startResult.success == 1)
                    {
                        IsProxyRunning = true;
                        UpdateProxyButtonState();
                        ProxyStatusMessage = $"✓ {startResult.message}";
                    }
                    else
                    {
                        ProxyStatusMessage = $"✗ {startResult.message}";
                    }
                }
            }
            catch (Exception ex)
            {
                ProxyStatusMessage = $"✗ Error toggling proxy: {ex.Message}";
            }
        }

        /// <summary>
        /// Loads system IP addresses from the DLL
        /// </summary>
        private void LoadSystemIpAddresses()
        {
            try
            {
                if (_nativeLibrary != null)
                {
                    var ips = _nativeLibrary.GetSystemIps();
                    HostIpAddresses.Clear();

                    foreach (var ip in ips)
                    {
                        HostIpAddresses.Add(ip);
                    }

                    // Set default selection to localhost
                    SelectedHostIpIndex = 0;
                }
                else
                {
                    // Fallback if native library is not available
                    HostIpAddresses.Clear();
                    HostIpAddresses.Add("127.0.0.1 (localhost)");
                    HostIpAddresses.Add("0.0.0.0 (all interfaces)");
                    SelectedHostIpIndex = 0;
                }
            }
            catch (Exception ex)
            {
                AddLogMessage($"Error loading IP addresses: {ex.Message}");
                // Fallback
                HostIpAddresses.Clear();
                HostIpAddresses.Add("127.0.0.1 (localhost)");
                HostIpAddresses.Add("0.0.0.0 (all interfaces)");
                SelectedHostIpIndex = 0;
            }
        }

        /// <summary>
        /// Automatically starts the proxy on application startup
        /// </summary>
        private async void AutoStartProxyAsync()
        {
            try
            {
                // Small delay to ensure UI is ready
                await Task.Delay(500);

                if (_nativeLibrary == null)
                {
                    AddLogMessage("Cannot auto-start proxy: Native library not initialized");
                    return;
                }

                if (IsProxyRunning)
                {
                    // Proxy already running - no need to log this
                    return;
                }

                // Auto-start proxy silently
                ProxyStatusMessage = "Auto-starting proxy...";

                // Start the proxy
                var startResult = _nativeLibrary.StartProxy();

                if (startResult.success == 1)
                {
                    IsProxyRunning = true;
                    UpdateProxyButtonState();
                    ProxyStatusMessage = $"{startResult.message}";
                    // Success - no need to log this
                }
                else
                {
                    ProxyStatusMessage = $"✗ {startResult.message}";
                    AddLogMessage($"Failed to auto-start proxy: {startResult.message}");
                }
            }
            catch (Exception ex)
            {
                var errorMsg = $"Error during proxy auto-start: {ex.Message}";
                ProxyStatusMessage = errorMsg;
                AddLogMessage(errorMsg);
            }
        }

        /// <summary>
        /// Refreshes the list of network interfaces
        /// </summary>
        private void RefreshInterfaces()
        {
            LoadSystemIpAddresses();
        }        /// <summary>
        /// Clear logs command - clears both UI and memory collections
        /// </summary>
        [RelayCommand]
        private void ClearLogs()
        {
            // CRITICAL: Ensure we're on the UI thread for ObservableCollection operations
            if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
            {
                ClearLogsInternal();
            }
            else
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() => ClearLogsInternal());
            }
        }        /// <summary>
        /// Clear connections command - clears both UI and memory collections
        /// </summary>
        [RelayCommand]
        private void ClearConnections()
        {
            // CRITICAL: Ensure we're on the UI thread for ObservableCollection operations
            if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
            {
                ClearConnectionsInternal();
            }
            else
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() => ClearConnectionsInternal());
            }
        }

        /// <summary>
        /// Clear proxy history command - clears both UI and memory collections
        /// </summary>
        [RelayCommand]
        private void ClearProxyHistory()
        {
            if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
            {
                ClearProxyHistoryInternal();
            }
            else
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() => ClearProxyHistoryInternal());
            }
        }

        private void ClearLogsInternal()
        {
            _allLogEntries.Clear();
            LogEntries.Clear();
            LogText = string.Empty;

            GC.Collect();
            GC.WaitForPendingFinalizers();
        }

        private void ClearConnectionsInternal()
        {
            _allConnectionEntries.Clear();
            FilteredConnectionEntries.Clear();

            GC.Collect();
            GC.WaitForPendingFinalizers();
        }

        /// <summary>
        /// Internal method to clear all proxy history collections and free memory
        /// </summary>
        private void ClearProxyHistoryInternal()
        {
            lock (_proxyEntriesLock)
            {
                _allProxyEntries.Clear();
            }

            ProxyEntries.Clear();

            SelectedProxyEntry = null;

            ProxyHistoryStatusMessage = "Proxy history cleared";

            GC.Collect();
            GC.WaitForPendingFinalizers();
        }

        private void ApplySearchFilter()
        {
            IEnumerable<LogEntry> filteredEntries;

            if (string.IsNullOrWhiteSpace(ActiveSearchFilter))
            {
                filteredEntries = _allLogEntries;
            }
            else
            {
                try
                {
                    var regex = new Regex(ActiveSearchFilter, RegexOptions.IgnoreCase | RegexOptions.Compiled);
                    filteredEntries = _allLogEntries.Where(l => regex.IsMatch(l.Message));
                }
                catch
                {
                    filteredEntries = _allLogEntries.Where(l => l.Message.Contains(ActiveSearchFilter, StringComparison.OrdinalIgnoreCase));
                }
            }

            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                LogEntries.Clear();
                foreach (var entry in filteredEntries)
                {
                    LogEntries.Add(entry);
                }
                OnPropertyChanged(nameof(LogEntries));
                UpdateLogText();
            });
        }

        private void UpdateLogText()
        {
            LogText = string.Join(Environment.NewLine, LogEntries.Select(entry => entry.ToString()));
        }

        partial void OnSearchQueryChanged(string value)
        {
            // Update active filter when Enter is pressed (handled by command binding)
            // No real-time filtering to improve performance with large datasets
        }
          private void ApplyConnectionSearchFilter()
        {
            IEnumerable<ConnectionEntry> filteredEntries;

            if (string.IsNullOrWhiteSpace(ActiveConnectionSearchFilter))
            {
                filteredEntries = _allConnectionEntries;
            }
            else
            {
                try
                {
                    var regex = new Regex(ActiveConnectionSearchFilter, RegexOptions.IgnoreCase | RegexOptions.Compiled);
                    filteredEntries = _allConnectionEntries.Where(c =>
                        regex.IsMatch(c.Event) ||
                        regex.IsMatch(c.ConnectionId.ToString()) ||
                        regex.IsMatch(c.SourceIp) ||
                        regex.IsMatch(c.SourcePort.ToString()) ||
                        regex.IsMatch(c.DestinationIp) ||
                        regex.IsMatch(c.DestinationPort.ToString()) ||
                        (c.AdditionalInfo != null && regex.IsMatch(c.AdditionalInfo)));
                }
                catch
                {
                    filteredEntries = _allConnectionEntries.Where(c =>
                        c.Event.Contains(ActiveConnectionSearchFilter, StringComparison.OrdinalIgnoreCase) ||
                        c.ConnectionId.ToString().Contains(ActiveConnectionSearchFilter, StringComparison.OrdinalIgnoreCase) ||
                        c.SourceIp.Contains(ActiveConnectionSearchFilter, StringComparison.OrdinalIgnoreCase) ||
                        c.SourcePort.ToString().Contains(ActiveConnectionSearchFilter, StringComparison.OrdinalIgnoreCase) ||
                        c.DestinationIp.Contains(ActiveConnectionSearchFilter, StringComparison.OrdinalIgnoreCase) ||
                        c.DestinationPort.ToString().Contains(ActiveConnectionSearchFilter, StringComparison.OrdinalIgnoreCase) ||
                        (c.AdditionalInfo != null && c.AdditionalInfo.Contains(ActiveConnectionSearchFilter, StringComparison.OrdinalIgnoreCase)));
                }
            }

            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                // PERFORMANCE OPTIMIZATION: Only update collection if there are actual changes
                var newEntries = filteredEntries.ToList();
                if (FilteredConnectionEntries.Count != newEntries.Count ||
                    !FilteredConnectionEntries.SequenceEqual(newEntries))
                {
                    // Only then update the collection
                    FilteredConnectionEntries.Clear();
                    foreach (var entry in newEntries)
                    {
                        FilteredConnectionEntries.Add(entry);
                    }
                    OnPropertyChanged(nameof(FilteredConnectionEntries));
                }
            });
        }
          /// <summary>
        /// Called when the connection search query changes
        /// </summary>
        partial void OnConnectionSearchQueryChanged(string value)
        {
            // Update active filter when Enter is pressed (handled by command binding)
            // No real-time filtering to improve performance with large datasets
        }        private void ApplyProxySearchFilter()
        {


            _proxyFilterCancellation?.Cancel();
            _proxyFilterCancellation = new CancellationTokenSource();
            var token = _proxyFilterCancellation.Token;

            Task.Run(async () =>
            {
                try
                {
                    List<ProxyEntry> allEntries;
                    lock (_proxyEntriesLock)
                    {
                        allEntries = new List<ProxyEntry>(_allProxyEntries);
                    }

                    var activeFilter = ActiveProxySearchFilter?.Trim();
                    List<ProxyEntry> filteredEntries;

                    if (string.IsNullOrEmpty(activeFilter))
                    {
                        // No filter - show all entries
                        filteredEntries = allEntries;
                    }
                    else
                    {
                        // Apply filter with enhanced search across all fields
                        try
                        {
                            var regex = new Regex(activeFilter, RegexOptions.IgnoreCase | RegexOptions.Compiled);
                            filteredEntries = allEntries.Where(p =>
                                regex.IsMatch(p.ConnectionId.ToString()) ||
                                regex.IsMatch(p.SourceIp) ||
                                regex.IsMatch(p.DestinationIp) ||
                                regex.IsMatch(p.DestinationPort.ToString()) ||
                                regex.IsMatch(p.MessageType) ||
                                regex.IsMatch(p.Modified) ||
                                regex.IsMatch(p.RawDataAsString)).ToList();
                        }
                        catch
                        {
                            // If regex is invalid, do a simple contains search
                            filteredEntries = allEntries.Where(p =>
                                p.ConnectionId.ToString().Contains(activeFilter, StringComparison.OrdinalIgnoreCase) ||
                                p.SourceIp.Contains(activeFilter, StringComparison.OrdinalIgnoreCase) ||
                                p.DestinationIp.Contains(activeFilter, StringComparison.OrdinalIgnoreCase) ||
                                p.DestinationPort.ToString().Contains(activeFilter, StringComparison.OrdinalIgnoreCase) ||
                                p.MessageType.Contains(activeFilter, StringComparison.OrdinalIgnoreCase) ||
                                p.Modified.Contains(activeFilter, StringComparison.OrdinalIgnoreCase) ||
                                p.RawDataAsString.Contains(activeFilter, StringComparison.OrdinalIgnoreCase)).ToList();
                        }
                    }

                    if (token.IsCancellationRequested) return;

                    // Update UI efficiently based on dataset size
                    if (filteredEntries.Count > LARGE_DATASET_THRESHOLD)
                    {
                        await UpdateProxyEntriesInBatches(filteredEntries, token);
                    }
                    else
                    {
                        await UpdateProxyEntriesDirect(filteredEntries);
                    }

                    // Clear status message after filtering
                    if (filteredEntries.Count > LARGE_DATASET_THRESHOLD)
                    {
                        await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
                        {
                            ProxyHistoryStatusMessage = "";
                        });
                    }
                }
                catch (OperationCanceledException)
                {
                    // Search was cancelled - clear status
                    await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        ProxyHistoryStatusMessage = "";
                    });
                }
                catch (Exception)
                {
                    // Handle any other errors gracefully
                    await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        ProxyHistoryStatusMessage = "Search error occurred";
                    });
                }
            }, token);
        }

        private async Task UpdateProxyEntriesDirect(List<ProxyEntry> filteredEntries)
        {
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                ProxyEntries.Clear();
                foreach (var entry in filteredEntries)
                {
                    ProxyEntries.Add(entry);
                }
            });
        }

        private async Task UpdateProxyEntriesInBatches(List<ProxyEntry> filteredEntries, CancellationToken token)
        {
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                ProxyEntries.Clear();
            });

            for (int i = 0; i < filteredEntries.Count; i += BATCH_SIZE)
            {
                if (token.IsCancellationRequested) return;

                var batch = filteredEntries.Skip(i).Take(BATCH_SIZE).ToList();

                await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
                {
                    foreach (var entry in batch)
                    {
                        ProxyEntries.Add(entry);
                    }
                });

                await Task.Delay(1, token);
            }
        }

        partial void OnProxySearchQueryChanged(string value)
        {
            // Update active filter when Enter is pressed (handled by command binding)
            // No real-time filtering to improve performance with large datasets
        }

        private void UpdateProxyHistoryModifiedStatus(int packetId, byte[] editedData)
        {
            try
            {
                var proxyEntry = _allProxyEntries.FirstOrDefault(p => p.PacketId == packetId);

                if (proxyEntry != null)
                {
                    // Update the Modified status to "Yes" and store the edited data
                    proxyEntry.Modified = "Yes";
                    proxyEntry.EditedData = editedData ?? Array.Empty<byte>();
                    // Optionally log for debugging
                    // AddLogMessage($"Updated proxy history: Packet {packetId} marked as Modified=Yes with edited data ({editedData?.Length ?? 0} bytes)");

                    // Refresh the filtered view to ensure UI reflects the change
                    ApplyProxySearchFilter();
                }
                else
                {
                    AddLogMessage($"WARNING: Could not find proxy entry for packet ID {packetId} to mark as modified");
                }
            }
            catch (Exception ex)
            {
                AddLogMessage($"ERROR: Exception updating proxy history modified status for packet {packetId}: {ex.Message}");
            }
        }

        /// <summary>
        /// Loads the proxy configuration from the native library
        /// </summary>
        private void LoadProxyConfiguration()
        {
            try
            {
                if (_nativeLibrary == null)
                {
                    AddLogMessage("Native library not initialized, using default configuration");
                    SetDefaultProxyConfiguration();
                    return;
                }
                var config = _nativeLibrary.GetProxyConfig();

                // Update the ViewModel properties with the config from the DLL
                ListenPort = config.port.ToString();
                VerboseMode = config.verbose_mode;

                IsProxyConfigLoaded = true;

                // Update proxy running state
                IsProxyRunning = config.is_running;
                UpdateProxyButtonState();
            }
            catch (Exception ex)
            {
                AddLogMessage($"Error loading proxy configuration: {ex.Message}");
                SetDefaultProxyConfiguration();
            }
        }/// <summary>
        /// Sets default proxy configuration values
        /// </summary>
        private void SetDefaultProxyConfiguration()
        {
            ListenPort = "4444";
            VerboseMode = true;

            IsProxyConfigLoaded = false;
            AddLogMessage("Using default proxy configuration");
        }
        /// Saves the current proxy configuration to the DLL
        /// </summary>
        private async void SaveConfig()
        {
            try
            {
                if (_nativeLibrary == null)
                {
                    AddLogMessage("ERROR: Native library not initialized, cannot save configuration");
                    return;
                }

                // Validate port number
                if (!int.TryParse(ListenPort, out int port) || port <= 0 || port > 65535)
                {
                    AddLogMessage("ERROR: Invalid port number. Port must be between 1 and 65535.");
                    return;
                }

                // Get the selected IP address from the ComboBox
                string bindAddr = "127.0.0.1"; // Default fallback
                if (SelectedHostIpIndex >= 0 && SelectedHostIpIndex < HostIpAddresses.Count)
                {
                    string selectedIp = HostIpAddresses[SelectedHostIpIndex];
                    // Extract IP from display format like "192.168.1.100" or "127.0.0.1 (localhost)"
                    var ipMatch = System.Text.RegularExpressions.Regex.Match(selectedIp, @"^(\d+\.\d+\.\d+\.\d+)");
                    if (ipMatch.Success)
                    {
                        bindAddr = ipMatch.Groups[1].Value;
                      }
                    else if (selectedIp.Contains("0.0.0.0"))
                    {
                        bindAddr = "0.0.0.0";
                    }
                }
                bool needsRestart = false;
                if (IsProxyRunning)
                {
                    var currentConfig = _nativeLibrary.GetProxyConfig();
                    if (currentConfig.bind_addr != bindAddr || currentConfig.port != port)
                    {
                        needsRestart = true;
                        AddLogMessage($"Detected IP/port change (from {currentConfig.bind_addr}:{currentConfig.port} to {bindAddr}:{port})");
                    }
                }

                // Call the native set_config function
                bool success = _nativeLibrary.SetConfig(bindAddr, port, VerboseMode);

                if (success)
                {
                    if (needsRestart)
                    {
                        AddLogMessage("Restarting proxy to apply IP/port changes...");
                        ProxyStatusMessage = "Restarting proxy for new settings...";

                        try
                        {
                            // Stop the proxy
                            var stopTask = Task.Run(() => _nativeLibrary.StopProxy());
                            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(10));
                            var completedTask = await Task.WhenAny(stopTask, timeoutTask);

                            if (completedTask == timeoutTask)
                            {
                                AddLogMessage("⚠ WARNING: StopProxy operation timed out during restart");
                                ProxyStatusMessage = "⚠ WARNING: Restart timed out";
                            }
                            else
                            {
                                // Start the proxy with new settings
                                var startResult = _nativeLibrary.StartProxy();

                                if (startResult.success == 1)
                                {
                                    IsProxyRunning = true;
                                    UpdateProxyButtonState();
                                    ProxyStatusMessage = $"✓ Proxy restarted: {startResult.message}";
                                }
                                else
                                {
                                    IsProxyRunning = false;
                                    UpdateProxyButtonState();
                                    ProxyStatusMessage = $"✗ Failed to restart: {startResult.message}";
                                    AddLogMessage($"✗ Failed to restart proxy: {startResult.message}");
                                }
                            }
                        }
                        catch (Exception restartEx)
                        {
                            AddLogMessage($"✗ Error during proxy restart: {restartEx.Message}");
                            ProxyStatusMessage = $"✗ Restart error: {restartEx.Message}";
                            // Update running state based on actual status
                            LoadProxyConfiguration();
                        }
                    }
                    // Reload configuration to update UI with actual values from DLL
                    LoadProxyConfiguration();
                }
                else
                {
                    AddLogMessage("Failed to save configuration. Please check the values and try again.");
                }
            }
            catch (Exception ex)
            {
                AddLogMessage($"Error saving configuration: {ex.Message}");
            }
        }

        /// <summary>
        /// Updates the proxy button text and color based on current state
        /// </summary>
        private void UpdateProxyButtonState()
        {
            if (IsProxyRunning)
            {
                ProxyButtonText = "Stop Proxy";
                ProxyButtonColor = "#DC3545"; // Red for stop
            }
            else
            {
                ProxyButtonText = "Start Proxy";
                ProxyButtonColor = "#28A745"; // Green for start
            }
        }        /// <summary>
        /// Opens the export certificate dialog
        /// </summary>
        private void OpenExportDialog()
        {
            IsExportDialogVisible = true;
            ExportType = 0; // Default to certificate
        }

        /// <summary>
        /// Cancels the export certificate dialog
        /// </summary>
        private void CancelExport()
        {
            IsExportDialogVisible = false;
        }        /// <summary>
        /// Confirms and performs the certificate export
        /// </summary>
        private async void ConfirmExport()
        {
            try
            {
                if (_nativeLibrary == null)
                {
                    AddLogMessage("ERROR: Native library not initialized, cannot export certificate");
                    return;
                }

                // Create a folder picker dialog
                var topLevel = Avalonia.Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                    ? desktop.MainWindow as Avalonia.Controls.TopLevel
                    : null;

                if (topLevel?.StorageProvider != null)
                {
                    var options = new Avalonia.Platform.Storage.FolderPickerOpenOptions
                    {
                        Title = "Select Export Directory",
                        AllowMultiple = false
                    };

                    var result = await topLevel.StorageProvider.OpenFolderPickerAsync(options);

                    if (result != null && result.Count > 0)
                    {
                        string outputDirectory = result[0].Path.LocalPath;

                        // Close the dialog first
                        IsExportDialogVisible = false;

                        // Call the native export function using the bound ExportType
                        bool success = _nativeLibrary.ExportCertificate(outputDirectory, ExportType);

                        if (success)
                        {
                            string exportTypeText = ExportType == 0 ? "Certificate (DER format)" : "Private Key (PEM format)";
                            AddLogMessage($"{exportTypeText} exported successfully to: {outputDirectory}");
                        }
                        else
                        {
                            AddLogMessage("Failed to export certificate. Please check the logs for details.");
                        }
                    }
                }
                else
                {
                    AddLogMessage("ERROR: Could not access directory picker");
                }
            }
            catch (Exception ex)
            {
                AddLogMessage($"Error during certificate export: {ex.Message}");
            }
        }

        /// <summary>
        /// Regenerates the CA certificate and key
        /// </summary>
        private async void RegenerateCertificate()
        {
            try
            {
                if (_nativeLibrary == null)
                {
                    AddLogMessage("ERROR: Native library not available");
                    return;
                }

                // Show confirmation dialog
                bool confirmed = await ShowRegenerateCertificateConfirmationAsync();
                if (!confirmed)
                {
                    AddLogMessage("Certificate regeneration cancelled by user");
                    return;
                }

                AddLogMessage("Regenerating CA certificate...");

                // Stop proxy if running to avoid conflicts
                bool wasProxyRunning = IsProxyRunning;
                if (wasProxyRunning)
                {
                    AddLogMessage("Stopping proxy to regenerate certificate...");
                    await Task.Run(() => _nativeLibrary.StopProxy());
                    await Task.Delay(1000); // Give it time to stop
                    IsProxyRunning = false;
                    UpdateProxyButtonState();
                }

                bool success = await Task.Run(() => _nativeLibrary.RegenerateCertificate());

                if (success)
                {
                    AddLogMessage("Certificate regenerated successfully! New certificate will be used for future connections.");

                    // Restart proxy if it was running
                    if (wasProxyRunning)
                    {
                        AddLogMessage("Restarting proxy with new certificate...");
                        await Task.Delay(1000); // Give it time to reload
                        var startResult = _nativeLibrary.StartProxy();
                        if (startResult.success == 1)
                        {
                            IsProxyRunning = true;
                            UpdateProxyButtonState();
                        }
                    }
                }
                else
                {
                    AddLogMessage("Failed to regenerate certificate. Please check the logs for details.");

                    // Restart proxy if it was running
                    if (wasProxyRunning)
                    {
                        var startResult = _nativeLibrary.StartProxy();
                        if (startResult.success == 1)
                        {
                            IsProxyRunning = true;
                            UpdateProxyButtonState();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AddLogMessage($"Error during certificate regeneration: {ex.Message}");
            }
        }

        /// <summary>
        /// Shows confirmation dialog for certificate regeneration
        /// </summary>
        private async Task<bool> ShowRegenerateCertificateConfirmationAsync()
        {
            try
            {
                var mainWindow = App.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop ? desktop.MainWindow : null;

                if (mainWindow == null)
                {
                    AddLogMessage("Warning: Could not show confirmation dialog, proceeding without confirmation");
                    return true;
                }

                var dialog = new Avalonia.Controls.Window
                {
                    Title = "Regenerate Certificate",
                    Width = 500,
                    Height = 200,
                    WindowStartupLocation = Avalonia.Controls.WindowStartupLocation.CenterOwner,
                    CanResize = false,
                    Content = new StackPanel
                    {
                        Margin = new Avalonia.Thickness(20),
                        Children =
                        {
                            new TextBlock
                            {
                                Text = "Are you sure you want to regenerate the CA certificate?",
                                FontWeight = Avalonia.Media.FontWeight.Bold,
                                TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                                Margin = new Avalonia.Thickness(0, 0, 0, 10)
                            },
                            new TextBlock
                            {
                                Text = "This will delete the existing CA certificate and generate a new one. All clients will need to install the new certificate to continue using the proxy.",
                                TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                                Margin = new Avalonia.Thickness(0, 0, 0, 20)
                            },
                            new StackPanel
                            {
                                Orientation = Avalonia.Layout.Orientation.Horizontal,
                                HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right,
                                Children =
                                {
                                    new Button
                                    {
                                        Content = "Yes, Regenerate",
                                        Margin = new Avalonia.Thickness(0, 0, 10, 0),
                                        Padding = new Avalonia.Thickness(20, 8),
                                        Background = Avalonia.Media.Brushes.Orange,
                                        Foreground = Avalonia.Media.Brushes.White
                                    },
                                    new Button
                                    {
                                        Content = "Cancel",
                                        Padding = new Avalonia.Thickness(20, 8),
                                        Background = Avalonia.Media.Brushes.Gray,
                                        Foreground = Avalonia.Media.Brushes.White
                                    }
                                }
                            }
                        }
                    }
                };
                bool result = false;
                var buttons = ((StackPanel)((StackPanel)dialog.Content).Children[2]).Children;
                ((Button)buttons[0]).Click += (s, e) => { result = true; dialog.Close(); };
                ((Button)buttons[1]).Click += (s, e) => { result = false; dialog.Close(); };

                await dialog.ShowDialog(mainWindow);
                return result;
            }
            catch (Exception ex)
            {
                AddLogMessage($"Error showing confirmation dialog: {ex.Message}");
                return false; // Default to not proceeding if dialog fails
            }
        }

        /// <summary>
        /// Initializes the data viewer tabs with the static Raw Data tab
        /// </summary>
        private void InitializeDataViewerTabs()
        {
            // Add the static Raw Data tab for Proxy History (read-only)
            var proxyRawDataTab = new DataViewerTabViewModel("Raw Data", "Select an item above to view its data...", isEditable: false);
            proxyRawDataTab.IsVisible = true;
            _dataViewerTabs.Add(proxyRawDataTab);

            // Add the static Hex tab for Proxy History (read-only) - treat as extension for content binding
            var proxyHexTab = new DataViewerTabViewModel("Hex", "Select an item above to view its data...", isEditable: false);
            proxyHexTab.IsVisible = true;
            // Mark as extension-like for proper content binding in XAML
            proxyHexTab.SetAsContentBased();
            _dataViewerTabs.Add(proxyHexTab);

            // Add the static Raw Data tab for Intercept (editable)
            var interceptRawDataTab = new DataViewerTabViewModel("Raw Data", "Select an item above to view its data...", isEditable: true);
            interceptRawDataTab.IsVisible = true;
            _interceptDataViewerTabs.Add(interceptRawDataTab);

            // Add the static Hex tab for Intercept (read-only) - treat as extension for content binding
            var interceptHexTab = new DataViewerTabViewModel("Hex", "Select an item above to view its data...", isEditable: false);
            interceptHexTab.IsVisible = true;
            // Mark as extension-like for proper content binding in XAML
            interceptHexTab.SetAsContentBased();
            _interceptDataViewerTabs.Add(interceptHexTab);

            // Initialize visible collections
            UpdateVisibleTabs();
        }

        /// <summary>
        /// Updates only the extension tabs (like Hex) when data changes, but leaves Raw Data tab alone
        /// </summary>
        private void UpdateExtensionTabsOnly()
        {
            // Only update extension tabs (IsExtension = true), not raw data tabs
            UpdateExtensionTabsForContext(_dataViewerTabs, SelectedProxyEntry, CreateDataContextFromProxyEntry);
            UpdateExtensionTabsForContext(_interceptDataViewerTabs, SelectedInterceptEntry, CreateDataContextFromInterceptEntry);
        }

        /// <summary>
        /// Forces a refresh of all extension tabs with current data from memory
        /// Call this when user switches tabs to ensure they see the latest data
        /// </summary>
        public void RefreshAllTabsWithCurrentData()
        {
            UpdateExtensionTabsOnly();
        }

        /// <summary>
        /// Updates only extension tabs for a specific context, skipping raw data tabs
        /// </summary>
        private void UpdateExtensionTabsForContext<T>(
            ObservableCollection<DataViewerTabViewModel> tabs,
            T? selectedEntry,
            Func<T, ExtensionDataContext> createDataContext) where T : class
        {
            if (selectedEntry == null) return;

            var dataContext = createDataContext(selectedEntry);

            foreach (var tab in tabs)
            {
                // Only update extension tabs, skip Raw Data tabs
                if (tab.IsExtension && tab.ExtensionTab == null) // Built-in extension-like tabs (Hex)
                {
                    if (tab.Name == "Hex")
                    {
                        // Update hex content for built-in Hex tab
                        var hexContent = dataContext.RawData != null ? FormatAsHex(dataContext.RawData) : "No data available";
                        tab.SetContent(hexContent, dataContext);
                    }
                }
                else if (tab.IsExtension && tab.ExtensionTab != null) // Real extension tabs (Base64, etc.)
                {
                    // Update real extension tab content with current data
                    try
                    {
                        var content = DataViewerAPI.ProcessData(tab.ExtensionTab.PythonHandler, dataContext, tab.ExtensionTab.ExtensionName);
                        tab.SetContent(content, dataContext);
                    }
                    catch (Exception ex)
                    {
                        tab.SetContent($"Error processing extension: {ex.Message}", dataContext);
                    }
                }
                // Skip Raw Data tabs entirely - they are bound directly to EditableData
            }
        }

        /// <summary>
        /// Updates the content of extension data viewer tabs when selection changes
        /// </summary>
        private void UpdateExtensionTabContent()
        {
            // Update both proxy and intercept tabs with a unified approach
            UpdateTabsForContext(_dataViewerTabs, SelectedProxyEntry, CreateDataContextFromProxyEntry, SelectedProxyDataContent);
            UpdateTabsForContext(_interceptDataViewerTabs, SelectedInterceptEntry, CreateDataContextFromInterceptEntry, null);

            // Update visible collections
            UpdateVisibleTabs();
        }

        /// <summary>
        /// Generic method to update tabs for any context (proxy/intercept)
        /// </summary>
        private void UpdateTabsForContext<T>(
            ObservableCollection<DataViewerTabViewModel> tabs,
            T? selectedEntry,
            Func<T, ExtensionDataContext> createDataContext,
            string? rawTabContent) where T : class
        {
            foreach (var tab in tabs)
            {
                if (tab.IsExtension && tab.ExtensionTab != null)
                {
                    // Extension tab
                    if (selectedEntry != null)
                    {
                        var dataContext = createDataContext(selectedEntry);
                        tab.IsVisible = tab.ExtensionTab.ShouldShowTab(dataContext);

                        if (tab.IsVisible)
                        {
                            var content = tab.ExtensionTab.ProcessData(dataContext);
                            tab.SetContent(content, dataContext);
                        }
                        else
                        {
                            tab.SetContent("No data selected");
                        }
                    }
                    else
                    {
                        tab.IsVisible = false;
                        tab.SetContent("No data selected");
                    }
                }
                else if (tab.Name == "Raw Data")
                {
                    // Raw Data tab - always visible, shows UTF-8 text
                    tab.IsVisible = true;
                    if (selectedEntry != null)
                    {
                        string content;
                        if (selectedEntry is InterceptEntry interceptEntry)
                        {
                            // For intercept entries, show editable data if available, otherwise raw data
                            content = interceptEntry.EditableData ?? interceptEntry.RawDataAsString;
                        }
                        else
                        {
                            // For proxy entries, use the provided raw tab content
                            content = rawTabContent ?? "Bound directly via XAML";
                        }

                        tab.SetContent(content);
                    }
                    else
                    {
                        tab.SetContent("Select an item above to view its data...");
                    }
                }
                else if (tab.Name == "Hex")
                {
                    // Hex tab - always visible, shows hex format
                    tab.IsVisible = true;
                    if (selectedEntry != null)
                    {
                        byte[]? rawData = null;
                        if (selectedEntry is ProxyEntry proxyEntry)
                        {
                            // Respect the dropdown selection for proxy entries
                            rawData = ProxyDataViewSelection == 1 && proxyEntry.HasEditedData
                                ? proxyEntry.EditedData
                                : proxyEntry.RawData;
                        }
                        else if (selectedEntry is InterceptEntry interceptEntry)
                        {
                            // For intercept entries, use the current editable data if available
                            if (!string.IsNullOrEmpty(interceptEntry.EditableData))
                            {
                                rawData = System.Text.Encoding.UTF8.GetBytes(interceptEntry.EditableData);
                            }
                            else
                            {
                                rawData = interceptEntry.RawData;
                            }
                        }

                        var hexContent = rawData != null ? FormatAsHex(rawData) : "No data available";
                        tab.SetContent(hexContent);
                    }
                    else
                    {
                        tab.SetContent("Select an item above to view its data...");
                    }
                }
                else
                {
                    // Other static tabs - always visible
                    tab.IsVisible = true;
                    tab.Content = selectedEntry != null ?
                        (rawTabContent ?? "Bound directly via XAML") :
                        "Select an item above to view its data...";
                }
            }
        }        /// <summary>
        /// Updates tab collection by checking visibility and updating content
        /// </summary>
        private void UpdateTabCollectionVisibility(ObservableCollection<DataViewerTabViewModel> tabCollection, Func<ExtensionDataContext?> getDataContext)
        {
            var dataContext = getDataContext();

            // Get all registered extension tabs for this collection
            var allPossibleExtensionTabs = GetAllRegisteredExtensionTabs(tabCollection);

            // Remove extension tabs that should not be visible
            var extensionTabsToRemove = tabCollection.Where(t => t.IsExtension && t.ExtensionTab != null).ToList();
            foreach (var tab in extensionTabsToRemove)
            {
                if (dataContext == null || !tab.ExtensionTab!.ShouldShowTab(dataContext))
                {
                    tabCollection.Remove(tab);
                }
            }

            // Add extension tabs that should be visible but aren't currently in the collection
            if (dataContext != null)
            {
                foreach (var extensionTab in allPossibleExtensionTabs)
                {
                    if (extensionTab.ShouldShowTab(dataContext))
                    {
                        // Check if this extension tab is already in the collection
                        bool alreadyExists = tabCollection.Any(t => t.IsExtension && t.ExtensionTab?.ExtensionName == extensionTab.ExtensionName && t.ExtensionTab?.TabName == extensionTab.TabName);

                        if (!alreadyExists)
                        {
                            var newTab = new DataViewerTabViewModel(extensionTab);
                            tabCollection.Add(newTab);
                        }
                    }
                }
            }

            // Update content for all tabs
            foreach (var tab in tabCollection)
            {
                if (tab.IsExtension && tab.ExtensionTab != null)
                {
                    // Extension tab
                    if (dataContext != null)
                    {
                        tab.Content = tab.ExtensionTab.ProcessData(dataContext);
                    }
                    else
                    {
                        tab.Content = "No data selected";
                    }
                }
                else if (!tab.IsExtension)
                {
                    // Raw Data tab - use appropriate content based on tab collection type
                    if (tabCollection == _dataViewerTabs)
                    {
                        // Proxy History Raw Data tab
                        tab.Content = SelectedProxyEntry != null ? SelectedProxyDataContent : "Select an item above to view its data...";
                    }
                    else
                    {
                        // Intercept Raw Data tab - bound directly via XAML
                        if (SelectedInterceptEntry != null)
                        {
                            OnPropertyChanged(nameof(SelectedInterceptEntry));
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Gets all registered extension tabs for a tab collection
        /// </summary>
        private List<ExtensionDataViewerTab> GetAllRegisteredExtensionTabs(ObservableCollection<DataViewerTabViewModel> tabCollection)
        {
            // Return all registered extension tabs from the persistent registry
            return _allRegisteredExtensionTabs.ToList();
        }

        /// <summary>
        /// Creates an ExtensionDataContext from a ProxyEntry
        /// </summary>
        private ExtensionDataContext CreateDataContextFromProxyEntry(ProxyEntry entry)
        {
            return CreateDataContext(
                sourceIp: entry.SourceIp,
                destinationIp: entry.DestinationIp,
                sourcePort: 0, // ProxyEntry doesn't have SourcePort
                destinationPort: entry.DestinationPort,
                direction: entry.Direction,
                size: entry.Size,
                data: SelectedProxyDataContent,
                rawData: ProxyDataViewSelection == 1 && entry.HasEditedData ? entry.EditedData : entry.RawData,
                messageType: entry.MessageType,
                timestamp: entry.Timestamp,
                connectionId: entry.ConnectionId,
                packetId: entry.PacketId,
                isEditable: false,
                editableData: null
            );
        }

        /// <summary>
        /// Creates an ExtensionDataContext from an InterceptEntry
        /// </summary>
        private ExtensionDataContext CreateDataContextFromInterceptEntry(InterceptEntry entry)
        {
            // Always use the current RawData which gets updated when EditableData changes
            return CreateDataContext(
                sourceIp: entry.SourceIp,
                destinationIp: entry.DestinationIp,
                sourcePort: entry.SourcePort,
                destinationPort: entry.DestinationPort,
                direction: entry.Direction,
                size: entry.Size,
                data: entry.RawDataAsString, // Use current RawDataAsString which reflects updated RawData
                rawData: entry.RawData, // Use current RawData which gets updated in real-time
                messageType: entry.MessageType,
                timestamp: entry.Timestamp,
                connectionId: entry.ConnectionId,
                packetId: entry.PacketId,
                isEditable: true,
                editableData: entry.EditableData
            );
        }

        /// <summary>
        /// Generic method to create ExtensionDataContext to reduce redundancy
        /// </summary>
        private ExtensionDataContext CreateDataContext(
            string sourceIp, string destinationIp, int sourcePort, int destinationPort,
            string direction, int size, string? data, byte[] rawData, string messageType,
            DateTime timestamp, int connectionId, int packetId, bool isEditable, string? editableData)
        {
            return new ExtensionDataContext
            {
                SourceIP = sourceIp,
                DestinationIP = destinationIp,
                SourcePort = sourcePort,
                DestinationPort = destinationPort,
                Direction = direction,
                Length = size,
                Data = data,
                RawData = rawData,
                Type = messageType,
                Timestamp = timestamp,
                ConnectionId = connectionId,
                PacketId = packetId,
                IsEditable = isEditable,
                EditableData = editableData
            };
        }

        /// <summary>
        /// Registers a new extension data viewer tab
        /// </summary>
        /// <param name="tabName">The name to display on the tab</param>
        /// <param name="extensionName">The name of the extension registering the tab</param>
        /// <param name="pythonHandler">The Python handler for the tab</param>
        public void RegisterExtensionDataViewerTab(string tabName, string extensionName, Python.Runtime.PyObject pythonHandler)
        {
            var extensionTab = new ExtensionDataViewerTab(tabName, extensionName, pythonHandler);
            _allRegisteredExtensionTabs.Add(extensionTab);

            var tabViewModels = new[]
            {
                new DataViewerTabViewModel(extensionTab, isEditable: false) { IsVisible = true }, // Proxy
                new DataViewerTabViewModel(extensionTab, isEditable: true) { IsVisible = true }   // Intercept
            };

            // Set up content change handler for the editable intercept tab
            tabViewModels[1].ContentChanged += OnExtensionTabContentChanged;

            ExecuteOnUIThread(() =>
            {
                _extensionDataViewerTabs.Add(extensionTab);
                _dataViewerTabs.Add(tabViewModels[0]);
                _interceptDataViewerTabs.Add(tabViewModels[1]);
                UpdateVisibleTabs();
            });
        }

        /// <summary>
        /// Helper method to execute actions on UI thread
        /// </summary>
        private void ExecuteOnUIThread(Action action)
        {
            if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
                action();
            else
                Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(action);
        }

        /// <summary>
        /// Removes all data viewer tabs for a specific extension
        /// </summary>
        /// <param name="extensionName">The name of the extension whose tabs should be removed</param>
        public void RemoveExtensionDataViewerTabs(string extensionName)
        {
            ExecuteOnUIThread(() => RemoveExtensionTabsInternal(extensionName));
        }

        private void RemoveExtensionTabsInternal(string extensionName)
        {
            // Remove from registry (List)
            _allRegisteredExtensionTabs.RemoveAll(tab => tab.ExtensionName == extensionName);

            // Remove from observable collections
            RemoveItemsFromCollection(_extensionDataViewerTabs, tab => tab.ExtensionName == extensionName);
            RemoveItemsFromCollection(_dataViewerTabs, tab => tab.IsExtension && tab.ExtensionTab?.ExtensionName == extensionName);
            RemoveItemsFromCollection(_interceptDataViewerTabs, tab => tab.IsExtension && tab.ExtensionTab?.ExtensionName == extensionName);

            UpdateVisibleTabs();
        }

        /// <summary>
        /// Helper method to remove items from any observable collection
        /// </summary>
        private static void RemoveItemsFromCollection<T>(ObservableCollection<T> collection, Func<T, bool> predicate)
        {
            var itemsToRemove = collection.Where(predicate).ToList();
            foreach (var item in itemsToRemove)
                collection.Remove(item);
        }

        #endregion

        #region IDisposable Implementation

        private bool _disposed = false;

        /// <summary>
        /// Properly dispose of resources to prevent memory leaks
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Protected dispose method for proper cleanup
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose Extensions first to properly shutdown Python.NET
                    Extensions?.Dispose();

                    // Unsubscribe from events to prevent memory leaks
                    if (_nativeLibrary != null)
                    {
                        _nativeLibrary.LogReceived -= OnLogReceived;
                        _nativeLibrary.ConnectionEstablished -= OnConnectionEstablished;
                        _nativeLibrary.ConnectionDisconnected -= OnConnectionDisconnected;
                        _nativeLibrary.ProxyLogReceived -= OnProxyLogReceived;
                        _nativeLibrary.PacketIntercepted -= OnPacketIntercepted;
                    }

                    // Unsubscribe from selected intercept entry property changes
                    if (_selectedInterceptEntry != null)
                    {
                        _selectedInterceptEntry.PropertyChanged -= OnSelectedInterceptEntryPropertyChanged;
                    }

                    // Clear collections to free memory
                    _allLogEntries.Clear();
                    LogEntries.Clear();
                    LogText = string.Empty;
                    _allConnectionEntries.Clear();
                    FilteredConnectionEntries.Clear();
                    _allProxyEntries.Clear();
                    ProxyEntries.Clear();
                    HostIpAddresses.Clear();
                    _allInterceptEntries.Clear();
                    InterceptEntries.Clear();

                    // Force garbage collection
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }
                _disposed = true;
            }
        }

        /// <summary>
        /// Finalizer to ensure cleanup if Dispose is not called
        /// </summary>
        ~MainWindowViewModel()
        {
            Dispose(false);
        }

        #endregion

        /// <summary>
        /// Removes the selected proxy entries from both all entries and filtered entries
        /// </summary>
        [RelayCommand]
        private void RemoveSelectedProxyEntries()
        {
            if (SelectedProxyEntries == null || SelectedProxyEntries.Count == 0)
                return;

            // Make a copy of the selected items to avoid collection modification issues
            var itemsToRemove = SelectedProxyEntries.ToList();

            foreach (var item in itemsToRemove)
            {
                _allProxyEntries.Remove(item);
            }

            // Clear selection
            SelectedProxyEntries.Clear();
            SelectedProxyEntry = null;

            // Update the filtered view
            ApplyProxySearchFilter();

            // Force garbage collection to free up memory
            GC.Collect();
        }

        /// <summary>
        /// Selects all proxy entries in the list
        /// </summary>
        [RelayCommand]
        private void SelectAllProxyEntries()
        {
            if (ProxyEntries == null || ProxyEntries.Count == 0)
                return;

            SelectedProxyEntries.Clear();
            foreach (var entry in ProxyEntries)
            {
                SelectedProxyEntries.Add(entry);
            }
        }

        /// <summary>
        /// Copies the selected proxy entries to clipboard
        /// </summary>
        [RelayCommand]
        private void CopySelectedProxyEntries()
        {
            if (SelectedProxyEntries == null || SelectedProxyEntries.Count == 0)
                return;

            var sb = new StringBuilder();
            foreach (var entry in SelectedProxyEntries)
            {
                sb.AppendLine($"{entry.FormattedTimestamp} | {entry.SourceIp} -> {entry.DestinationIp}:{entry.DestinationPort} | {entry.MessageType}");
            }

            try
            {
                // Set clipboard text using Avalonia's clipboard service
                var topLevel = Avalonia.Controls.TopLevel.GetTopLevel((Avalonia.Application.Current?.ApplicationLifetime as Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime)?.MainWindow);
                if (topLevel != null)
                {
                    topLevel.Clipboard?.SetTextAsync(sb.ToString()).GetAwaiter().GetResult();
                    AddLogMessage($"Copied {SelectedProxyEntries.Count} entries to clipboard");
                }
            }
            catch (Exception ex)
            {
                AddLogMessage($"Failed to copy to clipboard: {ex.Message}");
            }
        }

        /// <summary>
        /// Handle the proxy selection changed event
        /// </summary>
        public void OnProxySelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // If a single item is selected, update the SelectedProxyEntry for the raw data viewer
            if (SelectedProxyEntries?.Count == 1)
            {
                SelectedProxyEntry = SelectedProxyEntries[0];
            }
            else if (SelectedProxyEntries?.Count > 1)
            {
                // Keep the currently selected entry if it's in the selection
                if (SelectedProxyEntry != null && !SelectedProxyEntries.Contains(SelectedProxyEntry))
                {
                    SelectedProxyEntry = SelectedProxyEntries[0];
                }
            }
        }

        /// <summary>
        /// Removes the selected connection entries
        /// </summary>
        [RelayCommand]
        private void RemoveSelectedConnectionEntries()
        {
            if (SelectedConnectionEntries == null || SelectedConnectionEntries.Count == 0)
                return;

            // Make a copy of the selected items to avoid collection modification issues
            var itemsToRemove = SelectedConnectionEntries.ToList();

            foreach (var item in itemsToRemove)
            {
                _allConnectionEntries.Remove(item);
            }

            // Clear selection
            SelectedConnectionEntries.Clear();

            // Update the filtered view
            ApplyConnectionSearchFilter();

            // Log action
            AddLogMessage($"Removed {itemsToRemove.Count} connection entries");

            // Force garbage collection to free up memory
            GC.Collect();
        }

        /// <summary>
        /// Selects all connection entries
        /// </summary>
        [RelayCommand]
        private void SelectAllConnectionEntries()
        {
            if (FilteredConnectionEntries == null || FilteredConnectionEntries.Count == 0)
                return;

            SelectedConnectionEntries.Clear();
            foreach (var entry in FilteredConnectionEntries)
            {
                SelectedConnectionEntries.Add(entry);
            }
        }

        /// <summary>
        /// Copies the selected connection entries to clipboard
        /// </summary>
        [RelayCommand]
        private void CopySelectedConnectionEntries()
        {
            if (SelectedConnectionEntries == null || SelectedConnectionEntries.Count == 0)
                return;

            var sb = new StringBuilder();
            foreach (var entry in SelectedConnectionEntries)
            {
                sb.AppendLine($"{entry.Timestamp.ToString("dd/MM/yyyy, HH:mm:ss")} | {entry.SourceIp}:{entry.SourcePort} -> {entry.DestinationIp}:{entry.DestinationPort} | {entry.Event}");
            }

            try
            {
                // Set clipboard text using Avalonia's clipboard service
                var topLevel = Avalonia.Controls.TopLevel.GetTopLevel((Avalonia.Application.Current?.ApplicationLifetime as Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime)?.MainWindow);
                if (topLevel != null)
                {
                    topLevel.Clipboard?.SetTextAsync(sb.ToString()).GetAwaiter().GetResult();
                    AddLogMessage($"Copied {SelectedConnectionEntries.Count} entries to clipboard");
                }
            }
            catch (Exception ex)
            {
                AddLogMessage($"Failed to copy to clipboard: {ex.Message}");
            }
        }

        /// <summary>
        /// Handle the connection selection changed event
        /// </summary>
        public void OnConnectionSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Handle any special logic for connection selection changes
            // Could be used for showing details of the selected connections
        }

        /// <summary>
        /// Apply search filter to intercept entries
        /// </summary>
        private void ApplyInterceptSearchFilter()
        {
            IEnumerable<InterceptEntry> filteredEntries;

            if (string.IsNullOrWhiteSpace(InterceptSearchQuery))
            {
                // If no search query, show all intercept entries
                filteredEntries = _allInterceptEntries;
            }
            else
            {
                // Filter intercept entries based on search
                try
                {
                    var regex = new Regex(InterceptSearchQuery, RegexOptions.IgnoreCase | RegexOptions.Compiled);
                    filteredEntries = _allInterceptEntries.Where(i =>
                        regex.IsMatch(i.ConnectionId.ToString()) ||
                        regex.IsMatch(i.PacketId.ToString()) ||
                        regex.IsMatch(i.SourceIp) ||
                        regex.IsMatch(i.DestinationIp) ||
                        regex.IsMatch(i.DestinationPort.ToString()) ||
                        regex.IsMatch(i.MessageType) ||
                        regex.IsMatch(i.Status) ||
                        regex.IsMatch(i.RawDataAsString));
                }
                catch
                {
                    // If regex is invalid, do a simple contains search
                    filteredEntries = _allInterceptEntries.Where(i =>
                        i.ConnectionId.ToString().Contains(InterceptSearchQuery, StringComparison.OrdinalIgnoreCase) ||
                        i.PacketId.ToString().Contains(InterceptSearchQuery, StringComparison.OrdinalIgnoreCase) ||
                        i.SourceIp.Contains(InterceptSearchQuery, StringComparison.OrdinalIgnoreCase) ||
                        i.DestinationIp.Contains(InterceptSearchQuery, StringComparison.OrdinalIgnoreCase) ||
                        i.DestinationPort.ToString().Contains(InterceptSearchQuery, StringComparison.OrdinalIgnoreCase) ||
                        i.MessageType.Contains(InterceptSearchQuery, StringComparison.OrdinalIgnoreCase) ||
                        i.Status.Contains(InterceptSearchQuery, StringComparison.OrdinalIgnoreCase) ||
                        i.RawDataAsString.Contains(InterceptSearchQuery, StringComparison.OrdinalIgnoreCase));
                }
            }

            // CRITICAL: Update the existing collection instead of replacing it
            // Must be done on UI thread
            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                InterceptEntries.Clear();
                foreach (var entry in filteredEntries)
                    InterceptEntries.Add(entry);
                OnPropertyChanged(nameof(InterceptEntries));
            });
        }

        /// <summary>
        /// Toggle intercept functionality on/off
        /// </summary>
        private void ToggleIntercept()
        {
            try
            {
                if (_nativeLibrary == null)
                {
                    AddLogMessage("ERROR: Native library not initialized");
                    return;
                }

                bool newState = !InterceptEnabled;
                // If we're turning OFF intercept, forward all queued packets first
                if (!newState && InterceptEntries.Count > 0)
                {
                    ForwardAllQueuedPackets();
                }

                bool result = _nativeLibrary.SetInterceptEnabled(newState);

                // Update UI state regardless of return value since the native library
                // seems to work but returns false incorrectly
                InterceptEnabled = newState;
            }
            catch (Exception ex)
            {
                AddLogMessage($"ERROR: Exception toggling intercept: {ex.Message}");
            }
        }

        /// <summary>
        /// Set intercept direction via native library
        /// </summary>
        private void SetInterceptDirectionNative(int direction)
        {
            try
            {
                if (_nativeLibrary == null)
                {
                    AddLogMessage("ERROR: Native library not initialized");
                    return;
                }

                bool result = _nativeLibrary.SetInterceptDirection(direction);

                string directionName = direction switch
                {
                    0 => "None",
                    1 => "Client->Server",
                    2 => "Server->Client",
                    3 => "Both",
                    _ => "Unknown"
                };

                if (!result)
                {
                    AddLogMessage($"ERROR: Failed to set intercept direction to: {directionName}");
                }
            }
            catch (Exception ex)
            {
                AddLogMessage($"ERROR: Exception setting intercept direction: {ex.Message}");
            }
        }

        /// <summary>
        /// Set intercept direction command handler
        /// </summary>
        private void SetInterceptDirection(int direction)
        {
            // This is now just for the command, the property setter handles the native call
            InterceptDirection = direction;
        }

        /// <summary>
        /// Forward intercepted packet (using current data, modified or not)
        /// </summary>
        private void ForwardPacket(InterceptEntry? interceptEntry)
        {
            if (interceptEntry == null)
            {
                AddLogMessage("ERROR: No packet selected for forwarding");
                return;
            }

            try
            {
                if (_nativeLibrary == null)
                {
                    AddLogMessage("ERROR: Native library not initialized");
                    return;
                }

                // Determine the action and data to send based on whether data has been edited
                byte[] dataToSend;
                int action;

                // Check if the user has edited the data
                if (!string.IsNullOrEmpty(interceptEntry.EditableData) && interceptEntry.IsModified)
                {
                    // Use MODIFY action with edited data
                    // For extension-modified data, the EditableData should already be properly encoded
                    dataToSend = System.Text.Encoding.UTF8.GetBytes(interceptEntry.EditableData);
                    action = INTERCEPT_ACTION_MODIFY;
                }
                else
                {
                    // Use FORWARD action with original raw data
                    dataToSend = interceptEntry.RawData;
                    action = INTERCEPT_ACTION_FORWARD;
                }                // Use PacketId as per C API: respond_to_intercept(int packet_id, int action, ...)
                string actionName = action == INTERCEPT_ACTION_FORWARD ? "FORWARD" : action == INTERCEPT_ACTION_MODIFY ? "MODIFY" : "UNKNOWN";
                AddLogMessage($"Forwarding packet {interceptEntry.PacketId} (ConnectionId={interceptEntry.ConnectionId}, Action={actionName})");

                // Call the native function (void return)
                _nativeLibrary.RespondToIntercept(interceptEntry.PacketId, action, dataToSend);

                // IMPORTANT: Remove packet regardless of return value since the native library
                // seems to return false even when it works (as evidenced by server responses in logs)
                interceptEntry.Status = action == INTERCEPT_ACTION_MODIFY ? "Modified & Forwarded" : "Forwarded";
                string actionDescription = action == INTERCEPT_ACTION_MODIFY ? "modification and forwarding" : "forwarding";
                AddLogMessage($"Packet {interceptEntry.PacketId} processed for {actionDescription}");

                // If packet was modified, update the corresponding entry in proxy history
                if (action == INTERCEPT_ACTION_MODIFY)
                {
                    UpdateProxyHistoryModifiedStatus(interceptEntry.PacketId, dataToSend);
                }

                // Remove the packet from the intercept list since it's been handled
                // Ensure we're on the UI thread
                if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
                {
                    InterceptEntries.Remove(interceptEntry);
                    _allInterceptEntries.Remove(interceptEntry);

                    // Auto-select the next packet in the queue if available
                    if (SelectedInterceptEntry == interceptEntry)
                    {
                        SelectedInterceptEntry = InterceptEntries.FirstOrDefault();
                    }
                }
                else
                {
                    Avalonia.Threading.Dispatcher.UIThread.Invoke(() =>
                    {
                        InterceptEntries.Remove(interceptEntry);
                        _allInterceptEntries.Remove(interceptEntry);

                        // Auto-select the next packet in the queue if available
                        if (SelectedInterceptEntry == interceptEntry)
                        {
                            SelectedInterceptEntry = InterceptEntries.FirstOrDefault();
                        }
                    });
                }

                // Notify that the current intercepted packet has changed
                OnPropertyChanged(nameof(CurrentInterceptedPacket));

                AddLogMessage($"Packet removed from queue. Remaining: {InterceptEntries.Count}");
            }
            catch (Exception ex)
            {
                AddLogMessage($"ERROR: Exception forwarding packet: {ex.Message}");
            }
        }

        /// <summary>
        /// Drop intercepted packet
        /// </summary>
        private void DropPacket(InterceptEntry? interceptEntry)
        {
            if (interceptEntry == null)
            {
                AddLogMessage("ERROR: No packet selected for dropping");
                return;
            }

            try
            {
                if (_nativeLibrary == null)
                {
                    AddLogMessage("ERROR: Native library not initialized");
                    return;
                }

                // Use INTERCEPT_ACTION_DROP
                AddLogMessage($"Dropping packet {interceptEntry.PacketId} using PacketId={interceptEntry.PacketId}, Action={INTERCEPT_ACTION_DROP} (DROP)");

                // Call the native function (void return)
                _nativeLibrary.RespondToIntercept(interceptEntry.PacketId, INTERCEPT_ACTION_DROP);
                AddLogMessage($"RespondToIntercept called for drop action");

                // Remove packet regardless of return value (same issue as forward)
                interceptEntry.Status = "Dropped";
                AddLogMessage($"Packet {interceptEntry.PacketId} (Connection {interceptEntry.ConnectionId}) processed for dropping");

                // Remove the packet from the intercept list since it's been handled
                // Ensure we're on the UI thread
                if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
                {
                    InterceptEntries.Remove(interceptEntry);
                    _allInterceptEntries.Remove(interceptEntry);

                    // Auto-select the next packet in the queue if available
                    if (SelectedInterceptEntry == interceptEntry)
                    {
                        SelectedInterceptEntry = InterceptEntries.FirstOrDefault();
                    }
                }
                else
                {
                    Avalonia.Threading.Dispatcher.UIThread.Invoke(() =>
                        {
                            InterceptEntries.Remove(interceptEntry);
                            _allInterceptEntries.Remove(interceptEntry);

                            // Auto-select the next packet in the queue if available
                            if (SelectedInterceptEntry == interceptEntry)
                            {
                                SelectedInterceptEntry = InterceptEntries.FirstOrDefault();
                            }
                        });
                }

                // Notify that the current intercepted packet has changed
                OnPropertyChanged(nameof(CurrentInterceptedPacket));
            }
            catch (Exception ex)
            {
                AddLogMessage($"ERROR: Exception dropping packet: {ex.Message}");
            }
        }

        /// <summary>
        /// Forward all queued intercepted packets in their original format
        /// This is called when intercept is turned OFF to clear the queue
        /// </summary>
        private void ForwardAllQueuedPackets()
        {
            if (_nativeLibrary == null)
            {
                AddLogMessage("ERROR: Native library not initialized for bulk forwarding");
                return;
            }

            int queuedCount = InterceptEntries.Count;
            if (queuedCount == 0)
            {
                AddLogMessage("No queued packets to forward");
                return;
            }

            AddLogMessage($"Forwarding all {queuedCount} queued packets in original format...");

            try
            {
                // Create a copy of the list to avoid modification during iteration
                var packetsToForward = InterceptEntries.ToList();

                foreach (var interceptEntry in packetsToForward)
                {
                    try
                    {
                        // Always use original raw data (not edited) and FORWARD action
                        byte[] dataToSend = interceptEntry.RawData;
                        int action = INTERCEPT_ACTION_FORWARD;

                        AddLogMessage($"Auto-forwarding packet {interceptEntry.PacketId} (Connection {interceptEntry.ConnectionId}) with original data ({dataToSend.Length} bytes)");

                        // Call the native function
                        _nativeLibrary.RespondToIntercept(interceptEntry.PacketId, action, dataToSend);

                        // Update status
                        interceptEntry.Status = "Auto-Forwarded";
                      }
                    catch (Exception ex)
                    {
                        AddLogMessage($"ERROR: Exception auto-forwarding packet {interceptEntry.PacketId}: {ex.Message}");
                        // Continue with other packets even if one fails
                    }
                }

                // Clear all intercepted packets from UI
                if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
                {
                    InterceptEntries.Clear();
                    _allInterceptEntries.Clear();
                    SelectedInterceptEntry = null;
                }
                else
                {
                    Avalonia.Threading.Dispatcher.UIThread.Invoke(() =>
                    {
                        InterceptEntries.Clear();
                        _allInterceptEntries.Clear();
                        SelectedInterceptEntry = null;
                    });
                }

                // Notify that the current intercepted packet has changed
                OnPropertyChanged(nameof(CurrentInterceptedPacket));

                AddLogMessage($"Successfully auto-forwarded {queuedCount} queued packets and cleared the intercept queue");
            }
            catch (Exception ex)
            {
                AddLogMessage($"ERROR: Exception during bulk packet forwarding: {ex.Message}");
            }
        }

        /// <summary>
        /// Called when the intercept search query changes
        /// </summary>
        partial void OnInterceptSearchQueryChanged(string value)
        {
            ApplyInterceptSearchFilter();
        }

        /// <summary>
        /// Selects the intercept entry for editing or viewing raw data
        /// </summary>
        private void SelectInterceptEntry(InterceptEntry? interceptEntry)
        {
            if (interceptEntry == null)
            {
                AddLogMessage("ERROR: No intercept entry selected");
                return;
            }

            try
            {
                // Update the SelectedInterceptEntry property
                SelectedInterceptEntry = interceptEntry;

                // Log the selection
                AddLogMessage($"Selected intercept entry: {interceptEntry.PacketId} (Connection {interceptEntry.ConnectionId})");
            }
            catch (Exception ex)
            {
                AddLogMessage($"ERROR: Exception selecting intercept entry: {ex.Message}");
            }
        }

        /// <summary>
        /// Current intercepted packet for editing (first in queue)
        /// </summary>
        public InterceptEntry? CurrentInterceptedPacket =>
            InterceptEntries.Count > 0 ? InterceptEntries[0] : null;

        /// <summary>
        /// Handles content changes in extension tabs and updates the underlying data
        /// </summary>
        private void OnExtensionTabContentChanged(DataViewerTabViewModel tab, string newContent)
        {
            try
            {
                if (tab.ExtensionTab == null)
                {
                    AddLogMessage("ERROR: Extension tab is null during content change");
                    return;
                }

                var dataContext = tab.GetEditTimeDataContext(); // Use edit-time context instead of current
                if (dataContext == null)
                {
                    AddLogMessage("ERROR: Extension tab edit-time data context is null during content change");
                    return;
                }

                AddLogMessage($"Processing extension data update for packet {dataContext.PacketId}");

                // Call the extension's UpdateData method to re-encode the edited content
                var updatedRawData = tab.ExtensionTab.UpdateData(dataContext, newContent);

                if (string.IsNullOrEmpty(updatedRawData))
                {
                    AddLogMessage($"ERROR: Extension '{tab.ExtensionTab.ExtensionName}' UpdateData returned empty result");
                    return;
                }

                // Find and update the corresponding InterceptEntry
                var interceptEntry = InterceptEntries.FirstOrDefault(e => e.PacketId == dataContext.PacketId);
                if (interceptEntry != null)
                {
                    AddLogMessage($"Updating packet {interceptEntry.PacketId} with modified data");

                    // Update the editable data with the re-encoded result
                    // This will trigger OnEditableDataChanged which updates RawData and other tabs
                    interceptEntry.EditableData = updatedRawData;
                    interceptEntry.IsModified = true;

                    // Force UI update immediately
                    OnPropertyChanged(nameof(SelectedInterceptEntry));

                    // Also update proxy history to show modified status
                    var encodedBytes = System.Text.Encoding.UTF8.GetBytes(updatedRawData);
                    UpdateProxyHistoryModifiedStatus(interceptEntry.PacketId, encodedBytes);
                }
                else
                {
                    AddLogMessage($"WARNING: Could not find InterceptEntry with PacketId {dataContext.PacketId} to update");
                }
            }
            catch (Exception ex)
            {
                AddLogMessage($"ERROR: Exception handling extension tab content change: {ex.Message}");
            }
        }

        /// <summary>
        /// Converts byte array to hex format for display
        /// </summary>
        private static string FormatAsHex(byte[] data)
        {
            if (data == null || data.Length == 0)
                return string.Empty;

            var result = new System.Text.StringBuilder();
            const int bytesPerLine = 16;

            for (int i = 0; i < data.Length; i += bytesPerLine)
            {
                // Offset
                result.AppendFormat("{0:X8}  ", i);

                // Hex bytes
                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (i + j < data.Length)
                    {
                        result.AppendFormat("{0:X2} ", data[i + j]);
                    }
                    else
                    {
                        result.Append("   ");
                    }

                    // Add extra space in the middle
                    if (j == 7)
                        result.Append(" ");
                }

                result.Append(" |");

                // ASCII representation
                for (int j = 0; j < bytesPerLine && i + j < data.Length; j++)
                {
                    byte b = data[i + j];
                    char c = (b >= 32 && b <= 126) ? (char)b : '.';
                    result.Append(c);
                }

                result.AppendLine("|");
            }

            return result.ToString();
        }
    }
}
