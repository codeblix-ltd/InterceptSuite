using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.IO;
using System.Linq;
using Avalonia.Threading;

namespace InterceptSuite.NativeInterop
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct ProxyConfig
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string bind_addr;

        public int port;

        [MarshalAs(UnmanagedType.Bool)]
        public bool verbose_mode;

        [MarshalAs(UnmanagedType.Bool)]
        public bool is_running;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct ProxyStartResult
    {
        public int success;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
        public string message;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct UpstreamProxyStatus
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool enabled;

        public int type; // 0=None, 1=HTTP, 2=SOCKS5

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string host;

        public int port;

        [MarshalAs(UnmanagedType.Bool)]
        public bool use_auth;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string username;
    }

    public class NativeLibrary
    {
        private static NativeLibrary? _instance;
        private static readonly object _lock = new object();

        private IntPtr _libraryHandle = IntPtr.Zero;

        public event EventHandler<string>? LogReceived;
        public event EventHandler<(string clientIp, int clientPort, string targetHost, int targetPort, int connectionId)>? ConnectionEstablished;
        public event EventHandler<(int connectionId, string reason)>? ConnectionDisconnected;
        public event EventHandler<(DateTime timestamp, int connectionId, int packetId, string direction, string srcIp, string dstIp, int dstPort, string protocol, string msgType, byte[] data)>? ProxyLogReceived;
        public event EventHandler<(int connectionId, string direction, string srcIp, string dstIp, int dstPort, string protocol, byte[] data, int packetId)>? PacketIntercepted;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void StatusCallbackDelegate(IntPtr messagePtr);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void ConnectionCallbackDelegate(IntPtr clientIpPtr, int clientPort, IntPtr targetHostPtr, int targetPort, int connectionId);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void DisconnectCallbackDelegate(int connectionId, IntPtr reasonPtr);

        // Log callback delegate for proxy history
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void LogCallbackDelegate(IntPtr timestampPtr, int connectionId, int packetId, IntPtr directionPtr, IntPtr srcIpPtr, IntPtr dstIpPtr, int dstPort, IntPtr protocolPtr, IntPtr dataPtr, int dataLength, IntPtr msgTypePtr);

        // Intercept callback delegate - matches the C typedef
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void InterceptCallbackDelegate(int connectionId, IntPtr directionPtr, IntPtr srcIpPtr, IntPtr dstIpPtr, int dstPort, IntPtr protocolPtr, IntPtr dataPtr, int dataLength, int packetId);

        private readonly StatusCallbackDelegate _statusCallback;
        private readonly ConnectionCallbackDelegate _connectionCallback;
        private readonly DisconnectCallbackDelegate _disconnectCallback;
        private readonly LogCallbackDelegate _logCallback;
        private readonly InterceptCallbackDelegate _interceptCallback;

        // Function delegates for proxy control
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate ProxyStartResult StartProxyDelegate();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void StopProxyDelegate();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int GetSystemIpsDelegate(IntPtr buffer, int bufferSize);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate ProxyConfig GetProxyConfigDelegate();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool SetConfigDelegate(string bindAddr, int port, int verboseMode);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool ExportCertificateDelegate(string outputDirectory, int exportType);

        /// <summary>
        /// Delegate for certificate regeneration function
        /// </summary>
        /// <returns>True if successful, false otherwise</returns>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool RegenerateCertificateDelegate();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SetStatusCallbackDelegate(IntPtr callback);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SetConnectionCallbackDelegate(ConnectionCallbackDelegate callback);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SetDisconnectCallbackDelegate(DisconnectCallbackDelegate callback);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SetLogCallbackDelegate(LogCallbackDelegate callback);

        // Intercept control function delegates
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SetInterceptEnabledDelegate(int enabled);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SetInterceptDirectionDelegate(int direction);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void RespondToInterceptDelegate(int packetId, int action, IntPtr modifiedData, int modifiedLength);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SetInterceptCallbackDelegate(InterceptCallbackDelegate callback);

        // Upstream proxy function delegates
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SetUpstreamProxyEnabledDelegate(int enabled);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SetUpstreamProxyTypeDelegate(int type);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SetUpstreamProxyHostDelegate(string host);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SetUpstreamProxyPortDelegate(int port);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SetUpstreamProxyAuthDelegate(string username, string password);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void DisableUpstreamProxyAuthDelegate();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int ConfigureUpstreamProxyDelegate(int type, string host, int port, string username, string password);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate UpstreamProxyStatus GetUpstreamProxyStatusDelegate();

        // Function pointers
        private StartProxyDelegate? _startProxy;
        private StopProxyDelegate? _stopProxy;
        private GetSystemIpsDelegate? _getSystemIps;
        private GetProxyConfigDelegate? _getProxyConfig;
        private SetConfigDelegate? _setConfig;
        private ExportCertificateDelegate? _exportCertificate;
        private RegenerateCertificateDelegate? _regenerateCertificateDelegate;
        private SetConnectionCallbackDelegate? _setConnectionCallback;
        private SetDisconnectCallbackDelegate? _setDisconnectCallback;
        private SetLogCallbackDelegate? _setLogCallback;
        private SetInterceptCallbackDelegate? _setInterceptCallback;
        private SetInterceptEnabledDelegate? _setInterceptEnabled;
        private SetInterceptDirectionDelegate? _setInterceptDirection;
        private RespondToInterceptDelegate? _respondToIntercept;

        // Upstream proxy function pointers
        private SetUpstreamProxyEnabledDelegate? _setUpstreamProxyEnabled;
        private SetUpstreamProxyTypeDelegate? _setUpstreamProxyType;
        private SetUpstreamProxyHostDelegate? _setUpstreamProxyHost;
        private SetUpstreamProxyPortDelegate? _setUpstreamProxyPort;
        private SetUpstreamProxyAuthDelegate? _setUpstreamProxyAuth;
        private DisableUpstreamProxyAuthDelegate? _disableUpstreamProxyAuth;
        private ConfigureUpstreamProxyDelegate? _configureUpstreamProxy;
        private GetUpstreamProxyStatusDelegate? _getUpstreamProxyStatus;

        // Private constructor (singleton pattern)
        private NativeLibrary()
        {
            // Create the delegates for the callbacks and ensure they don't get garbage collected
            _statusCallback = OnStatusCallback;
            _connectionCallback = OnConnectionCallback;
            _disconnectCallback = OnDisconnectCallback;
            _logCallback = OnLogCallback;
            _interceptCallback = OnInterceptCallback;

            // Initialize the library
            try
            {
                InitializeLibrary();
            }
            catch (Exception)
            {
                // Log error and re-throw
                throw;
            }
        }

        /// <summary>
        /// Gets the singleton instance of the NativeLibrary
        /// </summary>
        public static NativeLibrary Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        _instance ??= new NativeLibrary();
                    }
                }
                return _instance;
            }
        }

        /// <summary>
        /// Initialize the library and set up callbacks
        /// </summary>
        private void InitializeLibrary()
        {
            try
            {
                // Get the path to the native library
                string libraryPath = ResourceManager.GetNativeLibraryPath();

                // Check if file exists
                if (!File.Exists(libraryPath))
                {
                    throw new Exception($"Library file does not exist: {libraryPath}");
                }

                // Load the library dynamically
                _libraryHandle = LoadNativeLibrary(libraryPath);
                if (_libraryHandle == IntPtr.Zero)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    throw new Exception($"Failed to load library: {libraryPath}, Error code: {errorCode}");
                }

                // Try to get function pointers
                IntPtr procAddress = GetNativeProcAddress(_libraryHandle, "set_status_callback");
                if (procAddress != IntPtr.Zero)
                {
                    try
                    {
                        var setStatusCallback = Marshal.GetDelegateForFunctionPointer<SetStatusCallbackDelegate>(procAddress);
                        setStatusCallback(Marshal.GetFunctionPointerForDelegate(_statusCallback));

                    }
                    catch (Exception ex)
                    {
                        LogReceived?.Invoke(this, $"Failed to set callback: {ex.Message}");
                    }
                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: set_status_callback function not found in library");
                }

                // Get function pointers for proxy control
                IntPtr startProxyPtr = GetNativeProcAddress(_libraryHandle, "start_proxy");
                if (startProxyPtr != IntPtr.Zero)
                {
                    _startProxy = Marshal.GetDelegateForFunctionPointer<StartProxyDelegate>(startProxyPtr);

                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: start_proxy function not found in library");
                }

                IntPtr stopProxyPtr = GetNativeProcAddress(_libraryHandle, "stop_proxy");
                if (stopProxyPtr != IntPtr.Zero)
                {
                    _stopProxy = Marshal.GetDelegateForFunctionPointer<StopProxyDelegate>(stopProxyPtr);

                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: stop_proxy function not found in library");
                }

                // Get function pointer for system IPs
                IntPtr getSystemIpsPtr = GetNativeProcAddress(_libraryHandle, "get_system_ips");
                if (getSystemIpsPtr != IntPtr.Zero)
                {
                    _getSystemIps = Marshal.GetDelegateForFunctionPointer<GetSystemIpsDelegate>(getSystemIpsPtr);

                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: get_system_ips function not found in library");
                }

                // Get function pointer for proxy config
                IntPtr getProxyConfigPtr = GetNativeProcAddress(_libraryHandle, "get_proxy_config");
                if (getProxyConfigPtr != IntPtr.Zero)
                {
                    _getProxyConfig = Marshal.GetDelegateForFunctionPointer<GetProxyConfigDelegate>(getProxyConfigPtr);

                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: get_proxy_config function not found in library");
                }

                // Get function pointer for set config
                IntPtr setConfigPtr = GetNativeProcAddress(_libraryHandle, "set_config");
                if (setConfigPtr != IntPtr.Zero)
                {
                    _setConfig = Marshal.GetDelegateForFunctionPointer<SetConfigDelegate>(setConfigPtr);

                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: set_config function not found in library");
                }

                // Get function pointer for export certificate
                IntPtr exportCertificatePtr = GetNativeProcAddress(_libraryHandle, "export_certificate");
                if (exportCertificatePtr != IntPtr.Zero)
                {
                    _exportCertificate = Marshal.GetDelegateForFunctionPointer<ExportCertificateDelegate>(exportCertificatePtr);

                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: export_certificate function not found in library");
                }

                // Get function pointer for regenerate certificate
                IntPtr regenerateCertificatePtr = GetNativeProcAddress(_libraryHandle, "regenerate_ca_certificate_wrapper");
                if (regenerateCertificatePtr != IntPtr.Zero)
                {
                    _regenerateCertificateDelegate = Marshal.GetDelegateForFunctionPointer<RegenerateCertificateDelegate>(regenerateCertificatePtr);
                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: regenerate_ca_certificate_wrapper function not found in library");
                }

                // Get function pointer for set_connection_callback
                IntPtr setConnectionCallbackPtr = GetNativeProcAddress(_libraryHandle, "set_connection_callback");
                if (setConnectionCallbackPtr != IntPtr.Zero)
                {
                    _setConnectionCallback = Marshal.GetDelegateForFunctionPointer<SetConnectionCallbackDelegate>(setConnectionCallbackPtr);
                    _setConnectionCallback(_connectionCallback);

                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: set_connection_callback function not found in library");
                }

                // Get function pointer for set_disconnect_callback
                IntPtr setDisconnectCallbackPtr = GetNativeProcAddress(_libraryHandle, "set_disconnect_callback");
                if (setDisconnectCallbackPtr != IntPtr.Zero)
                {
                    _setDisconnectCallback = Marshal.GetDelegateForFunctionPointer<SetDisconnectCallbackDelegate>(setDisconnectCallbackPtr);
                    _setDisconnectCallback(_disconnectCallback);

                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: set_disconnect_callback function not found in library");
                }

                // Get function pointer for set_log_callback
                IntPtr setLogCallbackPtr = GetNativeProcAddress(_libraryHandle, "set_log_callback");
                if (setLogCallbackPtr != IntPtr.Zero)
                {
                    _setLogCallback = Marshal.GetDelegateForFunctionPointer<SetLogCallbackDelegate>(setLogCallbackPtr);
                    _setLogCallback(_logCallback);

                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: set_log_callback function not found in library");
                }

                // Get function pointer for set_intercept_callback
                IntPtr setInterceptCallbackPtr = GetNativeProcAddress(_libraryHandle, "set_intercept_callback");
                if (setInterceptCallbackPtr != IntPtr.Zero)
                {
                    _setInterceptCallback = Marshal.GetDelegateForFunctionPointer<SetInterceptCallbackDelegate>(setInterceptCallbackPtr);
                    _setInterceptCallback(_interceptCallback);

                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: set_intercept_callback function not found in library");
                }

                // Get function pointer for set_intercept_enabled
                IntPtr setInterceptEnabledPtr = GetNativeProcAddress(_libraryHandle, "set_intercept_enabled");
                if (setInterceptEnabledPtr != IntPtr.Zero)
                {
                    _setInterceptEnabled = Marshal.GetDelegateForFunctionPointer<SetInterceptEnabledDelegate>(setInterceptEnabledPtr);

                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: set_intercept_enabled function not found in library");
                }

                // Get function pointer for set_intercept_direction
                IntPtr setInterceptDirectionPtr = GetNativeProcAddress(_libraryHandle, "set_intercept_direction");
                if (setInterceptDirectionPtr != IntPtr.Zero)
                {
                    _setInterceptDirection = Marshal.GetDelegateForFunctionPointer<SetInterceptDirectionDelegate>(setInterceptDirectionPtr);

                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: set_intercept_direction function not found in library");
                }

                // Get function pointer for respond_to_intercept
                IntPtr respondToInterceptPtr = GetNativeProcAddress(_libraryHandle, "respond_to_intercept");
                if (respondToInterceptPtr != IntPtr.Zero)
                {
                    _respondToIntercept = Marshal.GetDelegateForFunctionPointer<RespondToInterceptDelegate>(respondToInterceptPtr);

                }
                else
                {
                    LogReceived?.Invoke(this, "WARNING: respond_to_intercept function not found in library");
                }

                // Get function pointers for upstream proxy functions
                IntPtr setUpstreamProxyEnabledPtr = GetNativeProcAddress(_libraryHandle, "set_upstream_proxy_enabled");
                if (setUpstreamProxyEnabledPtr != IntPtr.Zero)
                {
                    _setUpstreamProxyEnabled = Marshal.GetDelegateForFunctionPointer<SetUpstreamProxyEnabledDelegate>(setUpstreamProxyEnabledPtr);
                }

                IntPtr setUpstreamProxyTypePtr = GetNativeProcAddress(_libraryHandle, "set_upstream_proxy_type");
                if (setUpstreamProxyTypePtr != IntPtr.Zero)
                {
                    _setUpstreamProxyType = Marshal.GetDelegateForFunctionPointer<SetUpstreamProxyTypeDelegate>(setUpstreamProxyTypePtr);
                }

                IntPtr setUpstreamProxyHostPtr = GetNativeProcAddress(_libraryHandle, "set_upstream_proxy_host");
                if (setUpstreamProxyHostPtr != IntPtr.Zero)
                {
                    _setUpstreamProxyHost = Marshal.GetDelegateForFunctionPointer<SetUpstreamProxyHostDelegate>(setUpstreamProxyHostPtr);
                }

                IntPtr setUpstreamProxyPortPtr = GetNativeProcAddress(_libraryHandle, "set_upstream_proxy_port");
                if (setUpstreamProxyPortPtr != IntPtr.Zero)
                {
                    _setUpstreamProxyPort = Marshal.GetDelegateForFunctionPointer<SetUpstreamProxyPortDelegate>(setUpstreamProxyPortPtr);
                }

                IntPtr setUpstreamProxyAuthPtr = GetNativeProcAddress(_libraryHandle, "set_upstream_proxy_auth");
                if (setUpstreamProxyAuthPtr != IntPtr.Zero)
                {
                    _setUpstreamProxyAuth = Marshal.GetDelegateForFunctionPointer<SetUpstreamProxyAuthDelegate>(setUpstreamProxyAuthPtr);
                }

                IntPtr disableUpstreamProxyAuthPtr = GetNativeProcAddress(_libraryHandle, "disable_upstream_proxy_auth");
                if (disableUpstreamProxyAuthPtr != IntPtr.Zero)
                {
                    _disableUpstreamProxyAuth = Marshal.GetDelegateForFunctionPointer<DisableUpstreamProxyAuthDelegate>(disableUpstreamProxyAuthPtr);
                }

                IntPtr configureUpstreamProxyPtr = GetNativeProcAddress(_libraryHandle, "configure_upstream_proxy");
                if (configureUpstreamProxyPtr != IntPtr.Zero)
                {
                    _configureUpstreamProxy = Marshal.GetDelegateForFunctionPointer<ConfigureUpstreamProxyDelegate>(configureUpstreamProxyPtr);
                }

                IntPtr getUpstreamProxyStatusPtr = GetNativeProcAddress(_libraryHandle, "get_upstream_proxy_status");
                if (getUpstreamProxyStatusPtr != IntPtr.Zero)
                {
                    _getUpstreamProxyStatus = Marshal.GetDelegateForFunctionPointer<GetUpstreamProxyStatusDelegate>(getUpstreamProxyStatusPtr);
                }

                // Library initialization completed silently - only log errors
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Failed to initialize native library: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Callback method invoked by the native code
        /// </summary>
        private void OnStatusCallback(IntPtr messagePtr)
        {
            try
            {
                // Convert the unmanaged string to a managed string
                string message = Marshal.PtrToStringUTF8(messagePtr) ?? string.Empty;

                // Marshal to UI thread using Avalonia's Dispatcher - Use Post for async execution
                Dispatcher.UIThread.Post(() =>
                {
                    // Forward the status message from C library to the GUI logs
                    LogReceived?.Invoke(this, message);
                });
            }
            catch (Exception ex)
            {
                // Log error on UI thread as well
                Dispatcher.UIThread.Post(() =>
                {
                    LogReceived?.Invoke(this, $"Error in callback: {ex.Message}");
                });
            }
        }

        /// <summary>
        /// Callback method invoked when a new connection is established
        /// </summary>
        private void OnConnectionCallback(IntPtr clientIpPtr, int clientPort, IntPtr targetHostPtr, int targetPort, int connectionId)
        {
            try
            {
                // Convert the unmanaged strings to managed strings
                string clientIp = Marshal.PtrToStringUTF8(clientIpPtr) ?? string.Empty;
                string targetHost = Marshal.PtrToStringUTF8(targetHostPtr) ?? string.Empty;

                // Marshal to UI thread
                Dispatcher.UIThread.Post(() =>
                {
                    // Raise the event
                    ConnectionEstablished?.Invoke(this, (clientIp, clientPort, targetHost, targetPort, connectionId));
                });
            }
            catch (Exception ex)
            {
                // Log error on UI thread
                Dispatcher.UIThread.Post(() =>
                {
                    LogReceived?.Invoke(this, $"Error in connection callback: {ex.Message}");
                });
            }
        }

        /// <summary>
        /// Callback method invoked when a connection is disconnected
        /// </summary>
        private void OnDisconnectCallback(int connectionId, IntPtr reasonPtr)
        {
            try
            {
                // Convert the unmanaged string to a managed string
                string reason = Marshal.PtrToStringUTF8(reasonPtr) ?? "Unknown reason";

                // Marshal to UI thread
                Dispatcher.UIThread.Post(() =>
                {
                    // Raise the event
                    ConnectionDisconnected?.Invoke(this, (connectionId, reason));
                });
            }
            catch (Exception ex)
            {
                // Log error on UI thread
                Dispatcher.UIThread.Post(() =>
                {
                    LogReceived?.Invoke(this, $"Error in disconnect callback: {ex.Message}");
                });
            }
        }

        /// <summary>
        /// Callback method invoked when proxy log data is received
        /// </summary>
        private void OnLogCallback(IntPtr timestampPtr, int connectionId, int packetId, IntPtr directionPtr, IntPtr srcIpPtr, IntPtr dstIpPtr, int dstPort, IntPtr protocolPtr, IntPtr dataPtr, int dataLength, IntPtr msgTypePtr)
        {
            try
            {
                // Validate connection ID and packet ID
                if (connectionId < 0 || packetId < 0)
                {
                    // Invalid connection/packet ID - ignore silently
                    return;
                }

                // Validate port number
                if (dstPort < 0 || dstPort > 65535)
                {
                    // Invalid port - ignore silently
                    return;
                }

                // Convert the unmanaged strings to managed strings with null checks
                string srcIp = string.Empty;
                string dstIp = string.Empty;
                string direction = string.Empty;
                string protocol = string.Empty;
                string msgType = string.Empty;
                string timestampStr = string.Empty;

                if (srcIpPtr != IntPtr.Zero)
                    srcIp = Marshal.PtrToStringUTF8(srcIpPtr) ?? string.Empty;

                if (dstIpPtr != IntPtr.Zero)
                    dstIp = Marshal.PtrToStringUTF8(dstIpPtr) ?? string.Empty;

                if (directionPtr != IntPtr.Zero)
                    direction = Marshal.PtrToStringUTF8(directionPtr) ?? string.Empty;

                if (protocolPtr != IntPtr.Zero)
                    protocol = Marshal.PtrToStringUTF8(protocolPtr) ?? string.Empty;

                if (msgTypePtr != IntPtr.Zero)
                    msgType = Marshal.PtrToStringUTF8(msgTypePtr) ?? string.Empty;

                if (timestampPtr != IntPtr.Zero)
                    timestampStr = Marshal.PtrToStringUTF8(timestampPtr) ?? string.Empty;

                // Parse the timestamp string (format from C code: "YYYY-MM-DD HH:MM:SS")
                DateTime dateTime;
                try
                {
                    if (!string.IsNullOrEmpty(timestampStr) && DateTime.TryParse(timestampStr, out DateTime parsedDate))
                    {
                        dateTime = parsedDate;
                    }
                    else
                    {
                        // Fallback to current time if timestamp is invalid
                        dateTime = DateTime.Now;
                        // Invalid timestamp - don't log this
                    }
                }
                catch
                {
                    // Fallback to current time if conversion fails
                    dateTime = DateTime.Now;
                }

                // Copy the data using the provided length
                byte[] data = Array.Empty<byte>();
                if (dataPtr != IntPtr.Zero && dataLength > 0)
                {
                    try
                    {
                        // Validate data length to prevent excessive memory allocation
                        if (dataLength > 0 && dataLength <= 64 * 1024 * 1024) // 64MB max
                        {
                            data = new byte[dataLength];
                            Marshal.Copy(dataPtr, data, 0, dataLength);
                        }
                        else if (dataLength > 64 * 1024 * 1024)
                        {
                            Dispatcher.UIThread.Post(() =>
                            {
                                LogReceived?.Invoke(this, $"WARNING: Data too large ({dataLength} bytes), truncated to 64MB");
                            });
                            data = new byte[64 * 1024 * 1024];
                            Marshal.Copy(dataPtr, data, 0, 64 * 1024 * 1024);
                        }
                    }
                    catch (Exception ex)
                    {
                        data = Array.Empty<byte>();
                        Dispatcher.UIThread.Post(() =>
                        {
                            LogReceived?.Invoke(this, $"ERROR: Failed to copy data: {ex.Message}");
                        });
                    }
                }

                // Marshal to UI thread - use Post for async execution to avoid deadlocks
                Dispatcher.UIThread.Post(() =>
                {
                    try
                    {
                        // Raise the event with the protocol parameter
                        ProxyLogReceived?.Invoke(this, (dateTime, connectionId, packetId, direction, srcIp, dstIp, dstPort, protocol, msgType, data));
                    }
                    catch (Exception ex)
                    {
                        LogReceived?.Invoke(this, $"Error raising ProxyLogReceived event: {ex.Message}");
                    }
                });
            }
            catch (Exception ex)
            {
                // Log error on UI thread - use Post to avoid potential deadlocks
                Dispatcher.UIThread.Post(() =>
                {
                    LogReceived?.Invoke(this, $"Error in log callback: {ex.Message}");
                });
            }
        }

        /// <summary>
        /// Callback method invoked when an intercept event occurs
        /// </summary>
        private void OnInterceptCallback(int connectionId, IntPtr directionPtr, IntPtr srcIpPtr, IntPtr dstIpPtr, int dstPort, IntPtr protocolPtr, IntPtr dataPtr, int dataLength, int packetId)
        {
            try
            {
                // Convert the unmanaged data to managed types
                byte[] data = new byte[dataLength];
                Marshal.Copy(dataPtr, data, 0, dataLength);

                // Convert the direction to a string
                string direction = directionPtr == IntPtr.Zero ? "Unknown" : Marshal.PtrToStringUTF8(directionPtr) ?? "Unknown";

                // Convert protocol to string
                string protocol = protocolPtr == IntPtr.Zero ? "TCP" : Marshal.PtrToStringUTF8(protocolPtr) ?? "TCP";

                // Convert IPs to strings
                string srcIp = srcIpPtr == IntPtr.Zero ? "0.0.0.0" : Marshal.PtrToStringUTF8(srcIpPtr) ?? "0.0.0.0";
                string dstIp = dstIpPtr == IntPtr.Zero ? "0.0.0.0" : Marshal.PtrToStringUTF8(dstIpPtr) ?? "0.0.0.0";

                // Log the intercept event and raise the PacketIntercepted event
                Dispatcher.UIThread.Post(() =>
                {

                    // Raise the PacketIntercepted event for the GUI
                    PacketIntercepted?.Invoke(this, (connectionId, direction, srcIp, dstIp, dstPort, protocol, data, packetId));
                });

                // Here you can add custom logic to respond to the intercept, e.g. modify data, change direction, etc.

            }
            catch (Exception ex)
            {
                // Log error on UI thread
                Dispatcher.UIThread.Post(() =>
                {
                    LogReceived?.Invoke(this, $"Error in intercept callback: {ex.Message}");
                });
            }
        }

        /// <summary>
        /// Starts the proxy server
        /// </summary>
        /// <returns>ProxyStartResult with success status and message</returns>
        public ProxyStartResult StartProxy()
        {
            if (_startProxy == null)
            {
                LogReceived?.Invoke(this, "ERROR: Native library not properly initialized");
                return new ProxyStartResult
                {
                    success = 0,
                    message = "Native library not properly initialized"
                };
            }

            try
            {
                ProxyStartResult result = _startProxy();
                return result;
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error starting proxy: {ex.Message}");
                return new ProxyStartResult
                {
                    success = 0,
                    message = $"Exception occurred: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Stops the proxy server
        /// </summary>
        public void StopProxy()
        {
            if (_stopProxy == null)
            {
                LogReceived?.Invoke(this, "ERROR: Native library not properly initialized");
                throw new InvalidOperationException("Native library not properly initialized");
            }

            try
            {
                _stopProxy();

            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error stopping proxy: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets the list of system IP addresses from the DLL
        /// </summary>
        /// <returns>List of IP addresses</returns>
        public List<string> GetSystemIps()
        {
            if (_getSystemIps == null)
            {
                LogReceived?.Invoke(this, "ERROR: get_system_ips function not available");
                return new List<string> { "127.0.0.1 (localhost)", "0.0.0.0 (all interfaces)" };
            }

            try
            {
                // Create buffer for IP addresses
                IntPtr buffer = Marshal.AllocHGlobal(4096);
                try
                {
                    int result = _getSystemIps(buffer, 4096);
                    if (result > 0)
                    {
                        // Convert buffer to string array
                        string responseString = Marshal.PtrToStringUTF8(buffer) ?? string.Empty;
                        if (!string.IsNullOrWhiteSpace(responseString))
                        {
                            // Try multiple separators: newline, semicolon, comma
                            var ips = new List<string>();

                            // First try splitting by semicolon (most likely based on the UI screenshot)
                            if (responseString.Contains(';'))
                            {
                                ips = responseString.Split(';', StringSplitOptions.RemoveEmptyEntries)
                                    .Select(ip => ip.Trim())
                                    .Where(ip => !string.IsNullOrWhiteSpace(ip))
                                    .ToList();
                            }
                            // Then try newline
                            else if (responseString.Contains('\n'))
                            {
                                ips = responseString.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                                    .Select(ip => ip.Trim())
                                    .Where(ip => !string.IsNullOrWhiteSpace(ip))
                                    .ToList();
                            }
                            // Finally try comma
                            else if (responseString.Contains(','))
                            {
                                ips = responseString.Split(',', StringSplitOptions.RemoveEmptyEntries)
                                    .Select(ip => ip.Trim())
                                    .Where(ip => !string.IsNullOrWhiteSpace(ip))
                                    .ToList();
                            }
                            else
                            {
                                // Single IP address
                                ips.Add(responseString.Trim());
                            }

                            if (ips.Count > 0)
                            {
                                return ips;
                            }
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }

                // Return fallback if native call fails (no need to log this)
                return new List<string> { "127.0.0.1 (localhost)", "0.0.0.0 (all interfaces)" };
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error getting system IPs: {ex.Message}");
                return new List<string> { "127.0.0.1 (localhost)", "0.0.0.0 (all interfaces)" };
            }
        }

        /// <summary>
        /// Gets the current proxy configuration from the DLL
        /// </summary>
        /// <returns>Current proxy configuration</returns>
        public ProxyConfig GetProxyConfig()
        {
            if (_getProxyConfig == null)
            {
                LogReceived?.Invoke(this, "ERROR: get_proxy_config function not available");
                return new ProxyConfig
                {
                    bind_addr = "127.0.0.1",
                    port = 4444,
                    verbose_mode = true,
                    is_running = false
                };
            }

            try
            {
                var config = _getProxyConfig();
                return config;
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error getting proxy config: {ex.Message}");
                return new ProxyConfig
                {
                    bind_addr = "127.0.0.1",
                    port = 4444,
                    verbose_mode = true,
                    is_running = false
                };
            }
        }

        /// <summary>
        /// Sets the proxy configuration in the DLL
        /// </summary>
        /// <param name="bindAddr">Bind address</param>
        /// <param name="port">Port number</param>
        /// <param name="logFile">Log file path</param>
        /// <param name="verboseMode">Verbose mode flag</param>
        /// <returns>True if successful</returns>
        public bool SetConfig(string bindAddr, int port, bool verboseMode)
        {
            if (_setConfig == null)
            {
                LogReceived?.Invoke(this, "ERROR: set_config function not available");
                return false;
            }

            try
            {
                bool result = _setConfig(bindAddr, port, verboseMode ? 1 : 0);
                return result;
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error setting config: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Exports the certificate to the specified directory
        /// </summary>
        /// <param name="outputDirectory">Output directory path</param>
        /// <param name="exportType">Export type (0 = Certificate DER, 1 = Private Key PEM)</param>
        /// <returns>True if successful</returns>
        public bool ExportCertificate(string outputDirectory, int exportType)
        {
            if (_exportCertificate == null)
            {
                LogReceived?.Invoke(this, "ERROR: export_certificate function not available");
                return false;
            }

            try
            {
                bool result = _exportCertificate(outputDirectory, exportType);
                return result;
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error exporting certificate: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Regenerates the CA certificate and private key
        /// </summary>
        /// <returns>True if successful, false otherwise</returns>
        public bool RegenerateCertificate()
        {
            try
            {
                if (_regenerateCertificateDelegate == null)
                {
                    LogReceived?.Invoke(this, "ERROR: regenerate_ca_certificate_wrapper function not available");
                    return false;
                }

                return _regenerateCertificateDelegate.Invoke();
            }
            catch (Exception ex)
            {
                // Log the error or handle as appropriate for your application
                LogReceived?.Invoke(this, $"Certificate regeneration failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Enable or disable traffic interception
        /// </summary>
        /// <param name="enabled">True to enable, false to disable</param>
        /// <returns>True if successful</returns>
        public bool SetInterceptEnabled(bool enabled)
        {
            if (_setInterceptEnabled == null)
            {
                LogReceived?.Invoke(this, "ERROR: set_intercept_enabled function not available");
                return false;
            }

            try
            {
                int enabledValue = enabled ? 1 : 0;
                _setInterceptEnabled(enabledValue);
                return true; // Since the native function is void, assume success if no exception
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error setting intercept enabled: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Set the direction for traffic interception
        /// </summary>
        /// <param name="direction">Direction: None (0), Client->Server (1), Server->Client (2), Both (3)</param>
        /// <returns>True if successful</returns>
        public bool SetInterceptDirection(int direction)
        {
            if (_setInterceptDirection == null)
            {
                LogReceived?.Invoke(this, "ERROR: set_intercept_direction function not available");
                return false;
            }

            try
            {
                _setInterceptDirection(direction);
                return true; // Since the native function is void, assume success if no exception
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error setting intercept direction: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Respond to an intercepted packet (Forward, Drop, or Modify)
        /// </summary>
        /// <param name="connectionId">Connection ID of the intercepted packet</param>
        /// <param name="action">Action to take (0=Forward, 1=Drop, 2=Modify)</param>
        /// <param name="modifiedData">Modified data (null for Forward/Drop)</param>
        public void RespondToIntercept(int packetId, int action, byte[]? modifiedData = null)
        {
            if (_respondToIntercept == null)
            {
                LogReceived?.Invoke(this, "ERROR: respond_to_intercept function not available");
                return;
            }

            try
            {
                IntPtr dataPtr = IntPtr.Zero;
                int dataLength = 0;

                if (modifiedData != null && modifiedData.Length > 0)
                {
                    dataLength = modifiedData.Length;
                    dataPtr = Marshal.AllocHGlobal(dataLength);
                    Marshal.Copy(modifiedData, 0, dataPtr, dataLength);
                }

                try
                {
                    _respondToIntercept(packetId, action, dataPtr, dataLength);

                }
                finally
                {
                    if (dataPtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(dataPtr);
                    }
                }
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error responding to intercept: {ex.Message}");
            }
        }

        /// <summary>
        /// Enable or disable upstream proxy usage
        /// </summary>
        /// <param name="enabled">True to enable, false to disable</param>
        public void SetUpstreamProxyEnabled(bool enabled)
        {
            if (_setUpstreamProxyEnabled == null)
            {
                LogReceived?.Invoke(this, "WARNING: set_upstream_proxy_enabled function not available");
                return;
            }

            try
            {
                _setUpstreamProxyEnabled(enabled ? 1 : 0);
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error setting upstream proxy enabled: {ex.Message}");
            }
        }

        /// <summary>
        /// Set upstream proxy type
        /// </summary>
        /// <param name="type">Proxy type: 0=None, 1=HTTP, 2=SOCKS5</param>
        public void SetUpstreamProxyType(int type)
        {
            if (_setUpstreamProxyType == null)
            {
                LogReceived?.Invoke(this, "WARNING: set_upstream_proxy_type function not available");
                return;
            }

            try
            {
                _setUpstreamProxyType(type);
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error setting upstream proxy type: {ex.Message}");
            }
        }

        /// <summary>
        /// Set upstream proxy host
        /// </summary>
        /// <param name="host">Proxy host address</param>
        public void SetUpstreamProxyHost(string host)
        {
            if (_setUpstreamProxyHost == null)
            {
                LogReceived?.Invoke(this, "WARNING: set_upstream_proxy_host function not available");
                return;
            }

            try
            {
                _setUpstreamProxyHost(host);
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error setting upstream proxy host: {ex.Message}");
            }
        }

        /// <summary>
        /// Set upstream proxy port
        /// </summary>
        /// <param name="port">Proxy port number</param>
        public void SetUpstreamProxyPort(int port)
        {
            if (_setUpstreamProxyPort == null)
            {
                LogReceived?.Invoke(this, "WARNING: set_upstream_proxy_port function not available");
                return;
            }

            try
            {
                _setUpstreamProxyPort(port);
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error setting upstream proxy port: {ex.Message}");
            }
        }

        /// <summary>
        /// Set upstream proxy authentication
        /// </summary>
        /// <param name="username">Username for authentication</param>
        /// <param name="password">Password for authentication</param>
        public void SetUpstreamProxyAuth(string username, string password)
        {
            if (_setUpstreamProxyAuth == null)
            {
                LogReceived?.Invoke(this, "WARNING: set_upstream_proxy_auth function not available");
                return;
            }

            try
            {
                _setUpstreamProxyAuth(username, password);
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error setting upstream proxy auth: {ex.Message}");
            }
        }

        /// <summary>
        /// Disable upstream proxy authentication
        /// </summary>
        public void DisableUpstreamProxyAuth()
        {
            if (_disableUpstreamProxyAuth == null)
            {
                LogReceived?.Invoke(this, "WARNING: disable_upstream_proxy_auth function not available");
                return;
            }

            try
            {
                _disableUpstreamProxyAuth();
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error disabling upstream proxy auth: {ex.Message}");
            }
        }

        /// <summary>
        /// Configure upstream proxy with all settings at once
        /// </summary>
        /// <param name="type">Proxy type: 0=None, 1=HTTP, 2=SOCKS5</param>
        /// <param name="host">Proxy host address</param>
        /// <param name="port">Proxy port number</param>
        /// <param name="username">Username for authentication (empty string if no auth)</param>
        /// <param name="password">Password for authentication (empty string if no auth)</param>
        /// <returns>True if successful</returns>
        public bool ConfigureUpstreamProxy(int type, string host, int port, string username, string password)
        {
            if (_configureUpstreamProxy == null)
            {
                LogReceived?.Invoke(this, "WARNING: configure_upstream_proxy function not available");
                return false;
            }

            try
            {
                int result = _configureUpstreamProxy(type, host, port, username, password);
                return result == 1;
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error configuring upstream proxy: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Get upstream proxy status and configuration
        /// </summary>
        /// <returns>Upstream proxy status structure</returns>
        public UpstreamProxyStatus? GetUpstreamProxyStatus()
        {
            if (_getUpstreamProxyStatus == null)
            {
                LogReceived?.Invoke(this, "WARNING: get_upstream_proxy_status function not available");
                return null;
            }

            try
            {
                return _getUpstreamProxyStatus();
            }
            catch (Exception ex)
            {
                LogReceived?.Invoke(this, $"Error getting upstream proxy status: {ex.Message}");
                return null;
            }
        }

        // Platform-specific native library loading
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string dllPath);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("libdl.so.2", SetLastError = true)]
        private static extern IntPtr dlopen(string filename, int flags);

        [DllImport("libdl.so.2", SetLastError = true)]
        private static extern IntPtr dlsym(IntPtr handle, string symbol);

        [DllImport("libSystem.dylib", EntryPoint = "dlopen", SetLastError = true)]
        private static extern IntPtr dlopen_mac(string filename, int flags);

        [DllImport("libSystem.dylib", EntryPoint = "dlsym", SetLastError = true)]
        private static extern IntPtr dlsym_mac(IntPtr handle, string symbol);

        private IntPtr LoadNativeLibrary(string libraryPath)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return LoadLibrary(libraryPath);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return dlopen(libraryPath, 2); // RTLD_NOW
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return dlopen_mac(libraryPath, 2); // RTLD_NOW
            }
            else
            {
                throw new PlatformNotSupportedException("Unsupported platform");
            }
        }

        private IntPtr GetNativeProcAddress(IntPtr libraryHandle, string functionName)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return GetProcAddress(libraryHandle, functionName);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return dlsym(libraryHandle, functionName);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return dlsym_mac(libraryHandle, functionName);
            }
            else
            {
                throw new PlatformNotSupportedException("Unsupported platform");
            }
        }
    }
}
