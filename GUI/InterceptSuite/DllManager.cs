// filepath: d:\Windows TLS\Dot NET GUI\TLS_MITM_WPF\DllManager.cs
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace InterceptSuite
{    /// <summary>
    /// Manages loading, initialization, and cleanup of native DLLs
    /// </summary>
    public class DllManager : IDisposable
    {
        private bool _disposed = false;
        private bool _dllLoaded = false;
        private bool _proxyRunning = false;
        private readonly object _proxyStateLock = new object();        private readonly NativeMethods.LogCallbackDelegate _logCallback;
        private readonly NativeMethods.StatusCallbackDelegate _statusCallback;
        private readonly NativeMethods.ConnectionCallbackDelegate _connectionCallback;
        private readonly NativeMethods.StatsCallbackDelegate _statsCallback;
        private readonly NativeMethods.DisconnectCallbackDelegate _disconnectCallback;
        private readonly NativeMethods.InterceptCallbackDelegate _interceptCallback;

        // Event handlers for callbacks
        public event Action<string, string, string, int, string, string>? OnLogMessage;
        public event Action<string>? OnStatusMessage;
        public event Action<string, int, string, int, int>? OnConnection;
        public event Action<int, int, int>? OnStats;
        public event Action<int, string>? OnDisconnect;
        public event Action<int, string, string, string, int, byte[]>? OnIntercept;

        public bool IsLoaded => _dllLoaded;
        public bool IsProxyRunning => _proxyRunning;        public DllManager(
            Action<string, string, string, int, string, string> logCallback,
            Action<string> statusCallback,
            Action<string, int, string, int, int> connectionCallback,
            Action<int, int, int> statsCallback,
            Action<int, string> disconnectCallback,
            Action<int, string, string, string, int, byte[]> interceptCallback)
        {
            // Store references to the callback methods to prevent garbage collection
            _logCallback = (timestamp, srcIp, dstIp, dstPort, msgType, data) =>
                OnLogMessage?.Invoke(timestamp, srcIp, dstIp, dstPort, msgType, data);

            _statusCallback = (message) =>
                OnStatusMessage?.Invoke(message);

            _connectionCallback = (clientIp, clientPort, targetHost, targetPort, connectionId) =>
                OnConnection?.Invoke(clientIp, clientPort, targetHost, targetPort, connectionId);

            _statsCallback = (totalConnections, activeConnections, totalBytesTransferred) =>
                OnStats?.Invoke(totalConnections, activeConnections, totalBytesTransferred);            _disconnectCallback = (connectionId, reason) =>
                OnDisconnect?.Invoke(connectionId, reason);

            _interceptCallback = (connectionId, direction, srcIp, dstIp, dstPort, dataPtr, dataLength) =>
            {
                // Convert IntPtr to byte array
                byte[] data = new byte[dataLength];
                if (dataPtr != IntPtr.Zero && dataLength > 0)
                {
                    System.Runtime.InteropServices.Marshal.Copy(dataPtr, data, 0, dataLength);
                }
                OnIntercept?.Invoke(connectionId, direction, srcIp, dstIp, dstPort, data);
            };

            // Register events
            OnLogMessage += logCallback;
            OnStatusMessage += statusCallback;
            OnConnection += connectionCallback;
            OnStats += statsCallback;
            OnDisconnect += disconnectCallback;
            OnIntercept += interceptCallback;
        }

        public async Task<(bool success, string message)> LoadDllAsync()
        {
            return await Task.Run(() =>
            {                try
                {
                    string? dllPath = FindDllPath();
                    if (dllPath == null)
                    {
                        return (false, "Could not find Intercept.dll");
                    }

                    // Add directory for loading dependencies
                    string? dllDirectory = Path.GetDirectoryName(dllPath);
                    if (dllDirectory != null)
                    {
                        NativeMethods.AddDllDirectory(dllDirectory);
                    }

                    // Load the DLL explicitly
                    IntPtr hModule = NativeMethods.LoadLibrary(dllPath);
                    if (hModule == IntPtr.Zero)
                    {
                        int error = Marshal.GetLastWin32Error();
                        return (false, $"Failed to load DLL at {dllPath}. Error code: {error}");
                    }

                    // Set callbacks
                    NativeMethods.set_log_callback(_logCallback);
                    NativeMethods.set_status_callback(_statusCallback);
                    NativeMethods.set_connection_callback(_connectionCallback);
                    NativeMethods.set_stats_callback(_statsCallback);
                    NativeMethods.set_disconnect_callback(_disconnectCallback);
                    NativeMethods.set_intercept_callback(_interceptCallback);

                    _dllLoaded = true;
                    return (true, $"DLL loaded successfully from {dllPath}");
                }
                catch (Exception ex)
                {
                    return (false, $"Failed to load DLL: {ex.Message}");
                }
            });
        }    // Helper to find DLL in possible locations
        private string? FindDllPath()
        {
            // Try possible paths
            string[] possiblePaths = new[]
            {
                @"d:\Windows TLS\build\Debug\Intercept.dll",
                @"d:\Windows TLS\build\Release\Intercept.dll",
                @"d:\Windows TLS\build\RelWithDebInfo\Intercept.dll",
                @"d:\Windows TLS\build\MinSizeRel\Intercept.dll",
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Intercept.dll"),
                "Intercept.dll"
            };

            foreach (string path in possiblePaths)
            {
                if (File.Exists(path))
                {
                    Console.WriteLine($"Found DLL at: {path}");
                    return path;
                }
            }

            Console.WriteLine("DLL not found in any of the expected locations");
            return null;
        }// Public proxy API methods
        public bool StartProxy()
        {
            lock (_proxyStateLock)
            {
                if (!_dllLoaded || _proxyRunning)
                    return false;

                try
                {
                    if (NativeMethods.start_proxy())
                    {
                        _proxyRunning = true;
                        return true;
                    }
                    return false;
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }

        public void StopProxy()
        {
            lock (_proxyStateLock)
            {
                if (!_dllLoaded || !_proxyRunning)
                    return;

                try
                {
                    NativeMethods.stop_proxy();
                }
                catch (Exception)
                {
                    // Ignore exceptions during shutdown
                }
                finally
                {
                    _proxyRunning = false;
                }
            }
        }        public bool SetConfig(string bindAddress, int port, string logFile, bool verboseMode) =>
            _dllLoaded && NativeMethods.set_config(bindAddress, port, logFile, verboseMode ? 1 : 0);



        public int GetSystemIps(StringBuilder buffer, int bufferSize) =>
            _dllLoaded ? NativeMethods.get_system_ips(buffer, bufferSize) : 0;        public bool GetProxyConfig(StringBuilder bindAddress, ref int port, StringBuilder logFile, ref int verboseMode) =>
            _dllLoaded && NativeMethods.get_proxy_config(bindAddress, ref port, logFile, ref verboseMode);

        public bool GetProxyStats(ref int connections, ref int bytes) =>
            _dllLoaded && NativeMethods.get_proxy_stats(ref connections, ref bytes);        // Interception control methods
        public void SetInterceptEnabled(bool enabled)
        {
            if (_dllLoaded)
            {
                NativeMethods.set_intercept_enabled(enabled);
            }
        }

        public void SetInterceptDirection(int direction)
        {
            if (_dllLoaded)
            {
                NativeMethods.set_intercept_direction(direction);
            }
        }        public void RespondToIntercept(int connectionId, int action, byte[]? modifiedData = null)
        {
            if (_dllLoaded)
            {
                int dataLength = modifiedData?.Length ?? 0;
                if (modifiedData != null && dataLength > 0)
                {
                    NativeMethods.respond_to_intercept(connectionId, action, modifiedData, dataLength);
                }
                else
                {
                    // Pass null and zero length when no modified data is available
                    NativeMethods.respond_to_intercept(connectionId, action, null, 0);
                }
            }
        }        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed state (managed objects)
                    OnLogMessage = null;
                    OnStatusMessage = null;
                    OnConnection = null;
                    OnStats = null;
                    OnDisconnect = null;
                    OnIntercept = null;
                }

                // Free unmanaged resources (unmanaged objects) and override finalizer
                // Stop proxy if it's still running during disposal
                if (_dllLoaded && _proxyRunning)
                {
                    try
                    {
                        StopProxy();
                    }
                    catch (Exception)
                    {
                        // Ignore exceptions during disposal
                    }
                }

                _disposed = true;
            }
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
