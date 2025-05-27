// filepath: d:\Windows TLS\Dot NET GUI\TLS_MITM_WPF\DllManager.cs
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace TLS_MITM_WPF
{    /// <summary>
    /// Manages loading, initialization, and cleanup of native DLLs
    /// </summary>
    public class DllManager : IDisposable
    {
        private bool _disposed = false;
        private bool _dllLoaded = false;
        private bool _proxyRunning = false;
        private readonly object _proxyStateLock = new object();
        private readonly NativeMethods.LogCallbackDelegate _logCallback;
        private readonly NativeMethods.StatusCallbackDelegate _statusCallback;
        private readonly NativeMethods.ConnectionCallbackDelegate _connectionCallback;
        private readonly NativeMethods.StatsCallbackDelegate _statsCallback;
        private readonly NativeMethods.DisconnectCallbackDelegate _disconnectCallback;

        // Event handlers for callbacks
        public event Action<string, string, string, int, string, string>? OnLogMessage;
        public event Action<string>? OnStatusMessage;
        public event Action<string, int, string, int, int>? OnConnection;
        public event Action<int, int, int>? OnStats;
        public event Action<int, string>? OnDisconnect;

        public bool IsLoaded => _dllLoaded;
        public bool IsProxyRunning => _proxyRunning;

        public DllManager(
            Action<string, string, string, int, string, string> logCallback,
            Action<string> statusCallback,
            Action<string, int, string, int, int> connectionCallback,
            Action<int, int, int> statsCallback,
            Action<int, string> disconnectCallback)
        {
            // Store references to the callback methods to prevent garbage collection
            _logCallback = (timestamp, srcIp, dstIp, dstPort, msgType, data) =>
                OnLogMessage?.Invoke(timestamp, srcIp, dstIp, dstPort, msgType, data);

            _statusCallback = (message) =>
                OnStatusMessage?.Invoke(message);

            _connectionCallback = (clientIp, clientPort, targetHost, targetPort, connectionId) =>
                OnConnection?.Invoke(clientIp, clientPort, targetHost, targetPort, connectionId);

            _statsCallback = (totalConnections, activeConnections, totalBytesTransferred) =>
                OnStats?.Invoke(totalConnections, activeConnections, totalBytesTransferred);

            _disconnectCallback = (connectionId, reason) =>
                OnDisconnect?.Invoke(connectionId, reason);

            // Register events
            OnLogMessage += logCallback;
            OnStatusMessage += statusCallback;
            OnConnection += connectionCallback;
            OnStats += statsCallback;
            OnDisconnect += disconnectCallback;
        }

        public async Task<(bool success, string message)> LoadDllAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    string? dllPath = FindDllPath();
                    if (dllPath == null)
                    {
                        return (false, "Could not find tls_proxy.dll");
                    }

                    // Add directory for loading dependencies
                    string? dllDirectory = Path.GetDirectoryName(dllPath);
                    if (dllDirectory != null)
                    {
                        NativeMethods.AddDllDirectory(dllDirectory);
                    }

                    // Set callbacks
                    NativeMethods.set_log_callback(_logCallback);
                    NativeMethods.set_status_callback(_statusCallback);
                    NativeMethods.set_connection_callback(_connectionCallback);
                    NativeMethods.set_stats_callback(_statsCallback);
                    NativeMethods.set_disconnect_callback(_disconnectCallback);

                    _dllLoaded = true;
                    return (true, "DLL loaded successfully");
                }
                catch (Exception ex)
                {
                    return (false, $"Failed to load DLL: {ex.Message}");
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
        }        // Public proxy API methods
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
            _dllLoaded && NativeMethods.get_proxy_stats(ref connections, ref bytes);        protected virtual void Dispose(bool disposing)
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
