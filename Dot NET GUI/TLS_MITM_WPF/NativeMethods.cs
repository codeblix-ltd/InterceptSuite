// filepath: d:\Windows TLS\Dot NET GUI\TLS_MITM_WPF\NativeMethods.cs
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace TLS_MITM_WPF
{
    /// <summary>
    /// This class centralizes all P/Invoke declarations for better organization and maintenance
    /// </summary>
    internal static class NativeMethods
    {
        // DLL P/Invoke declarations for tls_proxy.dll
        [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool start_proxy();

        [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void stop_proxy();

        [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool set_config(
            [MarshalAs(UnmanagedType.LPStr)] string bind_addr,
            int port,
            [MarshalAs(UnmanagedType.LPStr)] string log_file);

        [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int get_system_ips(
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder buffer,
            int buffer_size);

        [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool get_proxy_config(
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder bind_addr,
            ref int port,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder log_file);

        [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool get_proxy_stats(
            ref int connections,
            ref int bytes_transferred);

        // Callback function registration
        [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void set_log_callback(LogCallbackDelegate callback);

        [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void set_status_callback(StatusCallbackDelegate callback);

        [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void set_connection_callback(ConnectionCallbackDelegate callback);

        [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void set_stats_callback(StatsCallbackDelegate callback);

        [DllImport("tls_proxy.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void set_disconnect_callback(DisconnectCallbackDelegate callback);

        // Win32 API for DLL loading
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool AddDllDirectory(string lpPathName);

        // Callback function delegates
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void LogCallbackDelegate(
            [MarshalAs(UnmanagedType.LPStr)] string timestamp,
            [MarshalAs(UnmanagedType.LPStr)] string src_ip,
            [MarshalAs(UnmanagedType.LPStr)] string dst_ip,
            int dst_port,
            [MarshalAs(UnmanagedType.LPStr)] string message_type,
            [MarshalAs(UnmanagedType.LPStr)] string data);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void StatusCallbackDelegate([MarshalAs(UnmanagedType.LPStr)] string message);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void ConnectionCallbackDelegate(
            [MarshalAs(UnmanagedType.LPStr)] string client_ip,
            int client_port,
            [MarshalAs(UnmanagedType.LPStr)] string target_host,
            int target_port,
            int connection_id);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void StatsCallbackDelegate(
            int total_connections,
            int active_connections,
            int total_bytes_transferred);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void DisconnectCallbackDelegate(
            int connection_id,
            [MarshalAs(UnmanagedType.LPStr)] string reason);
    }
}
