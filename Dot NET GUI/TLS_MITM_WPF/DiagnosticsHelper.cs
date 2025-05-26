// filepath: d:\Windows TLS\Dot NET GUI\TLS_MITM_WPF\DiagnosticsHelper.cs
using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace TLS_MITM_WPF
{
    /// <summary>
    /// Helper class for diagnostics and network utility functions
    /// </summary>
    public static class DiagnosticsHelper
    {
        /// <summary>
        /// Checks if a port is available on the specified IP address
        /// </summary>
        /// <param name="ipAddress">IP address to check</param>
        /// <param name="port">Port to check</param>
        /// <returns>True if the port is available, false otherwise</returns>
        public static bool IsPortAvailable(string ipAddress, int port)
        {
            try
            {
                // Don't use System.Net.NetworkInformation.IPGlobalProperties for port checking
                // as it only checks local machine ports. For specific IP bindings, we need to attempt binding.
                using Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                socket.Bind(new IPEndPoint(IPAddress.Parse(ipAddress), port));
                socket.Close();
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Gets the network interface information for the specified IP address
        /// </summary>
        /// <param name="ipAddress">IP address to get information for</param>
        /// <returns>A string containing information about the network interface</returns>
        public static string GetNetworkInterfaceInfo(string ipAddress)
        {
            StringBuilder info = new StringBuilder();

            try
            {
                // Check if IP is loopback
                if (ipAddress == "127.0.0.1" || ipAddress == "localhost")
                {
                    info.AppendLine("Interface: Loopback");
                    info.AppendLine("Status: Always available");
                    return info.ToString();
                }

                // Find the network interface with the specified IP
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up)
                    {
                        foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                        {
                            if (ip.Address.AddressFamily == AddressFamily.InterNetwork &&
                                ip.Address.ToString() == ipAddress)
                            {
                                info.AppendLine($"Interface: {ni.Name}");
                                info.AppendLine($"Description: {ni.Description}");
                                info.AppendLine($"Type: {ni.NetworkInterfaceType}");
                                info.AppendLine($"Status: {ni.OperationalStatus}");
                                info.AppendLine($"Speed: {ni.Speed / 1000000} Mbps");
                                return info.ToString();
                            }
                        }
                    }
                }

                // If we got here, we couldn't find the interface
                info.AppendLine("Could not find network interface for this IP");
            }
            catch (Exception ex)
            {
                info.AppendLine($"Error retrieving network interface info: {ex.Message}");
            }

            return info.ToString();
        }

        /// <summary>
        /// Generates a diagnostic report for the proxy configuration
        /// </summary>
        /// <param name="bindAddress">The binding address</param>
        /// <param name="port">The port number</param>
        /// <returns>A diagnostic report string</returns>
        public static string GenerateDiagnosticReport(string bindAddress, int port)
        {
            StringBuilder report = new StringBuilder();
            report.AppendLine("[DIAGNOSTIC] Proxy Configuration Report:");

            // Check binding address
            report.AppendLine($"[DIAGNOSTIC] Binding address: {bindAddress}");
            report.AppendLine($"[DIAGNOSTIC] Port: {port}");

            // Check port availability
            bool portAvailable = IsPortAvailable(bindAddress, port);
            report.AppendLine($"[DIAGNOSTIC] Port {port} on {bindAddress} is {(portAvailable ? "available" : "already in use")}");

            // Get network interface info
            report.AppendLine("[DIAGNOSTIC] Network interface information:");
            report.AppendLine(GetNetworkInterfaceInfo(bindAddress));

            return report.ToString();
        }
    }
}
