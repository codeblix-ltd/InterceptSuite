using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace TLS_MITM_WPF
{
    // Enhanced network interfaces handling
    public partial class MainWindow
    {
        // Modified method to update network interfaces list
        private void UpdateNetworkInterfaces()
        {
            // Keep track of the old selected item
            object? oldSelectedItem = BindAddressComboBox.SelectedItem;

            if (!_proxyDllLoaded)
            {
                // We already have an implementation for this in the original code
                // Just call the existing method
                RefreshNetworkInterfaces();
                return;
            }

            try
            {
                // Use DLL API to get IP addresses
                StringBuilder buffer = new StringBuilder(2048);
                int result = get_system_ips(buffer, buffer.Capacity);

                if (result > 0)
                {
                    string ipList = buffer.ToString();
                    AddStatusMessage($"[DEBUG] Raw IP list from DLL: '{ipList}'");

                    // Split by common separators (comma OR semicolon)
                    // Use RemoveEmptyEntries to handle any potential double separators
                    string[] ipAddresses = ipList.Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);

                    List<string> uniqueIps = new List<string>();

                    // Clear existing list
                    BindAddressComboBox.Items.Clear();

                    // Add each IP, ensuring we don't add duplicates
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

                    // Reselect the previously selected item if possible
                    if (oldSelectedItem != null && BindAddressComboBox.Items.Contains(oldSelectedItem))
                    {
                        BindAddressComboBox.SelectedItem = oldSelectedItem;
                    }
                    else if (BindAddressComboBox.Items.Count > 0)
                    {
                        BindAddressComboBox.SelectedIndex = 0;
                    }

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
                AddStatusMessage($"[DEBUG] Exception details: {ex}");
                RefreshNetworkInterfaces_Fallback();
            }
        }
    }
}
