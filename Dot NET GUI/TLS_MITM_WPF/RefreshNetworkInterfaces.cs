using System;
using System.Text;
using System.Windows;

namespace TLS_MITM_WPF
{
    public partial class MainWindow
    {
        // Enhanced version of RefreshNetworkInterfaces method
        private void RefreshNetworkInterfaces_Enhanced()
        {
            if (!_proxyDllLoaded)
            {
                // We already have a fallback for non-DLL case so just call existing method
                RefreshNetworkInterfaces();
                return;
            }

            try
            {
                // Use DLL API
                StringBuilder buffer = new StringBuilder(2048);
                int result = get_system_ips(buffer, buffer.Capacity);

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

                    // If we didn't get any valid IPs, add loopback
                    if (BindAddressComboBox.Items.Count == 0)
                    {
                        BindAddressComboBox.Items.Add("127.0.0.1");
                        AddStatusMessage("[DEBUG] No valid IPs found, added loopback");
                    }

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
                AddStatusMessage($"[DEBUG] Exception details: {ex}");
                RefreshNetworkInterfaces_Fallback();
            }
        }

        // Enhanced refresh interfaces button click handler
        private void RefreshInterfaces_Click_Enhanced(object sender, RoutedEventArgs e)
        {
            RefreshNetworkInterfaces_Enhanced();

            // Add debug information
            StringBuilder debugInfo = new StringBuilder();
            debugInfo.AppendLine("[SYSTEM] Network interfaces refreshed");
            debugInfo.AppendLine($"[DEBUG] Found {BindAddressComboBox.Items.Count} interfaces:");

            foreach (var item in BindAddressComboBox.Items)
            {
                debugInfo.AppendLine($"[DEBUG] - {item}");
            }

            AddStatusMessage(debugInfo.ToString());
        }
    }
}
