using System;
using System.Text;
using System.Windows;

namespace TLS_MITM_WPF
{
    // Enhanced refresh button handler
    public partial class MainWindow
    {
        // This method will be called from the original RefreshInterfaces_Click
        private void RefreshInterfacesEnhanced(object sender, RoutedEventArgs e)
        {
            // Use our enhanced update method
            UpdateNetworkInterfaces();

            // Add detailed debug information
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
