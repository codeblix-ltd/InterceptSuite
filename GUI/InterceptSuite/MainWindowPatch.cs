
using System;
using System.Windows;
using System.Windows.Controls;
using System.Text;

namespace InterceptSuite
{
    // This is a partial class containing patched methods
    public partial class MainWindow
    {
        // This is the original event handler in MainWindow.xaml with enhanced logic
        private void RefreshInterfaces_Click(object sender, RoutedEventArgs e)
        {
            // Use the shared logic for refreshing network interfaces
            RefreshNetworkInterfaces();

            // Add debug information after refresh
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
