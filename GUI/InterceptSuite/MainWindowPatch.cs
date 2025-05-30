
using System;
using System.Windows;
using System.Windows.Controls;
using System.Text;

namespace InterceptSuite
{
    public partial class MainWindow
    {
        private void RefreshInterfaces_Click(object sender, RoutedEventArgs e)
        {
            RefreshNetworkInterfaces();

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
