// Filename: D:\Windows TLS\Dot NET GUI\TLS_MITM_WPF\MainWindowPatch.cs

using System;
using System.Windows;
using System.Windows.Controls;

namespace TLS_MITM_WPF
{
    // This is a partial class containing patched methods
    public partial class MainWindow
    {
        // This is the original event handler in MainWindow.xaml with additional logic
        private void RefreshInterfaces_Click(object sender, RoutedEventArgs e)
        {
            // Call our enhanced method directly
            UpdateNetworkInterfaces();

            // Add debug information
            RefreshInterfacesEnhanced(sender, e);
        }
    }
}
