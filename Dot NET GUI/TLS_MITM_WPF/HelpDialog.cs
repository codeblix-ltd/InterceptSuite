using System.Windows;
using System.Windows.Controls;

namespace TLS_MITM_WPF
{
    public partial class MainWindow
    {
        // Add a help button click handler
        private void ShowHelpDialog_Click(object sender, RoutedEventArgs e)
        {
            // Create a new window for help
            Window helpWindow = new Window
            {
                Title = "TLS MITM Proxy Help",
                Width = 600,
                Height = 500,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this
            };

            // Create a scrollviewer for content
            ScrollViewer scrollViewer = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto
            };

            // Create a stackpanel for content
            StackPanel contentPanel = new StackPanel
            {
                Margin = new Thickness(15)
            };

            // Add help content
            contentPanel.Children.Add(new TextBlock
            {
                Text = "TLS MITM Proxy Help",
                FontSize = 20,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 15)
            });

            // Basic Usage Section
            contentPanel.Children.Add(new TextBlock
            {
                Text = "Basic Usage",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 10, 0, 5)
            });

            contentPanel.Children.Add(new TextBlock
            {
                Text = "1. Select a binding address from the dropdown (typically 127.0.0.1 for local use)\n" +
                      "2. Enter a port number (default is 4444)\n" +
                      "3. Click 'Apply Configuration'\n" +
                      "4. Click 'Start Proxy'\n" +
                      "5. Configure your browser to use the proxy as described below",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(10, 0, 0, 10)
            });

            // Browser Configuration Section
            contentPanel.Children.Add(new TextBlock
            {
                Text = "Browser Configuration",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 10, 0, 5)
            });

            // Firefox Configuration
            contentPanel.Children.Add(new TextBlock
            {
                Text = "Firefox:",
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(10, 5, 0, 0)
            });

            contentPanel.Children.Add(new TextBlock
            {
                Text = "1. Go to Settings (≡ Menu → Settings)\n" +
                      "2. Scroll down to 'Network Settings' and click 'Settings...'\n" +
                      "3. Select 'Manual proxy configuration'\n" +
                      "4. Enter '127.0.0.1' in SOCKS Host field\n" +
                      "5. Enter '4444' (or your chosen port) in Port field\n" +
                      "6. Select 'SOCKS v5'\n" +
                      "7. IMPORTANT: Check 'Proxy DNS when using SOCKS v5'\n" +
                      "8. Click 'OK'",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(20, 0, 0, 10)
            });

            // Chrome Configuration
            contentPanel.Children.Add(new TextBlock
            {
                Text = "Chrome:",
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(10, 5, 0, 0)
            });

            contentPanel.Children.Add(new TextBlock
            {
                Text = "1. Go to Settings → Advanced → System\n" +
                      "2. Click 'Open your computer's proxy settings'\n" +
                      "3. In Windows settings, select 'Manual proxy setup'\n" +
                      "4. Toggle on 'Use a proxy server'\n" +
                      "5. Enter '127.0.0.1' for Address\n" +
                      "6. Enter '4444' (or your chosen port) for Port\n" +
                      "7. Click Save",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(20, 0, 0, 10)
            });

            // Troubleshooting Section
            contentPanel.Children.Add(new TextBlock
            {
                Text = "Troubleshooting",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 10, 0, 5)
            });

            contentPanel.Children.Add(new TextBlock
            {
                Text = "If HTTPS websites don't load:\n\n" +
                      "1. Make sure 'Proxy DNS when using SOCKS v5' is checked in Firefox\n" +
                      "2. For Chrome, launch it with this command line flag:\n" +
                      "   --host-resolver-rules=\"MAP * ~NOTFOUND , EXCLUDE localhost\"\n" +
                      "3. Check if port 4444 is not blocked by firewall\n" +
                      "4. Restart your browser after configuring the proxy\n" +
                      "5. Check the 'Proxy History' tab for connection attempts",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(10, 0, 0, 10)
            });

            // Set up the window content
            scrollViewer.Content = contentPanel;
            helpWindow.Content = scrollViewer;

            // Show the help window
            helpWindow.ShowDialog();
        }
    }
}
