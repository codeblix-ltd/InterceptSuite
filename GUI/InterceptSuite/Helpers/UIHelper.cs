using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace InterceptSuite.Helpers
{
    /// <summary>
    /// Helper class for common UI operations
    /// Reduces code duplication across UI interactions
    /// </summary>
    public static class UIHelper
    {
        /// <summary>
        /// Shows an error message box with consistent styling
        /// </summary>
        /// <param name="message">Error message to display</param>
        /// <param name="title">Window title (defaults to "Error")</param>
        public static void ShowError(string message, string title = "Error")
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error);
        }

        /// <summary>
        /// Shows an information message box with consistent styling
        /// </summary>
        /// <param name="message">Information message to display</param>
        /// <param name="title">Window title (defaults to "Information")</param>
        public static void ShowInfo(string message, string title = "Information")
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);
        }

        /// <summary>
        /// Safely invokes an action on the UI thread
        /// </summary>
        /// <param name="dispatcher">The dispatcher to use</param>
        /// <param name="action">Action to invoke</param>
        public static void SafeInvoke(Dispatcher dispatcher, Action action)
        {
            try
            {
                if (dispatcher.CheckAccess())
                {
                    action();
                }
                else
                {
                    dispatcher.Invoke(action);
                }
            }
            catch (Exception ex)
            {
                // Log or handle the exception as needed
                System.Diagnostics.Debug.WriteLine($"UI operation failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Auto-scrolls a ListView to the last item if it has items
        /// </summary>
        /// <param name="listView">ListView to scroll</param>
        public static void AutoScrollToEnd(ListView listView)
        {
            if (listView?.Items.Count > 0)
            {
                listView.ScrollIntoView(listView.Items[listView.Items.Count - 1]);
            }
        }

        /// <summary>
        /// Sets the visibility of a panel and manages navigation button states
        /// </summary>
        /// <param name="targetPanel">Panel to show</param>
        /// <param name="targetButton">Button to disable (mark as selected)</param>
        /// <param name="allPanels">All panels to hide</param>
        /// <param name="allButtons">All buttons to enable</param>
        public static void NavigateToPanel(FrameworkElement targetPanel, Button targetButton,
            FrameworkElement[] allPanels, Button[] allButtons)
        {
            // Enable all buttons
            foreach (var button in allButtons)
            {
                button.IsEnabled = true;
            }

            // Hide all panels
            foreach (var panel in allPanels)
            {
                panel.Visibility = Visibility.Collapsed;
            }

            // Show target panel and disable its button
            targetPanel.Visibility = Visibility.Visible;
            targetButton.IsEnabled = false;
        }
    }
}
