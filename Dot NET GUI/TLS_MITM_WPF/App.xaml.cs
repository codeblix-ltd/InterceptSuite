using System.Configuration;
using System.Data;
using System.Windows;
using System.Runtime.InteropServices;
using System;
using Microsoft.Win32;

namespace TLS_MITM_WPF;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Enable dark mode for the title bar
        EnableDarkTitleBar();
    }

    private void EnableDarkTitleBar()
    {
        // Check if we're on Windows 10 or later where dark title bar is supported
        if (Environment.OSVersion.Version.Major >= 10)
        {
            // Set app theme to dark
            SetAppThemeToDark();
        }
    }

    private void SetAppThemeToDark()
    {
        try
        {
            // Set the app's theme registry key to dark
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", true))
            {
                if (key != null)
                {
                    // Set Apps to dark mode (0 = dark, 1 = light)
                    key.SetValue("AppsUseLightTheme", 0, RegistryValueKind.DWord);

                    // For completeness, also set system to dark mode
                    key.SetValue("SystemUsesLightTheme", 0, RegistryValueKind.DWord);
                }
            }

            // Use DwmSetWindowAttribute if available (Windows 10 1809 or later)
            if (DwmSetWindowAttribute != null)
            {
                // This will be called for each window when MainWindow loads
                foreach (Window window in Windows)
                {
                    if (window.IsLoaded)
                    {
                        ApplyDarkTitleBarToWindow(window);
                    }
                    else
                    {
                        window.Loaded += Window_Loaded;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            // Log exception if needed
            Console.WriteLine($"Error setting dark theme: {ex.Message}");
        }
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is Window window)
        {
            ApplyDarkTitleBarToWindow(window);
            window.Loaded -= Window_Loaded;
        }
    }

    private void ApplyDarkTitleBarToWindow(Window window)
    {
        try
        {
            // Get the window handle
            var windowInteropHelper = new System.Windows.Interop.WindowInteropHelper(window);
            var hwnd = windowInteropHelper.Handle;

            // Set the window attribute to use dark mode
            if (hwnd != IntPtr.Zero && DwmSetWindowAttribute != null)
            {
                int darkMode = 1; // 1 = dark mode
                DwmSetWindowAttribute(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, ref darkMode, sizeof(int));
            }
        }
        catch (Exception ex)
        {
            // Log exception if needed
            Console.WriteLine($"Error applying dark title bar: {ex.Message}");
        }
    }

    // Windows API for setting window attributes
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);
}

