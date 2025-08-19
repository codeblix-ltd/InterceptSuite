using Avalonia;
using System;
using System.IO;
using System.Runtime.InteropServices;
using InterceptSuite.NativeInterop;

namespace InterceptSuite;

sealed class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var resourcePath = Path.Combine(AppContext.BaseDirectory, "resource");
            if (Directory.Exists(resourcePath))
            {
                var currentPath = Environment.GetEnvironmentVariable("PATH") ?? "";
                Environment.SetEnvironmentVariable("PATH", currentPath + ";" + resourcePath);
            }
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            ResourceManager.TryPreloadNativeLibrary(out _);
        }

        BuildAvaloniaApp()
            .StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont();
}
