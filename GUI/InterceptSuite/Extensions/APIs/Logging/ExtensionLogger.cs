using System;
using Avalonia.Threading;
using InterceptSuite.ViewModels;

namespace InterceptSuite.Extensions.APIs.Logging;

public static class ExtensionLogger
{
    private static ExtensionsViewModel? _extensionsViewModel;

    public static void Initialize(ExtensionsViewModel extensionsViewModel)
    {
        _extensionsViewModel = extensionsViewModel;
    }

    public static void Log(string message)
    {
        if (_extensionsViewModel == null)
            return;

        // Ensure UI updates happen on the UI thread immediately
        Dispatcher.UIThread.InvokeAsync(() =>
        {
            _extensionsViewModel.AddConsoleOutput(message);
        }, DispatcherPriority.Send); // Use Send for immediate execution
    }
}
