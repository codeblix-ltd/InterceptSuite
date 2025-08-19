using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Data.Core;
using Avalonia.Data.Core.Plugins;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Markup.Xaml;
using InterceptSuite.ViewModels;
using InterceptSuite.Views;
using System;
using System.Threading;

namespace InterceptSuite;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // Avoid duplicate validations from both Avalonia and the CommunityToolkit.
            // More info: https://docs.avaloniaui.net/docs/guides/development-guides/data-validation#manage-validationplugins
            DisableAvaloniaDataAnnotationValidation();

            // Add exit handler to ensure proper cleanup
            desktop.Exit += OnApplicationExit;

            // Show project startup dialog as the main window initially
            var projectStartupWindow = new ProjectStartupWindow();
            desktop.MainWindow = projectStartupWindow;

            // Handle when the startup dialog is closed
            projectStartupWindow.Closed += (sender, e) =>
            {
                if (projectStartupWindow.DataContext is ProjectStartupViewModel viewModel && viewModel.DialogResult)
                {
                    // Create and show the main application window
                    var mainViewModel = new MainWindowViewModel();

                    // Set project information if available
                    if (!string.IsNullOrEmpty(viewModel.SelectedProjectPath))
                    {
                        // Handle project file loading here when implemented
                        // For now, just continue normally
                    }

                    var mainWindow = new MainWindow
                    {
                        DataContext = mainViewModel,
                    };

                    desktop.MainWindow = mainWindow;
                    mainWindow.Show();
                }
                else
                {
                    // User cancelled, exit application
                    desktop.Shutdown();
                }
            };
        }

        base.OnFrameworkInitializationCompleted();
    }

    private void DisableAvaloniaDataAnnotationValidation()
    {
        // Get an array of plugins to remove
        var dataValidationPluginsToRemove =
            BindingPlugins.DataValidators.OfType<DataAnnotationsValidationPlugin>().ToArray();

        // remove each entry found
        foreach (var plugin in dataValidationPluginsToRemove)
        {
            BindingPlugins.DataValidators.Remove(plugin);
        }
    }

    private void OnApplicationExit(object? sender, ControlledApplicationLifetimeExitEventArgs e)
    {
        // Ensure proper cleanup when application exits
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var mainWindow = desktop.MainWindow;
            if (mainWindow?.DataContext is MainWindowViewModel mainVm)
            {
                // Force disposal of the main view model to cleanup Python.NET
                mainVm.Dispose();
            }
        }

        // Give Python.NET some time to cleanup, then force exit if needed
        Task.Run(async () =>
        {
            await Task.Delay(2000); // Wait 2 seconds for cleanup

            // Force exit if Python.NET doesn't shutdown cleanly
            Environment.Exit(0);
        });
    }

     private async void AboutMenuItem_OnClick(object? sender, EventArgs e)
    {
        try
        {
            var aboutDialog = new AboutDialog();
            
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop &&
                desktop.MainWindow != null)
            {
                await aboutDialog.ShowDialog(desktop.MainWindow);
            }
        }
        catch (Exception ex)
        {
            // Log error or handle gracefully
            Console.WriteLine($"Error showing about dialog: {ex.Message}");
        }
    }
}