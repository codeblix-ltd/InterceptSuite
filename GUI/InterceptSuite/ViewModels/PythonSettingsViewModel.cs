using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using InterceptSuite.Extensions;
using InterceptSuite.Extensions.APIs.Logging;

namespace InterceptSuite.ViewModels;

public partial class PythonSettingsViewModel : ViewModelBase
{
    [ObservableProperty]
    private string pythonDirectory = string.Empty;

    [ObservableProperty]
    private string statusMessage = "No Python directory selected";

    [ObservableProperty]
    private bool isValid;

    public ObservableCollection<string> ValidationMessages { get; } = new();

    public PythonSettingsViewModel()
    {
        LoadSettings();
    }

    private void LoadSettings()
    {
        try
        {
            var settings = PythonSettings.LoadAsync().Result;
            PythonDirectory = settings.PythonDirectory ?? string.Empty;

            if (!string.IsNullOrEmpty(PythonDirectory))
            {
                ValidateConfiguration();
            }
            else
            {
                StatusMessage = "No Python directory selected";
                IsValid = false;
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to load settings: {ex.Message}";
            ExtensionLogger.Log($"Failed to load Python settings: {ex}");
        }
    }

    [RelayCommand]
    private async Task BrowsePythonDirectory()
    {
        try
        {
            var topLevel = TopLevel.GetTopLevel((Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow);
            if (topLevel == null) return;

            var result = await topLevel.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
            {
                Title = "Select Python Directory",
                AllowMultiple = false
            });

            if (result.Count > 0)
            {
                PythonDirectory = result[0].Path.LocalPath;
                StatusMessage = "Detecting Python installation...";

                // Use the new method that detects and saves paths automatically
                var settings = await PythonSettings.SetDirectoryAndDetectAsync(PythonDirectory);

                // Update our view with the detected info
                StatusMessage = "Python detection completed";
                ValidateConfiguration();
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to browse directory: {ex.Message}";
        }
    }

    private void ValidateConfiguration()
    {
        ValidationMessages.Clear();

        try
        {
            if (string.IsNullOrEmpty(PythonDirectory))
            {
                IsValid = false;
                StatusMessage = "No Python directory selected";
                ValidationMessages.Add("Please select a Python directory");
                return;
            }

            // Load current settings to get saved paths
            var settings = PythonSettings.LoadAsync().Result;

            // Use the validation method from PythonSettings
            var (success, message) = settings.ValidateConfiguration();

            IsValid = success;
            StatusMessage = message;

            if (success)
            {
                // Show details of detected/saved Python installation
                if (!string.IsNullOrEmpty(settings.PythonExecutable))
                {
                    ValidationMessages.Add($"✓ Python executable: {Path.GetFileName(settings.PythonExecutable)}");
                }
                if (!string.IsNullOrEmpty(settings.PythonLibrary))
                {
                    ValidationMessages.Add($"✓ Python library: {Path.GetFileName(settings.PythonLibrary)}");
                }
                ValidationMessages.Add("Extensions can now use this Python installation");
            }
            else
            {
                ValidationMessages.Add(message);
                if (message.Contains("no longer exist"))
                {
                    ValidationMessages.Add("Try selecting the Python directory again to re-detect files");
                }
            }
        }
        catch (Exception ex)
        {
            IsValid = false;
            StatusMessage = $"Validation failed: {ex.Message}";
            ValidationMessages.Add($"Validation error: {ex.Message}");
        }
    }
}
