using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using InterceptSuite.Extensions;
using InterceptSuite.Extensions.APIs.Logging;
using InterceptSuite.Services;

namespace InterceptSuite.ViewModels;

public partial class ExtensionsViewModel : ObservableObject, IDisposable
{
    [ObservableProperty]
    private ObservableCollection<ExtensionItem> _extensions = new();

    [ObservableProperty]
    private ObservableCollection<string> _consoleOutput = new();

    [ObservableProperty]
    private string? _selectedOutput;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private ExtensionItem? _selectedExtension;

    public string ExtensionOutput => string.Join("\n", ConsoleOutput);

    private readonly ExtensionConfigManager _configManager = new();
    private readonly PythonExtensionLoader _pythonLoader;
    private readonly MainWindowViewModel? _mainWindowViewModel;
    private bool _disposed = false;
    private bool _isInitialized = false;
    private readonly object _initLock = new();

    public ExtensionsViewModel(MainWindowViewModel? mainWindowViewModel = null)
    {
        _mainWindowViewModel = mainWindowViewModel;
        _pythonLoader = new PythonExtensionLoader(mainWindowViewModel);

        ExtensionLogger.Initialize(this);
    }

    public async Task EnsureInitializedAsync()
    {
        if (_isInitialized) return;

        lock (_initLock)
        {
            if (_isInitialized) return;
            _isInitialized = true;
        }

        await LoadExtensionsAsync();
    }

    [RelayCommand]
    private async Task LoadExtension()
    {
        try
        {
            IsLoading = true;
            await EnsureInitializedAsync();

            var mainWindow = App.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop ? desktop.MainWindow : null;

            if (mainWindow?.StorageProvider == null)
            {
                LogToMainTab("Error: Storage provider not available");
                return;
            }

            var files = await mainWindow.StorageProvider.OpenFilePickerAsync(new Avalonia.Platform.Storage.FilePickerOpenOptions
            {
                Title = "Select Python Extension",
                AllowMultiple = false,
                FileTypeFilter = new[] { new Avalonia.Platform.Storage.FilePickerFileType("Python Files") { Patterns = new[] { "*.py" } } }
            });

            if (files?.Count > 0)
            {
                var filePath = files[0].Path.LocalPath;
                if (Extensions.Any(e => e.FilePath.Equals(filePath, StringComparison.OrdinalIgnoreCase)))
                {
                    LogToMainTab($"Extension '{Path.GetFileName(filePath)}' is already added");
                    return;
                }

                var extensionInstance = await _pythonLoader.LoadExtensionAsync(filePath);
                if (extensionInstance != null)
                {
                    var extension = new ExtensionItem
                    {
                        Id = Guid.NewGuid().ToString(),
                        Name = extensionInstance.Name,
                        Version = extensionInstance.Version,
                        FilePath = filePath,
                        IsEnabled = true,
                        IsLoaded = true,
                        LoadedAt = DateTime.Now,
                        PythonInstance = extensionInstance
                    };

                    Extensions.Add(extension);
                    await _configManager.AddExtensionAsync(filePath, true);
                }
            }
        }
        catch (Exception ex)
        {
            LogToMainTab($"Error loading extension: {ex.Message}");
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    private async Task RemoveExtension(ExtensionItem? extension)
    {
        if (extension == null) return;

        try
        {
            if (extension.IsLoaded)
            {
                await UnloadExtensionAsync(extension);
            }

            Extensions.Remove(extension);
            await _configManager.RemoveExtensionAsync(extension.FilePath);
            LogToMainTab($"Extension '{extension.Name}' removed");
        }
        catch (Exception ex)
        {
            LogToMainTab($"Error removing extension: {ex.Message}");
        }
    }

    [RelayCommand]
    private async Task ToggleExtensionLoaded(ExtensionItem? extension)
    {
        if (extension == null) return;

        bool wantsToLoad = extension.IsLoaded;

        try
        {
            if (wantsToLoad)
            {
                extension.IsLoaded = false;
                await LoadExistingExtensionAsync(extension);
            }
            else
            {
                extension.IsLoaded = true;

                var result = await ShowUnloadConfirmationAsync(extension.Name);
                if (!result)
                {
                    extension.IsLoaded = true;
                    return;
                }

                await UnloadExtensionAsync(extension);
            }

            await _configManager.SetExtensionLoadedStateAsync(extension.FilePath, extension.IsLoaded);
        }
        catch (Exception ex)
        {
            AddConsoleOutput($"Error toggling extension '{extension.Name}': {ex.Message}");
            extension.IsLoaded = false;
            extension.IsLoaded = extension.PythonInstance != null;
        }
    }

    private async Task<bool> ShowUnloadConfirmationAsync(string extensionName)
    {
        try
        {
            var mainWindow = App.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop ? desktop.MainWindow : null;

            if (mainWindow == null)
            {
                AddConsoleOutput("Warning: Could not show confirmation dialog");
                return true;
            }

            var dialog = new Avalonia.Controls.Window
            {
                Title = "Confirm Unload",
                Width = 400,
                Height = 150,
                WindowStartupLocation = Avalonia.Controls.WindowStartupLocation.CenterOwner,
                CanResize = false,
                Content = new StackPanel
                {
                    Margin = new Avalonia.Thickness(20),
                    Children =
                    {
                        new TextBlock
                        {
                            Text = $"Are you sure you want to unload the extension '{extensionName}'?",
                            TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                            Margin = new Avalonia.Thickness(0, 0, 0, 20)
                        },
                        new StackPanel
                        {
                            Orientation = Avalonia.Layout.Orientation.Horizontal,
                            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right,
                            Children =
                            {
                                new Button
                                {
                                    Content = "Yes",
                                    Margin = new Avalonia.Thickness(0, 0, 10, 0),
                                    Padding = new Avalonia.Thickness(20, 8),
                                    Background = Avalonia.Media.Brushes.Red,
                                    Foreground = Avalonia.Media.Brushes.White
                                },
                                new Button
                                {
                                    Content = "Cancel",
                                    Padding = new Avalonia.Thickness(20, 8),
                                    Background = Avalonia.Media.Brushes.Gray,
                                    Foreground = Avalonia.Media.Brushes.White
                                }
                            }
                        }
                    }
                }
            };

            bool result = false;
            var buttons = ((StackPanel)((StackPanel)dialog.Content).Children[1]).Children;
            ((Button)buttons[0]).Click += (s, e) => { result = true; dialog.Close(); };
            ((Button)buttons[1]).Click += (s, e) => { result = false; dialog.Close(); };

            await dialog.ShowDialog(mainWindow);
            return result;
        }
        catch (Exception ex)
        {
            AddConsoleOutput($"Error showing confirmation dialog: {ex.Message}");
            return true;
        }
    }

    private Task UnloadExtensionAsync(ExtensionItem extension)
    {
        try
        {
            if (extension.PythonInstance != null)
            {
                try
                {
                    extension.PythonInstance.Unload();
                    extension.PythonInstance = null;
                }
                catch (Exception ex)
                {
                    AddConsoleOutput($"Warning: Error during extension cleanup: {ex.Message}");
                }
            }

            extension.IsLoaded = false;
            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            LogToMainTab($"Error unloading extension '{extension.Name}': {ex.Message}");
            return Task.FromException(ex);
        }
    }

    private async Task LoadExistingExtensionAsync(ExtensionItem extension)
    {
        try
        {
            LogToMainTab($"Loading extension: {extension.Name}");

            if (!File.Exists(extension.FilePath))
            {
                LogToMainTab($"Error: Extension file not found: {extension.FilePath}");
                return;
            }

            var extensionInstance = await _pythonLoader.LoadExtensionAsync(extension.FilePath);

            if (extensionInstance != null)
            {
                extension.PythonInstance = extensionInstance;
                extension.IsLoaded = true;
                extension.LoadedAt = DateTime.Now;

                extension.Name = extensionInstance.Name;
                extension.Version = extensionInstance.Version;

                LogToMainTab($"Extension '{extension.Name}' loaded successfully");
            }
            else
            {
                LogToMainTab($"Failed to load extension from: {extension.FilePath}");
            }
        }
        catch (Exception ex)
        {
            AddConsoleOutput($"Error loading extension '{extension.Name}': {ex.Message}");
            throw;
        }
    }

    [RelayCommand] private void ClearConsole() =>
        Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
        {
            ConsoleOutput.Clear();
            OnPropertyChanged(nameof(ConsoleOutput));
            OnPropertyChanged(nameof(ExtensionOutput));
        }, Avalonia.Threading.DispatcherPriority.Send);

    [RelayCommand] private async Task RemoveSelectedExtension() =>
        await RemoveExtension(SelectedExtension);

    public void AddConsoleOutput(string message)
    {
        Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
        {
            ConsoleOutput.Add(message);
            OnPropertyChanged(nameof(ExtensionOutput));

            if (ConsoleOutput.Count > 1000)
            {
                ConsoleOutput.RemoveAt(0);
            }
        }, Avalonia.Threading.DispatcherPriority.Send);
    }

    /// <summary>
    /// Logs app-related messages to the main log tab
    /// </summary>
    private void LogToMainTab(string message)
    {
        if (_mainWindowViewModel != null)
        {
            _mainWindowViewModel.AddLogMessage($"[EXTENSIONS] {message}");
        }
        else
        {
            // Fallback to console output if main view model is not available
            AddConsoleOutput($"[APP] {message}");
        }
    }

    private async Task LoadExtensionsAsync()
    {
        try
        {
            IsLoading = true;
            var pythonSettings = await PythonSettings.LoadAsync();

            if (string.IsNullOrEmpty(pythonSettings.PythonDirectory) || !Directory.Exists(pythonSettings.PythonDirectory))
            {
                LogToMainTab(string.IsNullOrEmpty(pythonSettings.PythonDirectory)
                    ? "No Python directory configured. Please configure Python in Settings tab."
                    : "Configured Python directory not found. Please update Python directory in Settings tab.");
            }

            var config = await _configManager.LoadConfigurationAsync();
            Extensions.Clear();

            foreach (var configItem in config.Extensions)
            {
                if (!File.Exists(configItem.Path))
                {
                    LogToMainTab($"Warning: Extension file not found: {configItem.Path}");
                    continue;
                }

                var extension = new ExtensionItem
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = Path.GetFileNameWithoutExtension(configItem.Path),
                    Version = "Unknown",
                    FilePath = configItem.Path,
                    IsEnabled = true,
                    IsLoaded = false,
                    LoadedAt = DateTime.Now,
                    PythonInstance = null
                };

                Extensions.Add(extension);

                if (configItem.IsLoaded)
                {
                    try
                    {
                        await LoadExistingExtensionAsync(extension);
                    }
                    catch (Exception ex)
                    {
                        AddConsoleOutput($"Failed to auto-load extension {Path.GetFileName(configItem.Path)}: {ex.Message}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            LogToMainTab($"Error loading extensions: {ex.Message}");
        }
        finally
        {
            IsLoading = false;
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            ExtensionLogger.Log("Disposing ExtensionsViewModel and shutting down Python...");

            foreach (var extension in Extensions.Where(e => e.IsLoaded).ToList())
            {
                try
                {
                    if (extension.PythonInstance != null)
                    {
                        extension.PythonInstance.Unload();
                        extension.PythonInstance = null;
                    }
                    extension.IsLoaded = false;
                }
                catch (Exception ex)
                {
                    ExtensionLogger.Log($"Error unloading extension {extension.Name} during disposal: {ex.Message}");
                }
            }

            // Shutdown Python engine to prevent hanging processes
            _pythonLoader?.Dispose();

            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }

    ~ExtensionsViewModel()
    {
        Dispose();
    }
}

public class ExtensionItem : ObservableObject
{
    private string _id = string.Empty;
    private string _name = string.Empty;
    private string _version = string.Empty;
    private string _filePath = string.Empty;
    private bool _isEnabled;
    private bool _isLoaded;
    private DateTime _loadedAt;

    public string Id
    {
        get => _id;
        set => SetProperty(ref _id, value);
    }

    public string Name
    {
        get => _name;
        set => SetProperty(ref _name, value);
    }

    public string Version
    {
        get => _version;
        set => SetProperty(ref _version, value);
    }

    public string FilePath
    {
        get => _filePath;
        set => SetProperty(ref _filePath, value);
    }

    public bool IsEnabled
    {
        get => _isEnabled;
        set => SetProperty(ref _isEnabled, value);
    }

    public bool IsLoaded
    {
        get => _isLoaded;
        set
        {
            if (SetProperty(ref _isLoaded, value))
            {
                OnPropertyChanged(nameof(Status));
            }
        }
    }

    public DateTime LoadedAt
    {
        get => _loadedAt;
        set => SetProperty(ref _loadedAt, value);
    }

    public string Status => IsLoaded ? "Loaded" : "Unloaded";

    public string Type => "Python";

    // Store the Python extension instance (not serialized)
    [JsonIgnore]
    public ExtensionInstance? PythonInstance { get; set; }
}
