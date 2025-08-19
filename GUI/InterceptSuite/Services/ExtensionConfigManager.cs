using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using InterceptSuite.Models;
using InterceptSuite.Json;
using InterceptSuite.Extensions.APIs.Logging;

namespace InterceptSuite.Services;

public class ExtensionConfigManager
{
    private const string ConfigFileName = "extensions.json";
    private readonly string _configPath;

    public ExtensionConfigManager()
    {
        _configPath = GetConfigPath();
    }

    public async Task<ExtensionConfiguration> LoadConfigurationAsync()
    {
        try
        {
            if (!File.Exists(_configPath))
            {
                ExtensionLogger.Log("No existing extensions.json found - starting fresh");
                return new ExtensionConfiguration();
            }

            var json = await File.ReadAllTextAsync(_configPath);
            var config = JsonSerializer.Deserialize(json, ExtensionJsonContext.Default.ExtensionConfiguration);

            return config ?? new ExtensionConfiguration();
        }
        catch (Exception ex)
        {
            ExtensionLogger.Log($"Error loading extensions configuration: {ex.Message}");
            return new ExtensionConfiguration();
        }
    }

    public async Task SaveConfigurationAsync(ExtensionConfiguration config)
    {
        try
        {
            var directory = Path.GetDirectoryName(_configPath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(config, ExtensionJsonContext.Default.ExtensionConfiguration);
            await File.WriteAllTextAsync(_configPath, json);


        }
        catch (Exception ex)
        {
            ExtensionLogger.Log($"Error saving extensions configuration: {ex.Message}");
        }
    }

    public async Task AddExtensionAsync(string filePath, bool isLoaded = true)
    {
        var config = await LoadConfigurationAsync();

        config.Extensions.RemoveAll(e => e.Path.Equals(filePath, StringComparison.OrdinalIgnoreCase));

        config.Extensions.Add(new ExtensionConfigItem
        {
            Path = filePath,
            IsLoaded = isLoaded
        });

        await SaveConfigurationAsync(config);
    }

    public async Task RemoveExtensionAsync(string filePath)
    {
        var config = await LoadConfigurationAsync();
        config.Extensions.RemoveAll(e => e.Path.Equals(filePath, StringComparison.OrdinalIgnoreCase));
        await SaveConfigurationAsync(config);
    }

    public async Task SetExtensionLoadedStateAsync(string filePath, bool isLoaded)
    {
        var config = await LoadConfigurationAsync();
        var extension = config.Extensions.FirstOrDefault(e => e.Path.Equals(filePath, StringComparison.OrdinalIgnoreCase));

        if (extension != null)
        {
            extension.IsLoaded = isLoaded;
            await SaveConfigurationAsync(config);
        }
    }

    private static string GetConfigPath()
    {
        var userDataPath = GetUserDataDirectory();
        return Path.Combine(userDataPath, ConfigFileName);
    }

    private static string GetUserDataDirectory()
    {
        string userDataPath;

        if (OperatingSystem.IsWindows())
        {
            userDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "InterceptSuite", "config"
            );
        }
        else if (OperatingSystem.IsMacOS())
        {
            userDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library", "Application Support", "InterceptSuite", "config"
            );
        }
        else // Linux and others
        {
            userDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".local", "share", "InterceptSuite", "config"
            );
        }

        return userDataPath;
    }
}
