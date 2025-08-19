using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using InterceptSuite.Extensions.APIs.Logging;
using InterceptSuite.ViewModels;
namespace InterceptSuite.Extensions
{
    public class PythonSettings
    {

        private static MainWindowViewModel? _mainWindowViewModel;

        public static void SetMainWindowViewModel(MainWindowViewModel mainWindowViewModel)
        {
            _mainWindowViewModel = mainWindowViewModel;
        }

        private static void LogToMainTab(string message)
        {
            _mainWindowViewModel?.AddLogMessage($"[PYTHON] {message}");
        }

        public string? PythonDirectory { get; set; }
        public string? PythonExecutable { get; set; }
        public string? PythonLibrary { get; set; }
        public string[]? AdditionalPaths { get; set; }

        // Legacy properties - kept for compatibility but not used in UI
        public string? CustomExecutablePath { get; set; }
        public string? CustomLibraryPath { get; set; }
        public bool UseCustomPaths { get; set; } = false;
        public bool AutoDetect { get; set; } = false; // Always false now

        private static readonly string SettingsPath = GetPythonSettingsPath();

        private static string GetPythonSettingsPath()
        {
            var userDataPath = GetUserDataDirectory();
            return Path.Combine(userDataPath, "python-settings.json");
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

        public static async Task<PythonSettings> LoadAsync()
        {
            try
            {

                LogToMainTab($"Looking for Python settings at: {SettingsPath}");

                // Use ConfigureAwait(false) to avoid deadlocks
                var fileExists = await Task.Run(() => File.Exists(SettingsPath)).ConfigureAwait(false);

                if (fileExists)
                {
                    // Read file on background thread to avoid blocking UI
                    var lines = await Task.Run(async () => await File.ReadAllLinesAsync(SettingsPath)).ConfigureAwait(false);
                    LogToMainTab($"Found settings file, lines: {lines.Length}");

                    var settings = new PythonSettings();
                    foreach (var line in lines)
                    {
                        if (line.StartsWith("PythonDirectory="))
                        {
                            settings.PythonDirectory = line.Substring("PythonDirectory=".Length);
                        }
                        else if (line.StartsWith("PythonExecutable="))
                        {
                            settings.PythonExecutable = line.Substring("PythonExecutable=".Length);
                        }
                        else if (line.StartsWith("PythonLibrary="))
                        {
                            settings.PythonLibrary = line.Substring("PythonLibrary=".Length);
                        }
                    }

                    LogToMainTab($"Loaded Python settings from: {SettingsPath}");
                    LogToMainTab($"Loaded directory: {settings.PythonDirectory}");
                    LogToMainTab($"Loaded executable: {settings.PythonExecutable}");
                    LogToMainTab($"Loaded library: {settings.PythonLibrary}");
                    return settings;
                }
                else
                {
                    LogToMainTab($"Settings file does not exist at: {SettingsPath}");
                }
            }
            catch (Exception ex)
            {
                LogToMainTab($"Failed to load Python settings: {ex}");

            }

            LogToMainTab("Using default Python settings (no directory configured)");
            return new PythonSettings();
        }

        public async Task SaveAsync()
        {
            try
            {
                var directory = Path.GetDirectoryName(SettingsPath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    LogToMainTab($"Creating directory: {directory}");
                    // Create directory on background thread
                    await Task.Run(() => Directory.CreateDirectory(directory)).ConfigureAwait(false);
                }

                var lines = new List<string>();
                if (!string.IsNullOrEmpty(PythonDirectory))
                {
                    lines.Add($"PythonDirectory={PythonDirectory}");
                }
                if (!string.IsNullOrEmpty(PythonExecutable))
                {
                    lines.Add($"PythonExecutable={PythonExecutable}");
                }
                if (!string.IsNullOrEmpty(PythonLibrary))
                {
                    lines.Add($"PythonLibrary={PythonLibrary}");
                }

                // Write file on background thread to avoid blocking UI
                await Task.Run(async () => await File.WriteAllLinesAsync(SettingsPath, lines)).ConfigureAwait(false);
                LogToMainTab($"Saved Python settings to: {SettingsPath}");
                LogToMainTab($"Saved directory: {PythonDirectory}");
                LogToMainTab($"Saved executable: {PythonExecutable}");
                LogToMainTab($"Saved library: {PythonLibrary}");
            }
            catch (Exception ex)
            {
                LogToMainTab($"Failed to save Python settings: {ex.Message}");
                LogToMainTab($"Full exception: {ex}");
            }
        }

        public static (string? executable, string? library, string? version) DetectFromDirectory(string pythonDir)
        {
            string? executable = null;
            string? library = null;
            string? version = null;

            try
            {
                LogToMainTab($"Scanning Python directory: {pythonDir}");

                // Find executable
                var possibleExes = OperatingSystem.IsWindows()
                    ? new[] { "python.exe", "python3.exe" }
                    : new[] { "python3", "python" };

                var possiblePaths = new[] {
                    pythonDir,
                    Path.Combine(pythonDir, "bin"),
                    Path.Combine(pythonDir, "Scripts") // Windows virtual environments
                };

                foreach (var path in possiblePaths)
                {
                    if (!Directory.Exists(path)) continue;

                    foreach (var exe in possibleExes)
                    {
                        var fullPath = Path.Combine(path, exe);
                        if (File.Exists(fullPath))
                        {
                            executable = fullPath;
                            LogToMainTab($"Found Python executable: {executable}");
                            break;
                        }
                    }
                    if (executable != null) break;
                }

                // Find shared library
                if (OperatingSystem.IsWindows())
                {
                    library = FindWindowsLibrary(pythonDir);
                }
                else if (OperatingSystem.IsLinux())
                {
                    library = FindLinuxLibrary(pythonDir);
                }
                else if (OperatingSystem.IsMacOS())
                {
                    library = FindMacOSLibrary(pythonDir);
                }

                // Try to get version if we found the executable
                if (!string.IsNullOrEmpty(executable))
                {
                    version = GetPythonVersion(executable);
                }

                LogToMainTab($"Detection results - Executable: {executable}, Library: {library}, Version: {version}");
            }
            catch (Exception ex)
            {
                ExtensionLogger.Log($"Error detecting Python from directory {pythonDir}: {ex.Message}");
            }

            return (executable, library, version);
        }

        public static async Task<PythonSettings> SetDirectoryAndDetectAsync(string pythonDir)
        {
            var settings = new PythonSettings
            {
                PythonDirectory = pythonDir
            };

            try
            {
                LogToMainTab($"Detecting Python files from directory: {pythonDir}");

                // Detect executable and library
                var (executable, library, version) = DetectFromDirectory(pythonDir);

                if (!string.IsNullOrEmpty(executable))
                {
                    settings.PythonExecutable = executable;
                    LogToMainTab($"Detected executable: {executable}");
                }

                if (!string.IsNullOrEmpty(library))
                {
                    settings.PythonLibrary = library;
                    LogToMainTab($"Detected library: {library}");
                }

                // Save the settings with detected paths
                await settings.SaveAsync();

                LogToMainTab($"Python detection complete - Version: {version}");
            }
            catch (Exception ex)
            {
                LogToMainTab($"Error during Python detection: {ex.Message}");
            }

            return settings;
        }

        private static string? FindWindowsLibrary(string pythonDir)
        {
            var searchPaths = new[] {
                pythonDir,
                Path.Combine(pythonDir, "DLLs"),
                Path.Combine(pythonDir, "libs")
            };

            LogToMainTab($"Searching for Python library in {searchPaths.Length} directories...");

            foreach (var path in searchPaths)
            {
                LogToMainTab($"Checking directory: {path}");

                if (!Directory.Exists(path))
                {
                    LogToMainTab($"  Directory does not exist: {path}");
                    continue;
                }

                LogToMainTab($"  Directory exists, searching for python*.dll files...");

                try
                {
                    var dlls = Directory.GetFiles(path, "python3*.dll")
                        .Concat(Directory.GetFiles(path, "python*.dll"))
                        .Where(f => !Path.GetFileName(f).StartsWith("python3_"))
                        .OrderByDescending(f => f)
                        .ToArray();

                    LogToMainTab($"  Found {dlls.Length} potential Python library files");

                    foreach (var dll in dlls)
                    {
                        LogToMainTab($"    Candidate: {dll}");
                    }

                    if (dlls.Length > 0)
                    {
                        LogToMainTab($"Selected Python DLL: {dlls[0]}");
                        return dlls[0];
                    }
                }
                catch (Exception ex)
                {
                    LogToMainTab($"  Error searching in {path}: {ex.Message}");
                }
            }

            LogToMainTab("No Python shared library found in any search path");
            return null;
        }

        private static string? FindLinuxLibrary(string pythonDir)
        {
            var searchPaths = new[] {
                Path.Combine(pythonDir, "lib"),
                pythonDir,
                Path.Combine(pythonDir, "..", "lib"), // For cases where bin and lib are siblings
                "/usr/lib",  // System default
                "/usr/local/lib",  // Local installation
                "/usr/lib/x86_64-linux-gnu",  // Debian/Ubuntu multiarch
                "/usr/lib64",  // Some 64-bit distributions
                "/lib/x86_64-linux-gnu",  // System multiarch
                "/lib64"  // System 64-bit libraries
            };

            LogToMainTab($"Searching for Python library in {searchPaths.Length} directories...");

            foreach (var path in searchPaths)
            {
                LogToMainTab($"Checking directory: {path}");

                if (!Directory.Exists(path))
                {
                    LogToMainTab($"  Directory does not exist: {path}");
                    continue;
                }

                LogToMainTab($"  Directory exists, searching for libpython3*.so* files...");

                try
                {
                    // Look for libpython3.x.so files
                    var sos = Directory.GetFiles(path, "libpython3*.so*", SearchOption.AllDirectories)
                        .Where(f => !f.Contains("config")) // Skip config-specific libraries
                        .OrderByDescending(f => f)
                        .ToArray();

                    LogToMainTab($"  Found {sos.Length} potential Python library files");

                    foreach (var so in sos)
                    {
                        LogToMainTab($"    Candidate: {so}");
                    }

                    if (sos.Length > 0)
                    {
                        LogToMainTab($"Selected Python SO: {sos[0]}");
                        return sos[0];
                    }
                }
                catch (Exception ex)
                {
                    LogToMainTab($"  Error searching in {path}: {ex.Message}");
                }
            }

            LogToMainTab("No Python shared library found in any search path");
            return null;
        }

        private static string? FindMacOSLibrary(string pythonDir)
        {
            var searchPaths = new[] {
                Path.Combine(pythonDir, "lib"),
                pythonDir,
                Path.Combine(pythonDir, "..", "lib"), // For cases where bin and lib are siblings
                Path.Combine(pythonDir, "Python.framework", "Versions", "Current", "lib"), // Framework installations
                "/usr/local/lib",  // Homebrew default
                "/opt/homebrew/lib",  // Apple Silicon Homebrew
                "/usr/lib",  // System libraries
                "/Library/Frameworks/Python.framework/Versions/Current/lib"  // System Python framework
            };

            LogToMainTab($"Searching for Python library in {searchPaths.Length} directories...");

            foreach (var path in searchPaths)
            {
                LogToMainTab($"Checking directory: {path}");

                if (!Directory.Exists(path))
                {
                    LogToMainTab($"  Directory does not exist: {path}");
                    continue;
                }

                LogToMainTab($"  Directory exists, searching for libpython3*.dylib files...");

                try
                {
                    // Look for libpython3.x.dylib files
                    var dylibs = Directory.GetFiles(path, "libpython3*.dylib", SearchOption.AllDirectories)
                        .Concat(Directory.GetFiles(path, "Python", SearchOption.AllDirectories)) // Framework binary
                        .OrderByDescending(f => f)
                        .ToArray();

                    LogToMainTab($"  Found {dylibs.Length} potential Python library files");

                    foreach (var dylib in dylibs)
                    {
                        LogToMainTab($"    Candidate: {dylib}");
                    }

                    if (dylibs.Length > 0)
                    {
                        LogToMainTab($"Selected Python DYLIB: {dylibs[0]}");
                        return dylibs[0];
                    }
                }
                catch (Exception ex)
                {
                    LogToMainTab($"  Error searching in {path}: {ex.Message}");
                }
            }

            LogToMainTab("No Python shared library found in any search path");
            return null;
        }

        private static string? GetPythonVersion(string executablePath)
        {
            try
            {
                // Add timeout to prevent hanging
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = executablePath,
                        Arguments = "--version",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();

                // Set a timeout to prevent hanging
                if (!process.WaitForExit(5000)) // 5 second timeout
                {
                    process.Kill();
                    ExtensionLogger.Log($"Python version check timed out for {executablePath}");
                    return null;
                }

                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();

                if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
                {
                    return output.Trim();
                }
                else if (!string.IsNullOrWhiteSpace(error))
                {
                    return error.Trim(); // Some Python versions output to stderr
                }
            }
            catch (Exception ex)
            {
                ExtensionLogger.Log($"Failed to get Python version from {executablePath}: {ex.Message}");
            }

            return null;
        }

        public (bool success, string message) ValidateConfiguration()
        {
            try
            {
                if (string.IsNullOrEmpty(PythonDirectory))
                {
                    return (false, "No Python directory configured. Please select a Python installation directory.");
                }

                if (!Directory.Exists(PythonDirectory))
                {
                    return (false, $"Python directory not found: {PythonDirectory}");
                }

                // Check if we have saved executable and library paths
                if (!string.IsNullOrEmpty(PythonExecutable) && !string.IsNullOrEmpty(PythonLibrary))
                {
                    // Validate saved paths still exist
                    if (File.Exists(PythonExecutable) && File.Exists(PythonLibrary))
                    {
                        // Try to get version to ensure it still works
                        var version = GetPythonVersion(PythonExecutable);
                        if (!string.IsNullOrEmpty(version))
                        {
                            return (true, $"Configuration valid. Python {version} found.");
                        }
                        else
                        {
                            return (false, $"Python executable exists but failed to get version: {PythonExecutable}");
                        }
                    }
                    else
                    {
                        return (false, "Saved Python paths no longer exist. Please reselect the Python directory.");
                    }
                }

                // If no saved paths, try to detect again
                var (executable, library, detectedVersion) = DetectFromDirectory(PythonDirectory);

                if (string.IsNullOrEmpty(executable))
                {
                    return (false, $"No Python executable found in: {PythonDirectory}");
                }

                if (string.IsNullOrEmpty(library))
                {
                    return (false, $"No Python library found in: {PythonDirectory}");
                }

                // Try to get version to ensure it works
                if (string.IsNullOrEmpty(detectedVersion))
                {
                    return (false, $"Failed to get version from Python executable: {executable}");
                }

                return (true, $"Configuration valid. Python {detectedVersion} found.");
            }
            catch (Exception ex)
            {
                return (false, $"Validation error: {ex.Message}");
            }
        }
    }
}
