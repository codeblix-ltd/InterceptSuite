using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace InterceptSuite.Extensions;

public static class PythonEnvironment
{
    public static string? PythonPath { get; private set; }
    public static string? PythonDllPath { get; private set; }

    public static async Task<bool> DetectPythonAsync()
    {
        // First check InterceptSuitePython environment variable
        var envPath = Environment.GetEnvironmentVariable("InterceptSuitePython");
        if (!string.IsNullOrEmpty(envPath) && File.Exists(envPath))
        {
            if (await ValidatePythonPath(envPath))
            {
                PythonPath = envPath;
                SetPythonDllPath(Path.GetDirectoryName(envPath) ?? "");
                return true;
            }
        }

        // Try common Python executable names based on platform
        string[] pythonExes = GetPythonExecutableNames();

        foreach (var exe in pythonExes)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = exe,
                        Arguments = "--version",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                await process.WaitForExitAsync();

                if (process.ExitCode == 0)
                {
                    PythonPath = exe;
                    // For system-installed Python, try to detect full executable path
                    try
                    {
                        var process2 = new Process
                        {
                            StartInfo = new ProcessStartInfo
                            {
                                FileName = exe,
                                Arguments = "-c \"import sys; print(sys.executable)\"",
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                CreateNoWindow = true
                            }
                        };
                        process2.Start();
                        var execPath = await process2.StandardOutput.ReadToEndAsync();
                        await process2.WaitForExitAsync();

                        if (process2.ExitCode == 0 && !string.IsNullOrEmpty(execPath))
                        {
                            var fullPath = execPath.Trim();
                            if (File.Exists(fullPath))
                            {
                                PythonPath = fullPath;
                                SetPythonDllPath(Path.GetDirectoryName(fullPath) ?? "");
                            }
                        }
                    }
                    catch
                    {
                        // If we can't get the full path, use what we have
                        // Just try to set DLL path based on the executable name in PATH
                        if (exe.Contains(Path.DirectorySeparatorChar))
                        {
                            SetPythonDllPath(Path.GetDirectoryName(exe) ?? "");
                        }
                    }

                    return true;
                }
            }
            catch
            {
                // Continue trying other executables
            }
        }

        return false;
    }

    private static string[] GetPythonExecutableNames()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return new[] { "python.exe", "python3.exe", "py.exe" };
        }
        else
        {
            return new[] { "python3", "python" };
        }
    }

    private static async Task<bool> ValidatePythonPath(string path)
    {
        try
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = path,
                    Arguments = "--version",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                }
            };

            process.Start();
            await process.WaitForExitAsync();

            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public static async Task<string> GetPythonVersionAsync()
    {
        if (string.IsNullOrEmpty(PythonPath))
            return "Not Found";

        try
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = PythonPath,
                    Arguments = "--version",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            var error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            return !string.IsNullOrEmpty(output) ? output.Trim() : error.Trim();
        }
        catch (Exception ex)
        {
            return $"Error: {ex.Message}";
        }
    }

    public static void SetPythonPath(string path)
    {
        if (File.Exists(path))
        {
            PythonPath = path;
            Environment.SetEnvironmentVariable("InterceptSuitePython", path);
        }
        else
        {
            throw new ArgumentException("Python executable not found at specified path", nameof(path));
        }
    }

    private static void SetPythonDllPath(string pythonDir)
    {
        if (string.IsNullOrEmpty(pythonDir) || !Directory.Exists(pythonDir))
        {
            PythonDllPath = null;
            return;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // On Windows, look for python3X.dll or python3XX.dll
            try
            {
                var dllFiles = Directory.GetFiles(pythonDir, "python3*.dll");
                if (dllFiles.Length > 0)
                {
                    // Sort by name to get the most specific version first
                    Array.Sort(dllFiles, (a, b) => string.Compare(Path.GetFileName(b), Path.GetFileName(a)));
                    PythonDllPath = dllFiles[0];
                    return;
                }

                // Try fallback patterns for specific versions
                var fallbackPatterns = new[]
                {
                    "python311.dll",
                    "python310.dll",
                    "python39.dll",
                    "python38.dll",
                    "python37.dll"
                };

                foreach (var pattern in fallbackPatterns)
                {
                    var dllPath = Path.Combine(pythonDir, pattern);
                    if (File.Exists(dllPath))
                    {
                        PythonDllPath = dllPath;
                        return;
                    }
                }
            }
            catch
            {
                // If we can't access the directory, just continue
            }
        }

        // On Linux/macOS, Python.NET handles library loading automatically
        PythonDllPath = null;
    }

    public static string GetRequiredMessage()
    {
        var platform = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" :
                      RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS";

        return $@"Python is required for extensions to work.

Please install Python 3.7+ from python.org or set the InterceptSuitePython environment variable.

Platform: {platform}

Installation:
- Windows: Download from python.org or use Microsoft Store
- Linux: sudo apt install python3 python3-dev (Ubuntu/Debian) or equivalent
- macOS: brew install python3 or download from python.org

Environment Variable Examples:
- Windows: set InterceptSuitePython=C:\Python311\python.exe
- Linux: export InterceptSuitePython=/usr/bin/python3
- macOS: export InterceptSuitePython=/usr/local/bin/python3

Current detected paths will be shown above if Python is found.";
    }
}
