using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Python.Runtime;
using InterceptSuite.Extensions.APIs.Logging;
using InterceptSuite.Extensions.APIs.Core;
using InterceptSuite.ViewModels;

namespace InterceptSuite.Extensions;

public class PythonExtensionLoader : IDisposable
{
    private bool _pythonInitialized = false;
    private bool _disposed = false;
    private readonly List<WeakReference> _loadedExtensions = new();
    private readonly object _extensionLock = new();
    private readonly MainWindowViewModel? _mainWindowViewModel;

    public PythonExtensionLoader(MainWindowViewModel? mainWindowViewModel = null)
    {
        _mainWindowViewModel = mainWindowViewModel;
    }

    /// <summary>
    /// Logs app-related messages to the main log tab
    /// </summary>
    private void LogToMainTab(string message)
    {
        if (_mainWindowViewModel != null)
        {
            _mainWindowViewModel.AddLogMessage($"[PYTHON] {message}");
        }
        else
        {
            // Fallback to extension logger if main view model is not available
            ExtensionLogger.Log(message);
        }
    }

    public async Task<bool> InitializePythonAsync()
    {
        if (_pythonInitialized)
            return true;

        try
        {
            LogToMainTab("Initializing Python environment...");

            // Load user settings
            var settings = await PythonSettings.LoadAsync();

            // Check if Python directory is configured
            if (string.IsNullOrEmpty(settings.PythonDirectory))
            {
                ExtensionLogger.Log("Python not configured! Please select a Python directory in Extensions > Settings");
                ExtensionLogger.Log("Go to Settings tab and browse for your Python installation directory");
                return false;
            }

            if (!Directory.Exists(settings.PythonDirectory))
            {
                LogToMainTab($"Python directory not found: {settings.PythonDirectory}");
                LogToMainTab("Please update the Python directory in Extensions > Settings");
                return false;
            }

            // Auto-detect Python from the configured directory
            var (pythonExecutable, pythonLibrary, version) = PythonSettings.DetectFromDirectory(settings.PythonDirectory);

            if (string.IsNullOrEmpty(pythonExecutable))
            {
                LogToMainTab($"No Python executable found in: {settings.PythonDirectory}");
                LogToMainTab("Please select a valid Python installation directory in Settings");
                return false;
            }

            if (string.IsNullOrEmpty(pythonLibrary))
            {
                LogToMainTab($"No Python library found in: {settings.PythonDirectory}");
                LogToMainTab("This Python installation may not support embedding");
                return false;
            }

            LogToMainTab($"Using Python {version}");
            LogToMainTab($"Executable: {pythonExecutable}");
            LogToMainTab($"Library: {pythonLibrary}");

            // Set Python DLL path for Python.NET
            LogToMainTab($"Setting Python DLL to: {pythonLibrary}");
            Runtime.PythonDLL = pythonLibrary;

            // Set environment variables
            var pythonHome = Path.GetDirectoryName(pythonExecutable);
            if (!string.IsNullOrEmpty(pythonHome))
            {
                LogToMainTab($"Setting PYTHONHOME to: {pythonHome}");
                Environment.SetEnvironmentVariable("PYTHONHOME", pythonHome);

                // Set PYTHONPATH for different platforms
                var stdLibPaths = new List<string>();

                if (OperatingSystem.IsWindows())
                {
                    var libPath = Path.Combine(pythonHome, "Lib");
                    var dllsPath = Path.Combine(pythonHome, "DLLs");

                    if (Directory.Exists(libPath))
                        stdLibPaths.Add(libPath);
                    if (Directory.Exists(dllsPath))
                        stdLibPaths.Add(dllsPath);
                }
                else
                {
                    // Look for lib/python3.x directory
                    var libDir = Path.Combine(pythonHome, "lib");
                    if (Directory.Exists(libDir))
                    {
                        var pythonLibDirs = Directory.GetDirectories(libDir, "python3.*");
                        if (pythonLibDirs.Length > 0)
                        {
                            stdLibPaths.Add(pythonLibDirs[0]);

                            var sitePackages = Path.Combine(pythonLibDirs[0], "site-packages");
                            if (Directory.Exists(sitePackages))
                                stdLibPaths.Add(sitePackages);
                        }
                    }

                    // Also try the parent lib directory (for some installations)
                    var parentLib = Path.Combine(pythonHome, "..", "lib");
                    if (Directory.Exists(parentLib))
                    {
                        var pythonLibDirs = Directory.GetDirectories(parentLib, "python3.*");
                        foreach (var dir in pythonLibDirs)
                        {
                            if (!stdLibPaths.Contains(dir))
                                stdLibPaths.Add(dir);
                        }
                    }
                }

                if (stdLibPaths.Count > 0)
                {
                    var pythonPath = string.Join(Path.PathSeparator, stdLibPaths);
                    LogToMainTab($"Setting PYTHONPATH to: {pythonPath}");
                    Environment.SetEnvironmentVariable("PYTHONPATH", pythonPath);
                }
                else
                {
                    ExtensionLogger.Log("Could not determine Python standard library path");
                }
            }

            // Initialize Python.NET
            LogToMainTab("Initializing Python.NET...");

            try
            {
                PythonEngine.Initialize();
                LogToMainTab("Python.NET engine started successfully");
            }
            catch (Exception engineEx)
            {
                LogToMainTab($"Failed to start Python.NET engine: {engineEx.Message}");
                if (engineEx.InnerException != null)
                    LogToMainTab($"Inner exception: {engineEx.InnerException.Message}");
                return false;
            }

            try
            {
                using (Py.GIL())
                {
                    // Test Python execution
                    using (var scope = Py.CreateScope())
                    {
                        scope.Exec("import sys");
                        scope.Exec("print('Python initialized successfully')");
                    }

                    // Add our assemblies to Python path
                    dynamic sys = Py.Import("sys");
                    sys.path.append(AppDomain.CurrentDomain.BaseDirectory);

                    // Import CLR
                    dynamic clr = Py.Import("clr");
                    clr.AddReference("InterceptSuite");
                }
            }
            catch (Exception pythonEx)
            {
                ExtensionLogger.Log($"Failed to configure Python environment: {pythonEx.Message}");
                ExtensionLogger.Log($"Python configuration error details: {pythonEx}");
                return false;
            }

            _pythonInitialized = true;
            LogToMainTab("Python.NET initialized successfully");
            return true;
        }
        catch (Exception ex)
        {
            LogToMainTab($"Failed to initialize Python: {ex.Message}");
            ExtensionLogger.Log($"Stack trace: {ex.StackTrace}");
            return false;
        }
    }

    public async Task<ExtensionInstance?> LoadExtensionAsync(string pythonFilePath)
    {
        if (!_pythonInitialized)
        {
            if (!await InitializePythonAsync())
                return null;
        }

        try
        {
            using (Py.GIL())
            {
                LogToMainTab($"Loading extension: {Path.GetFileName(pythonFilePath)}");

                // Execute the Python file
                var scope = Py.CreateScope();
                var pythonCode = await File.ReadAllTextAsync(pythonFilePath);

                scope.Exec(pythonCode);

                // Look for the InterceptSuiteExtension class
                dynamic? extensionObject = null;
                string extensionName;
                string extensionVersion;
                InterceptSuiteInterceptor? interceptor = null;

                try
                {
                    var extensionClass = scope.Get("InterceptSuiteExtension");
                    extensionObject = scope.Eval("InterceptSuiteExtension()");

                    // Create the interceptor instance for this extension
                    interceptor = new InterceptSuiteInterceptor(_mainWindowViewModel);

                    // Call register_interceptor_api method
                    if (extensionObject.HasAttr("register_interceptor_api"))
                    {
                        using (Py.GIL())
                        {
                            extensionObject.register_interceptor_api(interceptor.ToPython());
                        }

                        // Get extension info from the interceptor (this will throw if not set)
                        try
                        {
                            extensionName = interceptor.ExtensionName;
                            extensionVersion = interceptor.ExtensionVersion;
                        }
                        catch (InvalidOperationException ex)
                        {
                            ExtensionLogger.Log($"Extension failed to set required information: {ex.Message}");
                            ExtensionLogger.Log("Extensions MUST call both set_extension_name() and set_extension_version()");
                            return null;
                        }

                        LogToMainTab($"Extension {extensionName} v{extensionVersion} loaded successfully");
                    }
                    else
                    {
                        ExtensionLogger.Log("Extension does not implement register_interceptor_api method");
                        return null;
                    }
                }
                catch (Exception ex)
                {
                    ExtensionLogger.Log(ex.Message);
                    return null;
                }

                if (extensionObject == null)
                {
                    ExtensionLogger.Log("Failed to create InterceptSuiteExtension instance");
                    return null;
                }

                var instance = new ExtensionInstance(extensionObject, pythonFilePath, extensionName, extensionVersion, interceptor);

                // Track the loaded extension
                lock (_extensionLock)
                {
                    _loadedExtensions.Add(new WeakReference(instance));
                }

                return instance;
            }
        }
        catch (Exception ex)
        {
            ExtensionLogger.Log($"Failed to load extension {Path.GetFileName(pythonFilePath)}: {ex.Message}");
            ExtensionLogger.Log($"Exception details: {ex}");
            return null;
        }
    }

    public void UnloadAllExtensions()
    {
        LogToMainTab("Unloading all extensions...");

        lock (_extensionLock)
        {
            var extensionsToUnload = new List<ExtensionInstance>();

            // Collect all live extension references
            for (int i = _loadedExtensions.Count - 1; i >= 0; i--)
            {
                var weakRef = _loadedExtensions[i];
                if (weakRef.Target is ExtensionInstance extension)
                {
                    extensionsToUnload.Add(extension);
                }
                else
                {
                    // Remove dead references
                    _loadedExtensions.RemoveAt(i);
                }
            }

            // Unload all extensions
            foreach (var extension in extensionsToUnload)
            {
                try
                {
                    extension.Unload();
                }
                catch (Exception ex)
                {
                    ExtensionLogger.Log($"Error unloading extension {extension.Name}: {ex.Message}");
                }
            }

            // Clear the list
            _loadedExtensions.Clear();
        }

        // Force garbage collection after unloading all extensions
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        LogToMainTab("All extensions unloaded");
    }

    public void Shutdown()
    {
        if (!_pythonInitialized)
            return;

        try
        {
            LogToMainTab("Shutting down Python.NET engine...");

            // First, unload all extensions
            UnloadAllExtensions();

            // Properly shutdown Python.NET to prevent hanging processes
            if (PythonEngine.IsInitialized)
            {
                using (Py.GIL())
                {
                    // Clean up any remaining Python objects
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }

                PythonEngine.Shutdown();
                LogToMainTab("Python.NET engine shut down successfully");
            }

            _pythonInitialized = false;
        }
        catch (Exception ex)
        {
            ExtensionLogger.Log($"Error during Python shutdown: {ex.Message}");
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            Shutdown();
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }

    ~PythonExtensionLoader()
    {
        Dispose();
    }
}

public class ExtensionInstance : IDisposable
{
    private dynamic _pythonExtension;
    private readonly string _name;
    private readonly string _version;
    private readonly InterceptSuiteInterceptor? _interceptor;
    private bool _disposed = false;

    public ExtensionInstance(dynamic pythonExtension, string filePath, string name, string version, InterceptSuiteInterceptor? interceptor = null)
    {
        _pythonExtension = pythonExtension;
        FilePath = filePath;
        _name = name;
        _version = version;
        _interceptor = interceptor;
    }

    public string Name => _name;
    public string Version => _version;
    public string FilePath { get; }

    public void Unload()
    {
        try
        {
            // First, clean up the interceptor to remove any registered UI components
            if (_interceptor != null)
            {
                try
                {
                    _interceptor.UnloadExtension();
                }
                catch (Exception ex)
                {
                    ExtensionLogger.Log($"Warning: Error during interceptor cleanup: {ex.Message}");
                }
            }

            if (_pythonExtension != null)
            {
                using (Py.GIL())
                {
                    try
                    {
                        // Try to call cleanup method if it exists (courtesy call)
                        if (_pythonExtension.HasAttr("cleanup"))
                        {


                            // Set a timeout for cleanup - don't let it hang
                            var cleanupTask = Task.Run(() =>
                            {
                                using (Py.GIL())
                                {
                                    _pythonExtension.cleanup();
                                }
                            });

                            // Wait max 5 seconds for cleanup
                            if (!cleanupTask.Wait(TimeSpan.FromSeconds(5)))
                            {
                                ExtensionLogger.Log($"Extension {Name} cleanup method timed out after 5 seconds");
                            }
                            else
                            {

                            }
                        }
                        else
                        {

                        }
                    }
                    catch (Exception ex)
                    {
                        ExtensionLogger.Log($"Error during extension cleanup for {Name}: {ex.Message}");
                    }
                    finally
                    {
                        // Force cleanup regardless of what happened above
                        try
                        {
                            // Clear the reference forcefully
                            _pythonExtension = null!;

                            // Force garbage collection to clean up Python objects
                            GC.Collect();
                            GC.WaitForPendingFinalizers();
                            GC.Collect();
                        }
                        catch (Exception ex)
                        {
                            ExtensionLogger.Log($"Error during forced cleanup for {Name}: {ex.Message}");
                        }
                    }
                }
            }


        }
        catch (Exception ex)
        {
            ExtensionLogger.Log($"Error unloading extension {Name}: {ex.Message}");

            // Even if there's an error, we still need to clear the reference
            _pythonExtension = null!;
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            Unload();
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }

    ~ExtensionInstance()
    {
        Dispose();
    }
}
