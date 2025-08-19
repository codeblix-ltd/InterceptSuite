using System;
using System.Reflection;
using InterceptSuite.Extensions.APIs.Logging;
using InterceptSuite.Extensions.APIs.DataViewer;
using Python.Runtime;

namespace InterceptSuite.Extensions.APIs.Core
{
    public class InterceptSuiteInterceptor
    {
        private string? _extensionName = null;
        private string? _extensionVersion = null;
        private readonly InterceptSuite.ViewModels.MainWindowViewModel? _mainWindowViewModel;

        public InterceptSuiteInterceptor(InterceptSuite.ViewModels.MainWindowViewModel? mainWindowViewModel = null)
        {
            _mainWindowViewModel = mainWindowViewModel;
        }

        public string ExtensionName => _extensionName ?? throw new InvalidOperationException("Extension name not set. Call set_extension_name() first.");
        public string ExtensionVersion => _extensionVersion ?? throw new InvalidOperationException("Extension version not set. Call set_extension_version() first.");

        public void set_extension_name(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Extension name cannot be null or empty");

            _extensionName = name;
        }

        public void set_extension_version(string version)
        {
            if (string.IsNullOrWhiteSpace(version))
                throw new ArgumentException("Extension version cannot be null or empty");

            _extensionVersion = version;
        }

        /// <summary>
        /// Gets the InterceptSuite application version information
        /// </summary>
        /// <returns>Version string in format "major.minor.build"</returns>
        public string get_interceptsuite_version()
        {
            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                var version = assembly.GetName().Version;
                if (version != null)
                {
                    return $"{version.Major}.{version.Minor}.{version.Build}";
                }
            }
            catch
            {
            }

            return "1.1.0";
        }

        public void AddDataViewerTab(string tabName, PyObject pythonHandler)
        {
            if (string.IsNullOrWhiteSpace(tabName))
                throw new ArgumentException("Tab name cannot be null or empty");

            if (pythonHandler == null)
                throw new ArgumentNullException(nameof(pythonHandler));

            // Validate that extension name and version are set first
            if (_extensionName == null || _extensionVersion == null)
                throw new InvalidOperationException("Extension must call set_extension_name() and set_extension_version() before registering data viewer tabs");

            // Validate that the Python handler implements required methods
            if (!DataViewerAPI.ValidateDataViewerHandler(pythonHandler))
            {
                var handlerInfo = DataViewerAPI.GetHandlerInfo(pythonHandler);
                throw new InvalidOperationException($"Python handler does not implement required data viewer methods. {handlerInfo}. Required: {DataViewerAPI.FetchDataMethodName}");
            }

            if (_mainWindowViewModel != null)
            {
                _mainWindowViewModel.RegisterExtensionDataViewerTab(tabName, _extensionName, pythonHandler);
            }
            else
            {
                ExtensionLogger.Log("Warning: MainWindowViewModel is null, cannot register data viewer tab in UI");
            }
        }

        public void UnloadExtension()
        {
            if (_mainWindowViewModel != null && _extensionName != null)
            {
                _mainWindowViewModel.RemoveExtensionDataViewerTabs(_extensionName);
                ExtensionLogger.Log($"Cleaned up data viewer tabs for extension '{_extensionName}'");
            }
        }

        internal PyObject ToPython()
        {
            using (Py.GIL())
            {
                return PyObject.FromManagedObject(this);
            }
        }
    }
}
