using System;
using System.Collections.Generic;
using Python.Runtime;
using InterceptSuite.Models;
using InterceptSuite.Extensions.APIs.Logging;

namespace InterceptSuite.Extensions.APIs.DataViewer
{
    /// <summary>
    /// API for extension data viewer functionality.
    /// Extensions should implement the required methods to participate in data viewing.
    /// </summary>
    public static class DataViewerAPI
    {
        /// <summary>
        /// Standard method name that extensions should implement to determine tab visibility
        /// </summary>
        public const string ShouldShowTabMethodName = "should_show_tab";

        /// <summary>
        /// Standard method name that extensions should implement to process and display data
        /// </summary>
        public const string FetchDataMethodName = "fetchdata";

        /// <summary>
        /// Standard method name that extensions should implement to update/encode modified data
        /// </summary>
        public const string UpdateDataMethodName = "updatedata";

        /// <summary>
        /// Checks if an extension tab should be visible for the given data context
        /// </summary>
        /// <param name="pythonHandler">The Python extension handler object</param>
        /// <param name="dataContext">The data context to evaluate</param>
        /// <param name="extensionName">Name of the extension (for logging)</param>
        /// <returns>True if the tab should be visible, false otherwise</returns>
        public static bool ShouldShowTab(PyObject pythonHandler, ExtensionDataContext dataContext, string extensionName)
        {
            try
            {
                using (Py.GIL())
                {
                    if (pythonHandler.HasAttr(ShouldShowTabMethodName))
                    {
                        using (var pythonDict = CreateDataDict(dataContext))
                        using (var result = pythonHandler.InvokeMethod(ShouldShowTabMethodName, pythonDict))
                        {
                            return result?.IsTrue() ?? false;
                        }
                    }
                    return true; // Default to visible if method not implemented
                }
            }
            catch (Exception ex)
            {
                ExtensionLogger.Log($"Error checking tab visibility for extension '{extensionName}': {ex.Message}");
                return true; // Default to visible on error
            }
        }

        /// <summary>
        /// Processes data using the extension's data viewer functionality
        /// </summary>
        /// <param name="pythonHandler">The Python extension handler object</param>
        /// <param name="dataContext">The data context to process</param>
        /// <param name="extensionName">Name of the extension (for logging)</param>
        /// <returns>The processed data as a string</returns>
        public static string ProcessData(PyObject pythonHandler, ExtensionDataContext dataContext, string extensionName)
        {
            try
            {
                using (Py.GIL())
                {
                    if (!pythonHandler.HasAttr(FetchDataMethodName))
                        return $"Error: Extension '{extensionName}' does not implement required '{FetchDataMethodName}' method";

                    using (var pythonDict = CreateDataDict(dataContext))
                    using (var result = pythonHandler.InvokeMethod(FetchDataMethodName, pythonDict))
                    {
                        return result?.ToString() ?? "Extension returned no data";
                    }
                }
            }
            catch (Exception ex)
            {
                ExtensionLogger.Log($"Error processing data in extension '{extensionName}': {ex.Message}");
                return $"Error processing data: {ex.Message}";
            }
        }

        /// <summary>
        /// Updates data using the extension's data encoding functionality
        /// </summary>
        /// <param name="pythonHandler">The Python extension handler object</param>
        /// <param name="dataContext">The original data context</param>
        /// <param name="editedData">The edited/modified data from the extension tab</param>
        /// <param name="extensionName">Name of the extension (for logging)</param>
        /// <returns>The encoded/updated data that should replace the original raw data</returns>
        public static string UpdateData(PyObject pythonHandler, ExtensionDataContext dataContext, string editedData, string extensionName)
        {
            try
            {
                using (Py.GIL())
                {
                    if (!pythonHandler.HasAttr(UpdateDataMethodName))
                        return dataContext.Data ?? ""; // Return original data if no update method

                    using (var pythonDict = CreateDataDict(dataContext))
                    {
                        // Add the edited data to the dictionary
                        pythonDict["edited_data"] = new PyString(editedData ?? "");

                        using (var result = pythonHandler.InvokeMethod(UpdateDataMethodName, pythonDict))
                        {
                            return result?.ToString() ?? dataContext.Data ?? "";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                ExtensionLogger.Log($"Error updating data in extension '{extensionName}': {ex.Message}");
                return dataContext.Data ?? ""; // Return original data on error
            }
        }

        /// <summary>
        /// Creates a Python dictionary with data context information for extensions
        /// </summary>
        /// <param name="dataContext">The data context to convert</param>
        /// <returns>A Python dictionary containing the data context</returns>
        private static PyDict CreateDataDict(ExtensionDataContext dataContext)
        {
            var pythonDict = new PyDict();
            pythonDict["ip"] = new PyString(dataContext.SourceIP ?? "");
            pythonDict["destination_ip"] = new PyString(dataContext.DestinationIP ?? "");
            pythonDict["source_port"] = new PyInt(dataContext.SourcePort);
            pythonDict["destination_port"] = new PyInt(dataContext.DestinationPort);
            pythonDict["direction"] = new PyString(dataContext.Direction ?? "");
            pythonDict["length"] = new PyInt(dataContext.Length);
            pythonDict["data"] = new PyString(dataContext.Data ?? "");
            pythonDict["type"] = new PyString(dataContext.Type ?? "");
            pythonDict["timestamp"] = new PyString(dataContext.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"));
            pythonDict["connection_id"] = new PyInt(dataContext.ConnectionId);
            pythonDict["is_editable"] = PyObject.FromManagedObject(dataContext.IsEditable);
            pythonDict["editable_data"] = new PyString(dataContext.EditableData ?? "");
            return pythonDict;
        }

        /// <summary>
        /// Validates that a Python handler implements the required data viewer methods
        /// </summary>
        /// <param name="pythonHandler">The Python handler to validate</param>
        /// <returns>True if the handler implements required methods, false otherwise</returns>
        public static bool ValidateDataViewerHandler(PyObject pythonHandler)
        {
            if (pythonHandler == null)
                return false;

            try
            {
                using (Py.GIL())
                {
                    // FetchData method is required for data viewer functionality
                    return pythonHandler.HasAttr(FetchDataMethodName);
                }
            }
            catch (Exception ex)
            {
                ExtensionLogger.Log($"Error validating data viewer handler: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Gets information about what methods a Python handler implements
        /// </summary>
        /// <param name="pythonHandler">The Python handler to inspect</param>
        /// <returns>String describing the implemented methods</returns>
        public static string GetHandlerInfo(PyObject pythonHandler)
        {
            if (pythonHandler == null)
                return "Handler is null";

            try
            {
                using (Py.GIL())
                {
                    var info = "Implemented methods: ";
                    var methods = new List<string>();

                    if (pythonHandler.HasAttr(FetchDataMethodName))
                        methods.Add(FetchDataMethodName);

                    if (pythonHandler.HasAttr(ShouldShowTabMethodName))
                        methods.Add(ShouldShowTabMethodName);

                    if (pythonHandler.HasAttr(UpdateDataMethodName))
                        methods.Add(UpdateDataMethodName);

                    return info + (methods.Count > 0 ? string.Join(", ", methods) : "none");
                }
            }
            catch (Exception ex)
            {
                ExtensionLogger.Log($"Error getting handler info: {ex.Message}");
                return "Error inspecting handler";
            }
        }
    }
}
