using System;
using Python.Runtime;
using InterceptSuite.Models;
using InterceptSuite.Extensions.APIs.DataViewer;

namespace InterceptSuite.ViewModels
{
    /// <summary>
    /// Represents a custom data viewer tab registered by an extension
    /// </summary>
    public class ExtensionDataViewerTab
    {
        public string TabName { get; }
        public string ExtensionName { get; }
        public PyObject PythonHandler { get; }

        public ExtensionDataViewerTab(string tabName, string extensionName, PyObject pythonHandler)
        {
            TabName = tabName;
            ExtensionName = extensionName;
            PythonHandler = pythonHandler;
        }

        public bool ShouldShowTab(ExtensionDataContext dataContext) =>
            DataViewerAPI.ShouldShowTab(PythonHandler, dataContext, ExtensionName);

        public string ProcessData(ExtensionDataContext dataContext) =>
            DataViewerAPI.ProcessData(PythonHandler, dataContext, ExtensionName);

        public string UpdateData(ExtensionDataContext dataContext, string editedData) =>
            DataViewerAPI.UpdateData(PythonHandler, dataContext, editedData, ExtensionName);
    }
}
