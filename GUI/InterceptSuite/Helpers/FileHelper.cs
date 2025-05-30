using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using InterceptSuite.Models;

namespace InterceptSuite.Helpers
{
    /// <summary>
    /// Helper class for common file operations and exports
    /// Reduces code duplication across the application
    /// </summary>
    public static class FileHelper
    {
        /// <summary>
        /// Shows a save file dialog and exports data to CSV
        /// </summary>
        /// <typeparam name="T">Type of data to export</typeparam>
        /// <param name="data">Collection of data to export</param>
        /// <param name="headers">CSV headers</param>
        /// <param name="dataSelector">Function to convert data item to CSV line</param>
        /// <param name="defaultFileName">Default filename for the save dialog</param>
        /// <param name="statusCallback">Callback to report status messages</param>
        /// <returns>True if export was successful, false otherwise</returns>
        public static bool ExportToCsv<T>(
            IEnumerable<T> data,
            string headers,
            Func<T, string> dataSelector,
            string defaultFileName,
            Action<string> statusCallback)
        {
            var saveFileDialog = new SaveFileDialog
            {
                Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
                DefaultExt = ".csv",
                FileName = defaultFileName
            };

            if (saveFileDialog.ShowDialog() != true)
                return false;

            try
            {
                using var writer = new StreamWriter(saveFileDialog.FileName);
                writer.WriteLine(headers);

                foreach (var item in data)
                {
                    writer.WriteLine(dataSelector(item));
                }

                statusCallback($"[SYSTEM] Data exported to {saveFileDialog.FileName}");
                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export data: {ex.Message}",
                               "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                statusCallback($"[ERROR] Export failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Shows a save file dialog for log files
        /// </summary>
        /// <param name="currentPath">Current path in the textbox</param>
        /// <returns>Selected file path or null if cancelled</returns>
        public static string? BrowseForLogFile(string currentPath)
        {
            var saveFileDialog = new SaveFileDialog
            {
                Filter = "Log files (*.log)|*.log|All files (*.*)|*.*",
                DefaultExt = ".log",
                FileName = currentPath
            };

            return saveFileDialog.ShowDialog() == true ? saveFileDialog.FileName : null;
        }

        /// <summary>
        /// Generates a timestamped filename for exports
        /// </summary>
        /// <param name="prefix">Filename prefix</param>
        /// <param name="extension">File extension (with dot)</param>
        /// <returns>Timestamped filename</returns>
        public static string GenerateTimestampedFilename(string prefix, string extension)
        {
            return $"{prefix}_{DateTime.Now:yyyyMMdd_HHmmss}{extension}";
        }
    }
}
