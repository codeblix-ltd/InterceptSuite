using System;
using System.Text;

namespace InterceptSuite.Helpers
{
    /// <summary>
    /// Helper class for data formatting and validation
    /// Reduces code duplication in data processing
    /// </summary>
    public static class DataHelper
    {        /// <summary>
        /// Formats data size information for display
        /// </summary>
        /// <param name="data">Data string to analyze</param>
        /// <returns>Human-readable size description</returns>
        public static string GetDataSizeDescription(string data)
        {
            if (string.IsNullOrEmpty(data))
                return "0 bytes";

            int length = data.Length;
            bool isTruncated = data.EndsWith("...(truncated)");

            return isTruncated
                ? $"{length} bytes (truncated)"
                : $"{length} bytes";
        }

        /// <summary>
        /// Formats data size information for display with byte count analysis
        /// </summary>
        /// <param name="data">Data string to analyze</param>
        /// <returns>Human-readable size description with units</returns>
        public static string GetDataSizeDescriptionWithUnits(string data)
        {
            if (string.IsNullOrEmpty(data))
                return "0 bytes";

            int byteCount = Encoding.UTF8.GetByteCount(data);
            
            return byteCount switch
            {
                0 => "0 bytes",
                1 => "1 byte",
                < 1024 => $"{byteCount} bytes",
                < 1024 * 1024 => $"{byteCount / 1024.0:F1} KB",
                _ => $"{byteCount / (1024.0 * 1024.0):F1} MB"
            };
        }

        /// <summary>
        /// Validates and sanitizes input data
        /// </summary>
        /// <param name="input">Input string to validate</param>
        /// <param name="fallback">Fallback value if input is null or empty</param>
        /// <returns>Sanitized string</returns>
        public static string ValidateString(string? input, string fallback = "")
        {
            return string.IsNullOrEmpty(input) ? fallback : input;
        }

        /// <summary>
        /// Safely converts data to UTF-8 text with fallback to hex
        /// </summary>
        /// <param name="data">Byte array to convert</param>
        /// <returns>Text representation of the data</returns>
        public static string SafeToText(byte[] data)
        {
            if (data == null || data.Length == 0)
                return "";

            try
            {
                return Encoding.UTF8.GetString(data);
            }
            catch
            {
                return BitConverter.ToString(data).Replace("-", " ");
            }
        }

        /// <summary>
        /// Converts byte array to hex string representation
        /// </summary>
        /// <param name="data">Byte array to convert</param>
        /// <returns>Hex string representation</returns>
        public static string ToHexString(byte[] data)
        {
            if (data == null || data.Length == 0)
                return "";

            try
            {
                return BitConverter.ToString(data).Replace("-", " ");
            }
            catch
            {
                return "[Error displaying hex data]";
            }
        }

        /// <summary>
        /// Formats intercept direction for display
        /// </summary>
        /// <param name="direction">Direction code</param>
        /// <returns>Human-readable direction string</returns>
        public static string FormatInterceptDirection(int direction)
        {
            return direction switch
            {
                0 => "None",
                1 => "Client → Server",
                2 => "Server → Client",
                3 => "Both directions",
                _ => "Unknown"
            };
        }

        /// <summary>
        /// Determines message type based on direction
        /// </summary>
        /// <param name="direction">Direction string (e.g., "C->S")</param>
        /// <returns>Message type description</returns>
        public static string GetMessageType(string direction)
        {
            return direction switch
            {
                "C->S" => "Request",
                "S->C" => "Response",
                _ => "Modified"
            };
        }
    }
}
