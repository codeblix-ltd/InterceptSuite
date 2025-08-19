using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace InterceptSuite.Converters
{
    public class StatusMessageColorConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is string message && !string.IsNullOrEmpty(message))
            {
                // Check the first character or prefix to determine color
                if (message.StartsWith("✓") || message.Contains("successfully"))
                {
                    return new SolidColorBrush(Color.FromRgb(34, 197, 94));   // Green for success
                }
                else if (message.StartsWith("✗") || message.StartsWith("ERROR") || message.Contains("failed") || message.Contains("error"))
                {
                    return new SolidColorBrush(Color.FromRgb(239, 68, 68));   // Red for error
                }
                else if (message.StartsWith("⚠") || message.StartsWith("WARNING") || message.Contains("warning"))
                {
                    return new SolidColorBrush(Color.FromRgb(255, 215, 0));   // Gold for warning
                }
                else
                {
                    return new SolidColorBrush(Color.FromRgb(96, 165, 250));  // Blue for info/default
                }
            }

            return new SolidColorBrush(Color.FromRgb(226, 232, 240)); // Default light gray
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
