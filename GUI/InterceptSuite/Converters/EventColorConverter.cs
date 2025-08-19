using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace InterceptSuite.Converters
{
    public class EventColorConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is string eventType)
            {
                return eventType.ToUpperInvariant() switch
                {
                    "CONNECTED" => new SolidColorBrush(Color.FromRgb(34, 197, 94)),   // Green
                    "DISCONNECTED" => new SolidColorBrush(Color.FromRgb(239, 68, 68)), // Red
                    "DISCONNECT" => new SolidColorBrush(Color.FromRgb(239, 68, 68)),   // Red
                    _ => new SolidColorBrush(Color.FromRgb(226, 232, 240))              // Default light gray
                };
            }

            return new SolidColorBrush(Color.FromRgb(226, 232, 240)); // Default
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
