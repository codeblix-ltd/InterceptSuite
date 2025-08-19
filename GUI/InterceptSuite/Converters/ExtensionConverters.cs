using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace InterceptSuite.Converters;

public class BoolToStatusColorConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool isLoaded)
        {
            return isLoaded ? new SolidColorBrush(Color.Parse("#4CAF50")) : new SolidColorBrush(Color.Parse("#f44336"));
        }
        return new SolidColorBrush(Color.Parse("#A0A0A0"));
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public class BoolToToggleTextConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool isLoaded)
        {
            return isLoaded ? "Disable" : "Enable";
        }
        return "Toggle";
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
