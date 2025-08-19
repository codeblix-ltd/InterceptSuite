using Avalonia.Controls;
using Avalonia.Interactivity;
using InterceptSuite.ViewModels;

namespace InterceptSuite.Views.Components;

public partial class ExtensionsView : UserControl
{
    public ExtensionsView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object? sender, RoutedEventArgs e)
    {
        if (DataContext is ExtensionsViewModel viewModel)
        {
            await viewModel.EnsureInitializedAsync();
        }
    }

    private void ClearOutput_Click(object? sender, RoutedEventArgs e)
    {
        if (DataContext is ExtensionsViewModel viewModel)
        {
            viewModel.ClearConsoleCommand.Execute(null);
        }
    }
}
