using Avalonia.Controls;
using Avalonia.Interactivity;
using InterceptSuite.ViewModels;
using System.ComponentModel;
using Avalonia.Input;

namespace InterceptSuite.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnMainWindowLoaded;
    }

    private async void OnMainWindowLoaded(object? sender, RoutedEventArgs e)
    {
        if (DataContext is MainWindowViewModel viewModel)
        {
            await viewModel.InitializeExtensionsAsync();

            // Subscribe to property changes for auto-scroll functionality
            viewModel.PropertyChanged += OnViewModelPropertyChanged;
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainWindowViewModel.LogText) && DataContext is MainWindowViewModel viewModel)
        {
            if (viewModel.AutoScrollToBottom)
            {
                // Scroll to bottom for both text boxes
                var logsTextBox = this.FindControl<TextBox>("LogsTextBox");
                if (logsTextBox != null)
                {
                    // Schedule the scroll to happen after the UI updates
                    Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                    {
                        logsTextBox.CaretIndex = logsTextBox.Text?.Length ?? 0;
                    });
                }
            }
        }
    }

    private void CertificateRadio_Checked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is MainWindowViewModel viewModel)
        {
            viewModel.ExportType = 0;
        }
    }

    private void PrivateKeyRadio_Checked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is MainWindowViewModel viewModel)
        {
            viewModel.ExportType = 1;
        }
    }

    /// <summary>
    /// Handle KeyDown events for ProxyHistory DataGrid with shortcuts
    /// </summary>
    private void OnProxyHistoryKeyDown(object? sender, KeyEventArgs e)
    {
        if (sender is DataGrid dataGrid && DataContext is MainWindowViewModel viewModel)
        {
            if (e.Key == Key.A && e.KeyModifiers == KeyModifiers.Control)
            {
                dataGrid.SelectAll();
                e.Handled = true;
            }
            else if (e.Key == Key.Delete && dataGrid.SelectedItems.Count > 0)
            {
                if (viewModel.RemoveSelectedProxyEntriesCommand?.CanExecute(null) == true)
                {
                    viewModel.RemoveSelectedProxyEntriesCommand.Execute(null);
                }
                e.Handled = true;
            }
        }
    }

    /// <summary>
    /// Handle KeyDown events for Connections DataGrid with  shortcuts
    /// </summary>
    private void OnConnectionsKeyDown(object? sender, KeyEventArgs e)
    {
        if (sender is DataGrid dataGrid && DataContext is MainWindowViewModel viewModel)
        {
            if (e.Key == Key.A && e.KeyModifiers == KeyModifiers.Control)
            {
                dataGrid.SelectAll();
                e.Handled = true;
            }
            else if (e.Key == Key.Delete && dataGrid.SelectedItems.Count > 0)
            {
                if (viewModel.RemoveSelectedConnectionEntriesCommand?.CanExecute(null) == true)
                {
                    viewModel.RemoveSelectedConnectionEntriesCommand.Execute(null);
                }
                e.Handled = true;
            }
        }
    }

    /// <summary>
    /// Handle proxy history DataGrid selection changes
    /// </summary>
    private void OnProxyHistorySelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (sender is DataGrid dataGrid && DataContext is MainWindowViewModel viewModel)
        {
            // Update the ViewModel's SelectedProxyEntries collection
            viewModel.SelectedProxyEntries.Clear();
            foreach (var item in dataGrid.SelectedItems)
            {
                if (item is Models.ProxyEntry proxyEntry)
                {
                    viewModel.SelectedProxyEntries.Add(proxyEntry);
                }
            }
        }
    }

    /// <summary>
    /// Handle connections DataGrid selection changes
    /// </summary>
    private void OnConnectionsSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (sender is DataGrid dataGrid && DataContext is MainWindowViewModel viewModel)
        {
            // Update the ViewModel's SelectedConnectionEntries collection
            viewModel.SelectedConnectionEntries.Clear();
            foreach (var item in dataGrid.SelectedItems)
            {
                if (item is Models.ConnectionEntry connectionEntry)
                {
                    viewModel.SelectedConnectionEntries.Add(connectionEntry);
                }
            }
        }
    }
}