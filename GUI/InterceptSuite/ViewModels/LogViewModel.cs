using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using InterceptSuite.Models;

namespace InterceptSuite.ViewModels
{
    public partial class LogViewModel : ViewModelBase
    {
        private readonly MainWindowViewModel _mainViewModel;

        [ObservableProperty] private ObservableCollection<LogEntry> _logs;
        [ObservableProperty] private string _searchQuery = string.Empty;
        [ObservableProperty] private bool _autoScrollToBottom = true;

        public LogViewModel(MainWindowViewModel mainViewModel)
        {
            _mainViewModel = mainViewModel;
            _logs = mainViewModel.LogEntries;
        }

        [RelayCommand] private void ClearLogs() => _mainViewModel.ClearLogsCommand.Execute(null);
        [RelayCommand] private void Search() => _mainViewModel.SearchCommand.Execute(null);
    }
}
