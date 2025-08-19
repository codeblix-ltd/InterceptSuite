using CommunityToolkit.Mvvm.ComponentModel;
using InterceptSuite.Models;
using System;
using System.Threading;

namespace InterceptSuite.ViewModels
{
    public partial class DataViewerTabViewModel : ObservableObject, IDisposable
    {
        public string Name { get; }

        [ObservableProperty]
        private string _content = string.Empty;

        [ObservableProperty]
        private bool _isVisible = true;

        public string Watermark { get; }
        public bool IsExtension { get; private set; }
        public bool IsEditable { get; }
        public ExtensionDataViewerTab? ExtensionTab { get; }

        private string _originalContent = string.Empty;
        private ExtensionDataContext? _currentDataContext;
        private ExtensionDataContext? _editTimeDataContext; // Capture context at edit time

        private Timer? _contentChangeTimer;
        private string _pendingContent = string.Empty;
        private const int DEBOUNCE_DELAY_MS = 100; // Reduced delay for better responsiveness

        public event Action<DataViewerTabViewModel, string>? ContentChanged;

        public DataViewerTabViewModel(string name, string watermark, bool isEditable = false)
        {
            Name = name;
            Watermark = watermark;
            IsExtension = false;
            IsEditable = isEditable;
        }

        public DataViewerTabViewModel(ExtensionDataViewerTab extensionTab, bool isEditable = false)
        {
            Name = extensionTab.TabName;
            Watermark = $"Extension tab '{extensionTab.TabName}' from '{extensionTab.ExtensionName}'";
            IsExtension = true;
            IsEditable = isEditable;
            ExtensionTab = extensionTab;
        }

        public void SetContent(string content, ExtensionDataContext? dataContext = null)
        {
            _originalContent = content;
            _currentDataContext = dataContext;
            Content = content;
        }

        public void SetAsContentBased()
        {
            IsExtension = true;
        }

        partial void OnContentChanged(string value)
        {
            if (IsEditable)
            {
                if (IsExtension && ExtensionTab != null && _currentDataContext != null)
                {
                    // Extension tab handling
                    if (!string.Equals(value, _originalContent, StringComparison.Ordinal))
                    {
                        _pendingContent = value;
                        // Capture the data context at the time of edit to avoid race conditions
                        _editTimeDataContext = _currentDataContext;

                        // Cancel any existing timer
                        _contentChangeTimer?.Dispose();

                        // For simple single character additions, use a shorter delay
                        var delay = Math.Abs(value.Length - _originalContent.Length) <= 1 ? 50 : DEBOUNCE_DELAY_MS;
                        _contentChangeTimer = new Timer(OnContentChangeTimerElapsed, null, delay, Timeout.Infinite);
                    }
                }
                else if (!IsExtension)
                {
                    // Non-extension tab (like Raw Data tab) - fire immediately
                    if (!string.Equals(value, _originalContent, StringComparison.Ordinal))
                    {
                        _pendingContent = value;

                        // Cancel any existing timer
                        _contentChangeTimer?.Dispose();

                        // Fire immediately for raw data changes and update the original content
                        Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
                        {
                            ContentChanged?.Invoke(this, _pendingContent);
                            // Update the original content to prevent repeated firing
                            _originalContent = _pendingContent;
                        });
                    }
                }
            }
        }

        private void OnContentChangeTimerElapsed(object? state)
        {
            Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
            {
                // Use the data context captured at edit time, not the current one
                if (_editTimeDataContext != null)
                {
                    ContentChanged?.Invoke(this, _pendingContent);
                    // Update the original content to prevent repeated firing
                    _originalContent = _pendingContent;
                }
            });
        }

        public ExtensionDataContext? GetCurrentDataContext() => _currentDataContext;

        /// <summary>
        /// Gets the data context that was active when the content was edited
        /// </summary>
        public ExtensionDataContext? GetEditTimeDataContext() => _editTimeDataContext;

        public void Dispose()
        {
            _contentChangeTimer?.Dispose();
            _contentChangeTimer = null;
        }
    }
}
