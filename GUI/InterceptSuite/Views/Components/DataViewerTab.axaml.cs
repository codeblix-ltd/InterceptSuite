using System;
using Avalonia;
using Avalonia.Controls;
using CommunityToolkit.Mvvm.ComponentModel;

namespace InterceptSuite.Views.Components
{
    public partial class DataViewerTab : UserControl
    {
        public static readonly StyledProperty<byte[]?> RawDataProperty =
            AvaloniaProperty.Register<DataViewerTab, byte[]?>(nameof(RawData));

        public static readonly StyledProperty<bool> IsEditableProperty =
            AvaloniaProperty.Register<DataViewerTab, bool>(nameof(IsEditable), false);

        public static readonly StyledProperty<string> TitleProperty =
            AvaloniaProperty.Register<DataViewerTab, string>(nameof(Title), "Data Viewer");

        public byte[]? RawData
        {
            get => GetValue(RawDataProperty);
            set => SetValue(RawDataProperty, value);
        }

        public bool IsEditable
        {
            get => GetValue(IsEditableProperty);
            set => SetValue(IsEditableProperty, value);
        }

        public string Title
        {
            get => GetValue(TitleProperty);
            set => SetValue(TitleProperty, value);
        }

        private DataViewerTabViewModel? _viewModel;

        public DataViewerTab()
        {
            InitializeComponent();
            _viewModel = new DataViewerTabViewModel();
            DataContext = _viewModel;

            this.PropertyChanged += DataViewerTab_PropertyChanged;
        }

        private void DataViewerTab_PropertyChanged(object? sender, AvaloniaPropertyChangedEventArgs e)
        {
            if (_viewModel == null) return;

            if (e.Property == RawDataProperty)
            {
                var rawData = e.NewValue as byte[];
                if (rawData != null)
                    _viewModel.SetRawDataFromBytes(rawData);
                else
                    _viewModel.ClearData();
            }
            else if (e.Property == IsEditableProperty)
            {
                _viewModel.SetEditable((bool)e.NewValue!);
            }
            else if (e.Property == TitleProperty)
            {
                _viewModel.SetTitle((string)e.NewValue!);
            }
        }
    }

    public partial class DataViewerTabViewModel : ObservableObject
    {
        [ObservableProperty]
        private string _rawData = string.Empty;

        [ObservableProperty]
        private bool _isEditable = false;

        [ObservableProperty]
        private string _title = "Data Viewer";

        [ObservableProperty]
        private string _emptyMessage = "Select an item above to view its data...";

        public void SetRawData(string data)
        {
            RawData = data ?? string.Empty;
        }

        public void SetRawDataFromBytes(byte[] data)
        {
            if (data != null && data.Length > 0)
            {
                try
                {
                    var dataString = System.Text.Encoding.UTF8.GetString(data);
                    SetRawData(dataString);
                }
                catch (Exception)
                {
                    SetRawData($"<Binary data: {data.Length} bytes>");
                }
            }
            else
            {
                ClearData();
            }
        }

        public void ClearData()
        {
            RawData = string.Empty;
        }

        public void SetEditable(bool editable)
        {
            IsEditable = editable;
        }

        public void SetTitle(string title)
        {
            Title = title ?? "Data Viewer";
        }

        public void SetEmptyMessage(string message)
        {
            EmptyMessage = message ?? "Select an item above to view its data...";
        }

        public byte[] GetEditedDataAsBytes()
        {
            if (string.IsNullOrEmpty(RawData))
                return Array.Empty<byte>();

            return System.Text.Encoding.UTF8.GetBytes(RawData);
        }
    }
}
