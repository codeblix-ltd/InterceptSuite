using InterceptSuite.ViewModels;

namespace InterceptSuite.Models
{
    /// <summary>
    /// Data model for log events - optimized with base class
    /// </summary>
    public class LogEvent : BaseViewModel
    {
        private string _timestamp = "";
        private string _sourceIp = "";
        private string _destinationIp = "";
        private int _port;
        private string _type = "";
        private string _data = "";
        private string _originalData = "";
        private bool _wasModified = false;

        public string Timestamp
        {
            get => _timestamp;
            set => SetProperty(ref _timestamp, value);
        }

        public string SourceIp
        {
            get => _sourceIp;
            set => SetProperty(ref _sourceIp, value);
        }

        public string DestinationIp
        {
            get => _destinationIp;
            set => SetProperty(ref _destinationIp, value);
        }

        public int Port
        {
            get => _port;
            set => SetProperty(ref _port, value);
        }

        public string Type
        {
            get => _type;
            set => SetProperty(ref _type, value);
        }

        public string Data
        {
            get => _data;
            set => SetProperty(ref _data, value);
        }

        public string OriginalData
        {
            get => _originalData;
            set => SetProperty(ref _originalData, value);
        }

        public bool WasModified
        {
            get => _wasModified;
            set
            {
                if (SetProperty(ref _wasModified, value))
                {
                    OnPropertyChanged(nameof(ModifiedIndicator));
                }
            }
        }

        public string ModifiedIndicator => WasModified ? "✓" : "";
    }
}
