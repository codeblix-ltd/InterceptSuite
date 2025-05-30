using InterceptSuite.ViewModels;

namespace InterceptSuite.Models
{
    /// <summary>
    /// Data model for connection events - optimized with base class
    /// </summary>
    public class ConnectionEvent : BaseViewModel
    {
        private string _timestamp = "";
        private string _event = "";
        private int _connectionId;
        private string _sourceIp = "";
        private int _sourcePort;
        private string _destinationIp = "";
        private int _destinationPort;

        public string Timestamp
        {
            get => _timestamp;
            set => SetProperty(ref _timestamp, value);
        }

        public string Event
        {
            get => _event;
            set => SetProperty(ref _event, value);
        }

        public int ConnectionId
        {
            get => _connectionId;
            set => SetProperty(ref _connectionId, value);
        }

        public string SourceIp
        {
            get => _sourceIp;
            set => SetProperty(ref _sourceIp, value);
        }

        public int SourcePort
        {
            get => _sourcePort;
            set => SetProperty(ref _sourcePort, value);
        }

        public string DestinationIp
        {
            get => _destinationIp;
            set => SetProperty(ref _destinationIp, value);
        }

        public int DestinationPort
        {
            get => _destinationPort;
            set => SetProperty(ref _destinationPort, value);
        }
    }
}
