using System;
using CommunityToolkit.Mvvm.ComponentModel;

namespace InterceptSuite.Models
{
    public partial class ProxyEntry : ObservableObject
    {
        public int Index { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public int ConnectionId { get; set; }
        public int PacketId { get; set; }
        public string SourceIp { get; set; } = string.Empty;
        public string DestinationIp { get; set; } = string.Empty;
        public int DestinationPort { get; set; }
        public string Direction { get; set; } = string.Empty;
        public string Protocol { get; set; } = string.Empty;
        public string MessageType { get; set; } = string.Empty;

        [ObservableProperty]
        private string _modified = "No";

        public byte[] RawData { get; set; } = Array.Empty<byte>();

        [ObservableProperty]
        private byte[] _editedData = Array.Empty<byte>();

        partial void OnModifiedChanged(string value)
        {
            OnPropertyChanged(nameof(HasEditedData));
        }

        partial void OnEditedDataChanged(byte[] value)
        {
            OnPropertyChanged(nameof(HasEditedData));
            OnPropertyChanged(nameof(EditedDataAsString));
        }

        public int Size => RawData?.Length ?? 0;

        public string FormattedTimestamp => Timestamp.ToString("dd/MM/yyyy, HH:mm:ss");

        public string RawDataAsString => RawData.Length > 0
            ? System.Text.Encoding.UTF8.GetString(RawData)
            : string.Empty;

        public string EditedDataAsString => EditedData.Length > 0
            ? System.Text.Encoding.UTF8.GetString(EditedData)
            : string.Empty;

        public bool HasEditedData => EditedData.Length > 0 && Modified == "Yes";

        public ProxyEntry(DateTime timestamp, int connectionId, int packetId,
                         string direction, string sourceIp, string destinationIp, int destinationPort,
                         string protocol, string messageType, byte[] data)
        {
            Timestamp = timestamp;
            ConnectionId = connectionId;
            PacketId = packetId;
            Direction = direction;
            SourceIp = sourceIp;
            DestinationIp = destinationIp;
            DestinationPort = destinationPort;
            Protocol = protocol;
            MessageType = messageType;
            RawData = data ?? Array.Empty<byte>();
        }

        public ProxyEntry()
        {
        }
    }
}
