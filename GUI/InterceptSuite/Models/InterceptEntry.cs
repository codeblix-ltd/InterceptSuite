using System;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;

namespace InterceptSuite.Models
{
    public partial class InterceptEntry : ObservableObject
    {
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public int ConnectionId { get; set; }
        public int PacketId { get; set; }
        public string SourceIp { get; set; } = string.Empty;
        public string DestinationIp { get; set; } = string.Empty;
        public int DestinationPort { get; set; }
        public int SourcePort { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public string MessageType { get; set; } = string.Empty;
        public byte[] RawData { get; set; } = Array.Empty<byte>();

        public string Status { get; set; } = "Pending";
        public bool IsModified { get; set; } = false;
        public string Direction { get; set; } = string.Empty;
        public int Size => RawData?.Length ?? 0;

        public string FormattedTimestamp => Timestamp.ToString("dd/MM/yyyy, HH:mm:ss");
        public string Destination => $"{DestinationIp}:{DestinationPort}";
        public string HeaderInfo => $"Connection {ConnectionId} | Packet {PacketId} | {Protocol} | {Direction} | {Size} bytes";

        public string RawDataAsString => RawData.Length > 0
            ? System.Text.Encoding.UTF8.GetString(RawData)
            : string.Empty;

        [ObservableProperty]
        private string _editableData = string.Empty;

        partial void OnEditableDataChanged(string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                string originalDataAsString = RawData.Length > 0
                    ? System.Text.Encoding.UTF8.GetString(RawData)
                    : string.Empty;

                var oldData = RawData;
                byte[] newData = System.Text.Encoding.UTF8.GetBytes(value);

                bool isActuallyModified = !RawData.SequenceEqual(newData);

                if (isActuallyModified)
                {
                    RawData = newData;
                    IsModified = true;
                }
                else
                {
                    IsModified = false;
                }
            }
        }

        public void SyncEditableData()
        {
            EditableData = RawDataAsString;
        }

        public InterceptEntry(int connectionId, int packetId,
                            string sourceIp, string destinationIp, int destinationPort,
                            string protocol, string messageType, byte[] data, string direction = "", int sourcePort = 0)
        {
            Timestamp = DateTime.Now;
            ConnectionId = connectionId;
            PacketId = packetId;
            SourceIp = sourceIp;
            DestinationIp = destinationIp;
            DestinationPort = destinationPort;
            SourcePort = sourcePort;
            Protocol = protocol;
            MessageType = messageType;
            RawData = data ?? Array.Empty<byte>();
            Direction = direction;
            Status = "Intercepted - Waiting for action";
            EditableData = RawDataAsString;
        }

        public InterceptEntry()
        {
        }
    }
}
