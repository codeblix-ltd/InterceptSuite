using System;

namespace InterceptSuite.Models
{
    public class ExtensionDataContext
    {
        public string? SourceIP { get; set; }
        public string? DestinationIP { get; set; }
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public string? Direction { get; set; }
        public int Length { get; set; }
        public string? Data { get; set; }
        public byte[]? RawData { get; set; }
        public string? Type { get; set; }
        public DateTime Timestamp { get; set; }
        public int ConnectionId { get; set; }
        public int PacketId { get; set; }

        // For intercept entries
        public bool IsEditable { get; set; }
        public string? EditableData { get; set; }

        public ExtensionDataContext(ExtensionDataContext other)
        {
            SourceIP = other.SourceIP;
            DestinationIP = other.DestinationIP;
            SourcePort = other.SourcePort;
            DestinationPort = other.DestinationPort;
            Direction = other.Direction;
            Length = other.Length;
            Data = other.Data;
            RawData = other.RawData;
            Type = other.Type;
            Timestamp = other.Timestamp;
            ConnectionId = other.ConnectionId;
            PacketId = other.PacketId;
            IsEditable = other.IsEditable;
            EditableData = other.EditableData;
        }

        public ExtensionDataContext()
        {
        }
    }
}
