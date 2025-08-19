using System;

namespace InterceptSuite.Models
{
    public sealed class ConnectionEntry
    {
        public DateTime Timestamp { get; }
        public string Event { get; }
        public int ConnectionId { get; }
        public string SourceIp { get; }
        public int SourcePort { get; }
        public string DestinationIp { get; }
        public int DestinationPort { get; }
        public string? AdditionalInfo { get; }

        private readonly string _formattedTimestamp;

        public ConnectionEntry(string clientIp, int clientPort, string targetHost, int targetPort, int connectionId)
        {
            Timestamp = DateTime.Now;
            Event = "CONNECTED";
            ConnectionId = connectionId;
            SourceIp = clientIp;
            SourcePort = clientPort;
            DestinationIp = targetHost;
            DestinationPort = targetPort;
            AdditionalInfo = null;
            _formattedTimestamp = Timestamp.ToString("dd/MM/yyyy, h:mm:ss tt");
        }

        public ConnectionEntry(int connectionId, string reason)
        {
            Timestamp = DateTime.Now;
            Event = "DISCONNECTED";
            ConnectionId = connectionId;
            SourceIp = "";
            SourcePort = 0;
            DestinationIp = reason == "Connection closed" ? "Connection closed" : "";
            DestinationPort = 0;
            AdditionalInfo = reason;
            _formattedTimestamp = Timestamp.ToString("dd/MM/yyyy, h:mm:ss tt");
        }

        public string FormattedTimestamp => _formattedTimestamp;

        public override string ToString() => $"[{FormattedTimestamp}] {Event} - Connection {ConnectionId}: {SourceIp}:{SourcePort} -> {DestinationIp}:{DestinationPort}";
    }
}
