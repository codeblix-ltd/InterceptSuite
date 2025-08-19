using System;

namespace InterceptSuite.Models
{
    public sealed class LogEntry
    {
        public DateTime Timestamp { get; }
        public string Message { get; }
        public string EventType { get; }
        private readonly string _formattedTimestamp;

        public LogEntry(string message) : this(message, "Info")
        {
        }

        public LogEntry(string message, string eventType)
        {
            Timestamp = DateTime.Now;
            Message = string.IsInterned(message) ?? message;
            EventType = eventType ?? "Info";
            _formattedTimestamp = Timestamp.ToString("dd/MM/yyyy, h:mm:ss tt");
        }

        public LogEntry(DateTime timestamp, string message) : this(timestamp, message, "Info")
        {
        }

        public LogEntry(DateTime timestamp, string message, string eventType)
        {
            Timestamp = timestamp;
            Message = string.IsInterned(message) ?? message;
            EventType = eventType ?? "Info";
            _formattedTimestamp = timestamp.ToString("dd/MM/yyyy, h:mm:ss tt");
        }

        public string FormattedTimestamp => _formattedTimestamp;

        public override string ToString() => $"[{FormattedTimestamp}] {Message}";
    }
}
