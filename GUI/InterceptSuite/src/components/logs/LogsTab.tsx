// Logs tab component - displays logs from C DLL through Rust status callback
import React, { useState, useEffect, useMemo, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { DataTable, ContextMenuItem } from '../common';
import { LogEntry } from '../../types/index';
import '../../styles/LogsTab.css';

export const LogsTab: React.FC = () => {
  const [logsData, setLogsData] = useState<LogEntry[]>([]);
  const [searchFilter, setSearchFilter] = useState('');
  const [selectedEntry, setSelectedEntry] = useState<LogEntry | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const tableContainerRef = useRef<HTMLDivElement>(null);

  // Load logs data when component mounts and set up periodic refresh
  useEffect(() => {
    const loadLogs = async () => {
      try {
        // Fetch existing logs from backend
        const data = await invoke('get_logs') as LogEntry[];
        setLogsData(data);

        // Auto-scroll to bottom if enabled
        if (autoScroll && tableContainerRef.current) {
          const scrollContainer = tableContainerRef.current.querySelector('.simple-table-body');
          if (scrollContainer) {
            scrollContainer.scrollTop = scrollContainer.scrollHeight;
          }
        }
      } catch (error) {
        console.error('Failed to load logs:', error);
        setLogsData([]);
      }
    };

    // Initial load
    loadLogs();

    // Set up periodic refresh to get new data from memory storage
    const intervalId = setInterval(() => {
      loadLogs();
    }, 1000); // Refresh every 1 second

    return () => {
      clearInterval(intervalId);
    };
  }, [autoScroll]);

  // Listen for real-time log messages
  useEffect(() => {
    const unlistenLogMessage = listen('log-message', (event) => {
      const message = event.payload as string;
      console.log('Received log message:', message);

      // The logs will be updated through the periodic refresh
      // This is just for debugging and could trigger a faster refresh if needed
    });

    return () => {
      unlistenLogMessage.then(unlisten => unlisten());
    };
  }, []);

  // Filter logs based on search
  const filteredData = useMemo(() => {
    return logsData.filter(entry => {
      const matchesSearch =
        entry.message?.toLowerCase().includes(searchFilter.toLowerCase()) ||
        entry.timestamp?.toLowerCase().includes(searchFilter.toLowerCase());

      return matchesSearch;
    });
  }, [logsData, searchFilter]);

  const columns = [
    {
      key: 'timestamp' as keyof LogEntry,
      header: 'Timestamp',
      width: '200px',
      render: (timestamp: string) => new Date(timestamp).toLocaleString()
    },
    {
      key: 'message' as keyof LogEntry,
      header: 'Message',
      width: 'auto'
    }
  ];

  const handleRowClick = (entry: LogEntry) => {
    setSelectedEntry(entry);
  };

  const handleClearLogs = async (selectedEntries?: LogEntry[]) => {
    try {
      if (selectedEntries && selectedEntries.length > 0 && selectedEntries.length < logsData.length) {
        // Clear only selected entries - call Rust backend with log IDs
        const logIds = selectedEntries.map(entry => entry.id);
        await invoke('clear_selected_logs', { logIds });

        // Update local state
        const selectedIds = new Set(logIds);
        const remainingEntries = logsData.filter(entry => !selectedIds.has(entry.id));
        setLogsData(remainingEntries);
        console.log(`Cleared ${selectedEntries.length} selected log entries from backend`);
      } else {
        // Clear all logs via Rust backend
        await invoke('clear_logs');
        setLogsData([]);
        setSelectedEntry(null);
        console.log('Cleared all logs');
      }
    } catch (error) {
      console.error('Failed to clear logs:', error);
    }
  };

  const getContextMenuItems = (selectedEntries: LogEntry[]): ContextMenuItem[] => {
    const selectedCount = selectedEntries.length;
    const totalCount = logsData.length;

    if (selectedCount === 0) {
      return [
        {
          label: `Clear All (${totalCount} items)`,
          action: () => handleClearLogs(),
          disabled: totalCount === 0
        }
      ];
    }

    return [
      {
        label: selectedCount === 1
          ? 'Clear Selected Item'
          : `Clear ${selectedCount} Selected Items`,
        action: () => handleClearLogs(selectedEntries),
        disabled: false
      },
      {
        label: '',
        action: () => {},
        separator: true
      },
      {
        label: `Clear All (${totalCount} items)`,
        action: () => handleClearLogs(),
        disabled: totalCount === 0
      }
    ];
  };

  return (
    <div className="logs-tab">
      <div className="logs-controls">
        <div className="filter-controls">
          <input
            type="text"
            placeholder="Search logs..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="search-input"
          />
        </div>
        <div className="display-controls">
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
            />
            Auto-scroll to bottom
          </label>
        </div>
      </div>

      {/* Logs table */}
      <div className="logs-content" ref={tableContainerRef}>
        <DataTable
          data={filteredData}
          columns={columns}
          onRowClick={handleRowClick}
          emptyMessage="No logs available"
          className="logs-table"
          contextMenuItems={getContextMenuItems}
        />
      </div>

      {/* Selected log details */}
      {selectedEntry && (
        <div className="logs-details">
          <div className="details-header">
            <h3>Log Details</h3>
            <button
              className="close-details"
              onClick={() => setSelectedEntry(null)}
            >
              ×
            </button>
          </div>
          <div className="details-content">
            <div className="detail-field">
              <label>Timestamp:</label>
              <span>{new Date(selectedEntry.timestamp).toLocaleString()}</span>
            </div>
            <div className="detail-field">
              <label>Message:</label>
              <div className="message-content">
                <pre>{selectedEntry.message}</pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
