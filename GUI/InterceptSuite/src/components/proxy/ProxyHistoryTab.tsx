// Proxy History tab component
import React, { useState, useEffect, useMemo, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { DataTable, ContextMenuItem, DataViewerTabs } from '../common';
import { ProxyHistoryEntry } from '../../types/index';
import '../../styles/ProxyHistoryTab.css';

export const ProxyHistoryTab: React.FC = () => {
  const [historyData, setHistoryData] = useState<ProxyHistoryEntry[]>([]);
  const [searchFilter, setSearchFilter] = useState('');
  const [selectedEntry, setSelectedEntry] = useState<ProxyHistoryEntry | null>(null);
  const [activeTab, setActiveTab] = useState('raw');
  const [dataSource, setDataSource] = useState<'original' | 'edited'>('original'); // For dropdown selector
  const [panelHeight, setPanelHeight] = useState(300); // Default bottom panel height
  const splitPaneRef = useRef<HTMLDivElement>(null);  const isDraggingRef = useRef(false);

  // Handle mouse events for the splitter
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDraggingRef.current || !splitPaneRef.current) return;

      const containerRect = splitPaneRef.current.getBoundingClientRect();
      const containerHeight = containerRect.height;
      const mouseY = e.clientY;
      const relativeY = mouseY - containerRect.top;

      // Calculate the new bottom panel height
      const newTopSectionHeight = Math.max(100, relativeY);
      const newBottomPanelHeight = Math.max(100, containerHeight - newTopSectionHeight);

      // Set the new height
      setPanelHeight(newBottomPanelHeight);
    };

    const handleMouseUp = () => {
      isDraggingRef.current = false;
      document.body.style.cursor = '';
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    const handleMouseDown = (e: MouseEvent) => {
      if (e.target instanceof Element && e.target.classList.contains('splitter-handle')) {
        isDraggingRef.current = true;
        document.body.style.cursor = 'ns-resize';
        document.addEventListener('mousemove', handleMouseMove);
        document.addEventListener('mouseup', handleMouseUp);
        e.preventDefault();
      }
    };

    document.addEventListener('mousedown', handleMouseDown);

    return () => {
      document.removeEventListener('mousedown', handleMouseDown);
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, []);  // Load proxy history data when component mounts and set up periodic refresh
  useEffect(() => {
    const loadProxyHistory = async () => {
      try {
        // Fetch existing proxy history from backend
        const data = await invoke('get_proxy_history') as ProxyHistoryEntry[];
        setHistoryData(data);
      } catch (error) {
        console.error('Failed to load proxy history:', error);
        setHistoryData([]);
      }
    };

    // Initial load
    loadProxyHistory();    // Set up periodic refresh to get new data from memory storage
    const intervalId = setInterval(() => {
      loadProxyHistory();
    }, 1000); // Refresh every 1 second

    return () => {
      clearInterval(intervalId);
    };
  }, []);

  // Reset data source to 'original' when a new entry is selected
  useEffect(() => {
    setDataSource('original');
  }, [selectedEntry]);
  const filteredData = useMemo(() => {
    return historyData.filter(entry => {
      const matchesSearch =
        (entry.source_ip?.toLowerCase() || '').includes(searchFilter.toLowerCase()) ||
        (entry.destination_ip?.toLowerCase() || '').includes(searchFilter.toLowerCase()) ||
        (entry.message_type?.toLowerCase() || '').includes(searchFilter.toLowerCase()) ||
        (entry.data?.toLowerCase() || '').includes(searchFilter.toLowerCase());

      return matchesSearch;
    });
  }, [historyData, searchFilter]);  const columns = [
    {
      key: 'timestamp' as keyof ProxyHistoryEntry,
      header: 'Timestamp',
      width: '180px',
      render: (timestamp: string) => new Date(timestamp).toLocaleString()
    },
    {
      key: 'connection_id' as keyof ProxyHistoryEntry,
      header: 'Conn ID',
      width: '100px'
    },
    {
      key: 'source_ip' as keyof ProxyHistoryEntry,
      header: 'Source IP',
      width: '140px'
    },
    {
      key: 'destination_ip' as keyof ProxyHistoryEntry,
      header: 'Destination IP',
      width: '140px'
    },
    {
      key: 'destination_port' as keyof ProxyHistoryEntry,
      header: 'Port',
      width: '80px'
    },
    {
      key: 'message_type' as keyof ProxyHistoryEntry,
      header: 'Type',
      width: '120px'
    },
    {
      key: 'modified' as keyof ProxyHistoryEntry,
      header: 'Modified',
      width: '80px',
      render: (modified: boolean) => modified ? '✓' : '✗'
    }
    // Note: packet_id is not included in columns as it's meant to be invisible
    // Note: data is not included as it will be displayed in the bottom panel
  ];  const handleRowClick = (entry: ProxyHistoryEntry) => {
    setSelectedEntry(entry);
  };

  // Get the data to display based on the selected source
  const getDisplayData = () => {
    if (!selectedEntry) return null;

    if (dataSource === 'edited' && selectedEntry.edited_data) {
      return selectedEntry.edited_data;
    }

    return selectedEntry.data;
  };

  // Check if the dropdown should be shown (only for modified entries)
  const shouldShowDropdown = selectedEntry?.modified === true;
  const handleClearHistory = async (selectedEntries?: ProxyHistoryEntry[]) => {
    try {
      if (selectedEntries && selectedEntries.length > 0 && selectedEntries.length < historyData.length) {
        // Clear only selected entries - call Rust backend with packet IDs
        const packetIds = selectedEntries.map(entry => entry.packet_id);
        await invoke('clear_selected_proxy_history', { entryIds: packetIds });

        // Update local state
        const selectedIds = new Set(packetIds);
        const remainingEntries = historyData.filter(entry => !selectedIds.has(entry.packet_id));
        setHistoryData(remainingEntries);
        console.log(`Cleared ${selectedEntries.length} selected proxy history entries from backend`);
      } else {
        // Clear all history via Rust backend
        await invoke('clear_proxy_history');
        setHistoryData([]);
        console.log('Cleared all proxy history');
      }
    } catch (error) {
      console.error('Failed to clear proxy history:', error);
    }
  };

  const getContextMenuItems = (selectedEntries: ProxyHistoryEntry[]): ContextMenuItem[] => {
    const selectedCount = selectedEntries.length;
    const totalCount = historyData.length;

    if (selectedCount === 0) {
      return [
        {
          label: `Clear All (${totalCount} items)`,
          action: () => handleClearHistory(),
          disabled: totalCount === 0
        }
      ];
    }

    return [
      {
        label: selectedCount === 1
          ? 'Clear Selected Item'
          : `Clear ${selectedCount} Selected Items`,
        action: () => handleClearHistory(selectedEntries),
        disabled: false
      },
      {
        label: '',
        action: () => {},
        separator: true
      },
      {
        label: `Clear All (${totalCount} items)`,
        action: () => handleClearHistory(),
        disabled: totalCount === 0
      }
    ];  };

  return (
    <div className="proxy-history-tab">
      <div className="history-controls">
        <div className="filter-controls">
          <input
            type="text"
            placeholder="Search history..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="search-input"
          />
        </div>
      </div>

      {/* Split pane layout with table on top and data viewer on bottom */}
      <div className="history-split-pane" ref={splitPaneRef}>
        {/* Top panel: Data table */}        <div className="history-content">
          <DataTable
            data={filteredData}
            columns={columns}
            onRowClick={handleRowClick}
            emptyMessage="No history data available"
            className="history-table"
            contextMenuItems={getContextMenuItems}
          />
        </div>

        {/* Splitter handle */}
        <div className="splitter-handle"></div>        {/* Bottom panel: Data viewer with tabs */}
        <div className="history-data-viewer" style={{ height: `${panelHeight}px` }}>          {/* Show dropdown only if data was modified */}
          {shouldShowDropdown && (
            <div className="data-viewer-controls">
              <select
                className="data-source-selector"
                value={dataSource}
                onChange={(e) => setDataSource(e.target.value as 'original' | 'edited')}
              >
                <option value="original">Original</option>
                <option value="edited">Edited</option>
              </select>
            </div>
          )}

          <DataViewerTabs
            data={getDisplayData()}
            activeTab={activeTab}
            onTabChange={setActiveTab}
            emptyMessage="Select an entry to view details"
          />
        </div>
      </div>
    </div>
  );
};
