// Connections tab component
import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { DataTable, ContextMenuItem } from '../common';
import { Connection } from '../../types';
import {ConnectionEvent } from '../../types/index'


export const ConnectionsTab: React.FC = () => {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Load existing connections from Rust memory on component mount
  useEffect(() => {
    const loadConnections = async () => {
      try {
        setIsLoading(true);
        const storedConnections = await invoke<ConnectionEvent[]>('get_connections');
        setConnections(storedConnections.map(mapConnectionEvent));
        console.log('Loaded', storedConnections.length, 'connections from memory');
      } catch (error) {
        console.error('Failed to load connections:', error);
      } finally {
        setIsLoading(false);
      }
    };

    loadConnections();
  }, []);
  // Listen for real-time connection events and refresh from memory
  useEffect(() => {
    const setupListeners = async () => {
      // Initialize callbacks first
      try {
        await invoke('setup_connection_callbacks');
        console.log('Connection callbacks setup completed');
      } catch (error) {
        console.warn('Failed to setup connection callbacks:', error);
      }

      // Listen for connection events and reload from memory
      const unlisten = await listen<ConnectionEvent>('connection-event', async (event) => {
        console.log('Received connection event:', event.payload);
        // Instead of adding to state, reload all connections from Rust memory
        // This prevents duplication and ensures we always have the latest data
        try {
          const storedConnections = await invoke<ConnectionEvent[]>('get_connections');
          setConnections(storedConnections.map(mapConnectionEvent));
        } catch (error) {
          console.error('Failed to reload connections after event:', error);
        }
      });

      return unlisten;
    };

    let unlisten: (() => void) | undefined;

    setupListeners().then((unlistenFn) => {
      unlisten = unlistenFn;
    });

    return () => {
      if (unlisten) {
        unlisten();
      }
    };
  }, []);

  const mapConnectionEvent = (event: ConnectionEvent): Connection => ({
    id: event.id,
    timestamp: new Date(event.timestamp),
    event: event.event,
    connectionId: event.connectionId,
    sourceIp: event.sourceIp,
    sourcePort: event.sourcePort,
    destinationIp: event.destinationIp,
    destinationPort: event.destinationPort,
  });  const handleClearConnections = async (selectedConnections?: Connection[]) => {
    try {
      if (selectedConnections && selectedConnections.length > 0 && selectedConnections.length < connections.length) {
        // Clear only selected connections - call Rust backend with event IDs
        const eventIds = selectedConnections.map(conn => conn.id);
        await invoke('clear_selected_connections', { eventIds });

        // Update local state
        const selectedIds = new Set(eventIds);
        const remainingConnections = connections.filter(conn => !selectedIds.has(conn.id));
        setConnections(remainingConnections);
        console.log(`Cleared ${selectedConnections.length} selected connections from backend`);
      } else {
        // Clear all connections via Rust backend
        await invoke('clear_connections');
        setConnections([]);
        console.log('Cleared all connections');
      }
    } catch (error) {
      console.error('Failed to clear connections:', error);
    }
  };
  const getContextMenuItems = (selectedConnections: Connection[]): ContextMenuItem[] => {
    const selectedCount = selectedConnections.length;
    const totalCount = connections.length;

    if (selectedCount === 0) {
      return [
        {
          label: `Clear All (${totalCount} items)`,
          action: () => handleClearConnections(),
          disabled: totalCount === 0 || isLoading
        }
      ];
    }

    return [
      {
        label: selectedCount === 1
          ? 'Clear Selected Item'
          : `Clear ${selectedCount} Selected Items`,
        action: () => handleClearConnections(selectedConnections),
        disabled: isLoading
      },
      {
        label: '',
        action: () => {},
        separator: true
      },
      {
        label: `Clear All (${totalCount} items)`,
        action: () => handleClearConnections(),
        disabled: totalCount === 0 || isLoading
      }
    ];
  };const columns = [
    {
      key: 'timestamp' as keyof Connection,
      header: 'Timestamp',
      width: '180px',
      render: (timestamp: Date) => timestamp.toLocaleString()
    },
    {
      key: 'event' as keyof Connection,
      header: 'Event',
      width: '120px',
      render: (event: string) => (
        <span className={`connection-event event-${event}`}>
          {event === 'connected' ? 'Connected' : 'Disconnected'}
        </span>
      )
    },
    {
      key: 'connectionId' as keyof Connection,
      header: 'Connection ID',
      width: '130px',
      render: (id: number) => id.toString()
    },
    {
      key: 'sourceIp' as keyof Connection,
      header: 'Source IP',
      width: '140px'
    },
    {
      key: 'sourcePort' as keyof Connection,
      header: 'Source Port',
      width: '110px',
      render: (port: number) => port.toString()
    },
    {
      key: 'destinationIp' as keyof Connection,
      header: 'Destination IP',
      width: '140px'
    },
    {
      key: 'destinationPort' as keyof Connection,
      header: 'Destination Port',
      width: '130px',
      render: (port: number) => port.toString()
    }
  ];  return (
    <div className="connections-tab">
      <div className="connections-content">
        {isLoading ? (
          <div className="loading-message">Loading connections...</div>
        ) : (
          <div className="connections-table-wrapper">
            <DataTable
              data={connections}
              columns={columns}
              emptyMessage="No connections recorded - Start the proxy to see live connection events"
              className="connections-table"
              contextMenuItems={getContextMenuItems}
            />
          </div>
        )}
      </div>
    </div>
  );
};
