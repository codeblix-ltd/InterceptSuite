import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { DataViewerTabs } from '../common';
import {InterceptedData, InterceptStatus} from '../../types/index'
import '../../styles/InterceptTab.css';

// Define intercept direction options
const INTERCEPT_DIRECTIONS = [
  { value: 0, label: 'None' },
  { value: 1, label: 'Client->Server' },
  { value: 2, label: 'Server->Client' },
  { value: 3, label: 'Both' }
];



export const InterceptTab: React.FC = () => {
  // State for intercept settings
  const [interceptEnabled, setInterceptEnabled] = useState<boolean>(false);
  const [direction, setDirection] = useState<number>(0);
  const [status, setStatus] = useState<InterceptStatus | null>(null);
  // Changed from a list to a queue implementation
  const [interceptQueue, setInterceptQueue] = useState<InterceptedData[]>([]);
  // Current packet is the first one in the queue (FIFO)
  const [currentPacket, setCurrentPacket] = useState<InterceptedData | null>(null);
  // Add loading state for UI feedback
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  // Track active tab for data viewer
  const [activeDataTab, setActiveDataTab] = useState<string>('raw');
  // Track edited packet data (separate from original data)
  const [editedData, setEditedData] = useState<string>('');
  // Get current intercept status on component mount
  useEffect(() => {
    getInterceptStatus();

    // Subscribe to intercepted packet events
    const unsubscribe = listen('intercepted-packet', (event: any) => {
      console.log('RECEIVED INTERCEPTED PACKET EVENT:', event);
      const packet = event.payload as InterceptedData;

      // When we receive a new packet, add it to the queue
      setInterceptQueue(prev => {
        // Add to end of queue (FIFO)
        const newQueue = [...prev, packet];
        console.log('Added packet to queue, new queue length:', newQueue.length);
        return newQueue;
      });
    });

    return () => {
      unsubscribe.then(unsub => unsub());
    };
  }, []);  // Effect to process the queue and show the current packet
  useEffect(() => {
    if (interceptQueue.length > 0 && currentPacket === null && !isProcessing) {
      // Take the first packet from the queue (FIFO)
      const packet = interceptQueue[0];
      setCurrentPacket(packet);

      // Initialize edited data with the original data
      // Convert hex string to binary data
      console.log('Processing new packet:');
      console.log('Original hex data:', packet.data);

      const hexArray = packet.data.split(' ')
        .filter((hex: string) => hex.trim() !== '')
        .map((hex: string) => parseInt(hex, 16));

      console.log('Hex array:', hexArray);

      // Convert binary data to string for editing
      const dataString = String.fromCharCode(...hexArray);
      console.log('Converted to string:', dataString);

      setEditedData(dataString);
    }
  }, [interceptQueue, currentPacket, isProcessing]);

  // Get current intercept status
  const getInterceptStatus = async () => {
    try {
      const result = await invoke<InterceptStatus>('get_intercept_status');
      setStatus(result);
      setInterceptEnabled(result.is_enabled);

      // Set direction based on the string value
      const directionOption = INTERCEPT_DIRECTIONS.find(d => d.label === result.direction);
      if (directionOption) {
        setDirection(directionOption.value);
      }
    } catch (error) {
      console.error('Failed to get intercept status:', error);
    }
  };

  // Toggle intercept enabled/disabled
  const toggleIntercept = async () => {
    try {
      await invoke('set_intercept_enabled', { enabled: !interceptEnabled });
      setInterceptEnabled(!interceptEnabled);
      getInterceptStatus(); // Refresh status after change
    } catch (error) {
      console.error('Failed to toggle intercept:', error);
    }
  };

  // Change intercept direction
  const handleDirectionChange = async (e: React.ChangeEvent<HTMLSelectElement>) => {
    const newDirection = parseInt(e.target.value, 10);
    try {
      await invoke('set_intercept_direction', { direction: newDirection });
      setDirection(newDirection);
      getInterceptStatus(); // Refresh status after change
    } catch (error) {
      console.error('Failed to change intercept direction:', error);
    }
  };
  // Process and remove the current packet from queue
  const processCurrentPacket = () => {
    if (currentPacket) {
      // Remove the processed packet from queue
      setInterceptQueue(queue => queue.filter((_, index) => index !== 0));
      // Clear the current packet
      setCurrentPacket(null);
    }
  };  // Forward intercepted packet
  const forwardPacket = async () => {
    if (!currentPacket) return;

    try {
      setIsProcessing(true);

      console.log('=== FORWARD BUTTON CLICKED ===');
      console.log('Current packet:', currentPacket);
      console.log('Edited data (string):', editedData);
      console.log('Edited data length:', editedData.length);

      // Convert the original hex data to string for comparison
      const hexArray = currentPacket.data.split(' ')
        .filter((hex: string) => hex.trim() !== '')
        .map((hex: string) => parseInt(hex, 16));
      const originalDataString = String.fromCharCode(...hexArray);

      // Check if data has been modified
      const isDataModified = editedData !== originalDataString;

      // Convert the edited string data to Uint8Array
      const data = new Uint8Array(
        Array.from(editedData).map(char => char.charCodeAt(0))
      );

      // Use correct action based on whether data was modified
      const action = isDataModified ? 2 : 0; // 0=forward unchanged, 2=forward with modifications

      console.log('Forwarding packet with data:');
      console.log('Original packet data (hex):', currentPacket.data);
      console.log('Original data (string):', originalDataString);
      console.log('Edited data (string):', editedData);
      console.log('Data modified:', isDataModified);
      console.log('Action:', action, action === 0 ? '(forward unchanged)' : '(forward with modifications)');
      console.log('Converted data (Uint8Array):', Array.from(data));
      console.log('Converted data (hex):', Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(' '));

      await invoke('respond_to_intercept', {
        connectionId: currentPacket.connection_id,
        packetId: currentPacket.packet_id,
        action, // Use the correct action
        data: Array.from(data) // Convert Uint8Array to regular array for Tauri
      });

      console.log('=== FORWARD COMPLETED ===');

      // Remove current packet from queue
      processCurrentPacket();

    } catch (error) {
      console.error('Failed to forward packet:', error);
    } finally {
      setIsProcessing(false);
    }
  };
  // Drop intercepted packet
  const dropPacket = async () => {
    if (!currentPacket) return;

    try {
      setIsProcessing(true);

      console.log('Dropping packet:', currentPacket.packet_id);

      await invoke('respond_to_intercept', {
        connectionId: currentPacket.connection_id,
        packetId: currentPacket.packet_id,
        action: 1, // Drop
        data: [] // Empty array for drop
      });

      // Remove current packet from queue
      processCurrentPacket();

    } catch (error) {
      console.error('Failed to drop packet:', error);
    } finally {
      setIsProcessing(false);
    }
  };
  return (
    <div className="intercept-tab">
      <div className="intercept-controls">
        <div className="control-row">
          <button
            className={`toggle-button ${interceptEnabled ? 'enabled' : 'disabled'}`}
            onClick={toggleIntercept}
          >
            Intercept {interceptEnabled ? 'ON' : 'OFF'}
          </button>

          <div className="direction-selector">
            <label htmlFor="direction-select">Direction:</label>
            <select
              id="direction-select"
              value={direction}
              onChange={handleDirectionChange}
              disabled={!interceptEnabled}
            >
              {INTERCEPT_DIRECTIONS.map(dir => (
                <option key={dir.value} value={dir.value}>
                  {dir.label}
                </option>
              ))}
            </select>
          </div>

          <div className="status-display">
            {status && (
              <span>
                Status: {status.is_enabled ? 'Enabled' : 'Disabled'},
                Direction: {status.direction}
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="intercept-container">
        <div className="queue-status">
          <span className="queue-info">
            Queue: {interceptQueue.length} packet(s) waiting
          </span>
        </div>        {currentPacket ? (
          <div className="current-packet">
            <div className="packet-actions">
              <div className="action-info">
                {editedData !== String.fromCharCode(...currentPacket.data.split(' ').filter(hex => hex.trim() !== '').map(hex => parseInt(hex, 16))) && (
                  <span className="data-modified-indicator">⚠️ Data has been modified</span>
                )}
              </div>
              <button
                onClick={forwardPacket}
                disabled={isProcessing}
                className="forward-button"
              >
                {isProcessing ? 'Processing...' : 'Forward'}
              </button>
              <button
                onClick={dropPacket}
                disabled={isProcessing}
                className="drop-button"
              >
                {isProcessing ? 'Processing...' : 'Drop'}
              </button>
            </div>

            <div className="packet-header">
              <h3>Intercepted Packet</h3>
              <div className="packet-meta">
                <div><strong>Connection ID:</strong> {currentPacket.connection_id}</div>
                <div><strong>Packet ID:</strong> {currentPacket.packet_id}</div>
                <div><strong>Direction:</strong> {currentPacket.direction}</div>
                <div><strong>Source:</strong> {currentPacket.src_ip}</div>
                <div><strong>Destination:</strong> {`${currentPacket.dst_ip}:${currentPacket.dst_port}`}</div>
                <div><strong>Size:</strong> {currentPacket.data_length} bytes</div>
                <div><strong>Time:</strong> {new Date(currentPacket.timestamp).toLocaleTimeString()}</div>
              </div>
            </div>            <div className="packet-data-viewer">
              <DataViewerTabs
                data={editedData}
                activeTab={activeDataTab}
                onTabChange={setActiveDataTab}
                editable={true}
                onChange={setEditedData}
                emptyMessage="No data to display"
              />
            </div>
          </div>
        ) : (
          <div className="no-packets">
            <p>No intercepted packets. {interceptEnabled ? 'Waiting for traffic...' : 'Enable intercept to capture packets.'}</p>
          </div>
        )}
      </div>
    </div>
  );
};
