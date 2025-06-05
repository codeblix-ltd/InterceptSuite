// Unified data viewer tabs component for displaying and optionally editing message/packet data
import React, { useState, useEffect } from 'react';
import '../../styles/DataViewerTabs.css';

// Tab definition interface that supports both read-only and editable content
export interface DataViewerTab {
  id: string;
  label: string;
  content: (data: string, onChange?: (newData: string) => void) => React.ReactNode;
  disabled?: boolean;
}

interface DataViewerTabsProps {
  data: string | null;
  activeTab: string;
  onTabChange: (tabId: string) => void;
  editable?: boolean; // New prop to control if the component is editable
  onChange?: (newData: string) => void; // Required when editable is true
  emptyMessage?: string;
  className?: string;
  tabs?: DataViewerTab[]; // Allow custom tabs to be passed
}

// Default tabs that support both read-only and editable modes
// Only Raw tab is available - the same tab works for both modes
const createDefaultTabs = (editable: boolean): DataViewerTab[] => [
  {
    id: 'raw',
    label: 'Raw',
    content: (data: string, onChange?: (newData: string) => void) => {
      if (editable && onChange) {
        return (
          <textarea
            className="data-content raw-data editable"
            value={data}
            onChange={(e) => onChange(e.target.value)}
            spellCheck={false}
          />
        );
      }
      return <pre className="data-content raw-data">{data}</pre>;
    }
  }
  // Extesion Tabs Supported TAB  - TBD WIP
];

export const DataViewerTabs: React.FC<DataViewerTabsProps> = ({
  data,
  activeTab,
  onTabChange,
  editable = false,
  onChange,
  emptyMessage = 'Select an entry to view details',
  className = '',
  tabs
}) => {
  const [localData, setLocalData] = useState<string>('');

  // Use provided tabs or create default tabs based on editable mode
  const defaultTabs = tabs || createDefaultTabs(editable);

  // Update local data when prop changes (only needed in editable mode)
  useEffect(() => {
    if (editable) {
      if (data !== null) {
        setLocalData(data);
      } else {
        setLocalData('');
      }
    }
  }, [data, editable]);

  // Handle local changes and propagate them up (only in editable mode)
  const handleDataChange = (newData: string) => {
    if (editable && onChange) {
      setLocalData(newData);
      onChange(newData);
    }
  };

  const renderActiveTabContent = () => {
    if (!data) {
      return <div className="empty-data-message">{emptyMessage}</div>;
    }

    const activeTabDef = defaultTabs.find(tab => tab.id === activeTab);
    if (!activeTabDef) {
      return <div className="empty-data-message">Tab not found</div>;
    }

    // In editable mode, pass localData and handleDataChange
    // In read-only mode, just pass the original data
    const dataToPass = editable ? localData : data;
    const onChangeToPass = editable ? handleDataChange : undefined;

    return activeTabDef.content(dataToPass, onChangeToPass);
  };

  return (
    <div className={`data-viewer-tabs-container ${className}`}>
      <div className="data-viewer-tabs">
        {defaultTabs.map(tab => (
          <button
            key={tab.id}
            className={`tab-button ${activeTab === tab.id ? 'active' : ''} ${tab.disabled ? 'disabled' : ''}`}
            onClick={() => !tab.disabled && onTabChange(tab.id)}
            disabled={tab.disabled}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div className="data-viewer-content">
        {renderActiveTabContent()}
      </div>
    </div>
  );
};
