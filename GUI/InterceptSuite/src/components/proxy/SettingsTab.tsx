// Settings tab component with form validation and proxy controls
import React, { useState, useEffect, useCallback } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { invoke } from '@tauri-apps/api/core';
import { ProxySettings, ProxyStatusResponse, NetworkInterface } from '../../types';



export const SettingsTab: React.FC = () => {
  // State for network interfaces - start with empty array, will be populated dynamically
  const [targetHostOptions, setTargetHostOptions] = useState<NetworkInterface[]>([]);
  const [settings, setSettings] = useState<ProxySettings>({
    listenPort: 4444,
    targetHost: '127.0.0.1',
    enableLogging: false,
    logFilePath: 'tls_proxy.log'
  });
  const [isProxyRunning, setIsProxyRunning] = useState(false);

  const [isDirty, setIsDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const [isStartingProxy, setIsStartingProxy] = useState(false);
  const [isStoppingProxy, setIsStoppingProxy] = useState(false);  const [isRefreshingInterfaces, setIsRefreshingInterfaces] = useState(false);

  // Export certificate modal state
  const [showExportModal, setShowExportModal] = useState(false);
  const [exportType, setExportType] = useState<'certificate' | 'key'>('certificate');
  const [isExporting, setIsExporting] = useState(false);

  // Define callback functions first, before using them in useEffect
  const loadNetworkInterfaces = useCallback(async () => {
    try {
      const interfaces = await invoke<NetworkInterface[]>('get_network_interfaces');
      setTargetHostOptions(interfaces);
    } catch (error) {
      console.error('Failed to load network interfaces:', error);
      // Keep default options on error
    }
  }, []);  const loadSettings = useCallback(async () => {
    setLoading(true);
    try {
      // Use proxy status as the primary source of truth for current configuration
      const status = await invoke<ProxyStatusResponse>('get_proxy_status');

      console.log('Proxy status:', status);

      const currentSettings: ProxySettings = {
        listenPort: status.port,
        targetHost: status.bind_addr,
        enableLogging: status.verbose_mode,
        logFilePath: status.log_file
      };      setSettings(currentSettings);
      setIsProxyRunning(status.is_running); // Set proxy running status from same response
      setIsDirty(false); // Mark as clean since we just loaded from backend
      console.log('Loaded settings from proxy status:', currentSettings);
    } catch (error) {
      console.error('Failed to load settings from proxy status:', error);
      // Keep default settings on error
    } finally {
      setLoading(false);
    }
  }, []);  // Load settings on component mount (when user clicks on Settings tab)
  useEffect(() => {
    console.log('SettingsTab mounted, loading initial settings...');
    loadSettings();
    loadNetworkInterfaces();
  }, [loadSettings, loadNetworkInterfaces]);

  const startProxy = async () => {
    setIsStartingProxy(true);
    try {
      await invoke('cmd_start_proxy');
      // Update proxy status
      setIsProxyRunning(true);
      console.log('Proxy started successfully');

      // Reload settings to ensure they're up to date after starting
      await loadSettings();
    } catch (error) {
      console.error('Failed to start proxy:', error);
      // Could show error message to user here
    } finally {
      setIsStartingProxy(false);
    }
  };
  const stopProxy = async () => {
    setIsStoppingProxy(true);
    try {
      await invoke('cmd_stop_proxy');
      // Update proxy status
      setIsProxyRunning(false);
      console.log('Proxy stopped successfully');

      // Reload settings to ensure they're up to date after stopping
      await loadSettings();
    } catch (error) {
      console.error('Failed to stop proxy:', error);
      // Could show error message to user here
    } finally {
      setIsStoppingProxy(false);
    }
  };

  const handleExportCertificate = async () => {
    try {
      const selectedPath = await open({
        directory: true,
        multiple: false,
        title: 'Select Export Directory'
      });

      if (selectedPath && typeof selectedPath === 'string') {
        setIsExporting(true);

        // Convert export type to number: 0 = certificate, 1 = key
        const exportTypeNum = exportType === 'certificate' ? 0 : 1;

        const success = await invoke<boolean>('export_certificate', {
          outputDirectory: selectedPath,
          exportType: exportTypeNum
        });

        if (success) {
          console.log(`${exportType} exported successfully to: ${selectedPath}`);
          // You could show a success message here
        } else {
          console.error(`Failed to export ${exportType}`);
          // You could show an error message here
        }
      }
    } catch (error) {
      console.error('Export failed:', error);
      // You could show an error message here
    } finally {
      setIsExporting(false);
      setShowExportModal(false);
    }
  };

  const handleInputChange = (field: keyof ProxySettings, value: any) => {
    setSettings(prev => ({ ...prev, [field]: value }));
    setIsDirty(true);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      console.log('Saving proxy settings to backend memory:', settings);
      await invoke('save_proxy_settings', { settings });
      setIsDirty(false);
      console.log('Settings saved successfully to backend memory and applied to proxy configuration');
    } catch (error) {
      console.error('Failed to save settings:', error);
      // Could show error message to user here
    } finally {
      setSaving(false);
    }
  };

  const selectLogFile = async () => {
    try {
      const selected = await open({
        filters: [
          { name: 'Log Files', extensions: ['log'] },
          { name: 'Text Files', extensions: ['txt'] },
          { name: 'All Files', extensions: ['*'] }
        ],
        defaultPath: settings.logFilePath,
        multiple: false
      });

      if (selected && typeof selected === 'string') {
        handleInputChange('logFilePath', selected);
      }
    } catch (error) {
      console.error('Failed to open file dialog:', error);
    }
  };

  const refreshInterfaces = async () => {
    setIsRefreshingInterfaces(true);
    try {
      console.log('Refreshing network interfaces...');
      // Clear current interfaces temporarily to show refresh is happening
      setTargetHostOptions([]);

      // Call the backend to get fresh system IPs
      const interfaces = await invoke<NetworkInterface[]>('get_network_interfaces');
      setTargetHostOptions(interfaces);

      console.log(`Successfully refreshed network interfaces. Found ${interfaces.length} interfaces:`, interfaces);
    } catch (error) {
      console.error('Failed to refresh interfaces:', error);
      // On error, try to reload the previous interfaces
      await loadNetworkInterfaces();
    } finally {
      setIsRefreshingInterfaces(false);
    }
  };

  return (
    <div className="settings-tab">
      <div className="settings-header">
        <h2>Proxy Settings</h2>
        <div className="header-actions">
          <button
            className="action-btn refresh"
            onClick={() => { loadSettings(); }}
            disabled={loading || saving}
            title="Refresh settings from memory"
          >
            {loading ? 'Loading...' : 'Refresh'}
          </button>
          {isDirty && (
            <div className="unsaved-indicator">
              Unsaved changes
            </div>
          )}
        </div>
      </div>
      <div className="settings-content">
        <div className="settings-section proxy-control">
          <h3>Proxy Control</h3>
          <div className="proxy-actions">
            {!isProxyRunning ? (
              <button
                className="action-btn start-btn"
                onClick={startProxy}
                disabled={isStartingProxy}
              >
                {isStartingProxy ? 'Starting...' : 'Start Proxy'}
              </button>
            ) : (
              <button
                className="action-btn stop-btn"
                onClick={stopProxy}
                disabled={isStoppingProxy}
              >
                {isStoppingProxy ? 'Stopping...' : 'Stop Proxy'}
              </button>
            )}
          </div>
        </div>
        <div className="settings-section">
          <h3>Configuration</h3>
          <div className="form-group">
            <label htmlFor="targetHost">Target Host</label>
            <div className="target-host-group">
              <select
                id="targetHost"
                value={settings.targetHost}
                onChange={(e) => handleInputChange('targetHost', e.target.value)}
                className="form-input form-select"
              >
                {targetHostOptions.map(option => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <button type="button" onClick={refreshInterfaces} className="refresh-btn" disabled={isRefreshingInterfaces}>
                {isRefreshingInterfaces ? 'Refreshing...' : 'Refresh Interfaces'}
              </button>
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="listenPort">Listen Port</label>
            <input
              id="listenPort"
              type="number"
              min="1"
              max="65535"
              value={settings.listenPort}
              onChange={(e) => handleInputChange('listenPort', parseInt(e.target.value))}
              className="form-input"
            />
          </div>
          <div className="form-group">
            <label className="checkbox-container">
              <input
                type="checkbox"
                checked={settings.enableLogging}
                onChange={(e) => handleInputChange('enableLogging', e.target.checked)}
              />
              Verbose Mode
            </label>
          </div>
          <div className="form-group">
            <label htmlFor="logFilePath">Log File Location</label>
            <div className="file-input-group">
              <input
                id="logFilePath"
                type="text"
                value={settings.logFilePath}
                onChange={(e) => handleInputChange('logFilePath', e.target.value)}
                className="form-input"
                placeholder="Path to log file"
              />
              <button type="button" onClick={selectLogFile} className="file-select-btn">
                Browse
              </button>
            </div>
          </div>          <div className="settings-actions">
            <button
              className="action-btn save"
              onClick={handleSave}
              disabled={!isDirty || saving}
            >
              {saving ? 'Saving...' : 'Save Settings'}
            </button>
          </div>
        </div>

        <div className="settings-section">
          <h3>Certificate Management</h3>
          <div className="certificate-actions">
            <button
              className="action-btn export-cert"
              onClick={() => setShowExportModal(true)}
              disabled={isExporting}
            >
              Export Certificate
            </button>
          </div>
        </div>
      </div>

      {showExportModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3>Export Certificate</h3>
              <button
                className="modal-close"
                onClick={() => setShowExportModal(false)}
                disabled={isExporting}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Export Type</label>
                <div className="radio-group">
                  <label className="radio-option">
                    <input
                      type="radio"
                      value="certificate"
                      checked={exportType === 'certificate'}
                      onChange={(e) => setExportType(e.target.value as 'certificate' | 'key')}
                      disabled={isExporting}
                    />
                    Certificate (.der format)
                  </label>
                  <label className="radio-option">
                    <input
                      type="radio"
                      value="key"
                      checked={exportType === 'key'}
                      onChange={(e) => setExportType(e.target.value as 'certificate' | 'key')}
                      disabled={isExporting}
                    />
                    Private Key (.key format)
                  </label>
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button
                className="action-btn secondary"
                onClick={() => setShowExportModal(false)}
                disabled={isExporting}
              >
                Cancel
              </button>
              <button
                className="action-btn export"
                onClick={handleExportCertificate}
                disabled={isExporting}
              >
                {isExporting ? 'Exporting...' : 'Export'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
