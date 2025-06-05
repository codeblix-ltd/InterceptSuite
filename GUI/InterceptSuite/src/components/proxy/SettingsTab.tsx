// Settings tab component with form validation and proxy controls
import React, { useState, useEffect, useCallback, useRef } from 'react';
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
  const [isStoppingProxy, setIsStoppingProxy] = useState(false);
  const [isRefreshingInterfaces, setIsRefreshingInterfaces] = useState(false);
  // Keep track of last settings load time to avoid unnecessary reloads
  const lastLoadTime = useRef<number>(0);
  const RELOAD_INTERVAL = 3000; // 3 seconds

  // Define callback functions first, before using them in useEffect
  const loadNetworkInterfaces = useCallback(async () => {
    try {
      const interfaces = await invoke<NetworkInterface[]>('get_network_interfaces');
      setTargetHostOptions(interfaces);
    } catch (error) {
      console.error('Failed to load network interfaces:', error);
      // Keep default options on error
    }
  }, []);

  // Load proxy status to check if it's running and get current configuration
  const loadProxyStatus = useCallback(async () => {
    try {
      const status = await invoke<ProxyStatusResponse>('get_proxy_status');

      console.log('Proxy status:', status);
      setIsProxyRunning(status.is_running);

      // Update settings with values from the proxy if needed
      if (status.is_running) {
        setSettings(prev => ({
          ...prev,
          targetHost: status.bind_addr,
          listenPort: status.port,
          enableLogging: status.verbose_mode,
          logFilePath: status.log_file
        }));
      }
    } catch (error) {
      console.error('Failed to get proxy status:', error);
    }
  }, []);

  const loadSettings = useCallback(async () => {
    setLoading(true);
    try {
      const savedSettings = await invoke<ProxySettings>('get_proxy_settings');
      setSettings(savedSettings);
      setIsDirty(false); // Mark as clean since we just loaded from backend
      lastLoadTime.current = Date.now();
      console.log('Loaded settings from backend:', savedSettings);
    } catch (error) {
      console.error('Failed to load settings:', error);
      // Keep default settings on error
    } finally {
      setLoading(false);
    }
  }, []);

  // Load settings on component mount
  useEffect(() => {
    console.log('SettingsTab mounted, loading initial settings...');
    loadSettings();
    loadNetworkInterfaces();
    loadProxyStatus();
  }, [loadSettings, loadNetworkInterfaces, loadProxyStatus]);

  // Listen for tab/window visibility changes to reload settings
  // This ensures we show the latest settings when user returns to this tab
  useEffect(() => {
    // Set up a timer that checks if we should reload settings
    const interval = setInterval(() => {
      const now = Date.now();
      const timeSinceLastLoad = now - lastLoadTime.current;

      // Only reload if:
      // 1. We're not currently in the middle of any operation
      // 2. It's been more than RELOAD_INTERVAL since last load
      // 3. Document is visible (tab is active)
      if (!loading &&
          !saving &&
          !isStartingProxy &&
          !isStoppingProxy &&
          !document.hidden &&
          timeSinceLastLoad > RELOAD_INTERVAL) {
        console.log('Auto-reloading settings from memory (ensuring fresh data)...');
        loadSettings();

        // Also check proxy status for real-time updates
        invoke('get_proxy_status')
          .then((status: any) => {
            console.log('Proxy status:', status);
            setIsProxyRunning(status.is_running);
          })
          .catch(err => console.error('Failed to get proxy status:', err));
      }
    }, 1000); // Check every second

    return () => clearInterval(interval);
  }, [loading, saving, isStartingProxy, isStoppingProxy, loadSettings]);

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
          </div>

          <div className="settings-actions">
            <button
              className="action-btn save"
              onClick={handleSave}
              disabled={!isDirty || saving}
            >
              {saving ? 'Saving...' : 'Save Settings'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
