// Main container component using DRY tab system
import React, { useState } from 'react';
import { TabNavigation, TabContent } from './common';
import { TabConfig } from '../types';

// Import all tab components
import { InterceptTab, ProxyHistoryTab, ConnectionsTab, SettingsTab } from './proxy';
import { LogsTab } from './logs/index';

// Main Proxy container with sub-tabs
const ProxyContainer: React.FC = () => {
  const [activeProxyTab, setActiveProxyTab] = useState('intercept');

  const proxyTabs: TabConfig[] = [
    { id: 'intercept', label: 'Intercept', component: InterceptTab, icon: 'icon-intercept' },
    { id: 'history', label: 'Proxy History', component: ProxyHistoryTab, icon: 'icon-history' },
    { id: 'connections', label: 'Connections', component: ConnectionsTab, icon: 'icon-connections' },
    { id: 'settings', label: 'Settings', component: SettingsTab, icon: 'icon-settings' }
  ];

  return (
    <div className="proxy-container">
      <TabNavigation
        tabs={proxyTabs}
        activeTab={activeProxyTab}
        onTabChange={setActiveProxyTab}
        className="proxy-sub-tabs"
      />
      <TabContent
        tabs={proxyTabs}
        activeTab={activeProxyTab}
      />
    </div>
  );
};

// Main application container
export const MainContainer: React.FC = () => {
  const [activeMainTab, setActiveMainTab] = useState('proxy');

  const mainTabs: TabConfig[] = [
    {
      id: 'proxy',
      label: 'Proxy',
      component: ProxyContainer,
      icon: 'icon-proxy',
      subTabs: [
        { id: 'intercept', label: 'Intercept', component: InterceptTab },
        { id: 'history', label: 'Proxy History', component: ProxyHistoryTab },
        { id: 'connections', label: 'Connections', component: ConnectionsTab },
        { id: 'settings', label: 'Settings', component: SettingsTab }
      ]
    },
    {
      id: 'logs',
      label: 'Logs',
      component: LogsTab,
      icon: 'icon-logs'
    }
  ];
  return (
    <div className="main-container">
      <div className="app-content">
        <TabNavigation
          tabs={mainTabs}
          activeTab={activeMainTab}
          onTabChange={setActiveMainTab}
          className="main-tabs"
        />

        <div className="tab-content-wrapper">
          <TabContent
            tabs={mainTabs}
            activeTab={activeMainTab}
          />
        </div>
      </div>
    </div>
  );
};
