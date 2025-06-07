// Generic reusable Tab component following DRY principles
import React from 'react';
import { TabConfig } from '../../types';

interface TabProps {
  tabs: TabConfig[];
  activeTab: string;
  onTabChange: (tabId: string) => void;
  className?: string;
}

export const TabNavigation: React.FC<TabProps> = ({
  tabs,
  activeTab,
  onTabChange,
  className = ''
}) => {
  return (
    <div className={`tab-navigation ${className}`}>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          className={`tab-button ${activeTab === tab.id ? 'active' : ''}`}
          onClick={() => onTabChange(tab.id)}
        >
          {tab.icon && <span className={`icon ${tab.icon}`} />}
          {tab.label}
        </button>
      ))}
    </div>
  );
};

interface TabContentProps {
  tabs: TabConfig[];
  activeTab: string;
}

export const TabContent: React.FC<TabContentProps> = ({ tabs, activeTab }) => {
  const currentTab = tabs.find(tab => tab.id === activeTab);

  if (!currentTab) {
    return <div className="tab-content-error">Tab not found</div>;
  }

  const Component = currentTab.component;
  return (
    <div className="tab-content">
      <Component />
    </div>
  );
};
