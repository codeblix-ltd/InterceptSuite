// Global type definitions for InterceptSuite
export interface TabConfig {
  id: string;
  label: string;
  icon?: string;
  component: React.ComponentType;
  subTabs?: TabConfig[];
}

export interface Connection {
  id: string;
  timestamp: Date;
  event: 'connected' | 'disconnected';
  connectionId: number;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
}

export interface ProxyRequest {
  id: string;
  method: string;
  url: string;
  status: number;
  responseTime: number;
  size: number;
  timestamp: Date;
  headers: Record<string, string>;
  body?: string;
}

export interface LogEntry {
  id: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  message: string;
  timestamp: Date;
  source: string;
}

export interface ProxySettings {
  listenPort: number;
  targetHost: string;
  enableLogging: boolean;
  logFilePath: string;
}

export interface ProxyHistoryEntry {
  id: string;
  timestamp: string;
  connection_id: number;
  packet_id: number; // Hidden from UI but used for tracking
  packet_key: string; // Unique key for deduplication
  source_ip: string;
  destination_ip: string;
  destination_port: number;
  message_type: string;
  data: string; // Raw message data that will be displayed in the bottom panel
  modified: boolean; // Whether this entry has been modified during interception
  edited_data?: string; // The edited data if modified
}


export interface ConnectionEvent {
  id: string;
  timestamp: string;
  event: 'connected' | 'disconnected';
  connectionId: number;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
}

// Define type for intercepted data
export interface InterceptedData {
  connection_id: number;
  packet_id: number;
  direction: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  data_length: number;
  data: string;
  timestamp: string;
}

// Define type for intercept status
export interface InterceptStatus {
  is_enabled: boolean;
  direction: string;
}


export interface NetworkInterface {
  value: string;
  label: string;
}

// Define the proxy status response type
export interface ProxyStatusResponse {
  bind_addr: string;
  port: number;
  log_file: string;
  verbose_mode: boolean;
  is_running: boolean;
}