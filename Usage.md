# InterceptSuite Usage Guide

This guide provides detailed instructions on how to use InterceptSuite for intercepting, analyzing, and manipulating TLS/SSL network traffic.

## Table of Contents

- [User Interface Overview](#user-interface-overview)
- [Initial Setup](#initial-setup)
- [Intercept Tab](#intercept-tab)
- [Proxy History Tab](#proxy-history-tab)
- [Settings Tab](#settings-tab)
- [Connections Tab](#connections-tab)
- [Common Workflows](#common-workflows)

## User Interface Overview

InterceptSuite's interface consists of four main tabs, each serving different functions:

- **Intercept**: For real-time interception and modification of network packets
- **Proxy History**: For viewing the history of all intercepted traffic
- **Settings**: For configuring proxy settings, interception rules, and logging options
- **Connections**: For tracking active TCP connections

Additionally, the interface includes:
- Log display area (bottom left): Shows application logs in real-time
- Packet information area (bottom right): Displays details about active connections

## Initial Setup

When you first run InterceptSuite, the application creates a CA (Certificate Authority) certificate that is essential for TLS interception functionality. This is a critical first step before you can begin intercepting traffic.

### CA Certificate Installation

1. **Certificate Generation**: When InterceptSuite is first started, it automatically generates a CA certificate file named `Intercept_Suite_Cert.pem` in the same directory as the InterceptSuite executable.

2. **Certificate Installation**: You must install this certificate into your Windows system as a trusted root certificate authority for InterceptSuite to properly intercept TLS traffic.

3. **Installation Steps**:
   - Locate the `Intercept_Suite_Cert.pem` file in your InterceptSuite installation directory
   - Double-click the certificate file to open it
   - Click "Install Certificate"
   - Select "Local Machine" as the store location
   - Select "Place all certificates in the following store"
   - Click "Browse" and select "Trusted Root Certification Authorities"
   - Click "OK", then "Next", and finally "Finish"
   - Confirm any security prompts that appear

4. **Verification**: Once the installation is complete, you should see a message indicating that the import was successful.

> **Why is this necessary?** InterceptSuite works by acting as a "man-in-the-middle" for TLS connections. By installing the CA certificate, you're telling your system to trust connections that InterceptSuite has intercepted and re-signed.


## Intercept Tab

![Intercept Tab Screenshot](Images/Intercept.png)

The Intercept tab allows you to view and modify network packets in real-time before they are transmitted to their destination.

### Features

- **Interception Toggle**: Enable/disable traffic interception with a checkbox
- **Packet Details View**: Information about the intercepted packet including:
  - Source/destination IP addresses and ports
  - Protocol information
  - Timestamp
- **Message Content Editor**: Text area to view and edit the intercepted packet data
- **Forward/Drop Controls**: Buttons to send modified packets or drop them entirely

### How to Use

1. Ensure your application is configured to use InterceptSuite's proxy
2. Enable interception by checking the "Intercept" checkbox
3. When a packet is intercepted:
   - Review the packet details in the information panel
   - Examine and modify the packet data in the text editor if needed
   - Click "Forward" to send the packet (possibly modified) or "Drop" to discard it

### Tips

- Text-based protocols (HTTP, SMTP, etc.) can be directly edited in the message content editor
- Binary protocols will display as raw bytes or hexadecimal values which may be more difficult to interpret
- Use the interception direction settings in the Settings tab to focus only on client-to-server or server-to-client traffic if needed

## Proxy History Tab

![Proxy History Tab Screenshot](Images/Prxoy-History.png)

The Proxy History tab maintains a log of all traffic passing through the proxy, allowing for retrospective analysis.

### Features

- **Chronological Traffic List**: All intercepted TCP/TLS messages displayed in a table
- **Message Details**: Complete information about each message when selected
- **Search/Filter Options**: Ability to locate specific types of traffic
- **Export Function**: Option to export the history for external analysis
- **Clear Button**: Option to clear the history table

### How to Use

1. Click on the "Proxy History" tab to view the history of traffic
2. Select an entry to view its details
3. Use search or filtering options to find specific messages
4. Click "Export" to save the history to a file for further analysis
5. Click "Clear" to remove all entries from the history (this does not affect the log files)

### Tips

- Regular reviews of proxy history can help identify patterns or issues in application communication
- Export the history before clearing if you need to maintain a record
- Correlate timestamps with application behaviors to diagnose networking issues

## Settings Tab

![Settings Tab Screenshot](Images/Settings.png)

The Settings tab allows you to configure how InterceptSuite operates, including proxy settings, logging preferences, and interception rules.

### Features

- **Proxy Configuration**:
  - IP Address: Define the listening interface (default: 127.0.0.1)
  - Port Number: Define the port to listen on (default: 4444)
- **Logging Options**:
  - Log File Location: Select where logs are stored
  - Verbose Logging: Toggle detailed logging for debugging
- **Interception Rules**:
  - Direction Selection: Drop-down menu to control which traffic directions are intercepted:
    - None: No interception
    - Client to Server: Only intercept client requests
    - Server to Client: Only intercept server responses
    - Both Directions: Intercept all traffic
- **Proxy Control**:
  - Start/Stop Proxy: Buttons to control the proxy service
  - Status Indicator: Shows if the proxy is currently running

### How to Use

1. Configure your proxy settings (IP address and port)
2. Select your preferred logging options
3. Choose which traffic directions to intercept
4. Click "Apply Configuration" to save your settings
5. Click "Start Proxy" to begin intercepting traffic (proxy is not automatically started when the application launches)

### Tips

- For most use cases, binding to 127.0.0.1 (localhost) is sufficient
- Only enable verbose logging when necessary for troubleshooting, as it can generate large log files
- Remember to start the proxy after launching the application, as it doesn't start automatically

## Connections Tab

![Connections Tab Screenshot](Images/Connections.png)

The Connections tab provides detailed information about active and historical TCP connections.

### Features

- **Connection List**: Table showing all tracked TCP connections
- **Connection Details**: Information such as:
  - Source/destination IP addresses and ports
  - Connection state
  - Duration
  - Byte counts
- **Export Function**: Option to export connection data
- **Clear Button**: Option to clear the connections table

### How to Use

1. Click on the "Connections" tab to view connection information
2. Select a connection to view its details
3. Click "Export" to save the connection data to a file
4. Click "Clear" to remove all entries from the connections table

### Tips

- Monitor this tab to identify unexpected or suspicious connections
- Correlate connections with proxy history events to understand application behavior
- The connection table helps diagnose issues like connection leaks or failures

## Common Workflows

### Basic Traffic Interception

1. Configure your client application to use InterceptSuite's SOCKS5 proxy (127.0.0.1:4444 by default)
2. Start the proxy in the Settings tab
3. Navigate to the Intercept tab and enable interception
4. Use your client application to generate traffic
5. Observe, and optionally modify, the intercepted traffic

### Selective Traffic Analysis

1. In the Settings tab, configure the intercept direction based on your needs
2. Start the proxy and generate traffic from your client application
3. Review the Proxy History tab to analyze the traffic
4. Use the search/filter functions to focus on specific traffic patterns

### Troubleshooting Connection Issues

1. Start the proxy and configure your client application
2. Monitor the Connections tab to observe connection establishment
3. Check the log area (bottom left) for connection errors
4. Review the packet information area (bottom right) for active connection details

### Exporting Traffic for Analysis

1. Generate traffic through the proxy
2. Navigate to either the Proxy History or Connections tab
3. Click the Export button to save the data
4. Use external tools to analyze the exported data if needed

---

For information about building InterceptSuite from source or integrating it with your own applications, see:
- [Build Guide](Build.md)
- [DLL Integration Guide](DLL_INTEGRATION.md)