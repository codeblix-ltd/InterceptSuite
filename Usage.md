# InterceptSuite Usage Guide

This guide provides detailed instructions on how to use InterceptSuite for intercepting, analyzing, and manipulating TLS/SSL network traffic.

## Table of Contents

- [User Interface Overview](#user-interface-overview)
- [Initial Setup](#initial-setup)
- [Proxy Tab](#proxy-tab)
  - [Intercept Subtab](#intercept-subtab)
  - [Proxy History Subtab](#proxy-history-subtab)
  - [Connections Subtab](#connections-subtab)
  - [Settings Subtab](#settings-subtab)
- [Log Tab](#log-tab)
- [Certificate Export](#certificate-export)
- [Common Workflows](#common-workflows)

## User Interface Overview

InterceptSuite's interface consists of two main tabs:

- **Proxy**: Contains all proxy-related functionality with four subtabs:
  - **Intercept**: For real-time interception and modification of network packets
  - **Proxy History**: For viewing the history of all intercepted traffic
  - **Connections**: For tracking active TCP connections
  - **Settings**: For configuring proxy settings, interception rules, and logging options
- **Log**: Displays application logs and status messages in real-time

## Initial Setup

When you first run InterceptSuite, the application creates a CA (Certificate Authority) certificate that is essential for TLS interception functionality. This is a critical first step before you can begin intercepting traffic.

### CA Certificate Installation

1. **Certificate Generation**: When InterceptSuite is first started, it automatically generates a CA certificate file named `Intercept_Suite_Cert.der` in the same directory as the InterceptSuite executable.

2. **Certificate Installation**: You must install this certificate into your system as a trusted root certificate authority for InterceptSuite to properly intercept TLS traffic. The installation process varies by operating system.

3. **Platform-Specific Installation Steps**:

#### Windows
- Locate the `Intercept_Suite_Cert.der` file in your InterceptSuite installation directory
- Double-click the certificate file to open it
- Click "Install Certificate"
- Select "Local Machine" as the store location (requires administrator privileges)
- Select "Place all certificates in the following store"
- Click "Browse" and select "Trusted Root Certification Authorities"
- Click "OK", then "Next", and finally "Finish"
- Confirm any security prompts that appear

#### Linux
**Using command line (Ubuntu/Debian):**
```bash
# Copy the certificate to the system certificate store
sudo cp Intercept_Suite_Cert.der /usr/local/share/ca-certificates/Intercept_Suite_Cert.crt

# Update the certificate store
sudo update-ca-certificates
```

**Using command line (CentOS/RHEL/Fedora):**
```bash
# Copy the certificate to the system certificate store
sudo cp Intercept_Suite_Cert.der /etc/pki/ca-trust/source/anchors/Intercept_Suite_Cert.crt

# Update the certificate store
sudo update-ca-trust
```

**For browser-specific installation:**
- Open your browser's certificate management settings
- Import the `Intercept_Suite_Cert.der` file as a trusted root certificate authority
- Enable trust for "Identifying websites"

#### macOS
**Using Keychain Access (GUI):**
- Open "Keychain Access" application
- Drag and drop the `Intercept_Suite_Cert.der` file into the "System" keychain
- Double-click the imported certificate
- Expand "Trust" section
- Set "When using this certificate" to "Always Trust"
- Close the window and enter your administrator password when prompted

**Using command line:**
```bash
# Import the certificate into the system keychain
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain Intercept_Suite_Cert.der
```

4. **Verification**: Once the installation is complete, you should see a message indicating that the import was successful. You can verify the installation by checking your system's certificate store or attempting to intercept HTTPS traffic.

> **Why is this necessary?** InterceptSuite works by acting as a "man-in-the-middle" for TLS connections. By installing the CA certificate, you're telling your system to trust connections that InterceptSuite has intercepted and re-signed.


## Proxy Tab

The Proxy tab is the main workspace for all proxy-related functionality. It contains four subtabs that handle different aspects of traffic interception and analysis.

### Intercept Subtab

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

### Proxy History Subtab

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

### Settings Subtab

![Settings Tab Screenshot](Images/Settings.png)

The Settings subtab allows you to configure how InterceptSuite operates, including proxy settings, logging preferences, and interception rules.

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

### Connections Subtab

![Connections Tab Screenshot](Images/Connections.png)

The Connections subtab provides detailed information about active and historical TCP connections.

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

## Log Tab

The Log tab displays real-time application logs and status messages, providing detailed information about the proxy's operation and any issues that may occur.

### Features

- **Real-time Log Display**: Live stream of application events and status messages
- **Log Level Filtering**: Different types of messages (info, warning, error, debug)
- **Timestamp Information**: Each log entry includes precise timing information
- **Clear Function**: Option to clear the current log display
- **Export Function**: Save log entries to file for analysis

### How to Use

1. Click on the "Log" tab to view real-time application logs
2. Monitor the logs for status updates and error messages
3. Use the clear function to reset the display when needed
4. Export logs to file for detailed analysis or troubleshooting

### Tips

- Monitor logs when troubleshooting connection issues or proxy problems
- Look for error messages that can help identify configuration problems
- Verbose logging (enabled in Settings) provides more detailed information for debugging

## Certificate Export

InterceptSuite provides cross-platform functionality to export the CA certificate and private key for use in other applications or for trust establishment on different systems.

### Features

- **Certificate Export**: Export the CA certificate in DER format for installation on other systems
- **Private Key Export**: Export the private key in PEM format for advanced use cases
- **Cross-Platform Compatibility**: Exported certificates work on Windows, Linux, and macOS
- **Automatic File Naming**: Exported files are automatically named with appropriate extensions
- **Directory Selection**: Choose where to save the exported certificate files

### How to Use

1. Navigate to the Settings subtab in the Proxy tab
2. Look for the "Certificate Export" section
3. Click "Export Certificate (DER)" to export the certificate file
4. Click "Export Private Key (PEM)" to export the private key file
5. Select the destination directory when prompted
6. The files will be saved with standard naming conventions

### Use Cases

- **Multi-System Setup**: Install the CA certificate on multiple computers or mobile devices across different operating systems
- **Development Teams**: Share the CA certificate with team members working on Windows, Linux, or macOS
- **CI/CD Pipelines**: Integrate the certificate into automated testing environments regardless of platform
- **Network Analysis**: Use with other security tools that require the CA certificate
- **Container Deployments**: Install certificates in Docker containers or Kubernetes pods

### Platform-Specific Usage

#### Windows
- The exported DER certificate can be directly installed using the Windows Certificate Manager
- Use the exported certificate with Windows applications and system certificate store

#### Linux
- Convert DER to PEM format if needed: `openssl x509 -inform DER -in cert.der -out cert.pem`
- Install using distribution-specific certificate management tools
- Use with applications that require custom CA certificates

#### macOS
- The DER format is directly compatible with macOS Keychain Access
- Import into system or user keychain as needed
- Compatible with macOS applications and system certificate verification

### Tips

- Keep the private key secure and only share when absolutely necessary
- The DER format certificate can be directly installed on most systems without conversion
- Consider regenerating certificates periodically for security best practices
- Test certificate installation on target platforms before deploying to production environments

## Common Workflows

### Basic Traffic Interception

1. Configure your client application to use InterceptSuite's SOCKS5 proxy (127.0.0.1:4444 by default)
2. Start the proxy in the Settings subtab
3. Navigate to the Intercept subtab and enable interception
4. Use your client application to generate traffic
5. Observe, and optionally modify, the intercepted traffic

### Selective Traffic Analysis

1. In the Settings subtab, configure the intercept direction based on your needs
2. Start the proxy and generate traffic from your client application
3. Review the Proxy History subtab to analyze the traffic
4. Use the search/filter functions to focus on specific traffic patterns

### Troubleshooting Connection Issues

1. Start the proxy and configure your client application
2. Monitor the Connections subtab to observe connection establishment
3. Check the Log tab for connection errors and status messages
4. Review connection details in the Connections subtab for active connection information

### Exporting Traffic for Analysis

1. Generate traffic through the proxy
2. Navigate to either the Proxy History or Connections subtab
3. Click the Export button to save the data
4. Use external tools to analyze the exported data if needed

---

For information about building InterceptSuite from source or integrating it with your own applications, see:
- [Build Guide](Build.md)
- [Library Integration Guide](Library_INTEGRATION.md)