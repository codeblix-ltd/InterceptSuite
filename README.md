# InterceptSuite

<img src="logo.png" alt="InterceptSuite Logo" width="200"/>

## Overview

InterceptSuite is a powerful network traffic interception tool designed for TLS/SSL inspection, analysis, and manipulation at the network level. Unlike tools like Burp Suite or OWASP ZAP that focus specifically on HTTP/HTTPS traffic, InterceptSuite aims to provide visibility into any TLS-encrypted protocol, operating at the TCP/TLS layer.

The original idea behind InterceptSuite was to solve a challenging problem in Windows application penetration testing. With limited options to intercept network traffic of Windows applications, it's often difficult for security professionals to perform packet or traffic analysis of thick clients.

[![Build and Upload .NET GUI App](https://github.com/Anof-cyber/InterceptSuite/actions/workflows/dotnet-gui.yml/badge.svg)](https://github.com/Anof-cyber/InterceptSuite/actions/workflows/dotnet-gui.yml)
[![Build Intercept Suite DLL](https://github.com/Anof-cyber/InterceptSuite/actions/workflows/Build-DLL.yml/badge.svg)](https://github.com/Anof-cyber/InterceptSuite/actions/workflows/Build-DLL.yml)
[![Create Release Package](https://github.com/Anof-cyber/InterceptSuite/actions/workflows/release.yml/badge.svg)](https://github.com/Anof-cyber/InterceptSuite/actions/workflows/release.yml)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Windows Proxy Configuration](#windows-proxy-configuration)
- [Current Limitations](#current-limitations)
- [When to Use InterceptSuite vs. HTTP-Specific Tools](#when-to-use-interceptsuite-vs-http-specific-tools)
- [Images](#images)
- [Development](#development)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Features

- **Protocol-Agnostic TLS Interception**: Intercept TLS/SSL traffic from any application or protocol
- **SOCKS5 Proxy Integration**: Uses SOCKS5 proxy protocol for versatile connection handling with various client applications
- **Real-time Traffic Analysis**: View decrypted traffic as it flows through the proxy
- **Connection Management**: Track active connections and view their details
- **Certificate Authority Management**: Automatic generation of CA certificates for TLS interception
- **Traffic Manipulation**: Modify intercepted traffic before forwarding
- **DLL Integration**: Embed TLS interception capabilities into your own applications
- **User-friendly GUI**: Modern interface for easy interaction with the proxy server
- **Detailed Logging**: Comprehensive logging of all intercepted traffic

## Getting Started

### Prerequisites

- Windows 10/11 (64-bit)
- .NET 8.0 Runtime

### Installation

1. Download the `InterceptSuite-v*-win-x64.zip` file from the [Releases page](https://github.com/anof-cyber/InterceptSuite/releases)
2. Extract the ZIP file to your preferred location
3. Run `InterceptSuite.exe` from the extracted folder

> [!Note]
> InterceptSuite requires .NET 8.0 Runtime or later to run. If not already installed on your system, the application will provide you with a direct download link when you attempt to run it.

For detailed build instructions, see the [Build Guide](Build.md).

## Usage

1. Start InterceptSuite
2. Configure proxy settings (default: 127.0.0.1:4444)
3. Start the proxy server
   - **Important:** When first started, InterceptSuite creates a new CA certificate (`Intercept_Suite_Cert.pem`) in the same directory
   - You must install this certificate into your Windows system as a trusted root certificate authority
   - To install: double-click the certificate file → Install Certificate → Local Machine → Place all certificates in the following store → Browse → Trusted Root Certification Authorities → OK → Next → Finish
4. Configure your client application to use the proxy
5. Begin intercepting TLS traffic

For detailed usage instructions and features explanation, see the [Usage Guide](Usage.md).

For more details on integration with your own applications, see the [DLL Integration Guide](DLL_INTEGRATION.md).


## Windows Proxy Configuration

Windows by default only supports HTTP proxies at the system level and does not provide native support for SOCKS5 proxies. Since InterceptSuite operates as a SOCKS5 proxy, it's recommended to use a proxy management tool such as [Proxifier](https://www.proxifier.com/) to enable system-wide proxy capabilities.

Benefits of using Proxifier with InterceptSuite:
- Enables kernel-mode Windows Filtering Platform (WFP) to force any application through the proxy
- Provides flexible proxy rules and configuration options
- Allows selective proxying based on application, destination, or other criteria
- Integrates seamlessly with SOCKS5 proxies like InterceptSuite

This combination creates a powerful setup for intercepting network traffic from applications that don't natively support proxy configuration.

## Current Limitations

- **Non-Standard TLS Handshakes**: InterceptSuite cannot bypass TLS for protocols that do not use standard TLS handshake as the initial packet after TCP handshake. Examples include:
  - PostgreSQL TLS sessions
  - MySQL TLS sessions
  - Any protocol that uses SmartTLS or similar technologies

  *This functionality is planned for future releases.*

- **Protocol Dissection**: The tool does not support protocol dissection, meaning it cannot decode protocol-specific binary formats or encodings regardless of whether TLS is used. For example:
  - Binary protocol encodings (like Protocol Buffers, MessagePack, etc.)
  - Custom application-specific encodings
  - Compressed or obfuscated data streams

  If a protocol doesn't transmit data in plain text (even after TLS decryption), InterceptSuite will show the raw bytes but not interpret them.

  *This functionality is planned for future releases.*

## When to Use InterceptSuite vs. HTTP-Specific Tools

> [!Note]
> While InterceptSuite can handle HTTP/HTTPS traffic, it is strongly recommended to use HTTP-specific tools like Burp Suite or OWASP ZAP for web traffic inspection. These tools provide specialized features optimized for HTTP-based protocols.

- **Use InterceptSuite when**:
  - Working with non-HTTP TLS-encrypted protocols
  - Analyzing network traffic at the TCP/TLS layer
  - Debugging custom TLS-encrypted protocols

- **Use Burp Suite or OWASP ZAP when**:
  - Working specifically with HTTP/HTTPS traffic
  - Testing web applications
  - Performing web security assessments
  - When HTTP-specific features (like request repeating, scanning, etc.) are needed


## Images

Below are screenshots of the main tabs in InterceptSuite:

### Intercept Tab
![Intercept Tab](Images/Intercept.png)
*The Intercept tab allows you to view and modify network packets in real-time.*

### Proxy History Tab
![Proxy History Tab](Images/Prxoy-History.png)
*The Proxy History tab shows all messages that have passed through the SOCKS5 proxy.*

### Settings Tab
![Settings Tab](Images/Settings.png)
*The Settings tab provides configuration options for the proxy server, logging, and interception rules.*

### Connections Tab
![Connections Tab](Images/Connections.png)
*The Connections tab displays TCP connection details and allows for exporting connection data.*


## Development

For information about building InterceptSuite from source, see the [Build Guide](Build.md).

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OpenSSL for TLS/SSL functionality
- .NET Framework for the GUI implementation