<div align="center">

<img src="logo.png" alt="InterceptSuite Logo" width="120"/>

# 🛡️ InterceptSuite

### *TLS/SSL Traffic Interception & Analysis*
*Protocol-agnostic network traffic inspection that goes beyond traditional HTTP-only tools*
</div>



![Tauri](https://img.shields.io/badge/Tauri-FFC131?style=for-the-badge&logo=tauri&logoColor=black)
![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)
[![Build Status](https://github.com/Anof-cyber/InterceptSuite/actions/workflows/rust-tauri.yml/badge.svg)](https://github.com/Anof-cyber/InterceptSuite/actions/workflows/rust-tauri.yml)
[![C InterceptSuite Build](https://github.com/Anof-cyber/InterceptSuite/actions/workflows/Build-DLL.yml/badge.svg)](https://github.com/Anof-cyber/InterceptSuite/actions/workflows/Build-DLL.yml)
[![Downloads](https://img.shields.io/github/downloads/anof-cyber/InterceptSuite/total)](https://github.com/anof-cyber/InterceptSuite/releases)
[![License](https://img.shields.io/github/license/anof-cyber/InterceptSuite)](LICENSE)
[![Stars](https://img.shields.io/github/stars/anof-cyber/InterceptSuite)](https://github.com/anof-cyber/InterceptSuite)

![Platform Support](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-purple)
![Tauri](https://img.shields.io/badge/GUI-Tauri%20%2B%20Rust-orange)
![Protocol](https://img.shields.io/badge/Protocol-SOCKS5-blue)



---

## 🌟 Overview

**InterceptSuite** is a cross-platform network traffic interception tool engineered for comprehensive TLS/SSL inspection, analysis, and manipulation at the network level. Unlike traditional tools such as Burp Suite or OWASP ZAP that focus specifically on HTTP/HTTPS traffic, InterceptSuite provides **unprecedented visibility** into any TLS-encrypted protocol, operating seamlessly at the TCP/TLS layer.

### 🎯 The Challenge We Solve

The original inspiration behind InterceptSuite was to address a critical gap in application penetration testing. Security professionals often struggle with limited options for intercepting network traffic from native applications, making it challenging to perform comprehensive packet or traffic analysis of thick clients and custom protocols.

### 💡 Our Solution

InterceptSuite bridges this gap by providing a **universal TLS interception engine** that works with any protocol, giving security researchers the tools they need to analyze, understand, and test encrypted communications effectively.

### Platform Support

| Component | Windows | Linux | macOS |
|-----------|:-------:|:-----:|:-----:|
| Core Library | ✅ | ✅ | ✅ |
| GUI Interface | ✅ | ✅ | ✅ |

## Table of Contents

- [🌟 Overview](#-overview)
- [✨ Features](#-features)
- [🚀 Getting Started](#-getting-started)
- [📖 Usage](#-usage)
- [🔧 Proxy Configuration](#-proxy-configuration)
- [⚠️ Current Limitations](#️-current-limitations)
- [🤔 When to Use InterceptSuite vs. HTTP-Specific Tools](#-when-to-use-interceptsuite-vs-http-specific-tools)
- [🖼️ Screenshots](#️-screenshots--interface)
- [🛠️ Development](#️-development)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)

## ✨ Features

- **🌐 Protocol-Agnostic TLS Interception**: Intercept TLS/SSL traffic from any application or protocol
- **🔌 SOCKS5 Proxy Integration**: Uses SOCKS5 proxy protocol for versatile connection handling
- **⚡ Real-time Traffic Analysis**: View decrypted traffic as it flows through the proxy
- **🎛️ Connection Management**: Track active connections and view their details
- **🔐 Certificate Authority Management**: Automatic generation of CA certificates with platform-specific storage
- **🔧 Traffic Manipulation**: Modify intercepted traffic before forwarding
- **⚡ High-Performance C Core**: Optimized C engine for maximum speed and minimal memory footprint
- **📚 Custom Integration**: Embed TLS interception capabilities into your own applications with our DyLib, So and DLL
- **🎨 Modern GUI**: Built with Tauri + Rust frontend and high-performance C core
- **📝 Detailed Logging**: Comprehensive logging with automatic rotation and cleanup

## 🚀 Getting Started

### Prerequisites

- **Windows 10/11 (64-bit)**, **Linux (x64)**, or **macOS (Apple Silicon)**

### Installation

1. **Download** the platform-specific installer from the [Releases page](https://github.com/anof-cyber/InterceptSuite/releases)
   - **Windows**: `.exe` installer or `.msi` package
   - **Linux**: `.deb` (Ubuntu/Debian) or `.rpm` (RedHat/Fedora) package
   - **macOS**: `.dmg` disk image
2. **Run** the installer and follow the setup wizard
3. **Launch** InterceptSuite from your applications menu or desktop shortcut

> **Note:** Platform-specific native installers are available for seamless installation on all supported operating systems.
## 📖 Usage

For comprehensive setup and usage instructions, see our detailed **[Usage Guide](Usage.md)**.

### Quick Start

1. **Launch** InterceptSuite application
2. **Start** the proxy server (default: `127.0.0.1:4444`)
3. **Install** the generated CA certificate as a trusted root
4. **Configure** your client application to use the SOCKS5 proxy
5. **Begin** intercepting and analyzing TLS traffic

> **Important:** InterceptSuite generates a unique CA certificate on first run that must be installed as a trusted root certificate authority for TLS interception to work.


## GitAds Sponsored
[![Sponsored by GitAds](https://gitads.dev/v1/ad-serve?source=anof-cyber/interceptsuite@github)](https://gitads.dev/v1/ad-track?source=anof-cyber/interceptsuite@github)



## 🔧 Proxy Configuration

Configure your client application to use the SOCKS5 proxy at `127.0.0.1:4444`.

For detailed platform-specific configuration instructions, see the **[Usage Guide](Usage.md)**.

### Platform Notes

- **Windows**: Use Proxifier for system-wide SOCKS5 support
- **Linux**: Multiple options including ProxyCap, tsocks, Proxychains, or iptables
- **macOS**: Proxifier for Mac or Proxychains-ng for terminal applications

## ⚠️ Current Limitations

Understanding InterceptSuite's current limitations helps you choose the right tool for your specific use case.

### 🚫 Non-Standard TLS Handshakes

**Current Limitation:** InterceptSuite cannot bypass TLS for protocols that do not use standard TLS handshake as the initial packet after TCP handshake.

#### 📋 Affected Protocols:

- **🐘 PostgreSQL** - TLS sessions
- **🐬 MySQL** - TLS sessions
- **🔧 SmartTLS** - Similar technologies
- **🔌 Custom Protocols** - Non-standard handshakes

> **🔜 Future Release:** This functionality is planned for future releases.

### 📊 Protocol Dissection

**Current Limitation:** The tool does not support protocol dissection, meaning it cannot decode protocol-specific binary formats or encodings regardless of whether TLS is used.

#### 🔍 Examples of Non-Supported Formats:

| Format Type | Examples | Description |
|-------------|----------|-------------|
| Binary Protocols | Protocol Buffers, MessagePack | Structured binary encodings |
| Custom Encodings | Application-specific formats | Proprietary data structures |
| Compressed Data | Obfuscated data streams | Compressed or encoded payloads |

> **💡 Important Note:** If a protocol doesn't transmit data in plain text (even after TLS decryption), InterceptSuite will show the raw bytes but not interpret them.

> **🔜 Future Release:** Protocol dissection functionality is planned for future releases.

## 🤔 When to Use InterceptSuite vs. HTTP-Specific Tools

Choose the right tool for your security testing needs with our comprehensive comparison guide.

> [!NOTE]
> **🎯 Key Recommendation:** While InterceptSuite can handle HTTP/HTTPS traffic, it is **strongly recommended** to use HTTP-specific tools like Burp Suite or OWASP ZAP for web traffic inspection. These tools provide specialized features optimized for HTTP-based protocols.

### ✅ Use InterceptSuite when:

- 🌐 Working with **non-HTTP TLS-encrypted protocols**
- 🔍 Analyzing network traffic at the **TCP/TLS layer**
- 🛠️ Debugging **custom TLS-encrypted protocols**
- 📱 Testing **thick client applications**
- 🎮 Analyzing **game or IoT protocols**
- 🔧 Developing **protocol-specific security tools**

### 🌐 Use Burp Suite or OWASP ZAP when:

- 🌍 Working specifically with **HTTP/HTTPS traffic**
- 🖥️ Testing **web applications**
- 🔒 Performing **web security assessments**
- 🔄 When HTTP-specific features are needed:
  - Request repeating
  - Vulnerability scanning
  - Session management
  - Authentication testing

### 🎯 Decision Matrix

| Scenario | InterceptSuite | Burp/ZAP | Reason |
|:---------|:--------------:|:---------:|:--------|
| 🌐 Web App Testing | ❌ | ✅ | HTTP-specific features needed |
| 📱 Mobile App API | 🤔 | ✅ | Depends on protocol (HTTP vs custom) |s
| 🔌 IoT Device Comms | ✅ | ❌ | Custom TLS protocols |
| 🖥️ Desktop App Traffic | ✅ | 🤔 | Protocol-dependent |
| 🔒 Database TLS | ⚠️ | ❌ | Limited support (future feature) |

**Legend:** ✅ Recommended • 🤔 Depends • ⚠️ Limited • ❌ Not suitable


## 🖼️ Screenshots & Interface

Explore InterceptSuite's intuitive interface through our comprehensive screenshot gallery showcasing each major feature.

### 🔍 Intercept Tab
![Intercept Tab](Images/Intercept.png)

*The Intercept tab allows you to view and modify network packets in real-time, providing granular control over TLS traffic flow.*

### 📚 Proxy History Tab
![Proxy History Tab](Images/Prxoy-History.png)

*The Proxy History tab shows all messages that have passed through the SOCKS5 proxy with comprehensive logging and filtering capabilities.*

### ⚙️ Settings Tab
![Settings Tab](Images/Settings.png)

*The Settings tab provides configuration options for the proxy server, logging, interception rules, and certificate management. Use the Export Certificate feature to save certificates in different formats.*

### 🔗 Connections Tab
![Connections Tab](Images/Connections.png)

*The Connections tab displays TCP connection details and allows for exporting connection data with real-time monitoring of active sessions.*


## 🛠️ Development

Join the InterceptSuite development community and contribute to the future of TLS traffic analysis tools.

[![📖 Build Guide](https://img.shields.io/badge/📖%20Build%20Guide-28a745?style=for-the-badge&logoColor=white)](Build.md)

### 🌍 Cross-Platform Building

InterceptSuite now supports building on **Windows**, **Linux**, and **macOS** with native library generation for each platform.

#### 📦 Platform-Specific Library Outputs

| Platform | Library Format | Build Tool | Status |
|----------|----------------|------------|--------|
| 🪟 Windows | `.dll` | Visual Studio / CMake | ✅ **Ready** |
| 🐧 Linux | `.so` | GCC / CMake | ✅ **Ready** |
| 🍎 macOS | `.dylib` | Clang / CMake | ✅ **Ready** |

> **🚀 Getting Started with Development:**
>
> For detailed instructions on building InterceptSuite for each platform, see the [**Build Guide**](Build.md). This guide includes platform-specific prerequisites, build commands, and troubleshooting tips.

### 🤝 Contributing

- **🐛 Bug Reports** - Found an issue? Report it on our GitHub Issues page with detailed reproduction steps.
- **✨ Feature Requests** - Have an idea for improvement? We welcome feature requests and enhancement suggestions.
- **🔧 Pull Requests** - Ready to contribute code? Check our contribution guidelines before submitting PRs.
- **📚 Documentation** - Help improve our documentation, examples, and tutorials for better user experience.

## 📄 License

InterceptSuite is open source software, committed to transparency and community collaboration.

![AGPL License](https://img.shields.io/badge/License-AGPL%20v3.0-blue?style=for-the-badge&logo=gnu)

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**

[![📖 Read Full License](https://img.shields.io/badge/%F0%9F%93%96%20Read%20Full%20License-007bff?style=for-the-badge&logoColor=white)](LICENSE)

*The AGPL-3.0 license ensures that InterceptSuite remains free and open source, while requiring that any network-based services using this code also provide their source code to users.*

---

## 🙏 Acknowledgments

Special thanks to the amazing open source communities and technologies that make InterceptSuite possible.

### 🔐 OpenSSL
![OpenSSL](https://img.shields.io/badge/OpenSSL-721412?style=for-the-badge&logo=openssl&logoColor=white)

Providing robust TLS/SSL functionality and cryptographic operations

### 🚀 Tauri + Rust + C
![Tauri](https://img.shields.io/badge/Tauri-FFC131?style=for-the-badge&logo=tauri&logoColor=black)
![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)

High-performance C core engine with modern Tauri + Rust GUI for optimal performance and user experience

### 🔨 CMake
![CMake](https://img.shields.io/badge/CMake-064F8C?style=for-the-badge&logo=cmake&logoColor=white)

Enabling cross-platform build system management and compilation

### 💖 Community Support

InterceptSuite is built with love by the cybersecurity community, for the cybersecurity community. Thank you to all contributors, testers, and users who help make this project better every day!

---

![Made with Love](https://img.shields.io/badge/Made%20with%20❤️%20for%20the%20Security%20Community-FF69B4?style=for-the-badge)

**🛡️ Secure by Design • 🌍 Cross-Platform • 🔓 Open Source**

[![⭐ Star on GitHub](https://img.shields.io/badge/⭐%20Star%20on%20GitHub-333?style=for-the-badge&logo=github)](https://github.com/anof-cyber/InterceptSuite)
[![🐛 Report Issues](https://img.shields.io/badge/🐛%20Report%20Issues-red?style=for-the-badge&logo=github)](https://github.com/anof-cyber/InterceptSuite/issues)