## TLS MITM Proxy C# Application Troubleshooting Guide

### Issue: HTTPS Not Working with Firefox

When using the C# application with Firefox, HTTPS websites (like YouTube) show "no internet" while the proxy history shows only port 80 connections. The Python application works correctly with the same DLL.

### Solution

The issue is related to how Firefox handles HTTPS connections through the SOCKS5 proxy. Here's how to fix it:

1. **Configure Firefox to properly use the SOCKS5 proxy for HTTPS**:

   - Open Firefox
   - Go to Settings (≡ Menu → Settings)
   - Scroll down to "Network Settings" and click "Settings..."
   - Configure proxy as follows:
     - Select "Manual proxy configuration"
     - SOCKS Host: 127.0.0.1
     - Port: 4444 (or whatever port you configured)
     - Select "SOCKS v5"
     - **Important**: Check "Proxy DNS when using SOCKS v5" (this is the key setting)

2. **Ensure complete HTTPS handling in Firefox**:

   - Type `about:config` in the address bar
   - Search for `network.proxy.socks_remote_dns`
   - Make sure it's set to `true`
   - Search for `security.ssl.require_safe_negotiation`
   - Make sure it's set to `false`

3. **Troubleshooting steps** if you still encounter issues:

   - Clear Firefox cache and cookies
   - Restart Firefox after configuring the proxy
   - Verify the proxy is running (check "Running" status in the app)
   - Try a different HTTPS website to test
   - Check if your antivirus/firewall is blocking the connections

### Technical Explanation

The TLS MITM proxy works by:
1. Receiving the SOCKS5 connection from Firefox
2. Extracting the hostname and port from the SOCKS5 request
3. Establishing a connection to the target server
4. Intercepting the TLS handshake and generating a certificate on-the-fly
5. Establishing encrypted connections with both the client and server

With HTTPS connections (port 443), Firefox needs to be configured to send DNS requests through the SOCKS proxy as well, which is what the "Proxy DNS when using SOCKS v5" option enables. Without this setting, DNS resolution happens locally, which can cause issues with the certificate validation.

This difference in behavior explains why the C# application is only showing port 80 connections - Firefox isn't properly routing HTTPS connections through the proxy due to configuration differences.
