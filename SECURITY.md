# Security Policy

## Supported Versions

We actively support and provide security updates for the following versions of InterceptSuite:

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.0   | :x:                |
| < 1.0   | :x:                |

> **Note**: We recommend always using the latest version available in our [releases page](https://github.com/InterceptSuite/InterceptSuite/releases) to ensure you have the most recent security updates and bug fixes.

## Reporting a Vulnerability

We take security seriously and appreciate your help in keeping InterceptSuite secure. If you discover a security vulnerability, please report it responsibly.

### How to Report

You can report security vulnerabilities through either of the following methods:

1. **GitHub Security Advisories (Preferred)**
   - Go to: https://github.com/InterceptSuite/InterceptSuite/security/advisories/new
   - Fill out the security advisory form with detailed information
   - This method allows for private disclosure and coordinated fixes

2. **Email**
   - Send an email to: **kalalsourav20@gmail.com**
   - Include "SECURITY VULNERABILITY" in the subject line
   - Provide detailed information about the vulnerability

### What to Include in Your Report

Please include the following information in your vulnerability report:

- **Description**: A clear description of the vulnerability
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Impact**: Potential impact and severity of the vulnerability
- **Affected Versions**: Which versions of InterceptSuite are affected
- **Environment**: Operating system, .NET version, and other relevant details
- **Proof of Concept**: If possible, include a proof of concept or exploit code
- **Suggested Fix**: If you have ideas for how to fix the issue

### Response Timeline

We are committed to responding to security reports promptly:

- **Initial Response**: Within 48 hours of receiving your report
- **Status Update**: Regular updates every 7 days until resolution
- **Fix Timeline**: Critical vulnerabilities will be addressed within 7 days, other vulnerabilities within 30 days
- **Public Disclosure**: Coordinated disclosure after the fix is available

### Security Best Practices for Users

To use InterceptSuite securely:

1. **Certificate Management**
   - Only install the InterceptSuite CA certificate on systems you control
   - Remove the CA certificate when no longer needed
   - Never share or distribute the generated CA certificate files

2. **Network Security**
   - Use InterceptSuite only in controlled, isolated environments
   - Be aware that InterceptSuite performs man-in-the-middle attacks on TLS traffic
   - Ensure proper network segmentation when analyzing production traffic

3. **Data Handling**
   - Be cautious when intercepting sensitive data
   - Follow your organization's data privacy and security policies
   - Securely delete captured traffic logs when analysis is complete

4. **Updates**
   - Keep InterceptSuite updated to the latest version
   - Monitor our releases for security updates
   - Subscribe to our security advisories for notifications

### Scope

This security policy covers:

- The InterceptSuite application (GUI and core library)
- The native C library (Intercept.dll/libIntercept.so/libIntercept.dylib)
- Build scripts and configuration files
- Documentation that could impact security

### Out of Scope

The following are typically considered out of scope:

- Vulnerabilities in third-party dependencies (please report to the respective projects)
- Issues that require physical access to the machine
- Social engineering attacks
- Denial of service attacks against the proxy server (by design, it's a local tool)

### Recognition

We believe in recognizing security researchers who help improve our project:

- Security researchers who report valid vulnerabilities will be credited in our security advisories (unless they prefer to remain anonymous)
- We maintain a list of security contributors in our project documentation
- For significant vulnerabilities, we may provide additional recognition as appropriate

### Legal

We will not pursue legal action against security researchers who:

- Report vulnerabilities through the proper channels described above
- Act in good faith and avoid violating privacy or destroying data
- Do not publicly disclose vulnerabilities before we have had a chance to address them
- Do not access or modify data that doesn't belong to them

### Contact

For any questions about this security policy, please contact:

- **Email**: kalalsourav20@gmail.com
- **GitHub**: [@Anof-cyber](https://github.com/Anof-cyber)

---

**Last Updated**: July 2025

This security policy may be updated from time to time. Please check back periodically for the most current version.
