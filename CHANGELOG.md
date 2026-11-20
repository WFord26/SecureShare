# Changelog

All notable changes to SecureShare will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Fixed MEDIUM severity: IP address validation flaw in `clientIp()` function
  - Replaced permissive regex with Node.js built-in `isIPv4()` and `isIPv6()` validation
  - Prevents invalid IPv4 addresses (octet > 255) from bypassing rate limiting
  - Prevents audit log spoofing with crafted IP addresses
- Fixed MEDIUM severity: Cookie parsing vulnerability in `getCookie()` function
  - Improved cookie name comparison logic to prevent partial matches
  - Enhanced protection against URL-encoded delimiter injection
  - See [SECURITY-FIXES.md](SECURITY-FIXES.md) for detailed vulnerability analysis

---

## [1.1.0] - 2026-09-30

Baseline entry: the state of the app when formal change tracking began. For
detail on anything before this point, see `git log`.

### Added

- Optional password protection for download links (the password can't be changed after upload, so uploaders are warned up front)
- Streaming uploads straight to Azure Blob Storage instead of buffering the whole file in memory, fixing 502s on large uploads on the B1 App Service plan
- Microsoft Defender for Storage malware scanning on every upload, gating download availability on a clean verdict
- Microsoft Purview integration for uploaded files
- Authentication and authorization via Microsoft Entra ID, including an app-role-gated activity log
