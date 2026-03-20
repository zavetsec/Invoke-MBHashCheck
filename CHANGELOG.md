# Changelog

All notable changes to Invoke-MBHashCheck are documented here.

## [2.0] — 2026-03-20

### Added
- **ThreatFox integration** — `search_hash` lookup on every MALICIOUS hit via ThreatFox API
- **GeoIP enrichment** — Country, city, ISP, ASN for C2 IPs via ip-api.com (no key required)
- **ThreatFox HTML section** — "ThreatFox IOC Intelligence" table in report with country flags, Shodan links, confidence color-coding
- `-ScanDirectory` parameter — auto-hash all files in a folder before lookup
- `-Recurse` switch — recurse into subdirectories when scanning
- `-Quiet` switch — suppress NOT_FOUND output, show only MALICIOUS in console
- `-PassThru` switch — return result objects to the PowerShell pipeline
- `-MaxRetries` / `-RetryDelaySeconds` — automatic retry on transient network errors
- Native PowerShell progress bar (`Write-Progress`)
- TF IOC count in final summary (`ThreatFox hits` / `TF IOCs total`)
- `Get-Prop` module-level helper for safe `PSObject.Properties` access under `StrictMode`

### Fixed
- `Signature` extraction: fallback chain — `signature` → `popular_threat_classification.suggested_threat_label` → first YARA rule name
- `Tags` extraction: fallback via `vendor_intel.ANY.RUN.malware_family`
- `Get-Prop` moved out of `try` block — was causing PS 5.1 scope issues resulting in all fields returning N/A
- ThreatFox hash lookup now uses SHA256 → MD5 → SHA1 → original hash fallback chain
- Removed `&nbsp;` artifact from FileType table cell
- Removed all Cyrillic from PowerShell executable code (UTF-8 BOM + CRLF encoding)

### Changed
- User-Agent updated to `ZavetSec-MBHashCheck/2.0 (github.com/zavetsec)`
- HTML report logo: gold glowing ZavetSec branding
- GitHub link added to report footer and header subtitle
- Script version bumped to 2.0

---

## [1.0] — 2025-03-15

### Added
- Initial release
- Hash lookup against MalwareBazaar API (MD5 / SHA1 / SHA256)
- Input from file, parameter array, or interactive console prompt
- Dark-themed HTML report with filter buttons and full-text search
- Auth-Key authentication via `Auth-Key` HTTP header
- Safe property access via `PSObject.Properties` under `Set-StrictMode -Version Latest`
- UTF-8 BOM + CRLF encoding for full PS 5.1 Windows compatibility
- Rate limiting delay between requests
