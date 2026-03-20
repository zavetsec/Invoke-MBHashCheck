<div align="center">

# 🔍 Invoke-MBHashCheck

**PowerShell hash lookup against MalwareBazaar & ThreatFox**  
*Built for DFIR analysts, SOC teams, and threat hunters*

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078d4?logo=windows)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-brightgreen)](LICENSE)
[![MalwareBazaar](https://img.shields.io/badge/API-MalwareBazaar-orange)](https://bazaar.abuse.ch)
[![ThreatFox](https://img.shields.io/badge/API-ThreatFox-red)](https://threatfox.abuse.ch)
[![Version](https://img.shields.io/badge/Version-2.0-gold)](CHANGELOG.md)

</div>

---

## What it does

Checks MD5 / SHA1 / SHA256 hashes against **MalwareBazaar** (abuse.ch) and enriches MALICIOUS hits with **ThreatFox** IOC intelligence + GeoIP data. Generates a self-contained, dark-themed HTML report.

```
Hash input (file / directory / inline)
        │
        ▼
 MalwareBazaar API  ──►  MALICIOUS  ──►  ThreatFox search_hash
        │                                       │
        ├── NOT_FOUND                     C2 IPs / Domains
        └── ERROR                               │
                                          GeoIP (ip-api.com)
                                               │
                                               ▼
                                      HTML Report + Console
```

---

## Features

| Feature | Description |
|---|---|
| **Bulk hash lookup** | Check hundreds of hashes from a text file |
| **Directory scan** | Auto-hash all files in a folder (`-ScanDirectory`) |
| **ThreatFox enrichment** | C2 IPs, domains, confidence levels for MALICIOUS hits |
| **GeoIP** | Country, city, ISP, ASN for each C2 IP via ip-api.com |
| **Retry logic** | Auto-retry on transient network errors |
| **Progress bar** | Native PowerShell `Write-Progress` |
| **Dark HTML report** | Filterable, searchable, self-contained |
| **Pipeline support** | `-PassThru` outputs objects for scripting |
| **Quiet mode** | `-Quiet` shows MALICIOUS only in console |
| **PS 5.1 compatible** | No external dependencies |

---

## Requirements

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 or later (built into Windows 10+) |
| MalwareBazaar Auth-Key | Free at **[auth.abuse.ch](https://auth.abuse.ch)** (sign in with GitHub / Google / LinkedIn) |
| Internet access | `mb-api.abuse.ch`, `threatfox-api.abuse.ch`, `ip-api.com` |

---

## Quick Start

```powershell
# 1. Get your free key at https://auth.abuse.ch

# 2. Run against a hash file
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt"

# 3. Open the generated HTML report
```

---

## Usage Examples

### Hash file
```powershell
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt"
```

### Auto-scan a directory
```powershell
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -ScanDirectory "C:\Suspicious" -Recurse
```

### Single hash (inline)
```powershell
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -Hashes "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
```

### Quiet mode — MALICIOUS hits only
```powershell
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt" -Quiet
```

### Pipeline / export to CSV
```powershell
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt" -PassThru |
    Where-Object Status -eq "MALICIOUS" |
    Select-Object Hash, Signature, Tags |
    Export-Csv hits.csv -NoTypeInformation
```

### Custom output folder and retry settings
```powershell
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt" `
    -OutputDir "C:\Reports" -MaxRetries 5 -RetryDelaySeconds 10
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-ApiKey` | String | — | MalwareBazaar / ThreatFox Auth-Key |
| `-HashFile` | String | — | Path to file with hashes (one per line) |
| `-Hashes` | String[] | — | Hashes passed directly as array |
| `-ScanDirectory` | String | — | Directory to scan and hash automatically |
| `-Recurse` | Switch | false | Recurse into subdirectories |
| `-OutputDir` | String | current dir | Where to save the HTML report |
| `-MaxRetries` | Int | 3 | Retry attempts on transient errors |
| `-RetryDelaySeconds` | Int | 5 | Seconds between retries |
| `-Quiet` | Switch | false | Show only MALICIOUS in console |
| `-PassThru` | Switch | false | Output result objects to pipeline |

---

## Hash file format

Plain text, one hash per line. Comments (`#`) and blank lines are ignored. MD5, SHA1, and SHA256 are all supported.

```text
# WannaCry
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa

# AgentTesla
5dd92be22d005624d865ddf07402eb852426fc97baa52bbc58316690d41adb74

# MD5 is fine too
84c82835a5d21bbcf75a61706d8ab549
```

---

## Console Output

```
 ______          _____
|___  /         /  ___|
   / /  __ ___  \ `--. ___  ___
  / /  / _` \ \  `--. / _ \/ __|
./ /__| (_| |> \/\__/ /  __/ (__
\_____/\__,_/_/\_\____/ \___|\___|
   ZavetSec - MalwareBazaar Hash Checker v2.0

[1/3] ed01ebfbc9eb5bbea545... (SHA256) ... [MALICIOUS]  WannaCry  | ransomware
  [TF] Querying ThreatFox for related IOCs...
      Found 2 IOC(s) | 2 IP/port
[2/3] 84c82835a5d21bbcf75a... (MD5)    ... [MALICIOUS]  WannaCry
[3/3] 0000000000000000000a... (SHA256) ... [NOT_FOUND]

------------------------------------------------------
  Total:         3
  MALICIOUS:     2
  NOT IN DB:     1
  ThreatFox hits:1
  TF IOCs total: 2
```

---

## HTML Report

Self-contained `.html` file saved to `OutputDir`. Features:

- Summary stat cards (total / malicious / not in DB / errors)
- Color-coded verdict badges per row
- Expandable hash details (SHA256 / SHA1 / MD5)
- Intel column: ClamAV detections, download/upload counts
- Filter buttons by verdict + full-text search
- **ThreatFox IOC section** (when C2 data available): IOC type, malware family, confidence %, GeoIP with country flags, Shodan links

---

## Understanding Results

| Status | Meaning |
|---|---|
| `MALICIOUS` | Confirmed in MalwareBazaar database |
| `NOT_FOUND` | Not in MalwareBazaar — **does not mean clean** |
| `ERROR` | API / network error |

> MalwareBazaar only indexes **confirmed malware samples**. `NOT_FOUND` means the hash hasn't been submitted, not that the file is safe. Cross-reference with additional threat intelligence sources.

**ThreatFox enrichment** fires on MALICIOUS hits when the hash has been explicitly submitted to ThreatFox as an IOC by a security researcher. This is relatively rare — most ThreatFox IOCs are IP:port and domain entries.

---

## License

MIT — free to use, modify, and distribute. Attribution appreciated.

---

<div align="center">

Built by **[ZavetSec](https://github.com/zavetsec)** · If this tool helped you, leave a ⭐

</div>
