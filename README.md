<div align="center">

# 🔍 Invoke-MBHashCheck

**PowerShell bulk hash triage — MalwareBazaar + ThreatFox + GeoIP**  
*No SIEM needed. No installation. Just run.*

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078d4?logo=windows)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-brightgreen)](LICENSE)
[![MalwareBazaar](https://img.shields.io/badge/API-MalwareBazaar-orange)](https://bazaar.abuse.ch)
[![ThreatFox](https://img.shields.io/badge/API-ThreatFox-red)](https://threatfox.abuse.ch)
[![Version](https://img.shields.io/badge/Version-2.0-gold)](CHANGELOG.md)
[![PSScriptAnalyzer](https://github.com/zavetsec/Invoke-MBHashCheck/actions/workflows/lint.yml/badge.svg)](https://github.com/zavetsec/Invoke-MBHashCheck/actions)

</div>

---

## The Problem

During incident response, analysts manually:

1. Take suspicious file hashes
2. Check MalwareBazaar — open browser, paste, wait
3. Check ThreatFox separately — open browser, paste, wait  
4. Look up GeoIP for C2 IPs — open browser, paste, wait
5. Write notes in a ticket

**With 50+ hashes this takes hours. This tool does it in minutes, automatically.**

---

## What it does

```
Hash list (file / directory scan / inline)
            │
            ▼
    ┌─────────────────┐
    │  MalwareBazaar  │  ──►  MALICIOUS  ──►  ┌──────────────────┐
    │   get_info API  │                        │  ThreatFox       │
    └─────────────────┘                        │  search_hash API │
            │                                  └──────┬───────────┘
            ├── NOT_FOUND                             │ C2 IPs / Domains
            └── ERROR                                 ▼
                                              ┌──────────────────┐
                                              │  ip-api.com      │
                                              │  GeoIP (free)    │
                                              └──────┬───────────┘
                                                     │
                                                     ▼
                                        Self-contained HTML Report
                                        + Console output
```

**Result:** one HTML file you can open, filter, search, and drop into a ticket.

---

## Why Invoke-MBHashCheck?

| | Manual workflow | Invoke-MBHashCheck |
|---|---|---|
| 50 hashes | ~2 hours | ~10 minutes |
| Output | Notes in a text file | Filterable HTML report |
| SIEM required | No | No |
| Installation | — | None (built-in PS 5.1) |
| C2 enrichment | Manual | Automatic |
| Offline report | No | Yes, self-contained HTML |
| Pipeline / scripting | No | `-PassThru` to pipeline |

---

## Console output

```
 ______          _____
|___  /         /  ___|
   / /  __ ___  \ `--. ___  ___
  / /  / _` \ \  `--. / _ \/ __|
./ /__| (_| |> \/\__/ /  __/ (__
\_____/\__,_/_/\_\____/ \___|\___|
   ZavetSec - MalwareBazaar Hash Checker v2.0
   Powered by abuse.ch  |  Free key: auth.abuse.ch

[1/4] ed01ebfbc9eb5bbea545... (SHA256) ... [MALICIOUS]  WannaCry  | ransomware, wannacry
  [TF] Querying ThreatFox for related IOCs...
      Found 3 IOC(s) | 3 IP/port
[2/4] 5dd92be22d005624d865... (SHA256) ... [MALICIOUS]  AgentTesla  | exe, stealer
  [TF] Querying ThreatFox for related IOCs...
      No IOCs found in ThreatFox
[3/4] af0cbe1cb2efa531b259... (SHA256) ... [MALICIOUS]  CoinMiner  | exe
  [TF] Querying ThreatFox for related IOCs...
      No IOCs found in ThreatFox
[4/4] 0000000000000000000a... (SHA256) ... [NOT_FOUND]

------------------------------------------------------
  Total:          4
  MALICIOUS:      3
  NOT IN DB:      1
  ThreatFox hits: 1
  TF IOCs total:  3
  HTML report saved: .\MB_HashReport_20260320_153642.html
```

---

## HTML Report

Self-contained `.html` — no server, no internet required to open.

**Sections:**
- **Summary cards** — Total / Malicious / Not in DB / Errors at a glance
- **Hash table** — verdict badge, file name, type, signature, tags, ClamAV detections, first seen
- **ThreatFox IOC Intelligence** *(appears when C2 data is available)* — IOC type, malware family, confidence %, country flag + city, ASN, Shodan link per IP
- **Filter buttons** — All / Malicious / Not in DB / Suspicious
- **Full-text search** — instant filter across all rows

---

## Quick Start

```powershell
# 1. Get your free key at https://auth.abuse.ch (sign in with GitHub / Google / LinkedIn)

# 2. Run
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt"

# 3. Open the generated HTML report
```

---

## Usage Examples

```powershell
# Bulk check from file
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt"

# Auto-hash all files in a directory
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -ScanDirectory "C:\Suspicious" -Recurse

# Single hash (inline)
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -Hashes "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"

# Quiet mode — MALICIOUS hits only in console
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt" -Quiet

# Export MALICIOUS hits to CSV via pipeline
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt" -PassThru |
    Where-Object Status -eq "MALICIOUS" |
    Select-Object Hash, Signature, Tags, FirstSeen |
    Export-Csv hits.csv -NoTypeInformation

# Custom output folder + retry tuning
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt" `
    -OutputDir "C:\Reports" -MaxRetries 5 -RetryDelaySeconds 10
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-ApiKey` | String | — | MalwareBazaar / ThreatFox Auth-Key |
| `-HashFile` | String | — | Path to text file with hashes (one per line) |
| `-Hashes` | String[] | — | Hashes passed directly as array |
| `-ScanDirectory` | String | — | Directory to auto-hash before lookup |
| `-Recurse` | Switch | false | Recurse into subdirectories |
| `-OutputDir` | String | current dir | Where to save the HTML report |
| `-MaxRetries` | Int | 3 | Retry attempts on transient network errors |
| `-RetryDelaySeconds` | Int | 5 | Seconds to wait between retries |
| `-Quiet` | Switch | false | Show only MALICIOUS hits in console |
| `-PassThru` | Switch | false | Output result objects to pipeline |

---

## Hash file format

Plain text, one hash per line. Comments (`#`) and blank lines are ignored.  
MD5, SHA1, and SHA256 are all supported — mix freely.

```text
# Ransomware samples
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa

# Stealers
5dd92be22d005624d865ddf07402eb852426fc97baa52bbc58316690d41adb74

# MD5 is fine too
84c82835a5d21bbcf75a61706d8ab549

# Blank lines and comments are ignored
```

---

## Understanding results

| Status | Meaning |
|---|---|
| `MALICIOUS` | Confirmed in MalwareBazaar — known malware |
| `NOT_FOUND` | Not in MalwareBazaar database — **does not mean clean** |
| `ERROR` | API or network error — see detail column |

> **NOT_FOUND ≠ Clean.** MalwareBazaar only indexes confirmed malware samples that have been submitted. A file absent from the database may still be malicious. Cross-reference with additional threat intelligence sources.

**ThreatFox enrichment** fires on MALICIOUS hits when the hash was explicitly submitted to ThreatFox as an IOC by a researcher. Most ThreatFox IOCs are IP:port and domain entries — hash-type IOCs are less common but provide the richest C2 context when present.

---

## Requirements

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 or later (built into Windows 10+) |
| Auth-Key | Free at **[auth.abuse.ch](https://auth.abuse.ch)** |
| Network | `mb-api.abuse.ch`, `threatfox-api.abuse.ch`, `ip-api.com` |

No modules to install. No dependencies. Runs on any Windows machine with PowerShell 5.1.

---

## Roadmap

Planned features for future releases:

- [ ] **VirusTotal fallback** — optional second lookup for NOT_FOUND hashes
- [ ] **JSON / CSV output** — structured export alongside HTML report
- [ ] **Async requests** — parallel lookups to reduce scan time on large lists
- [ ] **Score aggregation** — composite risk score across MB + TF + VT
- [ ] **Sigma rule export** — generate detection rules from confirmed hits
- [ ] **Local cache** — avoid re-querying already seen hashes
- [ ] **MISP integration** — push results to MISP instance

Contributions and feature requests welcome via [Issues](https://github.com/zavetsec/Invoke-MBHashCheck/issues).

---

## License

MIT — free to use, modify, and distribute. Attribution appreciated.

---

<div align="center">

Built by **[ZavetSec](https://github.com/zavetsec)** · If this helped your investigation, leave a ⭐

</div>
