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

## Why not just use the browser?

| Approach | Time for 50 hashes | Output | C2 context | Automatable |
|---|---|---|---|---|
| MalwareBazaar GUI | ~2 hours | Notes | No | No |
| ThreatFox GUI | ~2 hours separate | Notes | Manual | No |
| VirusTotal GUI | ~2 hours + rate limits | Notes | No | No |
| **Invoke-MBHashCheck** | **~2-5 minutes** | **HTML report** | **Automatic** | **Yes** |

> VirusTotal is great for single-file analysis. This tool is for **bulk triage** — when you have a list of suspicious hashes and need answers fast, in a format you can share.

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

```powershell
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt" -Quiet
```

```
 ______          _____
|___  /         /  ___|
   / /  __ ___  \ `--. ___  ___
  / /  / _` \ \  `--. / _ \/ __|
./ /__| (_| |> \/\__/ /  __/ (__
\_____/\__,_/_/\_\____/ \___|\___| 
   ZavetSec - MalwareBazaar Hash Checker v2.0
   Powered by abuse.ch  |  Free key: auth.abuse.ch
----------------------------------------------------

[07:32:11] [INFO] Loaded 14 hash(es) for analysis.
[07:32:11] [INFO] Source: MalwareBazaar (abuse.ch) | Auth-Key: ....e043

  [1/14] 6439834bec1cc530b12b1d821a509561... (SHA256) ... [MALICIOUS]  command_and_control  | elf
  [TF] Querying ThreatFox for related IOCs...
      No IOCs found in ThreatFox

  [2/14] c46cd09676c6393ba3530f03135d1484... (SHA256) ... [MALICIOUS]  ACRStealer  | exe, stealer
  [TF] Querying ThreatFox for related IOCs...
      No IOCs found in ThreatFox

  [3/14] af0cbe1cb2efa531b2592f0f208cb7b2... (SHA256) ... [MALICIOUS]  CoinMiner  | exe, signed
  [4/14] ac931f9419235283f509bbed222918c3... (SHA256) ... [MALICIOUS]  Petya  | exe
  [5/14] 2de70ca737c1f4602517c555ddd54165... (SHA256) ... [MALICIOUS]  Triada  | apk
  ...
  [14/14] 0000000000000000000000000000001... (SHA256) ... [NOT_FOUND]

------------------------------------------------------
[07:41:15] [HEAD] Analysis complete.
  Total:          14
  MALICIOUS:      12
  NOT IN DB:       2
  Errors:          0
  ThreatFox hits:  0
  TF IOCs total:   0

[07:41:15] [OK] HTML report saved: .\MB_HashReport_20260320_074115.html
```

> `-Quiet` suppresses NOT_FOUND rows. Use `-PassThru` to pipe results into further automation.

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

## Report Preview

The HTML report is self-contained — open it anywhere, no internet required.

> 📎 **[Sample report →](sample_report.html)** *(open in browser to see live filtering)*

**Summary header:**

```
┌──────────┬──────────┬──────────┬──────────┐
│  Total   │ Malicious│ Not in DB│  Errors  │
│    14    │    12    │    2     │    0     │
└──────────┴──────────┴──────────┴──────────┘
```

**Hash table columns:** Hash (clickable → MalwareBazaar) · Verdict badge · File name · Type · Signature · Tags · First seen · Intel (ClamAV + download counts)

**ThreatFox section** *(shown when C2 data is available)*: IOC · Type · Threat · Malware family · Confidence % · GeoIP with country flag · ASN · Shodan link

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

**ThreatFox enrichment** fires on MALICIOUS hits when the hash was explicitly submitted to ThreatFox as an IOC by a researcher. In practice, most hashes return "No IOCs found" — this is expected and correct. Hash-type IOCs are rare in ThreatFox; when present they provide C2 IPs/domains with confidence level and GeoIP. Note: ThreatFox expires IOCs older than 6 months, so older samples will not return results even if they were in the database previously.

---

## Requirements

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 or later (built into Windows 10+) |
| Auth-Key | Free at **[auth.abuse.ch](https://auth.abuse.ch)** |
| Network | `mb-api.abuse.ch`, `threatfox-api.abuse.ch`, `ip-api.com` |

No modules to install. No dependencies. Runs on any Windows machine with PowerShell 5.1.

---

## DFIR Workflow — Process Triage

One of the most powerful use cases for this tool is **live process triage** during incident response.

### The scenario

You suspect a machine is compromised. You need to quickly answer:
> *"Are any running processes known malware?"*

### Step 1 — Collect process hashes with ZavetSecTriage

Use **[Invoke-ZavetSecTriage](https://github.com/zavetsec/Invoke-ZavetSecTriage)** — a companion tool that collects running process hashes, network connections, loaded modules, and persistence artifacts into a structured DFIR package.

```powershell
# Run triage on a suspect host (local or remote via PsExec)
.\Invoke-ZavetSecTriage.ps1 -OutputDir "C:\Triage\HOST01"

# Result: triage package including process_hashes.txt
```

### Step 2 — Feed the hashes directly into MBHashCheck

```powershell
# Check all running process hashes against MalwareBazaar + ThreatFox
.\Invoke-MBHashCheck.ps1 `
    -ApiKey "YOUR_KEY" `
    -HashFile "C:\Triage\HOST01\process_hashes.txt" `
    -Quiet `
    -OutputDir "C:\Triage\HOST01"
```

`-Quiet` shows only MALICIOUS hits — clean processes are suppressed.

### Step 3 — Review the report

Open the generated HTML — every MALICIOUS process is flagged with:
- Malware family name
- ClamAV vendor detections
- ThreatFox C2 IPs / domains (if available) with GeoIP

### Full pipeline example

```powershell
$key = "YOUR_KEY"
$host = "WORKSTATION-042"
$out  = "C:\IR\$host"

# 1. Collect
.\Invoke-ZavetSecTriage.ps1 -ComputerName $host -OutputDir $out

# 2. Check hashes
$hits = .\Invoke-MBHashCheck.ps1 -ApiKey $key `
    -HashFile "$out\process_hashes.txt" `
    -PassThru -Quiet |
    Where-Object Status -eq "MALICIOUS"

# 3. Instant verdict
if ($hits) {
    Write-Host "COMPROMISE CONFIRMED: $($hits.Count) malicious process(es)" -ForegroundColor Red
    $hits | Select-Object Hash, Signature, Tags, TFIOCs | Format-Table
} else {
    Write-Host "No known malware in running processes" -ForegroundColor Green
}
```

### Why this combination works

| What you get | ZavetSecTriage | Invoke-MBHashCheck |
|---|---|---|
| Running process hashes | ✅ Collects | — |
| Network connections | ✅ Collects | — |
| Persistence artifacts | ✅ Collects | — |
| Malware family ID | — | ✅ MalwareBazaar |
| C2 infrastructure | — | ✅ ThreatFox + GeoIP |
| Self-contained report | ✅ HTML | ✅ HTML |

> Both tools are built to the same conventions — PS 5.1 compatible, no dependencies, dark HTML reports, PsExec/remote friendly. They are designed to work together as part of the **ZavetSec DFIR toolkit**.

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

## Getting started as contributor

The repo uses a single `main` branch. When submitting PRs:

```bash
git clone https://github.com/zavetsec/Invoke-MBHashCheck
cd Invoke-MBHashCheck

# Make your changes
# Test with PSScriptAnalyzer locally:
Invoke-ScriptAnalyzer -Path .\Invoke-MBHashCheck.ps1 -Severity Warning,Error

# Commit with a descriptive message
git add .
git commit -m "feat: add JSON export format"
git push origin main
```

Issues and feature requests welcome → [open an issue](https://github.com/zavetsec/Invoke-MBHashCheck/issues)

---

## License

MIT — free to use, modify, and distribute. Attribution appreciated.

---

<div align="center">

Built by **[ZavetSec](https://github.com/zavetsec)** · If this helped your investigation, leave a ⭐

</div>
