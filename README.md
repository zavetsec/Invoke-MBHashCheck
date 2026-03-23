<div align="center">

```
     ____                  _    ____            
    |_  /__ ___ _____ ___ | |_ / __/__ ___     
     / // _` \ V / -_)  _||  _\__ \/ -_) _|    
    /___\__,_|\_/\___\__| |_| |___/\___\__|    
```

**Bulk hash triage — MalwareBazaar + ThreatFox + GeoIP**  
*50 hashes. 5 minutes. One HTML report. No SIEM. No install.*

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078d4?logo=windows)](https://microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-brightgreen)](LICENSE)
[![MalwareBazaar](https://img.shields.io/badge/API-MalwareBazaar-orange)](https://bazaar.abuse.ch)
[![ThreatFox](https://img.shields.io/badge/API-ThreatFox-red)](https://threatfox.abuse.ch)
[![Version](https://img.shields.io/badge/Version-1.0-gold)](CHANGELOG.md)
[![Stars](https://img.shields.io/github/stars/zavetsec/Invoke-MBHashCheck?style=flat-square)](https://github.com/zavetsec/Invoke-MBHashCheck/stargazers)

</div>

---

> **TL;DR** — Give it a list of hashes. It checks MalwareBazaar, enriches hits with ThreatFox C2 intel + GeoIP, and outputs a filterable HTML report. Free API. No install. Runs on built-in PowerShell.

---

## The problem

You have 50 suspicious file hashes from a compromised host. You need to know which ones are confirmed malware, what families they belong to, and whether any C2 infrastructure is known.

Manual approach:

1. Open MalwareBazaar — paste hash — wait
2. Open ThreatFox — paste hash — wait
3. Open ip-api — look up the C2 IP — wait
4. Take notes in a ticket
5. Repeat 49 more times

**With 50+ hashes this takes hours. This tool does it in minutes, automatically.**

---

## What it does

```
Hash list (file / directory scan / inline)
            │
            ▼
    ┌─────────────────┐
    │  MalwareBazaar  │  ──►  MALICIOUS  ──►   ┌──────────────────┐
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

## Quick start

```powershell
# 1. Get your free key at https://auth.abuse.ch (GitHub / Google / LinkedIn login)

# 2. Run against your hash list
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt"

# 3. Open the generated HTML report
```

---

## Console output

```
 ______          _____
|___  /         /  ___|
   / /  __ ___  \ `--. ___  ___
  / /  / _` \ \  `--. / _ \/ __|
./ /__| (_| |> \/\__/ /  __/ (__
\_____/\__,_/_/\_\____/ \___|\___
   ZavetSec - MalwareBazaar Hash Checker v1.0
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
[07:41:15] Analysis complete.
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

## HTML report

Self-contained `.html` — no server, no internet required to open.

**Summary header:**
```
┌──────────┬──────────┬──────────┬──────────┐
│  Total   │ Malicious│ Not in DB│  Errors  │
│    14    │    12    │    2     │    0     │
└──────────┴──────────┴──────────┴──────────┘
```

**Hash table columns:** Hash (clickable → MalwareBazaar) · Verdict badge · File name · Type · Signature · Tags · First seen · ClamAV detections + download counts

**ThreatFox section** *(shown when C2 data is available)*: IOC · Type · Malware family · Confidence % · Country flag · City · ASN · Shodan link

**Filters:** All / Malicious / Not in DB / Suspicious  
**Search:** instant full-text across all rows

> 📎 **[Sample report →](sample_report.html)** *(open in browser to see live filtering)*

Drop it in a ticket. Email it. Open it on an airgapped analyst machine.

---

## Why not just VirusTotal?

VirusTotal is excellent for deep single-file analysis. This tool solves a different problem: **bulk triage with C2 context during incident response.**

| | MalwareBazaar GUI | VirusTotal GUI | **Invoke-MBHashCheck** |
|---|---|---|---|
| **50 hashes** | ~2 hours | ~2 hours + rate limits | ~5 minutes |
| **Output format** | Browser notes | Browser notes | Filterable HTML |
| **C2 enrichment** | No | No | Automatic (ThreatFox) |
| **GeoIP on C2 IPs** | No | No | Yes |
| **Automatable** | No | No | Yes (`-PassThru`) |
| **Free** | Yes | Freemium | Yes |
| **Offline report** | No | No | Yes |

---

## Usage

```powershell
# Bulk check from file
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt"

# Auto-hash all files in a directory
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -ScanDirectory "C:\Suspicious" -Recurse

# Single hash inline
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -Hashes "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"

# Quiet mode — MALICIOUS hits only in console
.\Invoke-MBHashCheck.ps1 -ApiKey "YOUR_KEY" -HashFile "hashes.txt" -Quiet

# Pipeline — export MALICIOUS hits to CSV
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
| `-ApiKey` | String | — | MalwareBazaar / ThreatFox Auth-Key (free) |
| `-HashFile` | String | — | Path to text file, one hash per line |
| `-Hashes` | String[] | — | Hashes passed directly as array |
| `-ScanDirectory` | String | — | Directory to auto-hash before lookup |
| `-Recurse` | Switch | false | Recurse into subdirectories |
| `-OutputDir` | String | current dir | Where to save the HTML report |
| `-MaxRetries` | Int | 3 | Retry attempts on transient network errors |
| `-RetryDelaySeconds` | Int | 5 | Seconds between retries |
| `-Quiet` | Switch | false | MALICIOUS hits only in console |
| `-PassThru` | Switch | false | Output result objects to pipeline |

---

## Hash file format

Plain text, one hash per line. Comments (`#`) and blank lines ignored. MD5, SHA1, SHA256 — mix freely.

```text
# Ransomware samples
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa

# Stealers
5dd92be22d005624d865ddf07402eb852426fc97baa52bbc58316690d41adb74

# MD5 is fine too
84c82835a5d21bbcf75a61706d8ab549
```

---

## Understanding results

| Status | Meaning |
|---|---|
| `MALICIOUS` | Confirmed in MalwareBazaar — known malware |
| `NOT_FOUND` | Not in MalwareBazaar — **does not mean clean** |
| `ERROR` | API or network error — see detail column |

> **NOT_FOUND ≠ Clean.** MalwareBazaar only indexes confirmed malware samples that have been submitted. A file absent from the database may still be malicious. Cross-reference with additional sources.

**ThreatFox enrichment** fires on MALICIOUS hits when the hash was explicitly submitted to ThreatFox as an IOC by a researcher. In practice, most hashes return "No IOCs found" — this is expected and correct. Hash-type IOCs are rare in ThreatFox; when present they provide C2 IPs/domains with confidence level and GeoIP. Note: ThreatFox expires IOCs older than 6 months, so older samples will not return results even if they were in the database previously.

---

## DFIR pipeline — from triage to verdict

The most powerful use case: pipe `Invoke-ZavetSecTriage` output directly into this tool.

### The scenario

You suspect a machine is compromised. You need to quickly answer:
> *"Are any running processes known malware?"*

### Step 1 — Collect process hashes

```powershell
# Run triage on a suspect host (local or remote via PsExec)
.\Invoke-ZavetSecTriage.ps1 -OutputDir "C:\Triage\HOST01"
# Result: triage package including Forensics\hashes.txt and hashes.csv
```

### Step 2 — Bulk hash check

```powershell
.\Invoke-MBHashCheck.ps1 `
    -ApiKey "YOUR_KEY" `
    -HashFile "C:\Triage\HOST01\Forensics\hashes.txt" `
    -Quiet -OutputDir "C:\Triage\HOST01"
```

`-Quiet` shows only MALICIOUS hits — clean processes suppressed.

### Step 3 — Instant verdict

```powershell
$key = "YOUR_KEY"
$out = "C:\IR\WORKSTATION-042"

.\Invoke-ZavetSecTriage.ps1 -OutputDir $out

$hits = .\Invoke-MBHashCheck.ps1 -ApiKey $key `
    -HashFile "$out\Forensics\hashes.txt" `
    -PassThru -Quiet |
    Where-Object Status -eq "MALICIOUS"

if ($hits) {
    Write-Host "COMPROMISE CONFIRMED: $($hits.Count) malicious process(es)" -ForegroundColor Red
    $hits | Select-Object Hash, Signature, Tags, TFIOCs | Format-Table
} else {
    Write-Host "No known malware in running processes" -ForegroundColor Green
}
```

**In practice:** triage ~3 min + hash check for 150 hashes ~5 min = **8 minutes from unknown host to confirmed verdict with malware family name and C2 IPs.**

### Why this combination works

| What you get | ZavetSecTriage | Invoke-MBHashCheck |
|---|---|---|
| Running process hashes | ✅ Collects | — |
| Network connections | ✅ Collects | — |
| Persistence artifacts | ✅ Collects | — |
| Malware family ID | — | ✅ MalwareBazaar |
| C2 infrastructure | — | ✅ ThreatFox + GeoIP |
| Self-contained HTML report | ✅ | ✅ |

---

## Requirements

| | |
|---|---|
| PowerShell | 5.1+ (built into Windows 10+) |
| API key | Free at [auth.abuse.ch](https://auth.abuse.ch) — GitHub / Google / LinkedIn login |
| Internet | `mb-api.abuse.ch`, `threatfox-api.abuse.ch`, `ip-api.com` |
| Install | None |

---

## Part of the ZavetSec DFIR toolkit

Designed to work together during live IR engagements. Each tool is independent — use any one standalone, or chain them as a pipeline.

| Tool | What it does |
|---|---|
| **[Invoke-ZavetSecTriage](https://github.com/zavetsec/Invoke-ZavetSecTriage)** | Live artifact collection — 18 modules, MITRE-tagged findings, HTML report |
| **Invoke-MBHashCheck** | Bulk hash triage — MalwareBazaar + ThreatFox C2 enrichment + GeoIP |
| **[ZavetSecHardeningBaseline](https://github.com/zavetsec/ZavetSecHardeningBaseline)** | 60+ hardening checks — CIS/STIG aligned, JSON rollback, compliance report |

All three: PS 5.1, zero dependencies, self-contained HTML reports, PsExec-compatible.

---

## Roadmap

- [ ] VirusTotal fallback for NOT_FOUND hashes
- [ ] JSON / CSV output alongside HTML
- [ ] Async parallel lookups for large lists
- [ ] Local cache — skip re-querying known hashes
- [ ] Score aggregation across MB + TF + VT
- [ ] Sigma rule export from confirmed hits
- [ ] MISP push integration

---

## Contributing

```bash
git clone https://github.com/zavetsec/Invoke-MBHashCheck
cd Invoke-MBHashCheck

# Test before submitting
Invoke-ScriptAnalyzer -Path .\Invoke-MBHashCheck.ps1 -Severity Warning,Error

git commit -m "feat: add JSON export"
git push origin main
```

Issues and feature requests → [open an issue](https://github.com/zavetsec/Invoke-MBHashCheck/issues)

---

## License

MIT — free to use, modify, distribute. Attribution appreciated.

---

<div align="center">

**[ZavetSec](https://github.com/zavetsec)** · Powered by [abuse.ch](https://abuse.ch) (MalwareBazaar + ThreatFox)

*Free API key: [auth.abuse.ch](https://auth.abuse.ch)*

*⭐ Star the repo to help other responders find it.*

</div>
