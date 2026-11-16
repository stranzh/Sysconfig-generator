# Sysmon-Generator Wiki & Technical Architecture Documentation

Welcome to the **Sysmon-Generator** Wiki. This document provides deep-dive architectural context, operational manuals, data ingestion specifications, and detection engineering best practices for building high-fidelity Sysmon configurations.

---

## Table of Contents
1. [Overview & Philosophy](#overview--philosophy)
2. [Architecture & Zero-Attack-Surface Security](#architecture--zero-attack-surface-security)
3. [Core Rule Sources & Integration](#core-rule-sources--integration)
   - [olafhartong/sysmon-modular Baseline](#olafhartongsysmon-modular-baseline)
   - [Why FileDelete (Events 23 & 26) Are Excluded](#why-filedelete-events-23--26-are-excluded)
   - [Living Off The Land (lolol.farm & LOLBAS)](#living-off-the-land-lololfarm--lolbas)
4. [Software Inventory Scanner & Rule Suggester](#software-inventory-scanner--rule-suggester)
   - [How It Works](#how-it-works)
   - [Running the PowerShell Scanner](#running-the-powershell-scanner)
   - [Auto-Matching Logic](#auto-matching-logic)
5. [MITRE ATT&CK Matrix Mapping](#mitre-attck-matrix-mapping)
6. [Sysmon Event Types Deep-Dive](#sysmon-event-types-deep-dive)
7. [Custom Rules Engine (Path, Hash, CLI, & ParentImage)](#custom-rules-engine-path-hash-cli--parentimage)
8. [Configuration Deployment & Testing](#configuration-deployment--testing)
9. [Development & Updating Datasets](#development--updating-datasets)

---

## 1. Overview & Philosophy

Sysmon (System Monitor) from Microsoft Sysinternals provides granular monitoring of process creations, network connections, file modifications, driver loads, and memory access. However, vanilla Sysmon without tuned configurations produces immense event log volume that floods SIEMs (Splunk, Elastic, Sentinel) and overwhelms SOC analysts.

**Sysmon-Generator** solves this by providing an interactive, client-side configuration studio:
- Pre-tuned high-signal baselines derived from industry-standard `sysmon-modular`.
- Proactive detection of LOLBins and Living Off The Land techniques from `lolol.farm` and the LOLBAS project.
- Automated software inventory ingestion that matches discovered enterprise applications with curated exclusions (to drop noise) and inclusions (to catch abuse).
- Fully transparent rule grouping, condition nesting (`begin with`, `is`, `contains`, `end with`), and instant live XML export.

---

## 2. Architecture & Zero-Attack-Surface Security

Sysmon-Generator was intentionally built with **no Electron runtime** and **no listening network backend**:
- **Pure Client-Side Web Application**: Delivered as a static single-page application (`index.html` + `data_bundle.js` + `app.js` + `style.css`).
- **Air-Gapped & Offline Ready**: All LOLBAS entries (245 binaries), LOLOL project catalogs (37 projects), software profiles, and modular manifest mappings are bundled directly in `src/data_bundle.js`.
- **Zero Remote Dependencies**: The application operates in isolated enclaves, jumpboxes, or SOC workstations without requiring internet access or privileged daemon accounts.
- **Dynamic Fetch Capability**: In environments with internet access, users can click "Fetch Online Rules" to pull real-time updates directly from GitHub API/Raw endpoints without writing to disk.

---

## 3. Core Rule Sources & Integration

### olafhartong/sysmon-modular Baseline
Sysmon-Generator structures rules according to the standard modular methodology developed by Olaf Hartong. Instead of flat `<ProcessCreate>` blocks, rules are partitioned into logical `<RuleGroup>` blocks configured with:
```xml
<RuleGroup name="" groupRelation="or">
    <!-- Included attack indicators or excluded operational noise -->
</RuleGroup>
```

### Why FileDelete (Events 23 & 26) Are Excluded
Per design specifications, **FileDelete** (Event ID 23: `FileDelete`) and **FileDeleteDetected** (Event ID 26: `FileDeleteDetected`) are strictly omitted:
1. **Severe I/O & Storage Overhead**: Enabling deletion archiving on endpoints rapidly exhausts disk space, especially on developer machines, build servers, and temp file churn environments.
2. **Performance Impact**: Intercepting every filesystem unlink operation causes perceptible system latency and high CPU utilization.
3. **Dedicated Retention Alternatives**: Ransomware canary files and endpoint backup solutions provide safer mechanisms for file recovery without Sysmon delete archiving.

### Living Off The Land (lolol.farm & LOLBAS)
`lolol.farm` serves as an index of over 37 Living Off The Land research initiatives (LOLBAS, LOLDrivers, HijackLibs, LOTS, WADComs, etc.). Sysmon-Generator extracts all Windows-compatible binaries and maps them into:
- **Event 1 (Process Create)**: Monitoring invocation of LOLBins with suspicious command lines (e.g., `Certutil -urlcache`, `mshta javascript:`, `rundll32.exe`, `bitsadmin /transfer`).
- **Event 7 (Image Load)**: Monitoring proxy execution and sideloading of unexpected DLLs.
- **Event 3 (Network Connection)**: Monitoring system binaries making outbound socket connections.
- **Event 10 (Process Access)**: Monitoring untrusted processes opening `PROCESS_VM_READ` or `PROCESS_ALL_ACCESS` handles to critical binaries.

---

## 4. Software Inventory Scanner & Rule Suggester

### How It Works
The tool includes a standalone scanner script (`scripts/scan_software.ps1`) that inspects target Windows endpoints and generates a JSON inventory. When imported into the GUI:
1. It compares installed software and active processes against the curated **Software Monitoring Catalog**.
2. For detected software (e.g., Chrome, Slack, VS Code, CrowdStrike, SentinelOne, AnyDesk), it proposes:
   - **Recommended Exclusions**: Filters noisy child processes and updater threads that pollute logs.
   - **Recommended Inclusions**: Detects high-risk attacks (e.g., Electron debug port hijacking, extension sideloading, reverse shells, memory scraping).
3. The user can review each recommendation with a single toggle before adding it to their live configuration.

### Running the PowerShell Scanner
On the target Windows machine, run:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\scan_software.ps1 -OutputFile software_scan_report.json
```
Upload or drag-and-drop `software_scan_report.json` directly into the **Software Scanner** tab in the GUI.

---

## 5. MITRE ATT&CK Matrix Mapping

Every rule and LOLBAS technique in Sysmon-Generator is tagged with its corresponding MITRE ATT&CK technique:
- **T1059 (Command and Scripting Interpreter)**: PowerShell, Cmd, WScript, CScript, MSHTA.
- **T1218 (System Binary Proxy Execution)**: Rundll32, Regsvr32, InstallUtil, Msiexec.
- **T1105 (Ingress Tool Transfer)**: Certutil, Bitsadmin, Curl, Powershell web requests.
- **T1562.001 (Impair Defenses)**: Process tampering, Defender registry bypass, EDR memory access.
- **T1219 (Remote Access Software)**: AnyDesk, TeamViewer, LogMeIn, ScreenConnect.
- **T1185 (Browser Session Hijacking)**: Chrome/Edge `--remote-debugging-port` execution.

---

## 6. Sysmon Event Types Deep-Dive

Sysmon-Generator allows configuring and toggling rules across all supported event IDs:

| Event ID | Sysmon Event Name | Primary Telemetry Purpose |
|----------|-------------------|---------------------------|
| **1** | `ProcessCreate` | Process executions, command lines, hashes, parent processes |
| **2** | `FileCreateTime` | File creation timestamp changes (timestomping) |
| **3** | `NetworkConnect` | Outbound and inbound TCP/UDP network connections |
| **5** | `ProcessTerminate` | Process termination monitoring |
| **6** | `DriverLoad` | Kernel driver loads (malicious rootkits & vulnerable drivers) |
| **7** | `ImageLoad` | DLL and executable module loads into processes |
| **8** | `CreateRemoteThread`| Thread injection across process boundaries (Code Injection) |
| **9** | `RawAccessRead` | Direct disk read attempts bypassing the filesystem driver |
| **10** | `ProcessAccess` | OpenProcess handles (LSASS credential dumping, EDR tampering) |
| **11** | `FileCreate` | File creations in sensitive locations (Startup, Temp, System32) |
| **12, 13, 14** | `RegistryEvent` | Registry key creation, value setting, and key deletions |
| **15** | `FileCreateStreamHash`| Alternate Data Streams (Zone.Identifier Mark-of-the-Web) |
| **17, 18** | `PipeEvent` | Named pipe creation and connection (PsExec, Cobalt Strike) |
| **19, 20, 21** | `WmiEvent` | WMI persistence filters, consumers, and consumer-to-filter bindings |
| **22** | `DnsQuery` | DNS lookup requests originating from endpoint processes |
| **24** | `ClipboardChange` | Clipboard content modifications |
| **25** | `ProcessTampering` | Process hollowing, Herpaderping, Doppelganging |
| **29** | `FileExecutableDetected`| Direct PE binary creation tracking |

---

## 7. Custom Rules Engine (Path, Hash, CLI, & ParentImage)

Users can append arbitrary custom rules directly in the GUI:
- **Condition Matching Operators**:
  - `is`: Exact equality match.
  - `begin with`: Prefix match (ideal for directory paths).
  - `end with`: Suffix match (ideal for file extensions or executable names).
  - `contains`: Substring match (ideal for command line parameters).
  - `image`: Process image match.
- **Rule Action**:
  - `include`: Logs matching events matching this pattern.
  - `exclude`: Discards matching events to conserve log storage.

---

## 8. Configuration Deployment & Testing

### 1. Validating Sysmon Configuration
Test the generated XML file with Sysmon's built-in schema validator:
```cmd
sysmon64.exe -c -v sysmonconfig.xml
```

### 2. Installing or Updating Sysmon
```cmd
:: Fresh Installation
sysmon64.exe -accepteula -i sysmonconfig.xml

:: Update Existing Installation
sysmon64.exe -c sysmonconfig.xml
```

### 3. Verifying Event Generation
Open **Event Viewer** (`eventvwr.msc`) and navigate to:
```
Applications and Services Logs -> Microsoft -> Windows -> Sysmon -> Operational
```

---

## 9. Development & Updating Datasets

To refresh the bundled datasets from upstream sources, run:
```bash
python3 scripts/build_datasets.py
```
This regenerates `src/data/*.json` and `src/data_bundle.js`.
