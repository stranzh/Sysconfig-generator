# Sysmon-Generator

> **High-Fidelity Sysmon Configuration Generator & Attack Matrix Explorer**  
> Built for SOC analysts, detection engineers, and blue teams to craft enterprise-grade Microsoft Sysinternals Sysmon configurations with zero noise, comprehensive Living Off The Land (LOLBAS/lolol.farm) coverage, and automated software inventory analysis.

---

## ⚡ Features

- **Latest Modular Baseline**: Clean baseline configuration based on [`olafhartong/sysmon-modular`](https://github.com/olafhartong/sysmon-modular), with strict exclusion of high-churn `FileDelete` (Events 23 & 26).
- **Living Off The Land Coverage**: Full ingestion of [`lolol.farm`](https://lolol.farm/) security projects and 240+ Living Off The Land Binaries and Scripts ([LOLBAS](https://lolbas-project.github.io/)) with ATT&CK technique tags.
- **Deep-Dive GUI**:
  - **Preset & Baseline Selector**: Choose from Balanced, Aggressive / Threat Hunting, or Minimal profiles.
  - **Event Types Rule Manager**: Granular configuration for all 19+ Sysmon event classes.
  - **LOLOL & ATT&CK Explorer**: Searchable matrix of LOLBins, paths, categories, and command line examples.
  - **Software Scanner & Rule Suggester**: Import host inventory reports to automatically suggest tuned inclusions and exclusions for installed tools (Chrome, Slack, VS Code, CrowdStrike, SentinelOne, AnyDesk, etc.).
  - **Custom Rules Engine**: Define custom path, SHA256/MD5/IMPHASH, command-line, and parent process rules on demand.
  - **Live XML Diff & Generator**: Real-time syntax highlighting, schema validation, instant copy, and one-click XML download.
- **Security-First Architecture**: Pure client-side single-page application. Runs completely offline in any web browser without Electron or backend server processes.
- **Complete WIKI**: Comprehensive detection engineering manual and architectural specifications in [`docs/WIKI.md`](docs/WIKI.md).

---

## 🚀 Quick Start

### 1. Launch the Web Interface
Simply open `index.html` in any modern web browser (Chrome, Edge, Firefox, Safari):

```bash
# Direct browser opening (Linux)
xdg-open index.html

# Direct browser opening (macOS)
open index.html

# Or serve locally using standard python static server if preferred
python3 -m http.server 8080
```

### 2. (Optional) Run Software Inventory Scan
To generate customized Sysmon rules tailored specifically to your endpoint's installed software:

**On Windows:**
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\scan_software.ps1 -OutputFile software_scan_report.json
```

**In the GUI:**
1. Navigate to the **Software Scanner** tab.
2. Click **Upload Scan Report** and select `software_scan_report.json`.
3. Review the proposed inclusions (threat detection) and exclusions (noise filtering).
4. Click **Apply Selected Suggestions** to instantly merge them into your Sysmon configuration.

### 3. Deploy to Sysmon
Once satisfied with your configuration in the **XML Output** tab:
1. Click **Download sysmonconfig.xml**.
2. Deploy the configuration with Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmonconfig.xml
   ```

---

## 📁 Repository Structure

```
.
├── index.html                  # Single-page web GUI application
├── style.css                   # Cyber-defense dark mode UI styling
├── app.js                      # Core reactive application & XML engine
├── src/
│   ├── data_bundle.js          # Bundled offline dataset (LOLBAS, lolol.farm, software catalog)
│   └── data/                   # Raw JSON datasets
│       ├── lolol_projects.json
│       ├── lolbas.json
│       ├── software_catalog.json
│       └── sysmon_modular_manifest.json
├── scripts/
│   ├── build_datasets.py       # Online crawler & dataset synchronizer
│   ├── scan_software.ps1       # Windows endpoint software & process scanner
│   └── scan_software.sh        # Linux testing inventory scanner
├── docs/
│   └── WIKI.md                 # Detailed technical wiki & detection guide
└── README.md
```

---

## 🛡️ License & Acknowledgments

- Baseline modular structure inspired by [Olaf Hartong's sysmon-modular](https://github.com/olafhartong/sysmon-modular).
- Attack techniques and binaries curated from [lolol.farm](https://lolol.farm/) and the [LOLBAS Project](https://lolbas-project.github.io/).
- MIT License.
