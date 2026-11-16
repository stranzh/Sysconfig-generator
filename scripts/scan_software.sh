#!/usr/bin/env bash
# Sysmon-Generator - Linux Process & Package Inventory Scanner (for cross-platform scanning/testing)
OUTPUT_FILE="${1:-software_scan_report.json}"

echo "[+] Running Sysmon-Generator Inventory Scanner (Linux/Unix)..."

python3 -c "
import json, sys, os, subprocess, datetime

data = {
    'scanner_version': '1.0.0',
    'timestamp': datetime.datetime.now().isoformat(),
    'os_info': {'Caption': os.uname().sysname + ' ' + os.uname().release, 'Architecture': os.uname().machine},
    'installed_software': [],
    'running_processes': []
}

# Collect running processes
try:
    ps_out = subprocess.check_output(['ps', '-eo', 'comm,args'], text=True).splitlines()
    seen = set()
    for line in ps_out[1:]:
        parts = line.strip().split(maxsplit=1)
        if parts:
            name = parts[0]
            if name not in seen:
                seen.add(name)
                data['running_processes'].append({'name': name, 'path': '/' + name, 'publisher': 'Unknown'})
except Exception as e:
    pass

with open('$OUTPUT_FILE', 'w') as f:
    json.dump(data, f, indent=2)

print(f'[✓] Exported inventory to $OUTPUT_FILE with {len(data[\"running_processes\"])} processes.')
"
