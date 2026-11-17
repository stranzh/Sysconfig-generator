import urllib.request
import json
import re
import os

print("--- Building datasets for Sysmon-Generator ---")
os.makedirs("src/data", exist_ok=True)

# 1. Fetch LOLOL.farm projects
print("1. Scraping lolol.farm projects...")
try:
    req = urllib.request.Request("https://lolol.farm/", headers={"User-Agent": "Mozilla/5.0"})
    html = urllib.request.urlopen(req, timeout=15).read().decode("utf-8")
    pattern = re.compile(r'<article class="card" data-tags="([^"]+)"[^>]*>.*?<h3 class="card-title"><a href="([^"]+)"[^>]*>(.*?)</a></h3>.*?<p class="card-desc">(.*?)</p>', re.DOTALL)
    lolol_projects = []
    for match in pattern.finditer(html):
        tags = [t.strip() for t in match.group(1).split(",")]
        href = match.group(2)
        title = re.sub(r"<[^>]+>", "", match.group(3)).replace("↗", "").strip()
        desc = re.sub(r"<[^>]+>", "", match.group(4)).strip()
        lolol_projects.append({"title": title, "tags": tags, "url": href, "description": desc})
    with open("src/data/lolol_projects.json", "w") as f:
        json.dump(lolol_projects, f, indent=2)
    print(f"   Done: {len(lolol_projects)} projects saved.")
except Exception as e:
    print(f"   Warning lolol.farm: {e}")

# 2. Fetch LOLBAS binaries & techniques
print("2. Fetching LOLBAS binaries & techniques...")
try:
    req = urllib.request.Request("https://lolbas-project.github.io/api/lolbas.json", headers={"User-Agent": "SysmonGen/1.0"})
    lolbas_raw = json.loads(urllib.request.urlopen(req, timeout=15).read().decode("utf-8"))
    parsed_lolbas = []
    for item in lolbas_raw:
        name = item.get("Name", "")
        desc = item.get("Description", "")
        paths = [p.get("Path", "") for p in item.get("Full_Path", []) if p.get("Path")]
        commands = item.get("Commands", [])
        mitre_ids = list(set([c.get("MitreID") for c in commands if c.get("MitreID")]))
        categories = list(set([c.get("Category") for c in commands if c.get("Category")]))
        cmd_examples = [c.get("Command") for c in commands if c.get("Command")]
        parsed_lolbas.append({
            "name": name,
            "description": desc,
            "paths": paths,
            "mitre_ids": mitre_ids,
            "categories": categories,
            "commands": cmd_examples,
            "url": item.get("url", "")
        })
    with open("src/data/lolbas.json", "w") as f:
        json.dump(parsed_lolbas, f, indent=2)
    print(f"   Done: {len(parsed_lolbas)} LOLBAS entries saved.")
except Exception as e:
    print(f"   Warning LOLBAS: {e}")

# 3. Compile src/data_bundle.js directly for zero-latency browser loading
print("3. Compiling src/data_bundle.js...")
try:
    with open("src/data/software_catalog.json") as f:
        software = json.load(f)
    with open("src/data/sysmon_modular_manifest.json") as f:
        modular = json.load(f)
    with open("src/data/vulnerable_drivers.json") as f:
        vuln_drivers = json.load(f)
    
    bundle_data = {
        "lolol_projects": lolol_projects,
        "lolbas": parsed_lolbas,
        "software_catalog": software,
        "sysmon_modular_manifest": modular,
        "vulnerable_drivers": vuln_drivers,
        "build_timestamp": "auto-generated"
    }
    with open("src/data_bundle.js", "w") as f:
        f.write("window.SYSMON_DATA_BUNDLE = " + json.dumps(bundle_data) + ";\n")
    print(f"   Done: Compiled src/data_bundle.js ({len(open('src/data_bundle.js').read())} bytes).")
except Exception as e:
    print(f"   Warning data bundle generation: {e}")

print("Datasets build completed successfully.")
