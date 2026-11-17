// Sysmon-Generator Core Application Engine
(function() {
  'use strict';

  // --- State Initialization ---
  const state = {
    schemaVersion: "4.50",
    hashAlgorithms: "md5,sha256,IMPHASH",
    checkRevocation: true,
    dnsLookup: true,
    activePreset: "balanced",
    
    // Core Sysmon Event Groups Status
    eventFilters: {
      1: { name: "ProcessCreate", enabled: true, onmatch: "exclude", count: 66 },
      2: { name: "FileCreateTime", enabled: true, onmatch: "exclude", count: 10 },
      3: { name: "NetworkConnect", enabled: true, onmatch: "include", count: 30 },
      5: { name: "ProcessTerminate", enabled: true, onmatch: "include", count: 2 },
      6: { name: "DriverLoad", enabled: true, onmatch: "exclude", count: 2 },
      7: { name: "ImageLoad", enabled: true, onmatch: "include", count: 29 },
      8: { name: "CreateRemoteThread", enabled: true, onmatch: "exclude", count: 4 },
      9: { name: "RawAccessRead", enabled: true, onmatch: "include", count: 1 },
      10: { name: "ProcessAccess", enabled: true, onmatch: "include", count: 42 },
      11: { name: "FileCreate", enabled: true, onmatch: "include", count: 72 },
      12: { name: "RegistryEvent", enabled: true, onmatch: "exclude", count: 87 },
      15: { name: "FileCreateStreamHash", enabled: true, onmatch: "include", count: 14 },
      17: { name: "PipeEvent", enabled: true, onmatch: "include", count: 30 },
      19: { name: "WmiEvent", enabled: true, onmatch: "include", count: 2 },
      22: { name: "DnsQuery", enabled: true, onmatch: "exclude", count: 12 },
      24: { name: "ClipboardChange", enabled: true, onmatch: "include", count: 1 },
      25: { name: "ProcessTampering", enabled: true, onmatch: "include", count: 8 },
      29: { name: "FileExecutableDetected", enabled: true, onmatch: "include", count: 10 }
    },

    // LOLBAS Rules
    selectedLolbas: new Set(),
    
    // lolol.farm Projects Rule Integrations
    selectedLololProjects: new Set(["LOLDrivers", "HijackLibs", "FileSec", "Persistence Info", "lolcerts", "LOT Tunnels", "LOLRMM", "WADComs", "LOT Webhooks", "LOLApps", "WTFBins"]),

    // Software Inclusions / Exclusions
    softwareSelections: {},

    // Custom Rules defined by user
    customRules: [],

    // Scanner detected software
    scanMatches: []
  };

  // Safe accessor for dataset bundle
  const bundle = window.SYSMON_DATA_BUNDLE || {
    lolol_projects: [],
    lolbas: [],
    software_catalog: [],
    sysmon_modular_manifest: {}
  };

  // Initialize all LOLBAS selected by default (for comprehensive defense)
  bundle.lolbas.forEach(l => {
    state.selectedLolbas.add(l.name);
  });

  // Initialize software selections
  bundle.software_catalog.forEach(sw => {
    state.softwareSelections[sw.id] = {
      include: true,
      exclude: true
    };
  });

  // --- DOM Elements ---
  const tabs = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");
  const lolbasTableBody = document.getElementById("lolbas-table-body");
  const lolbasSearch = document.getElementById("lolbas-search");
  const lololGrid = document.getElementById("lolol-projects-grid");
  const softwareCatalogList = document.getElementById("software-catalog-list");
  const customRulesTableBody = document.getElementById("custom-rules-body");
  const xmlPreview = document.getElementById("xml-preview");
  const xmlLineCount = document.getElementById("xml-line-count");
  const xmlRuleCount = document.getElementById("xml-rule-count");

  // --- Tab Navigation ---
  tabs.forEach(btn => {
    btn.addEventListener("click", () => {
      tabs.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));
      btn.classList.add("active");
      const target = document.getElementById(btn.getAttribute("data-tab"));
      if (target) target.classList.add("active");
      
      if (btn.getAttribute("data-tab") === "tab-xml") {
        renderXmlPreview();
      }
    });
  });

  // --- Global Engine Parameters Handlers ---
  const optSchema = document.getElementById("opt-schema");
  const optHashes = document.getElementById("opt-hashes");
  const optRevocation = document.getElementById("opt-revocation");

  if (optSchema) {
    optSchema.addEventListener("input", (e) => {
      state.schemaVersion = e.target.value.trim() || "4.50";
      renderXmlPreview();
    });
  }
  if (optHashes) {
    optHashes.addEventListener("input", (e) => {
      state.hashAlgorithms = e.target.value.trim() || "md5,sha256,IMPHASH";
      renderXmlPreview();
    });
  }
  if (optRevocation) {
    optRevocation.addEventListener("change", (e) => {
      state.checkRevocation = e.target.value === "true";
      renderXmlPreview();
    });
  }

  // --- Presets Handler ---
  document.querySelectorAll(".preset-card").forEach(card => {
    card.addEventListener("click", () => {
      document.querySelectorAll(".preset-card").forEach(c => c.classList.remove("active-preset"));
      card.classList.add("active-preset");
      const preset = card.getAttribute("data-preset");
      state.activePreset = preset;
      applyPreset(preset);
      renderXmlPreview();
    });
  });

  function applyPreset(preset) {
    if (preset === "minimal") {
      // Only high-fidelity alerts
      for (let k in state.eventFilters) {
        state.eventFilters[k].enabled = [1, 3, 7, 10, 25].includes(parseInt(k));
      }
    } else if (preset === "aggressive") {
      // Enable every single telemetry event
      for (let k in state.eventFilters) {
        state.eventFilters[k].enabled = true;
      }
    } else {
      // Balanced baseline (Default)
      for (let k in state.eventFilters) {
        state.eventFilters[k].enabled = ![24, 29].includes(parseInt(k));
      }
    }
    renderEventCheckboxes();
  }

  // --- Render Event Types ---
  function renderEventCheckboxes() {
    const container = document.getElementById("event-types-list");
    if (!container) return;
    container.innerHTML = "";

    for (let id in state.eventFilters) {
      const ev = state.eventFilters[id];
      const div = document.createElement("div");
      div.className = "card";
      div.style.padding = "16px";
      div.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <span class="tag" style="background:#1e293b; color:#38bdf8; margin-right:8px;">ID ${id}</span>
            <strong style="font-size:0.95rem;">${ev.name}</strong>
          </div>
          <label class="switch">
            <input type="checkbox" data-event-id="${id}" ${ev.enabled ? "checked" : ""}>
            <span class="slider"></span>
          </label>
        </div>
        <div style="display:flex; gap:10px; margin-top:12px; font-size:0.8rem; color:var(--text-muted);">
          <span>Default match: <strong style="color:var(--text-main);">${ev.onmatch}</strong></span>
          <span>•</span>
          <span>Rules catalog: <strong style="color:var(--accent-cyan);">${ev.count}</strong></span>
        </div>
      `;
      const checkbox = div.querySelector("input");
      checkbox.addEventListener("change", (e) => {
        state.eventFilters[id].enabled = e.target.checked;
        renderXmlPreview();
      });
      container.appendChild(div);
    }
  }

  // --- Render LOLBAS Table ---
  function renderLolbasTable(filterText = "") {
    if (!lolbasTableBody) return;
    lolbasTableBody.innerHTML = "";
    const filter = filterText.toLowerCase();

    const items = bundle.lolbas.filter(item => {
      if (!filter) return true;
      const matchName = item.name.toLowerCase().includes(filter);
      const matchDesc = (item.description || "").toLowerCase().includes(filter);
      const matchMitre = (item.mitre_ids || []).some(m => m.toLowerCase().includes(filter));
      const matchCat = (item.categories || []).some(c => c.toLowerCase().includes(filter));
      return matchName || matchDesc || matchMitre || matchCat;
    });

    document.getElementById("lolbas-total-count").textContent = `${items.length} / ${bundle.lolbas.length} active`;

    items.forEach(l => {
      const isSelected = state.selectedLolbas.has(l.name);
      const tr = document.createElement("tr");
      
      const mitreTags = (l.mitre_ids || []).map(m => `<span class="tag tag-attack">${m}</span>`).join(" ");
      const catTags = (l.categories || []).map(c => `<span class="tag">${c}</span>`).join(" ");
      const pathPreview = (l.paths || []).slice(0, 2).map(p => `<code style="font-size:0.75rem; color:#94a3b8;">${escapeHtml(p)}</code>`).join("<br>");

      tr.innerHTML = `
        <td style="width:40px;">
          <input type="checkbox" data-lolbas-name="${escapeHtml(l.name)}" ${isSelected ? "checked" : ""}>
        </td>
        <td>
          <strong style="color:#f8fafc;">${escapeHtml(l.name)}</strong>
          <div style="font-size:0.78rem; color:var(--text-muted); margin-top:3px;">${escapeHtml(l.description || "")}</div>
        </td>
        <td>${pathPreview || '<span style="color:var(--text-dim);">Default System32</span>'}</td>
        <td>${catTags || "—"}</td>
        <td>${mitreTags || '<span class="tag">Unmapped</span>'}</td>
      `;

      const cb = tr.querySelector("input");
      cb.addEventListener("change", (e) => {
        if (e.target.checked) {
          state.selectedLolbas.add(l.name);
        } else {
          state.selectedLolbas.delete(l.name);
        }
        document.getElementById("lolbas-selected-badge").textContent = `${state.selectedLolbas.size} Enabled`;
        renderXmlPreview();
      });

      lolbasTableBody.appendChild(tr);
    });
  }

  // --- Render LOLOL.farm Projects Grid ---
  function renderLololProjects() {
    if (!lololGrid) return;
    lololGrid.innerHTML = "";

    bundle.lolol_projects.forEach(p => {
      const card = document.createElement("div");
      card.className = "card";
      card.style.display = "flex";
      card.style.flexDirection = "column";

      const tags = (p.tags || []).map(t => `<span class="tag" style="background:#1e293b; color:#94a3b8;">${t}</span>`).join(" ");
      const isConfigured = state.selectedLololProjects.has(p.title);
      const hasTemplate = p.rule_template && p.rule_template.rules && p.rule_template.rules.length > 0;

      card.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">
          <h4 style="font-size:1.05rem; font-weight:700; color:#38bdf8;">${escapeHtml(p.title)}</h4>
          <a href="${escapeHtml(p.url)}" target="_blank" rel="noopener noreferrer" style="color:var(--text-muted); text-decoration:none; font-size:0.9rem;" title="Visit Research Page">↗</a>
        </div>
        <p style="font-size:0.84rem; color:var(--text-muted); flex:1; margin-bottom:12px;">${escapeHtml(p.description)}</p>
        
        ${hasTemplate ? `
          <div style="background:#090d14; border:1px solid var(--border-color); border-radius:6px; padding:10px; margin-bottom:12px; font-size:0.78rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
              <span class="tag tag-include" style="font-size:0.7rem;">${p.rule_template.event} (${p.rule_template.rules.length} rules)</span>
              <label class="switch" style="width:36px; height:20px;">
                <input type="checkbox" data-lolol-title="${escapeHtml(p.title)}" ${isConfigured ? "checked" : ""}>
                <span class="slider"></span>
              </label>
            </div>
            <div style="color:var(--text-muted); font-size:0.75rem;">
              ${escapeHtml(p.rule_template.description || "Active Monitoring Rules")}
            </div>
          </div>
        ` : `
          <div style="font-size:0.75rem; color:var(--text-dim); margin-bottom:12px;">
            External reference index
          </div>
        `}

        <div style="display:flex; gap:6px; flex-wrap:wrap; margin-top:auto;">
          ${tags}
        </div>
      `;

      const cb = card.querySelector("input[data-lolol-title]");
      if (cb) {
        cb.addEventListener("change", (e) => {
          if (e.target.checked) {
            state.selectedLololProjects.add(p.title);
          } else {
            state.selectedLololProjects.delete(p.title);
          }
          renderXmlPreview();
        });
      }

      lololGrid.appendChild(card);
    });
  }

  // --- Render Software Catalog List ---
  function renderSoftwareCatalog() {
    if (!softwareCatalogList) return;
    softwareCatalogList.innerHTML = "";

    bundle.software_catalog.forEach(sw => {
      const sel = state.softwareSelections[sw.id] || { include: true, exclude: true };
      const card = document.createElement("div");
      card.className = "card";
      card.style.marginBottom = "14px";

      card.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
          <div>
            <strong style="font-size:1.05rem;">${escapeHtml(sw.name)}</strong>
            <span class="tag" style="margin-left:8px;">${escapeHtml(sw.category)}</span>
            <span style="font-size:0.8rem; color:var(--text-muted); margin-left:8px;">by ${escapeHtml(sw.vendor)}</span>
          </div>
          <div style="display:flex; gap:16px;">
            <label style="display:inline-flex; align-items:center; gap:6px; font-size:0.82rem; cursor:pointer;">
              <input type="checkbox" data-sw-id="${sw.id}" data-type="include" ${sel.include ? "checked" : ""}>
              <span class="tag tag-include">Monitor Abuse (${sw.monitoring.include.length})</span>
            </label>
            <label style="display:inline-flex; align-items:center; gap:6px; font-size:0.82rem; cursor:pointer;">
              <input type="checkbox" data-sw-id="${sw.id}" data-type="exclude" ${sel.exclude ? "checked" : ""}>
              <span class="tag tag-exclude">Noise Exclusions (${sw.monitoring.exclude.length})</span>
            </label>
          </div>
        </div>
        <div style="font-size:0.8rem; color:var(--text-muted);">
          Monitored Executables: <code>${sw.executables.join(", ")}</code>
        </div>
      `;

      card.querySelectorAll("input").forEach(cb => {
        cb.addEventListener("change", (e) => {
          const swId = e.target.getAttribute("data-sw-id");
          const type = e.target.getAttribute("data-type");
          state.softwareSelections[swId][type] = e.target.checked;
          renderXmlPreview();
        });
      });

      softwareCatalogList.appendChild(card);
    });
  }

  // --- Custom Rules Engine ---
  document.getElementById("btn-add-rule").addEventListener("click", () => {
    const event = document.getElementById("rule-event").value;
    const action = document.getElementById("rule-action").value;
    const field = document.getElementById("rule-field").value;
    const condition = document.getElementById("rule-condition").value;
    const value = document.getElementById("rule-value").value.trim();
    const comment = document.getElementById("rule-comment").value.trim();

    if (!value) {
      alert("Please provide a target pattern/path/hash/CLI value.");
      return;
    }

    state.customRules.push({
      id: Date.now(),
      event,
      action,
      field,
      condition,
      value,
      comment
    });

    document.getElementById("rule-value").value = "";
    document.getElementById("rule-comment").value = "";
    renderCustomRules();
    renderXmlPreview();
  });

  function renderCustomRules() {
    if (!customRulesTableBody) return;
    customRulesTableBody.innerHTML = "";

    if (state.customRules.length === 0) {
      customRulesTableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:20px;">No custom rules defined yet. Use the form above to add specific rules.</td></tr>`;
      return;
    }

    state.customRules.forEach(rule => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span class="tag" style="background:#1e293b; color:#38bdf8;">${escapeHtml(rule.event)}</span></td>
        <td><span class="tag ${rule.action === "include" ? "tag-include" : "tag-exclude"}">${rule.action}</span></td>
        <td><code>${escapeHtml(rule.field)}</code> [${escapeHtml(rule.condition)}]</td>
        <td><code style="word-break:break-all;">${escapeHtml(rule.value)}</code></td>
        <td style="color:var(--text-muted); font-size:0.8rem;">${escapeHtml(rule.comment || "—")}</td>
        <td style="text-align:right;">
          <button class="btn btn-secondary btn-sm" data-delete-rule="${rule.id}" style="color:var(--accent-red);">Remove</button>
        </td>
      `;

      tr.querySelector("[data-delete-rule]").addEventListener("click", () => {
        state.customRules = state.customRules.filter(r => r.id !== rule.id);
        renderCustomRules();
        renderXmlPreview();
      });

      customRulesTableBody.appendChild(tr);
    });
  }

  // --- Software Scanner Handling ---
  const scanFileInput = document.getElementById("scan-file-input");
  const scanDropzone = document.getElementById("scan-dropzone");
  const scanResultsContainer = document.getElementById("scan-results");

  scanDropzone.addEventListener("click", () => scanFileInput.click());
  scanDropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    scanDropzone.style.borderColor = "var(--accent-cyan)";
  });
  scanDropzone.addEventListener("dragleave", () => {
    scanDropzone.style.borderColor = "var(--border-color)";
  });
  scanDropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    scanDropzone.style.borderColor = "var(--border-color)";
    if (e.dataTransfer.files.length) {
      handleScanFile(e.dataTransfer.files[0]);
    }
  });

  scanFileInput.addEventListener("change", (e) => {
    if (e.target.files.length) {
      handleScanFile(e.target.files[0]);
    }
  });

  function handleScanFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const report = JSON.parse(e.target.result);
        processScanReport(report);
      } catch (err) {
        scanResultsContainer.style.display = "block";
        const container = document.getElementById("scan-matches-list");
        if (container) {
          container.innerHTML = `<div class="callout callout-warning"><strong>Invalid Scan File:</strong> ${escapeHtml(err.message)}. Please verify this is a valid JSON file exported by <code>scan_software.ps1</code> or <code>scan_software.sh</code>.</div>`;
        }
      }
    };
    reader.readAsText(file);
  }

  function processScanReport(report) {
    scanResultsContainer.style.display = "block";
    const appList = Array.isArray(report.installed_software) 
      ? report.installed_software 
      : (report.installed_software ? [report.installed_software] : []);
    const procList = Array.isArray(report.running_processes) 
      ? report.running_processes 
      : (report.running_processes ? [report.running_processes] : []);
    const detectedSoftware = [];

    // Match against catalog
    bundle.software_catalog.forEach(sw => {
      let matched = false;
      let matchedName = "";

      // Match running processes
      for (let p of procList) {
        const pName = (p.name || "").toLowerCase();
        if (sw.executables.some(exe => exe.toLowerCase().replace(".exe", "") === pName.replace(".exe", ""))) {
          matched = true;
          matchedName = p.name;
          break;
        }
      }

      // Match installed software
      if (!matched) {
        for (let app of appList) {
          const aName = (app.name || "").toLowerCase();
          if (aName.includes(sw.name.toLowerCase()) || aName.includes(sw.id)) {
            matched = true;
            matchedName = app.name;
            break;
          }
        }
      }

      if (matched) {
        detectedSoftware.push({
          catalog: sw,
          discoveredAs: matchedName
        });
      }
    });

    state.scanMatches = detectedSoftware;
    renderScanMatches();
  }

  function renderScanMatches() {
    const container = document.getElementById("scan-matches-list");
    container.innerHTML = "";

    if (state.scanMatches.length === 0) {
      container.innerHTML = `<div class="callout callout-info">Scan report processed, but no pre-cataloged third-party software was identified. You can add custom rules for any discovered paths.</div>`;
      return;
    }

    state.scanMatches.forEach(item => {
      const sw = item.catalog;
      const card = document.createElement("div");
      card.className = "card";
      card.style.marginBottom = "12px";
      card.style.borderLeft = "4px solid var(--accent-green)";

      card.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong>✓ Discovered: ${escapeHtml(sw.name)}</strong>
            <span style="font-size:0.8rem; color:var(--text-muted); margin-left:10px;">(Matched artifact: <code>${escapeHtml(item.discoveredAs)}</code>)</span>
          </div>
          <button class="btn btn-cyan btn-sm" data-apply-sw="${sw.id}">Apply Recommended Rules</button>
        </div>
        <div style="margin-top:8px; font-size:0.82rem; color:var(--text-dim);">
          Suggested: ${sw.monitoring.include.length} Attack Inclusions, ${sw.monitoring.exclude.length} Noise Exclusions.
        </div>
      `;

      card.querySelector("[data-apply-sw]").addEventListener("click", () => {
        state.softwareSelections[sw.id] = { include: true, exclude: true };
        renderSoftwareCatalog();
        renderXmlPreview();
        alert(`Applied monitoring and exclusion rules for ${sw.name}!`);
      });

      container.appendChild(card);
    });
  }

  // --- Sysmon XML Generator Engine ---
  function generateSysmonXml() {
    let xml = `<!--\n  Sysmon Configuration Generated by Sysmon-Generator\n  Baseline: sysmon-modular (FileDelete excluded per design)\n  Living Off The Land Coverage: lolol.farm & LOLBAS\n  Generated At: ${new Date().toISOString()}\n-->\n`;
    xml += `<Sysmon schemaversion="${state.schemaVersion}">\n`;
    
    // Hash configuration
    xml += `\t<!-- [Global Configuration] -->\n`;
    xml += `\t<HashAlgorithms>${state.hashAlgorithms}</HashAlgorithms>\n`;
    if (state.checkRevocation) {
      xml += `\t<CheckRevocation/>\n`;
    }
    if (state.dnsLookup) {
      xml += `\t<DnsLookup>False</DnsLookup>\n`;
    }
    xml += `\t<EventFiltering>\n`;

    let totalRulesGenerated = 0;

    // 1. ProcessCreation (Event 1)
    if (state.eventFilters[1].enabled) {
      xml += `\n\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<!-- SYSMON EVENT 1: PROCESS CREATION                           -->\n`;
      xml += `\t\t<!-- ************************************************************* -->\n`;
      
      // LOLBAS & LOLOL Rules
      xml += `\t\t<RuleGroup name="LivingOffTheLand_LOLBAS" groupRelation="or">\n`;
      xml += `\t\t\t<ProcessCreate onmatch="include">\n`;
      
      bundle.lolbas.forEach(l => {
        if (state.selectedLolbas.has(l.name)) {
          totalRulesGenerated++;
          const mitre = (l.mitre_ids || []).join(", ") || "T1218";
          xml += `\t\t\t\t<!-- LOLOL/LOLBAS: ${escapeHtml(l.name)} [ATT&CK ${mitre}] -->\n`;
          xml += `\t\t\t\t<OriginalFileName condition="is">${escapeHtml(l.name)}</OriginalFileName>\n`;
          xml += `\t\t\t\t<Image condition="end with">\\${escapeHtml(l.name)}</Image>\n`;
        }
      });
      xml += `\t\t\t</ProcessCreate>\n`;
      xml += `\t\t</RuleGroup>\n`;

      // Software Specific Inclusions (Event 1)
      xml += `\t\t<RuleGroup name="Software_Abuse_Monitoring" groupRelation="or">\n`;
      xml += `\t\t\t<ProcessCreate onmatch="include">\n`;
      bundle.software_catalog.forEach(sw => {
        if (state.softwareSelections[sw.id]?.include) {
          sw.monitoring.include.filter(r => r.event === "ProcessCreate").forEach(r => {
            totalRulesGenerated++;
            xml += `\t\t\t\t<!-- ${escapeHtml(sw.name)}: ${escapeHtml(r.comment)} [${r.technique || ''}] -->\n`;
            xml += `\t\t\t\t<${r.field} condition="${r.condition}">${escapeHtml(r.value)}</${r.field}>\n`;
          });
        }
      });
      xml += `\t\t\t</ProcessCreate>\n`;
      xml += `\t\t</RuleGroup>\n`;

      // Software Specific Exclusions (Event 1)
      xml += `\t\t<RuleGroup name="Software_Noise_Filtering" groupRelation="or">\n`;
      xml += `\t\t\t<ProcessCreate onmatch="exclude">\n`;
      bundle.software_catalog.forEach(sw => {
        if (state.softwareSelections[sw.id]?.exclude) {
          sw.monitoring.exclude.filter(r => r.event === "ProcessCreate").forEach(r => {
            totalRulesGenerated++;
            xml += `\t\t\t\t<!-- ${escapeHtml(sw.name)} Noise Filter: ${escapeHtml(r.comment)} -->\n`;
            xml += `\t\t\t\t<${r.field} condition="${r.condition}">${escapeHtml(r.value)}</${r.field}>\n`;
          });
        }
      });
      xml += `\t\t\t</ProcessCreate>\n`;
      xml += `\t\t</RuleGroup>\n`;
    }

    // 2. Network Connect (Event 3)
    if (state.eventFilters[3].enabled) {
      xml += `\n\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<!-- SYSMON EVENT 3: NETWORK CONNECTION INITIATED                -->\n`;
      xml += `\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<RuleGroup name="LOLBAS_NetworkConnections" groupRelation="or">\n`;
      xml += `\t\t\t<NetworkConnect onmatch="include">\n`;
      xml += `\t\t\t\t<!-- Suspicious System Binaries Initiating Remote Connections -->\n`;
      ["certutil.exe", "powershell.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe", "curl.exe"].forEach(bin => {
        totalRulesGenerated++;
        xml += `\t\t\t\t<Image condition="end with">\\${bin}</Image>\n`;
      });
      xml += `\t\t\t</NetworkConnect>\n`;
      xml += `\t\t</RuleGroup>\n`;
    }

    // 3. Driver Load (Event 6)
    if (state.eventFilters[6].enabled) {
      xml += `\n\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<!-- SYSMON EVENT 6: DRIVER LOADED INTO KERNEL                    -->\n`;
      xml += `\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<RuleGroup name="Driver_Monitoring" groupRelation="or">\n`;
      xml += `\t\t\t<DriverLoad onmatch="exclude">\n`;
      xml += `\t\t\t\t<Signature condition="contains">Microsoft</Signature>\n`;
      xml += `\t\t\t\t<Signature condition="contains">Windows</Signature>\n`;
      xml += `\t\t\t</DriverLoad>\n`;
      xml += `\t\t</RuleGroup>\n`;
      totalRulesGenerated += 2;
    }

    // 4. Image Load (Event 7)
    if (state.eventFilters[7].enabled) {
      xml += `\n\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<!-- SYSMON EVENT 7: IMAGE LOAD / DLL INJECTION                  -->\n`;
      xml += `\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<RuleGroup name="HighRisk_DLL_Loads" groupRelation="or">\n`;
      xml += `\t\t\t<ImageLoad onmatch="include">\n`;
      ["amsi.dll", "clr.dll", "wldap32.dll", "vaultcli.dll", "samlib.dll"].forEach(dll => {
        totalRulesGenerated++;
        xml += `\t\t\t\t<!-- Monitor high-risk credential/AMSI DLL load: ${dll} -->\n`;
        xml += `\t\t\t\t<ImageLoaded condition="end with">\\${dll}</ImageLoaded>\n`;
      });
      xml += `\t\t\t</ImageLoad>\n`;
      xml += `\t\t</RuleGroup>\n`;
    }

    // 5. Process Access (Event 10)
    if (state.eventFilters[10].enabled) {
      xml += `\n\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<!-- SYSMON EVENT 10: PROCESS ACCESS (LSASS/EDR DEFENSE)         -->\n`;
      xml += `\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<RuleGroup name="CredentialAccess_LSASS_Defense" groupRelation="or">\n`;
      xml += `\t\t\t<ProcessAccess onmatch="include">\n`;
      xml += `\t\t\t\t<!-- LSASS Memory Dumping Protection -->\n`;
      xml += `\t\t\t\t<TargetImage condition="end with">\\lsass.exe</TargetImage>\n`;
      totalRulesGenerated++;
      // EDR defense inclusions from software catalog
      bundle.software_catalog.forEach(sw => {
        if (state.softwareSelections[sw.id]?.include) {
          sw.monitoring.include.filter(r => r.event === "ProcessAccess").forEach(r => {
            totalRulesGenerated++;
            xml += `\t\t\t\t<!-- EDR Tamper Protection: ${escapeHtml(sw.name)} -->\n`;
            xml += `\t\t\t\t<${r.field} condition="${r.condition}">${escapeHtml(r.value)}</${r.field}>\n`;
          });
        }
      });
      xml += `\t\t\t</ProcessAccess>\n`;
      xml += `\t\t</RuleGroup>\n`;
    }

    // 6. Registry Events (12, 13, 14)
    if (state.eventFilters[12].enabled) {
      xml += `\n\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<!-- SYSMON EVENT 12/13/14: REGISTRY MODIFICATIONS              -->\n`;
      xml += `\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<RuleGroup name="Persistence_RunKeys" groupRelation="or">\n`;
      xml += `\t\t\t<RegistryEvent onmatch="include">\n`;
      xml += `\t\t\t\t<TargetObject condition="contains">\\CurrentVersion\\Run</TargetObject>\n`;
      xml += `\t\t\t\t<TargetObject condition="contains">\\CurrentVersion\\RunOnce</TargetObject>\n`;
      xml += `\t\t\t\t<TargetObject condition="contains">\\System\\CurrentControlSet\\Services</TargetObject>\n`;
      xml += `\t\t\t</RegistryEvent>\n`;
      xml += `\t\t</RuleGroup>\n`;
      totalRulesGenerated += 3;
    }

    // 7. lolol.farm Research Projects Rule Group
    const activeLololProjects = bundle.lolol_projects.filter(p => 
      state.selectedLololProjects.has(p.title) && p.rule_template && p.rule_template.rules && p.rule_template.rules.length > 0
    );

    if (activeLololProjects.length > 0) {
      xml += `\n\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<!-- LOLOL.FARM RESEARCH PROJECTS (LOLDrivers, HijackLibs, etc.)  -->\n`;
      xml += `\t\t<!-- ************************************************************* -->\n`;

      const groupedByEvent = {};
      activeLololProjects.forEach(p => {
        const ev = p.rule_template.event;
        const act = p.rule_template.action || "include";
        const key = `${ev}_${act}`;
        if (!groupedByEvent[key]) groupedByEvent[key] = [];
        groupedByEvent[key].push(p);
      });

      for (let k in groupedByEvent) {
        const [ev, act] = k.split("_");
        xml += `\t\t<RuleGroup name="LOLOL_Farm_${ev}" groupRelation="or">\n`;
        xml += `\t\t\t<${ev} onmatch="${act}">\n`;
        groupedByEvent[k].forEach(p => {
          xml += `\t\t\t\t<!-- [${escapeHtml(p.title)}] ${escapeHtml(p.rule_template.description || '')} -->\n`;
          p.rule_template.rules.forEach(r => {
            totalRulesGenerated++;
            if (r.comment) xml += `\t\t\t\t<!-- ${escapeHtml(r.comment)} -->\n`;
            xml += `\t\t\t\t<${r.field} condition="${r.condition}">${escapeHtml(r.value)}</${r.field}>\n`;
          });
        });
        xml += `\t\t\t</${ev}>\n`;
        xml += `\t\t</RuleGroup>\n`;
      }
    }

    // 8. Custom Rules Block
    if (state.customRules.length > 0) {
      xml += `\n\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<!-- USER-DEFINED CUSTOM RULES                                   -->\n`;
      xml += `\t\t<!-- ************************************************************* -->\n`;
      xml += `\t\t<RuleGroup name="UserDefined_CustomRules" groupRelation="or">\n`;
      
      const grouped = {};
      state.customRules.forEach(r => {
        const key = `${r.event}_${r.action}`;
        if (!grouped[key]) grouped[key] = [];
        grouped[key].push(r);
      });

      for (let k in grouped) {
        const [ev, act] = k.split("_");
        xml += `\t\t\t<${ev} onmatch="${act}">\n`;
        grouped[k].forEach(r => {
          totalRulesGenerated++;
          if (r.comment) xml += `\t\t\t\t<!-- ${escapeHtml(r.comment)} -->\n`;
          xml += `\t\t\t\t<${r.field} condition="${r.condition}">${escapeHtml(r.value)}</${r.field}>\n`;
        });
        xml += `\t\t\t</${ev}>\n`;
      }
      xml += `\t\t</RuleGroup>\n`;
    }

    // Close configuration
    xml += `\t</EventFiltering>\n`;
    xml += `</Sysmon>\n`;

    return { xml, totalRulesGenerated };
  }

  function renderXmlPreview() {
    if (!xmlPreview) return;
    const { xml, totalRulesGenerated } = generateSysmonXml();
    xmlPreview.textContent = xml;
    const lines = xml.split("\n").length;
    if (xmlLineCount) xmlLineCount.textContent = `${lines} Lines`;
    if (xmlRuleCount) xmlRuleCount.textContent = `${totalRulesGenerated} Active Rules`;
  }

  // --- XML Actions ---
  document.getElementById("btn-copy-xml").addEventListener("click", () => {
    const { xml } = generateSysmonXml();
    navigator.clipboard.writeText(xml).then(() => {
      alert("Sysmon XML copied to clipboard!");
    }).catch(err => {
      alert("Failed to copy: " + err);
    });
  });

  document.getElementById("btn-download-xml").addEventListener("click", () => {
    const { xml } = generateSysmonXml();
    const blob = new Blob([xml], { type: "application/xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "sysmonconfig.xml";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  // --- LOLBAS Filters & Actions ---
  if (lolbasSearch) {
    lolbasSearch.addEventListener("input", (e) => {
      renderLolbasTable(e.target.value);
    });
  }

  document.getElementById("btn-select-all-lolbas").addEventListener("click", () => {
    bundle.lolbas.forEach(l => state.selectedLolbas.add(l.name));
    document.getElementById("lolbas-selected-badge").textContent = `${state.selectedLolbas.size} Enabled`;
    renderLolbasTable(lolbasSearch ? lolbasSearch.value : "");
    renderXmlPreview();
  });

  document.getElementById("btn-deselect-all-lolbas").addEventListener("click", () => {
    state.selectedLolbas.clear();
    document.getElementById("lolbas-selected-badge").textContent = `0 Enabled`;
    renderLolbasTable(lolbasSearch ? lolbasSearch.value : "");
    renderXmlPreview();
  });

  // --- Helper escapeHtml ---
  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // --- Initial Render ---
  renderEventCheckboxes();
  renderLolbasTable();
  renderLololProjects();
  renderSoftwareCatalog();
  renderCustomRules();
  renderXmlPreview();

})();
