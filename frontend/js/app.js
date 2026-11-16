/**
 * Core Application Controller for Aegis AI-NIDS SOC Dashboard
 */

let alertsCache = [];
let currentModalAlert = null;
let ws = null;

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  connectWebSocket();
  fetchInitialAlerts();
  fetchInitialMetrics();
});

// -------------------------------------------------------------
// WebSocket Real-time Feed
// -------------------------------------------------------------
function connectWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/soc-feed`;

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    console.log('[✓] Connected to Aegis SOC Live Feed');
    updateWsStatus(true);
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleWsEvent(msg);
    } catch (err) {
      console.error('Error parsing WS message:', err);
    }
  };

  ws.onclose = () => {
    console.warn('[!] WS connection closed. Reconnecting in 3s...');
    updateWsStatus(false);
    setTimeout(connectWebSocket, 3000);
  };

  ws.onerror = (err) => {
    console.error('WS Error:', err);
    updateWsStatus(false);
  };
}

function updateWsStatus(connected) {
  const indicator = document.getElementById('ws-indicator');
  const text = document.getElementById('ws-status-text');
  if (connected) {
    indicator.className = 'relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500';
    text.textContent = 'ENGINE ARMED';
    text.className = 'text-xs font-mono text-emerald-400';
  } else {
    indicator.className = 'relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-500';
    text.textContent = 'RECONNECTING';
    text.className = 'text-xs font-mono text-rose-400';
  }
}

function handleWsEvent(msg) {
  if (msg.type === 'NEW_ALERT') {
    handleNewAlert(msg.data);
  } else if (msg.type === 'FLOW_PROCESSED') {
    handleFlowProcessed(msg.data);
  } else if (msg.type === 'METRICS_UPDATE') {
    updateMetricsUI(msg.data);
  }
}

function handleNewAlert(alert) {
  alertsCache.unshift(alert);
  if (alertsCache.length > 200) alertsCache.pop();

  renderAlertRow(alert, true);
  updateTimelineChart(true);
  fetchInitialMetrics();
}

function handleFlowProcessed(data) {
  updateTimelineChart(data.is_threat);
}

// -------------------------------------------------------------
// Data Fetching
// -------------------------------------------------------------
async function fetchInitialAlerts() {
  try {
    const res = await fetch('/api/v1/alerts?limit=25');
    if (res.ok) {
      alertsCache = await res.json();
      renderAlertsTable();
    }
  } catch (err) {
    console.error('Failed to fetch initial alerts:', err);
  }
}

async function fetchInitialMetrics() {
  try {
    const res = await fetch('/api/v1/metrics');
    if (res.ok) {
      const data = await res.json();
      updateMetricsUI(data);
    }
  } catch (err) {
    console.error('Failed to fetch metrics:', err);
  }
}

function updateMetricsUI(m) {
  document.getElementById('kpi-flows').textContent = Number(m.total_flows_processed).toLocaleString();
  document.getElementById('kpi-attacks').textContent = Number(m.total_attacks_detected).toLocaleString();
  document.getElementById('kpi-quarantined').textContent = Number(m.active_quarantined_ips).toLocaleString();
  document.getElementById('kpi-cti-hits').textContent = Number(m.threat_intel_hits).toLocaleString();
  document.getElementById('kpi-mttd').textContent = m.mttd_ms;

  const ratio = ((m.total_attacks_detected / Math.max(m.total_flows_processed, 1)) * 100).toFixed(1);
  document.getElementById('kpi-attack-rate').textContent = `${ratio}% Detection Ratio`;

  // Defcon label
  const defconEl = document.getElementById('defcon-label');
  const defconBadge = document.getElementById('defcon-badge');
  defconEl.textContent = m.active_threat_level;

  if (m.active_threat_level.includes('DEFCON 1')) {
    defconBadge.className = 'flex items-center space-x-2 px-3 py-1 rounded-md border border-rose-500/50 bg-rose-950/40 text-rose-400 text-xs font-mono font-bold tracking-wider critical-pulse';
  } else if (m.active_threat_level.includes('DEFCON 2')) {
    defconBadge.className = 'flex items-center space-x-2 px-3 py-1 rounded-md border border-orange-500/40 bg-orange-950/40 text-orange-400 text-xs font-mono font-bold tracking-wider';
  } else {
    defconBadge.className = 'flex items-center space-x-2 px-3 py-1 rounded-md border border-amber-500/30 bg-amber-950/30 text-amber-400 text-xs font-mono font-bold tracking-wider';
  }

  // Update Doughnut chart
  if (m.attacks_by_type) {
    updateThreatTypesChart(m.attacks_by_type);
  }
}

// -------------------------------------------------------------
// Table Rendering
// -------------------------------------------------------------
function renderAlertsTable() {
  const tbody = document.getElementById('alerts-tbody');
  tbody.innerHTML = '';

  if (alertsCache.length === 0) {
    tbody.innerHTML = `
      <tr id="no-alerts-row">
        <td colspan="8" class="text-center py-10 text-slate-500 font-mono text-xs">
          No active threats recorded yet. Launch an attack simulation above to observe live intrusion detection.
        </td>
      </tr>
    `;
    return;
  }

  alertsCache.forEach(alert => renderAlertRow(alert, false));
  if (window.lucide && window.lucide.createIcons) { lucide.createIcons(); }
}

function renderAlertRow(alert, prepend = false) {
  const tbody = document.getElementById('alerts-tbody');
  const noRow = document.getElementById('no-alerts-row');
  if (noRow) noRow.remove();

  const tr = document.createElement('tr');
  tr.id = `alert-row-${alert.alert_id}`;
  tr.className = 'hover:bg-slate-800/40 transition font-sans text-xs border-b border-slate-800/40';

  const sevClass = getSeverityBadgeClass(alert.detection.severity);
  const timeStr = new Date(alert.timestamp).toLocaleTimeString();
  const mitreTags = alert.detection.mitre_techniques.map(t => 
    `<span class="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-cyan-300 border border-slate-700 font-mono mr-1">${t.technique_id}</span>`
  ).join('') || '<span class="text-slate-500 text-[10px] font-mono">None</span>';

  const quarantinedBadge = alert.quarantined
    ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-400 border border-rose-800 font-bold">QUARANTINED</span>`
    : `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">ACTIVE</span>`;

  tr.innerHTML = `
    <td class="py-3 px-3 font-mono text-cyan-400 font-semibold">${alert.alert_id}</td>
    <td class="py-3 px-3">
      <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${sevClass}">
        ${alert.detection.severity}
      </span>
    </td>
    <td class="py-3 px-3">
      <div class="font-medium text-slate-200">${alert.detection.predicted_class}</div>
      <div class="text-[10px] text-slate-400 font-mono">Conf: ${(alert.detection.confidence * 100).toFixed(1)}%</div>
    </td>
    <td class="py-3 px-3 font-mono text-[11px]">
      <div class="text-slate-300 font-semibold flex items-center space-x-1">
        <span>${alert.flow.src_ip}</span>
        ${alert.threat_intel && alert.threat_intel.country_code ? `<span class="text-[10px] text-slate-400">(${alert.threat_intel.country_code})</span>` : ''}
      </div>
      <div class="text-slate-500 text-[10px]">↳ ${alert.flow.dst_ip}:${alert.flow.dst_port} [${alert.flow.protocol}]</div>
    </td>
    <td class="py-3 px-3 font-mono">
      <div class="flex items-center space-x-2">
        <span class="font-bold text-slate-200">${alert.detection.threat_score}</span>
        <div class="w-14 bg-slate-800 rounded-full h-1.5 overflow-hidden">
          <div class="bg-gradient-to-r from-amber-500 to-rose-500 h-1.5 rounded-full" style="width: ${alert.detection.threat_score}%"></div>
        </div>
      </div>
    </td>
    <td class="py-3 px-3">${mitreTags}</td>
    <td class="py-3 px-3">${quarantinedBadge}</td>
    <td class="py-3 px-3 text-right">
      <button onclick="openForensicModal('${alert.alert_id}')" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 rounded border border-slate-700 text-xs font-mono transition">
        Inspect
      </button>
    </td>
  `;

  if (prepend && tbody.firstChild) {
    tbody.insertBefore(tr, tbody.firstChild);
  } else {
    tbody.appendChild(tr);
  }
}

function getSeverityBadgeClass(sev) {
  switch (sev) {
    case 'CRITICAL': return 'badge-critical';
    case 'HIGH': return 'badge-high';
    case 'MEDIUM': return 'badge-medium';
    case 'LOW': return 'badge-low';
    default: return 'badge-info';
  }
}

function filterAlerts() {
  const filter = document.getElementById('severity-filter').value;
  const filtered = filter ? alertsCache.filter(a => a.detection.severity === filter) : alertsCache;
  const tbody = document.getElementById('alerts-tbody');
  tbody.innerHTML = '';
  filtered.forEach(a => renderAlertRow(a, false));
  if (window.lucide && window.lucide.createIcons) { lucide.createIcons(); }
}

function clearAlertFeed() {
  alertsCache = [];
  renderAlertsTable();
}

// -------------------------------------------------------------
// Forensic Modal (Detailed Inspection)
// -------------------------------------------------------------
function openForensicModal(alertId) {
  const alert = alertsCache.find(a => a.alert_id === alertId);
  if (!alert) return;

  currentModalAlert = alert;

  // Header & Title
  document.getElementById('modal-title').textContent = `INCIDENT DOSSIER: ${alert.alert_id}`;
  const sevBadge = document.getElementById('modal-sev-badge');
  sevBadge.textContent = alert.detection.severity;
  sevBadge.className = `px-2 py-0.5 rounded text-xs font-mono font-bold ${getSeverityBadgeClass(alert.detection.severity)}`;

  // Top Metrics
  document.getElementById('modal-threat-score').textContent = `${alert.detection.threat_score} / 100`;
  document.getElementById('modal-confidence').textContent = `${(alert.detection.confidence * 100).toFixed(1)}%`;
  document.getElementById('modal-anomaly-score').textContent = `${alert.detection.anomaly_score.toFixed(3)} (${alert.detection.is_anomaly ? 'High' : 'Normal'})`;
  document.getElementById('modal-containment').textContent = alert.quarantined ? 'QUARANTINED' : 'ACTIVE';
  document.getElementById('modal-containment').className = alert.quarantined ? 'text-xl font-bold text-rose-400 mt-1' : 'text-xl font-bold text-emerald-400 mt-1';

  // Explainable AI (XAI) bars
  const xaiContainer = document.getElementById('modal-xai-container');
  xaiContainer.innerHTML = '';
  if (alert.detection.explainability && alert.detection.explainability.length > 0) {
    alert.detection.explainability.forEach(item => {
      const el = document.createElement('div');
      el.className = 'text-xs font-mono';
      el.innerHTML = `
        <div class="flex items-center justify-between text-slate-300 mb-1">
          <span class="text-cyan-400 font-semibold">${item.feature_name}</span>
          <span class="text-slate-400">${item.description} (+${item.contribution.toFixed(1)}% impact)</span>
        </div>
        <div class="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
          <div class="bg-gradient-to-r from-cyan-500 to-indigo-500 h-1.5 rounded-full" style="width: ${Math.min(item.contribution, 100)}%"></div>
        </div>
      `;
      xaiContainer.appendChild(el);
    });
  } else {
    xaiContainer.innerHTML = `<span class="text-xs text-slate-500 font-mono">No abnormal feature deviations recorded.</span>`;
  }

  // Threat Intelligence & Actor
  const ctiContainer = document.getElementById('modal-cti-container');
  ctiContainer.innerHTML = '';
  const cti = alert.threat_intel;
  if (cti) {
    ctiContainer.innerHTML = `
      <div class="p-2 bg-slate-950 rounded border border-slate-800">
        <span class="text-slate-400 text-[10px]">Reputation Score</span>
        <div class="text-slate-200 font-bold">${cti.reputation_score} / 100 (${cti.is_malicious ? 'MALICIOUS' : 'CLEAN'})</div>
      </div>
      <div class="p-2 bg-slate-950 rounded border border-slate-800">
        <span class="text-slate-400 text-[10px]">Attributed Threat Actor</span>
        <div class="text-rose-400 font-bold">${cti.threat_actor || 'Unattributed Entity'}</div>
      </div>
      <div class="p-2 bg-slate-950 rounded border border-slate-800">
        <span class="text-slate-400 text-[10px]">Origin & Geolocation</span>
        <div class="text-slate-200">${cti.city ? cti.city + ', ' : ''}${cti.country} (${cti.country_code})</div>
      </div>
      <div class="p-2 bg-slate-950 rounded border border-slate-800">
        <span class="text-slate-400 text-[10px]">Autonomous System (ASN)</span>
        <div class="text-slate-200">${cti.asn || 'N/A'} - ${cti.isp || 'N/A'}</div>
      </div>
      <div class="p-2 bg-slate-950 rounded border border-slate-800">
        <span class="text-slate-400 text-[10px]">Tor Exit Node Status</span>
        <div class="${cti.tor_exit_node ? 'text-amber-400 font-bold' : 'text-slate-400'}">${cti.tor_exit_node ? 'CONFIRMED TOR NODE' : 'Direct IP'}</div>
      </div>
      <div class="p-2 bg-slate-950 rounded border border-slate-800">
        <span class="text-slate-400 text-[10px]">Associated CVEs</span>
        <div class="text-cyan-400">${cti.cve_ids && cti.cve_ids.length ? cti.cve_ids.join(', ') : 'None'}</div>
      </div>
    `;
  }

  // MITRE Techniques
  const mitreContainer = document.getElementById('modal-mitre-container');
  mitreContainer.innerHTML = '';
  if (alert.detection.mitre_techniques && alert.detection.mitre_techniques.length > 0) {
    alert.detection.mitre_techniques.forEach(t => {
      const el = document.createElement('div');
      el.className = 'p-3 bg-slate-950 rounded border border-slate-800 font-mono';
      el.innerHTML = `
        <div class="flex items-center justify-between">
          <span class="text-cyan-400 font-bold">${t.technique_id} - ${t.name}</span>
          <span class="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300 text-[10px]">${t.tactic}</span>
        </div>
        <p class="text-slate-400 text-xs mt-1.5 font-sans">${t.description}</p>
        <div class="mt-2 text-[11px] text-teal-400 font-sans border-t border-slate-800 pt-1.5">
          <span class="font-bold text-teal-300">Defense Action:</span> ${t.mitigation}
        </div>
      `;
      mitreContainer.appendChild(el);
    });
  }

  // Payload Disassembly
  document.getElementById('modal-payload-preview').textContent = 
    alert.flow.payload_preview || `Source: ${alert.flow.src_ip}:${alert.flow.src_port} -> ${alert.flow.dst_ip}:${alert.flow.dst_port} [${alert.flow.protocol}] (No ASCII payload)`;

  // Firewall Rule
  document.getElementById('modal-firewall-rule').textContent = 
    alert.firewall_rules?.iptables || `sudo iptables -I INPUT -s ${alert.flow.src_ip} -j DROP`;

  // Quarantine button text
  const qBtn = document.getElementById('modal-quarantine-toggle-btn');
  if (alert.quarantined) {
    qBtn.textContent = 'Release Host from Quarantine';
    qBtn.className = 'px-4 py-1.5 bg-slate-700 hover:bg-slate-600 text-white rounded text-xs font-bold transition';
  } else {
    qBtn.textContent = 'Quarantine Host';
    qBtn.className = 'px-4 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-bold transition';
  }

  document.getElementById('forensic-modal').classList.remove('hidden');
  if (window.lucide && window.lucide.createIcons) { lucide.createIcons(); }
}

function closeForensicModal() {
  document.getElementById('forensic-modal').classList.add('hidden');
}

function copyFirewallRule() {
  const rule = document.getElementById('modal-firewall-rule').textContent;
  navigator.clipboard.writeText(rule);
  alert('Copied iptables firewall rule to clipboard!');
}

async function toggleQuarantineFromModal() {
  if (!currentModalAlert) return;
  const ip = currentModalAlert.flow.src_ip;

  if (currentModalAlert.quarantined) {
    // Unquarantine
    const res = await fetch('/api/v1/mitigation/unquarantine', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    if (res.ok) {
      currentModalAlert.quarantined = false;
      closeForensicModal();
      fetchInitialAlerts();
      fetchInitialMetrics();
    }
  } else {
    // Quarantine
    const res = await fetch('/api/v1/mitigation/quarantine', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason: 'Analyst SOC Manual Action' })
    });
    if (res.ok) {
      currentModalAlert.quarantined = true;
      closeForensicModal();
      fetchInitialAlerts();
      fetchInitialMetrics();
    }
  }
}

async function downloadStixForModalAlert() {
  if (!currentModalAlert) return;
  try {
    const res = await fetch(`/api/v1/alerts/${currentModalAlert.alert_id}/stix`);
    if (res.ok) {
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data.stix_json, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `stix_2.1_${currentModalAlert.alert_id}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }
  } catch (err) {
    console.error('Error exporting STIX:', err);
  }
}

// -------------------------------------------------------------
// Attack Simulation Controls
// -------------------------------------------------------------
async function triggerSimulation(attackType, count = 10) {
  try {
    const res = await fetch('/api/v1/simulation/launch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        attack_type: attackType,
        packet_count: count,
        target_ip: '192.168.1.100'
      })
    });
    if (res.ok) {
      const data = await res.json();
      console.log('Simulation complete:', data);
    }
  } catch (err) {
    console.error('Simulation failed:', err);
  }
}

// -------------------------------------------------------------
// PCAP Upload & Export
// -------------------------------------------------------------
async function handlePcapUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/v1/traffic/upload-pcap', {
      method: 'POST',
      body: formData
    });
    if (res.ok) {
      const data = await res.json();
      alert(`PCAP Analysis Finished: Extracted ${data.total_flows_extracted} flows, detected ${data.threats_detected} threats!`);
      fetchInitialAlerts();
      fetchInitialMetrics();
    }
  } catch (err) {
    console.error('PCAP upload failed:', err);
  }
}

function exportPcap() {
  window.open('/api/v1/traffic/export-pcap', '_blank');
}

// -------------------------------------------------------------
// Threat Intelligence Search Modal
// -------------------------------------------------------------
function openThreatIntelModal() {
  document.getElementById('cti-modal').classList.remove('hidden');
}

function closeThreatIntelModal() {
  document.getElementById('cti-modal').classList.add('hidden');
}

async function searchThreatIntel() {
  const indicator = document.getElementById('cti-search-input').value.trim();
  if (!indicator) return;

  const resultsDiv = document.getElementById('cti-results-container');
  resultsDiv.classList.remove('hidden');
  resultsDiv.innerHTML = '<span class="text-slate-400">Querying Cyber Threat Intelligence feeds...</span>';

  try {
    const res = await fetch(`/api/v1/threat-intel/lookup/${encodeURIComponent(indicator)}`);
    if (res.ok) {
      const data = await res.json();
      resultsDiv.innerHTML = `
        <div class="border-b border-slate-800 pb-2 mb-2 flex items-center justify-between">
          <span class="text-cyan-400 font-bold text-sm">${data.indicator}</span>
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${data.is_malicious ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'}">
            ${data.is_malicious ? 'CONFIRMED THREAT' : 'BENIGN INDICATOR'}
          </span>
        </div>
        <div><span class="text-slate-400">Reputation Score:</span> <span class="text-slate-200 font-bold">${data.reputation_score} / 100</span></div>
        <div><span class="text-slate-400">Attributed Actor:</span> <span class="text-rose-400">${data.threat_actor || 'None'}</span></div>
        <div><span class="text-slate-400">Categories:</span> <span class="text-slate-300">${data.categories.join(', ') || 'N/A'}</span></div>
        <div><span class="text-slate-400">Geolocation:</span> <span class="text-slate-300">${data.city ? data.city + ', ' : ''}${data.country} (${data.country_code})</span></div>
        <div><span class="text-slate-400">ASN / ISP:</span> <span class="text-slate-300">${data.asn || 'N/A'} - ${data.isp || 'N/A'}</span></div>
        <div><span class="text-slate-400">Tor Exit Node:</span> <span class="text-slate-300">${data.tor_exit_node ? 'YES' : 'NO'}</span></div>
        <div><span class="text-slate-400">Reported Abuse Count:</span> <span class="text-slate-300">${data.reported_abuse_count}</span></div>
      `;
    }
  } catch (err) {
    resultsDiv.innerHTML = '<span class="text-rose-400">Lookup failed. Please verify indicator format.</span>';
  }
}
