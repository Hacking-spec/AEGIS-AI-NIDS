/**
 * Core Application Controller for Aegis AI-NIDS SOC Dashboard
 * Supports both WebSocket live push and Serverless/Vercel auto-polling fallback.
 */

let alertsCache = [];
let currentModalAlert = null;
let ws = null;
let pollTimer = null;

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  connectWebSocket();
  fetchInitialAlerts();
  fetchInitialMetrics();
});

// -------------------------------------------------------------
// WebSocket & Serverless Polling Fallback
// -------------------------------------------------------------
function connectWebSocket() {
  try {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/soc-feed`;
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log('[✓] Connected to Aegis SOC Live WebSocket Feed');
      updateWsStatus(true);
      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
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
      console.log('[!] WebSocket connection closed. Activating serverless polling fallback.');
      updateWsStatus(false);
      startPolling();
    };

    ws.onerror = (err) => {
      console.log('[!] WebSocket error (expected on serverless hosts like Vercel). Activating polling.');
      updateWsStatus(false);
      startPolling();
    };
  } catch (e) {
    console.log('[!] WebSocket init failed. Activating serverless polling mode.');
    updateWsStatus(false);
    startPolling();
  }
}

function startPolling() {
  if (!pollTimer) {
    pollTimer = setInterval(() => {
      fetchInitialAlerts();
      fetchInitialMetrics();
    }, 3000);
  }
}

function updateWsStatus(connected) {
  const indicator = document.getElementById('ws-indicator');
  const text = document.getElementById('ws-status-text');
  if (connected) {
    if (indicator) indicator.style.backgroundColor = '#10b981';
    if (text) {
      text.textContent = 'ENGINE ARMED';
      text.className = 'text-emerald';
    }
  } else {
    // Graceful fallback for serverless hosting (Vercel)
    if (indicator) indicator.style.backgroundColor = '#06b6d4';
    if (text) {
      text.textContent = 'TELEMETRY ACTIVE';
      text.className = 'text-cyan';
    }
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
      const newAlerts = await res.json();
      alertsCache = newAlerts;
      renderAlertsTable();
    }
  } catch (err) {
    console.warn('Failed to fetch initial alerts:', err);
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
    console.warn('Failed to fetch initial metrics:', err);
  }
}

function updateMetricsUI(metrics) {
  if (!metrics) return;

  const kpiFlows = document.getElementById('kpi-flows');
  const kpiAttacks = document.getElementById('kpi-attacks');
  const kpiAttackRate = document.getElementById('kpi-attack-rate');
  const kpiQuarantined = document.getElementById('kpi-quarantined');
  const kpiCtiHits = document.getElementById('kpi-cti-hits');
  const kpiMttd = document.getElementById('kpi-mttd');
  const defconLabel = document.getElementById('defcon-label');
  const defconBadge = document.getElementById('defcon-badge');

  if (kpiFlows) kpiFlows.textContent = (metrics.total_flows_processed || 0).toLocaleString();
  if (kpiAttacks) kpiAttacks.textContent = (metrics.total_attacks_intercepted || 0).toLocaleString();
  if (kpiQuarantined) kpiQuarantined.textContent = (metrics.quarantined_hosts_count || 0).toLocaleString();
  if (kpiCtiHits) kpiCtiHits.textContent = (metrics.active_c2_indicators_tracked || 0).toLocaleString();
  if (kpiMttd) kpiMttd.textContent = (metrics.mttd_latency_ms || 2.4).toFixed(1);

  if (kpiAttackRate) {
    const ratio = metrics.total_flows_processed > 0 
      ? ((metrics.total_attacks_intercepted / metrics.total_flows_processed) * 100).toFixed(1)
      : '0.0';
    kpiAttackRate.textContent = `${ratio}% Detection Ratio`;
  }

  if (defconLabel) {
    defconLabel.textContent = metrics.active_threat_level || 'DEFCON 5 (NOMINAL)';
  }

  if (defconBadge) {
    const level = metrics.active_threat_level || 'DEFCON 5';
    if (level.includes('DEFCON 1') || level.includes('DEFCON 2')) {
      defconBadge.style.color = '#fb7185';
      defconBadge.style.borderColor = 'rgba(244, 63, 94, 0.6)';
      defconBadge.style.backgroundColor = 'rgba(244, 63, 94, 0.15)';
    } else if (level.includes('DEFCON 3') || level.includes('DEFCON 4')) {
      defconBadge.style.color = '#fbbf24';
      defconBadge.style.borderColor = 'rgba(245, 158, 11, 0.5)';
      defconBadge.style.backgroundColor = 'rgba(245, 158, 11, 0.15)';
    } else {
      defconBadge.style.color = '#34d399';
      defconBadge.style.borderColor = 'rgba(16, 185, 129, 0.5)';
      defconBadge.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
    }
  }

  if (metrics.attacks_by_type && typeof updateThreatTypesChart === 'function') {
    updateThreatTypesChart(metrics.attacks_by_type);
  }
}

// -------------------------------------------------------------
// Alerts Table Rendering
// -------------------------------------------------------------
function renderAlertsTable() {
  const tbody = document.getElementById('alerts-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (alertsCache.length === 0) {
    tbody.innerHTML = `
      <tr id="no-alerts-row">
        <td colspan="8" style="text-align:center; padding: 2.5rem 1rem; color:#64748b; font-family:monospace; font-size:0.8rem;">
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
  if (!tbody) return;
  const noRow = document.getElementById('no-alerts-row');
  if (noRow) noRow.remove();

  const tr = document.createElement('tr');
  tr.id = `alert-row-${alert.alert_id}`;

  const sevClass = getSeverityBadgeClass(alert.detection.severity);
  const mitreTags = (alert.detection.mitre_techniques || []).map(t => 
    `<span style="display:inline-block; padding:0.15rem 0.4rem; border-radius:0.25rem; background:#1e293b; color:#38bdf8; border:1px solid #334155; font-family:monospace; font-size:0.65rem; margin-right:0.25rem;">${t.technique_id}</span>`
  ).join('') || '<span style="color:#64748b; font-family:monospace; font-size:0.65rem;">None</span>';

  const quarantinedBadge = alert.quarantined
    ? `<span class="badge badge-critical">QUARANTINED</span>`
    : `<span class="badge badge-info">ACTIVE</span>`;

  tr.innerHTML = `
    <td style="font-family:monospace; font-weight:700; color:#38bdf8;">${alert.alert_id}</td>
    <td>
      <span class="badge ${sevClass}">
        ${alert.detection.severity}
      </span>
    </td>
    <td>
      <div style="font-weight:600; color:#e2e8f0;">${alert.detection.predicted_class}</div>
      <div style="font-size:0.68rem; color:#94a3b8; font-family:monospace;">Conf: ${(alert.detection.confidence * 100).toFixed(1)}%</div>
    </td>
    <td style="font-family:monospace; font-size:0.75rem;">
      <div style="font-weight:600; color:#cbd5e1;">
        <span>${alert.flow.src_ip}</span>
        ${alert.threat_intel && alert.threat_intel.country_code ? `<span style="font-size:0.68rem; color:#94a3b8;">(${alert.threat_intel.country_code})</span>` : ''}
      </div>
      <div style="color:#64748b; font-size:0.68rem;">↳ ${alert.flow.dst_ip}:${alert.flow.dst_port} [${alert.flow.protocol}]</div>
    </td>
    <td style="font-family:monospace;">
      <div style="display:flex; align-items:center; gap:0.5rem;">
        <span style="font-weight:700; color:#f1f5f9;">${alert.detection.threat_score}</span>
        <div style="width:60px; background:#1e293b; border-radius:999px; height:6px; overflow:hidden;">
          <div style="background:linear-gradient(90deg, #f59e0b, #f43f5e); height:6px; width:${alert.detection.threat_score}%;"></div>
        </div>
      </div>
    </td>
    <td>${mitreTags}</td>
    <td>${quarantinedBadge}</td>
    <td style="text-align:right;">
      <button onclick="openForensicModal('${alert.alert_id}')" class="btn btn-secondary" style="font-size:0.7rem; padding:0.25rem 0.65rem;">
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
  sevBadge.className = `badge ${getSeverityBadgeClass(alert.detection.severity)}`;

  // Top Metrics
  document.getElementById('modal-threat-score').textContent = `${alert.detection.threat_score} / 100`;
  document.getElementById('modal-confidence').textContent = `${(alert.detection.confidence * 100).toFixed(1)}%`;
  document.getElementById('modal-anomaly-score').textContent = `${alert.detection.anomaly_score.toFixed(3)} (${alert.detection.is_anomaly ? 'High' : 'Normal'})`;
  
  const cEl = document.getElementById('modal-containment');
  cEl.textContent = alert.quarantined ? 'QUARANTINED' : 'ACTIVE';
  cEl.style.color = alert.quarantined ? '#f43f5e' : '#10b981';

  // Explainable AI (XAI) bars
  const xaiContainer = document.getElementById('modal-xai-container');
  xaiContainer.innerHTML = '';
  if (alert.detection.explainability && alert.detection.explainability.length > 0) {
    alert.detection.explainability.forEach(item => {
      const el = document.createElement('div');
      el.style.cssText = 'font-size:0.75rem; font-family:monospace;';
      el.innerHTML = `
        <div style="display:flex; justify-content:space-between; color:#cbd5e1; margin-bottom:0.25rem;">
          <span style="color:#06b6d4; font-weight:700;">${item.feature_name}</span>
          <span style="color:#94a3b8;">${item.description} (+${item.contribution.toFixed(1)}% impact)</span>
        </div>
        <div style="width:100%; background:#1e293b; height:6px; border-radius:999px; overflow:hidden;">
          <div style="background:linear-gradient(90deg, #06b6d4, #6366f1); height:6px; width:${Math.min(item.contribution, 100)}%;"></div>
        </div>
      `;
      xaiContainer.appendChild(el);
    });
  } else {
    xaiContainer.innerHTML = `<span style="font-size:0.72rem; color:#64748b; font-family:monospace;">No abnormal feature deviations recorded.</span>`;
  }

  // Threat Intelligence & Actor
  const ctiContainer = document.getElementById('modal-cti-container');
  ctiContainer.innerHTML = '';
  const cti = alert.threat_intel;
  if (cti) {
    ctiContainer.innerHTML = `
      <div style="padding:0.6rem; background:#02050d; border-radius:0.4rem; border:1px solid #1e293b;">
        <span style="color:#64748b; font-size:0.65rem;">Reputation Score</span>
        <div style="color:#f1f5f9; font-weight:700;">${cti.reputation_score} / 100 (${cti.is_malicious ? 'MALICIOUS' : 'CLEAN'})</div>
      </div>
      <div style="padding:0.6rem; background:#02050d; border-radius:0.4rem; border:1px solid #1e293b;">
        <span style="color:#64748b; font-size:0.65rem;">Attributed Threat Actor</span>
        <div style="color:#f43f5e; font-weight:700;">${cti.threat_actor || 'Unattributed Entity'}</div>
      </div>
      <div style="padding:0.6rem; background:#02050d; border-radius:0.4rem; border:1px solid #1e293b;">
        <span style="color:#64748b; font-size:0.65rem;">Origin & Geolocation</span>
        <div style="color:#f1f5f9;">${cti.city ? cti.city + ', ' : ''}${cti.country} (${cti.country_code})</div>
      </div>
      <div style="padding:0.6rem; background:#02050d; border-radius:0.4rem; border:1px solid #1e293b;">
        <span style="color:#64748b; font-size:0.65rem;">Autonomous System (ASN)</span>
        <div style="color:#f1f5f9;">${cti.asn || 'N/A'} - ${cti.isp || 'N/A'}</div>
      </div>
      <div style="padding:0.6rem; background:#02050d; border-radius:0.4rem; border:1px solid #1e293b;">
        <span style="color:#64748b; font-size:0.65rem;">Tor Exit Node Status</span>
        <div style="font-weight:700; color:${cti.tor_exit_node ? '#f59e0b' : '#64748b'};">${cti.tor_exit_node ? 'CONFIRMED TOR NODE' : 'Direct IP'}</div>
      </div>
      <div style="padding:0.6rem; background:#02050d; border-radius:0.4rem; border:1px solid #1e293b;">
        <span style="color:#64748b; font-size:0.65rem;">Associated CVEs</span>
        <div style="color:#06b6d4;">${cti.cve_ids && cti.cve_ids.length ? cti.cve_ids.join(', ') : 'None'}</div>
      </div>
    `;
  }

  // MITRE Techniques
  const mitreContainer = document.getElementById('modal-mitre-container');
  mitreContainer.innerHTML = '';
  if (alert.detection.mitre_techniques && alert.detection.mitre_techniques.length > 0) {
    alert.detection.mitre_techniques.forEach(t => {
      const el = document.createElement('div');
      el.style.cssText = 'padding:0.65rem; background:#02050d; border-radius:0.4rem; border:1px solid #1e293b; font-family:monospace;';
      el.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <span style="color:#06b6d4; font-weight:700;">${t.technique_id} - ${t.name}</span>
          <span style="padding:0.15rem 0.45rem; border-radius:0.25rem; background:#0f172a; border:1px solid #334155; color:#94a3b8; font-size:0.65rem;">${t.tactic}</span>
        </div>
        <p style="color:#94a3b8; font-size:0.72rem; margin-top:0.35rem; font-family:sans-serif;">${t.description}</p>
        <div style="margin-top:0.5rem; font-size:0.7rem; color:#2dd4bf; border-top:1px solid #1e293b; padding-top:0.35rem; font-family:sans-serif;">
          <span style="font-weight:700; color:#5eead4;">Defense Action:</span> ${t.mitigation}
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
    qBtn.className = 'btn btn-secondary';
  } else {
    qBtn.textContent = 'Quarantine Host';
    qBtn.className = 'btn btn-danger';
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
      fetchInitialAlerts();
      fetchInitialMetrics();
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
  resultsDiv.innerHTML = '<span style="color:#94a3b8;">Querying Cyber Threat Intelligence feeds...</span>';

  try {
    const res = await fetch(`/api/v1/threat-intel/lookup/${encodeURIComponent(indicator)}`);
    if (res.ok) {
      const data = await res.json();
      resultsDiv.innerHTML = `
        <div style="border-bottom:1px solid #1e293b; padding-bottom:0.5rem; margin-bottom:0.5rem; display:flex; justify-content:space-between; align-items:center;">
          <span style="color:#06b6d4; font-weight:700; font-size:0.9rem;">${data.indicator}</span>
          <span class="badge ${data.is_malicious ? 'badge-critical' : 'badge-low'}">
            ${data.is_malicious ? 'CONFIRMED THREAT' : 'BENIGN INDICATOR'}
          </span>
        </div>
        <div><span style="color:#64748b;">Reputation Score:</span> <span style="color:#f1f5f9; font-weight:700;">${data.reputation_score} / 100</span></div>
        <div><span style="color:#64748b;">Attributed Actor:</span> <span style="color:#f43f5e; font-weight:700;">${data.threat_actor || 'None'}</span></div>
        <div><span style="color:#64748b;">Categories:</span> <span style="color:#cbd5e1;">${data.categories.join(', ') || 'N/A'}</span></div>
        <div><span style="color:#64748b;">Geolocation:</span> <span style="color:#cbd5e1;">${data.city ? data.city + ', ' : ''}${data.country} (${data.country_code})</span></div>
        <div><span style="color:#64748b;">ASN / ISP:</span> <span style="color:#cbd5e1;">${data.asn || 'N/A'} - ${data.isp || 'N/A'}</span></div>
        <div><span style="color:#64748b;">Tor Exit Node:</span> <span style="color:#cbd5e1;">${data.tor_exit_node ? 'YES' : 'NO'}</span></div>
        <div><span style="color:#64748b;">Reported Abuse Count:</span> <span style="color:#cbd5e1;">${data.reported_abuse_count}</span></div>
      `;
    }
  } catch (err) {
    resultsDiv.innerHTML = '<span style="color:#f43f5e;">Lookup failed. Please verify indicator format.</span>';
  }
}
