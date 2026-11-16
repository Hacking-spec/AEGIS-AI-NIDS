# 🎨 AEGIS AI-NIDS // UI/UX DESIGN SYSTEM SPECIFICATION
### Next-Gen Tactical Cyber Defense Operations Center (SOC) Design Blueprint

---

## 1. Design Philosophy & Vision

The **AEGIS AI-NIDS** user interface is crafted to embody the ergonomics of an elite military Cyber Defense Operations Center (SOC). It merges **high-contrast tactical visibility**, **zero-latency real-time telemetry**, and **subtle futuristic glassmorphism** to maximize operational awareness and minimize cognitive fatigue during active incident response.

### Core Tenets:
1. **At-A-Glance Situational Awareness**: Critical threat telemetry (DEFCON rating, packet velocity, zero-day anomaly scores) is prioritized in top-level sightlines.
2. **Deterministic Triage Ergonomics**: High-severity events are immediately distinguishable through luminance, saturated hue tokens, and pulsing tactical glow effects.
3. **Deep Forensic Translucency**: Analysts can drill down from high-level KPI trends into packet disassembly, explainable feature importance, and multi-vendor firewall playbooks in fewer than two clicks.
4. **Dark-Adaptive Visual Comfort**: Engineered for low-light command center environments, mitigating eye strain while preserving sharp visual hierarchy.

---

## 2. Visual Architecture & Layout Grid

```
+-----------------------------------------------------------------------------------+
| TOP HUD NAVBAR: Brand • Version • Engine Armed Beacon • DEFCON Posture • Controls |
+-----------------------------------------------------------------------------------+
| KPI TELEMETRY RIBBON: Flows • Attacks • Quarantines • CTI Hits • Latency • Accuracy|
+-------------------------------------------------+---------------------------------+
| LIVE TRAFFIC TIMELINE (Chart.js Dual-Axis)      | THREAT VECTOR BREAKDOWN (Donut) |
| (Real-time Flow Volume vs Intrusion Intercepts) | & MITRE ATT&CK RADAR MATRIX     |
+-------------------------------------------------+---------------------------------+
| ATTACK SIMULATION STUDIO                        | FORENSIC PCAP DROPZONE          |
| (SYN, Nmap, SSH Brute, SQLi, C2 Beacon)         | (Binary Libpcap Inspection)     |
+-------------------------------------------------+---------------------------------+
| LIVE INTRUSION ALERTS TABLE (Timestamp • Vector • IPs • Threat Score • Status)    |
+-----------------------------------------------------------------------------------+
| FORENSIC MODAL DRAWER (Payload Disassembly • XAI SHAP • Firewall Rules • STIX)   |
+-----------------------------------------------------------------------------------+
```

---

## 3. Color Tokens & Semantic Hierarchy

| Token Name | Hex Code | Role & Semantics | Visual Application |
| :--- | :--- | :--- | :--- |
| `--bg-deep` | `#050811` | Primary Canvas Background | Void-black foundational canvas |
| `--bg-panel` | `rgba(11, 17, 32, 0.78)` | Glassmorphic Surface | HUD panels, modal windows |
| `--border-subtle` | `rgba(51, 65, 85, 0.45)` | Structural Boundaries | Panel dividers, table borders |
| `--accent-cyan` | `#06b6d4` | Primary System Accent | Active navigation, normal packets |
| `--accent-emerald` | `#10b981` | Engine Armed / Nominal State | DEFCON 5, benign traffic, healthy links |
| `--accent-amber` | `#f59e0b` | Elevated Warning State | DEFCON 3, port scanning, medium risk |
| `--accent-rose` | `#f43f5e` | Critical Infiltration Breach | DEFCON 1, exploits, active quarantine |
| `--accent-indigo` | `#6366f1` | Threat Intelligence & STIX | CTI matches, APT actors, OASIS export |

---

## 4. Typography Scale

The interface uses a deliberate pairing of geometric humanistic sans-serif for UI readability and precision monospace for packet telemetry:

1. **Body & Controls (`Plus Jakarta Sans`)**:
   - Headers: `font-bold` to `font-black`, uppercase tracking (`tracking-wider`)
   - Labels & Buttons: `text-xs` (12px) to `text-sm` (14px), font-weight 600
2. **Telemetry & Code (`JetBrains Mono`)**:
   - IP Addresses & Ports: `font-mono text-cyan-300`
   - Timestamps & DEFCON levels: `font-mono tracking-wide`
   - Disassembly & Hex Dumps: `font-mono text-xs text-cyan-400 bg-black/60`
   - Multi-vendor Firewall Scripts: `font-mono text-emerald-400`

---

## 5. Micro-Interactions & Motion Design

1. **Active Engine Pulse**:
   - The WebSocket indicator features a concentric CSS `@keyframes` ping ring indicating live bidirectional socket telemetry.
2. **Threat Level Escalation (`critical-pulse`)**:
   - High-severity alerts trigger an automated border illumination cycle that draws the operator’s peripheral vision directly to uncontained intrusions.
3. **Telemetry Counters (`CountUp.js` / Smooth Interpolation)**:
   - Metric numerals update smoothly without abrupt layout shifts.
4. **Interactive Charting**:
   - Chart.js animations are throttled to 30 FPS to conserve GPU cycles on low-power SOC workstations.

---

## 6. Ergonomic & Accessibility Standards

- **Color Contrast**: All text tokens exceed **WCAG 2.1 AAA** contrast ratios against dark surface panels ($\ge 7:1$).
- **Dual Coding**: Severity levels are conveyed simultaneously via **Hue**, **Text Badges** (e.g. `CRITICAL`, `HIGH`, `MEDIUM`), and **DEFCON Numerical Scale** to ensure complete usability for color-deficient operators.
- **Copy-to-Clipboard Efficiency**: Every generated firewall command (`iptables`, `windows_netsh`, `cisco_ios`) includes a dedicated one-click copy button with visual state feedback (`Copied!`).

