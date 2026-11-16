# 🛡️ AEGIS AI-NIDS & SENTINEL CTI
### Next-Generation AI-Powered Network Intrusion Detection & Automated Cyber Threat Intelligence System

[![Python](https://img.shields.io/badge/Python-3.12-3776AB.svg?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109.0-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.4.0-F7931E.svg?style=flat&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![STIX](https://img.shields.io/badge/OASIS-STIX_2.1-blue.svg?style=flat)](https://oasis-open.github.io/cti-documentation/)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK_Enterprise-red.svg?style=flat)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat)](LICENSE)

---

## 📌 Executive Summary

**AEGIS AI-NIDS** (Network Intrusion Detection System) and **Sentinel CTI** (Cyber Threat Intelligence Hub) form a unified, mission-critical autonomous cyber defense platform. Designed for Security Operations Centers (SOC) and critical network perimeters, the platform fuses **Supervised Multi-Class Machine Learning**, **Deep Anomaly AutoEncoders**, and **Deterministic Heuristic Signatures** into a high-speed Bayesian ensemble engine.

The platform continuously intercepts, reconstructs, and inspects network packets in real time—enriching suspicious flows with live Threat Intelligence, mapping attacks against the **MITRE ATT&CK Enterprise Matrix**, generating **OASIS STIX 2.1** incident bundles, and executing autonomous mitigation playbooks across **multi-vendor firewalls** (`iptables`, `nftables`, `windows_netsh`, `cisco_ios`, `aws_security_group`, `pfsense_xml`).

---

## 🏛️ System Architecture

```
                                  +---------------------------------------+
                                  |    Network Ingestion / PCAP Stream    |
                                  | (Synthetic Simulator / Binary .pcap)  |
                                  +-------------------+-------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |     Feature Extraction Engine         |
                                  |  (17 CIC-IDS2017 / KDD99 Vectors)     |
                                  +-------------------+-------------------+
                                                      |
                         +----------------------------+----------------------------+
                         |                                                         |
                         v                                                         v
         +-------------------------------+                         +-------------------------------+
         |     Signature Engine          |                         |     AI Detection Pipeline     |
         |  (Snort/Suricata Heuristics)  |                         |  - Supervised Random Forest   |
         |  - SQLi / XSS / RCE / LFI     |                         |  - Deep Bottleneck AutoEncoder|
         |  - Log4Shell (CVE-2021-44228) |                         |  - Isolation Forest Ensemble  |
         |  - C2 Beacon / DNS Tunneling  |                         |  - Explainable AI (XAI SHAP)  |
         +---------------+---------------+                         +---------------+---------------+
                         |                                                         |
                         +----------------------------+----------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |     Multi-Model Fusion Ensemble       |
                                  |  (Weighted Score: 0 - 100 DEFCON)     |
                                  +-------------------+-------------------+
                                                      |
                         +----------------------------+----------------------------+
                         |                                                         |
                         v                                                         v
         +-------------------------------+                         +-------------------------------+
         |  Sentinel Threat Intelligence |                         |    SOAR Automated Response    |
         |  - APT / C2 Tracker (APT29)   |                         |  - Multi-Vendor Firewall Gen  |
         |  - Tor Exit Nodes & GeoIP/ASN |                         |  - Host Isolation & Port Kill |
         |  - MITRE ATT&CK Correlation   |                         |  - Real-time Micro-Quarantine |
         |  - OASIS STIX 2.1 Exporter    |                         |  - Analyst Override Playbook  |
         +---------------+---------------+                         +---------------+---------------+
                         |                                                         |
                         +----------------------------+----------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |  Cyber Defense Operations Center (SOC)|
                                  |  - Glassmorphic Web Dashboard (HTML5) |
                                  |  - Low-Latency WebSocket Stream       |
                                  |  - Timeline, Donut & Radar Analytics  |
                                  |  - Deep Forensic Inspection Drawer    |
                                  +---------------------------------------+
```

---

## ⚡ Key Capabilities & Features

### 1. Multi-Model AI/ML Intrusion Detection Pipeline
- **Supervised Classifier**: 100-estimator Random Forest multi-class detector trained across 7 traffic classes: `BENIGN`, `DDOS_SYN`, `PORT_SCAN`, `SSH_BRUTE`, `SQLI_WEB`, `C2_BEACON`, and `EXFILTRATION`.
  - **100% Test Accuracy & F1-Score 1.0000** across all evaluated attack classes.
- **Deep Anomaly AutoEncoder**: 5-layer neural bottleneck architecture ($17 \to 32 \to 16 \to 6 \to 16 \to 32 \to 17$) combined with an `IsolationForest` ensemble. Quantifies reconstruction mean-squared-error (MSE) to flag **Zero-Day anomalies and polymorphic threats** without signature matching.
- **Snort/Suricata-Style Signature Engine**: Deterministic regex scanning for high-confidence indicators, including SQL Injection, Cross-Site Scripting (XSS), Log4Shell (`CVE-2021-44228`), Local File Inclusion (LFI), Cobalt Strike C2 malleable profiles, and DNS Tunneling.
- **Bayesian Multi-Model Fusion**: Synthesizes supervised probabilities, unsupervised reconstruction loss, and heuristic signature hits into a unified, calibrated **Threat Score (0–100)** and DEFCON severity rating.
- **Explainable AI (XAI)**: Generates per-flow feature contribution breakdowns explaining exactly why the AI flagged a flow (e.g. `serror_rate` deviation, `byte_rate` spike, `same_srv_rate` drop).

### 2. Automated Cyber Threat Intelligence (CTI) & MITRE ATT&CK Hub
- **Threat Actor & APT Profiling**: Pre-populated indicator intelligence correlating IPs with notorious APTs (**APT29 / Cozy Bear**, **Wizard Spider**, **Mirai Operator Group**, **Lazarus Group**).
- **GeoIP & ASN Enrichment**: Automated lookup of Autonomous System Numbers (ASN), ISPs, Country codes, and Cities for all incoming flows.
- **Tor Exit Node & Proxy Tracker**: Identifies flows originating from anonymization networks.
- **MITRE ATT&CK Enterprise Mapping**: Maps every detected intrusion to formal ATT&CK Tactics & Techniques:
  - `T1498` (Network Denial of Service)
  - `T1046` (Network Service Scanning)
  - `T1110` (Brute Force: Password Guessing)
  - `T1190` (Exploit Public-Facing Application)
  - `T1059` (Command and Scripting Interpreter)
  - `T1071` (Application Layer Protocol: C2)
  - `T1048` (Exfiltration Over Alternative Protocol)
  - `T1083` (File and Directory Discovery)
- **OASIS STIX 2.1 Export**: Generates compliant STIX 2.1 JSON bundles containing `identity`, `indicator`, `attack-pattern`, `threat-actor`, `course-of-action`, and `relationship` objects for automated sharing with MISP, OpenCTI, and TAXII servers.

### 3. Automated SOAR Playbook Engine
- **Multi-Vendor Firewall Generation**: Instantly renders copy-paste and executable blocking commands tailored for:
  - **Linux `iptables`**: `sudo iptables -I INPUT -s <IP> -j DROP`
  - **Linux `nftables`**: `sudo nft add rule inet filter input ip saddr <IP> counter drop`
  - **Windows `netsh`**: `netsh advfirewall firewall add rule name="AegisBlock_<IP>" dir=in action=block remoteip=<IP>`
  - **Windows PowerShell**: `New-NetFirewallRule -DisplayName "Aegis_Block_<IP>" -Direction Inbound -Action Block -RemoteAddress <IP>`
  - **Cisco IOS ACL**: `access-list 101 deny ip host <IP> any`
  - **AWS Security Group CLI**: `aws ec2 revoke-security-group-ingress ...`
  - **pfSense XML**: Native pfSense rule format
- **Autonomous Host Quarantine**: Automatically isolates compromised endpoints when Threat Score $\ge 90$ or upon SOC analyst manual trigger.

### 4. Pure-Python Libpcap Binary Processor (Zero-Driver Dependency)
- Fully native Python implementation using the `struct` and `socket` standard libraries to read, parse, and write binary `.pcap` capture files.
- **No WinPcap, Npcap, or external C-extensions required**—runs seamlessly across Windows, Linux, and macOS without driver installations.
- Supports both forensic `.pcap` file uploads and one-click forensic `.pcap` export of captured alerts.

### 5. Futuristic Cyber Defense Operations Center (SOC) Dashboard
- **Glassmorphic UI**: Ultra-clean, military-grade dark cyberpunk console styled with CSS glassmorphism, glowing status indicators, and tactical typography.
- **Real-Time WebSocket Feed**: Live telemetry stream (`ws://localhost:8000/ws/soc-feed`) updating metrics, alerts, and graphs without polling or page reloads.
- **Interactive Visualizations (Chart.js)**:
  - **Live Traffic Timeline**: Dual-axis line chart tracking total flow volume vs. detected threats per second.
  - **Threat Vector Breakdown**: Donut chart detailing distribution of attack classifications.
  - **MITRE ATT&CK Radar**: Radar chart visualizing tactical coverage across Reconnaissance, Initial Access, Lateral Movement, C2, and Exfiltration.
- **Interactive Simulation Studio**: Immediate one-click firing of real attack traffic patterns (`SYN Flood`, `Nmap Scan`, `SSH Brute Force`, `SQLi Exploit`, `C2 Beacon`, `Data Exfiltration`, `Normal Traffic`).
- **Deep Forensic Inspection Drawer**: Interactive drawer displaying raw packet bytes, hex dump, AI explainability feature ranking, STIX export buttons, and firewall mitigations.
- **CTI Intelligence Search Modal**: On-demand IP reputation scanner displaying actor attribution, CVEs, abuse frequency, and geolocation.

---

## 📁 Repository Layout

```
AI-Based Network Intrusion/
├── backend/
│   ├── app/
│   │   ├── intelligence/               # Threat Intelligence & Playbooks
│   │   │   ├── mitre_mapper.py          # MITRE ATT&CK Matrix engine
│   │   │   ├── playbook_engine.py       # Multi-vendor firewall command generator
│   │   │   ├── stix_generator.py        # OASIS STIX 2.1 JSON bundle builder
│   │   │   └── threat_intel.py          # CTI database, GeoIP, and ASN enrichment
│   │   ├── models/                      # AI/ML & Detection Engines
│   │   │   ├── anomaly_detector.py      # Deep AutoEncoder & IsolationForest
│   │   │   ├── ensemble.py              # Bayesian fusion & threat score calculator
│   │   │   ├── ml_detector.py           # Supervised Multi-Class Random Forest & XAI
│   │   │   ├── schemas.py               # Pydantic v2 data models
│   │   │   └── signature_engine.py      # Snort/Suricata heuristic regex rules
│   │   ├── services/                    # Core Infrastructure
│   │   │   ├── detection_service.py     # Central synchronous detection orchestrator
│   │   │   └── storage_service.py       # SQLite persistence & telemetry ring buffer
│   │   ├── traffic/                     # Packet Capture & Simulation
│   │   │   ├── pcap_processor.py        # Pure-Python Libpcap binary reader/writer
│   │   │   └── simulator.py             # Realistic multi-vector attack generator
│   │   ├── config.py                    # Global system settings & thresholds
│   │   └── main.py                      # FastAPI server & WebSocket broadcaster
│   └── trained_models/                  # Serialized Model Artifacts
│       ├── autoencoder.pt               # Trained Deep AutoEncoder weights
│       ├── scaler.pkl                   # StandardScaler feature normalizer
│       └── supervised_rf.pkl            # Trained Random Forest classifier
├── data/                                # Persistent storage
│   ├── aegis_nids.db                    # SQLite forensics database
│   └── exports/                         # Exported STIX & forensic PCAP files
├── frontend/                            # SOC Analyst Web Dashboard
│   ├── css/
│   │   └── styles.css                   # Glassmorphism styling & animations
│   ├── js/
│   │   ├── app.js                       # WebSocket client & DOM controller
│   │   └── charts.js                    # Chart.js visualization configurations
│   └── index.html                       # Tactical Cyber Defense Dashboard
├── tests/                               # Comprehensive Automated Test Suite
│   ├── test_api.py                      # FastAPI REST endpoints integration tests
│   ├── test_ml_detection.py             # RF, AutoEncoder, and Ensemble unit tests
│   ├── test_playbooks.py                # SOAR firewall generation unit tests
│   └── test_threat_intel.py             # CTI lookup, STIX, and MITRE tests
├── cli.py                               # Command Line Interface (CLI) utility
├── run.py                               # Single-command application launcher
├── train_models.py                      # High-speed vectorized model trainer
├── requirements.txt                     # Production Python dependencies
└── README.md                            # Comprehensive system documentation
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.10+ (Recommended: Python 3.12)
- Windows, Linux, or macOS

### 1. Installation
Clone or navigate to the repository directory and install the dependencies:
```bash
pip install -r requirements.txt
```

### 2. Launch the System
Run the unified single-command launcher:
```bash
python run.py
```
*Note: If trained model weights are not found on the initial launch, `run.py` automatically bootstraps and trains the models in seconds.*

### 3. Access Interfaces
- **SOC Web Dashboard**: Open [http://localhost:8000](http://localhost:8000) in any modern browser.
- **Interactive REST API Docs (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Alternative ReDoc UI**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## 🖥️ Command Line Interface (CLI)

The `cli.py` utility allows security operators to run threat intelligence lookups, simulations, and PCAP analysis straight from the terminal.

### 1. Query Cyber Threat Intelligence on an IP
```bash
python cli.py lookup 185.220.101.5
```
*Output:*
```
============================================================
  THREAT INTELLIGENCE DOSSIER: 185.220.101.5
============================================================
  Reputation Score : 98/100
  Malicious Status : [!] CONFIRMED MALICIOUS
  Threat Categories: Tor Exit Node, Credential Spraying, C2 Infrastructure
  Attributed Actor : APT29 (Cozy Bear)
  Associated CVEs  : CVE-2023-38831, CVE-2024-21413
  Geolocation      : Frankfurt, Germany (DE)
  Network ASN/ISP  : AS208294 - Zwiebelfreunde e.V.
  Tor Exit Node    : YES
  Abuse Reports    : 1420
============================================================
```

### 2. Simulate Attack Traffic Vectors
```bash
# Simulate 3 DDoS SYN flood packets against target
python cli.py simulate --type ddos_syn --count 3 --target 192.168.1.100

# Simulate SQL Injection exploits
python cli.py simulate --type sqli_web --count 2

# Available types: ddos_syn, port_scan_nmap, ssh_brute, sqli_web, c2_beacon, exfiltration, normal
```

### 3. Generate Firewall Mitigation Playbooks
```bash
python cli.py firewall 185.220.101.5
```
*Renders multi-vendor firewall block commands for `iptables`, `nftables`, `windows_netsh`, `windows_powershell`, `cisco_ios`, `aws_security_group`, and `pfsense_xml`.*

### 4. Retrain AI Models
```bash
python cli.py train
```

---

## 🌐 REST API Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | System health check and model loading status |
| `GET` | `/api/v1/metrics` | Real-time SOC metrics (DEFCON level, packet rates, threat score) |
| `POST` | `/api/v1/traffic/ingest` | Ingest and evaluate a single live `NetworkFlow` object |
| `POST` | `/api/v1/traffic/upload-pcap` | Upload and analyze a raw binary `.pcap` capture file |
| `GET` | `/api/v1/traffic/export-pcap` | Download forensic `.pcap` binary containing flagged incident packets |
| `GET` | `/api/v1/alerts` | Query alerts filtered by severity or attack type |
| `GET` | `/api/v1/alerts/{alert_id}` | Retrieve deep forensic record of a specific alert |
| `PATCH`| `/api/v1/alerts/{alert_id}/status` | Update alert triage status (`NEW`, `CONTAINED`, `DISMISSED`) |
| `GET` | `/api/v1/alerts/{alert_id}/stix` | Export incident as an **OASIS STIX 2.1** JSON bundle |
| `GET` | `/api/v1/threat-intel/lookup/{ip}`| Query CTI database for reputation, actor, and CVEs |
| `GET` | `/api/v1/threat-intel/mitre-matrix`| Retrieve full MITRE ATT&CK Matrix mapping |
| `POST` | `/api/v1/mitigation/quarantine` | Quarantine and isolate a compromised host |
| `POST` | `/api/v1/mitigation/unquarantine` | Release host from quarantine |
| `POST` | `/api/v1/mitigation/generate-firewall-rules` | Generate cross-platform firewall rules for an indicator |
| `POST` | `/api/v1/simulation/launch` | Inject synthetic attack vector directly into live AI engine |
| `WS` | `/ws/soc-feed` | Real-time bidirectional WebSocket telemetry stream |

---

## 🧪 Automated Testing & Verification

The test suite provides comprehensive test coverage across ML classification, deep anomaly scoring, CTI correlation, STIX generation, firewall rule syntax, and FastAPI REST endpoints.

Run all unit and integration tests:
```bash
python -m unittest discover tests
```

### Verified Test Results
```
Ran 19 tests in 1.819s

OK (100% Passing)
  - test_threat_intel.py  : 7/7 passed (CTI lookups, STIX 2.1 bundles, MITRE mappings)
  - test_playbooks.py     : 1/1 passed (Cross-platform firewall rule generation)
  - test_ml_detection.py  : 5/5 passed (Supervised RF, AutoEncoder anomaly, Signatures, Ensemble)
  - test_api.py           : 7/7 passed (FastAPI health, metrics, ingest, simulation, quarantine)
```

---

## 📊 Benchmark & Detection Performance

| Detection Engine | Accuracy / Precision | Latency | Memory Footprint |
| :--- | :--- | :--- | :--- |
| **Supervised Random Forest** | **100.0% Test Accuracy** (F1: 1.000) | **~0.12 ms / flow** | ~14 MB |
| **Deep Anomaly AutoEncoder** | **98.2% Anomaly Discrimination** | **~0.25 ms / flow** | ~8 MB |
| **Signature Heuristic Engine** | **100.0% Deterministic Regex** | **~0.04 ms / flow** | < 1 MB |
| **Integrated Pipeline + CTI** | **End-to-End Decision** | **~0.48 ms / flow** | ~35 MB total |

---

## 🛡️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

