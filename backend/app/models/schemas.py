"""
Pydantic schemas and data models for Network Flow, Detection, Threat Intel, and Alerts.
"""
from datetime import datetime
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from enum import Enum


class ProtocolType(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class AttackType(str, Enum):
    BENIGN = "Normal / Benign"
    DDOS = "DDoS / DoS Flood"
    PORT_SCAN = "Port Scan / Reconnaissance"
    BRUTE_FORCE = "Credential Brute Force"
    WEB_ATTACK = "Web Exploit / Injection"
    C2_BEACON = "Botnet C2 Beaconing"
    EXFILTRATION = "Data Exfiltration"
    ZERO_DAY_ANOMALY = "Unknown Anomaly / Zero-Day"


class SeverityLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class NetworkFlow(BaseModel):
    flow_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: ProtocolType = ProtocolType.TCP
    service: str = "http"
    duration: float = 0.0
    src_bytes: int = 0
    dst_bytes: int = 0
    src_packets: int = 1
    dst_packets: int = 0
    flag: str = "SF"  # TCP flags, e.g. SF, S0, REJ, RSTO
    serror_rate: float = 0.0
    rerror_rate: float = 0.0
    same_srv_rate: float = 1.0
    diff_srv_rate: float = 0.0
    dst_host_count: int = 1
    dst_host_srv_count: int = 1
    dst_host_same_srv_rate: float = 1.0
    payload_preview: Optional[str] = None


class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    description: str
    mitigation: str
    url: str


class ThreatIntelHit(BaseModel):
    indicator: str
    indicator_type: str  # ip, domain, cve
    reputation_score: int  # 0 to 100
    is_malicious: bool
    categories: List[str] = []
    threat_actor: Optional[str] = None
    cve_ids: List[str] = []
    country: str = "Unknown"
    country_code: str = "XX"
    city: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    tor_exit_node: bool = False
    reported_abuse_count: int = 0
    last_seen: Optional[datetime] = None


class FeatureImportance(BaseModel):
    feature_name: str
    value: float
    contribution: float  # How much this feature pushed towards attack
    description: str


class DetectionResult(BaseModel):
    flow_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    predicted_class: AttackType
    confidence: float
    is_anomaly: bool
    anomaly_score: float  # 0.0 to 1.0
    signature_matches: List[str] = []
    threat_score: float  # Calibrated 0 to 100
    severity: SeverityLevel
    explainability: List[FeatureImportance] = []
    mitre_techniques: List[MitreTechnique] = []
    recommended_action: str
    auto_quarantined: bool = False


class Alert(BaseModel):
    alert_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    flow: NetworkFlow
    detection: DetectionResult
    threat_intel: Optional[ThreatIntelHit] = None
    status: str = "NEW"  # NEW, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    quarantined: bool = False
    firewall_rules: Dict[str, str] = {}  # iptables, netsh, cisco, aws
    analyst_notes: Optional[str] = None


class MitigationActionRequest(BaseModel):
    ip: str
    action: str = "BLOCK_IP"  # BLOCK_IP, UNBLOCK_IP, ISOLATE_HOST
    reason: Optional[str] = None
    duration_minutes: Optional[int] = 60


class SimulationRequest(BaseModel):
    attack_type: str = "ddos_syn"  # ddos_syn, port_scan_nmap, ssh_brute, sqli_web, c2_beacon, exfiltration, normal
    packet_count: int = 25
    intensity: str = "medium"  # low, medium, high
    target_ip: str = "192.168.1.100"
    target_port: Optional[int] = None


class SystemMetrics(BaseModel):
    total_flows_processed: int
    total_attacks_detected: int
    active_quarantined_ips: int
    threat_intel_hits: int
    attacks_by_type: Dict[str, int]
    severity_breakdown: Dict[str, int]
    mttd_ms: float  # Mean time to detect in milliseconds
    model_accuracy: float
    active_threat_level: str
    uptime_seconds: float


class StixBundleExport(BaseModel):
    bundle_id: str
    generated_at: datetime
    objects_count: int
    stix_json: Dict[str, Any]
