"""
Ensemble Fusion Engine.
Synthesizes Supervised ML, Deep AutoEncoder Anomaly Scoring, and Signature Detection
into a unified Threat Score, calibrated Severity, and actionable response.
"""
import uuid
from typing import Dict, Any, List
from backend.app.models.schemas import (
    NetworkFlow, DetectionResult, AttackType, SeverityLevel, MitreTechnique
)
from backend.app.models.ml_detector import MLDetector
from backend.app.models.anomaly_detector import AnomalyDetector
from backend.app.models.signature_engine import SignatureEngine
from backend.app.intelligence.mitre_mapper import MitreMapper
from backend.app.intelligence.playbook_engine import PlaybookEngine


class EnsembleDetector:
    def __init__(self, ml_detector: MLDetector, anomaly_detector: AnomalyDetector, signature_engine: SignatureEngine):
        self.ml_detector = ml_detector
        self.anomaly_detector = anomaly_detector
        self.signature_engine = signature_engine

    def evaluate_flow(self, flow: NetworkFlow) -> DetectionResult:
        flow_id = flow.flow_id or str(uuid.uuid4())[:8]

        # 1. Supervised ML Classification
        predicted_class, ml_conf, explainability = self.ml_detector.predict(flow)

        # 2. Deep AutoEncoder Anomaly Scoring
        raw_features = self.ml_detector.extract_features(flow).reshape(1, -1)
        scaled_features = self.ml_detector.scaler.transform(raw_features) if self.ml_detector.is_trained else raw_features
        anomaly_res = self.anomaly_detector.predict(scaled_features)
        anomaly_score = anomaly_res["anomaly_score"]
        is_anomaly = anomaly_res["is_anomaly"]

        # 3. Signature & Heuristic Rule Matching
        sig_matches = []
        rule_mitre_ids = []

        # Check payload
        if flow.payload_preview:
            payload_hits = self.signature_engine.evaluate_payload(flow.payload_preview)
            for hit in payload_hits:
                sig_matches.append(f"{hit['rule_id']}: {hit['name']}")
                rule_mitre_ids.append(hit["mitre_id"])

        # Check flow heuristics
        heur_hits = self.signature_engine.check_flow_heuristics(flow)
        for hit in heur_hits:
            sig_matches.append(f"{hit['rule_id']}: {hit['name']}")
            rule_mitre_ids.append(hit["mitre_id"])

        # 4. Synthesize and Fuse Threat Score (0 to 100)
        # Base ML contribution (0 to 45)
        is_attack_class = (predicted_class != AttackType.BENIGN)
        ml_score = (ml_conf * 45.0) if is_attack_class else (1.0 - ml_conf) * 15.0

        # Anomaly contribution (0 to 30)
        ae_score = anomaly_score * 30.0

        # Signature contribution (0 to 25)
        sig_score = min(len(sig_matches) * 15.0, 25.0)

        raw_threat_score = ml_score + ae_score + sig_score

        # Rule overrides
        if len(sig_matches) > 0 and any("CRITICAL" in s or "RCE" in s or "SQLI" in s or "LOG4J" in s or "C2" in s for s in sig_matches):
            raw_threat_score = max(raw_threat_score, 92.0)
            if predicted_class == AttackType.BENIGN:
                # Override benign ML prediction when explicit malicious signature matches
                predicted_class = AttackType.WEB_ATTACK

        # Zero-Day anomaly override: If ML thinks normal, but Deep Autoencoder is extremely anomalous
        if predicted_class == AttackType.BENIGN and is_anomaly and anomaly_score >= 0.85:
            predicted_class = AttackType.ZERO_DAY_ANOMALY
            raw_threat_score = max(raw_threat_score, 78.0)

        # Cap score between 0 and 100
        threat_score = round(float(max(0.0, min(raw_threat_score, 100.0))), 1)

        # Determine Severity Level
        if threat_score < 25.0:
            severity = SeverityLevel.INFO
        elif threat_score < 50.0:
            severity = SeverityLevel.LOW
        elif threat_score < 75.0:
            severity = SeverityLevel.MEDIUM
        elif threat_score < 90.0:
            severity = SeverityLevel.HIGH
        else:
            severity = SeverityLevel.CRITICAL

        # MITRE ATT&CK Mapping
        mitre_techniques = MitreMapper.get_techniques_for_attack(predicted_class, rule_mitre_ids)

        # Playbook recommendation
        pb_rec = PlaybookEngine.get_playbook_recommendation(predicted_class.value, severity.value, flow.src_ip)
        rec_action = pb_rec["recommended_action"]

        auto_quarantine = (severity == SeverityLevel.CRITICAL or threat_score >= 90.0)

        return DetectionResult(
            flow_id=flow_id,
            predicted_class=predicted_class,
            confidence=round(float(ml_conf), 4),
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            signature_matches=sig_matches,
            threat_score=threat_score,
            severity=severity,
            explainability=explainability,
            mitre_techniques=mitre_techniques,
            recommended_action=rec_action,
            auto_quarantined=auto_quarantine
        )
